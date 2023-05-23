/*
 * package plugins_common contains common interfaces and structs that are used by all plugins
 * It is used by plugin manager to manage plugins
 */

package plugins_common

import (
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "sync"
    "time"
)

/*
 *Plugin interface is implemented by all plugins and is used by plugin manager to call plugin methods
 */
type Plugin interface {
    Init(actionCfg *lomcommon.ActionCfg_t) error
    Request(hbchan chan PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData
    Shutdown() error
    GetPluginID() PluginId
}

/*
 * PluginStage indicates the current stage of plugin. Based on  this value plugin manager decisions. For e.g.  whether to accept requests from engine or not
 */
type PluginStage int

const (
    PluginStageUnknown PluginStage = iota // default value
    PluginStageLoadingSuccess
    PluginStageRequestStarted
    PluginStageRequestSuccess
    PluginStageRequestTimeout
    PluginStageShutdownStarted
    PluginStageShutdownCompleted
    PluginStageShutdownTimeout
    PluginStageDisabled
    PluginStageCount
)

var pluginStageStrings = [PluginStageCount]string{
    "Unknown",
    "Loading success",
    "Request started",
    "Request success",
    "Request timeout",
    "Shutdown started",
    "Shutdown completed",
    "Shutdown timeout",
    "Disabled",
}

/*
 * GetPluginStageToString returns the string representation of PluginStage
 */
func GetPluginStageToString(stage PluginStage) string {
    if stage >= 0 && int(stage) < len(pluginStageStrings) {
        return pluginStageStrings[stage]
    }
    return "Unknown stage"
}

const (
    MAX_PLUGIN_RESPONSES_DEFAULT = 100 /* Max number of reesponses that plugin can send per
       anamolykey during last MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT
      before plugin manager mark it as disabled. Applicable for plugin's with timeout */
    MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT_DEFAULT = 60 * time.Second /* Interval in which plugin can send
       MAX_PLUGIN_RESPONSES_DEFAULT responses per anamoly key */
)

/*
 * sent from plugin to plugin manager via heartbeat channel
 */
type PluginHeartBeat struct {
    PluginName string
    EpochTime  int64
}

/*
 * sent from plugin to plugin manager as a responce to getPluginId()
 */
type PluginId struct {
    Name    string
    Version string
}

/*
 * IPluginMetadata has common methods that are used by plugin manager to manage plugins. Data remain same for all plugins
 */
type IPluginMetadata interface {
    GetPluginStage() PluginStage
    SetPluginStage(stage PluginStage)
    CheckMisbehavingPlugins(pluginKey string) bool
}

/*
 * RollingWindow is used to keep track of response times of plugin requests
 */
type PluginResponseRollingWindow struct {
    response map[string][]time.Time // map of pluginname+Anamolykey to slice of response times
}

/*
 * Dynamically create objects of plugins based on action name
 */
type PluginConstructor func(...interface{}) Plugin

var PluginConstructors = make(map[string]PluginConstructor)

// Register a constructor function for a given action name
func RegisterPlugin(name string, constructor PluginConstructor) {
    PluginConstructors[name] = constructor
}

/*
 * Holds all data specific to plugin, run time info, etc
 */
type PluginMetadata struct {
    ActionCfg   *lomcommon.ActionCfg_t
    StartedTime time.Time
    Pluginstage PluginStage // indicate the current plugin stage
    PluginId
    mu                           sync.Mutex    // Mutex to synchronize access to PluginStage field
    PluginResponseRollingWindow                // rolling window of response times
    MaxPluginResponses           int           // max number of responses that plugin can send per anamolykey during last MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT
    MaxPluginResponsesWindowTime time.Duration // interval in which plugin can send MAX_PLUGIN_RESPONSES responses per anamoly key
    // ... other common metadata fields
}

/*
 * Get the current stage of plugin
 */
func (gpl *PluginMetadata) GetPluginStage() PluginStage {
    gpl.mu.Lock()
    defer gpl.mu.Unlock()
    return gpl.Pluginstage
}

/*
 * Set the current stage of plugin
 */
func (gpl *PluginMetadata) SetPluginStage(stage PluginStage) {
    gpl.mu.Lock()
    defer gpl.mu.Unlock()
    gpl.Pluginstage = stage
}

/*
 * CheckMisbehavingPlugins maintains rolling window for certain time. Checks if the rolling window for the given plugin+Anamolykey
 * has reached a certain size within the specified time.
 * It returns true if the window size has reached the limit, false otherwise.
 */
func (gpl *PluginMetadata) CheckMisbehavingPlugins(pluginKey string) bool {

    now := time.Now()
    responses, ok := gpl.PluginResponseRollingWindow.response[pluginKey] // rerurns window(slice) for the given pluginname
    if !ok {
        // First response for this plugin, create a new slice
        gpl.response[pluginKey] = []time.Time{now}
        return false
    }

    // Remove expired responses from the window(slice)
    threshold := now.Add(-gpl.MaxPluginResponsesWindowTime) // go back in time by duration
    for i := 0; i < len(responses); i++ {
        if responses[i].Before(threshold) {
            responses = responses[i+1:]
            i--
        } else {
            break
        }
    }

    // Add current response to the slice
    responses = append(responses, now)

    // Update the response slice for the pluginKey
    gpl.response[pluginKey] = responses

    // Check if the window size has reached the limit
    if len(responses) >= gpl.MaxPluginResponses {
        // Window size reached the limit, delete the window
        delete(gpl.response, pluginKey)
        return true // misbehaving plugin
    }

    return false // plugin is behaving well
}
