/*
 * package pluginmgr_common provides plugin manager functionality. Plugin manager is responsible for loading plugins, managing plugins, communicating
 * with engine, etc. Plugin manager is implemented as a singleton.
 */

package pluginmgr_common

import (
    "flag"
    "fmt"
    "log/syslog"
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "lom/src/plugins/plugins_common"
    "os"
    "os/signal"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
)

/*
 * Plugin manager ----------------------------------------------------------------------------------------------------
 */

// Plugin Manager global variables
var (
    ProcID    string         = ""
    pluginMgr *PluginManager = nil
)

// TODO: Goutham : Add this to global_conf.json
/*
 * Constants for plugin manager with default values
 */
const (
    GOLIB_TIMEOUT_DEFAULT                    = 0 * time.Millisecond /* Default GoLIB API timeouts */
    PLUGIN_PERIODIC_FALLBACK_TIMEOUT_DEFAULT = 3600 * time.Second   /* Default Periodic logging long timeout */
    PLUGIN_PERIODIC_TIMEOUT_DEFAULT          = 300 * time.Second    /* Default periodic logging short timeout */
    PLUGIN_LOADING_TIMEOUT_DEFAULT           = 30 * time.Second
    PLUGIN_SHUTDOWN_TIMEOUT_DEFAULT          = 30 * time.Second
    GOROUTINE_CLEANUP_TIMEOUT_DEFAULT        = 30 * time.Second
    APP_NAME_DEAULT                          = "plgMgr"
)

var LogInfo = lomcommon.LogInfo
var LogError = lomcommon.LogError
var LogDebug = lomcommon.LogDebug
var LogWarning = lomcommon.LogWarning
var LogPanic = lomcommon.LogPanic
var RegisterForSysShutdown = lomcommon.RegisterForSysShutdown
var DeregisterForSysShutdown = lomcommon.DeregisterForSysShutdown
var DoSysShutdown = lomcommon.DoSysShutdown
var osExit = os.Exit
var AddPeriodicLogWithTimeouts = lomcommon.AddPeriodicLogWithTimeouts

/*
 * Plugin Manager interface to be implemented by plugin manager
 */
type IPluginManager interface {
    getPlugin(plgname string) (plugins_common.Plugin, bool)
    getPluginMetadata(plgname string) (plugins_common.IPluginMetadata, bool)
    setShutdownStatus(value bool)
    getShutdownStatus() bool
    run() error
    verifyRequestMsg(actionReq *lomipc.ActionRequestData) (plugins_common.Plugin, plugins_common.IPluginMetadata, error)
    handleRequest(actionReq *lomipc.ActionRequestData) error
    handleMisbehavingPlugins(respData *lomipc.ActionResponseData, pluginmetadata plugins_common.IPluginMetadata)
    handleRequestWithHeartbeats(actionReq *lomipc.ActionRequestData, hbChan <-chan plugins_common.PluginHeartBeat,
        respChan <-chan *lomipc.ActionResponseData, handleResponseFunc func(respData *lomipc.ActionResponseData))
    handleRequestWithTimeouts(
        actionReq *lomipc.ActionRequestData, respChan <-chan *lomipc.ActionResponseData, handleResponseFunc func(respData *lomipc.ActionResponseData))
    handleShutdown() error
    shutdownPlugin(pluginname string)
    sendResponseToEngine(responseObj interface{}) error
    addPlugin(pluginName string, pluginVersion string) error
    loadPlugin(pluginName string, pluginVersion string) error
    registerActionWithEngine(pluginName string) error
    deRegisterActionWithEngine(pluginName string) error
}

/*
 * Interface  for lomipc.ClientTx
 */
type IClientTx interface {
    RegisterClient(client string) error
    DeregisterClient() error
    RegisterAction(action string) error
    DeregisterAction(action string) error
    RecvServerRequest() (*lomipc.ServerRequestData, error)
    SendServerResponse(res *lomipc.MsgSendServerResponse) error
    NotifyHeartbeat(action string, tstamp int64) error
}

type PluginManager struct {
    clientTx IClientTx
    plugins  map[string]plugins_common.Plugin /* map : pluginname -> Plugin struct Object(at go/src/plugins/plugins_common)
       e.g. "linkflapdetection" -->  {linkFlapDetection object} */
    pluginMetadata   map[string]plugins_common.IPluginMetadata /* map : pluginname -> PluginMetadata struct Object(at go/src/plugins/plugins_common) */
    systemStopChan   <-chan int                                /* system wide channel used to stop plugin mamanegr  */
    responseChan     chan interface{}                          /* channel used to send response to server */
    isActiveShutdown int32                                     /* atomic flag to indicate if shutdown is active */

    pluginPeriodicFallbackTimeout time.Duration /* Periodic logging long timeout */
    pluginPeriodicTimeout         time.Duration /* Periodic logging short timeout */
    pluginLoadingTimeout          time.Duration /* Plugin loading timeout */
    pluginShutdownTimeout         time.Duration /* Plugin shutdown timeout */
    goRoutineCleanupTimeout       time.Duration /* Go routine cleanup timeout */
}

/*
 * InitPluginManager : Initialize plugin manager & register with server
 */
func GetPluginManager(clientTx IClientTx) *PluginManager {
    if pluginMgr != nil {
        return pluginMgr
    }

    // register for system shutdown
    schan := RegisterForSysShutdown(APP_NAME_DEAULT + ProcID)

    vpluginMgr := &PluginManager{
        clientTx:         clientTx,
        plugins:          make(map[string]plugins_common.Plugin),
        pluginMetadata:   make(map[string]plugins_common.IPluginMetadata),
        systemStopChan:   schan,
        responseChan:     make(chan interface{}, 1),
        isActiveShutdown: 0,
    }
    if err := vpluginMgr.clientTx.RegisterClient(ProcID); err != nil {
        vpluginMgr = nil
        LogPanic("Error in registering Plugin manager client for procId : " + ProcID)
        return nil
    }

    pluginMgr = vpluginMgr

    // TODO: Goutham : Read this from API from global_conf.json
    // assign constants to plugin manager
    pluginMgr.pluginPeriodicFallbackTimeout = PLUGIN_PERIODIC_FALLBACK_TIMEOUT_DEFAULT
    pluginMgr.pluginPeriodicTimeout = PLUGIN_PERIODIC_TIMEOUT_DEFAULT
    pluginMgr.pluginLoadingTimeout = PLUGIN_LOADING_TIMEOUT_DEFAULT
    pluginMgr.pluginShutdownTimeout = PLUGIN_SHUTDOWN_TIMEOUT_DEFAULT
    pluginMgr.goRoutineCleanupTimeout = GOROUTINE_CLEANUP_TIMEOUT_DEFAULT

    LogInfo("Plugin Manager initialized successfully for procId : " + ProcID)
    return pluginMgr
}

/*
 * getPluginManager : Get plugin manager object
 */
func (plmgr *PluginManager) getPlugin(plgname string) (plugins_common.Plugin, bool) {
    plugin, ok := plmgr.plugins[plgname]
    return plugin, ok
}

/*
 * getPluginMetadata : Get plugin metadata object
 */
func (plmgr *PluginManager) getPluginMetadata(plgname string) (plugins_common.IPluginMetadata, bool) {
    pluginmetadata, ok := plmgr.pluginMetadata[plgname]
    return pluginmetadata, ok
}

/*
 * SetIsActiveShutdown atomically sets the value of isActiveShutdown.
 */
func (plmgr *PluginManager) setShutdownStatus(value bool) {
    var v int32
    if value {
        v = 1
    }
    atomic.StoreInt32(&plmgr.isActiveShutdown, v)
}

/*
 * GetIsActiveShutdown atomically gets the value of isActiveShutdown.
 */
func (plmgr *PluginManager) getShutdownStatus() bool {
    return atomic.LoadInt32(&plmgr.isActiveShutdown) != 0
}

/*
 * Listens for server requests via golib. This call blocks.
 *
 * Input:
 *  stop - stop channel used to stop the blocking receive server call
 *
 * Output:
 *  none -
 *
 * Return:
 *  error - error message or nil on success
 */
func (plmgr *PluginManager) run() error {
    serverReqChan := make(chan *lomipc.ServerRequestData, 1) // Channel for server requests

    // Start a goroutine to receive server requests and send them to the serverReqChan channel
    lomcommon.GetGoroutineTracker().Start("plg_mgr_Run_RecvServerRequest"+"_"+lomcommon.GetUUID(),
        func() {
            for {
                serverReq, err := plmgr.clientTx.RecvServerRequest()
                if plmgr.getShutdownStatus() {
                    LogInfo("In run() RecvServerRequest: Shutdown is active, ignoring request: %v", serverReq)
                    if lomcommon.GetLoMRunMode() == lomcommon.LoMRunMode_Test {
                        return
                    }
                } else if err != nil {
                    LogError("Error in run() RecvServerRequest: %v", err)
                } else if serverReq == nil {
                    LogError("run() RecvServerRequest returned : %v", serverReq)
                } else {
                    serverReqChan <- serverReq
                }
            }
        })

    for {
        select {
        case <-plmgr.systemStopChan: // system shutdown is received
            LogInfo("RecvServerRequest() : Received system shutdown. Stopping plugin manager run loop")
            return nil
        case respObj := <-plmgr.responseChan: // response from plugin are received here and sent to engine via clientTx interface
            // If plugin manager is shutting down, do not send response to engine
            if plmgr.getShutdownStatus() {
                LogInfo("In run(): Plugin manager is shutdown. Not sending response to engine %v", respObj)
                //return nil
            } else {
                LogInfo("In run() : Received response object : %v", respObj)
                switch resp := respObj.(type) {
                case *lomipc.MsgSendServerResponse:
                    if err := plmgr.clientTx.SendServerResponse(resp); err != nil {
                        LogError("In run() : Error in SendServerResponse() : %v", err)
                    }
                case lomipc.MsgNotifyHeartbeat:
                    if err := plmgr.clientTx.NotifyHeartbeat(resp.Action, resp.Timestamp); err != nil {
                        LogError("In run() : Error in NotifyHeartbeat() : %v", err)
                    }
                }
            }
        case serverReq := <-serverReqChan: // requests from engine are received here and handled
            if plmgr.getShutdownStatus() {
                LogInfo("In run() RecvServerRequest: Shutdown is active, so ignoring request: %v", serverReq)
                if lomcommon.GetLoMRunMode() == lomcommon.LoMRunMode_Test {
                    return nil
                }
            } else {
                switch serverReq.ReqType {
                case lomipc.TypeServerRequestAction:
                    LogInfo("In run() RecvServerRequest : Received action request : %v", serverReq)
                    actionReq, ok := serverReq.ReqData.(*lomipc.ActionRequestData)
                    if !ok {
                        LogError("In run() RecvServerRequest : Error in parsing ActionRequestData for type : %v, data : %v",
                            serverReq.ReqType, serverReq.ReqData)
                    } else {
                        lomcommon.GetGoroutineTracker().Start("plg_mgr_Run_Action_"+actionReq.Action+"_"+lomcommon.GetUUID(),
                            plmgr.handleRequest, actionReq)
                    }
                case lomipc.TypeServerRequestShutdown:
                    LogInfo("In run() RecvServerRequest : Received shutdown request : %v", serverReq)
                    shutdownReq, ok := serverReq.ReqData.(*lomipc.ShutdownRequestData)
                    if !ok {
                        LogError("In run RecvServerRequest : Error in parsing ShutdownRequestData for type : %v, data : %v",
                            serverReq.ReqType, serverReq.ReqData)
                    } else {
                        if shutdownReq == nil {
                            LogError("In run() RecvServerRequest: shutdown request is nil")
                        } else {
                            plmgr.setShutdownStatus(true)
                            // start with native go routine only to handle goroutine tracker cleaneup gracefully on shutdown without deadlocks
                            go plmgr.handleShutdown()
                        }
                    }
                default:
                    LogError("In run() RecvServerRequest : Unknown server request type : %v", serverReq.ReqType)
                }
            }
        }
    }
    return nil
}

/*
 * verify request message
 */
func (plmgr *PluginManager) verifyRequestMsg(actionReq *lomipc.ActionRequestData) (plugins_common.Plugin, plugins_common.IPluginMetadata, error) {
    if actionReq == nil {
        return nil, nil, LogError("verifyRequestMsg() : nil request data")
    }

    if actionReq.Action == "" {
        return nil, nil, LogError("verifyRequestMsg() : empty action name")
    }

    plugin, ok := plmgr.getPlugin(actionReq.Action)
    if !ok {
        return nil, nil, LogError("verifyRequestMsg() : Plugin %s not initialized", actionReq.Action)
    }

    if plugin == nil {
        return nil, nil, LogError("verifyRequestMsg() : Plugin %s is nil", actionReq.Action)
    }

    pluginmetadata, ok := plmgr.getPluginMetadata(actionReq.Action)
    if !ok {
        return nil, nil, LogError("verifyRequestMsg() : Plugin %s metadata not initialized", actionReq.Action)
    }

    if pluginmetadata == nil {
        return nil, nil, LogError("verifyRequestMsg() : Plugin %s metadata is nil", actionReq.Action)
    }

    pluginStage := pluginmetadata.GetPluginStage()
    if pluginStage != plugins_common.PluginStageUnknown &&
        pluginStage != plugins_common.PluginStageLoadingSuccess &&
        pluginStage != plugins_common.PluginStageRequestSuccess {
        return nil, nil, LogError("verifyRequestMsg() : Unable to process request for Plugin %s. Reason : %s",
            actionReq.Action, plugins_common.GetPluginStageToString(pluginStage))
    }

    return plugin, pluginmetadata, nil
}

// TODO: Goutham - Need to handle the case where plugin is already working on request and new request comes in
/*
 * handleRequest : Handle request from server
 * Basic validation on ActionRequestData is done. Detail validation job is responsibility of plugin
 */
func (plmgr *PluginManager) handleRequest(actionReq *lomipc.ActionRequestData) error {
    // Verify request message and get plugin object for the request action
    plugin, pluginmetadata, err := plmgr.verifyRequestMsg(actionReq)
    if err != nil {
        return err
    }

    LogInfo(
        "In handleRequest(): Processing action request for plugin:%s, timeout:%d InstanceId:%s AnomalyInstanceId:%s AnomalyKey:%s",
        actionReq.Action,
        actionReq.Timeout,
        actionReq.InstanceId,
        actionReq.AnomalyInstanceId,
        actionReq.AnomalyKey,
    )

    // create a channel for receiving the responses from plugin
    respChan := make(chan *lomipc.ActionResponseData, 1)

    // create a channel for receiving the heartbeats from plugin
    hbChan := make(chan plugins_common.PluginHeartBeat, 1)

    // create a channel for stopping the periodic loogging
    var stopChan chan bool

    // Start the plugin request in a separate goroutine
    lomcommon.GetGoroutineTracker().Start("plg_mgr_handleRequest_"+actionReq.Action+"_"+lomcommon.GetUUID(),
        func() {
            pluginmetadata.SetPluginStage(plugins_common.PluginStageRequestStarted)

            // Invoke the plugin request and send the heartbeats through the channel
            resp := plugin.Request(hbChan, actionReq)

            // Send the response back to the respChan
            respChan <- resp
        })

    handleResponseFunc := func(respData *lomipc.ActionResponseData) {
        if respData == nil {
            LogPanic("In handleRequest(): Received nil response from plugin %v", actionReq.Action)
            return
        }

        LogDebug("In handleRequest(): Received response from plugin %v", respData.Action)

        if respData.Action != actionReq.Action {
            LogPanic("In handleRequest(): Invalid action name received. Got  %v, expected %v",
                respData.Action, actionReq.Action)
            return
        }

        // For plugin with timeouts, stop the periodic log if its started due to previous request timeout
        if actionReq.Timeout != 0 && stopChan != nil {
            stopChan <- true
        }

        // check misbehaving plugins for long running plugins
        if actionReq.Timeout != 0 && plmgr.handleMisbehavingPlugins(respData, pluginmetadata) {
            return
        }

        plmgr.sendResponseToEngine(respData)

        pluginmetadata.SetPluginStage(plugins_common.PluginStageRequestSuccess)
    }

    if actionReq.Timeout == 0 {
        plmgr.handleRequestWithHeartbeats(actionReq, hbChan, respChan, handleResponseFunc) // long running
    } else {
        stopChan = plmgr.handleRequestWithTimeouts(actionReq, respChan, handleResponseFunc) // short running
    }

    LogInfo("In handleRequest(): Completed processing action request for plugin:%s", actionReq.Action)

    return nil
}

/*
 * Tracking Plugin’s Responses:
 * The Plugin manager to identify misbehaving plugins & prevent flooding logs, will track responses from the plugins at a
 * high level for long running plugins (no timeout).
 * Have a moving window for the last X responses from plugin per "Action" + "Anomaly key”. If it crosses the set interval, mark plugin
 * as disabled and send de-register action to Engine & send shutdown () to plugin. Also, periodically for every one-hour log to syslog using
 * golib API.
 */
func (plmgr *PluginManager) handleMisbehavingPlugins(
    respData *lomipc.ActionResponseData,
    pluginmetadata plugins_common.IPluginMetadata,
) bool {

    if respData.AnomalyKey != "" && respData.ResultCode == 0 { // plugin+Anamolykey has valid response
        pluginKey := respData.Action + respData.AnomalyKey

        // check misbehaving plugin
        if pluginmetadata.CheckMisbehavingPlugins(pluginKey) {
            LogInfo("In handleMisbehavingPlugins(): Plugin %v is misbehaving for anamoly key %v. Ignoring the response",
                respData.Action, respData.AnomalyKey)

            pluginmetadata.SetPluginStage(plugins_common.PluginStageDisabled)

            lomcommon.GetGoroutineTracker().Start("handleMisbehavingPlugins_"+respData.Action+"_"+lomcommon.GetUUID(),
                func() {
                    // stop the plugin
                    plmgr.shutdownPlugin(respData.Action)

                    // deregister action with engine
                    plmgr.deRegisterActionWithEngine(respData.Action)

                    //do periodic log
                    errMsg := fmt.Sprintf("Plugin %v is misbehaving for anamoly key %v. Disabled the plugin",
                        respData.Action, respData.AnomalyKey)
                    LogInfo(errMsg)
                    AddPeriodicLogWithTimeouts("handleMisbehavingPlugins"+lomcommon.GetUUID()+"_"+respData.Action,
                        errMsg, plmgr.pluginPeriodicTimeout, plmgr.pluginPeriodicFallbackTimeout)
                })

            return true // ignore the response
        }
    }
    return false // process the response
}

/*
 * handleRequestWithHeartbeats : Handle request from server with heartbeats and response from plugin
 * Here the plugin is long running(e.g. detection). So watch for heartbeats. No need to handle timeouts
 */

func (plmgr *PluginManager) handleRequestWithHeartbeats(
    actionReq *lomipc.ActionRequestData,
    hbChan <-chan plugins_common.PluginHeartBeat,
    respChan <-chan *lomipc.ActionResponseData,
    handleResponseFunc func(respData *lomipc.ActionResponseData),
) {
loop:
    for {
        select {
        case hbvalue := <-hbChan:
            LogDebug("In handleRequest(): Received heartbeat from plugin %v", hbvalue.PluginName)
            if hbvalue.PluginName != actionReq.Action {
                LogPanic("In handleRequest(): Error, Received heartbeat from plugin %v, expected %v",
                    hbvalue.PluginName, actionReq.Action)
            }
            plmgr.sendResponseToEngine(hbvalue)
        case respData := <-respChan:
            // Response received from plugin.
            handleResponseFunc(respData)
            break loop
        }
    }
}

/*
 * handleRequestWithTimeouts : Handle request from server with timeouts and response from plugin
 * Here Timeout is set, not a long running action. Do not watch for heartbeats. Just Handle timeouts
 */
func (plmgr *PluginManager) handleRequestWithTimeouts(
    actionReq *lomipc.ActionRequestData,
    respChan <-chan *lomipc.ActionResponseData,
    handleResponseFunc func(respData *lomipc.ActionResponseData)) chan bool {

    timeout := time.Duration(actionReq.Timeout) * time.Second
    timer := time.NewTimer(timeout)
    var stopchan chan bool
loop:
    for {
        select {
        case <-timer.C:
            // Timeout occurred from plugin's response call. Log periodic message
            errMsg := fmt.Sprintf("In handleRequestWithTimeouts(): Action request timed out for plugin %s", actionReq.Action)
            LogInfo(errMsg)

            stopchan = AddPeriodicLogWithTimeouts("Plgmgr_handleRequestWithTimeouts_"+actionReq.Action+"_"+lomcommon.GetUUID(),
                errMsg, plmgr.pluginPeriodicTimeout, plmgr.pluginPeriodicFallbackTimeout)
        case respData := <-respChan:
            // Response received from plugin.
            handleResponseFunc(respData)
            // stop timer
            timer.Stop()
            select {
            case <-timer.C:
            default:
            }
            break loop
        }
    }
    return stopchan
}

/* handleShutdown : Handle shutdown request from server
 * Send shutdown request to all plugins and wait for them to shutdown
 */
func (plmgr *PluginManager) handleShutdown() error {
    // Send shutdown request to all plugins in a goroutine
    var wg sync.WaitGroup
    for name := range plmgr.plugins {
        wg.Add(1)
        lomcommon.GetGoroutineTracker().Start("plg_mgr_handleShutdown_"+name+"_"+lomcommon.GetUUID(),
            func(pluginname string) {
                defer wg.Done()
                plmgr.shutdownPlugin(pluginname)
            }, name)
    }

    // Wait for all plugins to shutdown or untill timeout expires
    wg.Wait()
    // TODO: Goutham/Renuka : verify if needed, Deregister the client with server
    plmgr.clientTx.DeregisterClient()

    DeregisterForSysShutdown(APP_NAME_DEAULT + ProcID)
    // calls blocks untill all the registered clients to be deregistered for shutdown
    DoSysShutdown(0) /* TODO: Goutham : Is it Needed ?? with '0' we are waiting indefinitly untill all
       the registered clients to be deregistered for shutdown */

    // Waiting for all goroutines created by goroutinetracker untill GOROUTINE_CLEANUP_TIMEOUT_DEFAULT(30 sec default) to finish
    // TODO: Goutham :  Do we need to log panic if unable to get shutdown from plugin in neded time?
    LogInfo("In handleShutdown(): Waiting for goroutines to finish")
    if !lomcommon.GetGoroutineTracker().WaitAll(plmgr.goRoutineCleanupTimeout) {
        LogInfo("In handleShutdown(): Timed out waiting for goroutines to finish")

        // Print running goroutine still left info to syslog
        lomcommon.PrintGoroutineInfo("")
    }

    // Clear the plugin and pluginMetadata maps
    plmgr.plugins = nil
    plmgr.pluginMetadata = nil

    // Exit the process
    LogInfo("In handleShutdown(): Exiting process")
    osExit(0)

    return nil
}

/*
 * Shutdown the plugin.
 * Invoke the plugin's shutdown method
 * Starts shutdown grace timer at its end. If the timer expires or if the shutdown is complete before timer expiry,
 * then shutdown is treated as complete.
 */
func (plmgr *PluginManager) shutdownPlugin(pluginname string) {
    plugin, ok := plmgr.plugins[pluginname]
    if !ok {
        LogInfo("In shutdownPlugin(): Plugin %s not found", pluginname)
        return
    }

    if plugin == nil {
        LogInfo("In shutdownPlugin(): Plugin %s is nil", pluginname)
        return
    }

    LogInfo("In shutdownPlugin(): Shutting down plugin %s", pluginname)

    pluginmetadata, ok := plmgr.getPluginMetadata(pluginname)
    if !ok {
        LogError("In shutdownPlugin() : Plugin %s metadata not initialized", pluginname)
        return
    }

    if pluginmetadata == nil {
        LogError("In shutdownPlugin() : Plugin %s metadata is nil", pluginname)
        return
    }

    // This is to handle a case for where plugin may be shutdown via misbehaving specific plugin logic
    if pluginmetadata.GetPluginStage() == plugins_common.PluginStageDisabled {
        LogInfo("In shutdownPlugin(): Plugin %s is already disabled", pluginname)
        return
    }

    shutdownRespCh := make(chan error, 1)

    lomcommon.GetGoroutineTracker().Start("plg_mgr_shutdownPlugin_"+pluginname+"_"+lomcommon.GetUUID(),
        func() {
            pluginmetadata.SetPluginStage(plugins_common.PluginStageShutdownStarted)
            retStatus := plugin.Shutdown()
            shutdownRespCh <- retStatus
            pluginmetadata.SetPluginStage(plugins_common.PluginStageShutdownCompleted)
        })

    // Wait for response from plugin or timeout
    select {
    case retStatus := <-shutdownRespCh:
        // Response received from plugin.
        if retStatus != nil {
            LogInfo("In shutdownPlugin(): Shutdown failed for plugin %s with error %v", pluginname, retStatus)
        } else {
            LogInfo("In shutdownPlugin(): Shutdown successful for plugin %s", pluginname)
        }
    case <-time.After(plmgr.pluginShutdownTimeout):
        LogInfo("In shutdownPlugin(): Shutdown timed out for plugin %s", pluginname)
        pluginmetadata.SetPluginStage(plugins_common.PluginStageShutdownTimeout)
    }
}

/* sendResponseToEngine : Send response to server
 * Send response to server based on the request type
 */
func (plmgr *PluginManager) sendResponseToEngine(responseObj interface{}) error {
    var serverResp interface{}
    switch resp := responseObj.(type) {
    case *lomipc.ActionResponseData:
        serverResp = &lomipc.MsgSendServerResponse{
            ReqType: lomipc.TypeServerRequestAction,
            ResData: resp,
        }
    case plugins_common.PluginHeartBeat:
        serverResp = lomipc.MsgNotifyHeartbeat{
            Action:    resp.PluginName,
            Timestamp: resp.EpochTime,
        }
    default:
        LogPanic("In sendResponseToEngine(): Unknown response type %v", responseObj)
        return nil
    }
    plmgr.responseChan <- serverResp
    return nil
}

// TODO: Goutham : Dynamic plugins are not handled in V1 cut. Add this code later
/*
 * Calls plugin init() and f its successful calls registerAction() to engine. This call may block.
 *
 * Input:
 *  pluginname - plugin name
 *  pluginVersion - plugin version
 *
 * Output:
 *  none -
 *
 * Return:
 *  error - error message or nil on success
 */
func (plmgr *PluginManager) addPlugin(pluginName string, pluginVersion string) error {
    retMsg := ""

    defer func() {
        if retMsg != "" {
            AddPeriodicLogWithTimeouts("Plgmgr_AddPlugin_"+lomcommon.GetUUID()+"_"+pluginName,
                retMsg, plmgr.pluginPeriodicTimeout, plmgr.pluginPeriodicFallbackTimeout)
        }
    }()

    // 1.Check if plugin is already loaded
    if _, ok := plmgr.getPlugin(pluginName); ok {
        retMsg = fmt.Sprintf("addPlugin : plugin with name %s and version %s is already loaded", pluginName, pluginVersion)
        return LogError(retMsg)
    }

    // 2.Get plugin specific details from actions config file and add any additional info(future) to pass to plugin's init() call
    actionCfg, err := lomcommon.GetConfigMgr().GetActionConfig(pluginName)
    if err != nil {
        retMsg = fmt.Sprintf("addPlugin : plugin %s not found in actions config file", pluginName)
        return LogError(retMsg)
    }

    // 3.Check if plugin disabled flag is set or not in the actions config file.
    if actionCfg.Disable {
        LogWarning("addPlugin : Plugin %s is disabled", pluginName)
        return nil
    }

    // 4.Create new plugin instance
    pluginID := plugins_common.PluginId{Name: pluginName, Version: pluginVersion}
    plugin, pluginmetadata, err := CreatePluginInstance(pluginID, actionCfg) // returns Plugin interface pointing to new plugin struct
    if err != nil {
        retMsg = fmt.Sprintf("addPlugin : Error creating plugin instance for %s %s: %s", pluginName, pluginVersion, err)
        return LogError(retMsg)
    }

    // 5.Check if plugin name and version from proc_conf.json file matches the values in static plugin. If not log periodic log
    if id := plugin.GetPluginID(); id.Name != pluginName || id.Version != pluginVersion {
        retMsg = fmt.Sprintf("addPlugin : Plugin ID does not match provided arguments: got %s %s, expected %s %s",
            id.Name, id.Version, pluginName, pluginVersion)
        return LogError(retMsg)
    }

    // 6. call plugin's init() call synchronously
    err = plugin.Init(actionCfg)
    if err != nil {
        retMsg = fmt.Sprintf("addPlugin : plugin %s init failed: %v", pluginName, err)
        return LogError(retMsg)
    }

    // 7. call plugin's registerAction() call synchronously
    err = plmgr.registerActionWithEngine(pluginName)
    if err != nil {
        retMsg = fmt.Sprintf("addPlugin : plugin %s registerAction failed: %v", pluginName, err)
        return LogError(retMsg)
    }

    // 8.Add plugin to plugin manager's map
    plmgr.plugins[pluginName] = plugin
    plmgr.pluginMetadata[pluginName] = pluginmetadata

    return nil
}

/* loadPlugin() : Loads plugin and calls its init() and registerAction() calls synchronously.
 * This call may block.
 * Input:
 *  pluginname - plugin name
 *  pluginVersion - plugin version
 * Output:
 *  none -
 * Return:
 *  error - error message or nil on success
 */

func (plmgr *PluginManager) loadPlugin(pluginName string, pluginVersion string) error {
    // Create a channel to receive the result of AddPlugin()
    resultChan := make(chan error, 1)

    lomcommon.GetGoroutineTracker().Start("plg_mgr_LoadPlugin_"+pluginName+"_"+lomcommon.GetUUID(), func() {
        resultChan <- plmgr.addPlugin(pluginName, pluginVersion)
    })

    // Wait for either the result or the timeout
    select {
    case err := <-resultChan:
        // AddPlugin completed within the timeout
        return err
    case <-time.After(plmgr.pluginLoadingTimeout):
        // AddPlugin timed out
        msg := fmt.Sprintf("loadPlugin : Registering plugin took too long. Skipped loading. pluginname : %s version : %s\n", pluginName, pluginVersion)
        AddPeriodicLogWithTimeouts("Plgmgr_loadPlugin_"+lomcommon.GetUUID()+"_"+pluginName,
            msg, plmgr.pluginPeriodicTimeout, plmgr.pluginPeriodicFallbackTimeout)
        return LogError(msg)
    }
    return nil
}

// RegisterActionWithEngine : Register plugin with engine
func (plmgr *PluginManager) registerActionWithEngine(pluginName string) error {
    if err := plmgr.clientTx.RegisterAction(pluginName); err != nil {
        return LogError("Failed to register plugin %s with engine", pluginName)
    }

    return nil
}

/*
 * DeRegister plugin with engine
 */
func (plmgr *PluginManager) deRegisterActionWithEngine(pluginName string) error {
    if err := plmgr.clientTx.DeregisterAction(pluginName); err != nil {
        return LogError("Failed to deregister plugin %s with engine", pluginName)
    }

    return nil
}

/*
 *   -------- Helper Functions ----------------------------------------------------------
 */

// TODO: define plugin metadata rolling window constants in config file
/*
 *  Create Plugin Instance. Multiple plugins can be created from this function
 * When a new plugin is added, add a case here to create the plugin instance and define the plugin in plugins_common package
 *
 * Input:
 *  pluginID - Plugin ID(pluginname, version) from plugins_common package
 *  pluginData - Plugin Data passed to plugin. For e.g. heartbeats timer, etc.
 *
 * Output:
 *  none -
 *
 * Return:
 *  plugin - Plugin instance
 *  pluginmetadata - Plugin metadata
 *  error - Error if any
 */
func CreatePluginInstance(pluginID plugins_common.PluginId, actionCfg *lomcommon.ActionCfg_t) (plugins_common.Plugin, plugins_common.IPluginMetadata, error) {
    constructor, found := plugins_common.PluginConstructors[pluginID.Name]
    if !found {
        return nil, nil, LogError("CreatePluginInstance : plugin not found: %s", pluginID.Name)
    }
    plugin := constructor() // creates plugin object by invoking each plugins constructor
    pluginmetadata := &plugins_common.PluginMetadata{
        ActionCfg:                    actionCfg,
        StartedTime:                  time.Now(),
        Pluginstage:                  plugins_common.PluginStageUnknown,
        PluginId:                     pluginID,
        MaxPluginResponses:           plugins_common.MAX_PLUGIN_RESPONSES_DEFAULT,
        MaxPluginResponsesWindowTime: plugins_common.MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT_DEFAULT,

        // ... other common metadata fields
    }
    return plugin, pluginmetadata, nil
}

/*
 * setup UNIX signals
 */
func SetupSignals() {
    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGTERM)

    lomcommon.GetGoroutineTracker().Start("HandleSyslogSignal"+lomcommon.GetUUID(),
        func() {
            for {
                // Wait for a signal to be received
                val, ok := <-signalChan
                if ok {
                    switch val {
                    case syscall.SIGTERM:
                        LogWarning("Received SIGTERM signal. Exiting plugin mgr:%s", ProcID)
                        osExit(0)
                    }
                }
            }
        })
}

/*
 * parse program command line arguments
 */

func ParseArguments() {
    // Create a new flag set
    fs := flag.NewFlagSet("customFlags", flag.ExitOnError)

    // Declare the command line flags
    var ProcIDFlag string
    var syslogLevelFlag int

    // Define the command line flags
    fs.StringVar(&ProcIDFlag, "proc_id", "", "Proc ID string")
    fs.IntVar(&syslogLevelFlag, "syslog_level", 7, "Syslog level")

    // Parse the command line arguments
    fs.Parse(os.Args[1:])

    if ProcIDFlag == "" {
        LogPanic("Exiting : Proc ID is not provided")
        return
    }

    // assign to variables which can be accessed from process
    ProcID = ProcIDFlag
    lomcommon.SetLogLevel(syslog.Priority(syslogLevelFlag))

    fmt.Printf("Program Arguments : proc ID : %s, Syslog Level : %d\n", ProcIDFlag, syslogLevelFlag)
}

/*
 * Setup Functions --------------------------------------------------------------------------------------------
 */

/*
 * Start Plugin Manager - Create Plugin Manager, read each plugin name and its parameters from actions_conf file & Setup each plugin
    * Input:
    *  waittime - 0 for infinite wait,  >0 for wait time in seconds
    * Output:
    *  none -
*/
func StartPluginManager(waittime time.Duration) error {
    // Create & Start Plugin Manager and do registration with engine
    vclientTx := lomipc.GetClientTx(int(GOLIB_TIMEOUT_DEFAULT))
    vpluginManager := GetPluginManager(vclientTx)
    if vpluginManager == nil {
        return LogError("StartPluginManager : Error creating plugin manager")
    }
    LogInfo("StartPluginManager : Plugin Manager created successfully")

    /* For a particular proc_X, read each plugin name and its parameters from proc_conf.json file &
       Setup each plugin */
    procInfo, err := lomcommon.GetConfigMgr().GetProcsConfig(ProcID)
    if err != nil {
        vpluginManager = nil
        return LogError("StartPluginManager : Error getting proc config for proc %s: %v", ProcID, err)
    }

    // TODO: Goutham : Note : Dynamic Plugins is not supported in V1 release. So no code is implemented for dynamic plugins
    for pluginname, plconfig := range procInfo {
        LogInfo("StartPluginManager : Initializing plugin %s version %s", pluginname, plconfig.Version)
        errv := vpluginManager.loadPlugin(pluginname, plconfig.Version)
        if errv != nil {
            LogError("StartPluginManager : Error Initializing plugin %s version %s : %v", pluginname, plconfig.Version, errv)
        } else {
            vpluginManager.pluginMetadata[pluginname].SetPluginStage(plugins_common.PluginStageLoadingSuccess)
            LogInfo("StartPluginManager : plugin %s version %s successfully Initialized", pluginname, plconfig.Version)
        }
    }

    lomcommon.GetGoroutineTracker().Start("StartPluginManager_"+ProcID+lomcommon.GetUUID(),
        vpluginManager.run)

    // blocks until all goroutines are done or untill timeout
    lomcommon.GetGoroutineTracker().WaitAll(waittime)

    // Reaches herer only when plugin manager is stopped

    return nil
}

/*
 * Setup Plugin Manager  - Parse program arguments, setup syslog signals, load environment variables, validate config files, etc
 */
func SetupPluginManager() error {

    //parse program arguments & assign values to program variables. Hree proc_X value is read
    ParseArguments()

    // setup application prefix for logging
    lomcommon.SetPrefix(APP_NAME_DEAULT + ProcID)

    //syslog level change from UNIX signals
    SetupSignals()
    LogInfo("SetupPluginManager : Successfully setup signals")

    // Initialize the config manager. This will read ENV config path location and  will read config files for attributes from there
    val, _ := lomcommon.GetEnvVarString("ENV_lom_conf_location")
    err := lomcommon.InitConfigPath(val)
    if err != nil {
        LogError("SetupPluginManager : Error initializing config manager: %s", err)
    }

    return nil
}
