/*
 * Arista IPTCRC Detection Plugin with TLS Security
 *
 * This plugin is designed to detect IPTCRC errors for Arista switches. It does get request to GNMI path from the GNMI server,
 * processes those notifications, and reports any anomalies found. Specifically, it listens to the "sand_counters_gnmi_path" for
 * notifications about IPTCRC errors.
 *
 * The plugin operates by creating a secure GNMI session with the Arista GNMI server using TLS, subscribing to the GNMI notifications,
 * and processing those notifications in a loop. When a notification is received, the plugin parses the notification, extracts the
 * IPTCRC counter details, and checks for any anomalies. If an anomaly is detected, it is reported to the Engine.
 *
 * The plugin also includes functionality for handling shutdowns, restarting the GNMI session, and updating a timer based on the
 * nearest expiry time from the reported anomalies.
 *
 * The plugin is initialized with a set of default values, which can be overridden by configuration settings from config files.
 * This includes the TLS security parameters such as the CA certificate, client certificate, and client key, which are used to
 * establish a secure connection to the GNMI server.
 *
 * The plugin is registered with the plugin manager under the name "iptcrc_detection".
 */

package iptcrc

import (
    "context"
    "encoding/json"
    "fmt"
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    plugins_common "lom/src/plugins/plugins_common"
    "lom/src/plugins/vendors/arista/arista_common"
    "strings"
    "sync"
)

/* Global Constants */
const (
    detection_plugin_name    = "iptcrc_detection"
    detection_plugin_prefix  = "iptcrc_detection"
    detection_plugin_version = "1.0.0.0"
    sand_counters_gnmi_path  = arista_common.SandCountersGnmiPath
    gnmi_subscription_prefix = ""

    detection_freq_in_secs_default = 30 // seconds
    iptcrc_counter_name_default    = "IptCrcErrCnt"

    /* Config Keys for accessing cfg file */
    initial_detection_reporting_freq_in_mins_config_key    = "initial_detection_reporting_frequency_in_mins"
    subsequent_detection_reporting_freq_in_mins_config_key = "subsequent_detection_reporting_frequency_in_mins"
    initial_detection_reporting_max_count_config_key       = "initial_detection_reporting_max_count"
    periodic_subscription_interval_in_hours_config_key     = "periodic_subscription_interval_in_hours"
    error_backoff_time_in_secs_config_key                  = "error_backoff_time_in_secs"
    iptcrc_counter_name_config_key                         = "iptcrc_test_counter_name"
    chipid_name_mappings_file_config_key                   = "chipid_name_mappings_file"
    detection_freq_in_secs_config_key                      = "DetectionFreqInSecs"
)

/* default logger */
var logger *plugins_common.PluginLogger

type IPTCRCDetectionPlugin struct {
    reportingFreqLimiter                       plugins_common.PluginReportingFrequencyLimiterInterface // Stores Count & Timestamp of gnmi notification for each chipId
    plugins_common.PeriodicDetectionPluginUtil                                                         // Util to handle the subscription based plugin
    aristaGnmiSession                          plugins_common.IGNMISession                             // Helpers to communicate with GNMI server
    runningChipDataMap                         map[string]*arista_common.LCChipData                    // Map to store the chipId and its corresponding LCChipData extracted from gnmi notifications
    subscriptionPaths                          []string                                                // List of subscription paths for this plugin
    sessionMutex                               sync.Mutex                                              // Mutex to ensure thread-safe access to aristaGnmiSession
    sessionValid                               bool                                                    // Flag to indicate if the GNMI session is valid
    counterName                                string                                                  // Name of the counter to be monitored
}

/* Return a new instance of the plugin */
func NewIPTCRCDetectionPlugin(...interface{}) plugins_common.Plugin {
    return &IPTCRCDetectionPlugin{}
}

/* Register the plugin with the plugin manager */
func init() {
    plugins_common.RegisterPlugin(detection_plugin_name, NewIPTCRCDetectionPlugin)
}

/*
 * Init initializes the IPTCRCDetectionPlugin. It is called by the plugin manager when the plugin is loaded.
 *
 * Parameters:
 * - actionConfig: A pointer to a lomcommon.ActionCfg_t instance. This contains the configuration for the plugin.
 *
 * Returns:
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 */
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) Init(actionConfig *lomcommon.ActionCfg_t) error {
    lomcommon.LogInfo("Started Init() for (%s)", detection_plugin_name)

    //Initialize the logger
    if logger == nil {
        logger = plugins_common.NewDefaultLogger(detection_plugin_prefix)
    }

    // Check if the plugin name is valid
    if actionConfig.Name != detection_plugin_name {
        return logger.LogError("Invalid plugin name passed. actionConfig.Name: %s", actionConfig.Name)
    }

    // Set defaults
    initial_detection_reporting_frequency_in_mins := lomcommon.GetConfigMgr().GetGlobalCfgInt("INITIAL_DETECTION_REPORTING_FREQ_IN_MINS")
    subsequent_detection_reporting_frequency_in_mins := lomcommon.GetConfigMgr().GetGlobalCfgInt("SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS")
    initial_detection_reporting_max_count := lomcommon.GetConfigMgr().GetGlobalCfgInt("INITIAL_DETECTION_REPORTING_MAX_COUNT")
    iptCRCDetectionPlugin.counterName = iptcrc_counter_name_default
    chipid_name_mappings_file := ""
    detectionFreqInSecs := int(detection_freq_in_secs_default)

    // Get config settings from config files or assign default values.
    var resultMap map[string]interface{}
    jsonErr := json.Unmarshal([]byte(actionConfig.ActionKnobs), &resultMap)
    if jsonErr == nil {
        initial_detection_reporting_frequency_in_mins = lomcommon.GetConfigFromMapping(resultMap, initial_detection_reporting_freq_in_mins_config_key, lomcommon.GetConfigMgr().GetGlobalCfgInt("INITIAL_DETECTION_REPORTING_FREQ_IN_MINS")).(int)
        subsequent_detection_reporting_frequency_in_mins = lomcommon.GetConfigFromMapping(resultMap, subsequent_detection_reporting_freq_in_mins_config_key, lomcommon.GetConfigMgr().GetGlobalCfgInt("SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS")).(int)
        initial_detection_reporting_max_count = lomcommon.GetConfigFromMapping(resultMap, initial_detection_reporting_max_count_config_key, lomcommon.GetConfigMgr().GetGlobalCfgInt("INITIAL_DETECTION_REPORTING_MAX_COUNT")).(int)
        iptCRCDetectionPlugin.counterName = lomcommon.GetConfigFromMapping(resultMap, iptcrc_counter_name_config_key, iptcrc_counter_name_default).(string)
        chipid_name_mappings_file = lomcommon.GetConfigFromMapping(resultMap, chipid_name_mappings_file_config_key, "").(string)
        detectionFreqInSecs = int(lomcommon.GetFloatConfigFromMapping(resultMap, detection_freq_in_secs_config_key, detection_freq_in_secs_default))
    } else {
        logger.LogError("Failed to parse actionConfig.ActionKnobs: %v. Using defaults", jsonErr)
    }

    // Initialize the reporting frequency limiter for this plugin
    iptCRCDetectionPlugin.reportingFreqLimiter = plugins_common.GetDetectionFrequencyLimiter(initial_detection_reporting_frequency_in_mins, subsequent_detection_reporting_frequency_in_mins, initial_detection_reporting_max_count)

    // Initialize the runningChipDataMap to store the chipId and its corresponding linecard details extracted from gnmi notifications
    iptCRCDetectionPlugin.runningChipDataMap = make(map[string]*arista_common.LCChipData)

    // Initialize the chipId to chipName mapping
    var err error
    err = arista_common.LoadChipMappings(chipid_name_mappings_file)
    if err != nil {
        return logger.LogError("Failed to initialize chipId to chipName mapping: %v", err)
    }

    // Initialize the common PeriodicDetectionPluginUtil utility
    err = iptCRCDetectionPlugin.PeriodicDetectionPluginUtil.Init(actionConfig.Name, detectionFreqInSecs, actionConfig, iptCRCDetectionPlugin.executeIPTCRCDetection,
        iptCRCDetectionPlugin.executeShutdown)
    if err != nil {
        return logger.LogError("Failed to initialize SubscriptionBasedPluginUtil: %v", err)
    }

    // Define the subscription paths for this plugin
    iptCRCDetectionPlugin.subscriptionPaths = []string{
        sand_counters_gnmi_path,
    }

    logger.LogInfo("Successfully Init() for (%s)", detection_plugin_name)
    return nil
}

/*
 * executeIPTCRCDetection starts the IPTCRC detection process, which involves subscribing to GNMI notifications,
 * processing those notifications, and reporting any anomalies found.
 *
 * Parameters:
 * - request: A pointer to a lomipc.ActionRequestData instance. This represents the request data for the action.
 * - ctx: A context.Context instance. This is used for managing the lifecycle of the function.
 * - restartConnection: A boolean flag indicating whether to restart the GNMI session.
 *
 * Returns:
 * - A pointer to a lomipc.ActionResponseData instance. This represents the response data for the action.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 *
 * If the context is done (i.e., a shutdown has been initiated), the function stops processing updates and returns.
 */
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) executeIPTCRCDetection(request *lomipc.ActionRequestData, isExecutionHealthy *bool, ctx context.Context) *lomipc.ActionResponseData {
    logger.LogInfo("IPTCRC Detection Starting")

    // Create a new GNMI session with the Arista GNMI server(mutex lock not needed). Note that new session is not created if the session is already valid.
    var err error
    iptCRCDetectionPlugin.aristaGnmiSession, err = plugins_common.NewGNMISession(nil, nil, nil)
    if err != nil {
        logger.LogError("Failed to create arista gnmi server session : %v", err)
        *isExecutionHealthy = false
        return nil
    }
    iptCRCDetectionPlugin.sessionValid = true

    defer func() {
        iptCRCDetectionPlugin.sessionMutex.Lock()
        defer iptCRCDetectionPlugin.sessionMutex.Unlock()
        if iptCRCDetectionPlugin.sessionValid {
            if err := iptCRCDetectionPlugin.aristaGnmiSession.Close(); err != nil {
                logger.LogError("Failed to close arista gnmi server session: %v", err)
            }
            iptCRCDetectionPlugin.sessionValid = false
        }
    }()

    // get the counters via gnmi get request
    response, err := iptCRCDetectionPlugin.aristaGnmiSession.Get(gnmi_subscription_prefix, iptCRCDetectionPlugin.subscriptionPaths)
    if err != nil {
        logger.LogError("Failed to get counters via gnmi get request: %v", err)
        *isExecutionHealthy = false
        return nil
    }

    // process the gnmi get response to get the IPTCRC counter details
    notifications, err := iptCRCDetectionPlugin.aristaGnmiSession.ProcessGet(response)
    if err != nil {
        logger.LogError("Failed to process gnmi get response: %v", err)
        *isExecutionHealthy = false
        return nil
    }

    *isExecutionHealthy = true

    // process gnmi notification to extract the IPTCRC error details
    for _, notification := range notifications {
        select {
        case <-ctx.Done():
            logger.LogInfo("Aborting processing updates")
            return nil
        default:
        }

        chipsWithIPTCRCErrorToReport, err := iptCRCDetectionPlugin.processGNMINotification(notification)
        if err != nil {
            logger.LogError("Failed to process gnmi subscription notification: %v", err)
            continue
        }

        // Report the anomaly if there are any chips with IPTCRC error to Engine
        // To-Do - Goutham : Need to break it in to multiple instances with each instance as a separate anomaly
        if len(chipsWithIPTCRCErrorToReport) > 0 {
            logger.LogInfo("IPTCRCDetection Anomaly Detected")
            logger.LogInfo("Chips with IPTCRC error: %v", chipsWithIPTCRCErrorToReport)

            // Convert chip IDs to chip names
            chipsWithIPTCRCErrorNames := make([]string, len(chipsWithIPTCRCErrorToReport))
            for i, chipId := range chipsWithIPTCRCErrorToReport {
                chipsWithIPTCRCErrorNames[i] = iptCRCDetectionPlugin.runningChipDataMap[chipId].ChipName
            }

            res := iptCRCDetectionPlugin.reportAnomalies(request, chipsWithIPTCRCErrorNames)
            // To-Do - Goutham : Here we are returning the response for the first anomaly skipping the rest of the anomalies. Although engine will call request again and we may
            // report the rest of the anomalies in the next call. Need to check if this is the expected behavior.
            return res
        }
    }
    return nil
}

// Helper to create response object to Report anomalies
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) reportAnomalies(request *lomipc.ActionRequestData, chipsWithIPTCRCError []string) *lomipc.ActionResponseData {
    return plugins_common.GetResponse(request,
        strings.TrimSuffix(strings.Join(chipsWithIPTCRCError, ","), ","),
        "Detected IPTCRC",
        plugins_common.ResultCodeSuccess,
        plugins_common.ResultStringSuccess)
}

/*
 * processGNMINotification processes a GNMI notification and returns a list of chips with IPTCRC errors.
 *
 * Parameters:
 * - notification: An interface{} instance. This represents the GNMI notification to be processed.
 *
 * Returns:
 * - A slice of strings. Each string is the ID  of a chip with an IPTCRC error to be reported.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 */
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) processGNMINotification(notification interface{}) ([]string, error) {
    // process gnmi notification
    parsedNotification, err := plugins_common.ParseNotification(notification)
    if err != nil {
        logger.LogError("Failed to parse gnmi subscription notification: %v", err)
        return nil, err
    }

    // get the prefix from the notification
    vprefix, err := plugins_common.GetPrefix(parsedNotification)
    if err != nil {
        logger.LogError("Failed to get prefix from gnmi notification: %v", err)
        return nil, err
    }
    vprefixStr := "/" + strings.Join(vprefix, "/")

    // path notification for get can be 2 types
    // 1. standard gnmi path update notification for sand_counters_gnmi_path
    // 2. standard gnmi path update notification for sand_counters_gnmi_path with prefix ending in _counts.
    // This is a special case for arista switches which gives the no of entries in the table.
    notificationType := plugins_common.CheckNotificationType(parsedNotification)

    logger.LogInfo("executeIPTCRCDetection - handling prefix: %s for notification type: %s, counter Name :  %s", vprefixStr, notificationType, iptCRCDetectionPlugin.counterName)

    // Check if the notification is for Standard gnmi path and not for prefix ending in _counts
    if vprefixStr == sand_counters_gnmi_path {
        if notificationType == "update" {
            // process gnmi update notification

            // parse the notification updates to get the IPTCRC counter details
            counterDetailsMap, err := arista_common.GetSandCounterUpdates(parsedNotification, iptCRCDetectionPlugin.counterName)
            if err != nil {
                logger.LogError("Failed to get IPTCRC counter updates from gnmi notification: %v", err)
                return nil, err
            }

            // Stores the list of chipId's with IPTCRC error to be reported
            var chipsWithIPTCRCErrorToReport []string

            // loop through the counterDetailsMap map to detect the IPTCRC error
            for chipId, counterDetails := range counterDetailsMap {
                // serialize the counterDetails to currentChipData struct which has all the IPTCRC related counter details for current chipId
                currentChipData, err := arista_common.ConvertToChipData(counterDetails)
                if err != nil {
                    logger.LogError("Failed to serialize counter details for chip %s: %v", chipId, err)
                    continue
                }

                // If drop count is > 0, treat it as anomaly
                if currentChipData.DropCount > 0 {
                    // check if this chipid can be reported or not based on the reporting frequency
                    if iptCRCDetectionPlugin.reportingFreqLimiter.ShouldReport(chipId) {
                        // report this chip as IPTCRC error
                        chipsWithIPTCRCErrorToReport = append(chipsWithIPTCRCErrorToReport, chipId)
                    } else {
                        // If the reporting frequency is not met, then skip reporting for this chip
                        logger.LogInfo("executeIPTCRCDetection - skipping reporting for chip %s as reporting frequency is not met", chipId)
                    }
                    iptCRCDetectionPlugin.runningChipDataMap[chipId] = currentChipData
                } else {
                    // invalid drop count value
                    logger.LogInfo("executeIPTCRCDetection - invalid drop count value %d for chip %s", currentChipData.DropCount, chipId)
                    continue
                }
            }
            return chipsWithIPTCRCErrorToReport, nil
        }
    }

    return nil, fmt.Errorf("executeIPTCRCDetection - ignoring prefix: %s", vprefixStr)
}

func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) executeShutdown() error {
    logger.LogInfo("Shutdown initiated for (%s)", detection_plugin_name)

    iptCRCDetectionPlugin.sessionMutex.Lock()
    defer iptCRCDetectionPlugin.sessionMutex.Unlock()

    if iptCRCDetectionPlugin.sessionValid {
        //iptCRCDetectionPlugin.aristaGnmiSession.Unsubscribe()
        err := iptCRCDetectionPlugin.aristaGnmiSession.Close()
        if err != nil {
            logger.LogError("Failed to close arista gnmi server session: %v", err)
        }
        //iptCRCDetectionPlugin.aristaGnmiSession = nil
        iptCRCDetectionPlugin.sessionValid = false
    }
    logger.LogInfo("Shutdown completed for (%s)", detection_plugin_name)
    return nil
}

func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    detection_plugin_name,
        Version: "1.0.0.0",
    }
}
