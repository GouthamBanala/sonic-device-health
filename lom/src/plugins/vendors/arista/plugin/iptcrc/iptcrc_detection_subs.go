//go:build ignore
// +build ignore

/*
 * Arista IPTCRC Detection Plugin with TLS Security
 *
 * This plugin is designed to detect IPTCRC errors for Arista switches. It subscribes to GNMI notifications from the GNMI server,
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
    "time"
)

/* Global Constants */
const (
    detection_plugin_name    = "iptcrc_detection"
    detection_plugin_prefix  = "iptcrc_detection"
    detection_plugin_version = "1.0.0.0"
    sand_counters_gnmi_path  = arista_common.SandCountersGnmiPath
    gnmi_subscription_prefix = ""

    error_backoff_time_default             = 60 // seconds
    periodic_subscription_interval_default = 24 // 24 hours
    iptcrc_counter_name_default            = "IptCrcErrCnt"

    /* Config Keys for accessing cfg file */
    initial_detection_reporting_freq_in_mins_config_key    = "initial_detection_reporting_frequency_in_mins"
    subsequent_detection_reporting_freq_in_mins_config_key = "subsequent_detection_reporting_frequency_in_mins"
    initial_detection_reporting_max_count_config_key       = "initial_detection_reporting_max_count"
    periodic_subscription_interval_in_hours_config_key     = "periodic_subscription_interval_in_hours"
    error_backoff_time_in_secs_config_key                  = "error_backoff_time_in_secs"
    iptcrc_counter_name_config_key                         = "iptcrc_test_counter_name"
    chipid_name_mappings_file_config_key                   = "chipid_name_mappings_file"
)

/* default logger */
var logger *plugins_common.PluginLogger

type IPTCRCDetectionPlugin struct {
    reportingFreqLimiter                       plugins_common.PluginReportingFrequencyLimiterInterface // Stores Count & Timestamp of gnmi notification for each chipId
    plugins_common.SubscriptionBasedPluginUtil                                                         // Util to handle the subscription based plugin
    aristaGnmiSession                          plugins_common.IGNMISession                             // Helpers to communicate with GNMI server
    runningChipDataMap                         map[string]*arista_common.LCChipData                    // Map to store the chipId and its corresponding LCChipData extracted from gnmi notifications
    subscriptionPaths                          []string                                                // List of subscription paths for this plugin
    error_backoff_time_secs                    int                                                     // In sec. used to backoff when there is an error in gnmi subscription
    periodic_subscription_interval_hours       int                                                     // In hours. used to restart the gnmi subscription periodically
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
    iptCRCDetectionPlugin.error_backoff_time_secs = error_backoff_time_default
    iptCRCDetectionPlugin.periodic_subscription_interval_hours = periodic_subscription_interval_default
    iptCRCDetectionPlugin.counterName = iptcrc_counter_name_default
    chipid_name_mappings_file := ""

    // Get config settings from config files or assign default values.
    var resultMap map[string]interface{}
    jsonErr := json.Unmarshal([]byte(actionConfig.ActionKnobs), &resultMap)
    if jsonErr == nil {
        initial_detection_reporting_frequency_in_mins = lomcommon.GetConfigFromMapping(resultMap, initial_detection_reporting_freq_in_mins_config_key, lomcommon.GetConfigMgr().GetGlobalCfgInt("INITIAL_DETECTION_REPORTING_FREQ_IN_MINS")).(int)
        subsequent_detection_reporting_frequency_in_mins = lomcommon.GetConfigFromMapping(resultMap, subsequent_detection_reporting_freq_in_mins_config_key, lomcommon.GetConfigMgr().GetGlobalCfgInt("SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS")).(int)
        initial_detection_reporting_max_count = lomcommon.GetConfigFromMapping(resultMap, initial_detection_reporting_max_count_config_key, lomcommon.GetConfigMgr().GetGlobalCfgInt("INITIAL_DETECTION_REPORTING_MAX_COUNT")).(int)
        iptCRCDetectionPlugin.error_backoff_time_secs = lomcommon.GetConfigFromMapping(resultMap, error_backoff_time_in_secs_config_key, error_backoff_time_default).(int)
        iptCRCDetectionPlugin.periodic_subscription_interval_hours = lomcommon.GetConfigFromMapping(resultMap, periodic_subscription_interval_in_hours_config_key, periodic_subscription_interval_default).(int)
        iptCRCDetectionPlugin.counterName = lomcommon.GetConfigFromMapping(resultMap, iptcrc_counter_name_config_key, iptcrc_counter_name_default).(string)
        chipid_name_mappings_file = lomcommon.GetConfigFromMapping(resultMap, chipid_name_mappings_file_config_key, "").(string)
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

    // Initialize the common SubscriptionBasedPluginUtil utility
    err = iptCRCDetectionPlugin.SubscriptionBasedPluginUtil.Init(actionConfig.Name, actionConfig, iptCRCDetectionPlugin.executeIPTCRCDetection,
        iptCRCDetectionPlugin.executeShutdown, logger, iptCRCDetectionPlugin.error_backoff_time_secs)
    if err != nil {
        return logger.LogError("Failed to initialize SubscriptionBasedPluginUtil: %v", err)
    }

    // Create a new GNMI session with the Arista GNMI server(mutex lock not needed)
    iptCRCDetectionPlugin.aristaGnmiSession, err = plugins_common.NewGNMISession(nil, nil, nil)
    if err != nil {
        return logger.LogError("Failed to create arista gnmi server session : %v", err)
    }
    iptCRCDetectionPlugin.sessionValid = true

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
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) executeIPTCRCDetection(request *lomipc.ActionRequestData, ctx context.Context, restartConnection bool) (*lomipc.ActionResponseData, error) {
    logger.LogInfo("IPTCRC Detection Starting, restartConnection: %v", restartConnection)

    // Create a timer with a large initial duration
    timer := time.NewTimer(time.Hour * time.Duration(iptCRCDetectionPlugin.periodic_subscription_interval_hours))

    // Flag to track if a shutdown has been initiated
    shutdownInitiated := false

    defer func() {
        iptCRCDetectionPlugin.sessionMutex.Lock()
        defer iptCRCDetectionPlugin.sessionMutex.Unlock()

        if iptCRCDetectionPlugin.sessionValid {
            iptCRCDetectionPlugin.aristaGnmiSession.Unsubscribe()
            if shutdownInitiated {
                if err := iptCRCDetectionPlugin.aristaGnmiSession.Close(); err != nil {
                    logger.LogError("Failed to close arista gnmi server session: %v", err)
                }
                iptCRCDetectionPlugin.sessionValid = false
            }
        }
        timer.Stop()
    }()

    // Restart the GNMI session if requested.
    if restartConnection {
        iptCRCDetectionPlugin.sessionMutex.Lock()
        err := iptCRCDetectionPlugin.restartNewGNMISession()
        iptCRCDetectionPlugin.sessionMutex.Unlock()
        if err != nil {
            return nil, err
        }
    }

    // Main loop for processing GNMI notifications and handling anomalies
    for {
        // Update the timer to the nearest expiry time from the reported anomalies
        iptCRCDetectionPlugin.updateTimer(timer)

        // Subscribe for GNMI notifications
        iptCRCDetectionPlugin.sessionMutex.Lock()
        err := iptCRCDetectionPlugin.aristaGnmiSession.Resubscribe(gnmi_subscription_prefix, iptCRCDetectionPlugin.subscriptionPaths)
        iptCRCDetectionPlugin.sessionMutex.Unlock()
        if err != nil {
            logger.LogError("Failed to subscribe to gnmi paths: %v", err)
            return nil, &plugins_common.SubscribeError{Err: err}
        }

        // Get the subscripton notification channel to receive the gnmi notifications
        iptCRCDetectionPlugin.sessionMutex.Lock()
        notificationsCh, notificationErrCh, err := iptCRCDetectionPlugin.aristaGnmiSession.Receive()
        iptCRCDetectionPlugin.sessionMutex.Unlock()
        if err != nil {
            logger.LogError("Failed to receive GNMI notifications : %v", err)
            return nil, &plugins_common.ReceiveError{Err: err}
        }

        // Main State Machine
    Loop:
        for {
            select {
            case <-ctx.Done():
                // Shutdown has been initiated, stop processing updates
                logger.LogInfo("Shutdown initiated, stopping executeIPTCRCDetection")
                shutdownInitiated = true
                return nil, &plugins_common.ShutdownError{Err: ctx.Err()}

            // notificationsCh is used to receive gnmi subscription notifications
            case notification, ok := <-notificationsCh:
                if !ok {
                    logger.LogInfo("GNNMI Subscribe Notifications channel has been closed")
                    return nil, &plugins_common.ChannelClosedError{}
                }

                if notification == plugins_common.SubscriptionCancelled {
                    logger.LogInfo("GNNMI Subscribe Notifications channel has been cancelled")
                    return nil, &plugins_common.SubscriptionCancelledError{}
                }

                // process gnmi subscribe notification to extract the IPTCRC error details
                chipsWithIPTCRCErrorToReport, chipsWithIPTCRCErrorToDelete, err := iptCRCDetectionPlugin.processGNMINotification(notification)
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
                    return res, nil
                }

                // Delete the anomaly if there are any chips with IPTCRC error to be cleared
                if len(chipsWithIPTCRCErrorToDelete) > 0 {
                    logger.LogInfo("IPTCRCDetection Anomaly Cleared")
                    logger.LogInfo("Chips with IPTCRC error cleared: %v", chipsWithIPTCRCErrorToDelete)

                    iptCRCDetectionPlugin.checkForClearedErrors(chipsWithIPTCRCErrorToDelete)
                }

                // Update the timer to the nearest expiry time from the reported anomalies
                iptCRCDetectionPlugin.updateTimer(timer)

            case <-timer.C:
                logger.LogInfo("Timer expired, resubscribing to GNMI paths")
                break Loop

            // notificationErrCh is used to receive any errors from the gnmi subscription session
            case err, ok := <-notificationErrCh:
                if !ok {
                    logger.LogInfo("GNMI SUbscription Error channel has been closed")
                    return nil, &plugins_common.SubscriptionCancelledError{}
                } else {
                    logger.LogError("Error received from GNMI subscriptioon session: %v\n", err)
                    return nil, &plugins_common.SubscribeprotocolError{Err: err}
                }
            }
        }
    }
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
* checkForClearedErrors checks for any previously reported anomalies that are no longer present in the current reported ones.
* It iterates over the provided list of chips with IPTCRC errors and removes any matching entries from the runningChipDataMap.
* It also deletes the corresponding entry from the reporting frequency limiter cache.
*
* Parameters:
* - chipsWithIPTCRCError: A slice of strings. Each string is the name of a chip with an IPTCRC error.
*
* Returns: None
 */
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) checkForClearedErrors(chipsWithIPTCRCError []string) {
    for _, chipId := range chipsWithIPTCRCError {
        if _, ok := iptCRCDetectionPlugin.runningChipDataMap[chipId]; ok {
            // This chip is in the list of chips with IPTCRC error to be cleared
            delete(iptCRCDetectionPlugin.runningChipDataMap, chipId)
            // reset limiter freq when detection is false.
            iptCRCDetectionPlugin.reportingFreqLimiter.DeleteCache(chipId)
        }
    }
}

/*
* restartNewGNMISession closes the current GNMI session and creates a new one.
*
* Parameters: None
*
* Returns:
* - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 */
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) restartNewGNMISession() error {
    if iptCRCDetectionPlugin.sessionValid {
        iptCRCDetectionPlugin.aristaGnmiSession.Unsubscribe()
        err := iptCRCDetectionPlugin.aristaGnmiSession.Close()
        if err != nil {
            logger.LogError("Failed to close arista gnmi server session: %v", err)
        }
        iptCRCDetectionPlugin.sessionValid = false
    }

    // Create a new GNMI session with the Arista GNMI server
    var err error
    iptCRCDetectionPlugin.aristaGnmiSession, err = plugins_common.NewGNMISession(nil, nil, nil)
    if err != nil {
        logger.LogError("Failed to create arista gnmi server session : %v", err)
        iptCRCDetectionPlugin.sessionValid = false
        return &plugins_common.SessionCreationError{Err: err}
    }
    iptCRCDetectionPlugin.sessionValid = true
    return nil
}

/*
* updateTimer updates the timer based on the nearest expiry time from the reported anomalies.
*
* The function first gets the next expiry time from the reported anomalies. If the next expiry time is not zero,
* this means there are reported anomalies, so the function resets the timer to the nearest expiry time.
* If the next expiry time is zero, this means there are no reported anomalies, so the function resets the timer to 24 hours.
*
* Parameters:
* - timer: A pointer to a time.Timer instance. This is the timer to be updated.
*
* Returns: None
 */
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) updateTimer(timer *time.Timer) {
    _, nextExpiry := iptCRCDetectionPlugin.reportingFreqLimiter.GetNextExpiry()
    if !nextExpiry.IsZero() {
        // non zero expiry time means there are reported anomalies. So, reset the timer to the nearest expiry time
        durationUntilNextExpiry := time.Until(nextExpiry)
        if durationUntilNextExpiry < 0 {
            // expiry time is in the past. This is possible since we are always adding 1 second to the expiry time
            durationUntilNextExpiry = 0 * time.Second // reset immediately after 1 second if expiry time is in the past
        }

        timer.Reset(durationUntilNextExpiry + 1*time.Second) // add 1 second to the expiry time to ensure the timer is reset after the expiry time
    } else {
        // zero expiry time means there are no reported anomalies. So, Reset the timer to 24 hours
        timer.Reset(time.Duration(iptCRCDetectionPlugin.periodic_subscription_interval_hours) * time.Hour)
    }
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
func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) processGNMINotification(notification interface{}) ([]string, []string, error) {
    // process gnmi subscribe notification
    parsedNotification, err := plugins_common.ParseNotification(notification)
    if err != nil {
        logger.LogError("Failed to parse gnmi subscription notification: %v", err)
        return nil, nil, err
    }

    // **** Signal to resume heartbeats as the subscription is healthy at this point ****
    iptCRCDetectionPlugin.SubscriptionBasedPluginUtil.NotifyAsHealthySubscription()

    // get the prefix from the notification
    vprefix, err := plugins_common.GetPrefix(parsedNotification)
    if err != nil {
        logger.LogError("Failed to get prefix from gnmi notification: %v", err)
        return nil, nil, err
    }
    vprefixStr := "/" + strings.Join(vprefix, "/")

    // path notification can be 3 types
    // 1. standard gnmi path update notification for sand_counters_gnmi_path
    // 2. standard gnmi path delete notification for sand_counters_gnmi_path
    // 3. standard gnmi path update notification for sand_counters_gnmi_path with prefix ending in _counts.
    // This is a special case for arista switches which gives the no of entries in the table.
    notificationType := plugins_common.CheckNotificationType(parsedNotification)

    logger.LogInfo("executeIPTCRCDetection - handling prefix: %s for notification type: %s counter Name : %s", vprefixStr, notificationType, iptCRCDetectionPlugin.counterName)

    // Check if the notification is for Standard gnmi path and not for prefix ending in _counts
    if vprefixStr == sand_counters_gnmi_path {
        if notificationType == "update" {
            // process gnmi update notification

            // parse the notification updates to get the IPTCRC counter details
            counterDetailsMap, err := arista_common.GetSandCounterUpdates(parsedNotification, iptCRCDetectionPlugin.counterName)
            if err != nil {
                logger.LogError("Failed to get IPTCRC counter updates from gnmi notification: %v", err)
                return nil, nil, err
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
            return chipsWithIPTCRCErrorToReport, nil, nil
        } else if notificationType == "delete" {
            // process gnmi delete notification

            // parse the notification deletes to get the IPTCRC counter details
            counterDetailsMap, err := arista_common.GetSandCounterDeletes(parsedNotification, iptCRCDetectionPlugin.counterName)
            if err != nil {
                logger.LogError("Failed to get IPTCRC counter deletes from gnmi notification: %v", err)
                return nil, nil, err
            }

            // Stores the list of chipId's with IPTCRC error to be cleared
            var chipsWithIPTCRCErrorToClear []string

            // map keys are the chipId's with IPTCRC error to be cleared
            for chipId := range counterDetailsMap {
                chipsWithIPTCRCErrorToClear = append(chipsWithIPTCRCErrorToClear, chipId)
            }
            return nil, chipsWithIPTCRCErrorToClear, nil
        }
    }

    return nil, nil, fmt.Errorf("executeIPTCRCDetection - ignoring prefix: %s", vprefixStr)
}

func (iptCRCDetectionPlugin *IPTCRCDetectionPlugin) executeShutdown() error {
    logger.LogInfo("Shutdown initiated for (%s)", detection_plugin_name)

    iptCRCDetectionPlugin.sessionMutex.Lock()
    defer iptCRCDetectionPlugin.sessionMutex.Unlock()

    if iptCRCDetectionPlugin.sessionValid {
        iptCRCDetectionPlugin.aristaGnmiSession.Unsubscribe()
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
