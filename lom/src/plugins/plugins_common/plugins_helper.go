/* This file contains helper utils that plugins can use to perform their actions/tasks */
package plugins_common

import (
    "container/list"
    "context"
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "sync"
    "sync/atomic"
    "time"
)

/*
 * Plugin Frequency Rate Limiter util defines a system for limiting the frequency of anomaly reporting from plugins. It includes an interface, structs,
 * and methods for managing reporting frequency and cache.
 */

/* Interface for limiting reporting frequency of plugin */
type PluginReportingFrequencyLimiterInterface interface {
    ShouldReport(anomalyKey string) bool
    ResetCache(anomalyKey string)
    Initialize(initialReportingFreqInMins int, subsequentReportingFreqInMins int, initialReportingMaxCount int)
    IsNotWithinFrequency(reportingDetails ReportingDetails) bool

    GetNextExpiry() (string, time.Time) // Returns the anomaly key and time of the next expiry
    DeleteCache(anomalyKey string)      // Deletes an entry from the cache for a given anomalyKey without checking the expiry
}

/* Contains when detection was last reported and the count of reports so far */
type ReportingDetails struct {
    lastReported         time.Time
    countOfTimesReported int
}

const (
    initial_detection_reporting_freq_in_mins    = "INITIAL_DETECTION_REPORTING_FREQ_IN_MINS"
    subsequent_detection_reporting_freq_in_mins = "SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS"
    initial_detection_reporting_max_count       = "INITIAL_DETECTION_REPORTING_MAX_COUNT"
)

// To-Do : Prithvi/Goutham : Use only one frequency in future
/* PluginReportingFrequencyLimiter struct implements the PluginReportingFrequencyLimiterInterface */
type PluginReportingFrequencyLimiter struct {
    cache                         map[string]*ReportingDetails // Cache for storing reporting details for each anomaly key
    initialReportingFreqInMins    int                          // Initial reporting frequency in minutes
    SubsequentReportingFreqInMins int                          // Subsequent reporting frequency in minutes
    initialReportingMaxCount      int                          // Maximum count for initial reporting
}

/* Initializes values with detection frequencies */
func (pluginReportingFrequencyLimiter *PluginReportingFrequencyLimiter) Initialize(initialReportingFreqInMins int, subsequentReportingFreqInMins int, initialReportingMaxCount int) {
    pluginReportingFrequencyLimiter.cache = make(map[string]*ReportingDetails)
    pluginReportingFrequencyLimiter.initialReportingFreqInMins = initialReportingFreqInMins
    pluginReportingFrequencyLimiter.SubsequentReportingFreqInMins = subsequentReportingFreqInMins
    pluginReportingFrequencyLimiter.initialReportingMaxCount = initialReportingMaxCount
}

/* Determines if detection can be reported now for an anomalyKey. True if it can be reported else false.*/
func (pluginReportingFrequencyLimiter *PluginReportingFrequencyLimiter) ShouldReport(anomalyKey string) bool {
    reportingDetails, ok := pluginReportingFrequencyLimiter.cache[anomalyKey]

    if !ok {
        // If the anomaly key is not in the cache, add it to the cache and report the anomaly
        reportingDetails := ReportingDetails{lastReported: time.Now(), countOfTimesReported: 1}
        pluginReportingFrequencyLimiter.cache[anomalyKey] = &reportingDetails
        return true
    } else {
        // If the anomaly key is in the cache, check if the current time is not within the frequency limit
        if pluginReportingFrequencyLimiter.IsNotWithinFrequency(*reportingDetails) {
            // If it's not within the frequency limit, increment the count of times reported, update the last reported
            // time, and report the anomaly
            defer func() {
                reportingDetails.countOfTimesReported = reportingDetails.countOfTimesReported + 1
                reportingDetails.lastReported = time.Now()
            }()
            return true
        }
        return false
    }
}

/* Resets cache for anomaly Key. This needs to be used when anomaly is not detected for an anomaly key */
func (pluginReportingFrequencyLimiter *PluginReportingFrequencyLimiter) ResetCache(anomalyKey string) {
    reportingDetails, ok := pluginReportingFrequencyLimiter.cache[anomalyKey]

    if ok {
        // If the anomaly key is in the cache, check if the current time is not within the frequency limit
        if pluginReportingFrequencyLimiter.IsNotWithinFrequency(*reportingDetails) {
            delete(pluginReportingFrequencyLimiter.cache, anomalyKey)
        }
    }
}

/*
Note :

    This method is called by ShouldReport() to check if the current time is not within the frequency limit to report an anomaly.
    It is also called by ResetCache() to check if the current time is not within the frequency limit to delete the cache for an anomaly key.

    Limitation:
    Assume the current window of reporting is in SubsequentReportingFreqInMins (default 1H). If a previously detected anomaly is cleared,
    the plugin will call ResetCache() to delete the cache for this anomaly key. However, the cache for that anomaly key will not be deleted.
    This is because the cache is deleted only when the last detection time (current time) is greater than SubsequentReportingFreqInMins (default 1H).
    This behavior is expected.

    However, imemdiately if an anomaly is detected freshly, the plugin will call ShouldReport() to see if it can report the anomaly or not.
    But since we are in the SubsequentReportingFreqInMins (default 1H) time window, it will report the anomaly only after SubsequentReportingFreqInMins.
    So all the reporting from now on will be delayed by SubsequentReportingFreqInMins.

    One possible solution is to make SubsequentReportingFreqInMins and  initialReportingFreqInMins timers very small.
    But this may result in more frequent reporting & not suitable expecially for polling window based plugins link linkcrc where anomaly is
    decided based on the number of times it is reported in a polling window.
    Other solution is if the anamoly is cleared, instead of calling ResetCache(), new method DeleteCache() can be called. THis will delete the cache
    immediately and the next detection will be reported immediately. But this will also result in more frequent reporting. This is more suitable for
    plugins like IPTCRC where anamoly cleared signal mean the anamoly is cleared completly and any next  detection mean a new anamoly.
*/
func (pluginReportingFrequencyLimiter *PluginReportingFrequencyLimiter) IsNotWithinFrequency(reportingDetails ReportingDetails) bool {
    if reportingDetails.countOfTimesReported <= pluginReportingFrequencyLimiter.initialReportingMaxCount {
        // If the count of times reported is less than or equal to the initial reporting max count, check against the initial reporting frequency
        if time.Since(reportingDetails.lastReported).Minutes() > float64(pluginReportingFrequencyLimiter.initialReportingFreqInMins) {
            return true
        }
    } else {
        //TO-DO : Prithvi/Goutham : Remove this & do proper code changes at other places
        // If the count of times reported is greater than the initial reporting max count, check against the subsequent reporting frequency
        if time.Since(reportingDetails.lastReported).Minutes() > float64(pluginReportingFrequencyLimiter.SubsequentReportingFreqInMins) {
            return true
        }
    }
    return false
}

/* Deletes an entry from the cache for a given anomalyKey */
func (pluginReportingFrequencyLimiter *PluginReportingFrequencyLimiter) DeleteCache(anomalyKey string) {
    _, ok := pluginReportingFrequencyLimiter.cache[anomalyKey]
    if ok {
        delete(pluginReportingFrequencyLimiter.cache, anomalyKey)
    }
}

/*
GetNextExpiry iterates over the cache of reporting details and calculates the next expiry time.
It returns the key associated with the next expiry and the time of the next expiry.

If the next expiry time has not been set (i.e., it's the zero value for a time.Time) or the calculated expiry time is before the next expiry
time, the function updates the next expiry time and the associated key.

Parameters: None

Returns:
- string: The key associated with the next expiry time.
- time.Time: The next expiry time.
*/
func (pluginReportingFrequencyLimiter *PluginReportingFrequencyLimiter) GetNextExpiry() (string, time.Time) {
    // Initialize the next expiry to a zero value
    var nextExpiry time.Time
    var nextExpiryKey string

    // To-Do : Goutham : Optimize this by maintaining a min heap of expiry times
    // Iterate over the cache
    for anomalyKey, reportingDetails := range pluginReportingFrequencyLimiter.cache {
        // Calculate the expiry time for this reporting detail
        expiry := reportingDetails.lastReported
        if reportingDetails.countOfTimesReported <= pluginReportingFrequencyLimiter.initialReportingMaxCount {
            expiry = expiry.Add(time.Minute * time.Duration(pluginReportingFrequencyLimiter.initialReportingFreqInMins))
        } else {
            expiry = expiry.Add(time.Minute * time.Duration(pluginReportingFrequencyLimiter.SubsequentReportingFreqInMins))
        }

        // If the next expiry is zero or this expiry is before the next expiry, update the next expiry
        if nextExpiry.IsZero() || expiry.Before(nextExpiry) {
            nextExpiry = expiry
            nextExpiryKey = anomalyKey // Update the anomaly key of the next expiry
        }
    }

    return nextExpiryKey, nextExpiry // Return the anomaly key and time of the next expiry
}

/* Factory method to get default detection reporting limiter instance */
func GetDefaultDetectionFrequencyLimiter() PluginReportingFrequencyLimiterInterface {
    detectionFreqLimiter := &PluginReportingFrequencyLimiter{}
    detectionFreqLimiter.Initialize(lomcommon.GetConfigMgr().GetGlobalCfgInt(initial_detection_reporting_freq_in_mins), lomcommon.GetConfigMgr().GetGlobalCfgInt(subsequent_detection_reporting_freq_in_mins), lomcommon.GetConfigMgr().GetGlobalCfgInt(initial_detection_reporting_max_count))
    return detectionFreqLimiter
}

/* Factory method to get custom detection reporting limiter instance */
func GetDetectionFrequencyLimiter(initialReportingFreqInMins int, subsequentReportingFreqInMins int, initialReportingMaxCount int) PluginReportingFrequencyLimiterInterface {
    detectionFreqLimiter := &PluginReportingFrequencyLimiter{}
    detectionFreqLimiter.Initialize(initialReportingFreqInMins, subsequentReportingFreqInMins, initialReportingMaxCount)
    return detectionFreqLimiter
}

/*
 * This util a fixed-size rolling window data structure. It includes methods for initialization, adding elements, and retrieving
 * all elements in the window.
 */

/* A generic rolling window data structure with fixed size */
type FixedSizeRollingWindow[T any] struct {
    orderedDataPoints    *list.List
    maxRollingWindowSize int
}

/* Initalizes the datastructure with size */
func (fxdSizeRollingWindow *FixedSizeRollingWindow[T]) Initialize(maxSize int) error {
    if maxSize <= 0 {
        return lomcommon.LogError("%d Invalid size for fxd size rolling window", maxSize)
    }
    fxdSizeRollingWindow.maxRollingWindowSize = maxSize
    fxdSizeRollingWindow.orderedDataPoints = list.New()
    return nil
}

/* Adds element to rolling window */
func (fxdSizeRollingWindow *FixedSizeRollingWindow[T]) AddElement(value T) {
    if fxdSizeRollingWindow.orderedDataPoints.Len() < fxdSizeRollingWindow.maxRollingWindowSize {
        fxdSizeRollingWindow.orderedDataPoints.PushBack(value)
        return
    }
    // Remove first element.
    element := fxdSizeRollingWindow.orderedDataPoints.Front()
    fxdSizeRollingWindow.orderedDataPoints.Remove(element)
    // Add the input element into the back.
    fxdSizeRollingWindow.orderedDataPoints.PushBack(value)
}

/* Gets all current elements as list */
func (fxdSizeRollingWindow *FixedSizeRollingWindow[T]) GetElements() *list.List {
    return fxdSizeRollingWindow.orderedDataPoints
}

/*
 * Global Constants
 */

const (
    ResultCodeSuccess int = iota
    ResultCodeInvalidArgument
    ResultCodeAborted
)

const (
    ResultStringSuccess = "Success"
    ResultStringFailure = "Failure"
)

const (
    min_err_cnt_to_skip_hb_key = "PLUGIN_MIN_ERR_CNT_TO_SKIP_HEARTBEAT"
    plugin_prefix              = "plugin_"
)

/*
* This util can be used by detection plugins which needs to detect anomalies periodically and send heartbeat to plugin manager.
* This util takes care of executing detection logic periodically and shutting down the request when shutdown is invoked on the plugin.
* If detection plugin uses this Util as a field in its struct, Request and Shutdown methods from this util get promoted to the plugin.
* Guidence for requestFunc
  *  - Return nil if periodic detection needs to be continued.
  *  - Return action response if Request needs to return to the caller.
  *  - isExecutionHealthy needs to be marked false when there is any issue in Request method that needs to be reported.
*/
type PeriodicDetectionPluginUtil struct {
    requestFrequencyInSecs  int
    heartBeatIntervalInSecs int
    requestFunc             func(*lomipc.ActionRequestData, *bool, context.Context) *lomipc.ActionResponseData
    shutdownFunc            func() error
    PluginName              string
    shutDownInitiated       atomic.Bool
    detectionRunInfo        DetectionRunInfo
    numOfConsecutiveErrors  atomic.Uint64
    responseChannel         chan *lomipc.ActionResponseData
    ctx                     context.Context
    cancelCtxFunc           context.CancelFunc
}

type DetectionRunInfo struct {
    /* If this value is nil, it indicates there is no current run in execution. Non-nil value signifies a current run in execution. */
    currentRunStartTimeInUtc *time.Time
    /* Duration of the latest completed run in seconds */
    durationOfLatestRunInSeconds int64
    mutex                        sync.Mutex
}

/* This method needs to be called to initialize fields present in PeriodicDetectionPluginUtil struct */
/* To-Do : Prithvi/Goutham : Handle cleanups upon shutdown. When shutdown is initiated, memory created in Init() like buffered channels will remain throughout
lifetime of plugin manager */
func (periodicDetectionPluginUtil *PeriodicDetectionPluginUtil) Init(pluginName string, requestFrequencyInSecs int, actionConfig *lomcommon.ActionCfg_t, requestFunction func(*lomipc.ActionRequestData, *bool, context.Context) *lomipc.ActionResponseData, shutDownFunction func() error) error {
    if actionConfig.HeartbeatInt <= 0 {
        // Do not use a default heartbeat interval. Validate and honor the one passed from plugin manager.
        return lomcommon.LogError("Invalid heartbeat interval %d", actionConfig.HeartbeatInt)
    }
    if requestFrequencyInSecs <= 0 {
        return lomcommon.LogError("Invalid requestFreq %d", requestFrequencyInSecs)
    }
    if requestFunction == nil || shutDownFunction == nil {
        return lomcommon.LogError("requestFunction or shutDownFunction is not initialized")
    }
    if pluginName == "" {
        return lomcommon.LogError("PluginName invalid")
    }
    periodicDetectionPluginUtil.requestFrequencyInSecs = requestFrequencyInSecs
    periodicDetectionPluginUtil.heartBeatIntervalInSecs = actionConfig.HeartbeatInt
    /* Size of responseChannel should be 2, so that the go routine handling request can be terminated on shutdown if the Request method has already terminated. */
    periodicDetectionPluginUtil.responseChannel = make(chan *lomipc.ActionResponseData, 2)
    periodicDetectionPluginUtil.requestFunc = requestFunction
    periodicDetectionPluginUtil.shutdownFunc = shutDownFunction
    periodicDetectionPluginUtil.PluginName = pluginName
    periodicDetectionPluginUtil.detectionRunInfo = DetectionRunInfo{}
    periodicDetectionPluginUtil.ctx, periodicDetectionPluginUtil.cancelCtxFunc = context.WithCancel(context.Background())
    lomcommon.LogInfo("Initialized periodicDetectionPluginUtil successfuly for (%s)", pluginName)
    return nil
}

/*
This method immediately starts heartbeat and request execution.
This method is promoted to the plugin. Honors shutdown when shutdown is invoked on plugin.
*/
func (periodicDetectionPluginUtil *PeriodicDetectionPluginUtil) Request(
    hbchan chan PluginHeartBeat,
    request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    lomcommon.LogInfo("STarted Request() for (%s)", periodicDetectionPluginUtil.PluginName)

    if request.Timeout > 0 {
        return GetResponse(request, "", "", ResultCodeInvalidArgument, "Invalid Timeout value for detection plugin")
    }

    // Publish a heartbeat immediately.
    pluginHeartBeat := PluginHeartBeat{PluginName: periodicDetectionPluginUtil.PluginName, EpochTime: time.Now().Unix()}
    hbchan <- pluginHeartBeat

    lomcommon.GetGoroutineTracker().Start(plugin_prefix+periodicDetectionPluginUtil.PluginName, periodicDetectionPluginUtil.handleRequest, request)
    heartBeatTicker := time.NewTicker(time.Duration(periodicDetectionPluginUtil.heartBeatIntervalInSecs) * time.Second)
    defer heartBeatTicker.Stop()

    for {
        select {

        case <-heartBeatTicker.C:
            periodicDetectionPluginUtil.publishHeartBeat(hbchan)

        case resp := <-periodicDetectionPluginUtil.responseChannel:
            return resp

        case <-periodicDetectionPluginUtil.ctx.Done():
            /* Shutdown stops the periodic detection */
            lomcommon.LogInfo("Aborting Request for (%s)", periodicDetectionPluginUtil.PluginName)
            responseData := GetResponse(request, "", "", ResultCodeAborted, ResultStringFailure)
            return responseData
        }
    }
}

/* Publishes heartbeat after performing validations */
func (periodicDetectionPluginUtil *PeriodicDetectionPluginUtil) publishHeartBeat(hbchan chan PluginHeartBeat) {

    numConsecutiveErrors := periodicDetectionPluginUtil.numOfConsecutiveErrors.Load()
    periodicDetectionPluginUtil.detectionRunInfo.mutex.Lock()
    durationOfLatestRunInSecs := periodicDetectionPluginUtil.detectionRunInfo.durationOfLatestRunInSeconds
    var currentRunStartTimeInUtc time.Time
    if periodicDetectionPluginUtil.detectionRunInfo.currentRunStartTimeInUtc != nil {
        currentRunStartTimeInUtc = *periodicDetectionPluginUtil.detectionRunInfo.currentRunStartTimeInUtc
    }
    periodicDetectionPluginUtil.detectionRunInfo.mutex.Unlock()

    if numConsecutiveErrors >= uint64(lomcommon.GetConfigMgr().GetGlobalCfgInt(min_err_cnt_to_skip_hb_key)) {
        lomcommon.LogError("Skipping heartbeat for %s. numConsecutiveErrors %d", periodicDetectionPluginUtil.PluginName, numConsecutiveErrors)
        return
    } else if durationOfLatestRunInSecs > int64(periodicDetectionPluginUtil.requestFrequencyInSecs) {
        lomcommon.LogError("Skipping heartbeat for %s. DurationOfLatestRunInSecs %d", periodicDetectionPluginUtil.PluginName, durationOfLatestRunInSecs)
        return
    } else if !currentRunStartTimeInUtc.IsZero() { /* Indicates a request is running currently */
        durationTillNow := int64(time.Since(currentRunStartTimeInUtc).Seconds())
        if durationTillNow > int64(periodicDetectionPluginUtil.requestFrequencyInSecs) {
            lomcommon.LogError("Skipping heartbeat for %s. Duration of current execution in secs %d", periodicDetectionPluginUtil.PluginName, durationTillNow)
            return
        }
    }

    /* Publish heartbeat only after above validations pass.*/
    pluginHeartBeat := PluginHeartBeat{PluginName: periodicDetectionPluginUtil.PluginName, EpochTime: time.Now().Unix()}
    hbchan <- pluginHeartBeat
}

/* Hanldes detection logic execution and honors shutdown as well. This is called in a goRoutine in the Request method */
func (periodicDetectionPluginUtil *PeriodicDetectionPluginUtil) handleRequest(request *lomipc.ActionRequestData) {

    detectionTicker := time.NewTicker(time.Duration(periodicDetectionPluginUtil.requestFrequencyInSecs) * time.Second)
    defer detectionTicker.Stop()
    lomcommon.LogInfo("Detection Timer initialized for plugin (%s)", periodicDetectionPluginUtil.PluginName)
    isExecutionHealthy := false
loop:
    for {
        // Start immediately before the select.
        if !periodicDetectionPluginUtil.shutDownInitiated.Load() {
            periodicDetectionPluginUtil.detectionRunInfo.mutex.Lock()
            startTimeInUtc := time.Now().UTC()
            periodicDetectionPluginUtil.detectionRunInfo.currentRunStartTimeInUtc = &startTimeInUtc
            periodicDetectionPluginUtil.detectionRunInfo.mutex.Unlock()

            /* Perform detection logic periodically */
            response := periodicDetectionPluginUtil.requestFunc(request, &isExecutionHealthy, periodicDetectionPluginUtil.ctx)
            if response != nil {
                // successful detection
                periodicDetectionPluginUtil.responseChannel <- response
                return
            }

            if !isExecutionHealthy {
                periodicDetectionPluginUtil.numOfConsecutiveErrors.Add(1)
                lomcommon.LogError("Incremented consecutiveError count for plugin (%s)", periodicDetectionPluginUtil.PluginName)
            } else {
                periodicDetectionPluginUtil.numOfConsecutiveErrors.Store(0)
            }

            elapsedTime := int64(time.Since(startTimeInUtc).Seconds())
            periodicDetectionPluginUtil.detectionRunInfo.mutex.Lock()
            periodicDetectionPluginUtil.detectionRunInfo.currentRunStartTimeInUtc = nil
            periodicDetectionPluginUtil.detectionRunInfo.durationOfLatestRunInSeconds = elapsedTime
            periodicDetectionPluginUtil.detectionRunInfo.mutex.Unlock()

            if elapsedTime > int64(periodicDetectionPluginUtil.requestFrequencyInSecs) {
                // Reset the timer.
                lomcommon.LogInfo("Resetting timer for plugin (%s)", periodicDetectionPluginUtil.PluginName)
                detectionTicker.Reset(time.Duration(periodicDetectionPluginUtil.requestFrequencyInSecs) * time.Second)
            }
        }

        select {
        case <-detectionTicker.C:
            continue

        case <-periodicDetectionPluginUtil.ctx.Done():
            /* Shutdown stops the periodic detection */
            lomcommon.LogInfo("Aborting handleRequest for (%s)", periodicDetectionPluginUtil.PluginName)
            break loop
        }
    }
}

/* Shutdown that aborts the request. It also cleans up plugin defined cleanUp at the end */
func (periodicDetectionPluginUtil *PeriodicDetectionPluginUtil) Shutdown() error {
    lomcommon.LogInfo("Shutdown called for plugin (%s)", periodicDetectionPluginUtil.PluginName)
    periodicDetectionPluginUtil.cancelCtxFunc()
    periodicDetectionPluginUtil.shutDownInitiated.Store(true)
    periodicDetectionPluginUtil.shutdownFunc()
    lomcommon.LogInfo("Shutdown successful for plugin (%s)", periodicDetectionPluginUtil.PluginName)
    return nil
}

/*
 * GetResponse constructs and returns a response object for a given action request. It includes the original request data,
 * anomaly key, response message, and result details.
 */

func GetResponse(request *lomipc.ActionRequestData, anomalyKey string, response string, resultCode int, resultString string) *lomipc.ActionResponseData {
    responseData := lomipc.ActionResponseData{Action: request.Action,
        InstanceId:        request.InstanceId,
        AnomalyInstanceId: request.AnomalyInstanceId,
        AnomalyKey:        anomalyKey,
        Response:          response,
        ResultCode:        resultCode,
        ResultStr:         resultString}
    return &responseData
}

/*

/*
 * This utility is designed for subscription-based plugins that need to detect anomalies triggered by GNMI subscriptions.
 * The utility manages the execution of detection logic when a subscription request is received and handles the shutdown of the request when the plugin is shut down.
 * If a detection plugin uses this utility as a field in its struct, the Request and Shutdown methods from this utility are promoted to the plugin.
 *
 * Guidance for requestFunc:
 *  - This function is called to handle a subscription request. It should return nil if the subscription detection needs to continue.
 *  - If the detection is complete and a response needs to be returned to the caller, the function should return an ActionResponseData.
 *  - If there is an issue in the Request method that needs to be reported, the function should return an error.
 *
 * The utility uses an exponential backoff strategy with jitter to handle errors and retries.
 *
 * The utility also uses a context to manage cancellation of the goroutines. Make sure that any long-running or blocking operations in requestFunc periodically check whether
 * the context has been cancelled and return early if so.
 *
 * The utility publishes a heartbeat at a configurable interval. If a certain number of consecutive errors occur, the heartbeat is skipped.
 *
 * The utility provides several custom error types to handle different error conditions, such as subscription errors, receive errors, shutdown errors, etc.


// SubscribeError represents an error that occurred while subscribing to GNMI paths.
type SubscribeError struct {
    Err error
}

func (e *SubscribeError) Error() string {
    return fmt.Sprintf("failed to subscribe to gnmi paths: %v", e.Err)
}

// ReceiveError represents an error that occurred while receiving GNMI notifications.
type ReceiveError struct {
    Err error
}

func (e *ReceiveError) Error() string {
    return fmt.Sprintf("failed to receive GNMI notifications: %v", e.Err)
}

// ShutdownError represents an error that occurred while shutting down the GNMI client.
type ShutdownError struct {
    Err error
}

func (e *ShutdownError) Error() string {
    return fmt.Sprintf("failed to shutdown GNMI client: %v", e.Err)
}

// ChannelClosedError represents an error that occurred when a channel was unexpectedly closed.
type ChannelClosedError struct {
    Err error
}

func (e *ChannelClosedError) Error() string {
    return fmt.Sprintf("channel closed: %v", e.Err)
}

// SubscriptionCancelledError represents an error that occurred when a subscription was cancelled.
type SubscriptionCancelledError struct {
    Err error
}

func (e *SubscriptionCancelledError) Error() string {
    return fmt.Sprintf("subscription cancelled: %v", e.Err)
}

// SubscribeprotocolError represents an internal error in the subscription protocol.
type SubscribeprotocolError struct {
    Err error
}

func (e *SubscribeprotocolError) Error() string {
    return fmt.Sprintf("Subscription internal error: %v", e.Err)
}

// SessionCreationError represents an error that occurred while creating a session.
type SessionCreationError struct {
    Err error
}

func (e *SessionCreationError) Error() string {
    return fmt.Sprintf("Session creation error: %v", e.Err)
}

type SubscriptionBasedPluginUtil struct {
    requestFunc             func(*lomipc.ActionRequestData, context.Context, bool) (*lomipc.ActionResponseData, error) // Handles subscription request in plugin
    shutdownFunc            func() error                                                                               // handles the shutdown in the plugin
    PluginName              string
    isShutDownInitiated     atomic.Bool // isShutDownInitiated is a flag that indicates whether the shutdown of the plugin has been initiated
    numOfConsecutiveErrors  atomic.Uint64
    responseChannel         chan *lomipc.ActionResponseData
    ctx                     context.Context
    cancelCtxFunc           context.CancelFunc
    heartBeatIntervalInSecs int
    pluginLogger            *PluginLogger
    backoffTimeSecs         int         // backoffTimeSecs is the time in seconds to wait before retrying after an error
    initInitialized         atomic.Bool // initInitialized is a flag that indicates whether the Init method has been called
}

/*
NotifyAsHealthySubscription resets the counter of consecutive errors.

This function should be called from plugin when a successful subscription detection occurs to indicate
that the plugin is healthy.

func (subscriptionBasedPluginUtil *SubscriptionBasedPluginUtil) NotifyAsHealthySubscription() {
    subscriptionBasedPluginUtil.numOfConsecutiveErrors.Store(0)
}

/*
 * Init initializes the SubscriptionBasedPluginUtil struct.
 *
 * Parameters:
 * - pluginName: A string. This is the name of the plugin.
 * - actionConfig: A pointer to an ActionCfg_t struct. This is the configuration for the action.
 * - requestFunction: A function. This is the function that handles a subscription request.
 * - shutDownFunction: A function. This is the function that handles the shutdown of the plugin.
 * - pluginLogger: A pointer to a PluginLogger struct. This is the logger for the plugin.
 *
 * Returns:
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.

func (subscriptionBasedPluginUtil *SubscriptionBasedPluginUtil) Init(pluginName string, actionConfig *lomcommon.ActionCfg_t,
    requestFunction func(*lomipc.ActionRequestData, context.Context, bool) (*lomipc.ActionResponseData, error), shutDownFunction func() error,
    pluginLogger *PluginLogger, backoffTimeSecs int) error {

    if pluginLogger == nil {
        return lomcommon.LogError("Plugin logger is nil")
    }
    subscriptionBasedPluginUtil.pluginLogger = pluginLogger

    if actionConfig.HeartbeatInt <= 0 {
        // Do not use a default heartbeat interval. Validate and honor the one passed from plugin manager.
        return pluginLogger.LogError("Invalid heartbeat interval %d", actionConfig.HeartbeatInt)
    }

    if requestFunction == nil || shutDownFunction == nil {
        return pluginLogger.LogError("requestFunction or shutDownFunction is not initialized")
    }

    if pluginName == "" {
        return pluginLogger.LogError("PluginName invalid")
    }

    subscriptionBasedPluginUtil.heartBeatIntervalInSecs = actionConfig.HeartbeatInt
    // Size of responseChannel should be 2, so that the go routine handling request can be terminated on shutdown if the Request method has already terminated.
    subscriptionBasedPluginUtil.responseChannel = make(chan *lomipc.ActionResponseData, 2)
    subscriptionBasedPluginUtil.requestFunc = requestFunction
    subscriptionBasedPluginUtil.shutdownFunc = shutDownFunction
    subscriptionBasedPluginUtil.PluginName = pluginName
    subscriptionBasedPluginUtil.backoffTimeSecs = backoffTimeSecs
    subscriptionBasedPluginUtil.ctx, subscriptionBasedPluginUtil.cancelCtxFunc = context.WithCancel(context.Background())
    subscriptionBasedPluginUtil.initInitialized.Swap(true)
    pluginLogger.LogInfo("Initialized subscriptionBasedPluginUtil successfuly for (%s)", pluginName)
    return nil
}

/*
 * Request starts handling a request and periodically sends a heartbeat until a response is received or untill shutdoen.
 *
 * Parameters:
 * - hbchan: A channel for sending heartbeats.
 * - request: The request to handle.
 *
 * The function returns a response when one is received or the operation is cancelled.
 * If shutdown has been initiated, the function logs an error and returns an aborted response.
 * If the request timeout is greater than 0, the function returns an invalid argument response.
 *
 * Returns:
 * - A pointer to an ActionResponseData struct. This is the response to the request.

func (subscriptionBasedPluginUtil *SubscriptionBasedPluginUtil) Request(hbchan chan PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    subscriptionBasedPluginUtil.pluginLogger.LogInfo("Started Request() for (%s)", subscriptionBasedPluginUtil.PluginName)

    // If shutdown has been initiated, log an error and return an aborted response
    if subscriptionBasedPluginUtil.isShutDownInitiated.Load() {
        subscriptionBasedPluginUtil.pluginLogger.LogError("Request called after shutdown for (%s)", subscriptionBasedPluginUtil.PluginName)
        return GetResponse(request, "", "", ResultCodeAborted, ResultStringFailure)
    }

    if !subscriptionBasedPluginUtil.initInitialized.Load() {
        subscriptionBasedPluginUtil.pluginLogger.LogError("Init not called for (%s)", subscriptionBasedPluginUtil.PluginName)
        return GetResponse(request, "", "", ResultCodeAborted, ResultStringFailure)
    }

    if request.Timeout > 0 {
        return GetResponse(request, "", "", ResultCodeInvalidArgument, "Invalid Timeout value for detection plugin")
    }

    // Publish a heartbeat immediately.
    pluginHeartBeat := PluginHeartBeat{PluginName: subscriptionBasedPluginUtil.PluginName, EpochTime: time.Now().Unix()}
    hbchan <- pluginHeartBeat

    // Start handling the request in a separate goroutine
    lomcommon.GetGoroutineTracker().Start(plugin_prefix+subscriptionBasedPluginUtil.PluginName+"_handleRequest_"+GetUniqueID(), subscriptionBasedPluginUtil.handleRequest, request)

    // Create a ticker for sending heartbeats
    heartBeatTicker := time.NewTicker(time.Duration(subscriptionBasedPluginUtil.heartBeatIntervalInSecs) * time.Second)
    defer heartBeatTicker.Stop()

    for {
        select {
        case <-heartBeatTicker.C:
            // When the ticker fires, publish a heartbeat
            subscriptionBasedPluginUtil.publishHeartBeat(hbchan)

        case resp := <-subscriptionBasedPluginUtil.responseChannel:
            // When a response is received, return it back to plugin manager
            return resp

        case <-subscriptionBasedPluginUtil.ctx.Done():
            // Shutdown stops the periodic detection, return an aborted response
            subscriptionBasedPluginUtil.pluginLogger.LogInfo("Aborting Request for (%s)", subscriptionBasedPluginUtil.PluginName)
            responseData := GetResponse(request, "", "", ResultCodeAborted, ResultStringFailure)
            return responseData
        }
    }
}

/*
 * publishHeartBeat publishes a heartbeat after performing validations.
 *
 * Parameters:
 * - hbchan: A channel for sending heartbeats.
 *
 * The function checks the number of consecutive errors before deciding whether to publish a heartbeat.
 * If the number of consecutive errors is greater than or equal to a certain threshold, the function logs an error and returns without publishing a heartbeat.
 * Otherwise, the function creates a PluginHeartBeat struct and sends it on the hbchan channel.
 *
 * This function does not return a value.

func (subscriptionBasedPluginUtil *SubscriptionBasedPluginUtil) publishHeartBeat(hbchan chan PluginHeartBeat) {
    numConsecutiveErrors := subscriptionBasedPluginUtil.numOfConsecutiveErrors.Load()

    if numConsecutiveErrors >= uint64(lomcommon.GetConfigMgr().GetGlobalCfgInt(min_err_cnt_to_skip_hb_key)) {
        subscriptionBasedPluginUtil.pluginLogger.LogError("Skipping heartbeat for %s. numConsecutiveErrors %d", subscriptionBasedPluginUtil.PluginName, numConsecutiveErrors)
        return
    }

    // Publish heartbeat only after above validations pass.
    pluginHeartBeat := PluginHeartBeat{PluginName: subscriptionBasedPluginUtil.PluginName, EpochTime: time.Now().Unix()}
    hbchan <- pluginHeartBeat
}

/*
 * handleRequest handles a subscription request.
 *
 * Parameters:
 * - request: A pointer to an ActionRequestData struct. This is the request to handle.
 *
 * The function initializes a backoffTimeSecs timer and a flag to indicate if the connection to the gnmi server needs to be restarted.
 *
 * This function does not return a value.

// To-Do : Goutham : Optimize this. Check if restartConnection flag is needed or not.
func (subscriptionBasedPluginUtil *SubscriptionBasedPluginUtil) handleRequest(request *lomipc.ActionRequestData) {
    subscriptionBasedPluginUtil.pluginLogger.LogInfo("Subscription handler initialized for plugin (%s)", subscriptionBasedPluginUtil.PluginName)
    // Initialize the backoffTimeSecs timer
    // The backoffTimeSecs timer is used to reconnect to the gnmi server in case of connection errors
    retryCount := 0
    maxDelay := float64(subscriptionBasedPluginUtil.backoffTimeSecs)
    var backoffTimer *time.Timer

    // Flag to indicate if the connection to gnmi server needs to be restarted.
    // This flag is set to true when there is connection error
    restartConnection := false

loop:
    for {
        var errCh chan error
        var goroutineResponseCh chan *lomipc.ActionResponseData

        // Call the plugin request function in a separate goroutine
        if backoffTimer == nil {
            errCh = make(chan error, 1)
            goroutineResponseCh = make(chan *lomipc.ActionResponseData, 1)

            lomcommon.GetGoroutineTracker().Start(plugin_prefix+subscriptionBasedPluginUtil.PluginName+"_plugin_request_"+GetUniqueID(),
                func() {
                    response, err := subscriptionBasedPluginUtil.requestFunc(request, subscriptionBasedPluginUtil.ctx, restartConnection)
                    if err != nil {
                        errCh <- err
                    } else {
                        // successful detection.
                        goroutineResponseCh <- response
                    }
                })
        }

        select {
        case data := <-goroutineResponseCh:
            // If a shutdown has been initiated, stop processing updates
            if subscriptionBasedPluginUtil.isShutDownInitiated.Load() {
                break loop
            }

            // successful detection. If a response is received, send the response to the response channel
            subscriptionBasedPluginUtil.responseChannel <- data
            subscriptionBasedPluginUtil.numOfConsecutiveErrors.Store(0)
            restartConnection = false
            retryCount = 0
            backoffTimer = nil
            return

        case err := <-errCh:
            //To-Do : Goutham : when there is max retries, need a way to stop and return error. Ensure engine does not call again after request method fails.
            //unhealthy execution
            subscriptionBasedPluginUtil.numOfConsecutiveErrors.Add(1)
            subscriptionBasedPluginUtil.pluginLogger.LogError("Incremented consecutiveError count for plugin (%s)", subscriptionBasedPluginUtil.PluginName)

            // decide if the connection to gnmi server needs to be restarted
            switch err.(type) {
            case *SubscribeprotocolError, *SessionCreationError, *ReceiveError, *SubscribeError:
                // For errors, use a backoff strategy to reconnect to the gnmi server
                delay := math.Min(maxDelay, math.Pow(2, float64(retryCount)))
                jitter := delay/2.0 + rand.Float64()*delay/2.0 // Add jitter
                backoffTimer = time.NewTimer(time.Duration(jitter) * time.Second)
                retryCount++

                restartConnection = true // Reconnect to the gnmi server
            default:
                // For other errors, do not use a backoff strategy to reconnect to the gnmi server
            }

        case <-subscriptionBasedPluginUtil.ctx.Done():
            // If the context is done (i.e., a shutdown has been initiated), stop processing updates
            subscriptionBasedPluginUtil.pluginLogger.LogInfo("Aborting handleRequest for (%s)", subscriptionBasedPluginUtil.PluginName)
            break loop
        }

        if backoffTimer != nil && restartConnection {
            select {
            // If the backoff timer expires, continue to the next iteration of the loop to retry the request
            case <-backoffTimer.C:
                backoffTimer = nil
            case <-subscriptionBasedPluginUtil.ctx.Done():
                break loop
            }
        }
    }
}

/*
 * Shutdown aborts the request and performs cleanup.
 *
 * This function does not take any parameters.
 *
 * Returns:
 * - An error. This is always nil, as the function does not perform any operations that can fail.

func (subscriptionBasedPluginUtil *SubscriptionBasedPluginUtil) Shutdown() error {
    subscriptionBasedPluginUtil.pluginLogger.LogInfo("Shutdown called for plugin (%s)", subscriptionBasedPluginUtil.PluginName)

    if !subscriptionBasedPluginUtil.initInitialized.Load() {
        subscriptionBasedPluginUtil.pluginLogger.LogError("Init not called for (%s)", subscriptionBasedPluginUtil.PluginName)
        return nil
    }

    subscriptionBasedPluginUtil.cancelCtxFunc()
    subscriptionBasedPluginUtil.isShutDownInitiated.Store(true)
    subscriptionBasedPluginUtil.shutdownFunc()
    subscriptionBasedPluginUtil.pluginLogger.LogInfo("Shutdown successful for plugin (%s)", subscriptionBasedPluginUtil.PluginName)
    return nil
}
*/
