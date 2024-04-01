/* This file contains logic for Link CRC anomaly detection. It detects CRC anomlies for all eligible interfaces on the device.*/
package linkcrc

import (
    "context"
    "encoding/json"
    "fmt"
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "lom/src/plugins/plugins_common"
    "lom/src/plugins/vendors/sonic/client/dbclient"
    "strings"
    "time"
)

const (
    /* Default values to be used for the detection, in case configuration does not set it */
    detection_freq_in_secs_default        = 30
    if_in_errors_diff_min_value_default   = 0
    in_unicast_packets_min_value_default  = 100
    out_unicast_packets_min_value_default = 100
    outlier_rolling_window_size_default   = 5
    min_crc_error_default                 = 0.000001
    min_outliers_for_detection_default    = 2
    look_back_period_in_secs_default      = 125

    /* Config Keys for accessing cfg file */
    detection_freq_in_secs_config_key        = "DetectionFreqInSecs"
    if_in_errors_diff_min_value_config_key   = "IfInErrorsDiffMinValue"
    in_unicast_packets_min_value_config_key  = "InUnicastPacketsMinValue"
    out_unicast_packets_min_value_config_key = "OutUnicastPacketsMinValue"
    outlier_rolling_window_size_config_key   = "OutlierRollingWindowSize"
    min_crc_error_config_key                 = "MinCrcError"
    min_outliers_for_detection_config_key    = "MinOutliersForDetection"
    look_back_period_in_secs_config_key      = "LookBackPeriodInSecs"
    link_crc_plugin_version                  = "1.0.0.0"
    link_crc_prefix                          = "link_crc_detection: "
    link_crc_plugin_name                     = "link_crc_detection"
)

var ifInErrorsDiffMinValue int
var inUnicastPacketsMinValue int
var outUnicastPacketsMinValue int
var outlierRollingWindowSize int
var minCrcError float64
var minOutliersForDetection int
var lookBackPeriodInSecs int

type LinkCRCDetectionPlugin struct {
    counterRepository          dbclient.CounterRepositoryInterface
    currentMonitoredInterfaces map[string]LinkCrcDetectorInterface
    reportingFreqLimiter       plugins_common.PluginReportingFrequencyLimiterInterface
    plugins_common.PeriodicDetectionPluginUtil
}

func NewLinkCRCDetectionPlugin(...interface{}) plugins_common.Plugin {
    // Create and return a new instance of MyPlugin
    return &LinkCRCDetectionPlugin{}
}

func init() {
    // Register the plugin with plugin manager
    plugins_common.RegisterPlugin(link_crc_plugin_name, NewLinkCRCDetectionPlugin)
}

/* Inheritied from Plugin */
func (linkCrcDetectionPlugin *LinkCRCDetectionPlugin) Init(actionConfig *lomcommon.ActionCfg_t) error {
    lomcommon.LogInfo("Started Init() for (%s)", "link_crc_detection")
    // Get config settings or assign default values.
    var resultMap map[string]interface{}
    jsonErr := json.Unmarshal([]byte(actionConfig.ActionKnobs), &resultMap)
    var detectionFreqInSecs int
    if jsonErr == nil {
        detectionFreqInSecs = int(lomcommon.GetFloatConfigFromMapping(resultMap, detection_freq_in_secs_config_key, detection_freq_in_secs_default))
        ifInErrorsDiffMinValue = int(lomcommon.GetFloatConfigFromMapping(resultMap, if_in_errors_diff_min_value_config_key, if_in_errors_diff_min_value_default))
        inUnicastPacketsMinValue = int(lomcommon.GetFloatConfigFromMapping(resultMap, in_unicast_packets_min_value_config_key, in_unicast_packets_min_value_default))
        outUnicastPacketsMinValue = int(lomcommon.GetFloatConfigFromMapping(resultMap, out_unicast_packets_min_value_config_key, out_unicast_packets_min_value_default))
        outlierRollingWindowSize = int(lomcommon.GetFloatConfigFromMapping(resultMap, outlier_rolling_window_size_config_key, outlier_rolling_window_size_default))
        minCrcError = lomcommon.GetFloatConfigFromMapping(resultMap, min_crc_error_config_key, min_crc_error_default)
        minOutliersForDetection = int(lomcommon.GetFloatConfigFromMapping(resultMap, min_outliers_for_detection_config_key, min_outliers_for_detection_default))
        lookBackPeriodInSecs = int(lomcommon.GetFloatConfigFromMapping(resultMap, look_back_period_in_secs_config_key, look_back_period_in_secs_default))
    } else {
        detectionFreqInSecs = detection_freq_in_secs_default
        ifInErrorsDiffMinValue = if_in_errors_diff_min_value_default
        inUnicastPacketsMinValue = in_unicast_packets_min_value_default
        outUnicastPacketsMinValue = out_unicast_packets_min_value_default
        outlierRollingWindowSize = outlier_rolling_window_size_default
        minCrcError = min_crc_error_default
        minOutliersForDetection = min_outliers_for_detection_default
        lookBackPeriodInSecs = look_back_period_in_secs_default
    }

    // Initialize values.
    if actionConfig.Name != link_crc_plugin_name {
        return lomcommon.LogError("Invalid plugin name passed. actionConfig.Name: %s", actionConfig.Name)
    }
    linkCrcDetectionPlugin.counterRepository = &dbclient.CounterRepository{RedisProvider: &dbclient.RedisProvider{}}
    linkCrcDetectionPlugin.currentMonitoredInterfaces = map[string]LinkCrcDetectorInterface{}
    linkCrcDetectionPlugin.reportingFreqLimiter = plugins_common.GetDefaultDetectionFrequencyLimiter()
    err := linkCrcDetectionPlugin.PeriodicDetectionPluginUtil.Init(actionConfig.Name, detectionFreqInSecs, actionConfig, linkCrcDetectionPlugin.executeCrcDetection, linkCrcDetectionPlugin.executeShutdown)
    if err != nil {
        lomcommon.LogError(fmt.Sprintf(link_crc_prefix+"Plugin initialization failed. (%s), err: (%v)", actionConfig.Name, err))
        return err
    }
    lomcommon.LogInfo("Successfully Init() for (%s)", "link_crc_detection")
    return nil
}

/*
Executes the crc detection logic. isExecutionHealthy is marked false when there is an issue in detecting the anomaly

    This is the logic that is periodically executed to detect crc anoamlies
*/
func (linkCrcDetectionPlugin *LinkCRCDetectionPlugin) executeCrcDetection(request *lomipc.ActionRequestData, isExecutionHealthy *bool, ctx context.Context) *lomipc.ActionResponseData {
    lomcommon.LogInfo(fmt.Sprintf(link_crc_prefix + "ExecuteCrcDetection Starting"))
    var listOfInterfacesWithCrcError strings.Builder
    currentInterfaceCounters, err := linkCrcDetectionPlugin.counterRepository.GetCountersForAllInterfaces(ctx)
    if err != nil {
        /* If redis call fails, there can be no detection that can be performed. Mark it unhealthy */
        lomcommon.LogError(link_crc_prefix+"Error fetching interface counters for LinkCrc detection. Err: %v", err)
        *isExecutionHealthy = false
        return nil
    }

    if len(currentInterfaceCounters) == 0 {
        /* currentInterfaceCounters is either nil or 0 which is invalid. Mark it unhealthy */
        *isExecutionHealthy = false
        lomcommon.LogError(link_crc_prefix + "interface counters is 0")
        return nil
    }

    *isExecutionHealthy = true
    for interfaceName, interfaceCounters := range currentInterfaceCounters {
        if interfaceCounters == nil {
            lomcommon.LogError(fmt.Sprintf(link_crc_prefix+"Nil interface Counters for %s", interfaceName))
            *isExecutionHealthy = false
            continue
        }
        linkCrcDetector, ok := linkCrcDetectionPlugin.currentMonitoredInterfaces[interfaceName]
        if !ok {
            /* For very first time, create an entry in the mapping for interface with linkCrcDetector */
            linkCrcDetector := &RollingWindowLinkCrcDetector{}
            linkCrcDetectionPlugin.currentMonitoredInterfaces[interfaceName] = linkCrcDetector
            linkCrcDetector.Initialize(interfaceName)
            linkCrcDetector.AddInterfaceCountersAndDetectCrc(interfaceCounters, time.Now().UTC())
        } else {
            if linkCrcDetector.AddInterfaceCountersAndDetectCrc(interfaceCounters, time.Now().UTC()) {
                /* Consider reporting only if it was not reported recently based on the rate limiter settings */
                if linkCrcDetectionPlugin.reportingFreqLimiter.ShouldReport(interfaceName) {
                    adminStatus, operStatus, err := linkCrcDetectionPlugin.counterRepository.GetInterfaceStatus(interfaceName)
                    if err != nil {
                        /* Log Error */
                        lomcommon.LogError(fmt.Sprintf(link_crc_prefix+"Error getting link status from redis for interface %s. Err: %v", interfaceName, err))
                        *isExecutionHealthy = false
                    } else if adminStatus && operStatus { /* If both are active, consider adding it to the list of final reported errors */
                        /* To-DO : Prithvi/Goutham : Should break the interfaces or do it in plugin manager */
                        listOfInterfacesWithCrcError.WriteString(interfaceName)
                        listOfInterfacesWithCrcError.WriteString(",")
                    }
                }
            } else {
                // reset limiter freq when detection is false and the datapoints look valid.
                linkCrcDetectionPlugin.reportingFreqLimiter.ResetCache(interfaceName)
            }
        }
        /* Note : For interfaces which are in monitoredInterfaces and not in currentInterfaceCounters, we dont perform any action.
           This is the same behaviour in event hub pipeline as well. When the counters start showing up for the link later,
           then we will start detecting the crc for that link */
    }

    if len(listOfInterfacesWithCrcError.String()) != 0 {
        lomcommon.LogInfo(link_crc_prefix + "executeCrcDetection Anomaly Detected")
        return plugins_common.GetResponse(request, strings.TrimSuffix(listOfInterfacesWithCrcError.String(), ","), "Detected Crc", plugins_common.ResultCodeSuccess, plugins_common.ResultStringSuccess)
    }
    return nil
}

/* Contains Clean up that needs to be done when Shutdown() is invoked. This will be invoked after ensuring request is aborted. */
func (linkCrcDetectionPlugin *LinkCRCDetectionPlugin) executeShutdown() error {
    return nil
}

func (linkCrcDetectionPlugin *LinkCRCDetectionPlugin) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{Name: link_crc_plugin_name, Version: link_crc_plugin_version}
}

type LinkCrcDetectorInterface interface {
    Initialize(interfaceName string)
    AddInterfaceCountersAndDetectCrc(currentCounters map[string]uint64, localTimeStampUtc time.Time) bool
    validateCountersDiff(previousCounter map[string]uint64, currentCounters map[string]uint64) bool
}

/*
Contains logic for detecting CRC on an interface using a rolling window based approach.
It uses same algorithm that is currently used by Event hub pipelines today
*/
type RollingWindowLinkCrcDetector struct {
    interfaceName        string
    latestCounters       map[string]uint64 // This will be nil for the very first time.
    outlierRollingWindow plugins_common.FixedSizeRollingWindow[CrcOutlierInfo]
}

/* Initializes the detector instance with config values */
func (linkCrcDetector *RollingWindowLinkCrcDetector) Initialize(interfaceName string) {
    linkCrcDetector.interfaceName = interfaceName
    linkCrcDetector.outlierRollingWindow = plugins_common.FixedSizeRollingWindow[CrcOutlierInfo]{}
    linkCrcDetector.outlierRollingWindow.Initialize(outlierRollingWindowSize)
}

/* Adds CRC based interface counters, computes outlier and detects CRC utilizing the rollowing window outlier details */
func (linkCrcDetector *RollingWindowLinkCrcDetector) AddInterfaceCountersAndDetectCrc(currentCounters map[string]uint64, localTimeStampUtc time.Time) bool {
    if currentCounters == nil {
        return false
    }
    defer func() {
        linkCrcDetector.latestCounters = currentCounters
    }()

    // For the very first time, initialize latestCounters to counters and return false, as diff can not be calculated.
    if linkCrcDetector.latestCounters == nil {
        return false
    }

    // validate if all diff counters are valid.
    if !linkCrcDetector.validateCountersDiff(linkCrcDetector.latestCounters, currentCounters) {
        lomcommon.LogError(fmt.Sprintf(link_crc_prefix+"Invalid counters for interface %s", linkCrcDetector.interfaceName))
        return false
    }

    // Check if current counter w.r.t previous counter evaluates to an outlier.
    ifInErrorsDiff := currentCounters[dbclient.IF_IN_ERRORS_COUNTER_KEY] - linkCrcDetector.latestCounters[dbclient.IF_IN_ERRORS_COUNTER_KEY]
    ifOutErrorsDiff := currentCounters[dbclient.IF_OUT_ERRORS_COUNTER_KEY] - linkCrcDetector.latestCounters[dbclient.IF_OUT_ERRORS_COUNTER_KEY]
    inUnicastPacketsDiff := currentCounters[dbclient.IN_UNICAST_PACKETS_COUNTER_KEY] - linkCrcDetector.latestCounters[dbclient.IN_UNICAST_PACKETS_COUNTER_KEY]
    outUnicastPacketsDiff := currentCounters[dbclient.OUT_UNICAST_PACKETS_COUNTER_KEY] - linkCrcDetector.latestCounters[dbclient.OUT_UNICAST_PACKETS_COUNTER_KEY]

    // Start evaluating the outliers and detect CRC anomaly.
    if ifInErrorsDiff > uint64(ifInErrorsDiffMinValue) && (inUnicastPacketsDiff > uint64(inUnicastPacketsMinValue) || outUnicastPacketsDiff > uint64(outUnicastPacketsMinValue)) {
        errorMetric := float64(ifInErrorsDiff) / (float64(inUnicastPacketsDiff) + float64(ifInErrorsDiff))
        if errorMetric > minCrcError {
            if inUnicastPacketsDiff > 0 {
                totalLinkErrors := ifInErrorsDiff - ifOutErrorsDiff
                fcsErrorRate := float64(totalLinkErrors) / float64(inUnicastPacketsDiff)
                if fcsErrorRate > 0 {
                    /* if fcsErrorRate is > 0, the diff counter considered an outlier */
                    lomcommon.LogError(link_crc_prefix+"FcsErrorRate for interface %s is %f", linkCrcDetector.interfaceName, fcsErrorRate)
                    crcOutlier := CrcOutlierInfo{TimeStamp: localTimeStampUtc}
                    linkCrcDetector.outlierRollingWindow.AddElement(crcOutlier)

                    // Check if outlier occured twice in past 125 seconds.
                    outliersCount := 0
                    crcOutliers := linkCrcDetector.outlierRollingWindow.GetElements()
                    for iterator := crcOutliers.Back(); iterator != nil; iterator = iterator.Prev() {
                        outlier := iterator.Value.(CrcOutlierInfo)
                        if localTimeStampUtc.Sub(outlier.TimeStamp).Seconds() < float64(lookBackPeriodInSecs) {
                            outliersCount = outliersCount + 1
                            if outliersCount == minOutliersForDetection {
                                return true
                            }
                        } else {
                            break
                        }
                    }
                }
            }
        }
    }

    return false
}

/* Validates if counters are valid. Note: Currently GWS does this validation before dumping counterDiffs into eventHub */
func (linkCrcDetector *RollingWindowLinkCrcDetector) validateCountersDiff(previousCounter map[string]uint64, currentCounters map[string]uint64) bool {
    if previousCounter[dbclient.IF_IN_ERRORS_COUNTER_KEY] > currentCounters[dbclient.IF_IN_ERRORS_COUNTER_KEY] {
        return false
    }
    if previousCounter[dbclient.IF_OUT_ERRORS_COUNTER_KEY] > currentCounters[dbclient.IF_OUT_ERRORS_COUNTER_KEY] {
        return false
    }
    if previousCounter[dbclient.IN_UNICAST_PACKETS_COUNTER_KEY] > currentCounters[dbclient.IN_UNICAST_PACKETS_COUNTER_KEY] {
        return false
    }
    if previousCounter[dbclient.OUT_UNICAST_PACKETS_COUNTER_KEY] > currentCounters[dbclient.OUT_UNICAST_PACKETS_COUNTER_KEY] {
        return false
    }
    return true
}

/* Contains details if counter diff is outlier or not */
type CrcOutlierInfo struct {
    TimeStamp time.Time
}
