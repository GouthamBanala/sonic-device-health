package arista_common

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "strconv"
    "strings"

    plugins_common "lom/src/plugins/plugins_common"
)

const (
    SandCountersGnmiPath = "/Smash/hardware/counter/internalDrop/SandCounters/internalDrop"
    FapDetailsGnmiPath   = "/Sysdb/hardware/sand/system/status/sand/fapName"
)

/* LCChipData stores the sand counters data extracted from gnmi notifications for each Line card chipId */
type LCChipData struct {
    Delta4                    float64
    DropCount                 int
    Offset                    int
    ChipName                  string
    Delta2                    float64
    Delta5                    float64
    Delta1                    float64
    ThresholdEventCount       int
    CounterId                 int
    LastSyslogTime            float64
    ChipType                  string
    ChipId                    int
    EventCount                int
    Delta3                    float64
    LastEventTime             float64
    InitialEventTime          float64
    CounterName               string
    InitialThresholdEventTime float64
    LastThresholdEventTime    float64
}

/* chipIdNameMap is a map from chip IDs to chip names. It is initialized from a JSON file. */
var chipIdNameMap = make(map[string]int)

/*
 * LoadChipMappings loads the chip mappings from a JSON file.
 *
 * It reads the file specified by the  ChipMappingsFile and unmarshals the JSON content into a map[string]int.
 * The resulting map is assigned to the global variable chipIdNameMap.
 * Loads the chip mappings from a JSON file. The JSON file should contain a map from chip names to chip IDs.
 * The file should be in the following format:
 *  {
 *      "FirstEntry": "0",
 *      "IptCrcErrCnt": "1",
 *      "UcFifoFullDrop": "2",
 *        ....
 *  }
 *
 * THis file is populated by the startup scripts
 *
 * If reading the file or unmarshalling the JSON fails, the function returns an error.
 *
 * Parameters:
    * - ChipMappingsFile: A string. This is the path to the JSON file containing the chip mappings.
 *
 * Returns:
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 *
 * Not Thread safe
*/
func LoadChipMappings(ChipMappingsFile string) error {
    // If chipIdNameMap is already populated, return early
    if len(chipIdNameMap) > 0 {
        return nil
    }

    data, err := os.ReadFile(ChipMappingsFile)
    if err != nil {
        return fmt.Errorf("failed to read file chipName to chipId mappings file: %v", err)
    }

    var counters map[string]int
    err = json.Unmarshal(data, &counters)
    if err != nil {
        return fmt.Errorf("failed to parse JSON in chipName to chipId mappings file: %v", err)
    }

    // Assign the loaded map to chipIdNameMap
    chipIdNameMap = counters
    return nil
}

/*
 * GetChipDetails extracts chip details from a parsed gNMI Notification(/Sysdb/hardware/sand/system/status/sand/fap)
 *
 * Parameters:
 * - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification Object.
 *
 * Returns:
 * - A map from string to string. This map represents the extracted chip details, with chip IDs as keys and chip names as values.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 *
 * Thread safe
 */
func GetChipDetails(parsedNotification map[string]interface{}) (map[string]string, error) {
    chipDetails := make(map[string]string)

    // Get the 'prefix' from the parsedNotification using GetPrefix
    prefixSlice, err := plugins_common.GetPrefix(parsedNotification)
    if err != nil {
        return nil, fmt.Errorf("failed to get prefix: %v", err)
    }

    // Join the prefix slice into a single string
    prefix := "/" + strings.Join(prefixSlice, "/")

    // Check if the prefix ends with "_counts"
    if strings.HasSuffix(prefix, "_counts") {
        return nil, fmt.Errorf("prefix ends with \"_counts\", got \"%s\"", prefix)
    }

    // Check if the prefix is equal to FapDetailsGnmiPath
    if prefix != FapDetailsGnmiPath {
        return nil, fmt.Errorf("expected prefix to be \"%s\", got \"%s\"", FapDetailsGnmiPath, prefix)
    }

    // Parse the 'updates' from the parsedNotification
    updates, err := plugins_common.ParseUpdates(parsedNotification)
    if err != nil {
        return nil, fmt.Errorf("failed to parse updates: %v", err)
    }

    for path, val := range updates {
        log.Printf("path: %s\n", path)
        log.Printf("val: %v\n", val)
        valMap, ok := val.(map[string]interface{})
        if !ok {
            return nil, fmt.Errorf("expected val to be map[string]interface{}, got %T", val)
        }
        log.Printf("valMap: %v\n", valMap)
        valueMap, ok := valMap["Value"].(map[string]interface{})
        if !ok {
            return nil, fmt.Errorf("expected valMap[\"Value\"] to be map[string]interface{}, got %T", valMap["Value"])
        }

        chipName, ok := valueMap["StringVal"].(string)
        if !ok {
            return nil, fmt.Errorf("expected valueMap[\"StringVal\"] to be string, got %T", valueMap["StringVal"])
        }

        chipDetails[path] = chipName
    }

    return chipDetails, nil
}

/*
 * GetSandCounterUpdates parses a SandCounters/internalDrop notification object and extracts counter details for a specific counterName on
 * all the chips. gnmi path : /Smash/hardware/counter/internalDrop/SandCounters/internalDrop
 *
 * The function first parses the 'updates' from the parsedNotification.
 * Then, for each update, it extracts the chipId, chipType, counterId, offset and attribute name from the path.
 * If the counterId in the path is not equal to the counterId corresponding to the provided counterName, the function skips processing the update.
 *
 * Next, the function extracts the actual value from the Value map in the update.
 *
 * Parameters:
 * - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification.
 * - counterName: A string. This is the counterName for which the function extracts counter details.
 *
 * Returns:
 * - A map[string]map[string]interface{}. This is the map of counter details extracted from the parsed gNMI Notification.
 * The keys of the outer map are chipIds, and the values are maps of attribute names to their actual values.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 *
 * An example for the returned map for IptCrcErrCnt(i.e counterName "IptCrcErrCnt") for chipId 6:
 * map[string]map[string]interface{}{
 * "6": map[string]interface{}{
 * "delta4": 4.294967295e+09 ,
 * "dropCount": 6.000000,
 * "offset": 65535,
 * "chipName": "Jericho4/0",
 * "delta2": 0,
 * "delta5": 4.294967295e+09,
 * "delta1": 0,
 * "thresholdEventCount": 0.000000,
 * "counterId": 1,
 * "lastSyslogTime":0.000000,
 * "chipType": "fap",
 * "chipId": 6.000000,
 * "eventCount": 1.000000,
 * "delta3": 4.294967295e+09,
 * "lastEventTime": 1703377178.446100,
 * "initialEventTime": 1703377178.446099,
 * "counterName": "IptCrcErrCnt",
 * "initialThresholdEventTime":0.000000,
 * "lastThresholdEventTime":0.000000,
 * },
 * }
 * Thread safe
 */
func GetSandCounterUpdates(parsedNotification map[string]interface{}, counterName string) (map[string]map[string]interface{}, error) {
    counterId, ok := chipIdNameMap[counterName]
    if !ok {
        return nil, fmt.Errorf("unknown counter name: %s", counterName)
    }

    counterDetails := make(map[string]map[string]interface{})

    // Get the 'prefix' from the parsedNotification using GetPrefix
    prefixSlice, err := plugins_common.GetPrefix(parsedNotification)
    if err != nil {
        return nil, fmt.Errorf("failed to get prefix: %v", err)
    }

    // Join the prefix slice into a single string
    prefix := "/" + strings.Join(prefixSlice, "/")

    // Check if the prefix ends with "_counts"
    if strings.HasSuffix(prefix, "_counts") {
        return nil, fmt.Errorf("prefix ends with \"_counts\", got \"%s\"", prefix)
    }

    // Check if the prefix is equal to SandCountersGnmiPath
    if prefix != SandCountersGnmiPath {
        return nil, fmt.Errorf("expected prefix to be \"%s\", got \"%s\"", SandCountersGnmiPath, prefix)
    }

    // Parse the 'updates' from the parsedNotification
    updates, err := plugins_common.ParseUpdates(parsedNotification)
    if err != nil {
        return nil, fmt.Errorf("failed to parse updates: %v", err)
    }

    for path, val := range updates {
        valMap, ok := val.(map[string]interface{})
        if !ok {
            return nil, fmt.Errorf("expected val to be map[string]interface{}, got %T", val)
        }

        // Extract chipId, chipType, counterId, offset and attribute name from path
        parts := strings.Split(path, "_")
        if len(parts) < 4 {
            return nil, fmt.Errorf("expected path to contain chipId, chipType, CounterId, offset and attribute name, got %s", path)
        }

        chipId := parts[0]
        pathCounterId, err := strconv.Atoi(parts[2])
        if err != nil {
            return nil, fmt.Errorf("failed to convert counterId to int: %v", err)
        }

        // Skip processing if pathCounterId is not equal to counterId
        if pathCounterId != counterId {
            continue
        }

        // Extract attribute name
        attributeParts := strings.Split(parts[3], "/")
        attribute := attributeParts[len(attributeParts)-1]

        // Extract the actual value
        valueMap, ok := valMap["Value"].(map[string]interface{})
        if !ok {
            return nil, fmt.Errorf("expected Value to be map[string]interface{}, got %T", valMap["Value"])
        }

        var actualValue interface{}
        if jsonVal, ok := valueMap["JsonVal"].(string); ok {
            // Decode base64 string
            decoded, err := base64.StdEncoding.DecodeString(jsonVal)
            if err != nil {
                return nil, fmt.Errorf("failed to decode base64 string: %v", err)
            }

            // Unmarshal JSON
            var value interface{}
            if err := json.Unmarshal(decoded, &value); err != nil {
                return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
            }

            // Handle different types of values
            switch v := value.(type) {
            case float64:
                actualValue = fmt.Sprintf("%f", v)
            /*case []byte:
              actualValue = string(v)
              log.Printf("actualValue: %v\n", actualValue)
              if strVal, ok := actualValue.(string); ok {
                  actualValue = strings.Trim(strVal, "\x00") // Remove trailing NULL bytes
              }*/
            case []interface{}:
                // Convert []interface{} of float64s to a string
                var bytes []byte
                for _, elem := range v {
                    if num, ok := elem.(float64); ok {
                        bytes = append(bytes, byte(num))
                    }
                }
                actualValue = string(bytes)
                if strVal, ok := actualValue.(string); ok {
                    actualValue = strings.Trim(strVal, "\x00") // Remove trailing NULL bytes
                }
            case map[string]interface{}:
                for _, val := range v {
                    actualValue = val
                }
            default:
                actualValue = value
            }
        } else if uintVal, ok := valueMap["UintVal"].(int); ok {
            actualValue = fmt.Sprintf("%d", uintVal)
        } else if uintVal, ok := valueMap["UintVal"].(int64); ok {
            actualValue = fmt.Sprintf("%d", uintVal)
        } else if floatVal, ok := valueMap["UintVal"].(float64); ok {
            actualValue = fmt.Sprintf("%f", floatVal)
        } else if stringVal, ok := valueMap["StringVal"].(string); ok {
            actualValue = stringVal
            if strVal, ok := actualValue.(string); ok {
                actualValue = strings.Trim(strVal, "\x00") // Remove trailing NULL bytes
            }
        } else if bytesVal, ok := valueMap["BytesVal"].([]byte); ok {
            actualValue = string(bytesVal)
            if strVal, ok := actualValue.(string); ok {
                actualValue = strings.Trim(strVal, "\x00") // Remove trailing NULL bytes
            }
        } else if innerMap, ok := valueMap["value"].(map[string]interface{}); ok {
            for _, val := range innerMap {
                actualValue = val
            }
        } else {
            return nil, fmt.Errorf("unexpected value type in Value map: %v", valueMap)
        }

        // If chipId already exists in counterDetails, merge the values
        if existingValues, ok := counterDetails[chipId]; ok {
            existingValues[attribute] = actualValue
        } else {
            counterDetails[chipId] = map[string]interface{}{attribute: actualValue}
        }
    }

    return counterDetails, nil
}

/*
 * GetSandCounterDeletes parses a SandCounters/internalDrop notification object and extracts counter details for a specific counterName on
 * all the chips. gnmi path : /Smash/hardware/counter/internalDrop/SandCounters/internalDrop
 *
 * The function first parses the 'deletes' from the parsedNotification.
 * Then, for each delete, it extracts the chipId, chipType, counterId, and offset from the path.
 * If the counterId in the path is not equal to the counterId corresponding to the provided counterName, the function skips processing the delete.
 *
 * Parameters:
 * - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification.
 * - counterName: A string. This is the counterName for which the function extracts counter details.
 *
 * Returns:
 * - A map[string]map[string]interface{}. This is the map of counter details extracted from the parsed gNMI Notification.
 *      The keys of the outer map are chipIds, and the values are maps of attribute names to their actual values.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 *
 * An example for the returned map for IptCrcErrCnt(i.e counterName "IptCrcErrCnt") for chipId 6:
 * map[string]map[string]interface{}{
 *     "6": map[string]interface{}{
 *         "offset": 65535,
 *         "counterId": 1,
 *         "chipType": fap,
 *     },
 * }
 * Thread safe
 */
func GetSandCounterDeletes(parsedNotification map[string]interface{}, counterName string) (map[string]map[string]interface{}, error) {
    counterId, ok := chipIdNameMap[counterName]
    if !ok {
        return nil, fmt.Errorf("unknown counter name: %s", counterName)
    }
    counterDetails := make(map[string]map[string]interface{})

    // Get the 'prefix' from the parsedNotification using GetPrefix
    prefixSlice, err := plugins_common.GetPrefix(parsedNotification)
    if err != nil {
        return nil, fmt.Errorf("failed to get prefix: %v", err)
    }

    // Join the prefix slice into a single string
    prefix := "/" + strings.Join(prefixSlice, "/")

    // Check if the prefix ends with "_counts"
    if strings.HasSuffix(prefix, "_counts") {
        return nil, fmt.Errorf("prefix ends with \"_counts\", got \"%s\"", prefix)
    }

    // Check if the prefix is equal to SandCountersGnmiPath
    if prefix != SandCountersGnmiPath {
        return nil, fmt.Errorf("expected prefix to be \"%s\", got \"%s\"", SandCountersGnmiPath, prefix)
    }

    // Parse the 'deletes' from the parsedNotification
    deletes, err := plugins_common.ParseDeletes(parsedNotification)
    if err != nil {
        return nil, fmt.Errorf("failed to parse deletes: %v", err)
    }

    for _, delete := range deletes {
        // Extract chipId, chipType, counterId, and offset from delete
        parts := strings.Split(delete, "_")
        if len(parts) < 4 {
            return nil, fmt.Errorf("expected delete to contain chipId, chipType, CounterId, and offset, got %s", delete)
        }

        chipId := parts[0]
        chipType := parts[1]
        deleteCounterId, err := strconv.Atoi(parts[2])
        if err != nil {
            return nil, fmt.Errorf("failed to convert counterId to int: %v", err)
        }
        offset, err := strconv.Atoi(parts[3])
        if err != nil {
            return nil, fmt.Errorf("failed to convert offset to int: %v", err)
        }

        // Skip processing if deleteCounterId is not equal to counterId
        if deleteCounterId != counterId {
            continue
        }

        // Add counter details to counterDetails
        counterDetails[chipId] = map[string]interface{}{
            "chipType":  chipType,
            "counterId": deleteCounterId,
            "offset":    offset,
        }
    }

    return counterDetails, nil
}

/*
 * ConvertToChipData takes a map with string keys and interface{} values, and attempts to convert and assign
 * the values to the fields of a new LCChipData struct. The function expects the map to contain specific keys
 * that correspond to the fields of the LCChipData struct. For each key, it checks if the value is of the
 * expected type, converts it if necessary, and assigns it to the corresponding field of the LCChipData struct.
 *
 * Parameters:
 * - details: A map[string]interface{}. This represents a map of attribute names to their actual values.
 *
 * Returns:
 * - A pointer to the filled LCChipData struct. This is the struct filled with the converted values from the details map.
 * - An error. This is nil if the conversion is successful for all fields and non-nil if an error occurred.
 *
 * Thread safe
 */
func ConvertToChipData(details map[string]interface{}) (*LCChipData, error) {
    chipData := &LCChipData{}

    // Assign fields after conversion
    if val, ok := details["dropCount"].(string); ok {
        dropCountFloat, err := strconv.ParseFloat(val, 64)
        if err != nil {
            return nil, fmt.Errorf("invalid value for dropCount: %v", err)
        }
        chipData.DropCount = int(dropCountFloat)
    } else {
        return nil, fmt.Errorf("invalid type for dropCount")
    }

    if val, ok := details["thresholdEventCount"].(string); ok {
        thresholdEventCountFloat, err := strconv.ParseFloat(val, 64)
        if err != nil {
            return nil, fmt.Errorf("invalid value for thresholdEventCount: %v", err)
        }
        chipData.ThresholdEventCount = int(thresholdEventCountFloat)
    } else {
        return nil, fmt.Errorf("invalid type for thresholdEventCount")
    }

    if val, ok := details["counterId"].(float64); ok {
        chipData.CounterId = int(val)
    } else {
        return nil, fmt.Errorf("invalid type for counterId")
    }

    if val, ok := details["chipId"].(string); ok {
        chipIdFloat, err := strconv.ParseFloat(val, 64)
        if err != nil {
            return nil, fmt.Errorf("invalid value for chipId: %v", err)
        }
        chipData.ChipId = int(chipIdFloat)
    } else {
        return nil, fmt.Errorf("invalid type for chipId")
    }

    if val, ok := details["eventCount"].(string); ok {
        eventCountFloat, err := strconv.ParseFloat(val, 64)
        if err != nil {
            return nil, fmt.Errorf("invalid value for eventCount: %v", err)
        }
        chipData.EventCount = int(eventCountFloat)
    } else {
        return nil, fmt.Errorf("invalid type for eventCount")
    }

    // Assign other fields without conversion
    if val, ok := details["delta4"].(float64); ok {
        chipData.Delta4 = val
    } else {
        return nil, fmt.Errorf("invalid type for delta4")
    }

    if val, ok := details["delta2"].(float64); ok {
        chipData.Delta2 = val
    } else {
        return nil, fmt.Errorf("invalid type for delta2")
    }

    if val, ok := details["delta5"].(float64); ok {
        chipData.Delta5 = val
    } else {
        return nil, fmt.Errorf("invalid type for delta5")
    }

    if val, ok := details["delta1"].(float64); ok {
        chipData.Delta1 = val
    } else {
        return nil, fmt.Errorf("invalid type for delta1")
    }

    if val, ok := details["delta3"].(float64); ok {
        chipData.Delta3 = val
    } else {
        return nil, fmt.Errorf("invalid type for delta3")
    }

    if val, ok := details["offset"].(float64); ok {
        chipData.Offset = int(val)
    } else {
        return nil, fmt.Errorf("invalid type for offset")
    }

    // Assign string fields without conversion
    if val, ok := details["chipType"].(string); ok {
        chipData.ChipType = val
    } else {
        return nil, fmt.Errorf("invalid type for chipType")
    }

    if val, ok := details["chipName"].(string); ok {
        chipData.ChipName = val
    } else {
        return nil, fmt.Errorf("invalid type for chipName")
    }

    if val, ok := details["counterName"].(string); ok {
        chipData.CounterName = val
    } else {
        return nil, fmt.Errorf("invalid type for counterName")
    }

    return chipData, nil
}

/*
 * GetUpdatesCount extracts the count of updates from a parsed gNMI Notification. Each notification will have this count value.
 * You can always get it from len(updates) from the parsedNotification.
 * But this can be used to cross check the count of updates from the parsedNotification and also used for updates parsing based on the count
 *
 * Parameters:
 * - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification.
 *
 * Returns:
 * - A uint64. This is the count of updates extracted from the parsed gNMI Notification.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 *
 * Thread safe
 */
func GetUpdatesCount(parsedNotification map[string]interface{}) (uint64, error) {
    // Get the 'prefix' from the parsedNotification using GetPrefix
    prefixSlice, err := plugins_common.GetPrefix(parsedNotification)
    if err != nil {
        return 0, fmt.Errorf("failed to get prefix: %v", err)
    }

    // Join the prefix slice into a single string
    prefix := "/" + strings.Join(prefixSlice, "/")

    // Check if the prefix ends with "_counts"
    if !strings.HasSuffix(prefix, "_counts") {
        return 0, fmt.Errorf("expected prefix to end with \"_counts\", got \"%s\"", prefix)
    }

    // Parse the 'updates' from the parsedNotification
    updates, err := plugins_common.ParseUpdates(parsedNotification)
    if err != nil {
        return 0, fmt.Errorf("failed to parse updates: %v", err)
    }

    if len(updates) != 1 {
        return 0, fmt.Errorf("expected one update, got %d", len(updates))
    }

    var count uint64
    for _, val := range updates {
        valMap, ok := val.(map[string]interface{})
        if !ok {
            return 0, fmt.Errorf("expected val to be map[string]interface{}, got %T", val)
        }

        valueMap, ok := valMap["Value"].(map[string]interface{})
        if !ok {
            return 0, fmt.Errorf("expected valMap[\"Value\"] to be map[string]interface{}, got %T", valMap["Value"])
        }

        countFloat, ok := valueMap["UintVal"].(float64)
        if !ok {
            return 0, fmt.Errorf("expected valueMap[\"UintVal\"] to be float64, got %T", valueMap["UintVal"])
        }

        count = uint64(countFloat)
    }

    return count, nil
}
