package arista_common

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "reflect"
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestGetChipDetails(t *testing.T) {
    t.Run("SuccessfulParse", func(t *testing.T) {
        // Define a parsedNotification for testing
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Sysdb"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "system"},
                    map[string]interface{}{"name": "status"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "fapName"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "11"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "StringVal": "Jericho4/5",
                        },
                    },
                },
                // ... rest of the updates ...
            },
        }

        // Call the function under test
        chipDetails, err := GetChipDetails(parsedNotification)

        // Assert that there was no error and that the chipDetails map is as expected
        assert.NoError(t, err)
        assert.Equal(t, map[string]string{
            "11": "Jericho4/5",
            // ... rest of the chipDetails ...
        }, chipDetails)
    })

    t.Run("ErrorParseUpdates", func(t *testing.T) {
        // Define a parsedNotification without "update" key but with correct prefix
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Sysdb"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "system"},
                    map[string]interface{}{"name": "status"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "fapName"},
                },
            },
        }

        // Call the function under test
        _, err := GetChipDetails(parsedNotification)

        // Assert that there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to parse updates")
    })

    t.Run("ErrorValNotMap", func(t *testing.T) {
        // Define a parsedNotification with "val" not being a map
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Sysdb"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "system"},
                    map[string]interface{}{"name": "status"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "fapName"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "11"},
                        },
                    },
                    "val": "Jericho4/5",
                },
            },
        }

        // Call the function under test
        _, err := GetChipDetails(parsedNotification)

        // Assert that there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected val to be map[string]interface{}")
    })

    t.Run("ErrorValueNotMap", func(t *testing.T) {
        // Define a parsedNotification where "Value" is not a map
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Sysdb"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "system"},
                    map[string]interface{}{"name": "status"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "fapName"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "11"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": "Jericho4/5",
                    },
                },
            },
        }

        // Call the function under test
        _, err := GetChipDetails(parsedNotification)

        // Assert that there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected valMap[\"Value\"] to be map[string]interface{}, got")
    })
    t.Run("ErrorStringValNotString", func(t *testing.T) {
        // Define a parsedNotification where "StringVal" is not a string
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Sysdb"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "system"},
                    map[string]interface{}{"name": "status"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "fapName"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "11"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "StringVal": 123,
                        },
                    },
                },
            },
        }

        // Call the function under test
        _, err := GetChipDetails(parsedNotification)

        // Assert that there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected valueMap[\"StringVal\"] to be string, got")
    })
    t.Run("ErrorPrefixEndsWithCounts", func(t *testing.T) {
        // Define a parsedNotification with prefix ending with "_counts"
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Sysdb"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "system"},
                    map[string]interface{}{"name": "status"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "fapName_counts"},
                },
            },
            // ... rest of the parsedNotification ...
        }

        // Call the function under test
        _, err := GetChipDetails(parsedNotification)

        // Assert that there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "prefix ends with \"_counts\"")
    })
    t.Run("ErrorPrefixNotEqualToFapDetailsGnmiPath", func(t *testing.T) {
        // Define a parsedNotification with prefix not equal to FapDetailsGnmiPath
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Sysdb"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "system"},
                    map[string]interface{}{"name": "status"},
                    map[string]interface{}{"name": "sand"},
                    map[string]interface{}{"name": "some_other_prefix"},
                },
            },
            // ... rest of the parsedNotification ...
        }

        // Call the function under test
        _, err := GetChipDetails(parsedNotification)

        // Assert that there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected prefix to be")
    })

    t.Run("FailGetPrefix", func(t *testing.T) {
        // Define a parsedNotification where the prefix is not a map
        parsedNotification := map[string]interface{}{
            "prefix": "invalid",
        }

        // Call the function under test
        _, err := GetChipDetails(parsedNotification)

        // Assert that there was an error and it contains the expected message
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to get prefix")
    })

}

func TestGetSandCounterUpdates(t *testing.T) {

    // Initialize the chipId to chipName mapping
    LoadChipMappings("../plugin_integration_tests/config/chipid_name_mappings.json")

    t.Run("SuccessfulParse", func(t *testing.T) {
        // Define a parsedNotification for testing
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "Wzc0LDEwMSwxMTQsMTA1LDk5LDEwNCwxMTEsNTEsNDcsNDgsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDBd",
                        },
                    },
                },

                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "counterName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "WzczLDExMiwxMTYsNjcsMTE0LDk5LDY5LDExNCwxMTQsNjcsMTEwLDExNiwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwXQ==",
                        },
                    },
                },

                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "delta1"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "eyJ2YWx1ZSI6MH0=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "delta2"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "eyJ2YWx1ZSI6MH0=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "delta3"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "eyJ2YWx1ZSI6MH0=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "delta4"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "eyJ2YWx1ZSI6MH0=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "delta5"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "eyJ2YWx1ZSI6MH0=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "dropCount"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": 1,
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "eventCount"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": 1,
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "initialEventTime"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "MTY5OTUxODEyOS43MTAxNjI=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "initialThresholdEventTime"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "MC4wMDAwMDA=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "key"},
                            map[string]interface{}{"name": "chipId"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": 0,
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "key"},
                            map[string]interface{}{"name": "chipType"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "StringVal": "fap",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "key"},
                            map[string]interface{}{"name": "counterId"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "eyJ2YWx1ZSI6MX0=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "key"},
                            map[string]interface{}{"name": "offset"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "eyJ2YWx1ZSI6NjU1MzV9",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "lastEventTime"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "MTY5OTUxODEyOS43MTAxNjI=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "lastSyslogTime"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "MC4wMDAwMDA=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "lastThresholdEventTime"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "MC4wMDAwMDA=",
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "thresholdEventCount"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": 0,
                        },
                    },
                },
            },
        }

        // Define a counterName for testing
        counterName := "IptCrcErrCnt"

        // Call the function under test
        chipDetails, err := GetSandCounterUpdates(parsedNotification, counterName)

        // Assert that there was no error and that the chipDetails map is as expected
        assert.NoError(t, err)
        assert.Equal(t, map[string]map[string]interface{}{
            "0": {
                "chipId":                    "0",
                "chipName":                  "Jericho3/0",
                "chipType":                  "fap",
                "counterId":                 float64(1),
                "counterName":               "IptCrcErrCnt",
                "delta1":                    float64(0),
                "delta2":                    float64(0),
                "delta3":                    float64(0),
                "delta4":                    float64(0),
                "delta5":                    float64(0),
                "dropCount":                 "1",
                "eventCount":                "1",
                "initialEventTime":          "1699518129.710162",
                "initialThresholdEventTime": "0.000000",
                "lastEventTime":             "1699518129.710162",
                "lastSyslogTime":            "0.000000",
                "lastThresholdEventTime":    "0.000000",
                "offset":                    float64(65535),
                "thresholdEventCount":       "0",
            },
        }, chipDetails)
    })

    t.Run("FailParseUpdates", func(t *testing.T) {
        // Define a parsedNotification without "update" key but with correct prefix
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }

        // Call the function under test
        _, err := GetSandCounterUpdates(parsedNotification, "IptCrcErrCnt")

        // Assert that there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to parse updates")
    })

    t.Run("FailInvalidValType", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": "invalid",
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected val to be map[string]interface{}, got string")
    })

    t.Run("FailInvalidPath", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "invalid"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "invalid",
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected path to contain chipId, chipType, CounterId, offset and attribute name, got invalid")
    })

    t.Run("FailInvalidCounterId", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_invalid_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "invalid",
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to convert counterId to int")
    })

    t.Run("SkipDifferentCounterId", func(t *testing.T) {
        result, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_2_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "invalid",
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Empty(t, result)
    })

    t.Run("FailInvalidValueType", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": "invalid", // Value is a string, not a map
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected Value to be map[string]interface{}, got string")
    })

    t.Run("FailInvalidBase64", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": "invalid", // JsonVal is not a valid base64 string
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to decode base64 string")
    })

    t.Run("FailInvalidJson", func(t *testing.T) {
        // "invalid" is not valid JSON, but it is a valid base64 string
        invalidJson := base64.StdEncoding.EncodeToString([]byte("invalid"))

        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": invalidJson,
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to unmarshal JSON")
    })

    t.Run("HandleDefaultValue", func(t *testing.T) {
        // Create a bool and encode it as a JSON string
        boolVal := true
        boolJson, _ := json.Marshal(boolVal)
        boolBase64 := base64.StdEncoding.EncodeToString(boolJson)

        result, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "JsonVal": boolBase64,
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Equal(t, map[string]map[string]interface{}{
            "0": {"chipName": boolVal},
        }, result)
    })
    t.Run("HandleInt64UintVal", func(t *testing.T) {
        uintVal := int64(123)

        result, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": uintVal,
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Equal(t, map[string]map[string]interface{}{
            "0": {"chipName": fmt.Sprintf("%d", uintVal)},
        }, result)
    })

    t.Run("HandleFloat64UintVal", func(t *testing.T) {
        uintVal := float64(123.456)

        result, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": uintVal,
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Equal(t, map[string]map[string]interface{}{
            "0": {"chipName": fmt.Sprintf("%f", uintVal)},
        }, result)
    })

    t.Run("HandleBytesVal", func(t *testing.T) {
        bytesVal := []byte("test")

        result, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "BytesVal": bytesVal,
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Equal(t, map[string]map[string]interface{}{
            "0": {"chipName": string(bytesVal)},
        }, result)
    })

    t.Run("HandleInnerMapValue", func(t *testing.T) {
        innerMap := map[string]interface{}{"key": "value"}

        result, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "value": innerMap,
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Equal(t, map[string]map[string]interface{}{
            "0": {"chipName": "value"},
        }, result)
    })
    t.Run("HandleUnexpectedValueType", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "0_fap_1_65535"},
                            map[string]interface{}{"name": "chipName"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UnexpectedVal": "unexpected",
                        },
                    },
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "unexpected value type in Value map")
    })

    t.Run("FailPrefixEndsWithCounts", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters_counts"},
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "prefix ends with \"_counts\"")
    })

    t.Run("FailPrefixNotEqualToSandCountersGnmiPath", func(t *testing.T) {
        _, err := GetSandCounterUpdates(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "NotSandCounters"},
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected prefix to be")
    })

    t.Run("FailGetPrefix", func(t *testing.T) {
        // Define a parsedNotification where the prefix is not a map
        parsedNotification := map[string]interface{}{
            "prefix": "invalid",
        }

        // Call the function under test
        _, err := GetSandCounterUpdates(parsedNotification, "IptCrcErrCnt")

        // Assert that there was an error and it contains the expected message
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to get prefix")
    })
}

func TestGetSandCounterDeletes(t *testing.T) {
    t.Run("SuccessfulParse", func(t *testing.T) {
        // Define a parsedNotification for testing
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "0_fap_1_65535"},
                    },
                },
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "1_fap_2_65536"},
                    },
                },
            },
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }

        // Define a counterName for testing
        counterName := "IptCrcErrCnt"

        // Call the function under test
        chipDetails, err := GetSandCounterDeletes(parsedNotification, counterName)

        // Assert that there was no error and that the chipDetails map is as expected
        assert.NoError(t, err)
        assert.Equal(t, map[string]map[string]interface{}{
            "0": {
                "chipType":  "fap",
                "counterId": 1,
                "offset":    65535,
            },
        }, chipDetails)
    })
    t.Run("FailParseDeletes", func(t *testing.T) {
        _, err := GetSandCounterDeletes(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "delete not found in parsed notification")
    })

    t.Run("FailInvalidDeleteFormat", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                "invalid",
            },
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }
        result, err := GetSandCounterDeletes(parsedNotification, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Empty(t, result)
    })

    t.Run("SkipDifferentCounterId", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "0_fap_2_65535"},
                    },
                },
            },
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }
        result, err := GetSandCounterDeletes(parsedNotification, "IptCrcErrCnt")
        assert.NoError(t, err)
        assert.Empty(t, result)
    })

    t.Run("FailInvalidCounterId", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "0_fap_invalid_65535"},
                    },
                },
            },
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }
        _, err := GetSandCounterDeletes(parsedNotification, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to convert counterId to int")
    })

    t.Run("FailPrefixEndsWithCounts", func(t *testing.T) {
        _, err := GetSandCounterDeletes(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters_counts"},
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "prefix ends with \"_counts\"")
    })

    t.Run("FailPrefixNotEqualToSandCountersGnmiPath", func(t *testing.T) {
        _, err := GetSandCounterDeletes(map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "NotSandCounters"},
                },
            },
        }, "IptCrcErrCnt")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected prefix to be")
    })

    t.Run("FailGetPrefix", func(t *testing.T) {
        // Define a parsedNotification where the prefix is not a map
        parsedNotification := map[string]interface{}{
            "prefix": "invalid",
        }

        // Call the function under test
        _, err := GetSandCounterDeletes(parsedNotification, "IptCrcErrCnt")

        // Assert that there was an error and it contains the expected message
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to get prefix")
    })

    t.Run("FailInvalidDeleteFormat", func(t *testing.T) {
        // Define a parsedNotification where the delete string does not contain enough parts
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "0_fap_1"},
                    },
                },
            },
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }

        // Call the function under test
        _, err := GetSandCounterDeletes(parsedNotification, "IptCrcErrCnt")

        // Assert that there was an error and it contains the expected message
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected delete to contain chipId, chipType, CounterId, and offset")
    })

    t.Run("FailInvalidOffset", func(t *testing.T) {
        // Define a parsedNotification where the offset cannot be converted to an integer
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "0_fap_1_invalid"},
                    },
                },
            },
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "internalDrop"},
                },
            },
        }

        // Call the function under test
        _, err := GetSandCounterDeletes(parsedNotification, "IptCrcErrCnt")

        // Assert that there was an error and it contains the expected message
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to convert offset to int")
    })
}

func TestGetUpdatesCount(t *testing.T) {
    // Test case where prefix does not end with "_counts"
    t.Run("PrefixDoesNotEndWithCounts", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "timestamp": int64(1699698166323923700),
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "internalDrop"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": float64(2),
                        },
                    },
                },
            },
        }

        _, err := GetUpdatesCount(parsedNotification)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected prefix to end with \"_counts\"")
    })

    t.Run("MultipleUpdates", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "timestamp": int64(1699698166323923700),
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "_counts"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "internalDrop"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": float64(2),
                        },
                    },
                },
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "internalDrop1"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": float64(2),
                        },
                    },
                },
            },
        }

        _, err := GetUpdatesCount(parsedNotification)
        if err != nil {
            assert.Contains(t, err.Error(), "expected one update")
        } else {
            t.Fatal("expected an error, got nil")
        }
    })

    // Test case where UintVal is not a float64
    t.Run("UintValNotFloat64", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "timestamp": int64(1699698166323923700),
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "_counts"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "internalDrop"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": "not a float64",
                        },
                    },
                },
            },
        }

        _, err := GetUpdatesCount(parsedNotification)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected valueMap[\"UintVal\"] to be float64")
    })

    t.Run("InvalidPrefix", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "timestamp": int64(1699698166323923700),
            "prefix":    "invalid", // This should cause GetPrefix to return an error
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "internalDrop"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "UintVal": float64(2),
                        },
                    },
                },
            },
        }

        _, err := GetUpdatesCount(parsedNotification)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to get prefix")
    })

    t.Run("InvalidUpdate", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "timestamp": int64(1699698166323923700),
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "_counts"},
                },
            },
            "update": "invalid", // This should cause ParseUpdates to return an error
        }

        _, err := GetUpdatesCount(parsedNotification)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to parse updates")
    })

    t.Run("InvalidValType", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "timestamp": int64(1699698166323923700),
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "_counts"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "internalDrop"},
                        },
                    },
                    "val": "invalid", // This should cause the type assertion to fail
                },
            },
        }

        _, err := GetUpdatesCount(parsedNotification)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected val to be map[string]interface{}")
    })

    t.Run("InvalidValueType", func(t *testing.T) {
        parsedNotification := map[string]interface{}{
            "timestamp": int64(1699698166323923700),
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "Smash"},
                    map[string]interface{}{"name": "hardware"},
                    map[string]interface{}{"name": "counter"},
                    map[string]interface{}{"name": "internalDrop"},
                    map[string]interface{}{"name": "SandCounters"},
                    map[string]interface{}{"name": "_counts"},
                },
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "internalDrop"},
                        },
                    },
                    "val": map[string]interface{}{
                        "Value": "invalid", // This should cause the type assertion to fail
                    },
                },
            },
        }

        _, err := GetUpdatesCount(parsedNotification)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "expected valMap[\"Value\"] to be map[string]interface{}")
    })
}

func TestConvertToChipData(t *testing.T) {
    tests := []struct {
        name    string
        details map[string]interface{}
        want    *LCChipData
        wantErr bool
    }{
        {
            name: "successful conversion",
            details: map[string]interface{}{
                "dropCount":           "6.000000",
                "thresholdEventCount": "0.000000",
                "counterId":           float64(1),
                "chipId":              "6.000000",
                "eventCount":          "1.000000",
                "delta4":              float64(4.294967295e+09),
                "delta2":              float64(0),
                "delta5":              float64(4.294967295e+09),
                "delta1":              float64(0),
                "delta3":              float64(4.294967295e+09),
                "offset":              float64(65535),
                "chipType":            "fap",
                "chipName":            "Jericho4/0",
                "counterName":         "IptCrcErrCnt",
            },
            want: &LCChipData{
                DropCount:           6,
                ThresholdEventCount: 0,
                CounterId:           1,
                ChipId:              6,
                EventCount:          1,
                Delta4:              4.294967295e+09,
                Delta2:              0,
                Delta5:              4.294967295e+09,
                Delta1:              0,
                Delta3:              4.294967295e+09,
                Offset:              65535,
                ChipType:            "fap",
                ChipName:            "Jericho4/0",
                CounterName:         "IptCrcErrCnt",
            },
            wantErr: false,
        },
        {
            name: "invalid type for dropCount",
            details: map[string]interface{}{
                "dropCount": float64(6),
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid value for dropCount",
            details: map[string]interface{}{
                "dropCount": "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for thresholdEventCount",
            details: map[string]interface{}{
                "thresholdEventCount": float64(0),
                "dropCount":           "6.1",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid value for thresholdEventCount",
            details: map[string]interface{}{
                "thresholdEventCount": "invalid",
                "dropCount":           "6.1",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "valid value for thresholdEventCount",
            details: map[string]interface{}{
                "dropCount":           "6.0",
                "thresholdEventCount": "0.000000",
                "counterId":           float64(1),
                "chipId":              "6.000000",
                "eventCount":          "1.000000",
                "delta4":              float64(4.294967295e+09),
                "delta2":              float64(0),
                "delta5":              float64(4.294967295e+09),
                "delta1":              float64(0),
                "delta3":              float64(4.294967295e+09),
                "offset":              float64(65535),
                "chipType":            "fap",
                "chipName":            "Jericho4/0",
                "counterName":         "IptCrcErrCnt",
            },
            want: &LCChipData{
                DropCount:           6,
                ThresholdEventCount: 0,
                CounterId:           1,
                ChipId:              6,
                EventCount:          1,
                Delta4:              4.294967295e+09,
                Delta2:              0,
                Delta5:              4.294967295e+09,
                Delta1:              0,
                Delta3:              4.294967295e+09,
                Offset:              65535,
                ChipType:            "fap",
                ChipName:            "Jericho4/0",
                CounterName:         "IptCrcErrCnt",
            },
            wantErr: false,
        },
        {
            name: "invalid type for counterId",
            details: map[string]interface{}{
                "counterId":           "1",
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for counterId",
            details: map[string]interface{}{
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for chipId",
            details: map[string]interface{}{
                "chipId":              float64(6),
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid value for chipId",
            details: map[string]interface{}{
                "chipId":              "invalid",
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for chipType",
            details: map[string]interface{}{
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for chipName",
            details: map[string]interface{}{
                "chipName":            42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for counterName",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "valid value for offset",
            details: map[string]interface{}{
                "offset":              float64(123),
                "dropCount":           "6.0",
                "thresholdEventCount": "0.000000",
                "counterId":           float64(1),
                "chipId":              "6.000000",
                "eventCount":          "1.000000",
                "delta4":              float64(4.294967295e+09),
                "delta2":              float64(0),
                "delta5":              float64(4.294967295e+09),
                "delta1":              float64(0),
                "delta3":              float64(4.294967295e+09),
                "chipType":            "fap",
                "chipName":            "Jericho4/0",
                "counterName":         "IptCrcErrCnt",
            },
            want: &LCChipData{
                DropCount:           6,
                ThresholdEventCount: 0,
                CounterId:           1,
                ChipId:              6,
                EventCount:          1,
                Delta4:              4.294967295e+09,
                Delta2:              0,
                Delta5:              4.294967295e+09,
                Delta1:              0,
                Delta3:              4.294967295e+09,
                Offset:              123,
                ChipType:            "fap",
                ChipName:            "Jericho4/0",
                CounterName:         "IptCrcErrCnt",
            },
            wantErr: false,
        },
        {
            name: "invalid type for eventCount",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for delta4",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for delta2",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for delta5",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              float64(1.1),
                "delta5":              "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for delta1",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              float64(1.1),
                "delta5":              float64(1.1),
                "delta1":              "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for delta3",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              float64(1.1),
                "delta5":              float64(1.1),
                "delta1":              float64(1.1),
                "delta3":              "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for offset",
            details: map[string]interface{}{
                "counterName":         42,
                "chipType":            42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              float64(1.1),
                "delta5":              float64(1.1),
                "delta1":              float64(1.1),
                "delta3":              float64(1.1),
                "offset":              "invalid",
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for chipType",
            details: map[string]interface{}{
                "counterName":         42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              float64(1.1),
                "delta5":              float64(1.1),
                "delta1":              float64(1.1),
                "delta3":              float64(1.1),
                "offset":              float64(1.1),
                "chipType":            1,
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for chipName",
            details: map[string]interface{}{
                "counterName":         42,
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              float64(1.1),
                "delta5":              float64(1.1),
                "delta1":              float64(1.1),
                "delta3":              float64(1.1),
                "offset":              float64(1.1),
                "chipType":            "type",
                "chipName":            1,
            },
            want:    nil,
            wantErr: true,
        },
        {
            name: "invalid type for counterName",
            details: map[string]interface{}{
                "counterId":           float64(1.1),
                "dropCount":           "6.1",
                "thresholdEventCount": "1.1",
                "chipId":              "1.0",
                "eventCount":          "1.0",
                "delta4":              float64(1.1),
                "delta2":              float64(1.1),
                "delta5":              float64(1.1),
                "delta1":              float64(1.1),
                "delta3":              float64(1.1),
                "offset":              float64(1.1),
                "chipType":            "type",
                "chipName":            "type",
                "counterName":         1,
            },
            want:    nil,
            wantErr: true,
        },
    }
    for _, tt := range tests {
        // Run the function we're testing
        result, err := ConvertToChipData(tt.details)
        fmt.Printf("result: %+v, err: %v for test - %s\n", result, err, tt.name)
        // Check if we got an error when we weren't expecting one, or vice versa
        if (err != nil) != tt.wantErr {
            t.Errorf("got unexpected error: %v for test - %s", err, tt.name)
            continue
        }

        // If we got here, the error status is what we expected (either nil or non-nil),
        // so now we compare the result to what we expected
        if !reflect.DeepEqual(result, tt.want) {
            t.Errorf("got %v, want %v", result, tt.want)
        }
    }
}

func TestLoadChipMappings(t *testing.T) {

    t.Run("SuccessfulLoad", func(t *testing.T) {
        // reset map
        chipIdNameMap = make(map[string]int)

        // Create a temporary file
        tmpfile, err := ioutil.TempFile("", "example")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write test data to the file
        testData := `{
            "FirstEntry": 0,
            "IptCrcErrCnt": 1,
            "UcFifoFullDrop": 2
        }`
        if _, err := tmpfile.Write([]byte(testData)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Test LoadChipMappings
        err = LoadChipMappings(tmpfile.Name())
        if err != nil {
            t.Fatal(err)
        }

        // Check that chipIdNameMap was populated correctly
        if len(chipIdNameMap) != 3 {
            t.Errorf("expected chipIdNameMap to have 3 entries, got %d", len(chipIdNameMap))
        }
        if chipIdNameMap["FirstEntry"] != 0 {
            t.Errorf("expected FirstEntry to map to 0, got %d", chipIdNameMap["FirstEntry"])
        }
        if chipIdNameMap["IptCrcErrCnt"] != 1 {
            t.Errorf("expected IptCrcErrCnt to map to 1, got %d", chipIdNameMap["IptCrcErrCnt"])
        }
        if chipIdNameMap["UcFifoFullDrop"] != 2 {
            t.Errorf("expected UcFifoFullDrop to map to 2, got %d", chipIdNameMap["UcFifoFullDrop"])
        }

        // Test LoadChipMappings with an already populated chipIdNameMap
        err = LoadChipMappings(tmpfile.Name())
        if err != nil {
            t.Fatal(err)
        }
    })

    t.Run("Invalid file", func(t *testing.T) {
        // reset map
        chipIdNameMap = make(map[string]int)

        // Test LoadChipMappings with a non-existent file
        err := LoadChipMappings("nonexistentfile.json")
        if err == nil {
            t.Error("expected LoadChipMappings to return an error for a non-existent file, got nil")
        }
    })

    t.Run("FailInvalidJson", func(t *testing.T) {
        // reset map
        chipIdNameMap = make(map[string]int)

        // Create a temporary file
        tmpfile, err := ioutil.TempFile("", "example")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write invalid JSON to the file
        if _, err := tmpfile.Write([]byte("{")); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Test LoadChipMappings with invalid JSON
        err = LoadChipMappings(tmpfile.Name())
        if err == nil {
            t.Error("expected LoadChipMappings to return an error for invalid JSON, got nil")
        }
    })

    t.Run("ALready populated values in global map", func(t *testing.T) {
        // reset map
        chipIdNameMap = make(map[string]int)

        // Populate the global map
        chipIdNameMap["FirstEntry"] = 0
        chipIdNameMap["IptCrcErrCnt"] = 1
        chipIdNameMap["UcFifoFullDrop"] = 2

        // Create a temporary file
        tmpfile, err := ioutil.TempFile("", "example")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write test data to the file
        testData := `{
            "FirstEntry": 0,
            "IptCrcErrCnt": 1,
            "UcFifoFullDrop": 2
        }`
        if _, err := tmpfile.Write([]byte(testData)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Test LoadChipMappings
        err = LoadChipMappings(tmpfile.Name())
        if err != nil {
            t.Fatal(err)
        }

        // Check that chipIdNameMap was populated correctly
        if len(chipIdNameMap) != 3 {
            t.Errorf("expected chipIdNameMap to have 3 entries, got %d", len(chipIdNameMap))
        }
        if chipIdNameMap["FirstEntry"] != 0 {
            t.Errorf("expected FirstEntry to map to 0, got %d", chipIdNameMap["FirstEntry"])
        }
        if chipIdNameMap["IptCrcErrCnt"] != 1 {
            t.Errorf("expected IptCrcErrCnt to map to 1, got %d", chipIdNameMap["IptCrcErrCnt"])
        }
        if chipIdNameMap["UcFifoFullDrop"] != 2 {
            t.Errorf("expected UcFifoFullDrop to map to 2, got %d", chipIdNameMap["UcFifoFullDrop"])
        }
    })
}
