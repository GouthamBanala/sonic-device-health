package libtest

import (
    "fmt"
    . "lom/src/lib/lomcommon"
    "testing"

    "github.com/stretchr/testify/assert"
)

func init() {
    InitSyslogWriter("")
}

/* Validates GetFloatConfigFromMapping for various config keys */
func Test_GetFloatConfigFromMapping(t *testing.T) {
    map1 := map[string]interface{}{"abc": 123.99}
    map2 := map[string]interface{}{"abc": 123}
    map3 := map1
    map4 := make(map[string]interface{})
    map5 := map[string]interface{}{"abc": float64(123)}
    expectedResult := []float64{123.99, 222.22, 222.22, 222.22, 123}
    configKey := []string{"abc", "abc", "xyz", "abc", "abc"}
    arrayOfMaps := []map[string]interface{}{map1, map2, map3, map4, map5}

    assert := assert.New(t)
    for index := 0; index < len(arrayOfMaps); index++ {
        result := GetFloatConfigFromMapping(arrayOfMaps[index], configKey[index], 222.22)
        assert.Equal(expectedResult[index], result, fmt.Sprintf("GetFloatConfigFromMapping Failed for test index : %d", index))
    }
}
