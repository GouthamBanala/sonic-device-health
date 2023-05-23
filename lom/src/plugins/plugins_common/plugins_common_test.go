package plugins_common

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

func TestCheckMisbehavingPlugins(t *testing.T) {
    // Create a new PluginMetadata object
    pluginMetadata := &PluginMetadata{
        PluginResponseRollingWindow: PluginResponseRollingWindow{
            response: make(map[string][]time.Time),
        },
    }

    // Test case 1: First response for the plugin
    pluginKey := "plugin1"
    result := pluginMetadata.CheckMisbehavingPlugins(pluginKey)
    assert.False(t, result, "Expected CheckMisbehavingPlugins to return false for the first response")

    // Test case 2: Add multiple responses exceed the window time
    pluginMetadata.MaxPluginResponses = 2
    pluginMetadata.MaxPluginResponsesWindowTime = 1 * time.Minute
    now := time.Now()
    pluginMetadata.PluginResponseRollingWindow.response[pluginKey] = []time.Time{now.Add(-time.Minute), now.Add(-30 * time.Second)}
    result = pluginMetadata.CheckMisbehavingPlugins(pluginKey)
    assert.True(t, result, "Expected CheckMisbehavingPlugins to return false when window size hasn't reached the limit")

    // Test case 3: Add responses that within the window size
    pluginMetadata.MaxPluginResponses = 4
    pluginMetadata.PluginResponseRollingWindow.response = make(map[string][]time.Time)
    pluginMetadata.PluginResponseRollingWindow.response[pluginKey] = []time.Time{now.Add(-time.Minute), now.Add(-30 * time.Second), now}
    result = pluginMetadata.CheckMisbehavingPlugins(pluginKey)
    assert.False(t, result, "Expected CheckMisbehavingPlugins to return true when window size has reached the limit")
}

func TestGetPluginStage(t *testing.T) {
    // Create a new PluginMetadata object
    pluginMetadata := &PluginMetadata{
        Pluginstage: PluginStageLoadingSuccess,
    }

    // Test case 1: Get the plugin stage
    result := pluginMetadata.GetPluginStage()
    assert.Equal(t, PluginStageLoadingSuccess, result, "Expected GetPluginStage to return PluginStageLoadingSuccess")
}

func TestSetPluginStage(t *testing.T) {
    // Create a new PluginMetadata object
    pluginMetadata := &PluginMetadata{
        Pluginstage: PluginStageLoadingSuccess,
    }

    // Test case 1: Set the plugin stage
    pluginMetadata.SetPluginStage(PluginStageRequestStarted)
    assert.Equal(t, PluginStageRequestStarted, pluginMetadata.Pluginstage, "Expected SetPluginStage to set the plugin stage to PluginStageRequestStarted")
}

func TestSetPluginStageName(t *testing.T) {

    assert.Equal(t, "Loading success", GetPluginStageToString(PluginStageLoadingSuccess),
        "Expected Sstring to be  Loading succes")
    assert.Equal(t, "Unknown stage", GetPluginStageToString(100),
        "Expected Sstring to be  Loading succes")
}
