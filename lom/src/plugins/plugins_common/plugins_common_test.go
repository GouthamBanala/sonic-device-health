package plugins_common

import (
    "fmt"
    "log/syslog"
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "sync"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

func TestCheckMisbehavingPlugins(t *testing.T) {
    // Create a new PluginMetadata object
    pluginMetadata := &PluginMetadata{
        PluginResponseRollingWindow: PluginResponseRollingWindow{
            Response: make(map[string][]time.Time),
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
    pluginMetadata.PluginResponseRollingWindow.Response[pluginKey] = []time.Time{now.Add(-time.Minute), now.Add(-30 * time.Second)}
    result = pluginMetadata.CheckMisbehavingPlugins(pluginKey)
    assert.True(t, result, "Expected CheckMisbehavingPlugins to return false when window size hasn't reached the limit")

    // Test case 3: Add responses that within the window size
    pluginMetadata.MaxPluginResponses = 4
    pluginMetadata.PluginResponseRollingWindow.Response = make(map[string][]time.Time)
    pluginMetadata.PluginResponseRollingWindow.Response[pluginKey] = []time.Time{now.Add(-time.Minute), now.Add(-30 * time.Second), now}
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

func Test_GetUniqueID(t *testing.T) {
    t.Run("test unique IDs", func(t *testing.T) {
        id1 := GetUniqueID()
        id2 := GetUniqueID()

        assert := assert.New(t)
        assert.NotEqual(id1, id2, "IDs are expected to be unique")
    })

    t.Run("test unique IDs with concurrency", func(t *testing.T) {
        var wg sync.WaitGroup
        var mu sync.Mutex
        ids := make(map[string]bool)

        for i := 0; i < 100; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                id := GetUniqueID()

                mu.Lock()
                if _, exists := ids[id]; exists {
                    t.Errorf("Duplicate ID found: %s", id)
                }
                ids[id] = true
                mu.Unlock()
            }()
        }

        wg.Wait()
    })
}

func Test_PluginLogger(t *testing.T) {
    var receivedMessage string
    var receivedPriority syslog.Priority

    // Mock log function that records the received message and priority
    mockLogFunc := func(skip int, priority syslog.Priority, messageFmt string, args ...interface{}) string {
        receivedMessage = fmt.Sprintf(messageFmt, args...)
        receivedPriority = priority
        return receivedMessage
    }

    logger := NewLogger("test", mockLogFunc)

    t.Run("LogInfo", func(t *testing.T) {
        expectedMessage := "test: This is an info message"
        expectedPriority := syslog.LOG_INFO

        msg := logger.LogInfo("This is an info message")

        assert := assert.New(t)
        assert.Equal(expectedMessage, msg)
        assert.Equal(expectedMessage, receivedMessage)
        assert.Equal(expectedPriority, receivedPriority)
    })

    t.Run("LogError", func(t *testing.T) {
        expectedMessage := "test: This is an error message"
        expectedPriority := syslog.LOG_ERR

        err := logger.LogError("This is an error message")

        assert := assert.New(t)
        assert.Error(err)
        assert.Equal(expectedMessage, err.Error())
        assert.Equal(expectedMessage, receivedMessage)
        assert.Equal(expectedPriority, receivedPriority)
    })

    t.Run("LogDebug", func(t *testing.T) {
        expectedMessage := "test: This is a debug message"
        expectedPriority := syslog.LOG_DEBUG

        msg := logger.LogDebug("This is a debug message")

        assert := assert.New(t)
        assert.Equal(expectedMessage, msg)
        assert.Equal(expectedMessage, receivedMessage)
        assert.Equal(expectedPriority, receivedPriority)
    })

    t.Run("LogWarning", func(t *testing.T) {
        expectedMessage := "test: This is a warning message"
        expectedPriority := syslog.LOG_WARNING

        msg := logger.LogWarning("This is a warning message")

        assert := assert.New(t)
        assert.Equal(expectedMessage, msg)
        assert.Equal(expectedMessage, receivedMessage)
        assert.Equal(expectedPriority, receivedPriority)
    })

    t.Run("LogPanic", func(t *testing.T) {
        expectedMessage := "test: This is a panic message"
        expectedPriority := syslog.LOG_CRIT

        msg := logger.LogPanic("This is a panic message")

        assert := assert.New(t)
        assert.Equal(expectedMessage, msg)
        assert.Equal(expectedMessage, receivedMessage)
        assert.Equal(expectedPriority, receivedPriority)
    })
}

type MockPlugin struct{}

func (m *MockPlugin) Init(actionCfg *lomcommon.ActionCfg_t) error { return nil }
func (m *MockPlugin) Request(hbchan chan PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {
    return nil
}
func (m *MockPlugin) Shutdown() error       { return nil }
func (m *MockPlugin) GetPluginID() PluginId { return PluginId{} }

func MockPluginConstructor(args ...interface{}) Plugin {
    return &MockPlugin{}
}

func TestRegisterPlugin(t *testing.T) {
    // Register a mock plugin
    RegisterPlugin("mock", MockPluginConstructor)

    // Assert that the plugin was registered
    constructor, exists := PluginConstructors["mock"]
    assert.True(t, exists, "Expected plugin to be registered")

    // Assert that the constructor is the correct function
    plugin := constructor()
    _, ok := plugin.(*MockPlugin)
    assert.True(t, ok, "Expected constructor to return a MockPlugin")
}
