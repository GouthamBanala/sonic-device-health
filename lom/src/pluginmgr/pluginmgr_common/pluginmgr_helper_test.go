package pluginmgr_common

import (
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "lom/src/plugins/plugins_common"

    "errors"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    //"os/signal"
    //"flag"
    "fmt"
    //"io/ioutil"
    "log/syslog"
    "os"
    //"regexp"
    "sync"
    "syscall"
    "testing"
    //"time"
    "flag"
    "strings"
    "sync/atomic"
    "time"
)

// ------------------------------------------ Plugins -------------------------------------------------------------//
// Define a mock struct for the ClientTx interface
type mockClientTx struct {
    mock.Mock
}

func (m *mockClientTx) RegisterClient(client string) error {
    args := m.Called(client)
    return args.Error(0)
}

func (m *mockClientTx) DeregisterClient() error {
    args := m.Called()
    return args.Error(0)
}

func (m *mockClientTx) RegisterAction(action string) error {
    args := m.Called(action)
    return args.Error(0)
}

func (m *mockClientTx) DeregisterAction(action string) error {
    args := m.Called(action)
    return args.Error(0)
}

func (m *mockClientTx) RecvServerRequest() (*lomipc.ServerRequestData, error) {
    args := m.Called()
    var v1 *lomipc.ServerRequestData
    if args.Get(0) != nil {
        v1 = args.Get(0).(*lomipc.ServerRequestData)
    }
    v2 := args.Error(1)
    return v1, v2
}

func (m *mockClientTx) SendServerResponse(res *lomipc.MsgSendServerResponse) error {
    args := m.Called(res)
    return args.Error(0)
}

func (m *mockClientTx) NotifyHeartbeat(action string, tstamp int64) error {
    args := m.Called(action, tstamp)
    return args.Error(0)
}

// ------------------------------------------ Plugins -------------------------------------------------------------//
// Define a mock struct for the Plugin interface
type MockPlugin struct {
    mock.Mock
}

func (m *MockPlugin) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {
    args := m.Called(hbchan, request)
    return args.Get(0).(*lomipc.ActionResponseData)
}

func (m *MockPlugin) Init(actionCfg *lomcommon.ActionCfg_t) error {
    args := m.Called(actionCfg)
    return args.Error(0)
}

func (m *MockPlugin) Shutdown() error {
    args := m.Called()
    return args.Error(0)
}

func (m *MockPlugin) GetPluginID() plugins_common.PluginId {
    args := m.Called()
    return args.Get(0).(plugins_common.PluginId)
}

// ------------------------------------------ PluginMetadata -------------------------------------------------------//

type MockPluginMetadata struct {
    mock.Mock
}

func (m *MockPluginMetadata) GetPluginStage() plugins_common.PluginStage {
    args := m.Called()
    return args.Get(0).(plugins_common.PluginStage)
}

func (m *MockPluginMetadata) SetPluginStage(stage plugins_common.PluginStage) {
    m.Called(stage)
}

func (m *MockPluginMetadata) CheckMisbehavingPlugins(pluginKey string) bool {
    args := m.Called(pluginKey)
    return args.Bool(0)
}

// ------------------------------------------ Logger -------------------------------------------------------------//

type myLogger struct {
    data []string
    pid  string
    mu   sync.Mutex
}

func (m *myLogger) LogInfo(s string, a ...interface{}) {
    msg := fmt.Sprintf(s, a...)
    m.mu.Lock()
    defer m.mu.Unlock()
    m.data = append(m.data, msg)
    fmt.Println(m.pid + " : " + msg)
}

func (m *myLogger) LogError(s string, a ...interface{}) error {
    msg := fmt.Sprintf(s, a...)
    m.mu.Lock()
    defer m.mu.Unlock()
    m.data = append(m.data, msg)
    err := errors.New(msg)
    fmt.Println(m.pid + " : " + msg)
    return err
}

func (m *myLogger) LogDebug(s string, a ...interface{}) {
    msg := fmt.Sprintf(s, a...)
    m.mu.Lock()
    defer m.mu.Unlock()
    m.data = append(m.data, msg)
    fmt.Println(m.pid + " : " + msg)
}

func (m *myLogger) LogWarning(s string, a ...interface{}) {
    msg := fmt.Sprintf(s, a...)
    m.mu.Lock()
    defer m.mu.Unlock()
    m.data = append(m.data, msg)
    fmt.Println(m.pid + " : " + msg)
}

func (m *myLogger) LogPanic(s string, a ...interface{}) {
    msg := fmt.Sprintf(s, a...)
    m.mu.Lock()
    defer m.mu.Unlock()
    m.data = append(m.data, msg)
    fmt.Println(m.pid + " : " + msg)
}

func (m *myLogger) FindPrefix(prefix string) bool {
    m.mu.Lock()
    defer m.mu.Unlock()
    for _, msg := range m.data {
        if strings.HasPrefix(msg, prefix) {
            return true
        }
    }
    return false
}

func (m *myLogger) FindPrefixWait(prefix string, waitTime time.Duration) bool {
    m.mu.Lock()
    defer m.mu.Unlock()

    startTime := time.Now()
    endTime := startTime.Add(waitTime)

    for {
        for _, msg := range m.data {
            if strings.HasPrefix(msg, prefix) {
                return true
            }
        }

        if time.Now().After(endTime) {
            break
        }

        time.Sleep(1000 * time.Millisecond)
    }

    return false
}

func (m *myLogger) myAddPeriodicLogWithTimeouts(ID string, message string, shortTimeout time.Duration,
    longTimeout time.Duration) chan bool {
    doneChan := make(chan bool)
    //msg := fmt.Sprintf(s, a...)
    m.mu.Lock()
    defer m.mu.Unlock()
    m.data = append(m.data, message)
    fmt.Println(m.pid + " : " + message)

    return doneChan
}

// ------------------------------------------ Setup -------------------------------------------------------------//

func setupMockLogger(pid string) *myLogger {
    // Create a mockLogger instance
    mockLogger := new(myLogger)
    mockLogger.pid = pid
    fmt.Println("")
    // Replace the logger functions with the mockLogger functions
    LogInfo = mockLogger.LogInfo
    LogError = mockLogger.LogError
    LogDebug = mockLogger.LogDebug
    LogWarning = mockLogger.LogWarning
    LogPanic = mockLogger.LogPanic
    AddPeriodicLogWithTimeouts = mockLogger.myAddPeriodicLogWithTimeouts
    return mockLogger
}

func resetMockLogger() {
    // Replace the logger functions with the lomcommon
    LogInfo = lomcommon.LogInfo
    LogError = lomcommon.LogError
    LogDebug = lomcommon.LogDebug
    LogWarning = lomcommon.LogWarning
    LogPanic = lomcommon.LogPanic
    AddPeriodicLogWithTimeouts = lomcommon.AddPeriodicLogWithTimeouts
}

var globalLock sync.Mutex

func setup() *myLogger {
    globalLock.Lock()
    defer globalLock.Unlock()

    pluginMgr = nil
    ProcID = "proc_0" + fmt.Sprintf("%d", time.Now().UnixNano())
    lomcommon.SetPrefix(ProcID)
    resetMockLogger()
    myLogger := setupMockLogger(ProcID)
    //os.Setenv("LOM_TESTMODE_NAME", "yes")
    lomcommon.SetLoMRunMode(lomcommon.LoMRunMode_Test)

    return myLogger
}

func SearchGoroutineTracker(namePrefix string) bool {
    goroutineInfoList := lomcommon.GetGoroutineTracker().InfoList(nil)

    for _, info := range goroutineInfoList {
        goroutineInfo := info.(lomcommon.GoroutineInfo)
        if strings.HasPrefix(goroutineInfo.Name, namePrefix) {
            return true
        }
    }

    return false
}

// ------------------------------------------ Tests -------------------------------------------------------------//

// Test Run() function
func TestNewPluginManager(t *testing.T) {
    // Setup
    setup()
    mockClient := new(mockClientTx)
    mockClient.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

    obj := GetPluginManager(mockClient)

    // Verification
    assert.NotNil(t, obj)

    // since object is already created, it should return the same object
    obj2 := GetPluginManager(mockClient)

    // Verification
    assert.NotNil(t, obj)
    assert.Equal(t, obj, obj2)
}

func TestNewPluginManager2(t *testing.T) {
    // Setup
    logger := setup()
    mockClient := new(mockClientTx)
    mockClient.On("RegisterClient", mock.Anything).Return(errors.New("some error")) // pass anything as first argument

    GetPluginManager(mockClient)

    if !logger.FindPrefix("Error in registering Plugin manager client for procId : ") {
        t.Errorf("Expected log message not found")
    }

    mockClient.AssertExpectations(t)
}

func TestGetPlugin(t *testing.T) {
    // Create a PluginManager object
    pluginManager := &PluginManager{
        plugins: map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
            "plugin2": &MockPlugin{},
        },
    }

    // Call the function being tested
    plugin, ok := pluginManager.getPlugin("plugin1")

    // Assert that the plugin was retrieved successfully
    assert.NotNil(t, plugin)
    assert.True(t, ok)

    // Call the function being tested with a plugin name that doesn't exist
    plugin, ok = pluginManager.getPlugin("plugin3")

    // Assert that the plugin was not retrieved successfully
    assert.Nil(t, plugin)
    assert.False(t, ok)
}

func TestGetPluginMetadata(t *testing.T) {
    // Create a PluginManager object
    pluginManager := &PluginManager{
        pluginMetadata: map[string]plugins_common.IPluginMetadata{
            "plugin1": &plugins_common.PluginMetadata{},
            "plugin2": &plugins_common.PluginMetadata{},
        },
    }

    // Call the function being tested with a plugin name that does exist
    pluginMetadata, ok := pluginManager.getPluginMetadata("plugin1")

    // Assert that the plugin metadata was retrieved successfully
    assert.NotNil(t, pluginMetadata)
    assert.True(t, ok)

    // Call the function being tested with a plugin name that doesn't exist
    pluginMetadata, ok = pluginManager.getPluginMetadata("plugin3")

    // Assert that the plugin metadata was not retrieved successfully
    assert.Nil(t, pluginMetadata)
    assert.False(t, ok)
}

func TestSetShutdownStatus(t *testing.T) {
    // Create a PluginManager object
    pluginManager := &PluginManager{}

    // Call the function being tested with a value of true
    pluginManager.setShutdownStatus(true)

    // Assert that the isActiveShutdown variable was set to true
    assert.True(t, pluginManager.getShutdownStatus())

    // Call the function being tested with a value of false
    pluginManager.setShutdownStatus(false)

    // Assert that the isActiveShutdown variable was set to false
    assert.False(t, pluginManager.getShutdownStatus())
}

func TestGetShutdownStatus(t *testing.T) {
    // Create a PluginManager object
    pluginManager := &PluginManager{}

    // Set the isActiveShutdown variable to true
    atomic.StoreInt32(&pluginManager.isActiveShutdown, 1)

    // Call the function being tested
    isActiveShutdown := pluginManager.getShutdownStatus()

    // Assert that the isActiveShutdown variable was retrieved successfully
    assert.True(t, isActiveShutdown)
}

func TestRun(t *testing.T) {

    t.Run("Run test start goroutine 1", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        //logger := setupMockLogger()
        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        // Set up the expectations for the mock objects
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        err := plmgr.run()
        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("In run() RecvServerRequest : Unknown server request type :") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In run() RecvServerRequest: Shutdown is active, ignoring request:") {
            t.Errorf("Expected log message not found")
        }

        //if !logger.FindPrefix("RecvServerRequest() : Received system shutdown. Stopping plugin manager run loop") {
        //  t.Errorf("Expected log message not found")
        //}

        // Assertions
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test start goroutine 2", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        //logger := setupMockLogger()
        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        // Set up the expectations for the mock objects
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, errors.New("some error"))

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        err := plmgr.run()
        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("Error in run() RecvServerRequest:") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In run() RecvServerRequest: Shutdown is active, ignoring request:") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("RecvServerRequest() : Received system shutdown. Stopping plugin manager run loop") {
            t.Errorf("Expected log message not found")
        }

        // Assertions
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test start goroutine 3", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        //logger := setupMockLogger()
        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        // Set up the expectations for the mock objects
        clientTx.On("RecvServerRequest").Return(nil, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        err := plmgr.run()
        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("run() RecvServerRequest returned :") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In run() RecvServerRequest: Shutdown is active, ignoring request:") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("RecvServerRequest() : Received system shutdown. Stopping plugin manager run loop") {
            t.Errorf("Expected log message not found")
        }

        assert.Nil(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine  TypeServerRequestAction 1", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        //logger := setupMockLogger()
        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        // Set up the expectations for the mock objects
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{
            ReqType: lomipc.TypeServerRequestAction,
            ReqData: &lomipc.ActionRequestData{
                Action: "nonexistent_plugin", // invalid plugin name
            },
        }, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        err := plmgr.run()
        time.Sleep(100 * time.Millisecond)

        if !logger.FindPrefix("In run() RecvServerRequest : Received action request") {
            t.Errorf("Expected log message not found")
        }

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine TypeServerRequestAction 2", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        //logger := setupMockLogger()
        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        // Set up the expectations for the mock objects
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{
            ReqType: lomipc.TypeServerRequestAction,
            ReqData: nil,
        }, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        err := plmgr.run()
        time.Sleep(100 * time.Millisecond)

        if !logger.FindPrefix("In run() RecvServerRequest : Error in parsing ActionRequestData for type :") {
            t.Errorf("Expected log message not found")
        }

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine  TypeServerRequestShutdown 1", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("DeregisterClient").Return(nil)

        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        DeregisterForSysShutdown = func(caller string) {
            // do nothing
        }

        DoSysShutdown = func(toutSecs int) {
            // do nothing
        }

        osExit = func(code int) {
            LogInfo("My osExit called")
        }

        // Set up the expectations for the mock objects
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{
            ReqType: lomipc.TypeServerRequestShutdown,
            ReqData: &lomipc.ShutdownRequestData{}, // valid request
        }, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        err := plmgr.run()
        time.Sleep(10000 * time.Millisecond)

        if !logger.FindPrefix("In run() RecvServerRequest : Received shutdown request :") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefixWait("My osExit called", 60*time.Second) {
            t.Errorf("Expected log message not found")
        }

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine  TypeServerRequestShutdown 2", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        DeregisterForSysShutdown = func(caller string) {
            // do nothing
        }

        DoSysShutdown = func(toutSecs int) {
            // do nothing
        }

        // Set up the expectations for the mock objects
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{
            ReqType: lomipc.TypeServerRequestShutdown,
            ReqData: nil, //invalid request
        }, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        err := plmgr.run()
        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("In run() RecvServerRequest : Received shutdown request :") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In run RecvServerRequest : Error in parsing ShutdownRequestData for type :") {
            t.Errorf("Expected log message not found")
        }

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine  responseChan  MsgNotifyHeartbeat 1", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, nil)
        clientTx.On("NotifyHeartbeat", mock.Anything, mock.Anything).Return(errors.New("errorggg"))

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        // Create the response object
        serverResp := lomipc.MsgNotifyHeartbeat{
            Action:    "dummy_plugin",
            Timestamp: time.Now().UnixNano(),
        }

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
            plmgr.responseChan <- serverResp
        }()

        plmgr.responseChan <- serverResp
        err := plmgr.run()

        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("In run() : Received response object : ") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In run() : Error in NotifyHeartbeat() : ") {
            t.Errorf("Expected log message not found")
        }

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine  responseChan  MsgNotifyHeartbeat 2", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, nil)
        clientTx.On("NotifyHeartbeat", mock.Anything, mock.Anything).Return(nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        // Create the response object
        serverResp := lomipc.MsgNotifyHeartbeat{
            Action:    "dummy_plugin",
            Timestamp: time.Now().UnixNano(),
        }

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
            plmgr.responseChan <- serverResp
        }()

        plmgr.responseChan <- serverResp
        err := plmgr.run()

        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("In run() : Received response object : ") {
            t.Errorf("Expected log message not found")
        }

        if logger.FindPrefix("In run() : Error in NotifyHeartbeat() : ") {
            t.Errorf("Expected log message not found")
        }

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine  responseChan 1", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, nil)
        clientTx.On("SendServerResponse", mock.Anything).Return(errors.New("errorggg"))

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        // Create the response object
        serverResp := &lomipc.MsgSendServerResponse{
            ReqType: lomipc.TypeServerRequestAction,
            ResData: nil,
        }

        // Set up the expectations for the logger mock
        //expectedLogInfoArg := "run() : Received response object : %v"

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        plmgr.responseChan <- serverResp
        err := plmgr.run()

        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("In run() : Received response object :") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In run() : Error in SendServerResponse() : ") {
            t.Errorf("Expected log message not found")
        }

        //if !logger.FindPrefixWait("In run() RecvServerRequest: Shutdown is active, ignoring request:", 1*time.Second) {
        //   t.Errorf("Expected log message not found")
        //}

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })

    t.Run("Run test main goroutine  responseChan 2", func(t *testing.T) {
        logger := setup()
        // Create the mock objects
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        syschan := make(chan int, 1)
        RegisterForSysShutdown = func(caller string) <-chan int {
            return syschan
        }

        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, nil)
        clientTx.On("SendServerResponse", mock.Anything).Return(nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.setShutdownStatus(false)

        // Create the response object
        serverResp := &lomipc.MsgSendServerResponse{
            ReqType: lomipc.TypeServerRequestAction,
            ResData: nil,
        }

        go func() {
            time.Sleep(5 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
            close(syschan)                // kill the run's main loop
            time.Sleep(1 * time.Millisecond)
        }()

        plmgr.responseChan <- serverResp
        err := plmgr.run()

        time.Sleep(10 * time.Millisecond)

        if !logger.FindPrefix("In run() : Received response object :") {
            t.Errorf("Expected log message not found")
        }

        if logger.FindPrefix("In run() : Error in SendServerResponse() : ") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefixWait("In run() RecvServerRequest: Shutdown is active, ignoring request:", 1*time.Second) {
            t.Errorf("Expected log message not found")
        }

        // Verification
        assert.NoError(t, err)
        clientTx.AssertExpectations(t)
    })
}

func TestVerifyRequestMsg(t *testing.T) {
    // Create a mock logger
    logger := setup()

    // Create the mock objects
    clientTx := new(mockClientTx)
    clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

    // Create the PluginManager instance with the mock objects
    plmgr := GetPluginManager(clientTx)
    plmgr.setShutdownStatus(false)

    // Mock plugin and metadata
    mockPlugin := new(MockPlugin)
    mockMetadata := new(MockPluginMetadata)
    plmgr.plugins["pluginA"] = mockPlugin
    plmgr.pluginMetadata["pluginA"] = mockMetadata

    // Test case 1: nil request data
    plugin, metadata, err := plmgr.verifyRequestMsg(nil)
    assert.Nil(t, plugin)
    assert.Nil(t, metadata)
    assert.Error(t, err)
    if !logger.FindPrefix("verifyRequestMsg() : nil request data") {
        t.Errorf("Expected log message not found")
    }

    // Test case 2: empty action
    actionReq := &lomipc.ActionRequestData{
        Action: "",
    }
    plugin, metadata, err = plmgr.verifyRequestMsg(actionReq)
    assert.Nil(t, plugin)
    assert.Nil(t, metadata)
    assert.Error(t, err)
    if !logger.FindPrefix("verifyRequestMsg() : empty action name") {
        t.Errorf("Expected log message not found")
    }

    // Test case 3: plugin not initialized
    actionReq = &lomipc.ActionRequestData{
        Action: "pluginB",
    }
    plugin, metadata, err = plmgr.verifyRequestMsg(actionReq)
    assert.Nil(t, plugin)
    assert.Nil(t, metadata)
    assert.Error(t, err)
    if !logger.FindPrefix("verifyRequestMsg() : Plugin pluginB not initialized") {
        t.Errorf("Expected log message not found")
    }

    // Test case 4: plugin is nil
    actionReq = &lomipc.ActionRequestData{
        Action: "pluginA",
    }
    plmgr.plugins["pluginA"] = nil
    plugin, metadata, err = plmgr.verifyRequestMsg(actionReq)
    assert.Nil(t, plugin)
    assert.Nil(t, metadata)
    assert.Error(t, err)
    if !logger.FindPrefix("verifyRequestMsg() : Plugin pluginA is nil") {
        t.Errorf("Expected log message not found")
    }

    // Test case 5: plugin metadata not initialized
    actionReq = &lomipc.ActionRequestData{
        Action: "pluginA",
    }
    plmgr.plugins["pluginA"] = mockPlugin
    delete(plmgr.pluginMetadata, "pluginA")
    plugin, metadata, err = plmgr.verifyRequestMsg(actionReq)
    assert.Nil(t, plugin)
    assert.Nil(t, metadata)
    assert.Error(t, err)
    if !logger.FindPrefix("verifyRequestMsg() : Plugin pluginA metadata not initialized") {
        t.Errorf("Expected log message not found")
    }

    // Test case 6: plugin metadata is nil
    actionReq = &lomipc.ActionRequestData{
        Action: "pluginA",
    }
    plmgr.plugins["pluginA"] = mockPlugin
    plmgr.pluginMetadata["pluginA"] = nil
    plugin, metadata, err = plmgr.verifyRequestMsg(actionReq)
    assert.Nil(t, plugin)
    assert.Nil(t, metadata)
    assert.Error(t, err)
    if !logger.FindPrefix("verifyRequestMsg() : Plugin pluginA metadata is nil") {
        t.Errorf("Expected log message not found")
    }

    // Test case 7: invalid plugin stage
    actionReq = &lomipc.ActionRequestData{
        Action: "pluginA",
    }
    plmgr.plugins["pluginA"] = mockPlugin
    plmgr.pluginMetadata["pluginA"] = mockMetadata
    mockMetadata.On("GetPluginStage").Return(plugins_common.PluginStageDisabled).Once()
    plugin, metadata, err = plmgr.verifyRequestMsg(actionReq)
    assert.Nil(t, plugin)
    assert.Nil(t, metadata)
    assert.Error(t, err)
    if !logger.FindPrefix("verifyRequestMsg() : Unable to process request for Plugin pluginA. Reason : Disabled") {
        t.Errorf("Expected log message not found")
    }

    // Test case 8: valid request
    actionReq = &lomipc.ActionRequestData{
        Action: "pluginA",
    }
    mockMetadata.On("GetPluginStage").Return(plugins_common.PluginStageRequestSuccess)
    plugin, metadata, err = plmgr.verifyRequestMsg(actionReq)
    assert.NotNil(t, plugin)
    assert.NotNil(t, metadata)
    assert.NoError(t, err)
}

func TestHandleMisbehavingPlugins(t *testing.T) {
    t.Run("TestHandleMisbehavingPlugins 1", func(t *testing.T) {

        // Create a mock logger
        logger := setup()
        mockMetadata := new(MockPluginMetadata)
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil)   // pass anything as first argument
        clientTx.On("DeregisterAction", mock.Anything).Return(nil) // pass anything as first argument

        mockMetadata.On("CheckMisbehavingPlugins", "pluginAanomaly1").Return(true)
        mockMetadata.On("SetPluginStage", plugins_common.PluginStageDisabled)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Test case 1: Misbehaving plugin
        respData := &lomipc.ActionResponseData{
            AnomalyKey: "anomaly1",
            ResultCode: 0,
            Action:     "pluginA",
        }

        assert.True(t, plmgr.handleMisbehavingPlugins(respData, mockMetadata))
        if !logger.FindPrefix("In handleMisbehavingPlugins(): Plugin pluginA is misbehaving for anamoly key anomaly1. Ignoring the response") {
            t.Errorf("Expected log message not found")
        }
        mockMetadata.AssertCalled(t, "SetPluginStage", plugins_common.PluginStageDisabled)
        mockMetadata.AssertCalled(t, "CheckMisbehavingPlugins", "pluginAanomaly1")

        // Perform the search for the specified duration with the given interval
        deadline := time.Now().Add(2 * time.Second)
        for time.Now().Before(deadline) {
            if SearchGoroutineTracker("handleMisbehavingPlugins_pluginA") {
                // Goroutine found
                break
            }
            time.Sleep(100 * time.Millisecond)
        }
        time.Sleep(100 * time.Millisecond)

        if !logger.FindPrefix("Plugin pluginA is misbehaving for anamoly key anomaly1. Disabled the plugin") {
            t.Errorf("Expected log message not found")
        }

        // Clean up the mock objects
        mockMetadata.AssertExpectations(t)
        clientTx.AssertExpectations(t)
    })

    t.Run("TestHandleMisbehavingPlugins 2", func(t *testing.T) {
        // Create a mock logger
        setup()
        mockMetadata := new(MockPluginMetadata)
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        mockMetadata.On("CheckMisbehavingPlugins", "pluginBkeyB").Return(false)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Test case 2: Non-misbehaving plugin
        respData := &lomipc.ActionResponseData{
            AnomalyKey: "keyB",
            ResultCode: 0,
            Action:     "pluginB",
        }

        assert.False(t, plmgr.handleMisbehavingPlugins(respData, mockMetadata))
        mockMetadata.AssertCalled(t, "CheckMisbehavingPlugins", "pluginBkeyB")

        // Clean up the mock objects
        mockMetadata.AssertExpectations(t)
        clientTx.AssertExpectations(t)
    })

    t.Run("TestHandleMisbehavingPlugins 3", func(t *testing.T) {
        // Create a mock logger
        setup()
        mockMetadata := new(MockPluginMetadata)
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Test case 2: Non-misbehaving plugin
        respData := &lomipc.ActionResponseData{
            AnomalyKey: "keyB",
            ResultCode: 1,
            Action:     "pluginB",
        }

        assert.False(t, plmgr.handleMisbehavingPlugins(respData, mockMetadata))
        mockMetadata.AssertNotCalled(t, "CheckMisbehavingPlugins", "pluginBkeyB")

        // Clean up the mock objects
        mockMetadata.AssertExpectations(t)
        clientTx.AssertExpectations(t)
    })
}

func TestHandleRequestWithHeartbeats(t *testing.T) {

    t.Run("TestshandleRequestWithHeartbeats 1", func(t *testing.T) {

        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action: "testAction",
        }

        hbChan := make(chan plugins_common.PluginHeartBeat)
        respChan := make(chan *lomipc.ActionResponseData)

        myandleResponseFunc := func(resp *lomipc.ActionResponseData) {
            // Do nothing
        }

        // Start the goroutine
        go plmgr.handleRequestWithHeartbeats(actionReq, hbChan, respChan, myandleResponseFunc)

        // Send a heartbeat value to the hbChan channel
        hbValue := plugins_common.PluginHeartBeat{
            PluginName: "testAction",
        }
        hbChan <- hbValue
        time.Sleep(10 * time.Millisecond)

        // Close the hbChan channel to exit the loop
        close(respChan)

        respObj := <-plmgr.responseChan
        resp := respObj.(lomipc.MsgNotifyHeartbeat)
        assert.Equal(t, resp.Action, "testAction")

        if !logger.FindPrefix("In handleRequest(): Received heartbeat from plugin testAction") {
            t.Errorf("Expected log message not found")
        }

        if logger.FindPrefix("In handleRequest(): Error,") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
    })

    t.Run("TestshandleRequestWithHeartbeats 2", func(t *testing.T) {

        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action: "testAction2",
        }

        hbChan := make(chan plugins_common.PluginHeartBeat)
        respChan := make(chan *lomipc.ActionResponseData)

        myandleResponseFunc := func(resp *lomipc.ActionResponseData) {
            // Do nothing
        }

        // Start the goroutine
        go plmgr.handleRequestWithHeartbeats(actionReq, hbChan, respChan, myandleResponseFunc)

        // Send a heartbeat value to the hbChan channel
        hbValue := plugins_common.PluginHeartBeat{
            PluginName: "testAction2_dummy",
        }
        hbChan <- hbValue
        time.Sleep(10 * time.Millisecond)

        // Close the hbChan channel to exit the loop
        close(respChan)

        if !logger.FindPrefix("In handleRequest(): Received heartbeat from plugin testAction2") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Error, Received heartbeat from plugin testAction2_dummy, expected testAction2") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
    })

    t.Run("TestshandleRequestWithHeartbeats 3", func(t *testing.T) {
        setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action: "testAction",
        }

        hbChan := make(chan plugins_common.PluginHeartBeat)
        respChan := make(chan *lomipc.ActionResponseData)

        var check int32
        atomic.StoreInt32(&check, 0)
        myandleResponseFunc := func(resp *lomipc.ActionResponseData) {
            // Do nothing
            atomic.StoreInt32(&check, 1)
        }

        // Start the goroutine
        go plmgr.handleRequestWithHeartbeats(actionReq, hbChan, respChan, myandleResponseFunc)

        // Send a response value to the respChan channel
        respData := &lomipc.ActionResponseData{
            ResultCode: 0,
        }
        respChan <- respData
        time.Sleep(10 * time.Millisecond)

        if atomic.LoadInt32(&check) != 1 {
            t.Errorf("Expected check to be true")
        }

        clientTx.AssertExpectations(t)

    })
}

func TestHandleRequestWithTimeouts(t *testing.T) {
    t.Run("TestHandleRequestWithTimeouts 1", func(t *testing.T) {
        setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action:  "testAction",
            Timeout: 1,
        }

        respChan := make(chan *lomipc.ActionResponseData)

        var check int32
        atomic.StoreInt32(&check, 0)
        myandleResponseFunc := func(resp *lomipc.ActionResponseData) {
            // Do nothing
            atomic.StoreInt32(&check, 1)
        }

        // Start the goroutine
        var check2 int32
        atomic.StoreInt32(&check2, 0)
        go func() {
            plmgr.handleRequestWithTimeouts(actionReq, respChan, myandleResponseFunc)
            atomic.StoreInt32(&check2, 1)
        }()

        // Send a response value to the respChan channel
        respData := &lomipc.ActionResponseData{
            ResultCode: 0,
        }
        respChan <- respData
        time.Sleep(1 * time.Millisecond)

        if atomic.LoadInt32(&check) != 1 {
            t.Errorf("Expected check to be true")
        }

        if atomic.LoadInt32(&check2) != 1 {
            t.Errorf("Expected check to be true")
        }

        clientTx.AssertExpectations(t)
    })

    t.Run("TestHandleRequestWithTimeouts 2", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action:  "testAction",
            Timeout: 1,
        }

        respChan := make(chan *lomipc.ActionResponseData)

        var check int32
        atomic.StoreInt32(&check, 0)
        myandleResponseFunc := func(resp *lomipc.ActionResponseData) {
            // Do nothing
            atomic.StoreInt32(&check, 1)
        }

        // Start the goroutine
        var check2 int32
        atomic.StoreInt32(&check2, 0)
        go func() {
            plmgr.handleRequestWithTimeouts(actionReq, respChan, myandleResponseFunc)
            atomic.StoreInt32(&check2, 1)
        }()

        time.Sleep(time.Duration(actionReq.Timeout) * time.Second)
        time.Sleep(10 * time.Millisecond) // sleep additional time

        // Send a response value to the respChan channel
        respData := &lomipc.ActionResponseData{
            ResultCode: 0,
        }
        respChan <- respData
        time.Sleep(1 * time.Millisecond)

        if atomic.LoadInt32(&check) != 1 {
            t.Errorf("Expected check to be true")
        }

        if atomic.LoadInt32(&check2) != 1 {
            t.Errorf("Expected check to be true")
        }

        if !logger.FindPrefix("In handleRequestWithTimeouts(): Action request timed out for plugin testAction") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
    })
}

func TestHandleShutdown(t *testing.T) {

    syschan := make(chan int, 1)
    RegisterForSysShutdown = func(caller string) <-chan int {
        return syschan
    }

    DeregisterForSysShutdown = func(caller string) {
        // Do nothing
    }

    osExit = func(code int) {
        // do nothing
    }

    DoSysShutdown = func(toutSecs int) {
        // do nothing
    }
    t.Run("TesthandleShutdown successful", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("DeregisterClient", mock.Anything).Return(nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)

        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
            "plugin2": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
            "plugin2": new(MockPluginMetadata),
        }

        // Mock plugin shutdown
        mockPlugin1 := plmgr.plugins["plugin1"].(*MockPlugin)
        mockPlugin1.On("Shutdown").Return(nil)
        mockPlugin2 := plmgr.plugins["plugin2"].(*MockPlugin)
        mockPlugin2.On("Shutdown").Return(nil)

        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageRequestSuccess)
        mockPluginMetadata1.On("SetPluginStage", mock.Anything)
        mockPluginMetadata2 := plmgr.pluginMetadata["plugin2"].(*MockPluginMetadata)
        mockPluginMetadata2.On("GetPluginStage").Return(plugins_common.PluginStageRequestSuccess)
        mockPluginMetadata2.On("SetPluginStage", mock.Anything)

        var wg sync.WaitGroup
        wg.Add(1)
        go func() {
            defer wg.Done()
            err := plmgr.handleShutdown()
            assert.NoError(t, err)
        }()

        wg.Wait()

        // Verify plugin shutdown called
        mockPlugin1.AssertCalled(t, "Shutdown")
        mockPlugin2.AssertCalled(t, "Shutdown")

        if !logger.FindPrefixWait("In handleShutdown(): Exiting process", 3*time.Second) {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
        mockPlugin1.AssertExpectations(t)
        mockPlugin2.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
        mockPluginMetadata2.AssertExpectations(t)
    })

    t.Run("TesthandleShutdown with error", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("DeregisterClient", mock.Anything).Return(nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)
        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
            "plugin2": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
            "plugin2": new(MockPluginMetadata),
        }

        // Mock plugin shutdown
        mockPlugin1 := plmgr.plugins["plugin1"].(*MockPlugin)
        mockPlugin1.On("Shutdown").Return(errors.New("plugin1 error"))
        mockPlugin2 := plmgr.plugins["plugin2"].(*MockPlugin)
        mockPlugin2.On("Shutdown").Return(nil)

        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageRequestSuccess)
        mockPluginMetadata1.On("SetPluginStage", mock.Anything)
        mockPluginMetadata2 := plmgr.pluginMetadata["plugin2"].(*MockPluginMetadata)
        mockPluginMetadata2.On("GetPluginStage").Return(plugins_common.PluginStageRequestSuccess)
        mockPluginMetadata2.On("SetPluginStage", mock.Anything)

        var wg sync.WaitGroup
        wg.Add(1)
        go func() {
            defer wg.Done()
            err := plmgr.handleShutdown()
            assert.NoError(t, err)
        }()

        wg.Wait()

        if !logger.FindPrefixWait("In shutdownPlugin(): Shutdown failed for plugin plugin1 with error plugin1 error", 3*time.Second) {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefixWait("In handleShutdown(): Exiting process", 3*time.Second) {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
        mockPlugin1.AssertExpectations(t)
        mockPlugin2.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
        mockPluginMetadata2.AssertExpectations(t)
    })

    t.Run("TesthandleShutdown with long running goroutine", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("DeregisterClient", mock.Anything).Return(nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)
        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
            "plugin2": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
            "plugin2": new(MockPluginMetadata),
        }

        // Mock plugin shutdown
        mockPlugin1 := plmgr.plugins["plugin1"].(*MockPlugin)
        mockPlugin1.On("Shutdown").Return(errors.New("plugin1 error"))
        mockPlugin2 := plmgr.plugins["plugin2"].(*MockPlugin)
        mockPlugin2.On("Shutdown").Return(nil)

        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageRequestSuccess)
        mockPluginMetadata1.On("SetPluginStage", mock.Anything)
        mockPluginMetadata2 := plmgr.pluginMetadata["plugin2"].(*MockPluginMetadata)
        mockPluginMetadata2.On("GetPluginStage").Return(plugins_common.PluginStageRequestSuccess)
        mockPluginMetadata2.On("SetPluginStage", mock.Anything)

        // start dummy goroutine
        dummyChan := make(chan int)
        lomcommon.GetGoroutineTracker().Start("dummy_plugin_"+lomcommon.GetUUID(),
            func() {
                <-dummyChan
            })

        var wg sync.WaitGroup
        wg.Add(1)
        go func() {
            defer wg.Done()
            err := plmgr.handleShutdown()
            assert.NoError(t, err)
        }()

        wg.Wait()

        if !logger.FindPrefixWait("In shutdownPlugin(): Shutdown failed for plugin plugin1 with error plugin1 error", 3*time.Second) {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefixWait("In handleShutdown(): Exiting process", 3*time.Second) {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefixWait("In handleShutdown(): Timed out waiting for goroutines to finish", 3*time.Second) {
            t.Errorf("Expected log message not found")
        }

        dummyChan <- 1

        clientTx.AssertExpectations(t)
        mockPlugin1.AssertExpectations(t)
        mockPlugin2.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
        mockPluginMetadata2.AssertExpectations(t)
    })
}

func TestShutdownPlugin(t *testing.T) {
    t.Run("TestShutdownPlugin ShutdownSuccessful", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)

        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
            "plugin2": nil,
            "plugin3": &MockPlugin{},
            "plugin4": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
            "plugin2": nil,
            "plugin3": nil,
        }
        //set plugin stage
        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageDisabled)

        plmgr.shutdownPlugin("plugin1dummy")
        plmgr.shutdownPlugin("plugin2")
        plmgr.shutdownPlugin("plugin3")
        plmgr.shutdownPlugin("plugin4")
        plmgr.shutdownPlugin("plugin1")

        if !logger.FindPrefix("In shutdownPlugin(): Plugin plugin1dummy not found") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In shutdownPlugin(): Plugin plugin2 is nil") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In shutdownPlugin() : Plugin plugin4 metadata not initialized") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In shutdownPlugin() : Plugin plugin3 metadata is nil") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In shutdownPlugin(): Plugin plugin1 is already disabled") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
    })
}

func TestHandleRequest(t *testing.T) {
    syschan := make(chan int, 1)
    RegisterForSysShutdown = func(caller string) <-chan int {
        return syschan
    }

    DeregisterForSysShutdown = func(caller string) {
        // Do nothing
    }

    osExit = func(code int) {
        // do nothing
    }

    DoSysShutdown = func(toutSecs int) {
        // do nothing
    }

    t.Run("TestHandleRequest nil request", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        plmgr.handleRequest(nil)

        if logger.FindPrefix("In handleRequest(): Processing action request for plugin") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
    })

    t.Run("TestHandleRequest timeout zero 1", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)

        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
        }
        //set plugin stage
        mockPlugin1 := plmgr.plugins["plugin1"].(*MockPlugin)
        mockPlugin1.On("Request", mock.Anything, mock.Anything).Return(
            &lomipc.ActionResponseData{
                Action: "plugin1",
            },
        )

        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageUnknown)
        mockPluginMetadata1.On("SetPluginStage", plugins_common.PluginStageRequestStarted)
        mockPluginMetadata1.On("SetPluginStage", plugins_common.PluginStageRequestSuccess)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action:  "plugin1",
            Timeout: 0,
        }

        // Start the goroutine
        go func() {
            plmgr.handleRequest(actionReq)
        }()

        time.Sleep(100 * time.Millisecond)

        if logger.FindPrefix("In handleRequest(): Processing action request for plugin plugin1") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Received response from plugin plugin1") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Completed processing action request for plugin:plugin1") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
        mockPlugin1.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
    })

    t.Run("TestHandleRequest timeout zero 2", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)

        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
        }
        //set plugin stage
        mockPlugin1 := plmgr.plugins["plugin1"].(*MockPlugin)
        mockPlugin1.On("Request", mock.Anything, mock.Anything).Return(
            (*lomipc.ActionResponseData)(nil),
        )

        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageUnknown)
        mockPluginMetadata1.On("SetPluginStage", plugins_common.PluginStageRequestStarted)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action:  "plugin1",
            Timeout: 0,
        }

        // Start the goroutine
        go func() {
            plmgr.handleRequest(actionReq)
        }()

        time.Sleep(100 * time.Millisecond)

        if logger.FindPrefix("In handleRequest(): Processing action request for plugin plugin1") {
            t.Errorf("Expected log message not found")
        }

        if logger.FindPrefix("In handleRequest(): Received response from plugin plugin1") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Received nil response from plugin plugin1") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Completed processing action request for plugin:plugin1") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
        mockPlugin1.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
    })

    t.Run("TestHandleRequest timeout zero invalid response plugion name ", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)

        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
        }
        //set plugin stage
        mockPlugin1 := plmgr.plugins["plugin1"].(*MockPlugin)
        mockPlugin1.On("Request", mock.Anything, mock.Anything).Return(
            &lomipc.ActionResponseData{
                Action: "plugin1_xx",
            },
        )

        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageUnknown)
        mockPluginMetadata1.On("SetPluginStage", plugins_common.PluginStageRequestStarted)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action:  "plugin1",
            Timeout: 0,
        }

        // Start the goroutine
        go func() {
            plmgr.handleRequest(actionReq)
        }()

        time.Sleep(100 * time.Millisecond)

        if logger.FindPrefix("In handleRequest(): Processing action request for plugin plugin1") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Invalid action name received. Got  plugin1_xx, expected plugin1") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Completed processing action request for plugin:plugin1") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
        mockPlugin1.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
    })

    t.Run("TestHandleRequest timeout non zero 1", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.setShutdownStatus(false)

        plmgr.plugins = map[string]plugins_common.Plugin{
            "plugin1": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plugin1": new(MockPluginMetadata),
        }
        //set plugin stage
        mockPlugin1 := plmgr.plugins["plugin1"].(*MockPlugin)
        mockPlugin1.On("Request", mock.Anything, mock.Anything).Return(
            &lomipc.ActionResponseData{
                Action: "plugin1",
            },
        )

        mockPluginMetadata1 := plmgr.pluginMetadata["plugin1"].(*MockPluginMetadata)
        mockPluginMetadata1.On("GetPluginStage").Return(plugins_common.PluginStageUnknown)
        mockPluginMetadata1.On("SetPluginStage", plugins_common.PluginStageRequestStarted)
        mockPluginMetadata1.On("SetPluginStage", plugins_common.PluginStageRequestSuccess)

        // Create the test data
        actionReq := &lomipc.ActionRequestData{
            Action:  "plugin1",
            Timeout: 2, // non zero timeout
        }

        // Start the goroutine
        go func() {
            plmgr.handleRequest(actionReq)
        }()

        time.Sleep(100 * time.Millisecond)

        if logger.FindPrefix("In handleRequest(): Processing action request for plugin plugin1") {
            t.Errorf("Expected log message not found")
        }

        if !logger.FindPrefix("In handleRequest(): Completed processing action request for plugin:plugin1") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
        mockPlugin1.AssertExpectations(t)
        mockPluginMetadata1.AssertExpectations(t)
    })
}

func TestSendResponseToEngine(t *testing.T) {
    syschan := make(chan int, 1)
    RegisterForSysShutdown = func(caller string) <-chan int {
        return syschan
    }

    DeregisterForSysShutdown = func(caller string) {
        // Do nothing
    }

    osExit = func(code int) {
        // do nothing
    }

    DoSysShutdown = func(toutSecs int) {
        // do nothing
    }

    t.Run("TestSendResponseToEngine default case", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        plmgr.sendResponseToEngine(nil)

        if !logger.FindPrefix("In sendResponseToEngine(): Unknown response type") {
            t.Errorf("Expected log message not found")
        }

        clientTx.AssertExpectations(t)
    })

}

// --------------- Test plugin(init good) -------------------------
type test_plugin_001 struct {
}

func (gpl *test_plugin_001) Init(actionCfg *lomcommon.ActionCfg_t) error {
    time.Sleep(2 * time.Second)
    LogInfo("In test_plugin_001 Init()")
    return nil
}

func (gpl *test_plugin_001) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    time.Sleep(10 * time.Second)

    // return data from request
    return &lomipc.ActionResponseData{
        Action:            request.Action,
        InstanceId:        request.InstanceId,
        AnomalyInstanceId: request.AnomalyInstanceId,
        AnomalyKey:        "Ethernet10",
        Response:          "Ethernet10 is down",
        ResultCode:        0,         // or non zero
        ResultStr:         "Success", // or "Failure"
    }
}

func (gpl *test_plugin_001) Shutdown() error {
    return nil
}

func (gpl *test_plugin_001) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    "test_plugin_001",
        Version: "1.0",
    }
}

//--------------- Test plugin -------------------------

// --------------- Test plugin(init error) -------------------------
type test_plugin_001_bad struct {
}

func (gpl *test_plugin_001_bad) Init(actionCfg *lomcommon.ActionCfg_t) error {
    time.Sleep(2 * time.Second)
    LogInfo("In test_plugin_001_bad Init()")
    return errors.New("Init failed")
}

func (gpl *test_plugin_001_bad) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    time.Sleep(10 * time.Second)

    // return data from request
    return &lomipc.ActionResponseData{
        Action:            request.Action,
        InstanceId:        request.InstanceId,
        AnomalyInstanceId: request.AnomalyInstanceId,
        AnomalyKey:        "Ethernet10",
        Response:          "Ethernet10 is down",
        ResultCode:        0,         // or non zero
        ResultStr:         "Success", // or "Failure"
    }
}

func (gpl *test_plugin_001_bad) Shutdown() error {
    return nil
}

func (gpl *test_plugin_001_bad) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    "test_plugin_001_bad",
        Version: "1.0",
    }
}

//--------------- Test plugin -------------------------

func TestLoadAddPlugin(t *testing.T) {
    syschan := make(chan int, 1)
    RegisterForSysShutdown = func(caller string) <-chan int {
        return syschan
    }

    DeregisterForSysShutdown = func(caller string) {
        // Do nothing
    }

    osExit = func(code int) {
        // do nothing
    }

    DoSysShutdown = func(toutSecs int) {
        // do nothing
    }

    cfgFiles := &lomcommon.ConfigFiles_t{
        GlobalFl:   "../../lib/lib_test/config/globals.conf.json",
        ActionsFl:  "../../lib/lib_test/config/actions.conf.json",
        BindingsFl: "../../lib/lib_test/config/bindings.conf.json",
        ProcsFl:    "../../lib/lib_test/config/procs.conf.json",
    }
    lomcommon.InitConfigMgr(cfgFiles)

    t.Run("TestLoadAddPlugin 1", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("RegisterAction", mock.Anything).Return(nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.pluginLoadingTimeout = 5 * time.Second
        plmgr.setShutdownStatus(false)

        plmgr.plugins = map[string]plugins_common.Plugin{
            "plmgr_plugin_1": &MockPlugin{},
        }
        plmgr.pluginMetadata = map[string]plugins_common.IPluginMetadata{
            "plmgr_plugin_1": new(MockPluginMetadata),
        }

        // loaded plugin
        plmgr.loadPlugin("plmgr_plugin_1", "1.0")
        if !logger.FindPrefix("addPlugin : plugin with name plmgr_plugin_1 and version 1.0 is already loaded") {
            t.Errorf("Expected log message not found")
        }

        plmgr.loadPlugin("plugin1_notexist", "1.0")
        if !logger.FindPrefix("addPlugin : plugin plugin1_notexist not found in actions config file") {
            t.Errorf("Expected log message not found")
        }

        // just there in conf file but not loaded and disabled
        plmgr.loadPlugin("plmgr_plugin_2", "1.0")
        if !logger.FindPrefix("addPlugin : Plugin plmgr_plugin_2 is disabled") {
            t.Errorf("Expected log message not found")
        }

        // just there in conf file but not loaded and no constructor
        plmgr.loadPlugin("plmgr_plugin_3", "1.0")
        if !logger.FindPrefix("CreatePluginInstance : plugin not found: plmgr_plugin_3") {
            t.Errorf("Expected log message not found")
        }
        if !logger.FindPrefix("addPlugin : Error creating plugin instance for plmgr_plugin_3 1.0: CreatePluginInstance : plugin not found: plmgr_plugin_3") {
            t.Errorf("Expected log message not found")
        }

        // create test_plugin_002
        f_obj_2 := func(...interface{}) plugins_common.Plugin {
            // ... create and return a new instance of MyPlugin
            return &test_plugin_001{}
        }
        plugins_common.RegisterPlugin("test_plugin_002", f_obj_2)

        plmgr.loadPlugin("test_plugin_002", "1.0")
        if !logger.FindPrefix("addPlugin : Plugin ID does not match provided arguments: got test_plugin_001 1.0, expected test_plugin_002 1.0") {
            t.Errorf("Expected log message not found")
        }

        // create test_plugin_001. COmplete happy path
        f_obj := func(...interface{}) plugins_common.Plugin {
            // ... create and return a new instance of MyPlugin
            return &test_plugin_001{}
        }
        plugins_common.RegisterPlugin("test_plugin_001", f_obj)

        eval := plmgr.loadPlugin("test_plugin_001", "1.0")
        if !logger.FindPrefix("In test_plugin_001 Init()") {
            t.Errorf("Expected log message not found")
        }
        assert.Nil(t, eval)

        clientTx.AssertExpectations(t)
    })

    t.Run("TestLoadAddPlugin check init failures", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.pluginLoadingTimeout = 5 * time.Second
        plmgr.setShutdownStatus(false)

        // create test_plugin_001.
        f_obj := func(...interface{}) plugins_common.Plugin {
            // ... create and return a new instance of MyPlugin
            return &test_plugin_001_bad{}
        }
        plugins_common.RegisterPlugin("test_plugin_001_bad", f_obj)

        eval := plmgr.loadPlugin("test_plugin_001_bad", "1.0")
        if !logger.FindPrefix("In test_plugin_001_bad Init()") {
            t.Errorf("Expected log message not found")
        }
        if !logger.FindPrefix("addPlugin : plugin test_plugin_001_bad init failed:") {
            t.Errorf("Expected log message not found")
        }
        assert.NotNil(t, eval)
        clientTx.AssertExpectations(t)
    })

    t.Run("TestLoadAddPlugin check register action failures", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("RegisterAction", mock.Anything).Return(errors.New("error"))

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.pluginLoadingTimeout = 5 * time.Second
        plmgr.setShutdownStatus(false)

        // create test_plugin_001.
        f_obj := func(...interface{}) plugins_common.Plugin {
            // ... create and return a new instance of MyPlugin
            return &test_plugin_001{}
        }
        plugins_common.RegisterPlugin("test_plugin_001", f_obj)

        eval := plmgr.loadPlugin("test_plugin_001", "1.0")
        if !logger.FindPrefix("addPlugin : plugin test_plugin_001 registerAction failed:") {
            t.Errorf("Expected log message not found")
        }
        assert.NotNil(t, eval)
        clientTx.AssertExpectations(t)
    })

    t.Run("TestLoadAddPlugin check long loading time", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        //clientTx.On("RegisterAction", mock.Anything).Return(errors.New("error"))

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.pluginLoadingTimeout = 100 * time.Millisecond
        plmgr.setShutdownStatus(false)

        // create test_plugin_001.
        f_obj := func(...interface{}) plugins_common.Plugin {
            // ... create and return a new instance of MyPlugin
            return &test_plugin_001_bad{}
        }

        plugins_common.RegisterPlugin("non_existant", f_obj)

        eval := plmgr.loadPlugin("test_plugin_001_bad", "1.0")
        if !logger.FindPrefix("loadPlugin : Registering plugin took too long. Skipped loading. pluginname : test_plugin_001_bad version : 1.0") {
            t.Errorf("Expected log message not found")
        }

        assert.NotNil(t, eval)
        clientTx.AssertExpectations(t)
    })

}

func TestDeregisterPLugin(t *testing.T) {

    t.Run("TestDeregisterPLugin nil response", func(t *testing.T) {

        setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        clientTx.On("DeregisterAction", mock.Anything).Return(nil)

        ret := plmgr.deRegisterActionWithEngine("dummy_name")
        assert.Nil(t, ret)
        clientTx.AssertExpectations(t)
    })

    t.Run("TestDeregisterPLugin not nil response", func(t *testing.T) {
        logger := setup()
        clientTx := new(mockClientTx)

        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)

        clientTx.On("DeregisterAction", mock.Anything).Return(errors.New("error"))

        ret := plmgr.deRegisterActionWithEngine("dummy_name")
        if !logger.FindPrefix("Failed to deregister plugin dummy_name with engine") {
            t.Errorf("Expected log message not found")
        }
        assert.NotNil(t, ret)
        clientTx.AssertExpectations(t)
    })
}

// ------------------------------------ TestSetupSyslogSignals -----------------------------------------------//
// Test for the `SetupSyslogSignals` function
func TestSetupSyslogSignals(t *testing.T) {
    logger := setup()
    SetupSignals()
    time.Sleep(500 * time.Millisecond)

    // Send the SIGUSR1 signal to increase the log level
    syscall.Kill(os.Getpid(), syscall.SIGTERM)
    time.Sleep(500 * time.Millisecond)

    if !logger.FindPrefix("Received SIGTERM signal. Exiting plugin mgr:") {
        t.Errorf("Expected log message not found")
    }
}

//------------------------------------ ParseArguments -----------------------------------------------//

func TestParseArguments(t *testing.T) {

    t.Run("TestParseArguments valid arguments", func(t *testing.T) {

        // Reset the flags before each test case
        flag.CommandLine = flag.NewFlagSet("", flag.ExitOnError)

        // Save original command line arguments
        oldArgs := os.Args
        defer func() { os.Args = oldArgs }()

        args := []string{"-proc_id=proc_1", "-syslog_level=3"}
        // Set command line arguments for this test case
        os.Args = append([]string{"test_prog"}, args...)

        // Call ParseArguments
        ParseArguments()

        // Check expected results
        assert.Equal(t, "proc_1", ProcID)
        assert.Equal(t, syslog.Priority(3), lomcommon.GetLogLevel())

    })

    t.Run("TestParseArguments In valid arguments", func(t *testing.T) {

        logger := setup()
        // Reset the flags before each test case
        flag.CommandLine = flag.NewFlagSet("", flag.ExitOnError)

        // Save original command line arguments
        oldArgs := os.Args
        defer func() { os.Args = oldArgs }()

        args := []string{"-syslog_level=3"}
        // Set command line arguments for this test case
        os.Args = append([]string{"test_prog"}, args...)

        // Call ParseArguments
        ParseArguments()

        if !logger.FindPrefix("Exiting : Proc ID is not provided") {
            t.Errorf("Expected log message not found")
        }

    })

    t.Run("TestParseArguments default arguments", func(t *testing.T) {

        setup()
        // Reset the flags before each test case
        flag.CommandLine = flag.NewFlagSet("", flag.ExitOnError)

        // Save original command line arguments
        oldArgs := os.Args
        defer func() { os.Args = oldArgs }()

        args := []string{"-proc_id=proc_1"}
        // Set command line arguments for this test case
        os.Args = append([]string{"test_prog"}, args...)

        // Call ParseArguments
        ParseArguments()

        // Check expected results
        assert.Equal(t, "proc_1", ProcID)
        assert.Equal(t, syslog.Priority(7), lomcommon.GetLogLevel())

    })
}

//------------------------------------ startup functions -----------------------------------------------//

// --------------- Test plugin(init good) -------------------------
type test_startup_plugin_001 struct {
}

func (gpl *test_startup_plugin_001) Init(actionCfg *lomcommon.ActionCfg_t) error {
    time.Sleep(2 * time.Second)
    LogInfo("In test_startup_plugin_001()")
    return nil
}

func (gpl *test_startup_plugin_001) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    time.Sleep(10 * time.Second)

    // return data from request
    return &lomipc.ActionResponseData{
        Action:            request.Action,
        InstanceId:        request.InstanceId,
        AnomalyInstanceId: request.AnomalyInstanceId,
        AnomalyKey:        "Ethernet10",
        Response:          "Ethernet10 is down",
        ResultCode:        0,         // or non zero
        ResultStr:         "Success", // or "Failure"
    }
}

func (gpl *test_startup_plugin_001) Shutdown() error {
    return nil
}

func (gpl *test_startup_plugin_001) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    "test_startup_plugin_001",
        Version: "1.0",
    }
}

//--------------- Test plugin -------------------------

func TestStartPluginManager(t *testing.T) {

    syschan := make(chan int, 1)
    RegisterForSysShutdown = func(caller string) <-chan int {
        return syschan
    }

    DeregisterForSysShutdown = func(caller string) {
        // Do nothing
    }

    osExit = func(code int) {
        // do nothing
    }

    DoSysShutdown = func(toutSecs int) {
        // do nothing
    }

    t.Run("TestStartPluginManager invalid client TX object", func(t *testing.T) {

        logger := setup()
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        eval := StartPluginManager(1 * time.Millisecond)
        if !logger.FindPrefix("StartPluginManager : Error creating plugin manager") {
            t.Errorf("Expected log message not found")
        }
        assert.NotNil(t, eval)

    })

    t.Run("TestStartPluginManager invalid proc ID", func(t *testing.T) {

        logger := setup()
        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.pluginLoadingTimeout = 5 * time.Second
        plmgr.setShutdownStatus(false)

        /*err := lomcommon.InitConfigPath("../../lib/lib_test/config/")
          if err != nil {
              t.Errorf("StartPluginManager : Error initializing config manager")
          }*/

        eval := StartPluginManager(1 * time.Millisecond) // this will pick above plmgr instance
        if !logger.FindPrefix("StartPluginManager : Error getting proc config for proc") {
            t.Errorf("Expected log message not found")
        }
        assert.NotNil(t, eval)

    })

    t.Run("TestStartPluginManager Plugin initialization failed", func(t *testing.T) {

        logger := setup()
        ProcID = "proc_3" // valid

        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.pluginLoadingTimeout = 5 * time.Second
        plmgr.setShutdownStatus(false)

        fObjj := func(...interface{}) plugins_common.Plugin {
            // ... create and return a new instance of MyPlugin
            return &test_startup_plugin_001{}
        }
        plugins_common.PluginConstructors = make(map[string]plugins_common.PluginConstructor)
        plugins_common.RegisterPlugin("invalid_plugin", fObjj)

        plmgr.setShutdownStatus(true) // kill the run loop

        StartPluginManager(1 * time.Millisecond) // this will pick above plmgr instance
        if !logger.FindPrefix("StartPluginManager : Error Initializing plugin invalid_plugin version 1.0") {
            t.Errorf("Expected log message not found")
        }
    })

    t.Run("TestStartPluginManager valid proc ID", func(t *testing.T) {
        logger := setup()
        ProcID = "proc_2" // valid

        clientTx := new(mockClientTx)
        clientTx.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument
        clientTx.On("RegisterAction", mock.Anything).Return(nil)
        clientTx.On("RecvServerRequest").Return(&lomipc.ServerRequestData{}, nil)

        // Create the PluginManager instance with the mock objects
        plmgr := GetPluginManager(clientTx)
        plmgr.goRoutineCleanupTimeout = 1 * time.Second
        plmgr.pluginLoadingTimeout = 5 * time.Second
        plmgr.setShutdownStatus(false)

        /*err := lomcommon.InitConfigPath("../../lib/lib_test/config/")
          if err != nil {
              t.Errorf("StartPluginManager : Error initializing config manager")
          }*/

        // os.Unsetenv("LOM_CONF_LOCATION")
        //os.Setenv("LOM_CONF_LOCATION", "../../lib/lib_test/config/")

        // define valid plugin constructors for plugins's test_plugin_001, test_plugin_002, ...
        //pluginCount := 1
        //for i := 1; i <= pluginCount; i++ {
        //  pluginName := fmt.Sprintf("test_plugin_g1__%03d", i)

        fObjj := func(...interface{}) plugins_common.Plugin {
            // ... create and return a new instance of MyPlugin
            return &test_startup_plugin_001{}
        }

        plugins_common.PluginConstructors = make(map[string]plugins_common.PluginConstructor)
        plugins_common.RegisterPlugin("test_startup_plugin_001", fObjj)
        //}

        go func() {
            time.Sleep(1000 * time.Millisecond)
            plmgr.setShutdownStatus(true) // kill the run loop
        }()

        eval := StartPluginManager(1 * time.Second) // picks above plmgr instance
        if !logger.FindPrefix("StartPluginManager : Initializing plugin test_startup_plugin_001 version 1.0") {
            t.Errorf("Expected log message not found")
        }
        if !logger.FindPrefix("StartPluginManager : plugin test_startup_plugin_001 version 1.0 successfully Initialized") {
            t.Errorf("Expected log message not found")
        }
        assert.Nil(t, eval) // plugin created successfullky

        clientTx.AssertExpectations(t)
    })
}

func TestSetupPluginManager(t *testing.T) {

    t.Run("TestSetupPluginManager valid path", func(t *testing.T) {

        logger := setup()
        envVarOld := os.Getenv("MY_ENV_VARIABLE")

        // Save original command line arguments
        oldArgs := os.Args
        defer func() {
            os.Args = oldArgs
        }()

        args := []string{"-proc_id=proc_1", "-syslog_level=3"}
        // Set command line arguments for this test case
        os.Args = append([]string{"test_prog"}, args...)

        os.Unsetenv("LOM_CONF_LOCATION")
        os.Setenv("LOM_CONF_LOCATION", "../../lib/lib_test/config/")
        SetupPluginManager()
        os.Setenv("LOM_CONF_LOCATION", envVarOld)
        if !logger.FindPrefix("SetupPluginManager : Successfully setup signals") {
            t.Errorf("Expected log message not found")
        }

        os.Unsetenv("LOM_CONF_LOCATION")
        os.Setenv("LOM_CONF_LOCATION", "../../lib/lib_test/config/dummy") // invalid path

        lomcommon.LoadEnvironmentVariables()
        SetupPluginManager()
        os.Setenv("LOM_CONF_LOCATION", envVarOld)

        if !logger.FindPrefix("SetupPluginManager : Error initializing config manager:") {
            t.Errorf("Expected log message not found")
        }

    })
}
