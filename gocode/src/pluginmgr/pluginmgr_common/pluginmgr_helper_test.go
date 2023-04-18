package pluginmgr_common

import (
	"gocode/src/lib/lomipc"
	"gocode/src/lib/lomcommon"
	"gocode/src/plugins/plugins_common"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/assert"
	"errors"
	//"os/signal"
	//"flag"
	"testing"
	"regexp"
	"fmt"
	"sync"
	"time"
	"os"
	"syscall"
	"log/syslog"
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
	if res == nil {
		return args.Error(0)
	}
	return nil
}

func (m *mockClientTx) NotifyHeartbeat(action string, tstamp int64) error {
	args := m.Called(action, tstamp)
	return args.Error(0)
}

type MockPlugin struct {
	mock.Mock
}

func (m *MockPlugin) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {
	args := m.Called(hbchan, request)
	return args.Get(0).(*lomipc.ActionResponseData)
}

func (m *MockPlugin) Init(plugindata plugins_common.PluginData) error {
	args := m.Called(plugindata)
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

func (m *MockPlugin) GetMetadata() plugins_common.PluginMetadata {
	args := m.Called()
	return args.Get(0).(plugins_common.PluginMetadata)
}

func (m *MockPlugin) SetMetadata(metadata plugins_common.PluginMetadata) {
	m.Called(metadata)
}

func (m *MockPlugin) GetPluginStage() plugins_common.PluginStage {
	args := m.Called()
	return args.Get(0).(plugins_common.PluginStage)
}

func (m *MockPlugin) SetPluginStage(stage plugins_common.PluginStage) {
	m.Called(stage)
}

// Test Run() function
func TestNewPluginManager(t *testing.T) {
	// Setup
	mockClient := new(mockClientTx)
	mockClient.On("RegisterClient", mock.Anything).Return(errors.New("error123")) // pass anything as first argument

	_, err := NewPluginManager(mockClient)

	// Verification
	assert.EqualError(t, err, "error123")
	mockClient.AssertExpectations(t)
}

// Test Run() function
func TestRun_RecvServerRequestError_ReturnError(t *testing.T) {
	// Setup
	mockClient := new(mockClientTx)
	mockClient.On("RecvServerRequest").Return(nil, errors.New("error")) // pass nil as first argument
	mockClient.On("RegisterClient", mock.Anything).Return(nil)          // pass anything as first argument

	pluginManager, err := NewPluginManager(mockClient)

	// Execution of run
	err = pluginManager.Run(nil)

	// Verification
	assert.EqualError(t, err, "error")
	mockClient.AssertExpectations(t)
}

// Test Run() function
func TestRun_RecvServerRequestError_ReturnError2(t *testing.T) {
	// Setup
	mockClient := new(mockClientTx)
	mockClient.On("RecvServerRequest").Return(nil, nil)        // pass nil as both argument
	mockClient.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

	pluginManager, err := NewPluginManager(mockClient)

	// Execution of run
	err = pluginManager.Run(nil)

	// Verification
	assert.EqualError(t, err, "Error RecvServerRequest() : nil")
	mockClient.AssertExpectations(t)
}

// Test Run() function
func TestRun_ActionRequestPluginNotFound_LogError(t *testing.T) {
	// Setup
	mockClient := new(mockClientTx)
	mockClient.On("RecvServerRequest").Return(&lomipc.ServerRequestData{
		ReqType: lomipc.TypeServerRequestAction,
		ReqData: &lomipc.ActionRequestData{
			Action: "nonexistent_plugin", // invalid plugin name
		},
	}, nil)
	
	mockClient.On("RegisterClient", mock.Anything).Return(nil) // pass anything as first argument

	pluginManager, err := NewPluginManager(mockClient)

	// Execution
	stop := make(chan struct{})
	go func() {
		time.Sleep(1 * time.Second)
		close(stop)
	}()
	err = pluginManager.Run(stop)

	// Verification
	assert.NoError(t, err)
	mockClient.AssertCalled(t, "RegisterClient", "")
	mockClient.AssertExpectations(t)
}

// Test Run() function
func TestRun_ActionRequestPluginFound_LogNotice(t *testing.T) {
	// Setup
	mockClient := new(mockClientTx)
	mockClient.On("RecvServerRequest").Return(&lomipc.ServerRequestData{
		ReqType: lomipc.TypeServerRequestAction,
		ReqData: &lomipc.ActionRequestData{
			Action: "plugin",
		},
	}, nil)

	mockPlugin := new(MockPlugin)
	mockPlugin.On("GetPluginID").Return(plugins_common.PluginId{Name: "plugin"}) // a valid plugin is created

	pluginManager := PluginManager{
		clientTx: mockClient,
		plugins: map[string]plugins_common.Plugin{
			"plugin": mockPlugin,
		},
	}

	// Execution
	stop := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		close(stop)
	}()
	err := pluginManager.Run(stop)

	// Verification
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

//------------------------------------ TestSetupSyslogSignals -----------------------------------------------//
// Test for the `SetupSyslogSignals` function
func TestSetupSyslogSignals(t *testing.T) {

	// Create Goroutine Tracker which will be used to track all goroutines in the process
	goroutinetracker = lomcommon.NewGoroutineTracker()
	if goroutinetracker == nil {
		panic("Error creating goroutine tracker")
	}

	lomcommon.SetLogLevel(syslog.LOG_EMERG)
	initialLevel := lomcommon.GetLogLevel()
	SetupSyslogSignals()
	fmt.Println("")

	// Send the SIGUSR1 signal to increase the log level
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)

	newLevel := lomcommon.GetLogLevel()
	if newLevel != initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)
	newLevel = lomcommon.GetLogLevel()
	if newLevel != initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)
	newLevel = lomcommon.GetLogLevel()
	if newLevel != initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)
	newLevel = lomcommon.GetLogLevel()
	if newLevel != initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)
	newLevel = lomcommon.GetLogLevel()
	if newLevel != initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)
	newLevel = lomcommon.GetLogLevel()
	if newLevel != initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)
	newLevel = lomcommon.GetLogLevel()
	if newLevel != initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	time.Sleep(500 * time.Millisecond)
	newLevel = lomcommon.GetLogLevel()
	if newLevel == initialLevel+1 {
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}

	initialLevel = lomcommon.GetLogLevel()
	// Send the SIGUSR2 signal to decrease the log level
	syscall.Kill(os.Getpid(), syscall.SIGUSR2)
	// Wait for the signal handler to update the log level
	time.Sleep(500 * time.Millisecond)

	// Check that the log level has been updated
	newLevel = lomcommon.GetLogLevel()
	if newLevel != initialLevel - 1{
		t.Errorf("log level not updated as expected: initialLevel=%v, newLevel=%v", initialLevel, newLevel)
	}
}

//------------------------------------ ParseArguments -----------------------------------------------//

func TestParseArguments_CustomValues(t *testing.T) {
	// Save original command line arguments
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	args   :=  []string{"-proc_id=proc_1", "-syslog_level=3"}
	// Set command line arguments for this test case
	os.Args = append([]string{"test_prog"}, args...)

	// Call ParseArguments
	ParseArguments()

	// Check expected results
	assert.Equal(t, "proc_1", lomcommon.ProcID)
	assert.Equal(t, syslog.Priority(3), lomcommon.GetLogLevel())
}

//------------------------------------ AddPlugin -----------------------------------------------//

// AddPlugin :  1.Check if plugin is already loaded - plugin exists in the plugins map
func TestRun_AddPlugin1(t *testing.T) {
	// Setup
	mockClient := new(mockClientTx)
	mockPlugin := new(MockPlugin)

	pluginManager := PluginManager{
		clientTx: mockClient,
		plugins: map[string]plugins_common.Plugin{
			"plugin": mockPlugin,
		},
		mu:        sync.Mutex{},
	}

	// Define test data
    pluginName := "plugin"
    pluginVersion := "v1.0.0"
    isDynamic := true

	// Execute
    err := pluginManager.AddPlugin(pluginName, pluginVersion, isDynamic)

    // Verify
    assert.Error(t, err)
	assert.Regexp(t, regexp.MustCompile(fmt.Sprintf("plugin with name %s and version %s is already loaded", pluginName, pluginVersion)), err.Error())
    mockClient.AssertExpectations(t)
}

// AddPlugin :  2.Get plugin specific details from actions config file and add any additional info to pass to plugin's init() call
func TestRun_AddPlugin2(t *testing.T) {
	// Setup
	mockClient := new(mockClientTx)
	mockPlugin := new(MockPlugin)
	mockPlugin.On("SetPluginStage", plugins_common.PluginStageLoadingStarted) // a valid plugin is created

	pluginManager := PluginManager{
		clientTx: mockClient,
		mu:        sync.Mutex{},
	}

	// Define test data
    pluginName := "plugin"
    pluginVersion := "v1.0.0"
    isDynamic := true

	pt := &lomcommon.ConfigMgr_t{new(lomcommon.GlobalConfig_t), make(lomcommon.ActionsConfigList_t), make(lomcommon.BindingsConfig_t), make(lomcommon.ProcConfigList_t)}
	pt.ActionsConfig["dummy_plugin"] = lomcommon.ActionCfg_t{
		Name:         "dummy_action",
		Type:         "dummy_type",
		Timeout:      10,
		HeartbeatInt: 5,
		Disable:      false,
		Mimic:        false,
		ActionKnobs:  "ActionKnobs_test",
	}
	configMgr = pt

	// Execute
    err := pluginManager.AddPlugin(pluginName, pluginVersion, isDynamic)

    // Verify
    assert.Error(t, err)
	expectedErrMsg := "plugin " + pluginName + " not found in actions config file"
	assert.Regexp(t, regexp.MustCompile(expectedErrMsg), err.Error())
    mockClient.AssertExpectations(t)
}