//go:build ignore
// +build ignore

package iptcrc

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "log/syslog"
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    plugins_common "lom/src/plugins/plugins_common"
    "lom/src/plugins/vendors/arista/arista_common"
    "regexp"
    "strings"
    "sync"
    "time"

    ext_gnmi "github.com/openconfig/gnmi/proto/gnmi"

    //"lom/src/lib/lomipc"
    "testing"

    //"time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func init() {
    lomcommon.SetPrefix("proc_0")
    lomcommon.SetAgentName("PluginMgr")

    InitConfigMgrDefault()
}

// MockLogger is a mock implementation of the Logger interface used for testing purposes
type MockLogger struct {
    logs      []string
    logsMutex sync.RWMutex
}

func (m *MockLogger) LogFunc(skip int, priority syslog.Priority, format string, a ...interface{}) string {
    msg := fmt.Sprintf(format, a...)
    m.logsMutex.Lock()
    m.logs = append(m.logs, msg)
    m.logsMutex.Unlock()
    return msg
}

func (m *MockLogger) GetLogs() []string {
    m.logsMutex.RLock()
    defer m.logsMutex.RUnlock()
    return m.logs
}

func (m *MockLogger) ClearLogs() {
    m.logsMutex.Lock()
    defer m.logsMutex.Unlock()
    m.logs = []string{}
}

func matchLogs(regex *regexp.Regexp, logger *MockLogger, waitTime, maxTime time.Duration) bool {
    startTime := time.Now()

    for {
        logs := logger.GetLogs()
        for _, log := range logs {
            if regex.MatchString(log) {
                return true
            }
        }

        if time.Since(startTime) >= maxTime {
            return false
        }

        time.Sleep(waitTime)
    }
}

func (m *MockLogger) WaitForLogMatch(regex *regexp.Regexp, waitTime, maxTimeMillis int) bool {
    waitDur := time.Duration(waitTime) * time.Millisecond
    maxDur := time.Duration(maxTimeMillis) * time.Millisecond
    return matchLogs(regex, m, waitDur, maxDur)
}

/*
func main() {
    mockLogger := &MockLogger{}
    mockLogger.LogFunc(0, syslog.LOG_INFO, "This is an error message")
    mockLogger.LogFunc(0, syslog.LOG_INFO, "This is another message")

    regex := regexp.MustCompile(`error`)
    waitTime := 500
    maxTime := 5000

    if mockLogger.WaitForLogMatch(regex, waitTime, maxTime) {
        fmt.Println("Match found")
    } else {
        fmt.Println("No match found within the specified time")
    }
}
*/

// MockGNMISession is a mock implementation of the GNMISession interface used for testing purposes
type MockGNMISession struct {
    mock.Mock
}

func (m *MockGNMISession) Capabilities() (*ext_gnmi.CapabilityResponse, error) {
    args := m.Called()
    return args.Get(0).(*ext_gnmi.CapabilityResponse), args.Error(1)
}

func (m *MockGNMISession) Get(prefix string, paths []string) (*ext_gnmi.GetResponse, error) {
    args := m.Called(prefix, paths)
    return args.Get(0).(*ext_gnmi.GetResponse), args.Error(1)
}

func (m *MockGNMISession) Subscribe(prefix string, paths []string) error {
    args := m.Called(prefix, paths)
    return args.Error(0)
}

func (m *MockGNMISession) Unsubscribe() error {
    args := m.Called()
    return args.Error(0)
}

func (m *MockGNMISession) Close() error {
    args := m.Called()
    return args.Error(0)
}

/*
func (m *MockGNMISession) Receive() (<-chan *ext_gnmi.Notification, <-chan error, error) {
    args := m.Called()
    return args.Get(0).(<-chan *ext_gnmi.Notification), args.Get(1).(<-chan error), args.Error(2)
}*/

func (m *MockGNMISession) Receive() (<-chan *ext_gnmi.Notification, <-chan error, error) {
    args := m.Called()
    return make(chan *ext_gnmi.Notification, 10), make(chan error, 10), args.Error(2)
}

func (m *MockGNMISession) Resubscribe(newPrefix string, newPaths []string) error {
    args := m.Called(newPrefix, newPaths)
    return args.Error(0)
}

func (m *MockGNMISession) IsSubscribed() bool {
    args := m.Called()
    return args.Bool(0)
}

func (m *MockGNMISession) Equals(other plugins_common.IGNMISession, comparePaths bool) bool {
    args := m.Called(other, comparePaths)
    return args.Bool(0)
}

// MockGNMIServerConnector is a mock implementation of the GNMIServerConnector interface used for testing purposes

type MockGNMIServerConnector struct {
    mock.Mock
}

func (m *MockGNMIServerConnector) capabilities(ctx context.Context) (*ext_gnmi.CapabilityResponse, error) {
    args := m.Called(ctx)
    return args.Get(0).(*ext_gnmi.CapabilityResponse), args.Error(1)
}

func (m *MockGNMIServerConnector) get(ctx context.Context, prefix string, paths []string) (*ext_gnmi.GetResponse, error) {
    args := m.Called(ctx, prefix, paths)
    return args.Get(0).(*ext_gnmi.GetResponse), args.Error(1)
}

func (m *MockGNMIServerConnector) subscribe(ctx context.Context, mode ext_gnmi.SubscriptionList_Mode, prefix string, paths []string) (ext_gnmi.GNMI_SubscribeClient, error) {
    args := m.Called(ctx, mode, prefix, paths)
    return args.Get(0).(ext_gnmi.GNMI_SubscribeClient), args.Error(1)
}

func (m *MockGNMIServerConnector) subscribeStream(ctx context.Context, prefix string, paths []string) (ext_gnmi.GNMI_SubscribeClient, error) {
    args := m.Called(ctx, prefix, paths)
    return args.Get(0).(ext_gnmi.GNMI_SubscribeClient), args.Error(1)
}

func (m *MockGNMIServerConnector) close() error {
    args := m.Called()
    return args.Error(0)
}

func (m *MockGNMIServerConnector) Server() string {
    args := m.Called()
    return args.String(0)
}

//-----Helpers to work with config files ----------------

// Config represents the structure of your configuration.
type Config map[string]interface{}

// WriteConfig writes the configuration to a file.
func WriteConfig(path string, config Config) error {
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(path, data, 0644)
}

// CreateConfig creates a configuration file with the given data.
// If data is nil, it uses the default data.
func CreateConfig(path string, data, defaultData []byte) error {
    var config Config
    if data == nil {
        if err := json.Unmarshal(defaultData, &config); err != nil {
            return err
        }
    } else {
        if err := json.Unmarshal(data, &config); err != nil {
            return err
        }
    }

    return WriteConfig(path, config)
}

// CreateActionsConfig creates the actions.conf.json file.
func CreateActionsConfig(data []byte) error {
    defaultData := []byte(`{
        "iptcrc_detection": {
            "Name": "iptcrc_detection",
            "Type": "Detection",
            "Timeout": 0,
            "HeartbeatInt": 30,
            "Disable": false,
            "Mimic": false,
            "ActionKnobs": {
                "initial_detection_reporting_frequency_in_mins": 1,
                "subsequent_detection_reporting_frequency_in_mins": 1,
                "initial_detection_reporting_max_count": 12,
                "periodic_subscription_interval_in_hours" : 24,
                "error_backoff_time_in_secs" : 60,
                "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
            }
        }
    }`)
    return CreateConfig("/tmp/actions.conf.json", data, defaultData)
}

// CreateBindingsConfig creates the bindings.conf.json file.
func CreateBindingsConfigFile(data []byte) error {
    defaultData := []byte(`{
        "bindings": [{
            "SequenceName": "iptcrc_bind-0",
            "Priority": 0,
            "Timeout": 30,
            "Actions": [{
                "name": "iptcrc_detection",
                "sequence": 0
            }]
        }]
    }`)
    return CreateConfig("/tmp/bindings.conf.json", data, defaultData)
}

// CreateProcsConfig creates the procs.conf.json file.
func CreateProcsConfigFile(data []byte) error {
    defaultData := []byte(`{
        "procs": {
            "proc_0": {
                "iptcrc_detection": {
                    "name": "iptcrc_detection",
                    "version": "1.0.0.0",
                    "path": ""
                }
            }
        }
    }`)
    return CreateConfig("/tmp/procs.conf.json", data, defaultData)
}

// CreateGlobalsConfig creates the globals.conf.json file.
func CreateGlobalsConfigFile(data []byte) error {
    defaultData := []byte(`{
        "MAX_SEQ_TIMEOUT_SECS": 120,
        "MIN_PERIODIC_LOG_PERIOD_SECS": 1,
        "ENGINE_HB_INTERVAL_SECS": 10,
        "INITIAL_DETECTION_REPORTING_FREQ_IN_MINS": 5,
        "SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS": 60,
        "INITIAL_DETECTION_REPORTING_MAX_COUNT": 12,
        "PLUGIN_MIN_ERR_CNT_TO_SKIP_HEARTBEAT" : 3, 
        "MAX_PLUGIN_RESPONSES" : 100,
        "MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT_IN_SECS" : 60,
        "LOCAL_GNMI_SERVER_USERNAME": "admin",
        "LOCAL_GNMI_SERVER_PASSWORD": "password",
        "LOCAL_GNMI_SERVER_ADDRESS": "localhost:50051",            
        "LOCAL_GNMI_USE_TLS" : "true",
        "LOCAL_GNMI_CERTIFICATE_FILE_PATH" : "../../plugin_integration_tests/config/security/streamingtelemetryserver.cer",
        "LOCAL_GNMI_PRIVATE_KEY_FILE_PATH" : "../../plugin_integration_tests/config/security/streamingtelemetryserver.key",
        "LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH" : "../../plugin_integration_tests/config/security/dsmsroot.cer",
        "LOCAL_GNMI_VALIDATE_SERVER_CERTIFICATE" : "false"
    }`)
    return CreateConfig("/tmp/globals.conf.json", data, defaultData)
}

// CreateAllConfigs creates all configuration files.
func CreateAllConfigsFiles(actionsData, bindingsData, procsData, globalsData []byte) error {
    if err := CreateActionsConfig(actionsData); err != nil {
        return err
    }
    if err := CreateBindingsConfigFile(bindingsData); err != nil {
        return err
    }
    if err := CreateProcsConfigFile(procsData); err != nil {
        return err
    }
    if err := CreateGlobalsConfigFile(globalsData); err != nil {
        return err
    }
    return nil
}

// INitialize the config manager with default config files
func InitConfigMgrDefault() {
    // Define the paths to the configuration files
    actionsPath := "/tmp/actions.conf.json"
    bindingsPath := "/tmp/bindings.conf.json"
    procsPath := "/tmp/procs.conf.json"
    globalsPath := "/tmp/globals.conf.json"

    // Create all configuration files
    if err := CreateAllConfigsFiles(nil, nil, nil, nil); err != nil {
        log.Fatalf("Failed to create configuration files: %v", err)
    }

    // Initialize the configuration manager
    configFiles := &lomcommon.ConfigFiles_t{
        GlobalFl:   globalsPath,
        ActionsFl:  actionsPath,
        BindingsFl: bindingsPath,
        ProcsFl:    procsPath,
    }
    if _, err := lomcommon.InitConfigMgr(cfgFiles); err != nil {
        t.Fatalf("Failed to init config (%v)", err)
    }
}

// INitialize the config manager with custom config files
func InitConfigMgr(actionsData, bindingsData, procsData, globalsData []byte) {
    // Define the paths to the configuration files
    actionsPath := "/tmp/actions.conf.json"
    bindingsPath := "/tmp/bindings.conf.json"
    procsPath := "/tmp/procs.conf.json"
    globalsPath := "/tmp/globals.conf.json"

    // Create all configuration files
    if err := CreateAllConfigsFiles(actionsData, bindingsData, procsData, globalsData); err != nil {
        log.Fatalf("Failed to create configuration files: %v", err)
    }

    // Initialize the configuration manager
    configFiles := &lomcommon.ConfigFiles_t{
        GlobalFl:   globalsPath,
        ActionsFl:  actionsPath,
        BindingsFl: bindingsPath,
        ProcsFl:    procsPath,
    }
    if _, err := lomcommon.InitConfigMgr(cfgFiles); err != nil {
        t.Fatalf("Failed to init config (%v)", err)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// TestInit tests the Init function of the IPTCRCDetectionPlugin

func TestInit_Integrationtest(t *testing.T) {

    t.Run("Error from LoadChipMappings", func(t *testing.T) {
        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        actionKnobs := json.RawMessage(`{
                "initial_detection_reporting_frequency_in_mins": 1,
                "subsequent_detection_reporting_frequency_in_mins": 1,
                "initial_detection_reporting_max_count": 12,
                "periodic_subscription_interval_in_hours" : 24,
                "error_backoff_time_in_secs" : 60,
                "iptcrc_test_counter_name": "DROP_VOQ_IN_PORT_NOT_VALN_MEMBER",
                "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings_invalid.json"
            }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection"}

        err := iPTCRCDetectionPlugin.Init(&actionConfig)

        // Assert that an error was returned
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "Failed to initialize chipId to chipName mapping:")

    })

    t.Run("Success testing params", func(t *testing.T) {
        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        actionKnobs := json.RawMessage(`{
                "initial_detection_reporting_frequency_in_mins": 1,
                "subsequent_detection_reporting_frequency_in_mins": 1,
                "initial_detection_reporting_max_count": 12,
                "periodic_subscription_interval_in_hours" : 24,
                "error_backoff_time_in_secs" : 60,
                "iptcrc_test_counter_name": "DROP_VOQ_IN_PORT_NOT_VALN_MEMBER",
                "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
            }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection"}
        iPTCRCDetectionPlugin.Init(&actionConfig)

        // Assert expectations
        assert := assert.New(t)
        assert.Equal(60, iPTCRCDetectionPlugin.error_backoff_time_secs)
        assert.Equal(24, iPTCRCDetectionPlugin.periodic_subscription_interval_hours)
        assert.Equal("DROP_VOQ_IN_PORT_NOT_VALN_MEMBER", iPTCRCDetectionPlugin.counterName)

    })

    t.Run("InvalidPluginName", func(t *testing.T) {
        // Create an instance of our test object
        iptCRCDetectionPlugin := new(IPTCRCDetectionPlugin)
        actionConfig := &lomcommon.ActionCfg_t{Name: "invalid_plugin_name"}

        // Call the Init function
        err := iptCRCDetectionPlugin.Init(actionConfig)

        // Assert that an error was returned and the error message contains the expected substring
        assert.Error(t, err)
        assert.Contains(t, err.Error(), fmt.Sprintf("Invalid plugin name passed. actionConfig.Name: %s", actionConfig.Name))
    })

    t.Run("SubscriptionBasedPluginUtil Invalid heartbeat", func(t *testing.T) {
        // Create an instance of our test object
        iptCRCDetectionPlugin := new(IPTCRCDetectionPlugin)
        actionConfig := &lomcommon.ActionCfg_t{Name: detection_plugin_name, ActionKnobs: json.RawMessage(`invalid_json`)}

        // Call the Init function
        err := iptCRCDetectionPlugin.Init(actionConfig)

        // Assert that an error was returned
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "Invalid heartbeat interval 0")

    })

    //
    // This test scenario covers the following steps for positive testing of the IPTCRCDetectionPlugin:
    //
    // 1. Start a GNMI server. This simulates the environment in which the IPTCRCDetectionPlugin operates.
    //
    // 2. Create an instance of IPTCRCDetectionPlugin. This plugin is responsible for detecting IPTCRC anomalies.
    //
    // 3. Define a configuration for the plugin. This configuration includes the username, password, and address of the GNMI server, as well as
    //   the reporting frequencies and maximum count for the detection.
    //
    // 4. Call the Init function of the IPTCRCDetectionPlugin with the prepared configuration. The Init function is responsible for initializing
    //   the plugin according to the provided configuration.
    //
    // 5. Use the assert package to verify that the Init function initialized the plugin correctly. This includes checking that the function
    //    returned no error.
    //
    // 6. Call the Shutdown function of the IPTCRCDetectionPlugin to clean up resources. This simulates the plugin manager shutting down the
    //    plugin.
    //
    t.Run("Successful API Call", func(t *testing.T) {
        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
                "initial_detection_reporting_frequency_in_mins": 1,
                "subsequent_detection_reporting_frequency_in_mins": 1,
                "initial_detection_reporting_max_count": 12
            }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        //cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
    })

    t.Run("TestInitWithInvalidJSONActionKnobs", func(t *testing.T) {
        // Create a plugin instance and an action config with invalid JSON action knobs
        plugin := &IPTCRCDetectionPlugin{}
        actionConfig := &lomcommon.ActionCfg_t{Name: detection_plugin_name, ActionKnobs: json.RawMessage(`{invalid_json`)}

        // Call the Init function
        err := plugin.Init(actionConfig)

        // Check that the function returned an error
        assert.Error(t, err)

        assert.Equal(t, error_backoff_time_default, plugin.error_backoff_time_secs)
        assert.Equal(t, periodic_subscription_interval_default, plugin.periodic_subscription_interval_hours)
        assert.Equal(t, iptcrc_counter_name_default, plugin.counterName)

        //cleanup
        plugin.Shutdown()
    })

    t.Run("TestInitWithMissingActionKnobs", func(t *testing.T) {
        // Create a plugin instance and an action config with missing action knobs
        plugin := &IPTCRCDetectionPlugin{}
        actionConfig := &lomcommon.ActionCfg_t{Name: detection_plugin_name, ActionKnobs: json.RawMessage(`{}`)}

        // Call the Init function
        plugin.Init(actionConfig)

        // Check that the plugin's configuration parameters are set to the default values
        assert.Equal(t, error_backoff_time_default, plugin.error_backoff_time_secs)
        assert.Equal(t, periodic_subscription_interval_default, plugin.periodic_subscription_interval_hours)
        assert.Equal(t, iptcrc_counter_name_default, plugin.counterName)

        //cleanup
        plugin.Shutdown()
    })
}

// TestRequest tests the handleRequest function of the IPTCRCDetectionPlugin
func TestRequest_Integrationtest(t *testing.T) {

    //
    // This test scenario covers the following steps for positive testing of an IPTCRC anomaly:
    //
    // 1. Start a GNMI server and populate it with an IPTCRC anomaly. This simulates the environment in which the IPTCRCDetectionPlugin
    //operates.

    // 2. Create an instance of IPTCRCDetectionPlugin. This plugin is responsible for detecting IPTCRC anomalies.
    //
    // 3. The IPTCRCDetectionPlugin subscribes to the GNMI server to receive anomalies. When it receives the IPTCRC anomaly from the
    //    server, it prepares a lomipc.ActionRequestData object with the anomaly details. The request includes details such as the action
    //   name (iptcrc_detection), instance ID, anomaly instance ID, anomaly key, and timeout.
    //
    // 4. Start the Request function of the IPTCRCDetectionPlugin in a goroutine with the prepared request. The Request function is
    //    responsible for handling the anomaly according to the plugin's logic.
    // 5. The Request function processes the anomaly and sends the response to a channel. The response includes details about how the
    //    anomaly was handled.
    //
    // 6. Receive the response from the channel outside of the goroutine. This simulates the plugin manager receiving the response from
    //   the plugin.
    //
    // 7. Use the assert package to verify that the Request function handled the anomaly correctly. This includes checking that the
    //     function returned no error and a non-nil response, and that the response contains the expected details.
    //
    // Note: Since this is the first time the IPTCRCDetectionPlugin is receiving the IPTCRC anomaly, the anomaly gets reported.
    //

    t.Run("Success first time Anomaly reported", func(t *testing.T) {
        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
               "initial_detection_reporting_frequency_in_mins": 1,
               "subsequent_detection_reporting_frequency_in_mins": 1,
               "initial_detection_reporting_max_count": 12,
               "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
           }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        //generate and send subscription9IPTCRC error) to client
        var sample_1 = map[string]interface{}{
            "key_details": "0_fap_1_65535", //chipId_chipType_CounterId_offset
            "Timestamp":   "1702436651320833298",
            "Updates": map[string]interface{}{
                "chipName":                  "Jericho3/0",
                "delta2":                    "4294967295",
                "initialThresholdEventTime": "0.000000",
                "lastSyslogTime":            "0.000000",
                "initialEventTime":          "1702436441.269680",
                "lastEventTime":             "1702436441.269680",
                "lastThresholdEventTime":    "0.000000",
                "counterName":               "IptCrcErrCnt",
                "dropCount":                 "1",
                "delta1":                    "0",
                "delta4":                    "4294967295",
                "chipId":                    "0",
                "chipType":                  "fap",
                "counterId":                 "1",
                "offset":                    "65535",
                "delta3":                    "4294967295",
                "delta5":                    "4294967295",
                "eventCount":                "1",
                "thresholdEventCount":       "0",
            },
        }
        server.UpdateDB("sample1_key", sample_1) // sends IPTCRC anomaly to client

        // Assert that the response was received
        response := <-responseChan
        assert.Equal(t, "instance1", response.InstanceId)
        assert.Equal(t, "anomaly1", response.AnomalyInstanceId)
        assert.Equal(t, "iptcrc_detection", response.Action)
        assert.Equal(t, "Jericho3/0", response.AnomalyKey)
        assert.Equal(t, "Detected IPTCRC", response.Response)
        assert.Equal(t, 0, response.ResultCode)
        assert.Equal(t, "Success", response.ResultStr)

        // Assert that an error was returned
        assert.NoError(t, err)

        //cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
    })

    // Waits needed
    //
    // This test scenario covers the following steps for testing the shutdown process of the IPTCRCDetectionPlugin and the error handling when
    // closing the GNMI server session:
    //
    // 1. A mock logger is created to capture the log messages generated during the test.
    //
    // 2. A GNMI server is started to simulate the environment in which the IPTCRCDetectionPlugin operates.
    //
    // 3. A configuration for the plugin is defined, including the GNMI server details and various detection parameters.
    //
    // 4. An instance of IPTCRCDetectionPlugin is created and initialized with the defined configuration.
    //
    // 5. A request is created to simulate an anomaly detection request.
    //
    // 6. The Request function of the IPTCRCDetectionPlugin is called in a goroutine with the prepared request and a heartbeat channel.
    // The function's response is sent to a response channel.
    //
    // 7. The GNMI server is stopped to simulate a server shutdown.
    //
    // 8. The Shutdown function of the IPTCRCDetectionPlugin is called to initiate the plugin's shutdown process.
    //
    // 9. The test waits for the response from the Request function.
    //
    // 10. The test checks the captured log messages to verify that the expected shutdown and error messages were logged.
    //
    // 11. Finally, the logger is cleaned up by setting it to nil.
    //
    // This test ensures that the IPTCRCDetectionPlugin handles the shutdown process correctly, including stopping the detection process and
    //handling errors when closing the GNMI server session.

    t.Run("test shutdown and error in gnmi close", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        //defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
               "initial_detection_reporting_frequency_in_mins": 1,
               "subsequent_detection_reporting_frequency_in_mins": 1,
               "initial_detection_reporting_max_count": 12,
               "periodic_subscription_interval_in_hours": 1,
               "error_backoff_time_in_secs": 60,
               "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
           }`)

        actionConfig := lomcommon.ActionCfg_t{
            ActionKnobs:  actionKnobs,
            Name:         "iptcrc_detection",
            Type:         "Detection",
            Timeout:      0,
            Disable:      false,
            Mimic:        false,
            HeartbeatInt: 10,
        }

        // create plugin object
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // sleep to setup subscriptin ready
        time.Sleep(1 * time.Second)

        // Stop the GNMI server
        server.Stop()

        // Initiate plugin shutdown
        iPTCRCDetectionPlugin.Shutdown()

        // Assert that the shutdoen response was received
        <-responseChan
        // sleep
        time.Sleep(2 * time.Second)

        // Check that the expected log message was logged
        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile("Shutdown initiated, stopping executeIPTCRCDetection")

        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }

        assert.True(t, found1, "Expected pattern not found: Shutdown initiated, stopping executeIPTCRCDetection")

        // cleanup
        logger = nil
    })

    // waits needed
    // tests when there is error in gnmi close without shutdoen initiated.
    t.Run("test  error in gnmi close", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        //defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
               "initial_detection_reporting_frequency_in_mins": 1,
               "subsequent_detection_reporting_frequency_in_mins": 1,
               "initial_detection_reporting_max_count": 12,
               "periodic_subscription_interval_in_hours": 1,
               "error_backoff_time_in_secs": 60,
               "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
           }`)

        actionConfig := lomcommon.ActionCfg_t{
            ActionKnobs:  actionKnobs,
            Name:         "iptcrc_detection",
            Type:         "Detection",
            Timeout:      0,
            Disable:      false,
            Mimic:        false,
            HeartbeatInt: 10,
        }

        // create plugin object
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // sleep to setup subscriptin ready
        time.Sleep(2 * time.Second)

        // Stop the GNMI server
        server.Stop()

        // Initiate plugin shutdown
        //iPTCRCDetectionPlugin.Shutdown()

        // sleep
        time.Sleep(2 * time.Second)

        // Check that the expected log message was logged
        logs := mylogger.GetLogs()
        fmt.Println("logs: ", logs)
        pattern1 := regexp.MustCompile("Error received from GNMI subscriptioon session")

        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }

        assert.True(t, found1, "Expected pattern not found: Error received from GNMI subscriptioon session")

        // cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
        logger = nil
    })

    // waits needed
    // tests defer block code in executeIPTCRCDetection
    t.Run("test defer error in executeIPTCRCDetection", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        //defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
               "initial_detection_reporting_frequency_in_mins": 1,
               "subsequent_detection_reporting_frequency_in_mins": 1,
               "initial_detection_reporting_max_count": 12,
               "periodic_subscription_interval_in_hours": 1,
               "error_backoff_time_in_secs": 60,
               "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
           }`)

        actionConfig := lomcommon.ActionCfg_t{
            ActionKnobs:  actionKnobs,
            Name:         "iptcrc_detection",
            Type:         "Detection",
            Timeout:      0,
            Disable:      false,
            Mimic:        false,
            HeartbeatInt: 10,
        }

        // create plugin object
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Stop the GNMI server
        server.Stop()

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // sleep to setup subscriptin ready
        time.Sleep(2 * time.Second)

        // Check that the expected log message was logged
        logs := mylogger.GetLogs()
        fmt.Println("logs: ", logs)
        pattern1 := regexp.MustCompile("Failed to subscribe to gnmi paths")

        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }

        assert.True(t, found1, "Expected pattern not found: Failed to subscribe to gnmi paths")

        // cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
        logger = nil
    })

    // waits needed
    t.Run("Check updateTimer API past expiry time", func(t *testing.T) {

        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
                  "initial_detection_reporting_frequency_in_mins": 1,
                  "subsequent_detection_reporting_frequency_in_mins": 1,
                  "initial_detection_reporting_max_count": 12,
                  "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
              }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 10) // >1 to avoid blocking

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        //generate and send subscription9IPTCRC message to client
        var sample_1 = map[string]interface{}{
            "key_details": "0_fap_1_65535", //chipId_chipType_CounterId_offset
            "Timestamp":   "1702436651320833298",
            "Updates": map[string]interface{}{
                "chipName":                  "Jericho3/0",
                "delta2":                    "4294967295",
                "initialThresholdEventTime": "0.000000",
                "lastSyslogTime":            "0.000000",
                "initialEventTime":          "1702436441.269680",
                "lastEventTime":             "1702436441.269680",
                "lastThresholdEventTime":    "0.000000",
                "counterName":               "IptCrcErrCnt",
                "dropCount":                 "1",
                "delta1":                    "0",
                "delta4":                    "4294967295",
                "chipId":                    "0",
                "chipType":                  "fap",
                "counterId":                 "1",
                "offset":                    "65535",
                "delta3":                    "4294967295",
                "delta5":                    "4294967295",
                "eventCount":                "1",
                "thresholdEventCount":       "0",
            },
        }
        server.UpdateDB("sample1_key", sample_1) // sends IPTCRC anomaly to client

        // Assert that the response was received
        response := <-responseChan
        fmt.Println("response: ", response)
        assert.Equal(t, "instance1", response.InstanceId)
        assert.Equal(t, "anomaly1", response.AnomalyInstanceId)
        assert.Equal(t, "iptcrc_detection", response.Action)
        assert.Equal(t, "Jericho3/0", response.AnomalyKey)
        assert.Equal(t, "Detected IPTCRC", response.Response)
        assert.Equal(t, 0, response.ResultCode)
        assert.Equal(t, "Success", response.ResultStr)

        // Assert that an error was returned
        assert.NoError(t, err)

        // Start the new Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // waitn untill initial_detection_reporting_frequency_in_mins is passed
        time.Sleep(61 * time.Second)

        //regenerate and send subscription9IPTCRC message to client
        sample_1 = map[string]interface{}{
            "key_details": "0_fap_1_65535", //chipId_chipType_CounterId_offset
            "Timestamp":   "1702436651320833298",
            "Updates": map[string]interface{}{
                "chipName":                  "Jericho3/0",
                "delta2":                    "4294967295",
                "initialThresholdEventTime": "0.000000",
                "lastSyslogTime":            "0.000000",
                "initialEventTime":          "1702436441.269680",
                "lastEventTime":             "1702436441.269680",
                "lastThresholdEventTime":    "0.000000",
                "counterName":               "IptCrcErrCnt",
                "dropCount":                 "1",
                "delta1":                    "0",
                "delta4":                    "4294967295",
                "chipId":                    "0",
                "chipType":                  "fap",
                "counterId":                 "1",
                "offset":                    "65535",
                "delta3":                    "4294967295",
                "delta5":                    "4294967295",
                "eventCount":                "1",
                "thresholdEventCount":       "0",
            },
        }

        server.UpdateDB("sample1_key", sample_1) // sends IPTCRC anomaly to client

        // Assert that the response was received
        response = <-responseChan
        fmt.Println("response: ", response)
        assert.Equal(t, "instance1", response.InstanceId)
        assert.Equal(t, "anomaly1", response.AnomalyInstanceId)
        assert.Equal(t, "iptcrc_detection", response.Action)
        assert.Equal(t, "Jericho3/0", response.AnomalyKey)
        assert.Equal(t, "Detected IPTCRC", response.Response)
        assert.Equal(t, 0, response.ResultCode)
        assert.Equal(t, "Success", response.ResultStr)

        //cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
        logger = nil
    })

    // waits needed
    // tests when there is error in gnmi connections and test if the connection to gnmi server is restarted
    // with proper backoff time
    t.Run("test request with restartconnection flag", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        //defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
            "initial_detection_reporting_frequency_in_mins": 1,
            "subsequent_detection_reporting_frequency_in_mins": 1,
            "initial_detection_reporting_max_count": 12,
            "periodic_subscription_interval_in_hours": 1,
            "error_backoff_time_in_secs": 1,
            "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
        }`)

        actionConfig := lomcommon.ActionCfg_t{
            ActionKnobs:  actionKnobs,
            Name:         "iptcrc_detection",
            Type:         "Detection",
            Timeout:      0,
            Disable:      false,
            Mimic:        false,
            HeartbeatInt: 10,
        }

        // create plugin object
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Stop the GNMI server
        server.Stop()

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // sleep
        time.Sleep(3 * time.Second)

        // since server is stopped. Expecting SubscribeError error in executeIPTCRCDetection
        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Incremented consecutiveError count for plugin \(iptcrc_detection\)`)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: Incremented consecutiveError count for plugin (iptcrc_detection)")

        // Now start the server
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // sleep untill backoff time is over
        time.Sleep(2 * time.Second)

        // Now expect executeIPTCRCDetection to be called again with restartConnection flag set to true
        logs = mylogger.GetLogs()
        pattern1 = regexp.MustCompile("IPTCRC Detection Starting, restartConnection: true")
        found1 = false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: IPTCRC Detection Starting, restartConnection: true")

        // wait untill request is completed and response is received
        //time.Sleep(1 * time.Second)

        // Send the anomaly to the client to simulate the anomaly detection process
        //generate and send subscription9IPTCRC error) to client
        var sample_1 = map[string]interface{}{
            "key_details": "0_fap_1_65535", //chipId_chipType_CounterId_offset
            "Timestamp":   "1702436651320833298",
            "Updates": map[string]interface{}{
                "chipName":                  "Jericho3/0",
                "delta2":                    "4294967295",
                "initialThresholdEventTime": "0.000000",
                "lastSyslogTime":            "0.000000",
                "initialEventTime":          "1702436441.269680",
                "lastEventTime":             "1702436441.269680",
                "lastThresholdEventTime":    "0.000000",
                "counterName":               "IptCrcErrCnt",
                "dropCount":                 "1",
                "delta1":                    "0",
                "delta4":                    "4294967295",
                "chipId":                    "0",
                "chipType":                  "fap",
                "counterId":                 "1",
                "offset":                    "65535",
                "delta3":                    "4294967295",
                "delta5":                    "4294967295",
                "eventCount":                "1",
                "thresholdEventCount":       "0",
            },
        }
        server.UpdateDB("sample1_key", sample_1) // sends IPTCRC anomaly to client

        // Assert that the response was received
        response := <-responseChan
        assert.Equal(t, "instance1", response.InstanceId)
        assert.Equal(t, "anomaly1", response.AnomalyInstanceId)
        assert.Equal(t, "iptcrc_detection", response.Action)
        assert.Equal(t, "Jericho3/0", response.AnomalyKey)
        assert.Equal(t, "Detected IPTCRC", response.Response)
        assert.Equal(t, 0, response.ResultCode)
        assert.Equal(t, "Success", response.ResultStr)

        // Assert that an error was returned
        assert.NoError(t, err)

        // cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
        logger = nil
    })

    t.Run("test request with restartconnection flag, error in reconnections", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        //defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
            "initial_detection_reporting_frequency_in_mins": 1,
            "subsequent_detection_reporting_frequency_in_mins": 1,
            "initial_detection_reporting_max_count": 12,
            "periodic_subscription_interval_in_hours": 1,
            "error_backoff_time_in_secs": 1,
            "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
        }`)

        actionConfig := lomcommon.ActionCfg_t{
            ActionKnobs:  actionKnobs,
            Name:         "iptcrc_detection",
            Type:         "Detection",
            Timeout:      0,
            Disable:      false,
            Mimic:        false,
            HeartbeatInt: 10,
        }

        // create plugin object
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Stop the GNMI server
        server.Stop()

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // sleep
        time.Sleep(3 * time.Second)

        // since server is stopped. Expecting SubscribeError error in executeIPTCRCDetection
        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Incremented consecutiveError count for plugin \(iptcrc_detection\)`)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: Incremented consecutiveError count for plugin (iptcrc_detection)")

        // Now start the server
        //if err := server.Start(":50051"); err != nil {
        //  t.Fatalf("Failed to start GNMI server: %v", err)
        //}
        // defer server.Stop()

        // sleep untill backoff time is over
        time.Sleep(2 * time.Second)

        // Now expect executeIPTCRCDetection to be called again with restartConnection flag set to true
        logs = mylogger.GetLogs()
        fmt.Println("logs: ", logs)
        pattern1 = regexp.MustCompile("IPTCRC Detection Starting, restartConnection: true")
        found1 = false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: IPTCRC Detection Starting, restartConnection: true")

        // cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(3 * time.Second)
        //server.Stop()
        logger = nil

    })
}

func TestShutdown_Integrationtest(t *testing.T) {

    //
    // This test ensures that the IPTCRCDetectionPlugin handles the shutdown process correctly, including stopping the detection process and
    //  returning the expected response.

    t.Run("test shutdown - success", func(t *testing.T) {

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
                "initial_detection_reporting_frequency_in_mins": 1,
                "subsequent_detection_reporting_frequency_in_mins": 1,
                "initial_detection_reporting_max_count": 12,
                "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
            }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // Initiate plugin shutdown
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)

        // Assert that the response was received
        response := <-responseChan
        assert.Equal(t, "instance1", response.InstanceId)
        assert.Equal(t, "anomaly1", response.AnomalyInstanceId)
        assert.Equal(t, "iptcrc_detection", response.Action)
        assert.Equal(t, "", response.AnomalyKey)
        assert.Equal(t, "", response.Response)
        assert.Equal(t, plugins_common.ResultCodeAborted, response.ResultCode)
        assert.Equal(t, plugins_common.ResultStringFailure, response.ResultStr)

    })
}

func TestRequest_GNMI_Delete_Integrationtest(t *testing.T) {

    // This test ensures that the IPTCRCDetectionPlugin handles the anomaly correctly when the anomaly is cleared.
    t.Run("Success gnmi delete notfication", func(t *testing.T) {

        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
                   "initial_detection_reporting_frequency_in_mins": 1,
                   "subsequent_detection_reporting_frequency_in_mins": 1,
                   "initial_detection_reporting_max_count": 12,
                   "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
               }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 10) // >1 to avoid blocking

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        //generate and send subscription9IPTCRC message to client
        var sample_1 = map[string]interface{}{
            "key_details": "0_fap_1_65535", //chipId_chipType_CounterId_offset
            "Timestamp":   "1702436651320833298",
            "Updates": map[string]interface{}{
                "chipName":                  "Jericho3/0",
                "delta2":                    "4294967295",
                "initialThresholdEventTime": "0.000000",
                "lastSyslogTime":            "0.000000",
                "initialEventTime":          "1702436441.269680",
                "lastEventTime":             "1702436441.269680",
                "lastThresholdEventTime":    "0.000000",
                "counterName":               "IptCrcErrCnt",
                "dropCount":                 "1",
                "delta1":                    "0",
                "delta4":                    "4294967295",
                "chipId":                    "0",
                "chipType":                  "fap",
                "counterId":                 "1",
                "offset":                    "65535",
                "delta3":                    "4294967295",
                "delta5":                    "4294967295",
                "eventCount":                "1",
                "thresholdEventCount":       "0",
            },
        }
        server.UpdateDB("sample1_key", sample_1) // sends IPTCRC anomaly to client

        // Assert that the response was received
        response := <-responseChan
        fmt.Println("response: ", response)
        assert.Equal(t, "instance1", response.InstanceId)
        assert.Equal(t, "anomaly1", response.AnomalyInstanceId)
        assert.Equal(t, "iptcrc_detection", response.Action)
        assert.Equal(t, "Jericho3/0", response.AnomalyKey)
        assert.Equal(t, "Detected IPTCRC", response.Response)
        assert.Equal(t, 0, response.ResultCode)
        assert.Equal(t, "Success", response.ResultStr)

        // Assert that an error was returned
        assert.NoError(t, err)

        // Start the new Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        // wait untill subscription is active
        time.Sleep(2 * time.Second)

        // Now send the gnmi delete notification to client for the same anomaly
        server.DeleteDB("sample1_key")

        // sleep untill anomaly is cleared
        time.Sleep(2 * time.Second)

        // check for logs
        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)

        patterns := []string{
            `skipping reporting for chip 0 as reporting frequency is not met`,
            `handling prefix: /Smash/hardware/counter/internalDrop/SandCounters/internalDrop for notification type: delete`,
            `IPTCRCDetection Anomaly Cleared`,
            `Chips with IPTCRC error cleared: \[0\]`,
        }

        found := make([]bool, len(patterns))

        for i, pattern := range patterns {
            re := regexp.MustCompile(pattern)
            for _, log := range logs {
                if re.MatchString(log) {
                    found[i] = true
                    break
                }
            }
        }

        for i, pattern := range patterns {
            assert.True(t, found[i], "Expected pattern not found: "+pattern)
        }

        //cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
        logger = nil
    })
}

func TestProcessGNMINotification(t *testing.T) {

    t.Run("Failure to parse notification", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        plugin := &IPTCRCDetectionPlugin{}

        a, b, c := plugin.processGNMINotification(nil)

        // assert a as nil, b as nil, c as error Failed to parse gnmi subscription notification
        assert.Nil(t, a)
        assert.Nil(t, b)
        assert.True(t, strings.HasPrefix(c.Error(), "invalid type for notification"))
    })

    t.Run("Failure to parse notification prefix", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        plugin := &IPTCRCDetectionPlugin{}

        plugin.reportingFreqLimiter = plugins_common.GetDetectionFrequencyLimiter(10, 10, 10)

        notification := &ext_gnmi.Notification{
            Timestamp: 1234567890,
            Update: []*ext_gnmi.Update{
                {
                    Path: &ext_gnmi.Path{
                        Element: []string{"state", "operStatus"},
                    },
                    Val: &ext_gnmi.TypedValue{
                        Value: &ext_gnmi.TypedValue_StringVal{
                            StringVal: "UP",
                        },
                    },
                },
            },
        }

        a, b, c := plugin.processGNMINotification(notification)

        // assert a as nil, b as nil, c as error Failed to parse gnmi subscription notification
        assert.Nil(t, a)
        assert.Nil(t, b)
        assert.True(t, strings.HasPrefix(c.Error(), "prefix not found in parsed notification"))
    })

    t.Run("invalid prefix", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        plugin := &IPTCRCDetectionPlugin{}

        plugin.reportingFreqLimiter = plugins_common.GetDetectionFrequencyLimiter(10, 10, 10)

        notification := &ext_gnmi.Notification{
            Timestamp: 1234567890,
            Prefix: &ext_gnmi.Path{
                Elem: []*ext_gnmi.PathElem{
                    {Name: "interfaces"},
                    {Name: "interface"},
                },
            },
            Update: []*ext_gnmi.Update{
                {
                    Path: &ext_gnmi.Path{
                        Elem: []*ext_gnmi.PathElem{
                            {Name: "Ethernet0"},
                            {Name: "state"},
                            {Name: "operStatus"},
                        },
                    },
                    Val: &ext_gnmi.TypedValue{
                        Value: &ext_gnmi.TypedValue_StringVal{
                            StringVal: "UP",
                        },
                    },
                },
            },
        }

        a, b, c := plugin.processGNMINotification(notification)

        // assert a as nil, b as nil, c as error Failed to parse gnmi subscription notification
        assert.Nil(t, a)
        assert.Nil(t, b)
        assert.True(t, strings.HasPrefix(c.Error(), "executeIPTCRCDetection - ignoring prefix"))
    })

    t.Run("GetSandCounterUpdates API error", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        plugin := &IPTCRCDetectionPlugin{}

        plugin.reportingFreqLimiter = plugins_common.GetDetectionFrequencyLimiter(10, 10, 10)

        notification := &ext_gnmi.Notification{
            Timestamp: 1234567890,
            Prefix: &ext_gnmi.Path{
                Elem: []*ext_gnmi.PathElem{
                    {Name: "Smash"},
                    {Name: "hardware"},
                    {Name: "counter"},
                    {Name: "internalDrop"},
                    {Name: "SandCounters"},
                    {Name: "internalDrop"},
                },
            },
            Update: []*ext_gnmi.Update{
                {
                    Path: &ext_gnmi.Path{
                        Elem: []*ext_gnmi.PathElem{
                            {Name: "Ethernet0"},
                            {Name: "state"},
                            {Name: "operStatus"},
                        },
                    },
                    Val: &ext_gnmi.TypedValue{
                        Value: &ext_gnmi.TypedValue_StringVal{
                            StringVal: "UP",
                        },
                    },
                },
            },
        }

        a, b, _ := plugin.processGNMINotification(notification)

        // assert a as nil, b as nil, c as error Failed to parse gnmi subscription notification
        assert.Nil(t, a)
        assert.Nil(t, b)
        //assert.True(t, strings.HasPrefix(c.Error(), "executeIPTCRCDetection - ignoring prefix"))

        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Failed to get IPTCRC counter updates from gnmi notification:`)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: Failed to get IPTCRC counter updates from gnmi notification:")

    })

    t.Run("ConvertToChipData API , invalid dropcount", func(t *testing.T) {
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
                   "initial_detection_reporting_frequency_in_mins": 1,
                   "subsequent_detection_reporting_frequency_in_mins": 1,
                   "initial_detection_reporting_max_count": 12,
                   "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
               }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        //generate and send subscription9IPTCRC error) to client
        var sample_1 = map[string]interface{}{
            "key_details": "0_fap_1_65535", //chipId_chipType_CounterId_offset
            "Timestamp":   "1702436651320833298",
            "Updates": map[string]interface{}{
                "chipName":                  "Jericho3/0",
                "delta2":                    "4294967295",
                "initialThresholdEventTime": "0.000000",
                "lastSyslogTime":            "0.000000",
                "initialEventTime":          "1702436441.269680",
                "lastEventTime":             "1702436441.269680",
                "lastThresholdEventTime":    "0.000000",
                "counterName":               "IptCrcErrCnt",
                "dropCount":                 "0", //invalid dropcount
                "delta1":                    "0",
                "delta4":                    "4294967295",
                "chipId":                    "0",
                "chipType":                  "fap",
                "counterId":                 "1",
                "offset":                    "65535",
                "delta3":                    "4294967295",
                "delta5":                    "4294967295",
                "eventCount":                "1",
                "thresholdEventCount":       "0",
            },
        }
        server.UpdateDB("sample1_key", sample_1) // sends IPTCRC anomaly to client

        //sleep
        time.Sleep(2 * time.Second)

        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`executeIPTCRCDetection - invalid drop count value `)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: executeIPTCRCDetection - invalid drop count value")

        //cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
        mylogger = nil
    })

    t.Run("GetSandCounterDeletes API error", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        plugin := &IPTCRCDetectionPlugin{}

        plugin.reportingFreqLimiter = plugins_common.GetDetectionFrequencyLimiter(10, 10, 10)

        notification := &ext_gnmi.Notification{
            Timestamp: 1234567890,
            Prefix: &ext_gnmi.Path{
                Elem: []*ext_gnmi.PathElem{
                    {Name: "Smash"},
                    {Name: "hardware"},
                    {Name: "counter"},
                    {Name: "internalDrop"},
                    {Name: "SandCounters"},
                    {Name: "internalDrop"},
                },
            },
            Delete: []*ext_gnmi.Path{
                {
                    Elem: []*ext_gnmi.PathElem{
                        {Name: "interfaces"},
                        {Name: "interface"},
                        {Name: "Ethernet2"},
                    },
                },
                {
                    Elem: []*ext_gnmi.PathElem{
                        {Name: "interfaces"},
                        {Name: "interface"},
                        {Name: "Ethernet3"},
                    },
                },
            },
        }

        a, b, _ := plugin.processGNMINotification(notification)

        // assert a as nil, b as nil, c as error Failed to parse gnmi subscription notification
        assert.Nil(t, a)
        assert.Nil(t, b)
        //assert.True(t, strings.HasPrefix(c.Error(), "executeIPTCRCDetection - ignoring prefix"))

        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Failed to get IPTCRC counter deletes from gnmi notification:`)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: Failed to get IPTCRC counter deletes from gnmi notification:")

    })
}

func TestGetPluginID(t *testing.T) {

    t.Run("Success", func(t *testing.T) {

        plugin := &IPTCRCDetectionPlugin{}
        assert.Equal(t, detection_plugin_name, plugin.GetPluginID().Name)
    })
}

// TestExecuteShutdown tests the executeIPTCRCDetection function
func TestExecuteShutdown(t *testing.T) {

    t.Run("Test error in gnmi close call", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
            "initial_detection_reporting_frequency_in_mins": 1,
            "subsequent_detection_reporting_frequency_in_mins": 1,
            "initial_detection_reporting_max_count": 12,
            "chipid_name_mappings_file": "../../plugin_integration_tests/config/chipid_name_mappings.json"
        }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // close gnmi session manually for first time
        iPTCRCDetectionPlugin.aristaGnmiSession.Unsubscribe()
        err = iPTCRCDetectionPlugin.aristaGnmiSession.Close()
        assert.NoError(t, err)

        iPTCRCDetectionPlugin.executeShutdown()

        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Failed to close arista gnmi server session: `)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: Failed to close arista gnmi server session: ")

        logger = nil
    })

    //  previously gnmi connection is closed and trying to do shutdoen twice
    t.Run("Test multiple shutdowns", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
            "initial_detection_reporting_frequency_in_mins": 1,
            "subsequent_detection_reporting_frequency_in_mins": 1,
            "initial_detection_reporting_max_count": 12
        }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // first time shutdown
        iPTCRCDetectionPlugin.executeShutdown()

        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Failed to close arista gnmi server session: `)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.False(t, found1, "Expected pattern not found: Failed to close arista gnmi server session: ")

        mylogger.ClearLogs()

        // second time shutdown
        iPTCRCDetectionPlugin.executeShutdown()

        // test iptCRCDetectionPlugin.sessionValid is false
        assert.False(t, iPTCRCDetectionPlugin.sessionValid)

        logger = nil
    })
}

// TestRestartNewGNMISession tests the restartNewGNMISession function
func TestRestartNewGNMISession(t *testing.T) {

    // test new session created
    t.Run("test with empty session params", func(t *testing.T) {

        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // create globals.conf.json file with empty session params
        globalCOnfigData := []byte(`{
            "MAX_SEQ_TIMEOUT_SECS": 120,
            "MIN_PERIODIC_LOG_PERIOD_SECS": 1,
            "ENGINE_HB_INTERVAL_SECS": 10,
            "INITIAL_DETECTION_REPORTING_FREQ_IN_MINS": 5,
            "SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS": 60,
            "INITIAL_DETECTION_REPORTING_MAX_COUNT": 12,
            "PLUGIN_MIN_ERR_CNT_TO_SKIP_HEARTBEAT" : 3, 
            "MAX_PLUGIN_RESPONSES" : 100,
            "MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT_IN_SECS" : 60,
            "LOCAL_GNMI_USE_TLS" : "false",
            "LOCAL_GNMI_CERTIFICATE_FILE_PATH" : "/tmp",
            "LOCAL_GNMI_PRIVATE_KEY_FILE_PATH" : "/tmp",
            "LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH" : "/tmp",
            "LOCAL_GNMI_VALIDATE_SERVER_CERTIFICATE" : "false"
        }`)

        InitConfigMgr(nil, nil, nil, globalCOnfigData)

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        err := iPTCRCDetectionPlugin.restartNewGNMISession()

        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Failed to create arista gnmi server session`)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: Failed to create arista gnmi server session")

        assert.Error(t, err)

        // test iptCRCDetectionPlugin.aristaGnmiSession is nil
        assert.Nil(t, iPTCRCDetectionPlugin.aristaGnmiSession)

        logger = nil

        //restore globals.conf.json file
        InitConfigMgrDefault()
    })

    // test new session created
    t.Run("test with error in session close", func(t *testing.T) {

        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        err := iPTCRCDetectionPlugin.restartNewGNMISession()

        assert.NoError(t, err)

        // test iptCRCDetectionPlugin.aristaGnmiSession is not nil
        assert.NotNil(t, iPTCRCDetectionPlugin.aristaGnmiSession)

        // close gnmi session manually
        iPTCRCDetectionPlugin.aristaGnmiSession.Unsubscribe()
        err = iPTCRCDetectionPlugin.aristaGnmiSession.Close()
        assert.NoError(t, err)

        // call the function to be tested
        err = iPTCRCDetectionPlugin.restartNewGNMISession() // will get close error

        assert.NoError(t, err)

        // test iptCRCDetectionPlugin.aristaGnmiSession is not nil
        assert.NotNil(t, iPTCRCDetectionPlugin.aristaGnmiSession)

        logs := mylogger.GetLogs()
        fmt.Print("logs: ", logs)
        pattern1 := regexp.MustCompile(`Failed to close arista gnmi server session: `)
        fmt.Println("logs: ", logs)
        found1 := false
        for _, log := range logs {
            if pattern1.MatchString(log) {
                found1 = true
            }
        }
        assert.True(t, found1, "Expected pattern not found: Failed to close arista gnmi server session: ")

        // cleanup
        iPTCRCDetectionPlugin.aristaGnmiSession.Close()
        iPTCRCDetectionPlugin.aristaGnmiSession = nil
        logger = nil

    })
}

// TestExecuteIPTCRCDetection tests the executeIPTCRCDetection function
func TestExecuteIPTCRCDetection(t *testing.T) {

    // test new session created
    t.Run("test executeIPTCRCDetection with Receive error", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // Create a mock GNMI session
        mockSession := new(MockGNMISession)

        // Set up expectation for the Resubscribe method
        mockSession.On("Resubscribe", mock.Anything, mock.Anything).Return(nil)
        mockSession.On("Unsubscribe").Return(nil)

        // Create an error for the mock Receive method
        receiveErr := errors.New("receive error")

        // Set up expectation for the Receive method to return an error
        mockSession.On("Receive").Return(nil, nil, receiveErr)

        // Create a new IPTCRCDetectionPlugin with the mock session
        plugin := &IPTCRCDetectionPlugin{
            aristaGnmiSession: mockSession,
        }
        plugin.reportingFreqLimiter = plugins_common.GetDetectionFrequencyLimiter(1, 1, 1)

        // Call the function under test
        _, err := plugin.executeIPTCRCDetection(nil, context.Background(), false)

        // Assert that there was an error and it's the expected one
        assert.Error(t, err)
        receiveError, ok := err.(*plugins_common.ReceiveError)
        assert.True(t, ok)
        assert.Equal(t, receiveErr, receiveError.Err)

        // Assert that the Resubscribe and Receive methods were called
        mockSession.AssertCalled(t, "Resubscribe", mock.Anything, mock.Anything)
        mockSession.AssertCalled(t, "Receive")
    })

    t.Run("test executeIPTCRCDetection with shutdown & defer close error", func(t *testing.T) {
        // Create a mock logger to capture the log messages
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // Create a mock GNMI session
        mockSession := new(MockGNMISession)

        // Set up expectation for the Resubscribe method
        mockSession.On("Resubscribe", mock.Anything, mock.Anything).Return(nil)
        mockSession.On("Unsubscribe").Return(nil)

        // Create an error for the mock Close method
        closeErr := errors.New("receive error")

        //shutdoen error
        shutdownErr := errors.New("context canceled")

        mockSession.On("Close").Return(closeErr)

        // Set up expectation for the Receive method to return an error
        mockSession.On("Receive").Return(nil, nil, nil)

        // Create a new IPTCRCDetectionPlugin with the mock session
        plugin := &IPTCRCDetectionPlugin{
            aristaGnmiSession: mockSession,
        }
        plugin.reportingFreqLimiter = plugins_common.GetDetectionFrequencyLimiter(1, 1, 1)

        // Create a context with a cancel function
        ctx, cancel := context.WithCancel(context.Background())

        // Cancel the context
        cancel()

        plugin.sessionValid = true
        // Call the function under test
        _, err := plugin.executeIPTCRCDetection(nil, ctx, false)

        // Assert that there was an error and it's the expected one
        assert.Error(t, err)
        shutdownError, ok := err.(*plugins_common.ShutdownError)
        assert.True(t, ok)
        assert.Equal(t, shutdownErr, shutdownError.Err)

        logs := mylogger.GetLogs()
        pattern1 := regexp.MustCompile(`Failed to close arista gnmi server session: `)
        pattern2 := regexp.MustCompile(`Shutdown initiated, stopping executeIPTCRCDetection`)
        found1, found2 := false, false
        for _, log := range logs {
            if !found1 && pattern1.MatchString(log) {
                found1 = true
            }
            if !found2 && pattern2.MatchString(log) {
                found2 = true
            }
            if found1 && found2 {
                break
            }
        }
        assert.True(t, found1, "Expected pattern not found: Failed to close arista gnmi server session: ")
        assert.True(t, found2, "Expected pattern not found: Shutdown initiated, stopping executeIPTCRCDetection")

        // Assert that the Resubscribe and Receive methods were called
        mockSession.AssertCalled(t, "Resubscribe", mock.Anything, mock.Anything)
        mockSession.AssertCalled(t, "Receive")
        assert.False(t, plugin.sessionValid)
    })
}

func TestInvalidGNMI_Integrationtest(t *testing.T) {
    t.Run("test Invalid gnmi notification - invalid path", func(t *testing.T) {
        mylogger := &MockLogger{}

        // Create a plugin logger with the mock logger's LogFunc method
        pluginLogger := plugins_common.NewLogger("test", mylogger.LogFunc)

        // Assign the plugin logger to the plugin
        logger = pluginLogger

        // create gnmi server
        certificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CERTIFICATE_FILE_PATH")
        privateKeyFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_PRIVATE_KEY_FILE_PATH")
        caCertificateFilePath := lomcommon.GetConfigMgr().GetGlobalCfgStr("LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH")

        server := arista_common.NewGNMITestServer()
        if err := server.Start(":50051", certificateFilePath, privateKeyFilePath, caCertificateFilePath); err != nil {
            t.Fatalf("Failed to start GNMI server: %v", err)
        }
        defer server.Stop()

        // define config
        actionKnobs := json.RawMessage(`{
               "initial_detection_reporting_frequency_in_mins": 1,
               "subsequent_detection_reporting_frequency_in_mins": 1,
               "initial_detection_reporting_max_count": 12
           }`)

        actionConfig := lomcommon.ActionCfg_t{HeartbeatInt: 10,
            ActionKnobs: actionKnobs,
            Name:        "iptcrc_detection",
            Type:        "Detection",
            Timeout:     0,
            Disable:     false,
            Mimic:       false,
        }

        // create plugin
        iPTCRCDetectionPlugin := IPTCRCDetectionPlugin{}

        // call init
        err := iPTCRCDetectionPlugin.Init(&actionConfig)
        assert.NoError(t, err)

        // Create a request
        request := lomipc.ActionRequestData{
            Action:            "iptcrc_detection",
            InstanceId:        "instance1",
            AnomalyInstanceId: "anomaly1",
            AnomalyKey:        "",
            Timeout:           0,
            //Context:           []*lomipc.ActionResponseData{},
        }

        // create heartbeat channel
        heartbeatChan := make(chan plugins_common.PluginHeartBeat, 1)

        // Create a channel to receive the response
        responseChan := make(chan *lomipc.ActionResponseData)

        // Start the Request function in a goroutine
        go func() {
            response := iPTCRCDetectionPlugin.Request(heartbeatChan, &request)
            responseChan <- response
        }()

        //sleep
        time.Sleep(2 * time.Second)

        server.UpdateDBFakeResponseNoPrefix() // send gnmi fake notification without prefix to client

        time.Sleep(2 * time.Second)

        logs := mylogger.GetLogs()
        fmt.Println("logs: ", logs)
        pattern1 := regexp.MustCompile(`Failed to process gnmi subscription notification`)
        pattern2 := regexp.MustCompile(`Failed to get prefix from gnmi notification`)
        found1, found2 := false, false
        for _, log := range logs {
            if !found1 && pattern1.MatchString(log) {
                found1 = true
            }
            if !found2 && pattern2.MatchString(log) {
                found2 = true
            }
            if found1 && found2 {
                break
            }
        }
        assert.True(t, found1, "Expected pattern not found: Failed to process gnmi subscription notification")
        assert.True(t, found2, "Expected pattern not found: Failed to get prefix from gnmi notification")

        //cleanup
        iPTCRCDetectionPlugin.Shutdown()
        time.Sleep(2 * time.Second)
        logger = nil
    })
}
