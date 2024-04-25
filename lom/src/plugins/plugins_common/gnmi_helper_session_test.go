package plugins_common

import (
    "encoding/json"
    "errors"
    "io"
    "io/ioutil"
    "log"
    "lom/src/lib/lomcommon"
    "net"
    "reflect"
    "testing"
    "time"

    "github.com/agiledragon/gomonkey"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "google.golang.org/grpc"

    "github.com/openconfig/gnmi/proto/gnmi"
    ext_gnmi "github.com/openconfig/gnmi/proto/gnmi"
)

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
                "error_backoff_time_in_secs" : 60
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
        "LOCAL_GNMI_USE_TLS" : "false",
        "LOCAL_GNMI_CERTIFICATE_FILE_PATH" : "/tmp",
        "LOCAL_GNMI_PRIVATE_KEY_FILE_PATH" : "/tmp",
        "LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH" : "/tmp",
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
    lomcommon.InitConfigMgr(configFiles)
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
    lomcommon.InitConfigMgr(configFiles)
}

//------------------------ Tests ---------------------------------

// Test readGNMISecurityParams API
func TestReadGNMISecurityParams(t *testing.T) {
    t.Run("SuccessfulRead", func(t *testing.T) {

        // Initilaize default config manager
        InitConfigMgrDefault()

        // Call the function under test
        security := readGNMISecurityParams()

        assert.Equal(t, "admin", security.username)
        assert.Equal(t, "password", security.password)
        assert.Equal(t, "localhost:50051", security.server)
        assert.Equal(t, false, security.useTLS)
    })

    t.Run("Missing params", func(t *testing.T) {

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
            "LOCAL_GNMI_CERTIFICATE_FILE_PATH" : "/tmp",
            "LOCAL_GNMI_PRIVATE_KEY_FILE_PATH" : "/tmp",
            "LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH" : "/tmp",
            "LOCAL_GNMI_VALIDATE_SERVER_CERTIFICATE" : "false"
        }`)

        // Initilaize
        InitConfigMgr(nil, nil, nil, defaultData)

        // Call the function under test
        security := readGNMISecurityParams()

        // values must be nil
        assert.Equal(t, "", security.username)
        assert.Equal(t, "", security.password)
        assert.Equal(t, "", security.server)
        assert.Equal(t, false, security.useTLS)

        // Cleanup
        InitConfigMgrDefault()
    })
}

func TestSessionCapabilities(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)

        // Setup expectations
        expectedResponse := &ext_gnmi.CapabilityResponse{
            SupportedModels: []*ext_gnmi.ModelData{
                {
                    Name:         "model1",
                    Organization: "org1",
                    Version:      "v1",
                },
                {
                    Name:         "model2",
                    Organization: "org2",
                    Version:      "v2",
                },
            },
            SupportedEncodings: []ext_gnmi.Encoding{ext_gnmi.Encoding_JSON, ext_gnmi.Encoding_PROTO},
            GNMIVersion:        "0.7.0",
        }
        mockClient.On("Capabilities", mock.Anything, mock.AnythingOfType("*gnmi.CapabilityRequest")).Return(expectedResponse, nil)

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Capabilities and assert the response
        response, err := session.Capabilities()
        assert.NoError(t, err)
        assert.Equal(t, expectedResponse, response)

        // Assert Expectations
        mockClient.AssertExpectations(t)
    })

    t.Run("Failure - Error from Capabilities", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)

        // Setup expectations
        mockClient.On("Capabilities", mock.Anything, mock.AnythingOfType("*gnmi.CapabilityRequest")).Return(nil, errors.New("mock error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Capabilities and assert the response
        _, err := session.Capabilities()
        assert.Error(t, err)
        assert.Equal(t, "failed to get capabilities: mock error", err.Error())

        // Assert Expectations
        mockClient.AssertExpectations(t)
    })

    t.Run("Failure - Client not initialized", func(t *testing.T) {
        // Setup instance
        instance := &gnmiServerConnector{}

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Capabilities and assert the response
        _, err := session.Capabilities()
        assert.Error(t, err)
        assert.Equal(t, "client is not initialized", err.Error())
    })
}

func TestSessionGet(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)

        // Setup expectations
        expectedResponse := &ext_gnmi.GetResponse{} // Fill this with the expected response
        mockClient.On("Get", mock.Anything, mock.AnythingOfType("*gnmi.GetRequest")).Return(expectedResponse, nil)

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Get and assert the response
        response, err := session.Get("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)
        assert.Equal(t, expectedResponse, response)

        // Assert Expectations
        mockClient.AssertExpectations(t)
    })
    t.Run("Error", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)

        // Setup expectations
        mockClient.On("Get", mock.Anything, mock.AnythingOfType("*gnmi.GetRequest")).Return(nil, errors.New("mock error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Get and assert the response
        _, err := session.Get("prefix", []string{"path1", "path2"})
        assert.Error(t, err)
        assert.Equal(t, "failed to get: mock error", err.Error())

        // Assert Expectations
        mockClient.AssertExpectations(t)
    })
}

func TestProcessGet(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Create a GNMISession
        session := &GNMISession{}

        // Create a GetResponse with a Notification
        response := &gnmi.GetResponse{
            Notification: []*gnmi.Notification{
                {
                    Timestamp: 123456789,
                    Prefix: &gnmi.Path{
                        Element: []string{"interfaces", "interface", "Ethernet0"},
                    },
                    Update: []*gnmi.Update{
                        {
                            Path: &gnmi.Path{
                                Element: []string{"state", "operStatus"},
                            },
                            Val: &gnmi.TypedValue{
                                Value: &gnmi.TypedValue_StringVal{
                                    StringVal: "UP",
                                },
                            },
                        },
                    },
                },
            },
        }

        // Call ProcessGet and assert the response
        notifications, err := session.ProcessGet(response)
        assert.NoError(t, err)
        assert.Equal(t, response.Notification, notifications)
    })

    t.Run("Error - response is nil", func(t *testing.T) {
        // Create a GNMISession
        session := &GNMISession{}

        // Call ProcessGet with a nil response and assert the error
        _, err := session.ProcessGet(nil)
        assert.Error(t, err)
        assert.Equal(t, errors.New("response is nil"), err)
    })

    t.Run("Error - no notifications in response", func(t *testing.T) {
        // Create a GNMISession
        session := &GNMISession{}

        // Create a GetResponse with no Notifications
        response := &gnmi.GetResponse{}

        // Call ProcessGet and assert the error
        _, err := session.ProcessGet(response)
        assert.Error(t, err)
        assert.Equal(t, errors.New("no notifications in response"), err)
    })
}

func TestSessionSubscribe(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)

        // Setup expectations
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Subscribe and assert no error
        err := session.Subscribe("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)

        // Assert that the prefix and paths are set correctly
        assert.Equal(t, "prefix", session.prefix)
        assert.Equal(t, []string{"path1", "path2"}, session.paths)

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockSubscribeClient.AssertExpectations(t)
    })

    t.Run("ErrorActiveSubscription", func(t *testing.T) {
        // Create GNMISession with an active subscription
        session := &GNMISession{
            cancel: func() {},
        }

        // Call Subscribe and assert the error
        err := session.Subscribe("prefix", []string{"path1", "path2"})
        assert.Error(t, err)
        assert.Equal(t, "a subscription is already active", err.Error())

        // Assert that cancel and stream fields are not nil
        assert.NotNil(t, session.cancel)
        assert.Nil(t, session.stream)
    })

    t.Run("ErrorSubscribeStream", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)

        // Setup expectations
        mockClient.On("Subscribe", mock.Anything).Return(nil, errors.New("mock error"))

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Subscribe and assert the error
        err := session.Subscribe("prefix", []string{"path1", "path2"})
        assert.Error(t, err)
        assert.Equal(t, "failed to subscribe: mock error", err.Error())

        // Assert that cancel and stream fields are nil
        assert.Nil(t, session.cancel)
        assert.Nil(t, session.stream)

        // Assert Expectations
        mockClient.AssertExpectations(t)
    })
}

func TestGNMISession_Unsubscribe(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)

        // Setup expectations
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Subscribe to set the cancel and stream fields
        err := session.Subscribe("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)

        // Call Unsubscribe and assert no error
        err = session.Unsubscribe()
        assert.NoError(t, err)

        // Assert that cancel and stream fields are nil
        assert.Nil(t, session.cancel)
        assert.Nil(t, session.stream)

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockSubscribeClient.AssertExpectations(t)
    })

    t.Run("NoActiveSubscription", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Unsubscribe and assert no error
        err := session.Unsubscribe()
        assert.NoError(t, err)

        // Assert that cancel and stream fields are nil
        assert.Nil(t, session.cancel)
        assert.Nil(t, session.stream)
    })
}

func TestGNMISession_Close(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)
        mockConn.On("Close").Return(nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockClient, nil)

        // setup connection to gNMI server
        securityDetails := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
        }
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, securityDetails)
        assert.NoError(t, err)
        assert.NotNil(t, instance)

        // Setup expectations
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Subscribe to set the cancel and stream fields
        err = session.Subscribe("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)

        // Call Close and assert no error
        err = session.Close()
        assert.NoError(t, err)

        // Assert that cancel and stream fields are nil
        assert.Nil(t, session.cancel)
        assert.Nil(t, session.stream)

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockSubscribeClient.AssertExpectations(t)
    })

    t.Run("ErrorClose", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)
        mockConn.On("Close").Return(errors.New("mock error"))

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockClient, nil)

        // setup connection to gNMI server
        securityDetails := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
        }
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, securityDetails)
        assert.NoError(t, err)
        assert.NotNil(t, instance)

        // Setup expectations
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Subscribe to set the cancel and stream fields
        err = session.Subscribe("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)

        // Call Close and assert the error
        err = session.Close()
        assert.Error(t, err)
        assert.Equal(t, "failed to close connection: mock error", err.Error())

        // Assert that cancel and stream fields are nil
        assert.Nil(t, session.cancel)
        assert.Nil(t, session.stream)

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockSubscribeClient.AssertExpectations(t)
        mockConn.AssertExpectations(t)
    })

    t.Run("NoActiveSubscription", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8081", mock.Anything).Return(mockConn, nil)
        mockConn.On("Close").Return(nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockClient, nil)

        // setup connection to gNMI server
        securityDetails := gnmiSecurityDetails{
            server:   "localhost:8081",
            username: "admin",
            password: "admin",
        }
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, securityDetails)
        assert.NoError(t, err)
        assert.NotNil(t, instance)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Close and assert no error
        err = session.Close()
        assert.NoError(t, err)

        // Assert that cancel and stream fields are nil
        assert.Nil(t, session.cancel)
        assert.Nil(t, session.stream)

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockConn.AssertExpectations(t)
    })
}

func TestGNMISession_Receive(t *testing.T) {
    t.Run("SuccessWithSyncResponse", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)

        // Setup expectations
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockSubscribeClient.On("Recv").Return(&ext_gnmi.SubscribeResponse{
            Response: &ext_gnmi.SubscribeResponse_SyncResponse{
                SyncResponse: true,
            },
        }, nil).Once()
        mockSubscribeClient.On("Recv").Return(nil, io.EOF)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Subscribe to set the cancel and stream fields
        err := session.Subscribe("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)

        // Call Receive and assert no error
        notificationsCh, errCh, err := session.Receive()
        assert.NoError(t, err)
        assert.NotNil(t, notificationsCh)
        assert.NotNil(t, errCh)

        // Read from the channels
        select {
        case notification := <-notificationsCh:
            assert.Nil(t, notification)
        case err := <-errCh:
            assert.NoError(t, err)
        case <-time.After(time.Second):
            t.Fatal("timeout waiting for notification")
        }

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockSubscribeClient.AssertExpectations(t)
    })
    t.Run("NoActiveSubscription", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8081", mock.Anything).Return(mockConn, nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockClient, nil)

        // setup connection to gNMI server
        securityDetails := gnmiSecurityDetails{
            server:   "localhost:8081",
            username: "admin",
            password: "admin",
        }
        instance, err := newGNMIClient(mockDialer, mockClientMethod, securityDetails)
        assert.NoError(t, err)
        assert.NotNil(t, instance)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: instance,
        }

        // Call Receive and assert the error
        _, _, err = session.Receive()
        assert.Error(t, err)
        assert.Equal(t, "no active subscription", err.Error())

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockDialer.AssertExpectations(t)
        mockClientMethod.AssertExpectations(t)
    })

    t.Run("ReceiveError", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)

        // Setup expectations
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockSubscribeClient.On("Recv").Return(nil, errors.New("mock error")).Once()
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Subscribe to set the cancel and stream fields
        err := session.Subscribe("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)

        // Call Receive and assert no error
        notificationsCh, errCh, err := session.Receive()
        assert.NoError(t, err)
        assert.NotNil(t, notificationsCh)
        assert.NotNil(t, errCh)

        // Read from the channels
        select {
        case notification := <-notificationsCh:
            assert.Nil(t, notification)
        case err := <-errCh:
            assert.Error(t, err)
            assert.Equal(t, "error receiving subscription: mock error", err.Error())
        case <-time.After(time.Second):
            t.Fatal("timeout waiting for notification")
        }

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockSubscribeClient.AssertExpectations(t)
    })
}

func TestGNMISession_Resubscribe(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)

        // Setup expectations
        mockSubscribeClient.On("Send", mock.Anything).Return(nil).Twice()
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil).Twice()

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Subscribe to set the cancel and stream fields
        err := session.Subscribe("prefix", []string{"path1", "path2"})
        assert.NoError(t, err)

        // Assert that the prefix and paths are set correctly
        assert.Equal(t, "prefix", session.prefix)
        assert.Equal(t, []string{"path1", "path2"}, session.paths)

        // Call Resubscribe and assert no error
        err = session.Resubscribe("newPrefix", []string{"newPath1", "newPath2"})
        assert.NoError(t, err)

        // Assert that the prefix and paths are updated correctly
        assert.Equal(t, "newPrefix", session.prefix)
        assert.Equal(t, []string{"newPath1", "newPath2"}, session.paths)

        // Assert Expectations
        mockClient.AssertExpectations(t)
        mockSubscribeClient.AssertExpectations(t)
    })

    t.Run("SubscribeError", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)

        // Setup expectations
        mockClient.On("Subscribe", mock.Anything).Return(nil, errors.New("mock error")).Once()

        // Create GNMISession with mockClient
        session := &GNMISession{
            client: &gnmiServerConnector{
                e_client: mockClient,
            },
        }

        // Call Resubscribe and assert the error
        err := session.Resubscribe("newPrefix", []string{"newPath1", "newPath2"})
        assert.Error(t, err)
        assert.Equal(t, "failed to subscribe: mock error", err.Error())

        // Assert that the prefix and paths are not updated
        assert.Empty(t, session.prefix)
        assert.Nil(t, session.paths)

        // Assert Expectations
        mockClient.AssertExpectations(t)
    })
}

// Tests the IsSubscribed method
func TestGNMISession(t *testing.T) {
    // Testing the IsSubscribed method of GNMISession
    t.Run("IsSubscribed", func(t *testing.T) {
        // Testing the case where there is an active subscription
        t.Run("WithActiveSubscription", func(t *testing.T) {
            // Create a new GNMISession with a non-nil cancel function
            s := &GNMISession{
                cancel: func() {},
            }

            // Check if IsSubscribed returns true
            // This test verifies that IsSubscribed returns true when there is an active subscription (cancel is not nil)
            if !s.IsSubscribed() {
                t.Errorf("IsSubscribed() = false; want true")
            }
        })

        // Testing the case where there is no active subscription
        t.Run("WithoutActiveSubscription", func(t *testing.T) {
            // Create a new GNMISession with a nil cancel function
            s := &GNMISession{
                cancel: nil,
            }

            // Check if IsSubscribed returns false
            // This test verifies that IsSubscribed returns false when there is no active subscription (cancel is nil)
            if s.IsSubscribed() {
                t.Errorf("IsSubscribed() = true; want false")
            }
        })
    })
}
func TestEquals(t *testing.T) {
    t.Run("EqualSessions", func(t *testing.T) {
        // Create an instance of our test object
        mockClient := new(MockGNMIClientExt)
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)
        mockConn.On("Close").Return(nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockClient, nil)

        // setup connection to gNMI server
        securityDetails := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
        }
        instance1, err := newGNMIClient(mockDialer, mockClientMethod, securityDetails)
        assert.NoError(t, err)
        assert.NotNil(t, instance1)

        instance2, err := newGNMIClient(mockDialer, mockClientMethod, securityDetails)
        assert.NoError(t, err)
        assert.NotNil(t, instance2)

        // Create two identical GNMISessions
        s1 := &GNMISession{
            client: instance1,
            paths:  []string{"path1", "path2"},
        }
        s2 := &GNMISession{
            client: instance2,
            paths:  []string{"path1", "path2"},
        }

        // Check if Equals returns true when comparePaths is true
        if !s1.Equals(s2, true) {
            t.Errorf("Equals() = false; want true")
        }

        // Check if Equals returns true when comparePaths is false
        if !s1.Equals(s2, false) {
            t.Errorf("Equals() = false; want true")
        }
    })

    t.Run("DifferentSessions", func(t *testing.T) {
        // Create an instance of our test object
        mockClient1 := new(MockGNMIClientExt)
        mockDialer1 := new(MockDialer)
        mockConn1 := new(MockGRPCConnExt)
        mockDialer1.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn1, nil)
        mockConn1.On("Close").Return(nil)

        mockClientMethod1 := new(MockGNMIClientMethodsExt)
        mockClientMethod1.On("NewGNMIClient", mockConn1).Return(mockClient1, nil)

        // setup connection to gNMI server
        securityDetails1 := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
        }
        instance1, err := newGNMIClient(mockDialer1, mockClientMethod1, securityDetails1)
        assert.NoError(t, err)
        assert.NotNil(t, instance1)

        // Create an instance of our test object
        mockClient2 := new(MockGNMIClientExt)
        mockDialer2 := new(MockDialer)
        mockConn2 := new(MockGRPCConnExt)
        mockDialer2.On("DialContext", mock.Anything, "localhost:8081", mock.Anything).Return(mockConn2, nil)
        mockConn2.On("Close").Return(nil)

        mockClientMethod2 := new(MockGNMIClientMethodsExt)
        mockClientMethod2.On("NewGNMIClient", mockConn2).Return(mockClient2, nil)

        // setup connection to gNMI server
        securityDetails2 := gnmiSecurityDetails{
            server:   "localhost:8081",
            username: "admin",
            password: "admin",
        }
        instance2, err := newGNMIClient(mockDialer2, mockClientMethod2, securityDetails2)
        assert.NoError(t, err)
        assert.NotNil(t, instance2)

        // Create two different GNMISessions
        s1 := &GNMISession{
            client: instance1,
            paths:  []string{"path1", "path2"},
        }
        s2 := &GNMISession{
            client: instance2,
            paths:  []string{"path3", "path4"},
        }

        // Check if Equals returns false when comparePaths is true
        if s1.Equals(s2, true) {
            t.Errorf("Equals() = true; want false")
        }

        // Check if Equals returns false when comparePaths is false
        if s1.Equals(s2, false) {
            t.Errorf("Equals() = true; want false")
        }
    })

    t.Run("DifferentPaths", func(t *testing.T) {
        // Create an instance of our test object
        mockClient1 := new(MockGNMIClientExt)
        mockDialer1 := new(MockDialer)
        mockConn1 := new(MockGRPCConnExt)
        mockDialer1.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn1, nil)
        mockConn1.On("Close").Return(nil)

        mockClientMethod1 := new(MockGNMIClientMethodsExt)
        mockClientMethod1.On("NewGNMIClient", mockConn1).Return(mockClient1, nil)

        // setup connection to gNMI server
        securityDetails1 := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
        }
        instance1, err := newGNMIClient(mockDialer1, mockClientMethod1, securityDetails1)
        assert.NoError(t, err)
        assert.NotNil(t, instance1)

        // Create an instance of our test object
        mockClient2 := new(MockGNMIClientExt)
        mockDialer2 := new(MockDialer)
        mockConn2 := new(MockGRPCConnExt)
        mockDialer2.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn2, nil)
        mockConn2.On("Close").Return(nil)

        mockClientMethod2 := new(MockGNMIClientMethodsExt)
        mockClientMethod2.On("NewGNMIClient", mockConn2).Return(mockClient2, nil)

        // setup connection to gNMI server
        securityDetails2 := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
        }
        instance2, err := newGNMIClient(mockDialer2, mockClientMethod2, securityDetails2)
        assert.NoError(t, err)
        assert.NotNil(t, instance2)

        // Create two GNMISessions with different paths
        s1 := &GNMISession{
            client: instance1,
            paths:  []string{"path1", "path2"},
        }
        s2 := &GNMISession{
            client: instance2,
            paths:  []string{"path3", "path4"},
        }

        // Check if Equals returns false when comparePaths is true
        if s1.Equals(s2, true) {
            t.Errorf("Equals() = true; want false")
        }
    })
}

func TestParseNotification(t *testing.T) {
    t.Run("SuccessfulParse", func(t *testing.T) {
        // Create a notification
        notification := &ext_gnmi.Notification{
            Timestamp: 1234567890,
            Prefix: &ext_gnmi.Path{
                Element: []string{"interfaces", "interface", "Ethernet0"},
            },
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

        // Parse the notification
        result, err := ParseNotification(notification)

        // Check if there was no error
        assert.NoError(t, err)

        // Check if the result is as expected
        expected := map[string]interface{}{
            "timestamp": float64(1234567890), // json.Unmarshal converts numbers to float64
            "prefix": map[string]interface{}{
                "element": []interface{}{"interfaces", "interface", "Ethernet0"},
            },
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "element": []interface{}{"state", "operStatus"},
                    },
                    "val": map[string]interface{}{
                        "Value": map[string]interface{}{
                            "StringVal": "UP",
                        },
                    },
                },
            },
        }
        assert.Equal(t, expected, result)
    })

    t.Run("UnsuccessfulParse", func(t *testing.T) {
        // Parse a nil notification
        _, err := ParseNotification(nil)

        // Check if there was an error
        assert.Error(t, err)
    })

    t.Run("UnsuccessfulTypeAssertion", func(t *testing.T) {
        // Parse an invalid notification
        _, err := ParseNotification("invalid")

        // Check if there was an error
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "invalid type for notification, expected *ext_gnmi.Notification")
    })
}

func TestGetTimestamp(t *testing.T) {
    t.Run("SuccessfulGet", func(t *testing.T) {
        // Create a parsed notification with a timestamp
        parsedNotification := map[string]interface{}{
            "timestamp": float64(1234567890),
        }

        // Get the timestamp
        timestamp, err := GetTimestamp(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("GetTimestamp() error = %v; want nil", err)
        }

        // Check if the timestamp is as expected
        if timestamp != 1234567890 {
            t.Errorf("GetTimestamp() = %v; want 1234567890", timestamp)
        }
    })

    t.Run("UnsuccessfulGet", func(t *testing.T) {
        // Create a parsed notification without a timestamp
        parsedNotification := map[string]interface{}{
            "otherKey": "otherValue",
        }

        // Get the timestamp
        _, err := GetTimestamp(parsedNotification)

        // Check if there was an error
        if err == nil {
            t.Errorf("GetTimestamp() error = nil; want non-nil")
        }
    })
}

func TestGetConstructedPaths(t *testing.T) {
    t.Run("SuccessfulGet", func(t *testing.T) {
        // Create a path map with elements
        pathMap := map[string]interface{}{
            "elem": []interface{}{
                map[string]interface{}{"name": "interfaces"},
                map[string]interface{}{"name": "interface"},
                map[string]interface{}{"name": "Ethernet0"},
            },
        }

        // Get the constructed paths
        paths, err := GetConstructedPaths(pathMap)

        // Check if there was no error
        if err != nil {
            t.Errorf("GetConstructedPaths() error = %v; want nil", err)
        }

        // Check if the paths are as expected
        expectedPaths := []string{"interfaces", "interface", "Ethernet0"}
        if !reflect.DeepEqual(paths, expectedPaths) {
            t.Errorf("GetConstructedPaths() = %v; want %v", paths, expectedPaths)
        }
    })

    t.Run("UnsuccessfulGet_NoElem", func(t *testing.T) {
        // Create a path map without "elem"
        pathMap := map[string]interface{}{
            "otherKey": "otherValue",
        }

        // Get the constructed paths
        _, err := GetConstructedPaths(pathMap)

        // Check if there was an error
        if err == nil {
            t.Errorf("GetConstructedPaths() error = nil; want non-nil")
        }
    })

    t.Run("UnsuccessfulGet_NoName", func(t *testing.T) {
        // Create a path map with an element without "name"
        pathMap := map[string]interface{}{
            "elem": []interface{}{
                map[string]interface{}{"otherKey": "otherValue"},
            },
        }

        // Get the constructed paths
        _, err := GetConstructedPaths(pathMap)

        // Check if there was an error
        if err == nil {
            t.Errorf("GetConstructedPaths() error = nil; want non-nil")
        }
    })

    t.Run("UnsuccessfulGet_ElemNotMap", func(t *testing.T) {
        // Create a path map with an element that is not a map
        pathMap := map[string]interface{}{
            "elem": []interface{}{
                "notAMap",
            },
        }

        // Get the constructed paths
        _, err := GetConstructedPaths(pathMap)

        // Check if there was an error
        if err == nil {
            t.Errorf("GetConstructedPaths() error = nil; want non-nil")
        }
    })
}

func TestGetPrefix(t *testing.T) {
    t.Run("SuccessfulGet", func(t *testing.T) {
        // Create a parsed notification with a prefix
        parsedNotification := map[string]interface{}{
            "prefix": map[string]interface{}{
                "elem": []interface{}{
                    map[string]interface{}{"name": "interfaces"},
                    map[string]interface{}{"name": "interface"},
                    map[string]interface{}{"name": "Ethernet0"},
                },
            },
        }

        // Get the prefix
        prefix, err := GetPrefix(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("GetPrefix() error = %v; want nil", err)
        }

        // Check if the prefix is as expected
        expectedPrefix := []string{"interfaces", "interface", "Ethernet0"}
        if !reflect.DeepEqual(prefix, expectedPrefix) {
            t.Errorf("GetPrefix() = %v; want %v", prefix, expectedPrefix)
        }
    })

    t.Run("UnsuccessfulGet_NoPrefix", func(t *testing.T) {
        // Create a parsed notification without a prefix
        parsedNotification := map[string]interface{}{
            "otherKey": "otherValue",
        }

        // Get the prefix
        _, err := GetPrefix(parsedNotification)

        // Check if there was an error
        if err == nil {
            t.Errorf("GetPrefix() error = nil; want non-nil")
        }
    })

    t.Run("UnsuccessfulGet_PrefixNotMap", func(t *testing.T) {
        // Create a parsed notification with a prefix that is not a map
        parsedNotification := map[string]interface{}{
            "prefix": "notAMap",
        }

        // Get the prefix
        _, err := GetPrefix(parsedNotification)

        // Check if there was an error
        if err == nil {
            t.Errorf("GetPrefix() error = nil; want non-nil")
        }
    })
}

func TestParseUpdates(t *testing.T) {
    t.Run("SuccessfulParse", func(t *testing.T) {
        // Create a parsed notification with updates
        parsedNotification := map[string]interface{}{
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "state"},
                            map[string]interface{}{"name": "operStatus"},
                        },
                    },
                    "val": map[string]interface{}{
                        "stringVal": "UP",
                    },
                },
            },
        }

        // Parse the updates
        updates, err := ParseUpdates(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseUpdates() error = %v; want nil", err)
        }

        // Check if the updates are as expected
        expectedUpdates := map[string]interface{}{
            "state/operStatus": map[string]interface{}{
                "stringVal": "UP",
            },
        }
        if !reflect.DeepEqual(updates, expectedUpdates) {
            t.Errorf("ParseUpdates() = %v; want %v", updates, expectedUpdates)
        }
    })

    t.Run("UnsuccessfulParse_NoUpdate", func(t *testing.T) {
        // Create a parsed notification without updates
        parsedNotification := map[string]interface{}{
            "otherKey": "otherValue",
        }

        // Parse the updates
        _, err := ParseUpdates(parsedNotification)

        // Check if there was an error
        if err == nil {
            t.Errorf("ParseUpdates() error = nil; want non-nil")
        }
    })

    t.Run("UnsuccessfulParse_UpdateNotMap", func(t *testing.T) {
        // Create a parsed notification with an update that is not a map
        parsedNotification := map[string]interface{}{
            "update": []interface{}{
                "notAMap",
            },
        }

        // Parse the updates
        _, err := ParseUpdates(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseUpdates() error = %v; want nil", err)
        }
    })

    t.Run("UnsuccessfulParse_NoPath", func(t *testing.T) {
        // Create a parsed notification with an update that does not have a "path"
        parsedNotification := map[string]interface{}{
            "update": []interface{}{
                map[string]interface{}{
                    "val": "value",
                },
            },
        }

        // Parse the updates
        updates, err := ParseUpdates(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseUpdates() error = %v; want nil", err)
        }

        // Check if the updates are empty
        if len(updates) != 0 {
            t.Errorf("ParseUpdates() = %v; want an empty map", updates)
        }
    })

    t.Run("UnsuccessfulParse_NoVal", func(t *testing.T) {
        // Create a parsed notification with an update that does not have a "val"
        parsedNotification := map[string]interface{}{
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "state"},
                            map[string]interface{}{"name": "operStatus"},
                        },
                    },
                },
            },
        }

        // Parse the updates
        updates, err := ParseUpdates(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseUpdates() error = %v; want nil", err)
        }

        // Check if the updates are empty
        if len(updates) != 0 {
            t.Errorf("ParseUpdates() = %v; want an empty map", updates)
        }
    })

    t.Run("UnsuccessfulParse_GetConstructedPathsError", func(t *testing.T) {
        // Create a parsed notification with an update that has a path with an invalid "elem"
        parsedNotification := map[string]interface{}{
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": "notAnArrayOfMaps",
                    },
                    "val": "value",
                },
            },
        }

        // Parse the updates
        updates, err := ParseUpdates(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseUpdates() error = %v; want nil", err)
        }

        // Check if the updates are empty
        if len(updates) != 0 {
            t.Errorf("ParseUpdates() = %v; want an empty map", updates)
        }
    })
}

func TestParseDeletes(t *testing.T) {
    t.Run("SuccessfulParse_SingleDelete", func(t *testing.T) {
        // Create a parsed notification with a single delete
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "interfaces"},
                        map[string]interface{}{"name": "interface"},
                        map[string]interface{}{"name": "Ethernet1"},
                    },
                },
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseDeletes() error = %v; want nil", err)
        }

        // Check if the deletes are as expected
        expectedDeletes := []string{
            "interfaces/interface/Ethernet1",
        }
        if !reflect.DeepEqual(deletes, expectedDeletes) {
            t.Errorf("ParseDeletes() = %v; want %v", deletes, expectedDeletes)
        }
    })

    t.Run("SuccessfulParse_MultipleDeletes", func(t *testing.T) {
        // Create a parsed notification with multiple deletes
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "interfaces"},
                        map[string]interface{}{"name": "interface"},
                        map[string]interface{}{"name": "Ethernet1"},
                    },
                },
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "interfaces"},
                        map[string]interface{}{"name": "interface"},
                        map[string]interface{}{"name": "Ethernet2"},
                    },
                },
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseDeletes() error = %v; want nil", err)
        }

        // Check if the deletes are as expected
        expectedDeletes := []string{
            "interfaces/interface/Ethernet1",
            "interfaces/interface/Ethernet2",
        }
        if !reflect.DeepEqual(deletes, expectedDeletes) {
            t.Errorf("ParseDeletes() = %v; want %v", deletes, expectedDeletes)
        }
    })

    t.Run("UnsuccessfulParse_NoDelete", func(t *testing.T) {
        // Create a parsed notification without deletes
        parsedNotification := map[string]interface{}{
            "otherKey": "otherValue",
        }

        // Parse the deletes
        _, err := ParseDeletes(parsedNotification)

        // Check if there was an error
        if err == nil {
            t.Errorf("ParseDeletes() error = nil; want non-nil")
        }
    })

    t.Run("UnsuccessfulParse_DeleteNotMap", func(t *testing.T) {
        // Create a parsed notification with a delete that is not a map
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                "notAMap",
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseDeletes() error = %v; want nil", err)
        }

        // Check if the deletes are empty
        if len(deletes) != 0 {
            t.Errorf("ParseDeletes() = %v; want an empty slice", deletes)
        }
    })

    t.Run("UnsuccessfulParse_NoElem", func(t *testing.T) {
        // Create a parsed notification with a delete that does not have an "elem"
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "val": "value",
                },
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseDeletes() error = %v; want nil", err)
        }

        // Check if the deletes are empty
        if len(deletes) != 0 {
            t.Errorf("ParseDeletes() = %v; want an empty slice", deletes)
        }
    })

    t.Run("UnsuccessfulParse_GetConstructedPathsError", func(t *testing.T) {
        // Create a parsed notification with a delete that has a path with an invalid "elem"
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": "notAnArrayOfMaps",
                },
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseDeletes() error = %v; want nil", err)
        }

        // Check if the deletes are empty
        if len(deletes) != 0 {
            t.Errorf("ParseDeletes() = %v; want an empty slice", deletes)
        }
    })

    t.Run("SuccessfulParse_MixOfUpdatesAndDeletes", func(t *testing.T) {
        // Create a parsed notification with a mix of updates and deletes
        parsedNotification := map[string]interface{}{
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "state"},
                            map[string]interface{}{"name": "operStatus"},
                        },
                    },
                    "val": map[string]interface{}{
                        "stringVal": "UP",
                    },
                },
            },
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "interfaces"},
                        map[string]interface{}{"name": "interface"},
                        map[string]interface{}{"name": "Ethernet1"},
                    },
                },
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseDeletes() error = %v; want nil", err)
        }

        // Check if the deletes are as expected
        expectedDeletes := []string{
            "interfaces/interface/Ethernet1",
        }
        if !reflect.DeepEqual(deletes, expectedDeletes) {
            t.Errorf("ParseDeletes() = %v; want %v", deletes, expectedDeletes)
        }
    })

    t.Run("SuccessfulParse_UpdatesOnly", func(t *testing.T) {
        // Create a parsed notification with updates only
        parsedNotification := map[string]interface{}{
            "update": []interface{}{
                map[string]interface{}{
                    "path": map[string]interface{}{
                        "elem": []interface{}{
                            map[string]interface{}{"name": "state"},
                            map[string]interface{}{"name": "operStatus"},
                        },
                    },
                    "val": map[string]interface{}{
                        "stringVal": "UP",
                    },
                },
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was an error
        if err == nil {
            t.Errorf("ParseDeletes() error = nil; want non-nil")
        }

        // Check if the deletes are empty
        if len(deletes) != 0 {
            t.Errorf("ParseDeletes() = %v; want an empty slice", deletes)
        }
    })

    t.Run("SuccessfulParse_DeletesOnly", func(t *testing.T) {
        // Create a parsed notification with deletes only
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{
                map[string]interface{}{
                    "elem": []interface{}{
                        map[string]interface{}{"name": "interfaces"},
                        map[string]interface{}{"name": "interface"},
                        map[string]interface{}{"name": "Ethernet1"},
                    },
                },
            },
        }

        // Parse the deletes
        deletes, err := ParseDeletes(parsedNotification)

        // Check if there was no error
        if err != nil {
            t.Errorf("ParseDeletes() error = %v; want nil", err)
        }

        // Check if the deletes are as expected
        expectedDeletes := []string{
            "interfaces/interface/Ethernet1",
        }
        if !reflect.DeepEqual(deletes, expectedDeletes) {
            t.Errorf("ParseDeletes() = %v; want %v", deletes, expectedDeletes)
        }
    })
}

func TestEqualPaths(t *testing.T) {
    t.Run("EqualSlices", func(t *testing.T) {
        // Create two equal slices
        paths1 := []string{"path1", "path2", "path3"}
        paths2 := []string{"path1", "path2", "path3"}

        // Check if equalPaths returns true
        if !equalPaths(paths1, paths2) {
            t.Errorf("equalPaths() = false; want true")
        }
    })

    t.Run("EqualSlicesDifferentOrder", func(t *testing.T) {
        // Create two slices with the same elements but in different orders
        paths1 := []string{"path1", "path2", "path3"}
        paths2 := []string{"path3", "path1", "path2"}

        // Check if equalPaths returns true
        if !equalPaths(paths1, paths2) {
            t.Errorf("equalPaths() = false; want true")
        }
    })

    t.Run("NotEqualSlices", func(t *testing.T) {
        // Create two not equal slices
        paths1 := []string{"path1", "path2", "path3"}
        paths2 := []string{"path4", "path5", "path6"}

        // Check if equalPaths returns false
        if equalPaths(paths1, paths2) {
            t.Errorf("equalPaths() = true; want false")
        }
    })

    t.Run("NotEqualLengths", func(t *testing.T) {
        // Create two slices with different lengths
        paths1 := []string{"path1", "path2", "path3"}
        paths2 := []string{"path1", "path2"}

        // Check if equalPaths returns false
        if equalPaths(paths1, paths2) {
            t.Errorf("equalPaths() = true; want false")
        }
    })
}

func TestCheckNotificationType(t *testing.T) {
    t.Run("UpdateNotification", func(t *testing.T) {
        // Create a parsed notification representing an update
        parsedNotification := map[string]interface{}{
            "update": []interface{}{},
        }

        // Call the function under test
        notificationType := CheckNotificationType(parsedNotification)

        // Assert that the returned notification type is "update"
        assert.Equal(t, "update", notificationType)
    })

    t.Run("DeleteNotification", func(t *testing.T) {
        // Create a parsed notification representing a delete
        parsedNotification := map[string]interface{}{
            "delete": []interface{}{},
        }

        // Call the function under test
        notificationType := CheckNotificationType(parsedNotification)

        // Assert that the returned notification type is "delete"
        assert.Equal(t, "delete", notificationType)
    })

    t.Run("UnknownNotification", func(t *testing.T) {
        // Create a parsed notification with no "update" or "delete" field
        parsedNotification := map[string]interface{}{}

        // Call the function under test
        notificationType := CheckNotificationType(parsedNotification)

        // Assert that the returned notification type is "unknown"
        assert.Equal(t, "unknown", notificationType)
    })
}

// ------------------- Integration Tests -------------------
// The following tests are integration tests that test the
// functions in this file with the actual gNMI server.
// ---------------------------------------------------------

func TestNewGNMISessionIntegration(t *testing.T) {
    // Start a gRPC server
    server := grpc.NewServer()
    ext_gnmi.RegisterGNMIServer(server, &MyGNMIServer{})
    lis, _ := net.Listen("tcp", "localhost:7464")
    go server.Serve(lis)
    defer server.Stop()

    t.Run("SuccessfulNewSession_notls", func(t *testing.T) {
        // Mock the readGNMISecurityParams function
        security := gnmiSecurityDetails{
            username: "username",
            password: "password",
            server:   lis.Addr().String(),
            useTLS:   false,
        }
        patches := gomonkey.ApplyFunc(readGNMISecurityParams, func() gnmiSecurityDetails {
            return security
        })
        defer patches.Reset()

        // Call the function under test
        session, err := NewGNMISession(nil, nil, nil)

        // Assert that there was no error and that the session is not nil
        assert.NoError(t, err)
        assert.NotNil(t, session)
    })

    t.Run("UnsuccessfulNewSession_notls", func(t *testing.T) {
        // Save the original GNMI_CONN_TIMEOUT
        originalTimeout := GNMI_CONN_TIMEOUT

        // Set GNMI_CONN_TIMEOUT to a very low value
        GNMI_CONN_TIMEOUT = 1 * time.Second

        // Mock the readGNMISecurityParams function to return an invalid server address
        patches := gomonkey.ApplyFunc(readGNMISecurityParams, func() gnmiSecurityDetails {
            return gnmiSecurityDetails{
                server: "invalidAddress",
            }
        })
        defer patches.Reset()

        // Call the function under test
        _, err := NewGNMISession(nil, nil, nil)

        // Assert that there was an error
        assert.Error(t, err)

        // Revert GNMI_CONN_TIMEOUT to its original value
        GNMI_CONN_TIMEOUT = originalTimeout
    })
}
