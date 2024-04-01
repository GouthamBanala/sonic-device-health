package arista_common

import (
    "encoding/json"
    "errors"
    "testing"

    "github.com/aristanetworks/goeapi"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

// MockNodeAPI is a mock implementation of iNodeAPI Interface
type MockNodeAPI struct {
    mock.Mock
    goeapi.Node
}

func (m *MockNodeAPI) Enable(commands []string) ([]map[string]string, error) {
    args := m.Called(commands)
    return args.Get(0).([]map[string]string), args.Error(1)
}

func (m *MockNodeAPI) ConfigWithErr(commands ...string) error {
    args := m.Called(commands)
    return args.Error(0)
}

func (m *MockNodeAPI) RunCommands(commands []string, encoding string) (*goeapi.JSONRPCResponse, error) {
    args := m.Called(commands, encoding)
    return args.Get(0).(*goeapi.JSONRPCResponse), args.Error(1)
}

// MockEapiConnection is a mock of iEapiConnection interface
type MockEapiConnection struct {
    mock.Mock
}

func (m *MockEapiConnection) Connect(network, address, username, password string, port int) (iNodeAPI, error) {
    args := m.Called(network, address, username, password, port)
    return args.Get(0).(iNodeAPI), args.Error(1)
}

// TestEAPIClient_RunEnableCommands: Tests the RunEnableCommands method with a valid command.
func TestEAPIClient_RunEnableCommands(t *testing.T) {
    mockNode := new(MockNodeAPI)
    mockNode.On("Enable", mock.Anything).Return([]map[string]string{{"result": "output"}}, nil)

    client := &eAPIClient{node: mockNode}
    output, err := client.RunEnableCommands([]string{"show version"})

    mockNode.AssertExpectations(t)
    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }
    if output != "output" {
        t.Errorf("Expected 'output', got %s", output)
    }
}

// TestEAPIClient_RunConfigCommand: Tests the RunConfigCommand method with a valid command.
func TestEAPIClient_RunConfigCommand(t *testing.T) {
    mockNode := new(MockNodeAPI)
    mockNode.On("ConfigWithErr", mock.Anything).Return(nil)

    client := &eAPIClient{node: mockNode}
    err := client.RunConfigCommand([]string{"interface", "Ethernet1", "description", "Test"})

    mockNode.AssertExpectations(t)
    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }
}

// TestEAPIClient_RunCommandsJSON: Tests the RunCommandsJSON method with a valid command.
func TestEAPIClient_RunCommandsJSON(t *testing.T) {
    mockNode := new(MockNodeAPI)
    mockNode.On("RunCommands", mock.Anything, "json").Return(&goeapi.JSONRPCResponse{Result: []map[string]interface{}{{"output": "output"}}}, nil)

    client := &eAPIClient{node: mockNode}
    output, err := client.RunCommandsJSON([]string{"show interfaces"})

    mockNode.AssertExpectations(t)
    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }

    var result []map[string]interface{}
    err = json.Unmarshal([]byte(output), &result)
    if err != nil {
        t.Errorf("Failed to unmarshal output: %v", err)
    }

    if result[0]["output"] != "output" {
        t.Errorf("Expected 'output', got %s", result[0]["output"])
    }
}

// TestEAPIClient_GetInstance: Tests getting the singleton instance of EAPIClient.
func TestEAPIClient_GetInstance(t *testing.T) {
    // Test getting the singleton instance of EAPIClient
    username := "test"
    password := "test"

    // Create a mock EapiConnection
    mockEapiConnection := new(MockEapiConnection)

    // Create a mock NodeAPI
    mockNode := &MockNodeAPI{}

    // Set up expectation for the Connect() call
    mockEapiConnection.On("Connect", "socket", "localhost", username, password, goeapi.UseDefaultPortNum).Return(mockNode, nil)

    // Set the connection provider
    SetEAPIConnectionProvider(mockEapiConnection)

    // Call Init function
    EAPIInit(username, password)

    // Get the instance
    client1 := GetEAPIInstance()

    // Get the instance again
    client2 := GetEAPIInstance()

    // Check that the two instances are the same
    assert.Equal(t, client1, client2)

    // Assert that the expectation was met
    mockEapiConnection.AssertExpectations(t)
}

// TestEAPIClient_RunEnableCommands_EmptyCommands: Tests the RunEnableCommands method with an empty command list.
func TestEAPIClient_RunEnableCommands_EmptyCommands(t *testing.T) {
    mockNode := new(MockNodeAPI)
    mockNode.On("Enable", []string{}).Return([]map[string]string{}, errors.New("no commands provided"))

    client := &eAPIClient{node: mockNode}
    output, err := client.RunEnableCommands([]string{})

    mockNode.AssertExpectations(t)
    assert.Error(t, err)
    assert.Empty(t, output)
}

// TestEAPIClient_RunConfigCommand_EmptyCommands: Tests the RunConfigCommand method with an empty command list.
func TestEAPIClient_RunConfigCommand_EmptyCommands(t *testing.T) {
    mockNode := new(MockNodeAPI)
    mockNode.On("ConfigWithErr", []string{}).Return(errors.New("no commands provided"))

    client := &eAPIClient{node: mockNode}
    err := client.RunConfigCommand([]string{})

    mockNode.AssertExpectations(t)
    assert.Error(t, err)
}

// TestEAPIClient_RunCommandsJSON_EmptyCommands: Tests the RunCommandsJSON method with an empty command list.
func TestEAPIClient_RunCommandsJSON_EmptyCommands(t *testing.T) {
    mockNode := new(MockNodeAPI)
    mockNode.On("RunCommands", []string{}, "json").Return(&goeapi.JSONRPCResponse{}, errors.New("no commands provided"))

    client := &eAPIClient{node: mockNode}
    output, err := client.RunCommandsJSON([]string{})

    mockNode.AssertExpectations(t)
    assert.Error(t, err)
    assert.Empty(t, output)
}

// TestEAPIClient_GetInstance_NotInitialized: Tests getting the instance of EAPIClient when it's not initialized.
func TestEAPIClient_GetInstance_NotInitialized(t *testing.T) {
    // Reset the instance before the test
    eAPIInstance = nil

    // Try to get the instance
    assert.Panics(t, func() { GetEAPIInstance() }, "The code did not panic")
}

// TestEapiConnection_Connect tests the Connect method of the eapiConnection struct.
// It asserts that no error is returned when connecting and that the returned node is of the correct type.
func TestEapiConnection_Connect(t *testing.T) {
    // Create an instance of eapiConnection
    conn := eapiConnection{}

    // Call the Connect method(No real call, it uses Unix Sockets)
    node, err := conn.Connect("socket", "localhost", "username", "password", goeapi.UseDefaultPortNum)

    assert.NoError(t, err)

    _, ok := node.(nodeWrapper)
    assert.True(t, ok)
}

// TestEapiConnection_Connect_Wrongsocket tests the Connect method of the eapiConnection struct with a wrong socket.
// It asserts that an error is returned when connecting with a wrong socket and that the returned node is nil.
func TestEapiConnection_Connect_Wrongsocket(t *testing.T) {
    // Create an instance of eapiConnection
    conn := eapiConnection{}

    // Call the Connect method(No real call, it uses Unix Sockets)
    node, err := conn.Connect("socket_wrong", "localhost", "username", "password", goeapi.UseDefaultPortNum)

    assert.Error(t, err)
    assert.Nil(t, node)
}

// TestEAPIClient_RunEnableCommands_EmptyResponse tests the RunEnableCommands method of the eAPIClient struct with an empty response.
// It asserts that no error is returned and that an empty string is returned when the response from the Enable command is empty.
func TestEAPIClient_RunEnableCommands_EmptyResponse(t *testing.T) {
    // Create a mock NodeAPI
    mockNodeAPI := new(MockNodeAPI)

    // Set up expectation for the Enable() call to return an empty response
    mockNodeAPI.On("Enable", []string{"command"}).Return([]map[string]string{}, nil)

    // Create an instance of eAPIClient with the mock NodeAPI
    client := &eAPIClient{node: mockNodeAPI}

    // Call the RunEnableCommands method
    result, err := client.RunEnableCommands([]string{"command"})

    assert.NoError(t, err)
    assert.Equal(t, "", result)
    mockNodeAPI.AssertExpectations(t)
}
