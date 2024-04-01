package arista_common

import (
    "encoding/json"
    "fmt"
    "sync"

    goeapi "github.com/aristanetworks/goeapi"
)

// INodeAPI is an Interface that defines the methods of goeapi.Node used in EAPIClient.
type iNodeAPI interface {
    Enable(commands []string) ([]map[string]string, error)
    ConfigWithErr(commands ...string) error
    RunCommands(commands []string, encoding string) (*goeapi.JSONRPCResponse, error)
}

// nodeWrapper is a struct that embeds *goeapi.Node and implements the iNodeAPI interface.
type nodeWrapper struct {
    *goeapi.Node
}

// IEapiConnection is an interface that has the same methods as goeapi
type iEapiConnection interface {
    Connect(transport string, host string, username string, passwd string, port int) (iNodeAPI, error)
}

// EapiConnection is a wrapper around goeapi.Connect
type eapiConnection struct{}

func (d eapiConnection) Connect(network, address, username, password string, port int) (iNodeAPI, error) {
    node, err := goeapi.Connect(network, address, username, password, port)
    if err != nil {
        return nil, err
    }
    return nodeWrapper{node}, nil
}

// EAPIClient is a client for the EAPI
type eAPIClient struct {
    node iNodeAPI
    once sync.Once
}

var (
    eAPIInstance                  *eAPIClient
    defaultEapiConnectionProvider iEapiConnection = eapiConnection{} // default connection provider
)

// SetConnectionProvider sets the connection provider to be used by the eAPIClient
func SetEAPIConnectionProvider(cp iEapiConnection) {
    defaultEapiConnectionProvider = cp
}

/*
 * Init initializes the singleton instance of eAPIClient with the given username and password.
 *
 * Parameters:
 * - username: The username to connect to the Arista device.
 * - password: The password to connect to the Arista device.
 *
 * Returns: None.
 *
 * Thread safe
 */
func EAPIInit(username, password string) {
    eAPIInstance = &eAPIClient{}
    eAPIInstance.once.Do(func() {
        initEAPI(username, password)
    })
}

// Init initializes the eAPIClient
func initEAPI(username, password string) {
    var err error
    eAPIInstance.node, err = defaultEapiConnectionProvider.Connect("socket", "localhost", username, password, goeapi.UseDefaultPortNum)
    if err != nil {
        panic(err)
    }
}

/*
 * GetInstance returns the singleton instance of EAPIClient.
 *
 * Parameters: None.
 *
 * Returns:
 * - The singleton instance of EAPIClient.
 *
 * Thread safe
 */
func GetEAPIInstance() *eAPIClient {
    if eAPIInstance == nil {
        panic("EAPIClient is not initialized, call Init first")
    }
    return eAPIInstance
}

/*
 * RunEnableCommands executes a list of commands on the Arista device and returns the result as plain text.
 *
 * Parameters:
 * - commands: The ordered list of commands to send to the device.
 *
 * This function is thread safe and must be called only once at a time per session.
 *
 * Returns:
 * - A string containing the result of the commands execution.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if there's an error while executing the commands).
 *
 * Thread safe
 */
func (client *eAPIClient) RunEnableCommands(commands []string) (string, error) {
    response, err := client.node.Enable(commands)
    if err != nil {
        return "", err
    }
    if len(response) > 0 {
        if result, ok := response[0]["result"]; ok {
            return result, nil
        }
    }
    return "", nil
}

/*
 * RunConfigCommand executes a configuration command on the Arista device.
 *
 * Parameters:
 * - commandParts: The parts of the command to send to the device. Each part is a separate string.
 *
 * Returns:
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g.,
 * if there's an error while executing the command).
 *
 * Thread safe
 */
func (client *eAPIClient) RunConfigCommand(commandParts []string) error {
    err := client.node.ConfigWithErr(commandParts...)
    if err != nil {
        return fmt.Errorf("error executing command '%v': %w", commandParts, err)
    }
    return nil
}

/*
 * RunCommandsJSON executes a list of commands on the Arista device and returns the result in JSON format.
 *
 * Parameters:
 * - commands: The ordered list of commands to send to the device.
 *
 * Returns:
 * - A string containing the JSON representation of the commands execution result.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g.,
 * if there's an error while executing the commands or converting the result to JSON).
 *
 * Note: Some commands like 'show platform fap' do not support JSON output. In such cases error "This is an unconverted command" is returned.
 * Use RunEnableCommands instead.
 *
 * Thread safe
 */
func (client *eAPIClient) RunCommandsJSON(commands []string) (string, error) {
    response, err := client.node.RunCommands(commands, "json")
    if err != nil {
        return "", err
    }

    jsonOutput, err := json.Marshal(response.Result)
    if err != nil {
        return "", err
    }

    return string(jsonOutput), nil
}
