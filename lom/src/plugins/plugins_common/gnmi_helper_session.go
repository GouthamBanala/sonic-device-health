package plugins_common

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "lom/src/lib/lomcommon"
    "strings"
    "sync"

    "github.com/openconfig/gnmi/proto/gnmi"
    ext_gnmi "github.com/openconfig/gnmi/proto/gnmi"
)

/****************************************************************************************************************************
 * Wrapper API's on the top of  gnmiServerConnector to make it easier to use
 ****************************************************************************************************************************/

/*
 * GNMISession is a wrapper around the gnmiServerConnector that provides a higher level API
 * for interacting with the gNMI server.
 * Multiple sessions can be created to interact with the same gNMI server.
 * All the active sessions to the same gNMMI server will share the same connection identified by the server address.
 */

type IGNMISession interface {
    Capabilities() (*ext_gnmi.CapabilityResponse, error)
    Get(prefix string, paths []string) (*ext_gnmi.GetResponse, error)
    Subscribe(prefix string, paths []string) error
    Unsubscribe() error
    Close() error
    Receive() (<-chan *ext_gnmi.Notification, <-chan error, error)
    Resubscribe(newPrefix string, newPaths []string) error
    IsSubscribed() bool
    Equals(other IGNMISession, comparePaths bool) bool
    ProcessGet(response *ext_gnmi.GetResponse) ([]*gnmi.Notification, error)
}

type IGNMIServerConnector interface {
    capabilities(ctx context.Context) (*ext_gnmi.CapabilityResponse, error)
    get(ctx context.Context, prefix string, paths []string) (*ext_gnmi.GetResponse, error)
    subscribe(ctx context.Context, mode ext_gnmi.SubscriptionList_Mode, prefix string, paths []string) (ext_gnmi.GNMI_SubscribeClient, error)
    subscribeStream(ctx context.Context, prefix string, paths []string) (ext_gnmi.GNMI_SubscribeClient, error)
    close() error
    Server() string
}

type GNMISession struct {
    client IGNMIServerConnector          // used to interact with the gNMI server via the gnmiServerConnector
    cancel context.CancelFunc            // cancel is used to cancel the subscription
    stream ext_gnmi.GNMI_SubscribeClient // stream is used to receive the subscription updates from the server for the current subscription
    prefix string                        // the prefix used for the current subscription
    paths  []string                      // the paths used for the current subscription
    mu     sync.Mutex
}

// Keys for reading GNMI security parameters from the config file
const (
    local_gnmi_server_username             = "LOCAL_GNMI_SERVER_USERNAME"
    local_gnmi_server_password             = "LOCAL_GNMI_SERVER_PASSWORD"
    local_gnmi_server_address              = "LOCAL_GNMI_SERVER_ADDRESS"
    local_gnmi_use_tls                     = "LOCAL_GNMI_USE_TLS"
    local_gnmi_certificate_file_path       = "LOCAL_GNMI_CERTIFICATE_FILE_PATH"
    local_gnmi_private_key_file_path       = "LOCAL_GNMI_PRIVATE_KEY_FILE_PATH"
    local_gnmi_ca_certificate_file_path    = "LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH"
    local_gnmi_validate_server_certificate = "LOCAL_GNMI_VALIDATE_SERVER_CERTIFICATE"
)

/*
* readGNMISecurityParams reads the gNMI security parameters from the configuration manager.
* It returns a gnmiSecurityDetails struct containing the parameters.
*
* The function does the following:
* - Retrieves the configuration manager instance
* - Reads the gNMI security parameters (username, password, server address, TLS usage, certificate file paths, and server certificate validation) from the configuration manager
* - Returns a gnmiSecurityDetails struct populated with the read parameters
*
* Returns:
* - A gnmiSecurityDetails struct. This struct contains the gNMI security parameters read from the configuration manager.
 */
func readGNMISecurityParams() gnmiSecurityDetails {
    configMgr := lomcommon.GetConfigMgr()

    username := configMgr.GetGlobalCfgStr(local_gnmi_server_username)
    password := configMgr.GetGlobalCfgStr(local_gnmi_server_password)
    server := configMgr.GetGlobalCfgStr(local_gnmi_server_address)
    useTLS := configMgr.GetGlobalCfgStr(local_gnmi_use_tls) == "true"
    certificateFilePath := configMgr.GetGlobalCfgStr(local_gnmi_certificate_file_path)
    privateKeyFilePath := configMgr.GetGlobalCfgStr(local_gnmi_private_key_file_path)
    caCertificateFilePath := configMgr.GetGlobalCfgStr(local_gnmi_ca_certificate_file_path)
    validateServerCertificate := configMgr.GetGlobalCfgStr(local_gnmi_validate_server_certificate) == "true"

    return gnmiSecurityDetails{
        username:                  username,
        password:                  password,
        server:                    server,
        useTLS:                    useTLS,
        certificateFilePath:       certificateFilePath,
        privateKeyFilePath:        privateKeyFilePath,
        caCertificateFilePath:     caCertificateFilePath,
        validateServerCertificate: validateServerCertificate,
    }
}

/*
* NewGNMISession creates a new GNMI session to the specified server with the specified security details.
* If the client parameter is nil, it creates a new gRPC connection.
* Blocking call
* Parameters:
* - client: An IGNMIServerConnector. This is the GNMI server connector. If this is nil, a new one will be created.
* - dialer: An igRPCDialerExt. This is the dialer for creating a new gRPC connection. If this is nil, a new one will be created.
* - clientMethod: An igNMIClientMethodsExt. This is the client method for creating a new GNMI client. If this is nil, a new one will be created.
*
  - Returns:
  - - A pointer to a GNMISession. This is the GNMI session. If the session cannot be created (e.g., if the connection cannot be established within
    the context's timeout defined by GNMI_CONN_TIMEOUT), the function will return a non-nil error and the session object may be nil.
  - - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if there's an error
    while dialing the server or if the context's deadline is exceeded).
*/
func NewGNMISession(client IGNMIServerConnector, dialer igRPCDialerExt, clientMethod igNMIClientMethodsExt) (*GNMISession, error) {
    if dialer == nil {
        dialer = &gRPCDialer{}
    }
    if clientMethod == nil {
        clientMethod = &gNMIClientMethodsExt{}
    }
    if client == nil {
        var err error
        security := readGNMISecurityParams()
        client, err = getGNMIInstance(dialer, clientMethod, security)
        if err != nil {
            return nil, err
        }
    }

    return &GNMISession{
        client: client,
    }, nil
}

/*
 * Capabilities retrieves the capabilities of the gNMI server.
 * This function is thread safe and can be called multiple times per session.
 *
 * Returns:
 * - A pointer to a gnmi.CapabilityResponse. This is the response from the server, which includes the server's capabilities.
 *   The structure of gnmi.CapabilityResponse is as follows:
 *
 *   message CapabilityResponse {
 *     repeated string supported_models = 1; // The YANG models supported by the server.
 *     repeated string supported_encodings = 2; // The encodings supported by the server.
 *     string gNMI_version = 3; // The version of the gNMI specification supported by the server.
 *   }
 *
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 */
func (s *GNMISession) Capabilities() (*ext_gnmi.CapabilityResponse, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Call the client's Capabilities method and return the response
    return s.client.capabilities(ctx)
}

/*
 * Get retrieves the specified paths from the gNMI server.
 *
 * Parameters:
 * - prefix: A string. This is the prefix used to identify the origin of the data.
 * - paths: A slice of strings. These are the paths to retrieve from the server.
 *
 * The function returns the response from the client's Get method, which includes the retrieved data and any error that occurred.
 * This function is thread safe and can be called multiple times per session.
 *
 * Returns:
 * - A pointer to a gnmi.GetResponse object. This is the response from the server, which includes the retrieved data.
 *   The structure of gnmi.GetResponse is as follows:
 *
 *   message GetResponse {
 *     repeated Notification notification = 1; // The notifications containing the retrieved data.
 *     ..... // other fields
 *   }
 *
 *   The Notification message is a collection of updates (and optionally deletes) to a set of paths in the data tree. Its structure is as follows:
 *
 *   message Notification {
 *     int64 timestamp = 1; // The timestamp associated with the data in the Update message.
 *     string prefix = 2; // The prefix used to identify the origin of the data.
 *     repeated Update update = 3; // The data updates.
 *     repeated string delete = 4; // The paths to delete.
 *     bool sync_response = 5; // Indicates that this message is the last in a SubscribeResponse message.
 *     string alias = 6; // The alias used to identify the origin of the data.
 *     Error error = 7; // The error associated with the data in the Update message.
 *   }
 *
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 */
func (s *GNMISession) Get(prefix string, paths []string) (*ext_gnmi.GetResponse, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Call the client's Get method to retrieve the paths and return the response
    return s.client.get(ctx, prefix, paths)
}

/*
 * ProcessGet processes a GetResponse from the gNMI server and returns the contained Notifications.
 *
 * Parameters:
 * - response: A pointer to an ext_gnmi.GetResponse. This is the response from the gNMI server to a Get request.
 *
 * The function checks if the response is valid and if it contains any Notifications. If the response is valid and contains Notifications,
 * the function returns these Notifications. Otherwise, it returns an error.
 *
 * Returns:
 * - A slice of pointers to gnmi.Notification. These are the Notifications contained in the response.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 */
func (s *GNMISession) ProcessGet(response *ext_gnmi.GetResponse) ([]*ext_gnmi.Notification, error) {
    // Check if the response is valid
    if response == nil {
        return nil, errors.New("response is nil")
    }

    // Check if the response contains any notifications
    if len(response.Notification) == 0 {
        return nil, errors.New("no notifications in response")
    }

    return response.Notification, nil
}

/*
 * Subscribe creates a subscription to the gNMI server with the specified prefix and paths.
 *
 * Parameters:
 * - prefix: A string. This is the prefix used to identify the origin of the data.
 * - paths: A slice of strings. These are the paths to subscribe to on the server.
 *
 * If there's an active subscription on the session, it returns an error.
 * This function must be called only once per session. If you need to subscribe again, call Unsubscribe first to cancel the current subscription.
 *
 * Returns:
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred.
 *
 */
func (s *GNMISession) Subscribe(prefix string, paths []string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // If there's an active subscription, return an error
    if s.cancel != nil {
        return errors.New("a subscription is already active")
    }

    ctx, cancel := context.WithCancel(context.Background())
    // Call the client's SubscribeStream method to create a new subscription
    stream, err := s.client.subscribeStream(ctx, prefix, paths)
    // If an error occurred, cancel the context and return the error
    if err != nil {
        cancel()
        return err
    }
    // If the subscription was successfully created, set the session fields
    s.cancel = cancel
    s.stream = stream
    s.paths = paths
    s.prefix = prefix

    return nil
}

/*
 * Unsubscribe cancels the subscription to the gNMI server.
 *
 * Parameters: None.
 *
 * Returns:
 * - An error. This is always nil, indicating that the function completed successfully.
 *
 * Thread safe
 */
func (s *GNMISession) Unsubscribe() error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // If there's an active subscription, cancel it
    if s.cancel != nil {
        s.cancel()
        // Set the cancel and stream fields to nil to indicate that there's no active subscription
        s.cancel = nil
        s.stream = nil
        s.paths = nil
        s.prefix = ""
    }
    return nil
}

/*
 * Close cancels any active subscriptions subscribed to the gNMI server in this session and closes the connection to the server.
 *
 * Parameters: None.
 *
 * If there's an active subscription on the session, it's cancelled.
 * If all active connections to the server are closed, the connection to the server is also closed.
 * This function is thread safe and must be called only once at a time per session.
 *
 * Returns:
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if there's an error while closing the connection to the server).
 *
 * Thread safe
 */
func (s *GNMISession) Close() error {
    // Cancel any active subscriptions
    err := s.Unsubscribe()
    if err != nil {
        return err
    }

    // Close the connection to the server and return any error
    return s.client.close()
}

/*
* Receive starts receiving notifications from the gNMI server for the current subscription.
*
* Parameters: None.
*
* It returns two channels: one for notifications and one for errors.
*
* Returns:
* - A receive-only channel of *gnmi.Notification. This channel returns pointers to gnmi.Notification objects.
*   Each gnmi.Notification represents a single gNMI notification, which is a collection of updates (and optionally deletes)
*   to a set of paths in the data tree.
*
* message Notification {
*   int64 timestamp = 1; // The timestamp associated with the data in the Update message.
*   string prefix = 2; // The prefix used to identify the origin of the data.
*   repeated Update update = 3; // The data updates.
*   repeated string delete = 4; // The paths to delete.
*   bool sync_response = 5; // Indicates that this message is the last in a SubscribeResponse message.
*   string alias = 6; // The alias used to identify the origin of the data.
*   Error error = 7; // The error associated with the data in the Update message.
* }
*
* message Update {
*   string path = 1; // The path to the data.
*   Value value = 2; // The updated value.
*   int64 timestamp = 3; // The timestamp associated with the data.
*  }

*  message Value {
*     oneof value {
*         string string_val = 1;
*         int64 int_val = 2;
*         uint64 uint_val = 3;
*         bool bool_val = 4;
*         bytes bytes_val = 5;
*         float float_val = 6;
*         double double_val = 7;
*        }
*  }
* - A receive-only channel of error. This channel returns error objects. If an error occurs while receiving subscriptions,
*   it will be sent on this channel. This channel is closed before the notifications channel, giving the caller a chance to read the error
*   before the notifications channel is closed.
*
* - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if there's no active subscription).
*
* This function is thread safe and must be called after Subscribe and before Unsubscribe.
* It must be called only once at a time per session.
 */
func (s *GNMISession) Receive() (<-chan *ext_gnmi.Notification, <-chan error, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // If there's no active subscription, return an error
    if s.stream == nil {
        return nil, nil, errors.New("no active subscription")
    }

    // Create a channel for notifications
    notificationsCh := make(chan *ext_gnmi.Notification, 1)
    // Create a buffered channel for errors
    errCh := make(chan error, 1)

    // Start a goroutine to receive notifications from the server
    go func() {
        // Call ReceiveSubscriptions to start receiving notifications
        err := receiveSubscriptions(s.stream, notificationsCh)
        // If an error occurs, send it to the error channel
        if err != nil {
            errCh <- err
        }
        // Close the error channel when done
        close(errCh)
    }()

    // Start a separate goroutine to close the notifications channel
    // only after the error channel has been closed
    go func() {
        // Wait for the error channel to be closed
        for range errCh {
        }
        // Then close the notifications channel
        close(notificationsCh)
    }()

    // Return the readonly channels to the caller
    return notificationsCh, errCh, nil
}

/*
 * Resubscribe cancels the current subscription and creates a new subscription with the specified prefix and paths.
 *
 * Parameters:
 * - newPrefix: A string. This is the prefix used to identify the origin of the data for the new subscription.
 * - newPaths: A slice of strings. These are the paths to subscribe to on the server for the new subscription.
 *
 * If there's an active subscription on the session, it's cancelled before the new subscription is created.
 * This function is thread safe, but it should be called concurrently for the same session once.
 *
 * Returns:
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if there's an error while unsubscribing or subscribing).
 *
 * Thread safe
 */
func (s *GNMISession) Resubscribe(newPrefix string, newPaths []string) error {
    s.Unsubscribe()
    return s.Subscribe(newPrefix, newPaths)
}

/*
 * IsSubscribed checks whether the session is currently subscribed to any paths on the gNMI server.
 *
 * Parameters: None.
 *
 * Returns:
 * - A bool. This is true if the session is currently subscribed to any paths and false otherwise.
 *
 * Thread safe
 */
func (s *GNMISession) IsSubscribed() bool {
    s.mu.Lock()
    defer s.mu.Unlock()

    // If the cancel field is not nil, there's an active subscription, so return true
    // If the cancel field is nil, there's no active subscription, so return false
    return s.cancel != nil
}

/*
 * Equals compares this session with another session.
 *
 * Parameters:
 * - other: An IGNMISession. This is the other session to compare with.
 * - comparePaths: A bool. If this is true, the function also compares the subscription paths.
 *
 * Returns:
 * - A bool. This is true if the sessions are equal and false otherwise.
 *
 * Thread safe
 */
func (s *GNMISession) Equals(other IGNMISession, comparePaths bool) bool {
    s.mu.Lock()
    defer s.mu.Unlock()

    otherSession, ok := other.(*GNMISession)
    if !ok {
        return false
    }

    // Lock the other session to ensure thread safety
    otherSession.mu.Lock()
    defer otherSession.mu.Unlock()

    // Compare the server addresses
    if s.client.Server() != otherSession.client.Server() {
        return false
    }

    // Compare the subscription paths
    if comparePaths {
        if !equalPaths(s.paths, otherSession.paths) {
            return false
        }
    }

    return true
}

/*
 * ParseNotification converts a gNMI Notification or an interface{} into a map[string]interface{}.
 *
 * Parameters:
 * - notification: Either a pointer to a ext_gnmi.Notification or an interface{}. This is the gNMI Notification to be parsed.
 *
 * Returns:
 * - A map[string]interface{}. This map represents the parsed gNMI Notification. The keys of the map are the fields of the Notification, and the values are the values of those fields.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if the Notification cannot be marshaled into JSON or the JSON cannot be unmarshaled into a map).
 *
 * For example, a gNMI Notification object like this:
 * &ext_gnmi.Notification{
 *     Timestamp: 1234567890,
 *     Prefix: &ext_gnmi.Path{
 *         Elem: []*ext_gnmi.PathElem{
 *             {Name: "interfaces"},
 *             {Name: "interface"},
 *         },
 *     },
 *     Update: []*ext_gnmi.Update{
 *         {
 *             Path: &ext_gnmi.Path{
 *                 Elem: []*ext_gnmi.PathElem{
 *                     {Name: "Ethernet0"},
 *                     {Name: "state"},
 *                     {Name: "operStatus"},
 *                 },
 *             },
 *             Val: &ext_gnmi.TypedValue{
 *                 Value: &ext_gnmi.TypedValue_StringVal{
 *                     StringVal: "UP",
 *                 },
 *             },
 *         },
 *         {
 *             Path: &ext_gnmi.Path{
 *                 Elem: []*ext_gnmi.PathElem{
 *                     {Name: "Ethernet1"},
 *                     {Name: "state"},
 *                     {Name: "operStatus"},
 *                 },
 *             },
 *             Val: &ext_gnmi.TypedValue{
 *                 Value: &ext_gnmi.TypedValue_StringVal{
 *                     StringVal: "DOWN",
 *                 },
 *             },
 *         },
 *     },
 *     Delete: []*ext_gnmi.Path{
 *         {
 *             Elem: []*ext_gnmi.PathElem{
 *                 {Name: "interfaces"},
 *                 {Name: "interface"},
 *                 {Name: "Ethernet2"},
 *             },
 *         },
 *         {
 *             Elem: []*ext_gnmi.PathElem{
 *                 {Name: "interfaces"},
 *                 {Name: "interface"},
 *                 {Name: "Ethernet3"},
 *             },
 *         },
 *     },
 * }
 *
 * In gNMI(gRPC), this would be represented as:
 * notification: {
 *     timestamp: 1234567890,
 *     prefix: {
 *         elem: [
 *             {name: "interfaces"},
 *             {name: "interface"},
 *             {name: "Ethernet0"}
 *         ]
 *     },
 *     update: [
 *         {
 *             path: {
 *                 elem: [
 *                     {name: "state"},
 *                     {name: "operStatus"}
 *                 ]
 *             },
 *             val: {
 *                 stringVal: "UP"
 *             }
 *         },
 *         {
 *             path: {
 *                 elem: [
 *                     {name: "state"},
 *                     {name: "adminStatus"}
 *                 ]
 *             },
 *             val: {
 *                 stringVal: "DOWN"
 *             }
 *         }
 *     ],
 *     delete: [
 *         {
 *             elem: [
 *                 {name: "interfaces"},
 *                 {name: "interface"},
 *                 {name: "Ethernet1"}
 *             ]
 *         },
 *         {
 *             elem: [
 *                 {name: "interfaces"},
 *                 {name: "interface"},
 *                 {name: "Ethernet2"}
 *             ]
 *         }
 *     ]
 * }
 *
 *
 * will be converted into a map like this:
 * map[string]interface{}{
 *     "timestamp": 1234567890,
 *     "prefix": map[string]interface{}{
 *         "elem": []interface{}{
 *             map[string]interface{}{"name": "interfaces"},
 *             map[string]interface{}{"name": "interface"},
 *             map[string]interface{}{"name": "Ethernet0"},
 *         },
 *     },
 *     "update": []interface{}{
 *         map[string]interface{}{
 *             "path": map[string]interface{}{
 *                 "elem": []interface{}{
 *                     map[string]interface{}{"name": "state"},
 *                     map[string]interface{}{"name": "operStatus"},
 *                 },
 *             },
 *              "val": map[string]interface{}{
 *                 "stringVal": "UP",
 *             },
 *         },
 *         map[string]interface{}{
 *             "path": map[string]interface{}{
 *                 "elem": []interface{}{
 *                     map[string]interface{}{"name": "state"},
 *                     map[string]interface{}{"name": "adminStatus"},
 *                 },
 *             },
 *              "val": map[string]interface{}{
 *                 "stringVal": "DOWN",
 *             },
 *         },
 *     },
 *     "delete": []interface{}{
 *         map[string]interface{}{
 *             "elem": []interface{}{
 *                 map[string]interface{}{"name": "interfaces"},
 *                 map[string]interface{}{"name": "interface"},
 *                 map[string]interface{}{"name": "Ethernet1"},
 *             },
 *         },
 *         map[string]interface{}{
 *             "elem": []interface{}{
 *                 map[string]interface{}{"name": "interfaces"},
 *                 map[string]interface{}{"name": "interface"},
 *                 map[string]interface{}{"name": "Ethernet2"},
 *             },
 *         },
 *     },
 * }
 * and nil.
 * If the Notification cannot be marshaled into JSON or the JSON cannot be unmarshaled into a map, it will return nil and an error.
 */
func ParseNotification(notification interface{}) (map[string]interface{}, error) {
    var gnmiNotification *ext_gnmi.Notification
    var ok bool

    // Perform a type switch to handle either *ext_gnmi.Notification or interface{}
    switch v := notification.(type) {
    case *ext_gnmi.Notification:
        gnmiNotification = v
    case interface{}:
        gnmiNotification, ok = v.(*ext_gnmi.Notification)
        if !ok {
            return nil, fmt.Errorf("invalid type for notification, expected *ext_gnmi.Notification")
        }
    default:
        return nil, fmt.Errorf("invalid type for notification, expected *ext_gnmi.Notification or interface{}")
    }

    if gnmiNotification == nil {
        return nil, fmt.Errorf("notification is nil")
    }

    // Marshal the gnmiNotification into a JSON string
    bytes, err := json.Marshal(gnmiNotification)

    if err != nil {
        return nil, fmt.Errorf("failed to parse notification: %w", err)
    }

    // Unmarshal the JSON string into a map[string]interface{}
    // Note: During this process, all numbers in the gnmiNotification are converted to float64
    // because that's the default behavior of Go's encoding/json package when unmarshalling JSON numbers.
    // If you need to preserve the integer types, you would need to post-process the map to convert float64 to int or int64 where appropriate.
    // Refer to https://golang.org/pkg/encoding/json/#Unmarshal for more details.
    var result map[string]interface{}
    err = json.Unmarshal(bytes, &result)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
    }
    return result, nil
}

/*
* GetTimestamp extracts the timestamp from a parsed gNMI Notification.
*
* Parameters:
* - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification.
*
* Returns:
* - An int64. This is the timestamp extracted from the parsed gNMI Notification. The timestamp is the number of nanoseconds
*   since the Unix epoch (January 1, 1970).
* - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if the timestamp is not
*   found in the parsed notification or if it's not an int64).
*
  - In a gNMI Notification, the timestamp is represented as a field named "timestamp". This field contains the number of nanoseconds
    since the Unix epoch (January 1, 1970).

*
* For example, if the parsedNotification map contains {"timestamp": 1234567890}, it will return 1234567890 and nil.
* If the parsedNotification map does not contain a "timestamp" key, or if the value of the "timestamp" key is not an int64, it will
* return 0 and an error.
*/
func GetTimestamp(parsedNotification map[string]interface{}) (int64, error) {
    timestamp, ok := parsedNotification["timestamp"]
    if !ok {
        return 0, fmt.Errorf("timestamp not found in parsed notification")
    }
    return int64(timestamp.(float64)), nil
}

/*
 * GetConstructedPaths constructs paths from a "path" map.
 *
 * Parameters:
 * - pathMap: A map[string]interface{}. This represents a path map from a parsed gNMI Notification.
 *
 * Returns:
 * - A slice of strings. Each string in the slice is a part of the path extracted from the path map.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if the "elem" key is not
 *  found in the path map, if an element is not a map, or if the "name" key is not found in an element map).
 *
 * In a gNMI Notification, the path is represented as a field named "path". This field contains a map with an "elem" key, which is a
 * slice of maps. Each map in the slice represents an element of the path and contains a "name" key with the name of the element.
 *
 * For example, from a path map like this:
 * map[string]interface{}{
 *     "elem": []interface{}{
 *         map[string]interface{}{"name": "interfaces"},
 *         map[string]interface{}{"name": "interface"},
 *         map[string]interface{}{"name": "Ethernet0"},
 *     },
 * }
 * it will return []string{"interfaces", "interface", "Ethernet0"} and nil.
 * If the path map does not contain an "elem" key, or if an element is not a map, or if the "name" key is not found in an element map,
 * it will return nil and an error.
 */
func GetConstructedPaths(pathMap map[string]interface{}) ([]string, error) {
    elems, ok := pathMap["elem"].([]interface{})
    if !ok {
        return nil, fmt.Errorf("element not found in path map")
    }
    paths := make([]string, len(elems))
    for i, elem := range elems {
        elemMap, ok := elem.(map[string]interface{})
        if !ok {
            return nil, fmt.Errorf("element is not a map")
        }
        name, ok := elemMap["name"].(string)
        if !ok {
            return nil, fmt.Errorf("name not found in element map")
        }
        paths[i] = name
    }
    return paths, nil
}

/*
 * GetPrefix extracts the prefix from a parsed GNMI notification.
 *
 * Parameters:
 * - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification.
 *
 * Returns:
 * - A slice of strings. Each string in the slice is a part of the prefix extracted from the prefix map.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if the "prefix" key is
 * not found in the parsed notification, if the prefix is not a map, or if the "elem" key is not found in the prefix map).
 *
 * In a gNMI Notification, the prefix is represented as a field named "prefix". This field contains a map with an "elem" key, which
 * is a slice of maps. Each map in the slice represents an element of the prefix and contains a "name" key with the name of the element.
 *
 * The function tries to extract a prefix map from the parsedNotification. If it succeeds, it constructs the paths using the
 * GetConstructedPaths helper function and returns them. If it fails to find a prefix map, it returns an error.
 */
func GetPrefix(parsedNotification map[string]interface{}) ([]string, error) {
    prefixMap, ok := parsedNotification["prefix"].(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("prefix not found in parsed notification")
    }
    return GetConstructedPaths(prefixMap)
}

/*
 * For example, from a parsedNotification map like this:
 * map[string]interface{}{
 *     "update": []interface{}{
 *         map[string]interface{}{
 *             "path": map[string]interface{}{
 *                 "elem": []interface{}{
 *                     map[string]interface{}{"name": "state"},
 *                     map[string]interface{}{"name": "operStatus"},
 *                 },
 *             },
 *             "val": map[string]interface{}{
 *                 "stringVal": "UP",
 *             },
 *         },
 *         map[string]interface{}{
 *             "path": map[string]interface{}{
 *                 "elem": []interface{}{
 *                     map[string]interface{}{"name": "state"},
 *                     map[string]interface{}{"name": "adminStatus"},
 *                 },
 *             },
 *             "val": map[string]interface{}{
 *                 "myVal": "DOWN",
 *             },
 *         },
 *     },
 * }
 * it will return a map like this:
 * map[string]interface{}{
 *     "state/operStatus": map[string]interface{}{
 *         "stringVal": "UP",
 *     },
 *     "state/adminStatus": map[string]interface{}{
 *         "myVal": "DOWN",
 *     },
 * }
 * and nil.
 */
func ParseUpdates(parsedNotification map[string]interface{}) (map[string]interface{}, error) {
    updates, ok := parsedNotification["update"].([]interface{})
    if !ok {
        return nil, fmt.Errorf("update not found in parsed notification")
    }
    parsedUpdates := make(map[string]interface{})
    for _, update := range updates {
        updateMap, ok := update.(map[string]interface{})
        if !ok {
            continue
        }
        path, ok := updateMap["path"].(map[string]interface{})
        if !ok {
            continue
        }
        key, err := GetConstructedPaths(path)
        if err != nil {
            continue
        }
        val, ok := updateMap["val"]
        if ok {
            parsedUpdates[strings.Join(key, "/")] = val
        }
    }
    return parsedUpdates, nil
}

/*
 * ParseDeletes extracts the delete paths from a parsed gNMI Notification.
 *
 * Parameters:
 * - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification.
 *
 * Returns:
 * - A slice of strings. Each string in the slice is a delete path extracted from the parsed gNMI Notification.
 * - An error. This is nil if the function completed successfully and non-nil if an error occurred (e.g., if the "delete" key is not
 * found in the parsed notification, or if a delete path is not a map).
 *
 * In a gNMI Notification, the delete paths are represented as a field named "delete". This field contains a slice of maps. Each map in
 * the slice represents a delete path.
 *
 * For example, from a parsedNotification map like this:
 * map[string]interface{}{
 *     "delete": []interface{}{
 *         map[string]interface{}{
 *             "elem": []interface{}{
 *                 map[string]interface{}{"name": "interfaces"},
 *                 map[string]interface{}{"name": "interface"},
 *                 map[string]interface{}{"name": "Ethernet1"},
 *             },
 *         },
 *         map[string]interface{}{
 *             "elem": []interface{}{
 *                 map[string]interface{}{"name": "interfaces"},
 *                 map[string]interface{}{"name": "interface"},
 *                 map[string]interface{}{"name": "Ethernet2"},
 *             },
 *         },
 *     },
 * }
 * it will return a slice like this:
 * []string{
 *     "interfaces/interface/Ethernet1",
 *     "interfaces/interface/Ethernet2",
 * }
 * and nil.
 * If the parsedNotification map does not contain a "delete" key, or if a delete path is not a map, it will return nil and an error.
 */
func ParseDeletes(parsedNotification map[string]interface{}) ([]string, error) {
    deletes, ok := parsedNotification["delete"].([]interface{})
    if !ok {
        return nil, fmt.Errorf("delete not found in parsed notification")
    }
    var parsedDeletes []string
    for _, delete := range deletes {
        deleteMap, ok := delete.(map[string]interface{})
        if !ok {
            continue
        }
        key, err := GetConstructedPaths(deleteMap)
        if err != nil {
            continue
        }
        parsedDelete := strings.Join(key, "/")
        parsedDeletes = append(parsedDeletes, parsedDelete)
    }
    return parsedDeletes, nil
}

/*
 * CheckNotificationType determines whether a parsed gNMI Notification is an update or a delete.
 *
 * Parameters:
 * - parsedNotification: A map[string]interface{}. This represents a parsed gNMI Notification.
 *
 * Returns:
 * - A string indicating the type of the notification ("update", "delete", or "unknown").
 */
func CheckNotificationType(parsedNotification map[string]interface{}) string {
    if _, ok := parsedNotification["update"].([]interface{}); ok {
        return "update"
    }
    if _, ok := parsedNotification["delete"].([]interface{}); ok {
        return "delete"
    }
    return "unknown"
}

/*
 * equalPaths compares two slices of paths.
 *
 * Parameters:
 * - paths1: A slice of strings. This is the first set of paths to compare.
 * - paths2: A slice of strings. This is the second set of paths to compare.
 *
 * Returns:
 * - A bool. This is true if the slices contain the same paths (in any order) and false otherwise.
 */

func equalPaths(paths1, paths2 []string) bool {
    // If the lengths of the slices are not equal, return false
    if len(paths1) != len(paths2) {
        return false
    }

    // Create a map to count the occurrences of each path in the first slice
    count := make(map[string]int, len(paths1))
    for _, path := range paths1 {
        count[path]++
    }

    // Iterate over the second slice, decrementing the count for each path in the map
    for _, path := range paths2 {
        count[path]--
        // If the count for any path becomes negative, return false
        if count[path] < 0 {
            return false
        }
    }

    return true
}
