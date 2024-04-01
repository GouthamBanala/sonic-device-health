/*
 * gNMI Server with TLS Security
 *
 * This file implements a simple gNMI (gRPC Network Management Interface) server for testing purposes with added TLS security.
 * The server supports the gNMI Subscribe method, which allows a client to subscribe to updates and deletes
 * for a specific path in the data tree. The server stores samples of data internally and can push these
 * samples to the client when they connect and subscribe to the correct path.
 *
 * The server also supports the gNMI Set and Capabilities methods, but these are not currently implemented.
 *
 * The server is started by calling the Start method, which starts a gRPC server on a specified port and registers
 * the gNMI server with it. The server runs in a separate goroutine, so the Start method returns immediately.
 * The server can be stopped by calling the Stop method, which stops the gRPC server and waits for all
 * goroutines to finish.
 *
 * The server's internal data can be updated by calling the UpdateDB method, which sets a sample in the
 * server's internal storage and sends it to the client if one is connected. The DeleteDB method deletes a
 * sample from the server's internal storage and sends a delete notification to the client if one is connected.
 *
 * The server_main function starts the server, sets some samples, and waits for the user to stop the server.
 * It demonstrates how to use the server.
 *
 * The server uses TLS security parameters such as the CA certificate, server certificate, and server key to
 * establish a secure connection with the gNMI client. This is optional.
 *
 * To use this file, you can run the main function, which starts the server and sets some initial data.
 * You can then connect a gNMI client to the server and subscribe to updates and deletes for the path
 * /Smash/hardware/counter/internalDrop/SandCounters/internalDrop. The client will receive the initial data
 * and any subsequent updates or deletes.
 *
 * Currently limited to one client at a time.
 */

package arista_common

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "io/ioutil"
    "net"
    "strconv"
    "strings"
    "sync"
    "time"

    "lom/src/lib/lomcommon"

    "github.com/openconfig/gnmi/proto/gnmi"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

const (
    // port is the port that the gNMI server listens on.
    serverAddressDefault = ":50051"
)

// GNMITestServer represents a gNMI server for testing.
type GNMITestServer struct {
    gnmi.UnimplementedGNMIServer
    srv     *grpc.Server
    samples map[string]map[string]interface{}
    wg      sync.WaitGroup
    stream  gnmi.GNMI_SubscribeServer
    lis     net.Listener // Listener for the gNMI server
}

// NewGNMITestServer creates a new GNMITestServer.
func NewGNMITestServer() *GNMITestServer {
    return &GNMITestServer{
        samples: make(map[string]map[string]interface{}),
    }
}

func (s *GNMITestServer) Start(serverAddress, certFile, keyFile, caCertFile string) error {
    if serverAddress == "" {
        serverAddress = serverAddressDefault
    }

    lomcommon.LogInfo("Test GNMI Server : Starting server on port %s, certFile: %s, keyFile: %s, caCertFile: %s", serverAddress, certFile, keyFile, caCertFile)

    var err error
    s.lis, err = net.Listen("tcp", serverAddress)
    if err != nil {
        lomcommon.LogInfo("Test GNMI Server : Failed to listen: %v", err)
        return err
    }

    if certFile != "" && keyFile != "" {
        // Load the server's certificate and private key
        cert, err := tls.LoadX509KeyPair(certFile, keyFile)
        if err != nil {
            lomcommon.LogInfo("Test GNMI Server : Failed to load server key pair: %v", err)
            return err
        }

        // Load the CA's certificate
        caCert, err := ioutil.ReadFile(caCertFile)
        if err != nil {
            lomcommon.LogInfo("Test GNMI Server : Failed to read CA certificate: %v", err)
            return err
        }

        // Create a certificate pool from the CA's certificate
        caCertPool := x509.NewCertPool()
        caCertPool.AppendCertsFromPEM(caCert)

        // Create the TLS credentials for the server
        creds := credentials.NewTLS(&tls.Config{
            Certificates: []tls.Certificate{cert},
            ClientCAs:    caCertPool,
            ClientAuth:   tls.RequireAndVerifyClientCert,
        })

        s.srv = grpc.NewServer(grpc.Creds(creds))
    } else {
        s.srv = grpc.NewServer()
    }

    gnmi.RegisterGNMIServer(s.srv, s)

    started := make(chan struct{})
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        close(started) // Signal that the goroutine has started
        if err := s.srv.Serve(s.lis); err != nil {
            lomcommon.LogInfo("Test GNMI Server : Failed to serve: %v", err)
        }
    }()
    <-started // Wait for the goroutine to start

    lomcommon.LogInfo("Test GNMI Server : Server started on port %s, certFile: %s, keyFile: %s, caCertFile: %s", serverAddress, certFile, keyFile, caCertFile)
    return nil
}

// Stop stops the gNMI server.
func (s *GNMITestServer) Stop() {
    s.samples = make(map[string]map[string]interface{})
    s.srv.Stop()
    s.lis.Close() // force closew ports in use
    s.wg.Wait()
    lomcommon.LogInfo("Test GNMI Server : Server stopped")
}

// ResponseData represents the data to be sent in a SubscribeResponse.
type ResponseData struct {
    Timestamp uint64
    Updates   []*gnmi.Update
}

// sample data resembling the output from gnmi path  /Smash/hardware/counter/internalDrop/SandCounters/internalDrop
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

// sample data resembling the output from gnmi path  /Smash/hardware/counter/internalDrop/SandCounters/internalDrop
var sample_2 = map[string]interface{}{
    "key_details": "1_fap_1_65535", //chipId_chipType_CounterId_offset
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
        "chipId":                    "1",
        "chipType":                  "fap",
        "counterId":                 "1",
        "offset":                    "65535",
        "delta3":                    "4294967295",
        "delta5":                    "4294967295",
        "eventCount":                "1",
        "thresholdEventCount":       "0",
    },
}

// byteArrayToString converts a byte array to a string.
func byteArrayToString(b []byte) string {
    var builder strings.Builder
    builder.WriteByte('[')
    for i, v := range b {
        if i > 0 {
            builder.WriteByte(',')
        }
        builder.WriteString(strconv.Itoa(int(v)))
    }
    builder.WriteByte(']')
    return builder.String()
}

// generateResponse generates a SubscribeResponse from the given data.
func generateResponse(sampleDataArray []map[string]interface{}) *gnmi.SubscribeResponse {
    var updates []*gnmi.Update
    var timestamp int64
    for _, sampleData := range sampleDataArray {

        // Extract values from sampleData
        keyDetails := sampleData["key_details"].(string)
        timestampStr := sampleData["Timestamp"].(string)
        var err error
        timestamp, err = strconv.ParseInt(timestampStr, 10, 64)
        if err != nil {
            lomcommon.LogError("Failed to convert string to int64: %v", err)
            return nil
        }

        chipName := sampleData["Updates"].(map[string]interface{})["chipName"].(string)
        chipNameBytes := []byte(chipName)
        chipNameVal := byteArrayToString(chipNameBytes)
        //fmt.LogInfo("chipNameVal: %s\n", chipNameVal)

        delta2Val := sampleData["Updates"].(map[string]interface{})["delta2"].(string)
        initialThresholdEventTimeVal := sampleData["Updates"].(map[string]interface{})["initialThresholdEventTime"].(string)
        lastSyslogTimeVal := sampleData["Updates"].(map[string]interface{})["lastSyslogTime"].(string)
        initialEventTimeVal := sampleData["Updates"].(map[string]interface{})["initialEventTime"].(string)
        lastEventTimeVal := sampleData["Updates"].(map[string]interface{})["lastEventTime"].(string)
        lastThresholdEventTimeVal := sampleData["Updates"].(map[string]interface{})["lastThresholdEventTime"].(string)

        counterName := sampleData["Updates"].(map[string]interface{})["counterName"].(string)
        counterNameBytes := []byte(counterName)
        counterNameVal := byteArrayToString(counterNameBytes)

        dropCountVal := sampleData["Updates"].(map[string]interface{})["dropCount"].(string)
        delta1Val := sampleData["Updates"].(map[string]interface{})["delta1"].(string)
        delta4Val := sampleData["Updates"].(map[string]interface{})["delta4"].(string)
        chipIdVal := sampleData["Updates"].(map[string]interface{})["chipId"].(string)
        chipTypeVal := sampleData["Updates"].(map[string]interface{})["chipType"].(string)
        counterIdVal := sampleData["Updates"].(map[string]interface{})["counterId"].(string)
        offsetVal := sampleData["Updates"].(map[string]interface{})["offset"].(string)
        delta3Val := sampleData["Updates"].(map[string]interface{})["delta3"].(string)
        delta5Val := sampleData["Updates"].(map[string]interface{})["delta5"].(string)
        eventCountVal := sampleData["Updates"].(map[string]interface{})["eventCount"].(string)
        thresholdEventCountVal := sampleData["Updates"].(map[string]interface{})["thresholdEventCount"].(string)

        dropCountValUint, err := strconv.ParseUint(dropCountVal, 10, 64)
        if err != nil {
            lomcommon.LogError("Failed to convert string to uint64: %v", err)
            return nil
        }

        chipIdValUint, err := strconv.ParseUint(chipIdVal, 10, 64)
        if err != nil {
            lomcommon.LogError("Failed to convert string to uint64: %v", err)
            return nil
        }

        eventCountValUint, err := strconv.ParseUint(eventCountVal, 10, 64)
        if err != nil {
            lomcommon.LogError("Failed to convert string to uint64: %v", err)
            return nil
        }

        thresholdEventCountValUint, err := strconv.ParseUint(thresholdEventCountVal, 10, 64)
        if err != nil {
            lomcommon.LogError("Failed to convert string to uint64: %v", err)
            return nil
        }

        // Create the updates
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "chipName"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(chipNameVal),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "delta2"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(fmt.Sprintf("{\"value\":%s}", delta2Val)),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "initialThresholdEventTime"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(initialThresholdEventTimeVal),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "lastSyslogTime"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(lastSyslogTimeVal),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "initialEventTime"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(initialEventTimeVal),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "lastEventTime"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(lastEventTimeVal),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "lastThresholdEventTime"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(lastThresholdEventTimeVal),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "counterName"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(counterNameVal),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "dropCount"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_UintVal{
                    UintVal: dropCountValUint,
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "delta1"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(fmt.Sprintf("{\"value\":%s}", delta1Val)),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "delta4"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(fmt.Sprintf("{\"value\":%s}", delta4Val)),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "key"},
                    {Name: "chipId"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_UintVal{
                    UintVal: uint64(chipIdValUint),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "key"},
                    {Name: "chipType"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_StringVal{
                    StringVal: chipTypeVal,
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "key"},
                    {Name: "counterId"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(fmt.Sprintf("{\"value\":%s}", counterIdVal)),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "key"},
                    {Name: "offset"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(fmt.Sprintf("{\"value\":%s}", offsetVal)),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "delta3"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(fmt.Sprintf("{\"value\":%s}", delta3Val)),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "delta5"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_JsonVal{
                    JsonVal: []byte(fmt.Sprintf("{\"value\":%s}", delta5Val)),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "eventCount"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_UintVal{
                    UintVal: uint64(eventCountValUint),
                },
            },
        })
        updates = append(updates, &gnmi.Update{
            Path: &gnmi.Path{
                Elem: []*gnmi.PathElem{
                    {Name: keyDetails},
                    {Name: "thresholdEventCount"},
                },
            },
            Val: &gnmi.TypedValue{
                Value: &gnmi.TypedValue_UintVal{
                    UintVal: uint64(thresholdEventCountValUint),
                },
            },
        })
    }
    // Generate the SubscribeResponse
    return &gnmi.SubscribeResponse{
        Response: &gnmi.SubscribeResponse_Update{
            Update: &gnmi.Notification{
                Timestamp: int64(timestamp),
                Prefix: &gnmi.Path{
                    Elem: []*gnmi.PathElem{
                        {Name: "Smash"},
                        {Name: "hardware"},
                        {Name: "counter"},
                        {Name: "internalDrop"},
                        {Name: "SandCounters"},
                        {Name: "internalDrop"},
                    },
                },
                Update: updates,
            },
        },
    }
}

// UpdateDB sets a sample in the server's internal storage and sends it to the client if connected.
func (s *GNMITestServer) UpdateDB(key string, sample map[string]interface{}) {
    s.samples[key] = sample
    lomcommon.LogInfo("Test GNMI Server : Sample set with key: %s\n", key)

    if s.stream == nil {
        lomcommon.LogInfo("Test GNMI Server : No client connected, skipping push")
        return
    }

    sampleDataArray := []map[string]interface{}{sample}
    response := generateResponse(sampleDataArray)

    if response == nil {
        lomcommon.LogError("Test GNMI Server : Failed to generate response")
        return
    }

    // Send the SubscribeResponse
    if err := s.stream.Send(response); err != nil {
        lomcommon.LogInfo("Test GNMI Server : Failed to send response: %v", err)
        return
    }
    lomcommon.LogInfo("Test GNMI Server : Sample pushed")
}

// DeleteDB deletes a sample from the server's internal storage and sends a delete notification to the client if connected.
func (s *GNMITestServer) DeleteDB(key string) {
    sample, exists := s.samples[key]
    if !exists {
        lomcommon.LogInfo("Test GNMI Server : Sample with key: %s does not exist\n", key)
        return
    }

    delete(s.samples, key)
    lomcommon.LogInfo("Test GNMI Server : Sample deleted with key: %s\n", key)

    if s.stream == nil {
        lomcommon.LogInfo("Test GNMI Server : No client connected, skipping push")
        return
    }

    // Generate the key for the gNMI delete message from the sample
    updates := sample["Updates"].(map[string]interface{})
    gnmiKey := fmt.Sprintf("%s_%s_%s_%s", updates["chipId"], updates["chipType"], updates["counterId"], updates["offset"])

    // Generate the delete notification
    deletePath := &gnmi.Path{
        Elem: []*gnmi.PathElem{
            {Name: gnmiKey},
        },
    }

    deleteNotification := &gnmi.Notification{
        Timestamp: time.Now().UnixNano(),
        Prefix: &gnmi.Path{
            Elem: []*gnmi.PathElem{
                {Name: "Smash"},
                {Name: "hardware"},
                {Name: "counter"},
                {Name: "internalDrop"},
                {Name: "SandCounters"},
                {Name: "internalDrop"},
            },
        },
        Delete: []*gnmi.Path{deletePath},
    }

    response := &gnmi.SubscribeResponse{
        Response: &gnmi.SubscribeResponse_Update{
            Update: deleteNotification,
        },
    }

    // Send the SubscribeResponse
    if err := s.stream.Send(response); err != nil {
        lomcommon.LogInfo("Test GNMI Server : Failed to send response: %v", err)
        return
    }
    lomcommon.LogInfo("Test GNMI Server : Delete notification pushed")
}

// GenerateFakeResponsevalid generates a fake SubscribeResponse for testing.
// Here fake means, gnmi path is not for sand counters.
// Note : Fake responses are stored in DB
func GenerateFakeResponsevalid() *gnmi.SubscribeResponse {
    // Create a fake update
    update := &gnmi.Update{
        Path: &gnmi.Path{
            Elem: []*gnmi.PathElem{
                {Name: "fakePath"},
            },
        },
        Val: &gnmi.TypedValue{
            Value: &gnmi.TypedValue_StringVal{
                StringVal: "fakeValue",
            },
        },
    }

    // Create a fake notification with the update
    notification := &gnmi.Notification{
        Timestamp: time.Now().Unix(),
        Prefix: &gnmi.Path{
            Elem: []*gnmi.PathElem{
                {Name: "fakePrefix"},
            },
        },
        Update: []*gnmi.Update{update},
    }

    // Create a fake SubscribeResponse with the notification
    response := &gnmi.SubscribeResponse{
        Response: &gnmi.SubscribeResponse_Update{
            Update: notification,
        },
    }

    return response
}

// UpdateDBFakeResponse updates the server's internal storage with a fake response and sends it to the client if connected.
// Note : Fake responses are stored in DB
func (s *GNMITestServer) UpdateDBFakeResponse() {
    lomcommon.LogInfo("Test GNMI Server : Generating fake response")

    if s.stream == nil {
        lomcommon.LogInfo("Test GNMI Server : No client connected, skipping push")
        return
    }

    response := GenerateFakeResponsevalid()

    if response == nil {
        lomcommon.LogError("Test GNMI Server : Failed to generate response")
        return
    }

    // Send the SubscribeResponse
    if err := s.stream.Send(response); err != nil {
        lomcommon.LogInfo("Test GNMI Server : Failed to send response: %v", err)
        return
    }
    lomcommon.LogInfo("Test GNMI Server : Sample pushed")
}

// GenerateFakeResponseNoPrefix generates a fake SubscribeResponse for testing without a prefix.
// Note : Fake responses are stored in DB
func GenerateFakeResponseNoPrefix() *gnmi.SubscribeResponse {
    // Create a fake update
    update := &gnmi.Update{
        Path: &gnmi.Path{
            Elem: []*gnmi.PathElem{
                {Name: "fakePath"},
            },
        },
        Val: &gnmi.TypedValue{
            Value: &gnmi.TypedValue_StringVal{
                StringVal: "fakeValue",
            },
        },
    }

    // Create a fake notification with the update but without a prefix
    notification := &gnmi.Notification{
        Timestamp: time.Now().Unix(),
        Update:    []*gnmi.Update{update},
    }

    // Create a fake SubscribeResponse with the notification
    response := &gnmi.SubscribeResponse{
        Response: &gnmi.SubscribeResponse_Update{
            Update: notification,
        },
    }

    return response
}

// UpdateDBFakeResponseNoPrefix updates the server's internal storage with a fake response without a prefix and sends it to the client if connected.
// Note : Fake responses are stored in DB
func (s *GNMITestServer) UpdateDBFakeResponseNoPrefix() {
    lomcommon.LogInfo("Test GNMI Server : Generating fake response without prefix")

    if s.stream == nil {
        lomcommon.LogInfo("Test GNMI Server : No client connected, skipping push")
        return
    }

    response := GenerateFakeResponseNoPrefix()

    if response == nil {
        lomcommon.LogError("Test GNMI Server : Failed to generate response")
        return
    }

    // Send the SubscribeResponse
    if err := s.stream.Send(response); err != nil {
        lomcommon.LogInfo("Test GNMI Server : Failed to send response: %v", err)
        return
    }
    lomcommon.LogInfo("Test GNMI Server : Sample pushed")
}

// Set handles a SetRequest from the client.
func (s *GNMITestServer) Set(ctx context.Context, req *gnmi.SetRequest) (*gnmi.SetResponse, error) {
    lomcommon.LogInfo("Test GNMI Server : Set request received")
    // Not implemented
    return &gnmi.SetResponse{}, nil
}

// Capabilities handles a CapabilityRequest from the client.
func (s *GNMITestServer) Capabilities(ctx context.Context, req *gnmi.CapabilityRequest) (*gnmi.CapabilityResponse, error) {
    lomcommon.LogInfo("Test GNMI Server : Capabilities request received")
    // Not implemented
    return &gnmi.CapabilityResponse{}, nil
}

// Subscribe handles a SubscribeRequest from the client.
func (s *GNMITestServer) Subscribe(stream gnmi.GNMI_SubscribeServer) error {
    lomcommon.LogInfo("Test GNMI Server : Subscribe request received")
    s.stream = stream

    // Define the correct path
    correctPath := []string{"Smash", "hardware", "counter", "internalDrop", "SandCounters", "internalDrop"}

    // Loop to handle multiple requests
    for {
        // Wait for a SubscribeRequest from the client
        req, err := stream.Recv()
        if err != nil {
            if err == io.EOF {
                // The client closed the connection
                lomcommon.LogInfo("Test GNMI Server : Client disconnected")
            } else {
                // A network error occurred
                lomcommon.LogInfo("Test GNMI Server : Network error: %v", err)
            }
            lomcommon.LogInfo("Test GNMI Server : Subscribe goroutine closing")
            return err
        }

        // Check if the client is subscribing to the correct path
        for _, subscription := range req.GetSubscribe().GetSubscription() {
            clientPath := subscription.GetPath().GetElem()
            if len(clientPath) != len(correctPath) {
                continue
            }

            match := true
            for i, elem := range clientPath {
                if elem.GetName() != correctPath[i] {
                    match = false
                    break
                }
            }
            if match {
                // Print client details and path when first connected
                lomcommon.LogInfo("Test GNMI Server : Client connected: %s, Path: %s\n", req.GetSubscribe().GetPrefix().GetTarget(), correctPath)

                // Send all stored samples to the client
                for _, sample := range s.samples {
                    sampleDataArray := []map[string]interface{}{sample}
                    response := generateResponse(sampleDataArray)

                    if response == nil {
                        return lomcommon.LogError("Test GNMI Server : Failed to generate response")
                    }

                    // Send the SubscribeResponse
                    if err := stream.Send(response); err != nil {
                        lomcommon.LogInfo("Test GNMI Server : Failed to send response:", err)
                        return err
                    }
                }
            }
        }
    }

    return nil
}

/*
   // server_main starts the gNMI server and pushes a sample to it.
   func Server_main() {
       server := NewGNMITestServer()
       if err := server.Start(); err != nil {
           lomcommon.Fatalf("Failed to start server: %v", err)
       }
       defer server.Stop()

       // Set some samples in the server
       server.UpdateDB("sample1_key", sample_1)
       server.UpdateDB("sample2_key", sample_2)

       // Wait for the user to stop the server
       var input string
       fmt.Scanln(&input)

       //server.UpdateDB("sample2_key", sample_2)

       //deletes
       server.DeleteDB("sample1_key")

       // Wait for the user to stop the server
       fmt.Scanln(&input)
   }
*/

/*
   func main() {
       server_main()
   }
*/
