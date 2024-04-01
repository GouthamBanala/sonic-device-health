package plugins_common

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "io"
    "net"
    "os"
    "reflect"
    "testing"

    "github.com/agiledragon/gomonkey"
    "github.com/openconfig/gnmi/proto/gnmi"
    ext_gnmi "github.com/openconfig/gnmi/proto/gnmi"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "google.golang.org/grpc"
    ext_grpc "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
)

//---------------------------------------------

type MockDialer struct {
    mock.Mock
}

/*
func (m *MockDialer) Dial(target string, opts ...ext_grpc.DialOption) (iGRPCConnExt, error) {
    args := m.Called(target, opts)
    return args.Get(0).(iGRPCConnExt), args.Error(1)
}*/

func (m *MockDialer) DialContext(ctx context.Context, target string, opts ...ext_grpc.DialOption) (iGRPCConnExt, error) {
    args := m.Called(ctx, target, opts)
    return args.Get(0).(iGRPCConnExt), args.Error(1)
}

//---------------------------------------------

type MockGNMIClientExt struct {
    mock.Mock
}

func (m *MockGNMIClientExt) Capabilities(ctx context.Context, in *gnmi.CapabilityRequest, opts ...grpc.CallOption) (*gnmi.CapabilityResponse, error) {
    args := m.Called(ctx, in)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*gnmi.CapabilityResponse), args.Error(1)
}

func (m *MockGNMIClientExt) Get(ctx context.Context, in *gnmi.GetRequest, opts ...grpc.CallOption) (*gnmi.GetResponse, error) {
    args := m.Called(ctx, in)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*gnmi.GetResponse), args.Error(1)
}

func (m *MockGNMIClientExt) Subscribe(ctx context.Context, opts ...ext_grpc.CallOption) (ext_gnmi.GNMI_SubscribeClient, error) {
    args := m.Called(ctx)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(ext_gnmi.GNMI_SubscribeClient), args.Error(1)
}

//---------------------------------------------

type MockGNMIClientMethodsExt struct {
    mock.Mock
}

func (m *MockGNMIClientMethodsExt) NewGNMIClient(conn iGRPCConnExt) (iGNMIClientExt, error) {
    args := m.Called(conn)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(iGNMIClientExt), args.Error(1)
}

//---------------------------------------------

type MockGRPCConnExt struct {
    //grpc.ClientConn
    mock.Mock
}

func (m *MockGRPCConnExt) Close() error {
    args := m.Called()
    return args.Error(0)
}

// ---------------------------------------------
// for subscribeStream
type MockSubscribeClient struct {
    mock.Mock
}

func (m *MockSubscribeClient) Send(req *gnmi.SubscribeRequest) error {
    args := m.Called(req)
    return args.Error(0)
}

func (m *MockSubscribeClient) Recv() (*ext_gnmi.SubscribeResponse, error) {
    args := m.Called()
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*ext_gnmi.SubscribeResponse), args.Error(1)
}

func (m *MockSubscribeClient) Header() (metadata.MD, error) {
    args := m.Called()
    return args.Get(0).(metadata.MD), args.Error(1)
}

func (m *MockSubscribeClient) Trailer() metadata.MD {
    args := m.Called()
    return args.Get(0).(metadata.MD)
}

func (m *MockSubscribeClient) CloseSend() error {
    args := m.Called()
    return args.Error(0)
}

func (m *MockSubscribeClient) Context() context.Context {
    args := m.Called()
    return args.Get(0).(context.Context)
}

func (m *MockSubscribeClient) SendMsg(i interface{}) error {
    args := m.Called(i)
    return args.Error(0)
}

func (m *MockSubscribeClient) RecvMsg(i interface{}) error {
    args := m.Called(i)
    return args.Error(0)
}

//---------------------------------------------
// For Integration kind of tests to test the NewGNMIClient() function

type MyGNMIServer struct {
    ext_gnmi.UnimplementedGNMIServer
}

func (s *MyGNMIServer) Capabilities(ctx context.Context, req *ext_gnmi.CapabilityRequest) (*ext_gnmi.CapabilityResponse, error) {
    // Get the credentials from the context
    if md, ok := metadata.FromIncomingContext(ctx); ok {
        if md["username"][0] == "" || md["password"][0] == "" {
            return nil, status.Error(codes.Unauthenticated, "invalid credentials")
        }
    }

    return &ext_gnmi.CapabilityResponse{}, nil
}

func (s *MyGNMIServer) Get(ctx context.Context, req *ext_gnmi.GetRequest) (*ext_gnmi.GetResponse, error) {
    return nil, nil
}

func (s *MyGNMIServer) Set(ctx context.Context, req *ext_gnmi.SetRequest) (*ext_gnmi.SetResponse, error) {
    return nil, nil
}

func (s *MyGNMIServer) Subscribe(srv ext_gnmi.GNMI_SubscribeServer) error {
    return nil
}

type MockInvalidConnType struct {
}

// Implement the Close method
func (m *MockInvalidConnType) Close() error {
    return nil
}

// -------------------------------------------------

// TestGetGNMIInstance tests the GetGNMIInstance() function
func TestGetGNMIInstance(t *testing.T) {

    // Test for creating a new instance
    t.Run("NewInstance", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        //mockDialer.On("Dial", "localhost:8080", mock.Anything).Return(mockConn, nil)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil).Once()
        //mockConn.On("Close").Return(nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockGNMIClient := new(MockGNMIClientExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockGNMIClient, nil)

        // Reset global variables after this test
        defer func() {
            gnmiServerConnectorInstances = make(map[string]*gnmiServerConnector)
            gnmiServerConnectorCounts = make(map[string]int)
        }()

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.NoError(t, err)
        assert.NotNil(t, instance)

        // Check if the instance is stored in the map
        assert.Equal(t, instance, gnmiServerConnectorInstances["localhost:8080"])

        // count the number of instances in the map
        count := 0
        for _, _ = range gnmiServerConnectorInstances {
            count++
        }
        assert.Equal(t, 1, count)

        // count the number of number of clients connected to this server
        assert.Equal(t, 1, gnmiServerConnectorCounts["localhost:8080"])

        // Check expectations
        mockDialer.AssertExpectations(t)
        mockConn.AssertExpectations(t)
        mockClientMethod.AssertExpectations(t)

        //cleanup global variables
        //assert.NoError(t, instance.e_conn.Close())
        //assert.Equal(t, 0, gnmiServerConnectorCounts["localhost:8080"])
        //assert.Equal(t, 0, len(gnmiServerConnectorInstances))
        //assert.Equal(t, 0, len(gnmiServerConnectorCounts))

    })

    // Test for retrieving an existing instance
    t.Run("ExistingInstance", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        //mockDialer.On("Dial", "localhost:8080", mock.Anything).Return(mockConn, nil).Once()
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil).Once()
        //mockConn.On("Close").Return(nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockGNMIClient := new(MockGNMIClientExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockGNMIClient, nil).Once()

        defer func() {
            gnmiServerConnectorInstances = make(map[string]*gnmiServerConnector)
            gnmiServerConnectorCounts = make(map[string]int)
        }()

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test twice
        instance1, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.NoError(t, err)
        assert.NotNil(t, instance1)

        instance2, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.NoError(t, err)
        assert.Equal(t, instance1, instance2)

        // Check if the instance is stored in the map
        assert.Equal(t, instance1, gnmiServerConnectorInstances["localhost:8080"])

        // count the number of instances in the map
        count := 0
        for _, _ = range gnmiServerConnectorInstances {
            count++
        }
        assert.Equal(t, 1, count)

        // count the number of number of clients connected to this server
        assert.Equal(t, 2, gnmiServerConnectorCounts["localhost:8080"])

        // Check expectations
        mockDialer.AssertExpectations(t)
        mockConn.AssertExpectations(t)
        mockClientMethod.AssertExpectations(t)

        // Check if Dial and NewGNMIClient were called only once
        mockDialer.AssertNumberOfCalls(t, "DialContext", 1)
        mockClientMethod.AssertNumberOfCalls(t, "NewGNMIClient", 1)
    })

    // Test for error when dialing
    t.Run("ErrorDialing", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil).Once()

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mock.Anything).Return(nil, errors.New("mock error")).Once()

        defer func() {
            gnmiServerConnectorInstances = make(map[string]*gnmiServerConnector)
            gnmiServerConnectorCounts = make(map[string]int)
        }()

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)

        // Check if the instance must not be stored in the map
        assert.Nil(t, gnmiServerConnectorInstances["localhost:8080"])

        // count the number of instances in the map
        count := 0
        for _, _ = range gnmiServerConnectorInstances {
            count++
        }
        assert.Equal(t, 0, count)

        // count the number of number of clients connected to this server
        assert.Equal(t, 0, gnmiServerConnectorCounts["localhost:8080"])

        // Check expectations
        mockDialer.AssertExpectations(t)
        mockClientMethod.AssertExpectations(t)
    })
    // Test for error when creating client
    t.Run("ErrorCreatingClient", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        //mockDialer.On("Dial", "localhost:8080", mock.Anything).Return(mockConn, nil)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil).Once()
        //mockConn.On("Close").Return(nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(nil, errors.New("mock error"))

        defer func() {
            gnmiServerConnectorInstances = make(map[string]*gnmiServerConnector)
            gnmiServerConnectorCounts = make(map[string]int)
        }()

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)

        // Check if the instance must not be stored in the map
        assert.Nil(t, gnmiServerConnectorInstances["localhost:8080"])

        // count the number of instances in the map
        count := 0
        for _, _ = range gnmiServerConnectorInstances {
            count++
        }
        assert.Equal(t, 0, count)

        // count the number of number of clients connected to this server
        assert.Equal(t, 0, gnmiServerConnectorCounts["localhost:8080"])

        // Check expectations
        mockDialer.AssertExpectations(t)
        mockConn.AssertExpectations(t)
        mockClientMethod.AssertExpectations(t)
    })

    // Test with nil for ext_dialer
    t.Run("NilDialer", func(t *testing.T) {
        // Setup mocks
        mockClientMethod := new(MockGNMIClientMethodsExt)

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }
        // Call the function under test
        instance, err := getGNMIInstance(nil, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)
    })

    // Test with nil for ext_clientMethod
    t.Run("NilClientMethod", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := getGNMIInstance(mockDialer, nil, security)
        assert.Error(t, err)
        assert.Nil(t, instance)
    })

    // Test with empty username
    t.Run("EmptyUsername", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockClientMethod := new(MockGNMIClientMethodsExt)

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)
    })

    // Test with empty password
    t.Run("EmptyPassword", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockClientMethod := new(MockGNMIClientMethodsExt)

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)
    })

    // Test with empty server
    t.Run("EmptyServer", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockClientMethod := new(MockGNMIClientMethodsExt)

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := getGNMIInstance(mockDialer, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)
    })
}

// TestNewGNMIClient tests the NewGNMIClient() function
func TestNewGNMIClient(t *testing.T) {
    // Test when newGNMIClientConnection returns an error
    t.Run("newGNMIClientConnectionError", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, errors.New("dial error"))

        mockClientMethod := new(MockGNMIClientMethodsExt)

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := newGNMIClient(mockDialer, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)
    })

    // Test when ext_clientMethod.NewGNMIClient returns an error
    t.Run("NewGNMIClientError", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(nil, errors.New("client error"))

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := newGNMIClient(mockDialer, mockClientMethod, security)
        assert.Error(t, err)
        assert.Nil(t, instance)
    })

    // Test when both functions succeed
    t.Run("Success", func(t *testing.T) {
        // Setup mocks
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        mockClientMethod := new(MockGNMIClientMethodsExt)
        mockGNMIClient := new(MockGNMIClientExt)
        mockClientMethod.On("NewGNMIClient", mockConn).Return(mockGNMIClient, nil)

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        instance, err := newGNMIClient(mockDialer, mockClientMethod, security)
        assert.NoError(t, err)
        assert.NotNil(t, instance)
    })
}

func TestNewGNMIClientConnection(t *testing.T) {
    // Test when security.useTLS is true and security.validateServerCertificate is also true
    t.Run("UseTLSAndValidateServerCertificate", func(t *testing.T) {
        // Setup mocks and variables
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        security := gnmiSecurityDetails{
            server:                    "localhost:8080",
            username:                  "admin",
            password:                  "admin",
            useTLS:                    true,
            validateServerCertificate: true,
            certificateFilePath:       "path/to/cert",
            privateKeyFilePath:        "path/to/key",
            caCertificateFilePath:     "path/to/caCert",
        }

        // Mock tls.LoadX509KeyPair function
        patches := gomonkey.ApplyFunc(tls.LoadX509KeyPair, func(certFile, keyFile string) (tls.Certificate, error) {
            return tls.Certificate{}, nil
        })
        // Mock x509.NewCertPool function
        patches.ApplyFunc(x509.NewCertPool, func() *x509.CertPool {
            return &x509.CertPool{}
        })
        // Mock ioutil.ReadFile function
        patches.ApplyFunc(os.ReadFile, func(filename string) ([]byte, error) {
            return []byte("dummy cert"), nil
        })
        // Mock caCertPool.AppendCertsFromPEM function
        patches.ApplyMethodSeq(reflect.TypeOf(&x509.CertPool{}), "AppendCertsFromPEM", []gomonkey.OutputCell{
            {Values: gomonkey.Params{true}},
        })
        patches.ApplyMethodSeq(reflect.TypeOf(&x509.CertPool{}), "AppendCertsFromPEM", []gomonkey.OutputCell{
            {Values: gomonkey.Params{true}},
        })
        // Mock credentials.NewTLS function
        patches.ApplyFunc(credentials.NewTLS, func(config *tls.Config) credentials.TransportCredentials {
            // Return a mock TransportCredentials. You'll need to replace this with a real mock value.
            return nil
        })
        defer patches.Reset()

        // Call the function under test
        conn, err := newGNMIClientConnection(mockDialer, security)
        assert.NoError(t, err)
        assert.NotNil(t, conn)
    })

    // Test when security.useTLS is false
    t.Run("NoTLS", func(t *testing.T) {
        // Setup mocks and variables
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Call the function under test
        conn, err := newGNMIClientConnection(mockDialer, security)
        assert.NoError(t, err)
        assert.NotNil(t, conn)
    })

    // Test when security.useTLS is true and security.validateServerCertificate is false
    t.Run("UseTLSNoValidateServerCertificate", func(t *testing.T) {
        // Setup mocks and variables
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        security := gnmiSecurityDetails{
            server:                    "localhost:8080",
            username:                  "admin",
            password:                  "admin",
            useTLS:                    true,
            validateServerCertificate: false,
            certificateFilePath:       "path/to/cert",
            privateKeyFilePath:        "path/to/key",
        }

        // Mock tls.LoadX509KeyPair function
        patches := gomonkey.ApplyFunc(tls.LoadX509KeyPair, func(certFile, keyFile string) (tls.Certificate, error) {
            return tls.Certificate{}, nil
        })
        // Mock x509.NewCertPool function
        patches.ApplyFunc(x509.NewCertPool, func() *x509.CertPool {
            return &x509.CertPool{}
        })
        // Mock credentials.NewTLS function
        patches.ApplyFunc(credentials.NewTLS, func(config *tls.Config) credentials.TransportCredentials {
            return nil
        })
        defer patches.Reset()

        // Call the function under test
        conn, err := newGNMIClientConnection(mockDialer, security)
        assert.NoError(t, err)
        assert.NotNil(t, conn)
    })

    // Test when security.useTLS is true, security.validateServerCertificate is true, and caCertPool.AppendCertsFromPEM(caCert) returns false
    t.Run("UseTLSValidateServerCertificateAppendCertsFromPEMFail", func(t *testing.T) {
        // Setup mocks and variables
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        security := gnmiSecurityDetails{
            server:                    "localhost:8080",
            username:                  "admin",
            password:                  "admin",
            useTLS:                    true,
            validateServerCertificate: true,
            certificateFilePath:       "path/to/cert",
            privateKeyFilePath:        "path/to/key",
            caCertificateFilePath:     "path/to/caCert",
        }

        // Mock tls.LoadX509KeyPair function
        patches := gomonkey.ApplyFunc(tls.LoadX509KeyPair, func(certFile, keyFile string) (tls.Certificate, error) {
            return tls.Certificate{}, nil
        })
        // Mock x509.NewCertPool function
        patches.ApplyFunc(x509.NewCertPool, func() *x509.CertPool {
            return &x509.CertPool{}
        })
        // Mock os.ReadFile function
        patches.ApplyFunc(os.ReadFile, func(filename string) ([]byte, error) {
            return []byte("dummy cert"), nil
        })
        // Mock caCertPool.AppendCertsFromPEM function to return false
        patches.ApplyMethodSeq(reflect.TypeOf(&x509.CertPool{}), "AppendCertsFromPEM", []gomonkey.OutputCell{
            {Values: gomonkey.Params{false}},
        })
        // Mock credentials.NewTLS function
        patches.ApplyFunc(credentials.NewTLS, func(config *tls.Config) credentials.TransportCredentials {
            return nil
        })
        defer patches.Reset()

        // Call the function under test
        _, err := newGNMIClientConnection(mockDialer, security)
        assert.Error(t, err)
    })

    // Test when ext_dialer.DialContext returns an error
    t.Run("DialContextError", func(t *testing.T) {
        // Setup mocks and variables
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, errors.New("dial context error"))

        security := gnmiSecurityDetails{
            server:   "localhost:8080",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        // Mock DialContext to return an error
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(nil, errors.New("dial context error"))

        // Call the function under test
        _, err := newGNMIClientConnection(mockDialer, security)
        assert.Error(t, err)
    })

    // Test when LoadX509KeyPair returns error
    t.Run("UseTLSNoValidateServerCertificate", func(t *testing.T) {
        // Setup mocks and variables
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        security := gnmiSecurityDetails{
            server:                    "localhost:8080",
            username:                  "admin",
            password:                  "admin",
            useTLS:                    true,
            validateServerCertificate: false,
            certificateFilePath:       "path/to/cert",
            privateKeyFilePath:        "path/to/key",
        }

        // Mock tls.LoadX509KeyPair function
        patches := gomonkey.ApplyFunc(tls.LoadX509KeyPair, func(certFile, keyFile string) (tls.Certificate, error) {
            return tls.Certificate{}, errors.New("load x509 key pair error")
        })
        defer patches.Reset()

        // Call the function under test
        conn, err := newGNMIClientConnection(mockDialer, security)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "load x509 key pair error")
        assert.Nil(t, conn)
    })

    // Test when os.ReadFile returns an error
    t.Run("UseTLSValidateServerCertificateAppendCertsFromPEMFail", func(t *testing.T) {
        // Setup mocks and variables
        mockDialer := new(MockDialer)
        mockConn := new(MockGRPCConnExt)
        mockDialer.On("DialContext", mock.Anything, "localhost:8080", mock.Anything).Return(mockConn, nil)

        security := gnmiSecurityDetails{
            server:                    "localhost:8080",
            username:                  "admin",
            password:                  "admin",
            useTLS:                    true,
            validateServerCertificate: true,
            certificateFilePath:       "path/to/cert",
            privateKeyFilePath:        "path/to/key",
            caCertificateFilePath:     "path/to/caCert",
        }

        // Mock tls.LoadX509KeyPair function
        patches := gomonkey.ApplyFunc(tls.LoadX509KeyPair, func(certFile, keyFile string) (tls.Certificate, error) {
            return tls.Certificate{}, nil
        })
        // Mock x509.NewCertPool function
        patches.ApplyFunc(x509.NewCertPool, func() *x509.CertPool {
            return &x509.CertPool{}
        })
        // Mock os.ReadFile function
        patches.ApplyFunc(os.ReadFile, func(filename string) ([]byte, error) {
            return []byte("dummy cert"), errors.New("read file error")
        })
        defer patches.Reset()

        // Call the function under test
        _, err := newGNMIClientConnection(mockDialer, security)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "read file error")
    })
}

// TestCapabilities tests the capabilities() function
func TestCapabilities(t *testing.T) {
    // Test when gs.e_client is nil
    t.Run("NilClient", func(t *testing.T) {
        // Setup instance
        instance := &gnmiServerConnector{}

        // Call the function under test
        response, err := instance.capabilities(context.Background())
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Capabilities returns an error
    t.Run("CapabilitiesError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Capabilities", mock.Anything, mock.Anything).Return(&gnmi.CapabilityResponse{}, errors.New("capabilities error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Call the function under test
        response, err := instance.capabilities(context.Background())
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Capabilities returns a Canceled error
    t.Run("CanceledError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Capabilities", mock.Anything, mock.Anything).Return(&gnmi.CapabilityResponse{}, status.Error(codes.Canceled, "context was cancelled"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Call the function under test
        response, err := instance.capabilities(context.Background())
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Capabilities returns a DeadlineExceeded error
    t.Run("DeadlineExceededError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Capabilities", mock.Anything, mock.Anything).Return(&gnmi.CapabilityResponse{}, status.Error(codes.DeadlineExceeded, "context deadline exceeded"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Call the function under test
        response, err := instance.capabilities(context.Background())
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Capabilities succeeds
    t.Run("Success", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Capabilities", mock.Anything, mock.Anything).Return(&gnmi.CapabilityResponse{}, nil)

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Call the function under test
        response, err := instance.capabilities(context.Background())
        assert.NoError(t, err)
        assert.NotNil(t, response)
    })
}

// TestSplitPath tests the splitPath() function
func TestSplitPath(t *testing.T) {

    // Test with a simple path
    t.Run("SimplePath", func(t *testing.T) {
        path := "a/b/c"
        expected := []*ext_gnmi.PathElem{
            {Name: "a"},
            {Name: "b"},
            {Name: "c"},
        }
        result := splitPath(path)
        assert.Equal(t, expected, result)
    })

    // Test with a path that has leading and trailing slashes
    t.Run("PathWithLeadingAndTrailingSlashes", func(t *testing.T) {
        path := "/a/b/c/"
        expected := []*ext_gnmi.PathElem{
            {Name: "a"},
            {Name: "b"},
            {Name: "c"},
        }
        result := splitPath(path)
        assert.Equal(t, expected, result)
    })

    // Test with a path that has multiple slashes between elements
    t.Run("PathWithMultipleSlashes", func(t *testing.T) {
        path := "a//b///c"
        expected := []*ext_gnmi.PathElem{
            {Name: "a"},
            {Name: "b"},
            {Name: "c"},
        }
        result := splitPath(path)
        assert.Equal(t, expected, result)
    })

    // Test with an empty path
    t.Run("EmptyPath", func(t *testing.T) {
        path := ""
        expected := []*ext_gnmi.PathElem{}
        result := splitPath(path)
        assert.Equal(t, expected, result)
    })

}

// TestGet tests the get() function
func TestGet(t *testing.T) {
    // Test when gs.e_client is nil
    t.Run("NilClient", func(t *testing.T) {
        // Setup instance
        instance := &gnmiServerConnector{}

        // Call the function under test
        response, err := instance.get(context.Background(), "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when no paths are provided
    t.Run("NoPaths", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.get(context.Background(), "/a/b/c", []string{})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Get returns an error
    t.Run("GetError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Get", mock.Anything, mock.Anything).Return(&gnmi.GetResponse{}, errors.New("get error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.get(context.Background(), "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Get returns a Canceled error
    t.Run("CanceledError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Get", mock.Anything, mock.Anything).Return(&gnmi.GetResponse{}, status.Error(codes.Canceled, "context was cancelled"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.get(context.Background(), "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Get returns a DeadlineExceeded error
    t.Run("DeadlineExceededError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Get", mock.Anything, mock.Anything).Return(&gnmi.GetResponse{}, status.Error(codes.DeadlineExceeded, "context deadline exceeded"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.get(context.Background(), "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Get succeeds
    t.Run("Success", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockClient.On("Get", mock.Anything, mock.Anything).Return(&gnmi.GetResponse{}, nil)

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.get(context.Background(), "/a/b/c", []string{"/d/e/f"})
        assert.NoError(t, err)
        assert.NotNil(t, response)
    })
}

// TestSubscribe tests the subscribe() function
func TestSubscribe(t *testing.T) {

    // Test when gs.e_client is nil
    t.Run("NilClient", func(t *testing.T) {
        // Setup instance
        instance := &gnmiServerConnector{}

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when no paths are provided
    t.Run("NoPaths", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Subscribe returns an error
    t.Run("SubscribeError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, errors.New("subscribe error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Subscribe returns a Canceled error
    t.Run("CanceledError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, errors.New("subscribe error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Subscribe returns a DeadlineExceeded error
    t.Run("DeadlineExceededError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, errors.New("subscribe error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when subscribeClient.Send returns an error
    t.Run("Success", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockSubscribeClient.On("CloseSend").Return(nil) // Mock the CloseSend method

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.NoError(t, err)
        assert.NotNil(t, response)
    })

    // Test when gs.e_client.Subscribe and subscribeClient.Send succeed
    t.Run("Success", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.NoError(t, err)
        assert.NotNil(t, response)
    })

    // Test when gs.e_client.Subscribe returns a Canceled error
    t.Run("SubscribeCanceledError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, status.Error(codes.Canceled, "canceled"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    // Test when gs.e_client.Subscribe returns a DeadlineExceeded error
    t.Run("SubscribeDeadlineExceededError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, status.Error(codes.DeadlineExceeded, "deadline exceeded"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })

    t.Run("SubscribeOtherError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, errors.New("other error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
        assert.Nil(t, response)
    })
}

// TestSubscribeStream tests the subscribeStream() function
func TestSubscribeStream(t *testing.T) {

    t.Run("Success", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)
        mockSubscribeClient.On("Send", mock.Anything).Return(nil)
        mockSubscribeClient.On("CloseSend").Return(nil) // Mock the CloseSend method

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        response, err := instance.subscribeStream(context.Background(), "/a/b/c", []string{"/d/e/f"})

        // Assert that there was no error and the response is not nil
        assert.NoError(t, err)
        assert.NotNil(t, response)

        // Assert that the Subscribe method was called with the correct parameters
        mockClient.AssertCalled(t, "Subscribe", mock.Anything)
    })

    // Test when gs.subscribe returns an error in subscribeStream
    t.Run("SubscribeError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, errors.New("error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        _, err := instance.subscribeStream(context.Background(), "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
    })

    // Test when gs.e_client.Subscribe returns an error in subscribe
    t.Run("SubscribeError_2", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, errors.New("error"))

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        // Call the function under test
        _, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
    })

    // Test when subscribeClient.Send returns an error in subscribe
    t.Run("SendError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockGNMIClientExt)
        mockSubscribeClient := new(MockSubscribeClient)
        mockClient.On("Subscribe", mock.Anything).Return(mockSubscribeClient, nil)
        mockSubscribeClient.On("Send", mock.Anything).Return(errors.New("error"))
        mockSubscribeClient.On("CloseSend").Return(nil) // Mock the CloseSend method

        // Setup instance
        instance := &gnmiServerConnector{
            e_client: mockClient,
        }

        _, err := instance.subscribe(context.Background(), ext_gnmi.SubscriptionList_ONCE, "/a/b/c", []string{"/d/e/f"})
        assert.Error(t, err)
    })
}

// TestClose tests the Close() function
func TestClose(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Setup instance
        mockConn := new(MockGRPCConnExt)
        mockConn.On("Close").Return(nil) // Mock the Close method

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "testServer",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        instance := &gnmiServerConnector{
            e_conn:   mockConn,
            security: security,
        }
        gnmiServerConnectorCounts[instance.security.server] = 1

        // Call the function under test
        err := instance.close()
        assert.NoError(t, err)
        assert.Nil(t, instance.e_conn)
        assert.Equal(t, 0, gnmiServerConnectorCounts[instance.security.server])
    })

    t.Run("ConnectionNotInitialized", func(t *testing.T) {
        // Setup instance
        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "testServer",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        instance := &gnmiServerConnector{
            e_conn:   nil,
            security: security,
        }

        err := instance.close()
        assert.Error(t, err)
        assert.Equal(t, "connection is not initialized", err.Error())
    })

    t.Run("NoClientCountForServer", func(t *testing.T) {
        // Setup instance
        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "testServer1",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        instance := &gnmiServerConnector{
            e_conn:   &MockGRPCConnExt{},
            security: security,
        }

        err := instance.close()
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "no client count for server")
    })

    t.Run("FailedToCloseConnection", func(t *testing.T) {
        // Setup instance
        mockConn := new(MockGRPCConnExt)
        mockConn.On("Close").Return(errors.New("error"))

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "testServer",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        instance := &gnmiServerConnector{
            e_conn:   mockConn,
            security: security,
        }
        gnmiServerConnectorCounts[instance.security.server] = 1

        err := instance.close()
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to close connection")
    })

    t.Run("ClientCountNotZero", func(t *testing.T) {
        // Setup instance
        mockConn := new(MockGRPCConnExt)
        mockConn.On("Close").Return(nil) // Mock the Close method

        // Prepare security details
        security := gnmiSecurityDetails{
            server:   "testServer",
            username: "admin",
            password: "admin",
            useTLS:   false,
        }

        instance := &gnmiServerConnector{
            e_conn:   mockConn,
            security: security,
        }
        gnmiServerConnectorCounts[instance.security.server] = 2 // Set the client count to 2

        err := instance.close()
        assert.NoError(t, err)
        assert.Equal(t, 1, gnmiServerConnectorCounts[instance.security.server])
    })
}

// TestReceiveResponses tests the receiveResponses() function
func TestReceiveSubscriptions(t *testing.T) {
    t.Run("Success", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockSubscribeClient)
        mockClient.On("Recv").Return(&ext_gnmi.SubscribeResponse{
            Response: &ext_gnmi.SubscribeResponse_Update{
                Update: &ext_gnmi.Notification{},
            },
        }, nil).Once()
        mockClient.On("Recv").Return(&ext_gnmi.SubscribeResponse{
            Response: &ext_gnmi.SubscribeResponse_SyncResponse{},
        }, nil).Once()
        mockClient.On("Recv").Return(nil, io.EOF)

        // Setup channel
        gnmiNotificationsCh := make(chan *ext_gnmi.Notification, 1)

        // Call the function under test
        err := receiveSubscriptions(mockClient, gnmiNotificationsCh)

        assert.NoError(t, err)
        assert.NotNil(t, <-gnmiNotificationsCh)
        assert.Equal(t, 0, len(gnmiNotificationsCh), "Channel should be empty after receiving all notifications")
    })

    t.Run("Error", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockSubscribeClient)
        mockClient.On("Recv").Return(nil, errors.New("error"))

        // Setup channel
        gnmiNotificationsCh := make(chan *ext_gnmi.Notification, 1)

        err := receiveSubscriptions(mockClient, gnmiNotificationsCh)
        assert.Error(t, err)
    })

    t.Run("TemporaryError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockSubscribeClient)
        mockClient.On("Recv").Return(nil, &net.DNSError{IsTemporary: true}).Once()
        mockClient.On("Recv").Return(&ext_gnmi.SubscribeResponse{
            Response: &ext_gnmi.SubscribeResponse_SyncResponse{},
        }, nil).Once()
        mockClient.On("Recv").Return(nil, io.EOF)

        // Setup channel
        gnmiNotificationsCh := make(chan *ext_gnmi.Notification, 1)

        // Call the function under test
        err := receiveSubscriptions(mockClient, gnmiNotificationsCh)

        // Assert that there was no error
        assert.NoError(t, err)
    })

    t.Run("EOFError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockSubscribeClient)
        mockClient.On("Recv").Return(nil, io.EOF)

        // Setup channel
        gnmiNotificationsCh := make(chan *ext_gnmi.Notification, 1)

        err := receiveSubscriptions(mockClient, gnmiNotificationsCh)
        assert.NoError(t, err)
    })

    t.Run("CanceledError", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockSubscribeClient)
        mockClient.On("Recv").Return(nil, status.Error(codes.Canceled, "canceled")).Once()
        mockClient.On("Recv").Return(nil, io.EOF)

        // Setup channel
        gnmiNotificationsCh := make(chan *ext_gnmi.Notification, 1)

        // Call the function under test
        err := receiveSubscriptions(mockClient, gnmiNotificationsCh)

        assert.NoError(t, err)

        // Assert that a SubscriptionCancelled notification was received
        assert.Equal(t, SubscriptionCancelled, <-gnmiNotificationsCh)
    })

    t.Run("NilResponse", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockSubscribeClient)
        mockClient.On("Recv").Return(nil, nil).Once()
        mockClient.On("Recv").Return(nil, io.EOF)

        // Setup channel
        gnmiNotificationsCh := make(chan *ext_gnmi.Notification, 1)

        // Call the function under test
        err := receiveSubscriptions(mockClient, gnmiNotificationsCh)
        assert.NoError(t, err)
    })

    t.Run("UnexpectedResponseType", func(t *testing.T) {
        // Setup mocks
        mockClient := new(MockSubscribeClient)
        mockClient.On("Recv").Return(&ext_gnmi.SubscribeResponse{}, nil)

        // Setup channel
        gnmiNotificationsCh := make(chan *ext_gnmi.Notification, 1)

        // Call the function under test
        err := receiveSubscriptions(mockClient, gnmiNotificationsCh)
        assert.Error(t, err)
    })
}

// ------------------- Integration Tests -------------------
// The following tests are integration tests that test the
// functions in this file with the actual gNMI server.
// ---------------------------------------------------------

// TestNewGNMIClientIntegration tests the NewGNMIClient() function
func TestNewGNMIClientIntegration(t *testing.T) {
    // Start a gRPC server
    server := grpc.NewServer()
    ext_gnmi.RegisterGNMIServer(server, &MyGNMIServer{})
    lis, _ := net.Listen("tcp", "localhost:0")
    go server.Serve(lis)
    defer server.Stop()

    // Create a gRPC connection
    conn, _ := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
    defer conn.Close()

    // Call the function under test
    clientMethods := &gNMIClientMethodsExt{}
    client, err := clientMethods.NewGNMIClient(&gRPCConnWrapperExt{ClientConn: conn})

    // Assert that there was no error and that the client is not nil
    assert.NoError(t, err)
    assert.NotNil(t, client)

    t.Run("InvalidConnType", func(t *testing.T) {
        // Setup mocks
        mockConn := new(MockInvalidConnType) // MockInvalidConnType is a mock type that does not implement iGRPCConnExt

        // Call the function under test
        clientMethods := &gNMIClientMethodsExt{}
        _, err := clientMethods.NewGNMIClient(mockConn)

        assert.Error(t, err)
    })
}

// Test GetRequestMetadata() and RequireTransportSecurity() internal grpc functions
func TestGetRequestMetadata(t *testing.T) {
    t.Run("Positive", func(t *testing.T) {

        // Setup a gRPC server
        server := grpc.NewServer()
        lis, _ := net.Listen("tcp", "localhost:0")

        // Implement the gNMI service in the server
        ext_gnmi.RegisterGNMIServer(server, &MyGNMIServer{}) // mockGNMIServer is a mock implementation of the gNMI service

        go server.Serve(lis)
        defer server.Stop()

        // Setup instance
        up := &usernamePassword{
            username: "testuser",
            password: "testpass",
        }

        // Create a gRPC connection with usernamePassword as the credentials
        conn, _ := grpc.Dial(lis.Addr().String(), grpc.WithInsecure(), grpc.WithPerRPCCredentials(up))
        defer conn.Close()

        // Create a gRPC client
        client := ext_gnmi.NewGNMIClient(conn)

        // Make a request to the server
        _, err := client.Capabilities(context.Background(), &ext_gnmi.CapabilityRequest{})

        assert.NoError(t, err)
    })

    t.Run("Negative", func(t *testing.T) {

        // Setup a gRPC server
        server := grpc.NewServer()
        lis, _ := net.Listen("tcp", "localhost:0")

        // Implement the gNMI service in the server
        ext_gnmi.RegisterGNMIServer(server, &MyGNMIServer{}) // mockGNMIServer is a mock implementation of the gNMI service

        go server.Serve(lis)
        defer server.Stop()

        // Setup instance with invalid credentials
        up := &usernamePassword{
            username: "",
            password: "",
        }

        // Create a gRPC connection with invalid usernamePassword as the credentials
        conn, _ := grpc.Dial(lis.Addr().String(), grpc.WithInsecure(), grpc.WithPerRPCCredentials(up))
        defer conn.Close()

        // Create a gRPC client
        client := ext_gnmi.NewGNMIClient(conn)

        // Make a request to the server
        _, err := client.Capabilities(context.Background(), &ext_gnmi.CapabilityRequest{})

        assert.Error(t, err)
    })

}

// TestDialIntegration tests the Dial() function of gRPCDialer
func TestDialIntegration(t *testing.T) {
    t.Run("DialContext", func(t *testing.T) {
        // Setup a gRPC server
        server := grpc.NewServer()
        lis, _ := net.Listen("tcp", "localhost:0")
        go server.Serve(lis)
        defer server.Stop()

        // Create a context with a timeout of 3 seconds
        ctx, cancel := context.WithTimeout(context.Background(), GNMI_CONN_TIMEOUT)
        defer cancel()

        // Call the function under test
        dialer := &gRPCDialer{}
        conn, err := dialer.DialContext(ctx, lis.Addr().String(), grpc.WithInsecure())

        // Assert that there was no error and that the connection is not nil
        assert.NoError(t, err)
        assert.NotNil(t, conn)

        // Clean up
        conn.Close()
    })

    t.Run("DialContextError", func(t *testing.T) {
        // Create a context with a timeout of 3 seconds
        ctx, cancel := context.WithTimeout(context.Background(), GNMI_CONN_TIMEOUT)
        defer cancel()

        // Call the function under test with an unreachable address
        dialer := &gRPCDialer{}
        _, err := dialer.DialContext(ctx, "nonexistent", grpc.WithInsecure(), grpc.WithBlock(), grpc.FailOnNonTempDialError(true))

        assert.Error(t, err)
    })
}
