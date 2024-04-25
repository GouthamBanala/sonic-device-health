package libtest

import (
    "fmt"
    "lom/src/lib/lomcommon"
    . "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "path/filepath"
    "strings"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    //"lom/src/lib/lomipc"
    //"lom/src/pluginmgr/pluginmgr_common"
    //"lom/src/plugins/plugins_common"
    //"lom/src/plugins/vendors"
    //"io/ioutil"
    "log/syslog"
    "os"

    //"path/filepath"
    "regexp"
    //"strconv"
    "sync"
    "testing"
    "time"

    //"encoding/json"
    //"errors"
    "io/ioutil"
)

func init() {
    InitSyslogWriter("")
}

//----------------------------------------- Test GoroutineTracker ---------------------------------------- //

type mockFunction struct {
    mock.Mock
}

// some dummy function to be called by the goroutine
func (m *mockFunction) exec(vv ...interface{}) {
    var timeval time.Duration = time.Duration(0) * time.Millisecond
    var wg *sync.WaitGroup = nil
    for _, v := range vv {
        switch val := v.(type) {
        case int:
            timeval = time.Duration(val) * time.Millisecond
        case *sync.WaitGroup:
            wg = val
        default:
            fmt.Println("Value is of an unknown type")
        }
    }
    time.Sleep(timeval)
    m.Called()

    if wg != nil {
        wg.Done()
    }
}

type MyStruct struct {
    Name string
}

func (s *MyStruct) Print() {
    fmt.Println(s.Name)
}

func (s *MyStruct) PrintArg(a int, b int) {
    fmt.Printf("Testing with args .......... %d %d", a, b)
}

func TestGoroutineTracker(t *testing.T) {
    mygoroutinetracker := lomcommon.GetGoroutineTracker()
    wg := sync.WaitGroup{}

    t.Run("Test - Start and Wait", func(t *testing.T) {
        //create mock object
        mockFunc := &mockFunction{}

        // set expectation
        mockFunc.On("exec").Once()

        // call mockFunc.exec in goroutine, name of goroutine is "test_goroutine" & function called is "exec"
        mygoroutinetracker.Start("test_goroutine", mockFunc.exec, 1000)

        // Check that the goroutine is running
        time.Sleep(100 * time.Millisecond) // Wait for the goroutine to start
        running, _ := mygoroutinetracker.IsRunning("test_goroutine")
        assert.True(t, running)

        // Check that the goroutine is no longer running after waiting for it
        mygoroutinetracker.Wait("test_goroutine")
        running, _ = mygoroutinetracker.IsRunning("test_goroutine")
        assert.False(t, running)

        // Check that the function exec() was called as per previous expectation
        mockFunc.AssertExpectations(t)
    })

    t.Run("Test - Start goroutine with existing name", func(t *testing.T) {
        mockFunc := &mockFunction{}
        mockFunc.On("exec").Once()
        mygoroutinetracker.Start("test_goroutine2", mockFunc.exec, 1000)

        // Attempting to start a goroutine with the same name
        assert.PanicsWithValue(t, "Cannot start goroutine, \"test_goroutine2\" as its active", func() {
            mygoroutinetracker.Start("test_goroutine2", mockFunc.exec)
        })

        mygoroutinetracker.Wait("test_goroutine2")
        running, _ := mygoroutinetracker.IsRunning("test_goroutine2")
        assert.False(t, running)

        mockFunc.AssertExpectations(t)
    })

    t.Run("Test - List goroutines statistics", func(t *testing.T) {
        mockFunc1 := &mockFunction{}
        mockFunc2 := &mockFunction{}

        // Wait for both goroutines to complete
        wg.Add(2)

        // Start two goroutines with different names
        mockFunc1.On("exec").Once()
        mygoroutinetracker.Start("test_goroutine3", mockFunc1.exec, 1000, &wg)

        mockFunc2.On("exec").Once()
        mygoroutinetracker.Start("test_goroutine4", mockFunc2.exec, 1000, &wg)

        // Check that both goroutines are running
        time.Sleep(100 * time.Millisecond) // Wait for the goroutines to start
        running, _ := mygoroutinetracker.IsRunning("test_goroutine3")
        assert.True(t, running)
        running, _ = mygoroutinetracker.IsRunning("test_goroutine4")
        assert.True(t, running)

        // Check that List returns both names
        infos := mygoroutinetracker.InfoList(nil)
        var names []string
        for _, info := range infos {
            if gi, ok := info.(lomcommon.GoroutineInfo); ok {

                names = append(names, gi.Name)

            }
        }
        assert.ElementsMatch(t, []string{"test_goroutine3", "test_goroutine4"}, names)

        // Check that both goroutines are no longer running after waiting for them
        wg.Wait()
        time.Sleep(100 * time.Millisecond) // Wait for the goroutines to finish
        running, _ = mygoroutinetracker.IsRunning("test_goroutine3")
        assert.False(t, running)
        running, _ = mygoroutinetracker.IsRunning("test_goroutine4")
        assert.False(t, running)

        mockFunc2.AssertExpectations(t)
        mockFunc1.AssertExpectations(t)
    })

    t.Run("Test - STart Time", func(t *testing.T) {
        mockFunc := &mockFunction{}
        mockFunc.On("exec").Once()

        wg.Add(1)
        mygoroutinetracker.Start("test_goroutine5", mockFunc.exec, 1000, &wg)

        funcgetstartedtime := func() string {
            infos := mygoroutinetracker.InfoList(nil)
            for _, info := range infos {
                if gi, ok := info.(lomcommon.GoroutineInfo); ok {
                    if gi.Name == "test_goroutine5" {
                        return gi.StartTime.String()
                    }
                }
            }
            return ""
        }

        // Check that the goroutine is running
        time.Sleep(100 * time.Millisecond) // Wait for the goroutine to start
        running, _ := mygoroutinetracker.IsRunning("test_goroutine5")
        assert.True(t, running)

        gottime, _ := mygoroutinetracker.GetTimeStarted("test_goroutine5")
        assert.Equal(t, funcgetstartedtime(), gottime)

        // Check that the goroutine is no longer running after waiting for it
        wg.Wait()
        time.Sleep(100 * time.Millisecond)
        running, _ = mygoroutinetracker.IsRunning("test_goroutine5")
        assert.False(t, running)

        // Now get the time for a goroutine which is not running.
        _, err := mygoroutinetracker.GetTimeStarted("test_goroutine5")
        assert.NotNil(t, err)

        // Now get the time for unknown goroutine
        gottime, err = mygoroutinetracker.GetTimeStarted("dummy_goroutine")
        assert.NotNil(t, err)
        assert.Equal(t, "", gottime)

        mockFunc.AssertExpectations(t)
    })

    t.Run("Test - List goroutines statistics for name", func(t *testing.T) {
        mockFunc1 := &mockFunction{}
        mockFunc2 := &mockFunction{}

        // Wait for both goroutines to complete
        wg.Add(2)

        // Start two goroutines with different names
        mockFunc1.On("exec").Once()
        mygoroutinetracker.Start("test_goroutine6", mockFunc1.exec, 1000, &wg)

        mockFunc2.On("exec").Once()
        mygoroutinetracker.Start("test_goroutine7", mockFunc2.exec, 1000, &wg)

        // Check that both goroutines are running
        time.Sleep(100 * time.Millisecond) // Wait for the goroutines to start
        running, _ := mygoroutinetracker.IsRunning("test_goroutine6")
        assert.True(t, running)
        running, _ = mygoroutinetracker.IsRunning("test_goroutine7")
        assert.True(t, running)

        // Check that List returns both names
        name := "test_goroutine6"
        infos := mygoroutinetracker.InfoList(&name)

        assert.Len(t, infos, 1)

        var names string
        for _, info := range infos {
            if gi, ok := info.(lomcommon.GoroutineInfo); ok {

                names = gi.Name

            }
        }
        assert.Regexp(t, name, names)

        // Check that both goroutines are no longer running after waiting for them
        wg.Wait()
        time.Sleep(100 * time.Millisecond) // Wait for the goroutines to finish
        running, _ = mygoroutinetracker.IsRunning("test_goroutine3")
        assert.False(t, running)
        running, _ = mygoroutinetracker.IsRunning("test_goroutine4")
        assert.False(t, running)

        mockFunc2.AssertExpectations(t)
        mockFunc1.AssertExpectations(t)
    })

    t.Run("PrintGoroutineInfo", func(t *testing.T) {
        mockFunc1 := &mockFunction{}
        mockFunc2 := &mockFunction{}

        // Wait for both goroutines to complete
        wg.Add(2)

        lomcommon.PrintGoroutineInfo("")

        // Start two goroutines with different names
        mockFunc1.On("exec").Once()
        mygoroutinetracker.Start("test_goroutine7", mockFunc1.exec, 1000, &wg)

        mockFunc2.On("exec").Once()
        mygoroutinetracker.Start("test_goroutine8", mockFunc2.exec, 1000, &wg)

        // Check that both goroutines are running
        time.Sleep(100 * time.Millisecond) // Wait for the goroutines to start
        running, _ := mygoroutinetracker.IsRunning("test_goroutine7")
        assert.True(t, running)
        running, _ = mygoroutinetracker.IsRunning("test_goroutine8")
        assert.True(t, running)

        lomcommon.PrintGoroutineInfo("")
        lomcommon.PrintGoroutineInfo("test_goroutine7")
        lomcommon.PrintGoroutineInfo("test_Unknown")

        // check for non running goroutines
        status, eval := mygoroutinetracker.IsRunning("test_non_existent")
        assert.False(t, status)
        pattern := `Goroutine with name ".*" doesn't exist`
        re := regexp.MustCompile(pattern)
        assert.Regexp(t, re, eval)

        // Check that both goroutines are no longer running after waiting for them
        wg.Wait()
        time.Sleep(100 * time.Millisecond) // Wait for the goroutines to finish
        running, _ = mygoroutinetracker.IsRunning("test_goroutine7")
        assert.False(t, running)
        running, _ = mygoroutinetracker.IsRunning("test_goroutine8")
        assert.False(t, running)

        mockFunc2.AssertExpectations(t)
        mockFunc1.AssertExpectations(t)
    })

    t.Run("Test API usage ways ", func(t *testing.T) {

        // Create Goroutine Tracker which will be used to track all goroutines in the process
        goroutinetracker := lomcommon.GetGoroutineTracker()
        if goroutinetracker == nil {
            panic("Error creating goroutine tracker")
        }

        goroutinetracker.Start("test", func(a int, b int) { fmt.Printf("some value %d %d", a, b) }, 10, 20)
        goroutinetracker.Start("test1", func() { fmt.Printf("some value") })
        var ptr = &MyStruct{"hello"}
        goroutinetracker.Start("test3", ptr.Print)
        goroutinetracker.Start("test4", ptr.PrintArg, 10, 20)

        //panic calls
        // goroutinetracker.Start("test5", func (a int, b int) { fmt.Printf("1111111111111111 %d %d", a,b) })
        //goroutinetracker.Start("test6", func () { fmt.Printf("1111111111111111") }, 10, 20)
        //goroutinetracker.Start("test7", ptr.Print, 10, 20)
        //goroutinetracker.Start("test8", ptr.PrintArg)

    })

    t.Run("Test waitAll", func(t *testing.T) {

        // start multiple goroutines
        mygoroutinetracker.Start("test_goroutine9", func() {
            time.Sleep(100 * time.Millisecond)
        })

        mygoroutinetracker.Start("test_goroutine10", func() {
            time.Sleep(200 * time.Millisecond)
        })

        // indefinite wait for all goroutines to complete
        status := mygoroutinetracker.WaitAll(0)
        assert.True(t, status)

        // check status of goroutines
        status, _ = mygoroutinetracker.IsRunning("test_goroutine9")
        assert.False(t, status)
        status, _ = mygoroutinetracker.IsRunning("test_goroutine10")
        assert.False(t, status)

        // start multiple goroutines
        mygoroutinetracker.Start("test_goroutine11", func() {
            time.Sleep(500 * time.Millisecond)
        })

        mygoroutinetracker.Start("test_goroutine12", func() {
            time.Sleep(500 * time.Millisecond)
        })

        // wait for all goroutines to complete
        status = mygoroutinetracker.WaitAll(100 * time.Millisecond)
        assert.False(t, status) // timeout

        status = mygoroutinetracker.WaitAll(500 * time.Millisecond)
        assert.True(t, status) // no timeout

    })
}

//------------------------------------------ End of Test GoroutineTracker ------------------------------------------//

//------------------------------------------ config.go -------------------------------------------------------------//

type mockReadFile struct {
    mock.Mock
}

func (m *mockReadFile) ReadFile(filename string) ([]byte, error) {
    args := m.Called(filename)
    return args.Get(0).([]byte), args.Error(1)
}

func TestReadProcsConf(t *testing.T) {
    testData_error := []byte(`{
        "proc_0": {
            "link_crc": {
                "name": "link_crc",
                "version": "00.01.1",
                "path": " /path/"
            },
            "link_flap"d: {
                "name": "link_flap",
                "version": "02.00.1",
                "path": " /path/"
            }
        },
        "proc_1": {
            "bgp_holddown": {
                "name": "bgp_holddown",
                "version": "02_1",
                "path": " /path/"
            }
        }
    }`)

    t.Run("success", func(t *testing.T) {
        os.Unsetenv("LOM_CONF_LOCATION")
        err := lomcommon.InitConfigPath("./")
        assert.Nil(t, err)

        config, _ := lomcommon.GetConfigMgr().GetProcsConfig("proc_0")
        assert.Equal(t, "link_crc", config["link_crc"].Name)
        assert.Equal(t, "02.00.1", config["link_flap"].Version)
    })

    t.Run("readFile_error", func(t *testing.T) {
        os.Unsetenv("LOM_CONF_LOCATION")
        err := lomcommon.InitConfigPath("./dummy/")
        assert.NotNil(t, err)

        // Define the regular expression pattern you want to match
        expectedPattern := `\bdummy\b.*\bno such file or directory\b`

        // Use assert.Regexp to match the pattern against the error message
        assert.Regexp(t, regexp.MustCompile(expectedPattern), err.Error())
    })

    t.Run("unmarshal_error", func(t *testing.T) {
        os.Unsetenv("LOM_CONF_LOCATION")
        // create the file
        err := ioutil.WriteFile("/tmp/test.json", testData_error, 0644)
        if err != nil {
            panic(err)
        }

        configFiles := &lomcommon.ConfigFiles_t{}
        configFiles.ProcsFl = "/tmp/test.json"
        configFiles.GlobalFl = "./globals.conf.json"
        configFiles.ActionsFl = "./actions.conf.json"
        configFiles.BindingsFl = "./bindings.conf.json"
        _, err = lomcommon.InitConfigMgr(configFiles)

        assert.NotNil(t, err)
        //assert.EqualError(t, err, "invalid character 'i' looking for beginning of value")
        assert.Regexp(t, regexp.MustCompile("Procs: /tmp/test.json: invalid character '.+' after object key"), err.Error())

        // delete the file
        err = os.Remove("/tmp/test.json")
        if err != nil {
            panic(err)
        }
    })

    t.Run("proc keys invalid", func(t *testing.T) {
        os.Unsetenv("LOM_CONF_LOCATION")
        configFiles := &lomcommon.ConfigFiles_t{}
        configFiles.ProcsFl = "./procs.conf.json"
        configFiles.GlobalFl = "./globals.conf.json"
        configFiles.ActionsFl = "./actions.conf.json"
        configFiles.BindingsFl = "./bindings.conf.json"
        configMgr, err := lomcommon.InitConfigMgr(configFiles)

        assert.Nil(t, err)
        config, _ := configMgr.GetProcsConfig("proc_0")
        assert.NotEqual(t, "link_crc_c", config["link_crc_c"].Name)
        assert.NotEqual(t, "dummy_path", config["link_crc"].Path)
    })

    t.Run("proc ID invalid", func(t *testing.T) {
        os.Unsetenv("LOM_CONF_LOCATION")
        configFiles := &lomcommon.ConfigFiles_t{}
        configFiles.ProcsFl = "./procs.conf.json"
        configFiles.GlobalFl = "./globals.conf.json"
        configFiles.ActionsFl = "./actions.conf.json"
        configFiles.BindingsFl = "./bindings.conf.json"

        configMgr, err := lomcommon.InitConfigMgr(configFiles)
        assert.Nil(t, err)

        _, err = configMgr.GetProcsConfig("proc_invalid_3") // proc_invalid_3 do not exist in config file
        assert.Regexp(t, regexp.MustCompile(`.*Failed to get config for proc ID \(proc_invalid_3\)`), err.Error())
    })

    t.Run("valid env path", func(t *testing.T) {
        os.Unsetenv("LOM_CONF_LOCATION")
        //originalValue := os.Getenv("ENV_lom_conf_location")
        err := os.Setenv("LOM_CONF_LOCATION", "./")
        if err != nil {
            fmt.Errorf("Error unsetting environment variable: %v", err)
        }

        err = lomcommon.InitConfigPath("")
        assert.Nil(t, err)

        config, _ := lomcommon.GetConfigMgr().GetProcsConfig("proc_0")
        assert.Equal(t, "link_crc", config["link_crc"].Name)
        assert.Equal(t, "02.00.1", config["link_flap"].Version)
    })
}

//------------------------------------------ End config.go -------------------------------------------------------------//

//------------------------------------------ REad Env variables test(helpers.go) -------------------------------------------------------------//

func TestGetEnvVarString(t *testing.T) {
    // set emnpty path and check if it returns default path
    os.Unsetenv("LOM_CONF_LOCATION")

    err := os.Setenv("LOM_CONF_LOCATION", "")
    if err != nil {
        fmt.Errorf("Error unsetting environment variable: %v", err)
    }
    lomcommon.LoadEnvironmentVariables()
    value, exists := lomcommon.GetEnvVarString("ENV_lom_conf_location")

    // Assert that the value and exists variables are correct
    assert.Equal(t, "", value)
    assert.True(t, exists)
}

//------------------------------------------ End Read Env variables test(helpers.go) -------------------------------------------------------------//

//------------------------------------------  Helper.go  Appprefix-------------------------------------------------------------//

func TestSyslogPrefix(t *testing.T) {
    lomcommon.SetPrefix("$_plugin_manager_$")

    err := lomcommon.LogError("test error")
    assert.NotNil(t, err)

    expectedPattern := `\$_plugin_manager_\$.*:test error`
    assert.Regexp(t, regexp.MustCompile(expectedPattern), err.Error())
}

//------------------------------------------ End Appprefix Helper.go  -------------------------------------------------------------//

//------------------------------------------  Helper.go  logperiodic-------------------------------------------------------------//

func TestLogPeriodic(t *testing.T) {

    t.Run("Test all wrappers", func(t *testing.T) {

        lomcommon.AddPeriodicLogNotice("ID1", "HellO message1", 30)
        time.Sleep(100 * time.Millisecond)
        err := lomcommon.UpdatePeriodicLogTime("ID1", 60) // by this API, its possible to check if the entry is present or not
        assert.Nil(t, err)

        lomcommon.AddPeriodicLogInfo("ID2", "HellO message2", 30)
        time.Sleep(100 * time.Millisecond)
        err = lomcommon.UpdatePeriodicLogTime("ID2", 60) // by this API, its possible to check if the entry is present or not
        assert.Nil(t, err)

        lomcommon.AddPeriodicLogDebug("ID3", "HellO message3", 30)
        time.Sleep(100 * time.Millisecond)
        err = lomcommon.UpdatePeriodicLogTime("ID3", 60) // by this API, its possible to check if the entry is present or not
        assert.Nil(t, err)

        lomcommon.AddPeriodicLogError("ID4", "HellO message4", 30)
        time.Sleep(100 * time.Millisecond)
        err = lomcommon.UpdatePeriodicLogTime("ID4", 60) // by this API, its possible to check if the entry is present or not
        assert.Nil(t, err)

        // test for removal
        lomcommon.RemovePeriodicLogEntry("ID1")
        time.Sleep(100 * time.Millisecond)
        err = lomcommon.UpdatePeriodicLogTime("ID1", 60) // by this API, its possible to check if the entry is present or not
        assert.NotNil(t, err)

    })

    t.Run("success", func(t *testing.T) {
        //lomcommon.RegisterForSysShutdown("plugin_manager")
        notifyChan := make(chan bool)
        initShutdown := false

        go func() {
            <-notifyChan
            lomcommon.DoSysShutdown(0)
            // lomcommon.DeregisterForSysShutdown("plugin_manager")
            initShutdown = true
        }()

        defer func() {
            if initShutdown {
                lomcommon.InitSysShutdown()
            }
        }()

        logperiodic := lomcommon.GetlogPeriodic()
        assert.NotNil(t, logperiodic)

        lomcommon.AddPeriodicLogEntry("ID5", "HellO new message", syslog.LOG_DEBUG, 30)
        time.Sleep(1 * time.Second)
        err := lomcommon.UpdatePeriodicLogTime("ID5", 60)
        assert.Nil(t, err)

        // shutdown
        notifyChan <- true

        // sleep for 3 seconds
        time.Sleep(2 * time.Second)

        // logperiodic must be deleted. SO no entried must be present
        err = lomcommon.UpdatePeriodicLogTime("ID1", 2)
        time.Sleep(100 * time.Millisecond)
        assert.NotNil(t, err)

    })

    t.Run("short long time test ", func(t *testing.T) {
        stopch := lomcommon.AddPeriodicLogWithTimeouts("PID1", "HellO message1", 2*time.Second, 4*time.Second)

        // just to check PID1 is present
        time.Sleep(100 * time.Millisecond)
        err := lomcommon.UpdatePeriodicLogTime("PID1", 1)
        time.Sleep(100 * time.Millisecond)
        assert.Nil(t, err)

        stopch <- true
        time.Sleep(100 * time.Millisecond)

        // PID1 must be removed
        err = lomcommon.UpdatePeriodicLogTime("PID1", 1)
        time.Sleep(100 * time.Millisecond)
        assert.NotNil(t, err)
    })

    t.Run("short long time test wait untill all timers expire ", func(t *testing.T) {
        stopch := lomcommon.AddPeriodicLogWithTimeouts("PID2", "HellO message1", 2*time.Second, 3*time.Second)

        time.Sleep(4000 * time.Millisecond)

        stopch <- true
        time.Sleep(100 * time.Millisecond)

        // PID1 must be removed
        err := lomcommon.UpdatePeriodicLogTime("PID1", 1)
        time.Sleep(100 * time.Millisecond)
        assert.NotNil(t, err)
    })
}

//------------------------------------------ End logperiodic Helper.go  -------------------------------------------------------------//

// ------------------------------------------ server_transport.go-------------------------------------------------------------//

func TestPrintActionRequest(t *testing.T) {
    request := &lomipc.ActionRequestData{
        Action:            "test",
        InstanceId:        "123",
        AnomalyInstanceId: "456",
        AnomalyKey:        "789",
        Timeout:           10,
        Context: []*lomipc.ActionResponseData{
            &lomipc.ActionResponseData{
                Action:            "test",
                InstanceId:        "123",
                AnomalyInstanceId: "456",
                AnomalyKey:        "789",
                Response:          "response",
                ResultCode:        0,
                ResultStr:         "success",
            },
        },
    }

    output := lomipc.PrintActionRequest(request, true)

    expectedOutput := "Action: test InstanceId: 123 AnomalyInstanceId: 456 AnomalyKey: 789 " +
        "Timeout: 10 Responses: Response 1: Action: test InstanceId: 123 AnomalyInstanceId: 456 AnomalyKey: " +
        "789 Response: response ResultCode: 0 ResultStr: success"

    if output != expectedOutput {
        t.Errorf("PrintActionRequest() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }

    output = lomipc.PrintActionRequest(nil, true)
    expectedOutput = "Invalid request"

    if output != expectedOutput {
        t.Errorf("PrintActionRequest() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }
}

func TestPrintServerRequest(t *testing.T) {
    actionRequest := lomipc.ActionRequestData{
        Action:            "test",
        InstanceId:        "123",
        AnomalyInstanceId: "456",
        AnomalyKey:        "789",
        Timeout:           10,
        Context: []*lomipc.ActionResponseData{
            &lomipc.ActionResponseData{
                Action:            "test",
                InstanceId:        "123",
                AnomalyInstanceId: "456",
                AnomalyKey:        "789",
                Response:          "response",
                ResultCode:        0,
                ResultStr:         "success",
            },
        },
    }

    shutdownRequest := lomipc.ShutdownRequestData{}

    serverRequestAction := &lomipc.ServerRequestData{
        ReqType: lomipc.TypeServerRequestAction,
        ReqData: actionRequest,
    }

    serverRequestShutdown := &lomipc.ServerRequestData{
        ReqType: lomipc.TypeServerRequestShutdown,
        ReqData: shutdownRequest,
    }

    outputAction := lomipc.PrintServerRequest(serverRequestAction, true)

    expectedOutputAction := "Action: test InstanceId: 123 AnomalyInstanceId: 456 AnomalyKey: 789 " +
        "Timeout: 10 Responses: Response 1: Action: test InstanceId: 123 AnomalyInstanceId: 456 " +
        "AnomalyKey: 789 Response: response ResultCode: 0 ResultStr: success"

    if outputAction != expectedOutputAction {
        t.Errorf("PrintServerRequest() returned unexpected output for action request. Expected: %s, Got: %s",
            expectedOutputAction, outputAction)
    }

    outputShutdown := lomipc.PrintServerRequest(serverRequestShutdown, true)

    expectedOutputShutdown := "Shutdown request"

    if outputShutdown != expectedOutputShutdown {
        t.Errorf("PrintServerRequest() returned unexpected output for shutdown request. Expected: %s, Got: %s",
            expectedOutputShutdown, outputShutdown)
    }

    // nil requeat
    output := lomipc.PrintServerRequest(nil, true)
    expectedOutput := "Invalid request"

    if output != expectedOutput {
        t.Errorf("PrintActionRequest() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }

    // unknown request
    unknownrequest := &lomipc.ServerRequestData{
        ReqData: struct{}{}, // Pass an empty struct as the request data
    }
    output = lomipc.PrintServerRequest(unknownrequest, true)
    expectedOutput = "Unknown request type: struct {}"

    if output != expectedOutput {
        t.Errorf("PrintServerRequest() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }
}

func TestPrintActionResponseData(t *testing.T) {
    response := &lomipc.ActionResponseData{
        Action:            "test",
        InstanceId:        "123",
        AnomalyInstanceId: "456",
        AnomalyKey:        "789",
        Response:          "response",
        ResultCode:        0,
        ResultStr:         "success",
    }

    output := lomipc.PrintActionResponseData(response)

    expectedOutput := "Action: test InstanceId: 123 AnomalyInstanceId: 456 AnomalyKey: 789 " +
        "Response: response ResultCode: 0 ResultStr: success"

    if output != expectedOutput {
        t.Errorf("PrintActionResponseData() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }
}

func TestPrintHeartbeatNotification(t *testing.T) {
    notification := lomipc.MsgNotifyHeartbeat{
        Action:    "test",
        Timestamp: 123,
    }

    output := lomipc.PrintHeartbeatNotification(notification)

    expectedOutput := "Heartbeat notification: test 123"

    if output != expectedOutput {
        t.Errorf("PrintHeartbeatNotification() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }
}

func TestPrintServerResponse(t *testing.T) {
    actionResponse := &lomipc.ActionResponseData{
        Action:            "test",
        InstanceId:        "123",
        AnomalyInstanceId: "456",
        AnomalyKey:        "789",
        Response:          "response",
        ResultCode:        0,
        ResultStr:         "success",
    }

    serverResponse := &lomipc.MsgSendServerResponse{
        ReqType: lomipc.TypeServerRequestAction,
        ResData: actionResponse,
    }

    output := lomipc.PrintServerResponse(serverResponse)

    expectedOutput := "Action: test InstanceId: 123 AnomalyInstanceId: 456 AnomalyKey: 789 Response: response " +
        "ResultCode: 0 ResultStr: success"

    if output != expectedOutput {
        t.Errorf("PrintServerResponse() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }

    notification := lomipc.MsgNotifyHeartbeat{
        Action:    "test",
        Timestamp: 123,
    }

    output = lomipc.PrintServerResponse(notification)

    expectedOutput = "Heartbeat notification: test 123"

    if output != expectedOutput {
        t.Errorf("TestPrintServerResponse() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }

    //invalid response
    output = lomipc.PrintServerResponse(nil)
    expectedOutput = "Unknown response type: <nil>"
    if output != expectedOutput {
        t.Errorf("PrintServerResponse() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }

    //unknown response
    unknownresponse := &lomipc.MsgSendServerResponse{
        ResData: struct{}{}, // Pass an empty struct as the response data
    }
    output = lomipc.PrintServerResponse(unknownresponse)
    expectedOutput = "Invalid response data"
    if output != expectedOutput {
        t.Errorf("PrintServerResponse() returned unexpected output. Expected: %s, Got: %s", expectedOutput, output)
    }
}

func TestSetLoMRunMode(t *testing.T) {
    // Set lomRunMode to LoMRunMode_Test
    SetLoMRunMode(LoMRunMode_Test)
    if GetLoMRunMode() != LoMRunMode_Test {
        t.Errorf("Expected lomRunMode to be 'LoMRunMode_Test', but got %v", GetLoMRunMode())
    }

    // Set lomRunMode to LoMRunMode_Prod
    SetLoMRunMode(LoMRunMode_Prod)
    if GetLoMRunMode() != LoMRunMode_Prod {
        t.Errorf("Expected lomRunMode to be 'LoMRunMode_Prod', but got %v", GetLoMRunMode())
    }
}

func TestGetSyslogFacilityLevelFromConfig(t *testing.T) {
    // Test case where JSON file can be read and parsed, and SYSLOG_FACILITY_LEVEL is found
    {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write the content of globals.conf.json to the file
        content := `{
            "VENDOR": "Arista",
            "SYSLOG_FACILITY_LEVEL" : "LOG_LOCAL4"
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call GetSyslogFacilityLevelFromConfig with the directory path of the file
        dir, _ := filepath.Split(tmpfile.Name())
        dir = strings.TrimSuffix(dir, "/")
        facilityLevel, err := GetSyslogFacilityLevelFromConfig(dir)
        if err != nil {
            t.Fatal(err)
        }

        // Check that the returned value is as expected
        expected := "LOG_LOCAL4"
        if facilityLevel != expected {
            t.Errorf("Expected %s, got %s", expected, facilityLevel)
        }
    }

    // Test case where JSON file cannot be read
    {
        _, err := GetSyslogFacilityLevelFromConfig("/nonexistent")
        if err == nil {
            t.Error("Expected error, got nil")
        }
    }

    // Test case where JSON file cannot be parsed
    {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write invalid JSON to the file
        content := `{
            "VENDOR": "Arista",
            "SYSLOG_FACILITY_LEVEL" : "LOG_LOCAL4",
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call GetSyslogFacilityLevelFromConfig with the directory path of the file
        dir, _ := filepath.Split(tmpfile.Name())
        dir = strings.TrimSuffix(dir, "/")
        _, err = GetSyslogFacilityLevelFromConfig(dir)
        if err == nil {
            t.Error("Expected error, got nil")
        }
    }

    // Test case where SYSLOG_FACILITY_LEVEL is not found
    {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write the content of globals.conf.json to the file
        content := `{
            "VENDOR": "Arista"
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call GetSyslogFacilityLevelFromConfig with the directory path of the file
        dir, _ := filepath.Split(tmpfile.Name())
        dir = strings.TrimSuffix(dir, "/")
        _, err = GetSyslogFacilityLevelFromConfig(dir)
        if err == nil {
            t.Error("Expected error, got nil")
        }
    }
}

func TestGetVendorFromConfig(t *testing.T) {
    // Test case where JSON file can be read and parsed, and VENDOR is found
    {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write the content of globals.conf.json to the file
        content := `{
            "VENDOR": "Arista",
            "SYSLOG_FACILITY_LEVEL" : "LOG_LOCAL4"
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call GetVendorFromConfig with the directory path of the file
        dir, _ := filepath.Split(tmpfile.Name())
        dir = strings.TrimSuffix(dir, "/")
        vendor, err := GetVendorFromConfig(dir)
        if err != nil {
            t.Fatal(err)
        }

        // Check that the returned value is as expected
        expected := "Arista"
        if vendor != expected {
            t.Errorf("Expected %s, got %s", expected, vendor)
        }
    }

    // Test case where JSON file cannot be parsed
    {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write invalid JSON to the file
        content := `{
            "VENDOR": "Arista",
            "SYSLOG_FACILITY_LEVEL" : "LOG_LOCAL4",
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call GetVendorFromConfig with the directory path of the file
        dir, _ := filepath.Split(tmpfile.Name())
        dir = strings.TrimSuffix(dir, "/")
        _, err = GetVendorFromConfig(dir)
        if err == nil {
            t.Error("Expected error, got nil")
        }
    }

    // Test case where VENDOR is not found
    {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }
        defer os.Remove(tmpfile.Name()) // clean up

        // Write the content of globals.conf.json to the file
        content := `{
            "SYSLOG_FACILITY_LEVEL" : "LOG_LOCAL4"
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call GetVendorFromConfig with the directory path of the file
        dir, _ := filepath.Split(tmpfile.Name())
        dir = strings.TrimSuffix(dir, "/")
        _, err = GetVendorFromConfig(dir)
        if err == nil {
            t.Error("Expected error, got nil")
        }
    }
}

func TestGetConfigFromMapping(t *testing.T) {
    // Test case where the map is empty
    {
        mapping := make(map[string]interface{})
        defaultValue := "default"
        val := GetConfigFromMapping(mapping, "key", defaultValue)
        if val != defaultValue {
            t.Errorf("Expected %s, got %v", defaultValue, val)
        }
    }

    // Test case where the key is not present in the map
    {
        mapping := map[string]interface{}{
            "otherKey": "value",
        }
        defaultValue := "default"
        val := GetConfigFromMapping(mapping, "key", defaultValue)
        if val != defaultValue {
            t.Errorf("Expected %s, got %v", defaultValue, val)
        }
    }

    // Test case where the value in the map is not of the expected type
    {
        mapping := map[string]interface{}{
            "key": 123,
        }
        defaultValue := "default"
        val := GetConfigFromMapping(mapping, "key", defaultValue)
        if val != defaultValue {
            t.Errorf("Expected %s, got %v", defaultValue, val)
        }
    }

    // Test case where the value in the map is of the expected type
    {
        mapping := map[string]interface{}{
            "key": "value",
        }
        defaultValue := "default"
        val := GetConfigFromMapping(mapping, "key", defaultValue)
        if val != mapping["key"] {
            t.Errorf("Expected %v, got %v", mapping["key"], val)
        }
    }

    // Test case where the expected type is int and the value in the map is a float64
    {
        mapping := map[string]interface{}{
            "key": 123.0,
        }
        defaultValue := 0
        val := GetConfigFromMapping(mapping, "key", defaultValue)
        if val != int(mapping["key"].(float64)) {
            t.Errorf("Expected %v, got %v", int(mapping["key"].(float64)), val)
        }
    }

    // Test case where the expected type is float64 and the value in the map is a float64
    {
        mapping := map[string]interface{}{
            "key": 123.0,
        }
        defaultValue := 0.0
        val := GetConfigFromMapping(mapping, "key", defaultValue)
        if val != mapping["key"] {
            t.Errorf("Expected %v, got %v", mapping["key"], val)
        }
    }
}

func TestSetAgentName(t *testing.T) {
    // Test case where a is not an empty string
    {
        // Call SetAgentName with a non-empty string
        SetAgentName("test")

        // Check that agentName is set to the given string
        if GetAgentName() != "test" {
            t.Errorf("Expected agentName to be 'test', got '%s'", GetAgentName())
        }
    }

    // Test case where a is an empty string
    {
        // Call SetAgentName with an empty string
        SetAgentName("")

        // Check that agentName is set to "lom"
        if GetAgentName() != "lom" {
            t.Errorf("Expected agentName to be 'lom', got '%s'", GetAgentName())
        }
    }
}

func TestValidatedVal(t *testing.T) {
    // Test case where sval is not a valid integer
    {
        // Call ValidatedVal with a non-integer string
        val := ValidatedVal("test", 10, 0, 5, "test")

        // Check that the return value is the default value
        if val != 5 {
            t.Errorf("Expected return value to be 5, got %d", val)
        }
    }

    // Test case where sval is a valid integer but is greater than max
    {
        // Call ValidatedVal with a string that represents an integer greater than max
        val := ValidatedVal("11", 10, 0, 5, "test")

        // Check that the return value is the default value
        if val != 5 {
            t.Errorf("Expected return value to be 5, got %d", val)
        }
    }

    // Test case where sval is a valid integer but is less than min
    {
        // Call ValidatedVal with a string that represents an integer less than min
        val := ValidatedVal("-1", 10, 0, 5, "test")

        // Check that the return value is the default value
        if val != 5 {
            t.Errorf("Expected return value to be 5, got %d", val)
        }
    }

    // Test case where sval is a valid integer and is within the range [min, max]
    {
        // Call ValidatedVal with a string that represents an integer within the range [min, max]
        val := ValidatedVal("7", 10, 0, 5, "test")

        // Check that the return value is the integer represented by sval
        if val != 7 {
            t.Errorf("Expected return value to be 7, got %d", val)
        }
    }
}

func TestInitSyslogWriter(t *testing.T) {
    // Set the LOM_RUN_MODE environment variable to "PROD"
    os.Setenv("LOM_RUN_MODE", "PROD")
    defer os.Unsetenv("LOM_RUN_MODE") // clean up

    // Define all log levels
    logLevels := []string{
        "LOG_LOCAL0",
        "LOG_LOCAL1",
        "LOG_LOCAL2",
        "LOG_LOCAL3",
        "LOG_LOCAL4",
        "LOG_LOCAL5",
        "LOG_LOCAL6",
        "LOG_LOCAL7",
        "INVALID", // This will test the default case
    }

    for _, level := range logLevels {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }

        content := `{
            "SYSLOG_FACILITY_LEVEL" : "` + level + `",
            "VENDOR": "Arista"
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call InitSyslogWriter
        InitSyslogWriter("/tmp")

        // Remove the file to clean up
        os.Remove(tmpfile.Name())

    }
}

func TestInitSyslogWriterwithPrefix(t *testing.T) {
    // Set the LOM_RUN_MODE environment variable to "PROD"
    os.Setenv("LOM_RUN_MODE", "PROD")
    defer os.Unsetenv("LOM_RUN_MODE") // clean up

    // Define all log levels
    logLevels := []string{
        "LOG_LOCAL0",
        "LOG_LOCAL1",
        "LOG_LOCAL2",
        "LOG_LOCAL3",
        "LOG_LOCAL4",
        "LOG_LOCAL5",
        "LOG_LOCAL6",
        "LOG_LOCAL7",
        "INVALID", // This will test the default case
    }

    for _, level := range logLevels {
        // Create a file named globals.conf.json in /tmp
        tmpfile, err := os.Create("/tmp/globals.conf.json")
        if err != nil {
            t.Fatal(err)
        }

        content := `{
            "SYSLOG_FACILITY_LEVEL" : "` + level + `",
            "VENDOR": "Arista"
        }`
        if _, err := tmpfile.Write([]byte(content)); err != nil {
            t.Fatal(err)
        }
        if err := tmpfile.Close(); err != nil {
            t.Fatal(err)
        }

        // Call InitSyslogWriter
        InitSyslogWriter("/tmp")

        // Set apprefix and agentName
        SetPrefix("TestPrefix")
        SetAgentName("TestAgent")

        // Test LogMessageWithSkip
        message := LogMessageWithSkip(1, syslog.LOG_INFO, "Test message")
        expectedStart := fmt.Sprintf("%s-\\d+-%s: .*:Test message", GetAgentName(), GetPrefix())
        match, _ := regexp.MatchString(expectedStart, message)
        if !match {
            t.Errorf("Expected message to match '%s', got '%s'", expectedStart, message)
        }

        // Remove the file to clean up
        os.Remove(tmpfile.Name())
    }
}
