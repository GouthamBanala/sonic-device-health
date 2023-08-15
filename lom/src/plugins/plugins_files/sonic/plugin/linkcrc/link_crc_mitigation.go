/*
 * package plugins_files contains all plugins. Each plugin is a go file with a struct that implements Plugin interface.
 * Example Plugin Implementation for reference purpose only
 */

package linkcrc

import (
	"fmt"
	"io"
	"lom/src/lib/lomcommon"
	"lom/src/lib/lomipc"
	"lom/src/plugins/plugins_common"
	"net"
	"time"
)

type LinkCRCMitigation struct {
    // ... Internal plugin data
}

func NewLinkCRCMitigation(...interface{}) plugins_common.Plugin {
    // ... initialize internal plugin data

    // ... create and return a new instance of MyPlugin
    return &LinkCRCMitigation{}
}

func init() {
    // ... register the plugin with plugin manager
    //if lomcommon.GetLoMRunMode() == lomcommon.LoMRunMode_Test {
    plugins_common.RegisterPlugin("link_crc_mitigation", NewLinkCRCMitigation)
    lomcommon.LogInfo("LinkCRCMitigation : In init() for (%s)", "link_crc_mitigation")
    //}
}

func (gpl *LinkCRCMitigation) Init(actionCfg *lomcommon.ActionCfg_t) error {
    lomcommon.LogInfo("LinkCRCMitigation : Started Init() for (%s)", "link_crc_mitigation")
    time.Sleep(2 * time.Second)

    return nil
}

func (gpl *LinkCRCMitigation) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    lomcommon.LogInfo("LinkCRCMitigation : Started Request() for (%s)", "LinkCRCMitigation")
    time.Sleep(2 * time.Second)

    if len(request.Context) == 0 || request.Context[0] == nil || request.Context[0].AnomalyKey == "" {
        return &lomipc.ActionResponseData{
            Action:            request.Action,
            InstanceId:        request.InstanceId,
            AnomalyInstanceId: request.AnomalyInstanceId,
            AnomalyKey:        request.AnomalyKey,
            Response:          "",
            ResultCode:        -1,
            ResultStr:         "Missing ifname ctx",
        }
    }

    lomcommon.LogInfo("LinkCRCMitigation : Request() for (%s) ifname=%s", "LinkCRCMitigation", request.Context[0].AnomalyKey)

    ifname := request.Context[0].AnomalyKey
    ret := 0
    retStr := ""

    if ifname != "" {
        cmd := fmt.Sprintf("sudo config int shutdown %s", ifname)
        _, err := getCommandOutput(cmd)
        if err != nil {
            lomcommon.LogError("LinkCRCMitigation : %v", err.Error())
            ret = -1
            retStr = fmt.Sprintf("link_crc_mitigation : Error shutting down link %s", ifname)
        } else {
            retStr = fmt.Sprintf("link_crc_mitigation : Brought down link %s", ifname)
        }
    } else {
        ret = -1
        retStr = "link_crc_mitigation : Missing ifname "
    }

    lomcommon.LogError(fmt.Sprintf("ret=%d ret_str=%s", ret, retStr))

    // return data from request
    return &lomipc.ActionResponseData{
        Action:            request.Action,
        InstanceId:        request.InstanceId,
        AnomalyInstanceId: request.AnomalyInstanceId,
        AnomalyKey:        request.AnomalyKey,
        Response:          "",
        ResultCode:        ret,    // or non zero
        ResultStr:         retStr, // or "Failure"
    }
}

var (
    socketPath = "/var/run/redis/lom_unix_socket" // Temporary. change it to proper path
)

func getCommandOutput(command string) ([]byte, error) {
    conn, err := net.Dial("unix", socketPath)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to Unix domain socket: %w", err)
    }
    defer conn.Close()

    _, err = conn.Write([]byte(command))
    if err != nil {
        return nil, fmt.Errorf("failed to write command to Unix domain socket: %w", err)
    }

    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        if err == io.EOF {
            // No output to read, return an empty slice
            return []byte{}, nil
        }
        return nil, fmt.Errorf("failed to read output from Unix domain socket: %w", err)
    }

    return buf[:n], nil
}

func (gpl *LinkCRCMitigation) Shutdown() error {
    // ... implementation

    lomcommon.LogInfo("LinkCRCMitigation : Started Shutdown() for (%s)", "LinkCRCMitigation")
    time.Sleep(3 * time.Second)

    return nil
}

func (gpl *LinkCRCMitigation) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    "link_crc_mitigation",
        Version: "1.0.0.0",
    }
}
