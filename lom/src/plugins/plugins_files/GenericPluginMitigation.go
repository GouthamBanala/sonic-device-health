/*
 * package plugins_files contains all plugins. Each plugin is a go file with a struct that implements Plugin interface.
 * Example Plugin Implementation for reference purpose only
 */

package plugins_files

import (
    "fmt"
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "lom/src/plugins/plugins_common"
    "os/exec"
    "time"
)

type GenericPluginMitigation struct {
    // ... Internal plugin data
}

func NewGenericPluginMitigation(...interface{}) plugins_common.Plugin {
    // ... initialize internal plugin data

    // ... create and return a new instance of MyPlugin
    return &GenericPluginMitigation{}
}

func init() {
    // ... register the plugin with plugin manager
    if lomcommon.GetLoMRunMode() == lomcommon.LoMRunMode_Test {
        plugins_common.RegisterPlugin("GenericPluginMitigation", NewGenericPluginMitigation)
        lomcommon.LogInfo("GenericPluginMitigation : In init() for (%s)", "GenericPluginMitigation")
    }
}

func (gpl *GenericPluginMitigation) Init(actionCfg *lomcommon.ActionCfg_t) error {
    lomcommon.LogInfo("GenericPluginMitigation : Started Init() for (%s)", "GenericPluginMitigation")
    time.Sleep(2 * time.Second)

    return nil
}

func (gpl *GenericPluginMitigation) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    lomcommon.LogInfo("GenericPluginMitigation : Started Request() for (%s)", "GenericPluginMitigation")
    time.Sleep(10 * time.Second)

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

    lomcommon.LogInfo("GenericPluginMitigation : Request() for (%s) ifname=%s", "GenericPluginMitigation", request.Context[0].AnomalyKey)

    ifname := request.Context[0].AnomalyKey
    ret := 0
    retStr := ""

    if ifname != "" {
        cmd := exec.Command("sudo", "config", "int", "shutdown", ifname)
        err := cmd.Run()
        if err != nil {
            lomcommon.LogError("GenericPluginMitigation : %v", err.Error())
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

func (gpl *GenericPluginMitigation) Shutdown() error {
    // ... implementation

    lomcommon.LogInfo("GenericPluginMitigation : Started Shutdown() for (%s)", "GenericPluginMitigation")
    time.Sleep(3 * time.Second)

    return nil
}

func (gpl *GenericPluginMitigation) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    "GenericPluginMitigation",
        Version: "1.0",
    }
}
