/*
 * package plugins_files contains all plugins. Each plugin is a go file with a struct that implements Plugin interface.
 * Example Plugin Implementation for reference purpose only
 */

package linkcrc

import (
	"fmt"
	"lom/src/lib/lomcommon"
	"lom/src/lib/lomipc"
	"lom/src/plugins/plugins_common"
	"strconv"
	"strings"
	"time"
)

type LinkCRCSafety struct {
    // ... Internal plugin data
    minUpCount float64
}

func NewLinkCRCSafety(...interface{}) plugins_common.Plugin {
    // ... initialize internal plugin data

    // ... create and return a new instance of MyPlugin
    return &LinkCRCSafety{}
}

func init() {
    // ... register the plugin with plugin manager
    //if lomcommon.GetLoMRunMode() == lomcommon.LoMRunMode_Test {
    plugins_common.RegisterPlugin("link_crc_safety", NewLinkCRCSafety)
    lomcommon.LogInfo("LinkCRCSafety : In init() for (%s)", "link_crc_safety")
    //}
}

func (gpl *LinkCRCSafety) Init(actionCfg *lomcommon.ActionCfg_t) error {
    lomcommon.LogInfo("LinkCRCSafety : Started Init() for (%s)", "link_crc_safety")
    time.Sleep(2 * time.Second)

    gpl.minUpCount = 80

    return nil
}

func (gpl *LinkCRCSafety) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {

    lomcommon.LogInfo("LinkCRCSafety : Started Request() for (%s)", "LinkCRCSafety")
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

    lomcommon.LogInfo("LinkCRCSafety : Request() for (%s) ifname=%s", "LinkCRCSafety", request.Context[0].AnomalyKey)
    ret, retStr := checkInterfaceStatus(request.Context[0].AnomalyKey, gpl.minUpCount)

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

func checkInterfaceStatus(ifname string, min float64) (int, string) {
    ret := -1
    retStr := ""

    if ifname != "" {
        upCntOutput, err := getCommandOutput("show int status | grep -v down | wc -l")
        if err != nil {
            retStr = err.Error()
            return ret, retStr
        }
        upCnt := strings.TrimSpace(string(upCntOutput))

        downCntOutput, err := getCommandOutput("show int status | grep down | wc -l")
        if err != nil {
            retStr = err.Error()
            return ret, retStr
        }
        downCnt := strings.TrimSpace(string(downCntOutput))

        upFloat, err := strconv.ParseFloat(upCnt, 64)
        if err != nil {
            retStr = err.Error()
            return ret, retStr
        }

        downFloat, err := strconv.ParseFloat(downCnt, 64)
        if err != nil {
            retStr = err.Error()
            return ret, retStr
        }

        res := 100 * upFloat / (upFloat + downFloat)

        if res >= min {
            ret = 0
            retStr = fmt.Sprintf("link_crc_safety: Success : Has %.2f percent up. Min: %.2f", res, min)
        } else {
            retStr = fmt.Sprintf("link_crc_safety: Fail : Has %.2f percent up. Min: %.2f", res, min)
        }
    } else {
        ret = -1
        retStr = "link_crc_safety: Missing ifname "
    }

    lomcommon.LogInfo(fmt.Sprintf("link_crc_safety: ret=%d ret_str=%s", ret, retStr))

    return ret, retStr
}

func (gpl *LinkCRCSafety) Shutdown() error {
    // ... implementation

    lomcommon.LogInfo("LinkCRCSafety : Started Shutdown() for (%s)", "LinkCRCSafety")
    time.Sleep(3 * time.Second)

    return nil
}

func (gpl *LinkCRCSafety) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    "link_crc_safety",
        Version: "1.0.0.0",
    }
}
