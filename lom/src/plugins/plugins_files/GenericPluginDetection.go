/*
 * package plugins_files contains all plugins. Each plugin is a go file with a struct that implements Plugin interface.
 * Example Plugin Implementation for reference purpose only
 */

package plugins_files

import (
    "lom/src/lib/lomcommon"
    "lom/src/lib/lomipc"
    "lom/src/plugins/plugins_common"
    "sync"
    "time"
)

type GenericPluginDetection struct {
    // ... Internal plugin data
    stopSignal chan struct{}  // Channel to signal goroutine to stop
    wg         sync.WaitGroup // WaitGroup to wait for goroutine to complete
    ticker     *time.Ticker   // Ticker to control heartbeat interval
}

func NewGenericPluginDetection(...interface{}) plugins_common.Plugin {
    // ... initialize internal plugin data

    // ... create and return a new instance of MyPlugin
    return &GenericPluginDetection{}
}

func init() {
    // ... register the plugin with plugin manager
    if lomcommon.GetLoMRunMode() == lomcommon.LoMRunMode_Test {
        plugins_common.RegisterPlugin("GenericPluginDetection", NewGenericPluginDetection)
    }
}

func (gpl *GenericPluginDetection) Init(actionCfg *lomcommon.ActionCfg_t) error {
    // ... implementation

    time.Sleep(2 * time.Second)
    return nil
}

func (gpl *GenericPluginDetection) Request(hbchan chan plugins_common.PluginHeartBeat, request *lomipc.ActionRequestData) *lomipc.ActionResponseData {
    // ... implementation

    gpl.stopSignal = make(chan struct{})
    gpl.ticker = time.NewTicker(2 * time.Second) // Heartbeat interval: 2 seconds

    lomcommon.GetGoroutineTracker().Start("GenericPluginDetection_request_"+"_"+plugins_common.GetUniqueID(), func() {
        defer gpl.wg.Done() // Mark the goroutine as completed when it exits

        for {
            select {
            case <-gpl.stopSignal: // Check if the stopSignal channel is closed
                return // Exit the goroutine if the stopSignal channel is closed
            case <-gpl.ticker.C:
                // ... implementation. Send heartbeats to hbchan to indicate progress
                hbchan <- plugins_common.PluginHeartBeat{
                    PluginName: "GenericPluginDetection",
                    EpochTime:  time.Now().Unix(),
                }
            }
        }
    })

    time.Sleep(10 * time.Second)

    // return data from request
    return &lomipc.ActionResponseData{
        Action:            request.Action,
        InstanceId:        request.InstanceId,
        AnomalyInstanceId: request.AnomalyInstanceId,
        AnomalyKey:        "Ethernet10",
        Response:          "Detected Issue on Ethernet10",
        ResultCode:        0,         // or non zero
        ResultStr:         "Success", // or "Failure"
    }
}

func (gpl *GenericPluginDetection) Shutdown() error {
    // ... implementation

    // Signal the goroutine to stop by closing the stopSignal channel
    if gpl.stopSignal != nil {
        close(gpl.stopSignal)
        gpl.stopSignal = nil
    }

    // Wait for the goroutine to complete
    gpl.wg.Wait()

    // Stop the ticker
    if gpl.ticker != nil {
        gpl.ticker.Stop()
        gpl.ticker = nil
    }

    return nil
}

func (gpl *GenericPluginDetection) GetPluginID() plugins_common.PluginId {
    return plugins_common.PluginId{
        Name:    "GenericPluginDetection",
        Version: "1.0",
    }
}
