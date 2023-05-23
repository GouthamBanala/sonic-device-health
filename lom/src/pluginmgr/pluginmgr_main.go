package main

import (
    "log/syslog"
    "lom/src/lib/lomcommon"
    "lom/src/pluginmgr/pluginmgr_common"
)

func main() {
    // setup logging
    lomcommon.SetLogLevel(syslog.LOG_INFO)

    lomcommon.LogInfo("plugin_mgr : Starting Plugin Manager")

    if err := pluginmgr_common.SetupPluginManager(); err != nil {
        lomcommon.LogPanic("plugin_mgr : SetupPluginManager failed") // exits
    }
    if err := pluginmgr_common.StartPluginManager(0); err != nil {
        lomcommon.LogPanic("plugin_mgr : StartPluginManager failed") // exits
    }

    lomcommon.LogInfo("plugin_mgr : Exiting plugin manager")
}
