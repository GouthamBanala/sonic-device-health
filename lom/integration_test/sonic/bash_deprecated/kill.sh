#!/bin/bash

# Function to kill LoMEngine
kill_lomengine() {
  engine_pid=$(pgrep -f "/usr/bin/LoMEngine")
  if [ -n "$engine_pid" ]; then
    echo "Killing LoMEngine (PID: $engine_pid)..."
    kill $engine_pid
    echo "LoMEngine killed."
  else
    echo "LoMEngine is not running."
  fi
}

# Function to kill all LoMPluginMgr instances
kill_lompluginmgr() {
  pluginmgr_pids=$(pgrep -f "/usr/bin/LoMPluginMgr -proc_id=")
  if [ -n "$pluginmgr_pids" ]; then
    echo "Killing LoMPluginMgr instances..."
    echo "$pluginmgr_pids" | while read -r pid; do
      echo "Killing LoMPluginMgr (PID: $pid)..."
      kill $pid
    done
    echo "LoMPluginMgr instances killed."
  else
    echo "No LoMPluginMgr instances are running."
  fi
}

# Print usage information
print_usage() {
  echo "Usage: ./kill_script.sh [all|engine|plugin]"
  echo "  all    : Kill both LoMEngine and LoMPluginMgr"
  echo "  engine : Kill LoMEngine"
  echo "  plugin : Kill all LoMPluginMgr instances"
}

# Check the argument
case "$1" in
  all)
    kill_lomengine
    kill_lompluginmgr
    ;;
  engine)
    kill_lomengine
    ;;
  plugin)
    kill_lompluginmgr
    ;;
  *)
    print_usage
    exit 1
    ;;
esac
