#!/bin/bash

# Function to print LoMEngine process
print_lomengine() {
  engine_pid=$(pgrep -f "/usr/bin/LoMEngine")
  if [ -n "$engine_pid" ]; then
    echo "LoMEngine is running (PID: $engine_pid)"
  else
    echo "LoMEngine is not running"
  fi
}

# Function to print LoMPluginMgr processes by proc ID
print_lompluginmgr() {
  pluginmgr_pids=$(pgrep -f "/usr/bin/LoMPluginMgr -proc_id=")
  if [ -n "$pluginmgr_pids" ]; then
    echo "LoMPluginMgr instances:"
    echo "$pluginmgr_pids" | while read -r pid; do
      proc_id=$(ps -p $pid -o args= | awk -F'-proc_id=' '{print $2}' | awk '{print $1}')
      echo "  PID: $pid, Proc ID: $proc_id"
    done
  else
    echo "No LoMPluginMgr instances are running"
  fi
}

# Print both LoMEngine and LoMPluginMgr processes
print_processes() {
  echo "Processes:"
  print_lomengine
  print_lompluginmgr
}

# Call the function to print processes
print_processes
