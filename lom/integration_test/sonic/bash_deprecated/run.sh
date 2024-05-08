#!/bin/bash

# Function to stop the processes and exit gracefully
stop_processes() {
  echo "Stopping LoMEngine pid : $engine_pid  and LoMPluginMgr pid :pluginmgr_pid ..."
  kill $engine_pid $pluginmgr_pid >/dev/null 2>&1
  echo "LoMEngine and LoMPluginMgr stopped."
  exit 0
}

# Trap the Ctrl+C signal and call the function to stop processes
trap stop_processes SIGINT

# proc Id
proc_id="proc_0"

# Check if LoMEngine binary exists
if [ ! -f "bin/LoMEngine" ]; then
    echo "Error: LoMEngine binary not found."
    exit 1
fi

# Check if LoMPluginMgr binary exists
if [ ! -f "bin/LoMPluginMgr" ]; then
    echo "Error: LoMPluginMgr binary not found."
    exit 1
fi

# Get the absolute path of the current directory
abs_path=$(pwd)

# Set environment variables
#/home/admin/int_test/config_files/
#
export LOM_CONF_LOCATION="$abs_path/config_files/"
export LOM_RUN_MODE="PROD"
echo "LOM_CONF_LOCATION=$LOM_CONF_LOCATION, LOM_RUN_MODE=$LOM_RUN_MODE"

# Check if LoMEngine is already running
engine_pid=$(pgrep -f "LoMEngine -path=")
#engine_pid=$(pgrep -f "LoMEngine")
if [ -n "$engine_pid" ]; then
    echo "Error: LoMEngine is already running with PID $engine_pid. Exiting test now"
    echo "To kill the process, run: kill $engine_pid"
    exit 1
fi

# Check if LoMPluginMgr is already running with the same -proc_id argument
existing_proc_id=$(pgrep -f "LoMPluginMgr -proc_id=$proc_id")
if [ -n "$existing_proc_id" ]; then
    echo "Error: LoMPluginMgr is already running with the same -proc_id=$proc_id. Exiting test now"
    echo "It is recommended to use a unique -proc_id argument for each instance."
    echo "To kill the process, run: kill $existing_proc_id"
    exit 1
fi

# Start LoMEngine with 'path' argument as the conf file location, running it in the background
./bin/LoMEngine -path="$LOM_CONF_LOCATION" >/dev/null 2>&1 &
#./bin/LoMEngine  >/dev/null 2>&1 &

# Store the PID of the LoMEngine process
engine_pid=$!

# Wait for a few seconds to allow the processes to start
sleep 2

# Check if LoMEngine started
if ps -p $engine_pid > /dev/null; then
    echo "LoMEngine started successfully. PID: $engine_pid"
else
    echo "Error: LoMEngine failed to start."
    exit 1
fi

# Print all running instances of LoMPluginMgr
running_instances=$(pgrep -f "LoMPluginMgr -proc_id=")
if [ -n "$running_instances" ]; then
    echo "Warning: The following instances of LoMPluginMgr are already running:"
    for pid in $running_instances; do
        cmd_line=$(ps -o cmd --no-headers -p $pid)
        echo "PID: $pid, Command: $cmd_line"
    done
fi

# Start LoMPluginMgr with arguments, running it in the background
./bin/LoMPluginMgr -proc_id="$proc_id" -syslog_level=7 >/dev/null 2>&1 &

# Store the PID of the LoMPluginMgr process
pluginmgr_pid=$!

# Wait for a few seconds to allow the processes to start
sleep 2

# Check if LoMPluginMgr started
if ps -p $pluginmgr_pid > /dev/null; then
    echo "LoMPluginMgr started successfully for proc ID : $proc_id, PID: $pluginmgr_pid"
else
    echo "Error: LoMPluginMgr failed to start for proc ID $proc_id."
    exit 1
fi

# Both binaries started successfully
echo "LoMEngine and LoMPluginMgr started successfully. Waiting for them to finish ...."

# Wait for both processes to finish
wait $engine_pid
engine_exit_code=$?

wait $pluginmgr_pid
pluginmgr_exit_code=$?

# Check the exit codes of both processes
if [ $engine_exit_code -ne 0 ]; then
    echo "Error: LoMEngine failed with exit code $engine_exit_code."
    exit 1
fi

if [ $pluginmgr_exit_code -ne 0 ]; then
    echo "Error: LoMPluginMgr failed with exit code $pluginmgr_exit_code."
    exit 1
fi

# Both binaries ran successfully
echo "LoMEngine and LoMPluginMgr ran successfully."
