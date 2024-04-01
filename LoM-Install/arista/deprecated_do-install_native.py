# Description: This script is used to start LoMEngine and LoMPluginMgr binaries.
#  It also does following checks:
#   1. Check if the configuration files exist
#   2. Check if the LoMEngine binary exists
#   3. Check if the LoMPluginMgr binary exists
#   4. Check if LoMEngine is already running. If so kill the process and restart it
#   5. Check if LoMPluginMgr is already running. If so kill the process and restart it
#   6. Check if LoMEngine and LoMPluginMgr started successfully

# Usage: python3 do-install.py

# To-Do List:
# 1. Handle exit errors gracefully
# 2. Add logging
# 3. Add unit tests

from __future__ import print_function  # Python 2/3 compatibility
import os
import subprocess
import signal
import time
import json
import sys

'''
# Function to stop the processes and exit gracefully
def stop_processes(engine_pid, plugin_mgr_pids):
    print("Stopping LoMEngine pid: {} and LoMPluginMgr pids: {} ...".format(engine_pid, plugin_mgr_pids))
    os.kill(engine_pid, signal.SIGTERM)  # Send SIGTERM to LoMEngine
    for pid in plugin_mgr_pids:
        os.kill(pid, signal.SIGTERM)  # Send SIGTERM to each LoMPluginMgr process
    print("LoMEngine and LoMPluginMgr stopped.")
    sys.exit(0)

# Trap the Ctrl+C signal and call the function to stop processes
def signal_handler(signal, frame):
    stop_processes(engine_pid, plugin_mgr_pids)
'''

# Function to get proc keys
def get_procs_keys(script_dir):
    try:
        # Read the contents of procs.conf.json
        with open(os.path.join(script_dir, '..', 'config', 'procs.conf.json'), 'r') as f:
            data = json.load(f)
        # Get the keys under the "procs" object
        procs_keys = list(data.get('procs', {}).keys())  # Convert to list for Python 2.7
        # Check if the "procs" object is empty
        if not procs_keys:
            print("Error: The 'procs' object is empty in procs.conf.json.")
            sys.exit(1)
        # Print the keys
        print("procs.conf.json keys: " + str(procs_keys))
        return procs_keys
    except IOError as e:
        print("Error: procs.conf.json not found in the specified path. {}".format(e))
        sys.exit(1)
    except ValueError as e:
        print("Error: Failed to decode procs.conf.json.{}".format(e))
        sys.exit(1)
    except Exception as e:
        print("Error: An unexpected error occurred while reading procs.conf.json. {}".format(e))
        sys.exit(1)
        

# Check if at least one argument was provided
if len(sys.argv) < 2:
    print("Error: Please provide at least one argument.")
    sys.exit(1)

# Get the first argument passed to the script
arg1 = sys.argv[1]

# Print the value of the argument
print("Installation option : ", arg1)

#signal.signal(signal.SIGINT, signal_handler)

# Get the directory where this script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
print("Script directory: " + str(script_dir))

# Specify the names of the configuration files
config_files = ['actions.conf.json', 'bindings.conf.json', 'globals.conf.json', 'procs.conf.json']

# Check if each configuration file exists
for config_file in config_files:
    config_file_path = os.path.join(script_dir, '..', 'config', config_file)
    if not os.path.exists(config_file_path):
        print("Error: {} not found.".format(config_file))
        sys.exit(1)

# Check if LoMEngine binary exists
lom_engine_path = os.path.join(script_dir, 'LoMEngine')
if not os.path.exists(lom_engine_path):
    print("Error: LoMEngine binary not found.")
    sys.exit(1)

# Check if LoMPluginMgr binary exists
lom_plugin_mgr_path = os.path.join(script_dir, 'LoMPluginMgr')
if not os.path.exists(lom_plugin_mgr_path):
    print("Error: LoMPluginMgr binary not found.")
    sys.exit(1)

# Construct the path to the 'config' directory based on the script's location
config_dir = os.path.join(script_dir, '..', 'config')

# Set environment variables
#os.environ["LOM_CONF_LOCATION"] = os.path.abspath(config_dir)
#os.environ["LOM_RUN_MODE"] = "PROD"

# Print the environment variables to verify
#print("LOM_CONF_LOCATION={}, LOM_RUN_MODE={}".format(os.environ['LOM_CONF_LOCATION'], os.environ['LOM_RUN_MODE']))

# Get the list of proc IDs from procs.conf.json
procs_keys = get_procs_keys(script_dir)

# Get all running instances of LoMPluginMgr and kill them
running_instances_bytes = subprocess.Popen(["pgrep", "-f", "install/LoMPluginMgr -proc_id="], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
running_instances = running_instances_bytes.decode('utf-8').split('\n')

# Remove any empty strings from the list
running_instances = [pid for pid in running_instances if pid.strip()]

# For each running instance, get the proc_id from the command line arguments and kill the process
for instance in running_instances:
    pid = instance.strip()
    # Get the command line of the process
    try:
        cmd_line = subprocess.check_output(["ps", "-o", "cmd", "--no-headers", "-p", pid], stderr=subprocess.STDOUT).decode('utf-8').strip()
        # Try to extract proc_id from the command line arguments
        try:
            proc_id = cmd_line.split('-proc_id=')[1].split()[0]
            print("proc_id: {}".format(proc_id))
        except IndexError:
            print("Error: Could not extract proc_id from command line: {}".format(cmd_line))
            sys.exit(1)  # Exit the script with an error code
        print("Command line: {}".format(cmd_line))
        print("Killing LoMPluginMgr instance with PID: {}, Command: {}".format(pid, cmd_line))
        # Kill the process
        try:
            os.kill(int(pid), signal.SIGTERM)
        except OSError:
            print("Error: Process with PID {} not found.".format(pid))
            sys.exit(1)  # Exit the script with an error code
        except Exception as e:
            print("Error: An unexpected error occurred while killing PID {}: {}".format(pid, str(e)))
            sys.exit(1)  # Exit the script with an error code
        time.sleep(2)  # wait for the process to terminate
    except subprocess.CalledProcessError as e:
        print("Error: Unable to retrieve command line for PID {}. Error: {}".format(pid, e.output.decode('utf-8').strip()))
        sys.exit(1)  # Exit the script with an error code

# Check if LoMEngine is already running. If so kill the process and restart it
engine_pids_bytes = subprocess.Popen(["pgrep", "-f", "install/LoMEngine"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
engine_pids = engine_pids_bytes.decode('utf-8').split('\n')

# Remove any empty strings from the list
engine_pids = [pid for pid in engine_pids if pid.strip()]

# Check if there are running instances of LoMEngine
if len(engine_pids) > 0:
    try:
        if len(engine_pids) > 1:
            print("Warning: Multiple instances of LoMEngine are running. Killing all instances now.")
            for pid in engine_pids:
                os.kill(int(pid), signal.SIGTERM)
                time.sleep(2)  # Wait for the process to terminate
        else:
            engine_pid = engine_pids[0]
            print("LoMEngine is already running with PID {}. Killing it now.".format(engine_pid))
            try:
                os.kill(int(engine_pid), signal.SIGTERM)
                time.sleep(2)  # Wait for the process to terminate
            except OSError:
                print("Error: Process with PID {} not found.".format(engine_pid))
                sys.exit(1)  # Exit the script with an error code
    except Exception as e:
        print("Error: An unexpected error occurred while killing the LoMEngine process: {}".format(str(e)))
        sys.exit(1)  # Exit the script with an error code

# set the command line arguments 
run_mode = "PROD"

# Start LoMEngine running it in the background
try:
    engine_process = subprocess.Popen([lom_engine_path, "-path={}".format(config_dir), "-mode={}".format(run_mode)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    engine_pid = engine_process.pid
except Exception as e:
    print("Error: Failed to start LoMEngine from path: {}. Exception: {}".format(lom_engine_path, str(e)))
    sys.exit(1)

# Wait for a few seconds to allow the processes to start
time.sleep(2)

# Check if LoMEngine started
if engine_process.poll() is None:
    print("LoMEngine started successfully. PID: {}, path: {}".format(engine_pid, lom_engine_path))
else:
    print("Error: LoMEngine failed to start from path: {}".format(lom_engine_path))
    sys.exit(1)


# Iterate over each proc_id in procs_keys and start LoMPluginMgr for each proc_id
plugin_mgr_pids = []
pluginmgr_process_list = []
for proc_id in procs_keys:
    try:
        # Start LoMPluginMgr with arguments, running it in the background
        pluginmgr_process = subprocess.Popen([lom_plugin_mgr_path, "-proc_id={}".format(proc_id), "-syslog_level=7", "-path={}".format(config_dir), "-mode={}".format(run_mode)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pluginmgr_pid = pluginmgr_process.pid
        plugin_mgr_pids.append(pluginmgr_pid)
        pluginmgr_process_list.append(pluginmgr_process)

        # Wait for a few seconds to allow the processes to start
        time.sleep(2)

        # Check if LoMPluginMgr started
        if pluginmgr_process.poll() is None:
            print("LoMPluginMgr started successfully for proc ID: {}, PID: {}, path: {}".format(proc_id, pluginmgr_pid, lom_plugin_mgr_path))
        else:
            print("Error: LoMPluginMgr failed to start for proc ID: {}, path: {}".format(proc_id, lom_plugin_mgr_path))
            sys.exit(1)
    except Exception as e:
        print("Error: Failed to start LoMPluginMgr for proc ID: {} path: {}. Exception: {}".format(proc_id, lom_plugin_mgr_path, str(e)))
        sys.exit(1)

# Both binaries started successfully
print("LoMEngine and LoMPluginMgr started successfully.")

'''
# Wait for both processes to finish
engine_exit_code = engine_process.wait()

# Check the exit code of engine process
if engine_exit_code != 0:
    print("Error: LoMEngine failed with exit code {}.".format(engine_exit_code))
    sys.exit(1)

# Iterate over the list of plugin manager processes
for i, pluginmgr_process in enumerate(pluginmgr_process_list):
    pluginmgr_exit_code = pluginmgr_process.wait()

    # Check the exit code of each plugin manager process
    if pluginmgr_exit_code != 0:
        print("Error: LoMPluginMgr for proc ID: {} failed with exit code {}.".format(procs_keys[i], pluginmgr_exit_code))
        sys.exit(1)

# Both binaries ran successfully
print("LoMEngine and LoMPluginMgr ran successfully.")    '''