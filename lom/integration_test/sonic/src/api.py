import subprocess
import sys
import threading
import re
import time
import select
import signal
import os
import json
import psutil

#===============================================================================
# Global Constants for tests 

TEST_FAIL = 1
TEST_PASS = 0

PATTERN_NOMATCH = 0
PATTERN_MATCH = 1

REMOTE_CONTAINER_NAME = "device-health"
REMOTE_CONTAINER_CONFIG_DIR = "/usr/share/lom/"
REMOTE_CONTAINER_BIN_DIR = "/usr/bin/"
GLOBALS_CONFIG_FILE = "globals.conf.json"
BINDINGS_CONFIG_FILE = "bindings.conf.json"
ACTIONS_CONFIG_FILE = "actions.conf.json"
PROCS_CONFIG_FILE = "procs.conf.json"

LOM_ENGINE_PROCESS_NAME = "LoMEngine"
LOM_PLUGIN_MGR_PROCESS_NAME = "LoMPluginMgr"
LOM_TEST_LINK_CRC_MOCKER = "linkcrc_mocker"
#===============================================================================

"""
    Returns the Sonic feature status

    Args:
        feature_name (str): The name of the feature to get the status for.

    Returns:
        tuple: A tuple containing the status of the feature and its properties.
            The tuple contains four elements:
                - A string indicating the status of the feature. Possible values are:
                    - "OK": The feature was found and its status was successfully retrieved.
                    - "FEATURE_NOT_FOUND": The feature was not found.
                    - "COMMAND_NOT_FOUND": The "show feature status" command was not found.
                    - "ERROR": An error occurred while executing the "show feature status" command.
                - A string indicating the state of the feature. Possible values are:
                    - "enabled"
                    - "disabled"
                    - "" (empty string) if the "State" column is not present in the output.
                - A string indicating whether the feature is set to auto-restart. Possible values are:
                    - "yes"
                    - "no"
                    - "" (empty string) if the "AutoRestart" column is not present in the output.
                - A string indicating the owner of the feature. This property is only present if the "SetOwner" column
                  is present in the output. Possible values are:
                    - "system"
                    - "user"
                    - "" (empty string) if the "SetOwner" column is not present in the output.
"""
def get_feature_status(feature_name):
    try:
        output = subprocess.check_output(["show", "feature", "status"]).decode().strip()
    except FileNotFoundError:
        return "COMMAND_NOT_FOUND", "", "", ""
    except subprocess.CalledProcessError:
        return "ERROR", "", "", ""
    
    feature_lines = output.split("\n")
    header = feature_lines[0].split()
    data_lines = feature_lines[2:]
    
    # Find the column indices for the required fields
    state_index = header.index("State") if "State" in header else -1
    auto_restart_index = header.index("AutoRestart") if "AutoRestart" in header else -1
    set_owner_index = header.index("SetOwner") if "SetOwner" in header else -1
    
    # Iterate through the data lines to find the feature and extract the values
    for line in data_lines:
        values = line.split()
        if values[0] == feature_name:
            state = values[state_index] if state_index != -1 else ""
            auto_restart = values[auto_restart_index] if auto_restart_index != -1 else ""
            set_owner = ""
            if len(values) > 3:
                set_owner = values[set_owner_index] if set_owner_index != -1 else ""
            return "OK", state, auto_restart, set_owner
        
    return "FEATURE_NOT_FOUND", "", "", ""

#===============================================================================

# Function to check if a container is running
def is_container_running(container_name):
    try:
        output = subprocess.check_output(['docker', 'inspect', '-f', '{{.State.Running}}', container_name])
        return output.decode().strip() == 'true'
    except subprocess.CalledProcessError:
        return False

# Function to get the ID of a container
def get_container_id(container_name):
    try:
        output = subprocess.check_output(['docker', 'ps', '-q', '-f', 'name=' + container_name])
        container_id = output.decode().strip()
        if container_id and is_container_running(container_id):
            return container_id
    except subprocess.CalledProcessError:
        pass    
    return None

"""
# Example usage
container_name = 'device-health'
container_id = get_container_id(container_name)
if container_id:
    print(f"Container {container_name} with ID {container_id} is running.")
else:
    print(f"Container {container_name} is not running.")
"""

#===============================================================================
# Function to check if a process is running
def is_process_running(process_name):
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == process_name:
            return True
    return False

# Function to wait for LoMEngine and LoMPluginMgr processes to start
def wait_for_lom_services_to_start():
    max_wait_time = 60  # Maximum time to wait in seconds
    wait_interval = 5  # Time interval to check the process status in seconds
    elapsed_time = 0

    while elapsed_time < max_wait_time:
        if is_process_running('LoMEngine') and is_process_running('LoMPluginMgr'):
            print("LoMEngine and LoMPluginMgr processes are running. Proceeding.")
            return True

        time.sleep(wait_interval)
        elapsed_time += wait_interval

    print("Timed out while waiting for LoMEngine and LoMPluginMgr processes to start.")
    return False

'''
# Example usage:
if wait_for_lom_services_to_start():
    print("Do something here...")
else:
    print("Failed to start LoMEngine and LoMPluginMgr processes.")
'''
#===============================================================================
"""
    Kill a process by its name.

    process_name: The name of the process to manage.
    force: If True, forcefully kill the process.

    Returns True if the process is successfully killed, False otherwise.
"""

def kill_process_by_name(process_name, force=False):    
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                pid = proc.info['pid']
                process = psutil.Process(pid)
                if force:
                    process.kill()
                else:
                    process.terminate()                
                # Wait for the process to terminate with a maximum of 5 seconds
                for _ in range(5):
                    if not process.is_running():
                        break
                    time.sleep(1)  # Wait for 1 second before checking again
                if process.is_running():
                    print(f"Failed to manage process '{process_name}' with PID {pid}.")
                    return False
                else:
                    print(f"Process '{process_name}' with PID {pid} managed.")
                    return True
        print(f"No process with name '{process_name}' found.")
        return False
    except psutil.NoSuchProcess as e:
        print(f"Error: Process '{process_name}' does not exist.")
        return False
    except psutil.AccessDenied as e:
        print(f"Error: Access denied. You may need elevated privileges to manage the process.")
        return False
    except Exception as e:
        print(f"Error occurred while managing process '{process_name}': {str(e)}")
        return False

'''
# Example usage to stop a process gracefully
process_name_to_stop = "LoMEngine"
if kill_process_by_name(process_name_to_stop):
    print(f"Process '{process_name_to_stop}' stopped successfully.")
else:
    print(f"Failed to stop process '{process_name_to_stop}'.")

# Example usage to forcefully kill a process
process_name_to_kill = "LoMEngine"
if kill_process_by_name(process_name_to_kill, force=True):
    print(f"Process '{process_name_to_kill}' killed successfully.")
else:
    print(f"Failed to kill process '{process_name_to_kill}'.")
'''
#===============================================================================

def overwrite_file_in_docker_with_json_data(json_data, config_file_name, container_name=REMOTE_CONTAINER_NAME , container_path=REMOTE_CONTAINER_CONFIG_DIR):
    try:
        container_id = get_container_id(container_name)
        if not container_id:
            print(f"Container '{container_name}' not found or not running.")
            return False
        # Check if the file exists in the Docker container
        check_file_command = f'docker exec {container_id} sh -c "test -f {container_path}/{config_file_name}"'
        result = subprocess.run(check_file_command, shell=True, capture_output=True)
        if result.returncode != 0:
            # File does not exist, create it
            create_file_command = f'docker exec {container_id} sh -c "touch {container_path}/{config_file_name}"'
            subprocess.run(create_file_command, shell=True, check=True)
        # Overwrite the file with the JSON data
        json_string = json.dumps(json_data, indent=4)
        command = f'echo \'{json_string}\' | docker exec -i {container_id} sh -c "cat > {container_path}/{config_file_name}"'
        subprocess.run(command, shell=True, check=True)
        return True
    except Exception as e:
        print(f"Error overwriting file {config_file_name} in Docker container with JSON data: {e}")
        return False

""" 
# Example usage
json_data = {
    "MAX_SEQ_TIMEOUT_SECS": 120,
    "MIN_PERIODIC_LOG_PERIOD_SECS": 1,
    "ENGINE_HB_INTERVAL_SECS": 10,
    
    "INITIAL_DETECTION_REPORTING_FREQ_IN_MINS": 5,
    "SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS": 60,
    "INITIAL_DETECTION_REPORTING_MAX_COUNT": 12,
    "PLUGIN_MIN_ERR_CNT_TO_SKIP_HEARTBEAT" : 3, 
        
    "MAX_PLUGIN_RESPONSES" : 1,
    "MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT_IN_SECS" : 60
}

container_name = "device-health"
container_path = "/usr/share/lom/"
file_name = "globals.conf.json"

if overwrite_file_in_docker_with_json_data(json_data, file_name, container_name, container_path):
    print("JSON data overwritten in Docker container successfully")
else:
    print("Error overwriting file in Docker container with JSON data") """
#===============================================================================

def copy_config_file_to_container(host_config_dir, dest_container_config_dir, container_name, file_name):
    # Check if the container is running
    container_id = get_container_id(container_name)
    if not container_id:
        print(f"Error: Container '{container_name}' is not running or doesn't exist.")
        return False
    
    # Check if the host config directory exists
    if not os.path.exists(host_config_dir):
        print(f"Error: Host config directory '{host_config_dir}' does not exist.")
        return False
    
    # Get the source file path
    src_file = os.path.join(host_config_dir, file_name)

    # Check if the source file exists and is a file
    if not os.path.isfile(src_file):
        print(f"Error: '{file_name}' does not exist in the host config directory {host_config_dir} or is not a file.")
        return False

    try:
        subprocess.run(['docker', 'cp', src_file, f"{container_id}:{dest_container_config_dir}"], check=True)
        print(f"Successfully copied '{file_name}' to container '{container_name}' at '{dest_container_config_dir}'")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while copying '{file_name}' to container '{container_name}': {str(e)}")
        return False
            

#===============================================================================

def check_device_health_status():
    try:
        output = subprocess.check_output(["systemctl", "status", "device-health"], universal_newlines=True)
    except FileNotFoundError:
        return "COMMAND_NOT_FOUND", ""
    except subprocess.CalledProcessError:
        return "ERROR", ""
    
    print("...............................................................")
    print(output)
    print("...............................................................")

    if "Active: active (running)" in output:
        return "OK", True
    else:
        return "OK", False


#===============================================================================

def check_docker_image():
    try:
        output = subprocess.check_output(["docker", "images", "docker-device-health"], universal_newlines=True)
    except FileNotFoundError:
        return "COMMAND_NOT_FOUND", ""
    except subprocess.CalledProcessError:
        return "ERROR", ""
    
    print("...............................................................")
    print(output)
    print("...............................................................")

    if "docker-device-health" in output:
        return "OK", True
    else:
        return "OK", False

#===============================================================================

def get_cmd_output(cmd):
    try:
        output = subprocess.check_output(cmd, universal_newlines=True)
    except FileNotFoundError:
        return "COMMAND_NOT_FOUND", ""
    except subprocess.CalledProcessError:
        return "ERROR", ""
    
    return "OK", output

#===============================================================================

# Function to stop a service
def stop_service(service_name):
    try:
        subprocess.run(['sudo', 'systemctl', 'stop', f'{service_name}.service'], check=True)
        print(f"{service_name} service stopped successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while stopping {service_name} service: {str(e)}")
        return False

# Function to start a service
def start_service(service_name):
    try:
        subprocess.run(['sudo', 'systemctl', 'reset-failed', f'{service_name}.service'], check=True)
        subprocess.run(['sudo', 'systemctl', 'start', f'{service_name}.service'], check=True)
        print(f"{service_name} service started successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while starting {service_name} service: {str(e)}")
        return False

# Function to restart a service
def restart_service(service_name):
    try:
        subprocess.run(['sudo', 'systemctl', 'reset-failed', f'{service_name}.service'], check=True)
        subprocess.run(['sudo', 'systemctl', 'restart', f'{service_name}.service'], check=True)
        print(f"{service_name} service restarted successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while restarting {service_name} service: {str(e)}")
        return False
import time

# Function to restart a service and wait for it to start
def restart_service_wait(service_name):
    try:
        subprocess.run(['sudo', 'systemctl', 'reset-failed', f'{service_name}.service'], check=True)
        subprocess.run(['sudo', 'systemctl', 'restart', f'{service_name}.service'], check=True)
        print(f"{service_name} service restarted successfully.")

        # Wait for the service to start
        max_wait_time = 60  # Maximum time to wait in seconds
        wait_interval = 5  # Time interval to check the service status in seconds
        elapsed_time = 0

        while elapsed_time < max_wait_time:
            time.sleep(wait_interval)
            status_output = subprocess.run(['sudo', 'systemctl', 'is-active', f'{service_name}.service'], stdout=subprocess.PIPE)
            status = status_output.stdout.decode().strip()

            if status == "active":
                print(f"{service_name} service is active. Proceeding.")
                return True

            elapsed_time += wait_interval

        print(f"Timed out while waiting for {service_name} service to start.")
        return False

    except subprocess.CalledProcessError as e:
        print(f"Error occurred while restarting {service_name} service: {str(e)}")
        return False

# Example usage
#service_name = "device-health"
#stop_success = stop_service(service_name)
#start_success = start_service(service_name)
#restart_success = restart_service(service_name)
# 
#===============================================================================

class BinaryRunner:
    def __init__(self, binary_path, *args):
        self.process = None
        self.binary_path = binary_path
        self.args = args

    def run_binary_in_background(self):
        try:
            # Start the binary in the background with the specified arguments
            command = [self.binary_path] + list(self.args)
            self.process = subprocess.Popen(command)
            print(f"Binary {self.binary_path} is running with PID: {self.process.pid}")
            return True
        except OSError as e:
            print(f"Failed to run the binary: {self.binary_path},  {str(e)}")
            return False
    
    def stop_binary(self):
        ret = False
        instances_stopped = 0
        actual_instances = 0

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if proc.info['name'] == os.path.basename(self.binary_path) and proc.info['cmdline'] == [self.binary_path] + list(self.args):
                try:
                    # Send the SIGTERM signal to the process to stop it
                    process = psutil.Process(proc.info['pid'])
                    actual_instances += 1
                    process.terminate()
                    process.wait()
                    instances_stopped += 1
                    #ret = True
                except psutil.NoSuchProcess as e:
                    print(f"Failed to stop the binary: {self.binary_path}, {str(e)}")
                except psutil.AccessDenied as e:
                    print(f"Access denied. You may need elevated privileges to stop the binary.")
                except Exception as e:
                    print(f"Error occurred while stopping the binary: {self.binary_path}, {str(e)}")
        
        if instances_stopped > 0:
            print(f"{instances_stopped} instance(s) of binary {self.binary_path} stopped.")
        else:
            print(f"No instances of binary {self.binary_path} found or already stopped.")
        
        if instances_stopped == actual_instances:
            ret = True

        self.process = None
        return ret

"""
binary_path = "/path/to/binary"
runner = BinaryRunner(binary_path)

# Run the binary in the background
if runner.run_binary_in_background():
    print("Binary started successfully")

# Do other work...

# Stop the running binary
runner.stop_binary()

binary_path = "/path/to/binary"
arg1 = "argument1"
arg2 = "argument2"
runner = BinaryRunner(binary_path, arg1, arg2)

# Run the binary in the background with arguments
if runner.run_binary_in_background():
    print("Binary started successfully with arguments:", arg1, arg2)

# Do other work...

# Stop the running binary
#runner.stop_binary()

"""
#===============================================================================

# Function to get the PIDs of LoMEngine processes
def get_lomengine_pids():
    try:
        engine_pids = subprocess.check_output(["pgrep", "-f", "/usr/bin/LoMEngine"]).decode().strip()
        if engine_pids:
            return [int(pid) for pid in engine_pids.split()]
    except subprocess.CalledProcessError:
        pass
    return []

# Function to get the PIDs of LoMPluginMgr processes
def get_lompluginmgr_pids():
    try:
        pluginmgr_pids = subprocess.check_output(["pidof", "/usr/bin/LoMPluginMgr"]).decode().strip()
        if pluginmgr_pids:
            return [int(pid) for pid in pluginmgr_pids.split()]
    except subprocess.CalledProcessError:
        pass
    return []

#===============================================================================

class LogMonitor:
    def __init__(self):
        self.engine_matched_patterns = {}  # {pattern: [(timestamp, log_message), ...]}
        self.engine_nomatched_patterns = {}  # {pattern: [(timestamp, log_message), ...]}
        self.plmgr_matched_patterns = {}  # {pattern: [(timestamp, log_message), ...]}
        self.plmgr_nomatched_patterns = {}  # {pattern: [(timestamp, log_message), ...]}
        self.match_lock = threading.Lock()
        self.monitoring_paused = False

    '''
    Pause monitoring of syslogs.
    '''
    def pause_monitoring(self):
        with self.match_lock:
            self.monitoring_paused = True

    '''
    Resume monitoring of syslogs.
    '''
    def resume_monitoring(self):
        with self.match_lock:
            self.monitoring_paused = False

    '''
    Clear existing data structures of patterns.
    '''
    def clear_log_buffers(self):
        with self.match_lock:
            self.engine_matched_patterns.clear()
            self.engine_nomatched_patterns.clear()
            self.plmgr_matched_patterns.clear()
            self.plmgr_nomatched_patterns.clear()

    '''
    Monitor the syslogs for the given patterns and update the matched patterns dictionary engine_matched_patterns
    This function blocks until all the patterns are matched or untill event is set via event argument

    patterns: List of patterns to match
    event: Caller can set this event to stop the monitoring. Before this make sure monitoring must not be paused. If so, then call resume_monitoring
    force_wait : If set to True, the function will wait untill event is set from the caller

    Returns True if all the patterns are matched, False otherwise
    '''

    def monitor_engine_syslogs_noblock(self, patterns, event, force_wait=False):
        command = r"tail -f /var/log/syslog"
        syslog_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        
        # Convert the patterns list to a set for efficient membership testing
        match_patterns = {pattern for flag, pattern in patterns if flag == PATTERN_MATCH}
        nomatch_patterns = {pattern for flag, pattern in patterns if flag == PATTERN_NOMATCH}
    
        # Keep track of the matched and nomatched patterns in sets
        matched_patterns = set()
        nomatched_patterns = set()
        
        while True:
            if event.is_set():
                break
            with self.match_lock:
                if self.monitoring_paused:
                    time.sleep(1)  # Pause monitoring for 1 second
                    continue
            ready_to_read, _, _ = select.select([syslog_process.stdout], [], [], 1)  # Timeout of 1 second
            if ready_to_read:
                line = syslog_process.stdout.readline().decode().strip()
                filter_pattern = r"(\w+\s+\d+\s\d+:\d+:\d+\.\d{2}).*?/usr/bin/LoMEngine.*?:\s(.*)" # 
                match = re.search(filter_pattern, line)
                if match:
                    timestamp = match.group(1)
                    log_message = match.group(2)
                    #print(f"Desired Engine data found - Timestamp: {timestamp}, Log Message: {log_message}")
                    for flag, pattern in patterns:
                        if re.search(pattern, log_message):
                            if flag == PATTERN_MATCH:
                                with self.match_lock:
                                    self.engine_matched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    matched_patterns.add(pattern)
                                    #print(f"*********** Matched Engine match pattern: {pattern}\n")
                            elif flag == PATTERN_NOMATCH:
                                with self.match_lock:
                                    self.engine_nomatched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    nomatched_patterns.add(pattern)
                                    #print(f"*********** Matched Engine nomatch pattern: {pattern}\n")
                     # Check if all the patterns are matched
                    if force_wait == False and  matched_patterns == match_patterns and nomatched_patterns == nomatch_patterns:
                        print(f"All the engine patterns are matched. Exiting the monitoring loop")
                        event.set()
        syslog_process.stdout.close()
        syslog_process.wait()

    '''
    Monitor the syslogs for the given patterns and update the matched patterns dictionary plmgr_matched_patterns
    This function blocks until all the patterns are matched or untill event is set via event argument

    patterns: List of patterns to match
    instance : Instance of the plugin manager process to monitor
    event: Caller can set this event to stop the monitoring
    force_wait : If set to True, the function will wait untill event is set from the caller

    Returns True if all the patterns are matched, False otherwise    
    '''

    def monitor_plmgr_syslogs_noblock(self, patterns, instance, event, force_wait=False):
        command = r"tail -f /var/log/syslog"
        syslog_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
        # Convert the patterns list to a set for efficient membership testing
        match_patterns = {pattern for flag, pattern in patterns if flag == PATTERN_MATCH}
        nomatch_patterns = {pattern for flag, pattern in patterns if flag == PATTERN_NOMATCH}
    
        # Keep track of the matched and nomatched patterns in sets
        matched_patterns = set()
        nomatched_patterns = set()
    
        while True:
            if event.is_set():
                break
            with self.match_lock:
                if self.monitoring_paused:
                    time.sleep(1)  # Pause monitoring for 1 second
                    continue
            ready_to_read, _, _ = select.select([syslog_process.stdout], [], [], 1)  # Timeout of 1 second
            if ready_to_read:
                line = syslog_process.stdout.readline().decode().strip()
                filter_pattern = r"(\w+\s+\d+\s\d+:\d+:\d+\.\d{2}).*?/usr/bin/LoMPluginMgr\[\d+\]:\s" + instance + r":\s(.*)"
                match = re.search(filter_pattern, line)
                if match:
                    timestamp = match.group(1)
                    log_message = match.group(2)
                    #print(f"Desired plmgr data found - Timestamp: {timestamp}, Log Message: {log_message}")
                    for flag, pattern in patterns:
                        if re.search(pattern, log_message):
                            if flag == PATTERN_MATCH:
                                with self.match_lock:
                                    self.plmgr_matched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    matched_patterns.add(pattern)
                                    #print(f"======== Matched plmgr pattern: {pattern}\n")
                            elif flag == PATTERN_NOMATCH:
                                with self.match_lock:
                                    self.plmgr_nomatched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    nomatched_patterns.add(pattern)
                                    #print(f"======== Matched plmgr nomatch pattern: {pattern}\n")
                    # Check if all the patterns are matched
                    if force_wait == False and matched_patterns == match_patterns and nomatched_patterns == nomatch_patterns:
                        print(f"All the plmgr patterns are matched. Exiting the monitoring loop")
                        event.set()
        syslog_process.stdout.close()
        syslog_process.wait()

#===============================================================================

# Print usage information
def print_usage():
    print("Usage: python3 api.py [command]")
    print("Available commands:")
    print("  get_feature_status <feature_name>   : Get the status of a feature")
    print("  is_container_running <container_name> : Check if a container is running")
    print("  get_container_id <container_name>   : Get the ID of a container")
    print("  is_process_running <process_name>   : Check if a process is running")
    print("  wait_for_lom_services_to_start      : Wait for LoMEngine and LoMPluginMgr processes to start")
    print("  kill_process_by_name <process_name> <force> : Kill a process by its name. Set force to True to forcefully kill the process")
    print("  check_device_health_status          : Check if device-health service is running")
    print("  check_docker_image                  : Check if docker-device-health image is present")
    print("  stop_service <service_name>         : Stop a service")
    print("  start_service <service_name>        : Start a service")
    print("  restart_service <service_name>      : Restart a service")
    print("  restart_service_wait <service_name> : Restart a service and wait for it to start")
    print("  get_lomengine_pids                  : Get the PIDs of LoMEngine processes")
    print("  get_lompluginmgr_pids               : Get the PIDs of LoMPluginMgr processes")


if __name__ == '__main__':        
    # Check the argument
    if len(sys.argv) < 2:
        print_usage()
        exit(1)

    arg = sys.argv[1]
    if arg == "get_feature_status":
        if len(sys.argv) != 3:
            print("Error: Missing feature name argument")
            print_usage()
            exit(1)
        print(get_feature_status(sys.argv[2]))
    elif arg == "is_container_running":
        if len(sys.argv) != 3:
            print("Error: Missing container name argument")
            print_usage()
            exit(1)
        print(is_container_running(sys.argv[2]))
    elif arg == "get_container_id":
        if len(sys.argv) != 3:
            print("Error: Missing container name argument")
            print_usage()
            exit(1)
        print(get_container_id(sys.argv[2]))
    elif arg == "is_process_running":
        if len(sys.argv) != 3:
            print("Error: Missing process name argument")
            print_usage()
            exit(1)
        print(is_process_running(sys.argv[2]))
    elif arg == "wait_for_lom_services_to_start":
        print(wait_for_lom_services_to_start())
    elif arg == "kill_process_by_name":
        if len(sys.argv) != 4:
            print("Error: Missing process name argument")
            print_usage()
            exit(1)
        print(kill_process_by_name(sys.argv[2], bool(sys.argv[3])))        
    elif arg == "check_device_health_status":
        print(check_device_health_status())
    elif arg == "check_docker_image":
        print(check_docker_image())
    elif arg == "stop_service":
        if len(sys.argv) != 3:
            print("Error: Missing service name argument")
            print_usage()
            exit(1)
        stop_service(sys.argv[2])
    elif arg == "start_service":
        if len(sys.argv) != 3:
            print("Error: Missing service name argument")
            print_usage()
            exit(1)
        start_service(sys.argv[2])
    elif arg == "restart_service":
        if len(sys.argv) != 3:
            print("Error: Missing service name argument")
            print_usage()
            exit(1)
        restart_service(sys.argv[2])
    elif arg == "get_lomengine_pids":
        print(get_lomengine_pids())
    elif arg == "get_lompluginmgr_pids":
        print(get_lompluginmgr_pids())
    else:
        print_usage()
        exit(1)