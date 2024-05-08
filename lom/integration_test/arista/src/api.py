import subprocess
import sys
import threading
import re
import time
import select
import signal
import os
import json
import errno
from datetime import datetime, timedelta

import arista_eapi_helper as eapi_helper

#===============================================================================
# Global Constants for tests 

TEST_FAIL = 1
TEST_PASS = 0

PATTERN_NOMATCH = 0
PATTERN_MATCH = 1

GLOBALS_CONFIG_FILE = "globals.conf.json"
BINDINGS_CONFIG_FILE = "bindings.conf.json"
ACTIONS_CONFIG_FILE = "actions.conf.json"
PROCS_CONFIG_FILE = "procs.conf.json"

LOM_ENGINE_PROCESS_NAME = "LoMEngine"
LOM_PLUGIN_MGR_PROCESS_NAME = "LoMPluginMgr"

LOM_DIR = "/mnt/flash/lom"
ACTIVE_INSTALLER_DIR = "/mnt/flash/lom/active"
BACKUP_INSTALLER_DIR = "/mnt/flash/lom/backup"
INSTALL_PARAMS_FILE  = "install_params.json"

MANAGEMENT_NAMESPACE = 'ns-MGMT'
DEFAULT_NAMESPACE = 'default'

TERMINATTR_DAEMON_NAME = 'TerminAttr'

EVENT_HANDLER_SCRIPT_PATH = "/mnt/flash/lom/active/install/LoM-install.sh -e"
EVENT_HANDLER_NAME = "lom-startup"

LOM_TEMP_INSTALLATION_FILE = "/tmp/lom-inside"

# for arista CLI helper
CLI_CONFGURATION_WAIT_TIME = 3  # Seconds to wait for the configuration to take effect

DAEMON_AFTER_ENABLED_WAIT_TIME = 3  # Seconds to wait to check after enabling a daemon
DAEMON_AFTER_DISABLED_WAIT_TIME = 3  # Seconds to wait to check after disabling a daemon 
DAEMON_IN_BETWEEN_WAIT_TIME = 10  # Seconds to wait to start plmgr after starting engine  

RUN_MODE = 'PROD'

#===============================================================================
# Function to check if a process is running

def is_process_running(process_name):
    try:
        # Use 'pgrep' to find the process
        subprocess.check_output("pgrep -x " + process_name, shell=True)
        return True
    except subprocess.CalledProcessError:
        # If 'pgrep' doesn't find the process, it throws a CalledProcessError
        return False
    
# Function to wait for LoMEngine and LoMPluginMgr processes to start
def wait_for_lom_services_to_start():
    max_wait_time = 60  # Maximum time to wait in seconds
    wait_interval = 5  # Time interval to check the process status in seconds
    elapsed_time = 0

    # To-Do : Goutham : Add lom gnmi server 
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
        # Use 'pgrep' to find the process
        pids = subprocess.check_output(["pgrep", "-x", process_name]).strip().split()
        if pids:
            for pid in pids:
                pid = int(pid)
                if force:
                    os.kill(pid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGTERM)
                time.sleep(1)  # Give the process some time to terminate
                # Wait for the process to terminate with a maximum of 5 seconds
                for _ in range(5):
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        print("Process '{}' with PID {} managed.".format(process_name, pid))
                        break
                    time.sleep(1)  # Wait for 1 second before checking again
                else:
                    print("Failed to manage process '{}' with PID {}.".format(process_name, pid))
                    return False
            return True
        else:
            print("No process with name '{}' found.".format(process_name))
            return False
    except subprocess.CalledProcessError:
        print("No process with name '{}' found.".format(process_name))
        return False
    except OSError as e:
        if e.errno == 1:  # Operation not permitted
            print("Error: Access denied. You may need elevated privileges to manage the process.")
        else:
            print("Error occurred while managing process '{}': {}".format(process_name, str(e)))
        return False
    except Exception as e:
        print("Error occurred while managing process '{}': {}".format(process_name, str(e)))
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

def kill_process_by_id(pid, force=False):
    try:
        # Convert pid to int
        pid = int(pid)

        # Kill the process
        if force:
            os.kill(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGTERM)

        print("Process with PID {} killed.".format(pid))
        return True
    except OSError as e:
        if e.errno == 1:  # Operation not permitted
            print("Error: Access denied. You may need elevated privileges to kill the process.")
        elif e.errno == 3:  # No such process
            print("Error: No process with PID {} found.".format(pid))
        else:
            print("Error occurred while killing process with PID {}: {}".format(pid, str(e)))
        return False
    except Exception as e:
        print("Error occurred while killing process with PID {}: {}".format(pid, str(e)))
        return False
#===============================================================================

def overwrite_file_with_json_data(json_data, config_file_path):
    try:
        # Check if the file exists
        if not os.path.isfile(config_file_path):
            # File does not exist, create it
            open(config_file_path, 'a').close()
        # Overwrite the file with the JSON data
        with open(config_file_path, 'w') as f:
            json.dump(json_data, f, indent=4)
        return True
    except Exception as e:
        print("Error overwriting file {} with JSON data: {}".format(config_file_path, str(e)))
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

file_path = "/usr/share/lom/globals.conf.json"

if overwrite_file_with_json_data(json_data, file_path):
    print("JSON data overwritten in file successfully")
else:
    print("Error overwriting file with JSON data")
"""
#===============================================================================


def get_cmd_output(cmd):
    try:
        output = subprocess.check_output(cmd, universal_newlines=True)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return "COMMAND_NOT_FOUND", ""
        else:
            raise
    except subprocess.CalledProcessError:
        return "ERROR", ""
    
    return "OK", output

def get_mac_address(interface_name):
    """
    This function gets the MAC address of the specified interface.

    Parameters:
    - interface_name: The name of the interface.

    Returns:
    - The MAC address of the interface, or an empty string if an error occurs.
    """
    # Replace "Et" with "et" in the interface name
    interface_name = interface_name.replace('Et', 'et')

    # Replace slashes with underscores in the interface name
    interface_name = interface_name.replace('/', '_')

    status, output = get_cmd_output(['ifconfig', interface_name])
    if status == "OK":
        # Use a regular expression to find the MAC address in the output
        match = re.search(r'ether (\S+)', output)
        if match:
            return match.group(1)
    return ""

#mac_address = get_mac_address('Et3/1/1')
#print(mac_address)  # Prints: c4:ca:2b:ff:ef:79

def format_mac_address(mac_address):
    """
    This function formats a MAC address in the format 'c4:ca:2b:ff:ef:79' to 'c4ca.2bff.ef79'.

    Parameters:
    - mac_address: The MAC address to format.

    Returns:
    - The formatted MAC address.
    """
    return mac_address.replace(':', '').lower()[0:4] + '.' + mac_address.replace(':', '').lower()[4:8] + '.' + mac_address.replace(':', '').lower()[8:]


#===============================================================================

# Function to stop a service

def stop_service(service_name):
    try:
        subprocess.check_call(['sudo', 'systemctl', 'stop', '{}.service'.format(service_name)])
        print("{} service stopped successfully.".format(service_name))
        return True
    except subprocess.CalledProcessError as e:
        print("Error occurred while stopping {} service: {}".format(service_name, str(e)))
        return False

# Function to start a service
def start_service(service_name):
    try:
        subprocess.check_call(['sudo', 'systemctl', 'reset-failed', '{}.service'.format(service_name)])
        subprocess.check_call(['sudo', 'systemctl', 'start', '{}.service'.format(service_name)])
        print("{} service started successfully.".format(service_name))
        return True
    except subprocess.CalledProcessError as e:
        print("Error occurred while starting {} service: {}".format(service_name, str(e)))
        return False

# Function to restart a service
def restart_service(service_name):
    try:
        subprocess.check_call(['sudo', 'systemctl', 'reset-failed', '{}.service'.format(service_name)])
        subprocess.check_call(['sudo', 'systemctl', 'restart', '{}.service'.format(service_name)])
        print("{} service restarted successfully.".format(service_name))
        return True
    except subprocess.CalledProcessError as e:
        print("Error occurred while restarting {} service: {}".format(service_name, str(e)))
        return False

# Function to restart a service and wait for it to start
def restart_service_wait(service_name):
    try:
        subprocess.check_call(['sudo', 'systemctl', 'reset-failed', '{}.service'.format(service_name)])
        subprocess.check_call(['sudo', 'systemctl', 'restart', '{}.service'.format(service_name)])
        print("{} service restarted successfully.".format(service_name))

        # Wait for the service to start
        max_wait_time = 60  # Maximum time to wait in seconds
        wait_interval = 5  # Time interval to check the service status in seconds
        elapsed_time = 0

        while elapsed_time < max_wait_time:
            time.sleep(wait_interval)
            status_output = subprocess.check_output(['sudo', 'systemctl', 'is-active', '{}.service'.format(service_name)])
            status = status_output.strip()

            if status == "active":
                print("{} service is active. Proceeding.".format(service_name))
                return True

            elapsed_time += wait_interval

        print("Timed out while waiting for {} service to start.".format(service_name))
        return False

    except subprocess.CalledProcessError as e:
        print("Error occurred while restarting {} service: {}".format(service_name, str(e)))
        return False

# Example usage
#service_name = "device-health"
#stop_success = stop_service(service_name)
#start_success = start_service(service_name)
#restart_success = restart_service(service_name)
# 

#===============================================================================
# copy from host to dest
def copy_file(host_dir, dest_dir, file_name):
    # Check if the host config directory exists
    if not os.path.exists(host_dir):
        print("Error: Host config directory '{}' does not exist.".format(host_dir))
        return False
    
    # Get the source file path
    src_file = os.path.join(host_dir, file_name)

    # Check if the source file exists and is a file
    if not os.path.isfile(src_file):
        print("Error: '{}' does not exist in the host config directory {} or is not a file.".format(file_name, host_dir))
        return False

    # Get the destination file path
    dest_file = os.path.join(dest_dir, file_name)

    try:
        with open(src_file, 'rb') as fsrc:
            with open(dest_file, 'wb') as fdst:
                fdst.write(fsrc.read())
        print("Successfully copied '{}' to '{}'".format(file_name, dest_dir))
        return True
    except Exception as e:
        print("Error occurred while copying '{}' to '{}': {}".format(file_name, dest_dir, str(e)))
        return False
    
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
            print("Starting binary {}...".format(self.binary_path))
            self.process = subprocess.Popen(command)
            print("Binary {} is running with PID: {}".format(self.binary_path, self.process.pid))
            return True
        except OSError as e:
            print("Failed to run the binary: {}, {}".format(self.binary_path, str(e)))
            return False
        except Exception as e:
            print("Error occurred while running the binary: {}, {}".format(self.binary_path, str(e)))
            return False

    def stop_binary(self):
        self.binary_name = os.path.basename(self.binary_path)
        print("Stopping binary {}...".format(self.binary_name))
        os.system("pkill -x " + self.binary_name)
        print("All instances of binary {} stopped.".format(self.binary_name))
        self.process = None
        return True

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
        engine_pids = subprocess.check_output(["pgrep", "-x", "LoMEngine"]).decode().strip()
        if engine_pids:
            return [int(pid) for pid in engine_pids.split()]
    except subprocess.CalledProcessError:
        pass
    return []

# Function to get the PIDs of LoMPluginMgr processes
def get_lompluginmgr_pids():
    try:
        pluginmgr_pids = subprocess.check_output(["pidof", "LoMPluginMgr"]).decode().strip()
        if pluginmgr_pids:
            return [int(pid) for pid in pluginmgr_pids.split()]
    except subprocess.CalledProcessError:
        pass
    return []


#===============================================================================

def get_procs_keys(dir_path):
    """
    This function reads the procs.conf.json file and returns the keys under the "procs" object.

    Parameters:
    - dir_path: The directory path where the procs.conf.json file is located.

    Returns:
    - procs_keys: A list of keys under the "procs" object in procs.conf.json.

    Raises:
    - IOError: If the procs.conf.json file is not found, or if there's an error reading the file.
    - ValueError: If there's an error decoding the JSON.
    - Exception: If an unexpected error occurs.
    """
    try:
        with open(os.path.join(dir_path, PROCS_CONFIG_FILE), 'r') as f:
            data = json.load(f)
        procs_keys = list(data.get('procs', {}).keys())  # Convert to list for Python 2.7 compatibility
        if not procs_keys:
            raise ValueError("Error: The 'procs' object is empty in procs.conf.json.")
        return procs_keys
    except IOError as e:
        raise IOError("Error: Failed to read procs.conf.json. {}".format(e))
    except ValueError as e:
        raise ValueError("Error: Failed to decode procs.conf.json.{}".format(e))
    except Exception as e:
        raise Exception("Error: An unexpected error occurred while reading procs.conf.json. {}".format(e))


def validate_all_daemons(g_switch_eapi_handler):
    try:
        # Validate if lom-engine is running
        running = g_switch_eapi_handler.is_daemon_running('lom-engine')
        if not running:
            print("lom-engine is not running")
            return False

        # Validate if all lom-plmgr instances are running
        lom_plmgr_info = g_switch_eapi_handler.get_daemon_lom_plmgr_info()

        # Check the count of lom-plmgr instances
        g_procs_keys = get_procs_keys(ACTIVE_INSTALLER_DIR + '/config')
        print("Procs keys from {} : {}".format(PROCS_CONFIG_FILE, g_procs_keys))
        if not lom_plmgr_info or len(lom_plmgr_info) != len(g_procs_keys):
            print("lom-plmgr is not running")
            return False
        else:
            for instance_name in lom_plmgr_info.keys():
                running = g_switch_eapi_handler.is_daemon_running(instance_name)
                if not running:
                    print("{} is not running".format(instance_name))
                    return False

        print("All daemons are running successfully")
        return True
    except Exception as e:
        print("Error while validating daemons: {}".format(e))
        raise e

def cleanup_plugin_mgr_daemon(g_switch_eapi_handler):
    """
    This function is responsible for cleaning up the plugin manager daemon.

    It performs the following steps:
    1. Disable all plugin manager daemon instances and get the list of disabled daemons
    2. Check if the daemon config still exists for each disabled daemon

    Returns:
    bool: True if the cleanup was successful, False otherwise.
    """
    cleanup_status = True

    try:
        print("Starting cleanup of lom-plmgr daemons...")

        # Disable all lom-plmgr daemon instances and get the list of disabled daemons
        disabled_daemons = g_switch_eapi_handler.remove_all_plmgr_daemons()

        if disabled_daemons:
            print("Disabled the following lom-plmgr daemons: {}".format(', '.join(disabled_daemons)))
        else:
            print("No lom-plmgr daemons were found to disable.")

        for daemon in disabled_daemons:
            print("Checking if {}'s config still exists...".format(daemon))

            # Check if the daemon config still exists
            if g_switch_eapi_handler.is_daemon_config_exists(daemon):
               print("Error: {}'s config still exists after attempting to disable it.".format(daemon))
               cleanup_status = False
            else:
                print("{}'s config has been successfully cleaned.".format(daemon))

    except Exception as e:
        print("Error occurred while removing all plmgr daemons or validating daemon config: {}".format(e))
        cleanup_status = False

    return cleanup_status

def cleanup_lom_engine_daemon(g_switch_eapi_handler):
    """
    This function is responsible for cleaning up the lom-engine daemon.

    It performs the following steps:
    1. Check if the lom-engine daemon exists
    2. Disable the lom-engine daemon if it exists
    3. Check if the lom-engine daemon config still exists after disabling it

    Returns:
    bool: True if the cleanup was successful, False otherwise.
    """
    try:
        print("Checking if lom-engine daemon exists...")

        # Get the lom-engine daemon info
        lom_engine_info = g_switch_eapi_handler.get_daemon_lom_engine_info()

        if not lom_engine_info:
           print("No lom-engine daemon config is enabled")
           return True
        
        # Disable the lom-engine daemon
        g_switch_eapi_handler.remove_daemon('lom-engine') # removes the config
        print("lom-engine disabled successfully")

        # Check if the lom-engine daemon config still exists
        if g_switch_eapi_handler.is_daemon_config_exists('lom-engine'):
            print("Error: lom-engine's config still exists after attempting to disable it.")
            return False
        else:
            print("lom-engine's config has been successfully cleaned.")

    except Exception as e:
        print("Error occurred while removing lom-engine daemon or validating daemon config: {}".format(e))
        raise e

    return True

def cleanup_lom_daemons(g_switch_eapi_handler):
    """
    This function is responsible for cleaning up the lom-engine and lom-plugin-manager daemons.

    It performs the following steps:
    1. Check if the lom-engine daemon exists
    2. Disable the lom-engine daemon if it exists
    3. Check if the lom-engine daemon config still exists after disabling it
    4. Disable all plugin manager daemon instances and get the list of disabled daemons
    5. Check if the daemon config still exists for each disabled daemon

    Returns:
    bool: True if the cleanup was successful, False otherwise.
    """
    cleanup_status = True

    try:
        print("Starting cleanup of lom-engine and lom-plmgr daemons...")

        # Cleanup the lom-engine daemon
        if not cleanup_lom_engine_daemon(g_switch_eapi_handler):
            cleanup_status = False

        # Cleanup the lom-plmgr daemon
        if not cleanup_plugin_mgr_daemon(g_switch_eapi_handler):
            cleanup_status = False

    except Exception as e:
        print("Error occurred while cleaning up lom-engine and lom-plmgr daemons: {}".format(e))
        cleanup_status = False

    return cleanup_status

def check_and_start_lom_engine(g_switch_eapi_handler):
    """
    This function is responsible for starting the lom-engine daemon and checking if it's running.

    It performs the following steps:
    1. Start the lom-engine daemon in the management namespace
    2. Wait for some time after starting the daemon
    3. Check if the lom-engine daemon is running

    Returns:
    bool: True if the lom-engine daemon is running, False otherwise.
    """
    print("Starting lom-engine daemon ...")
    try:
        # Start the lom-engine daemon in management namespace
        g_lom_engine_path = os.path.join(ACTIVE_INSTALLER_DIR, 'install', 'bin', 'LoMEngine')
        g_config_dir = os.path.join(ACTIVE_INSTALLER_DIR, 'config')
        g_switch_eapi_handler.add_lom_engine_daemon(g_lom_engine_path, g_config_dir, RUN_MODE, 6, True)
        print("lom-engine started successfully")
    except Exception as e:
        print("Error while starting lom-engine: {}".format(e))
        raise e
    
    # Wait for some time after starting the daemon
    time.sleep(DAEMON_AFTER_ENABLED_WAIT_TIME)

    # Check if lom-engine daemon is running
    try:
        running = g_switch_eapi_handler.is_daemon_running('lom-engine')
    except Exception as e:
        print("Error while checking if lom-engine is running: {}".format(e))
        raise e

    if not running:
        print("lom-engine is not running")
        return False

    print("lom-engine is running successfully")
    return True

def check_and_start_plugin_manager_deamon(g_switch_eapi_handler):
    """
    This function is responsible for starting the lom-plugin-manager daemon for each proc_id and checking if it's running.

    It performs the following steps:
    1. Iterate over each proc_id in g_procs_keys
    2. Start the lom-plugin-manager daemon for each proc_id
    3. Wait for some time after starting the daemon
    4. Check if the lom-plugin-manager daemon is running for each proc_id

    Returns:
    bool: True if all lom-plugin-manager daemons are running, False otherwise.
    """
    # Iterate over each proc_id in g_procs_keys and start lom-plmgr for each proc_id      
    g_procs_keys = get_procs_keys(ACTIVE_INSTALLER_DIR + '/config')
    print("Procs keys from {} : {}".format(PROCS_CONFIG_FILE, g_procs_keys))      
    for proc_id in g_procs_keys:
        # Start the lom-plugin-manager daemon
        print("Starting lom-plmgr for proc_id {} ...".format(proc_id))
        try:
            g_lom_plugin_mgr_path = os.path.join(ACTIVE_INSTALLER_DIR, 'install', 'bin', 'LoMPluginMgr')
            g_config_dir = os.path.join(ACTIVE_INSTALLER_DIR, 'config')
            g_switch_eapi_handler.add_plugin_manager_daemon(g_lom_plugin_mgr_path, proc_id, g_config_dir, RUN_MODE, 6, True)
            print("lom-plmgr started successfully for proc_id {}".format(proc_id))            
        except Exception as e:
            print("Error while starting lom-plmgr for proc_id {}: {}".format(proc_id, e))
            raise e
        
        time.sleep(DAEMON_AFTER_ENABLED_WAIT_TIME)
        instance_name = "lom-plmgr-{}".format(proc_id)

        # Check if lom-plmgr daemon is running
        try:
            running = g_switch_eapi_handler.is_daemon_running(instance_name)
        except Exception as e:
            print("Error while checking if {} is running: {}".format(instance_name, e))
            raise e

        if not running:
            print("{} is not running".format(instance_name))
            return False
        print("{} is running successfully".format(instance_name))            
    return True

def start_lom_daemons(g_switch_eapi_handler):
    """
    This function is responsible for starting the lom-engine and lom-plugin-manager daemons.

    It performs the following steps:
    1. Start the lom-engine daemon
    2. Start the lom-plugin-manager daemon for each proc_id

    Returns:
    bool: True if all lom-engine and lom-plugin-manager daemons are running, False otherwise.
    """
    try:
        # Start the lom-engine daemon
        if not check_and_start_lom_engine(g_switch_eapi_handler):
            return False

        # Start the lom-plugin-manager daemon for each proc_id
        if not check_and_start_plugin_manager_deamon(g_switch_eapi_handler):
            return False

    except Exception as e:
        print("Error occurred while starting lom-engine and lom-plmgr daemons: {}".format(e))
        return False

    print("All daemons started successfully")
    return True  

def configure_interface_loopback(g_switch_eapi_handler, interface_name, vlan_id):
    """
    This function configures the specified interface.

    Parameters:
    - interface_name: The name of the interface to configure.
    - vlan_id: The VLAN ID to assign to the interface.

    Raises:
    - Exception: If an error occurs while executing the command.
    """
    # Define the command sequence to configure the interface
    command = [
        'configure',
        'interface {}'.format(interface_name),
        'traffic-loopback source system device mac',
        'exit',
        'interface {}'.format(interface_name),
        'switchport',
        'switchport access vlan {}'.format(vlan_id),
        'exit'
    ]

    try:
        g_switch_eapi_handler.execute_command(command)
    except Exception as e:
        raise Exception("Error configuring interface: {0}".format(str(e)))

def remove_interface_loopback(g_switch_eapi_handler, interface_name, vlan_id):
    """
    This function configures the specified interface.

    Parameters:
    - interface_name: The name of the interface to configure.
    - vlan_id: The VLAN ID to assign to the interface.

    Raises:
    - Exception: If an error occurs while executing the command.
    """
    # Define the command sequence to configure the interface
    command = [
        'configure',
        'interface {}'.format(interface_name),
        'no switchport',
        'no switchport access vlan {}'.format(vlan_id),
        'exit',
        'interface {}'.format(interface_name),
        'no traffic-loopback source system device mac',
        'exit',
        'no vlan 10',
        'exit'
    ]

    try:
        g_switch_eapi_handler.execute_command(command)
    except Exception as e:
        # Intentional as this is hidden command and may fail if isn't configured after reboot
        print("Error configuring interface: {0}".format(str(e)))

def show_hardware_counter_drop_count(g_switch_eapi_handler, counter):
    """
    This function retrieves the sum of the drop counts for a specific hardware counter on all chips.

    Parameters:
    - counter: The name of the counter for which the drop count is to be retrieved.

    Returns:
    - total_dropCount: The sum of the drop counts for the specified counter on all chips.

    Raises:
    - Exception: If an error occurs while executing the command or processing the output.
    """
    # Define the command to show the hardware counter drop
    command = ['show hardware counter drop']

    total_dropCount = 0

    try:
        output = g_switch_eapi_handler.execute_command(command)

        # Parse the command output
        for chip, data in output[0]['dropEvents'].items():
            for event in data['dropEvent']:
                if event['counterName'] == counter:
                    total_dropCount += event['dropCount']  # Add the drop count for the specified counter on the current chip to the total

        return total_dropCount
    except Exception as e:
        raise Exception("Failed to show counter drop count: {}".format(e))

#total_drop_count = show_hardware_counter_drop_count(g_switch_eapi_handler, 'dropVoqInPortNotVlanMember')
#print(total_drop_count)  # Prints the sum of the drop counts for the 'dropVoqInPortNotVlanMember' counter on all chips

def clear_hardware_counter_drop(g_switch_eapi_handler):
        """
        This function executes the 'clear hardware counter drop' command.

        Raises:
        - Exception: If an error occurs while executing the command.
        """
        try:
            # Define the command to clear the hardware counter drop
            command = [
                        'configure',
                        'clear hardware counter drop',
                        'exit'
                    ]

            # Execute the command
            g_switch_eapi_handler.execute_command(command)
        except Exception as e:
            raise Exception("Failed to clear hardware counter drop: {}".format(e))
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
        print("Pausing monitoring")
        with self.match_lock:
            self.monitoring_paused = True

    '''
    Resume monitoring of syslogs.
    '''
    def resume_monitoring(self):
        print("Resuming monitoring")
        with self.match_lock:
            self.monitoring_paused = False

    '''
    Clear existing data structures of patterns.
    '''
    def clear_log_buffers(self):
        print("Clearing log buffers")
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
        command = r"tail -f /var/log/messages"
        syslog_process = None

        # Convert the patterns list to a set for efficient membership testing
        match_patterns = set(pattern for flag, pattern in patterns if flag == PATTERN_MATCH)
        nomatch_patterns = set(pattern for flag, pattern in patterns if flag == PATTERN_NOMATCH)

        # Keep track of the matched and nomatched patterns in sets
        matched_patterns = set()
        nomatched_patterns = set()

        while True:
            if event.is_set():
                if syslog_process is not None:
                    syslog_process.stdout.close()
                    syslog_process.wait()
                break
            with self.match_lock:
                if self.monitoring_paused:
                    if syslog_process is not None:
                        syslog_process.stdout.close()
                        syslog_process.wait()
                        syslog_process = None
                    time.sleep(1)  # Pause monitoring for 1 second
                    continue
                elif syslog_process is None:
                    syslog_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            ready_to_read, _, _ = select.select([syslog_process.stdout], [], [], 0.1)  # Timeout of 0.1 second
            if ready_to_read:
                line = syslog_process.stdout.readline().strip()
                filter_pattern = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00).*?/mnt/flash/lom/active/install/bin/LoMEngine.*?:\s.*: (.*)"
                match = re.search(filter_pattern, line)
                if match:
                    timestamp = match.group(1)
                    log_message = match.group(2)
                    #print "Desired Engine data found - Timestamp: %s, Log Message: %s" % (timestamp, log_message)
                    for flag, pattern in patterns:
                        if re.search(pattern, log_message):
                            if flag == PATTERN_MATCH:
                                with self.match_lock:
                                    self.engine_matched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    matched_patterns.add(pattern)
                                    #print("*********** Matched Engine match pattern: %s\n" % pattern)
                            elif flag == PATTERN_NOMATCH:
                                with self.match_lock:
                                    self.engine_nomatched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    nomatched_patterns.add(pattern)
                                    #print("*********** Matched Engine nomatch pattern: %s\n" % pattern)
                    # Check if all the patterns are matched
                    if force_wait == False and  matched_patterns == match_patterns and nomatched_patterns == nomatch_patterns:
                        print("All the engine patterns are matched. Exiting the monitoring loop")
                        event.set()
        if syslog_process is not None:
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
        command = r"tail -f /var/log/messages"
        syslog_process = None

        # Convert the patterns list to a set for efficient membership testing
        match_patterns = set(pattern for flag, pattern in patterns if flag == PATTERN_MATCH)
        nomatch_patterns = set(pattern for flag, pattern in patterns if flag == PATTERN_NOMATCH)

        # Keep track of the matched and nomatched patterns in sets
        matched_patterns = set()
        nomatched_patterns = set()

        while True:
            if event.is_set():
                if syslog_process is not None:
                    syslog_process.stdout.close()
                    syslog_process.wait()
                break
            with self.match_lock:
                if self.monitoring_paused:
                    if syslog_process is not None:
                        syslog_process.stdout.close()
                        syslog_process.wait()
                        syslog_process = None
                    time.sleep(1)  # Pause monitoring for 1 second
                    continue
                elif syslog_process is None:
                    syslog_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            ready_to_read, _, _ = select.select([syslog_process.stdout], [], [], 0.1)  # Timeout of 0.1 second
            if ready_to_read:
                line = syslog_process.stdout.readline().strip()
                filter_pattern = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00).*?/mnt/flash/lom/active/install/bin/LoMPluginMgr.*?:\s%LOM_PLUGIN_MGR-\d+-" + instance + r":.*?:.*?:\s*(.*)"
                match = re.search(filter_pattern, line)
                if match:
                    timestamp = match.group(1)
                    log_message = match.group(2)
                    #print("Desired plmgr data found - Timestamp: %s, Log Message: %s" % (timestamp, log_message))
                    for flag, pattern in patterns:
                        if re.search(pattern, log_message):
                            if flag == PATTERN_MATCH:
                                with self.match_lock:
                                    self.plmgr_matched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    matched_patterns.add(pattern)
                                    #print("======== Matched plmgr pattern: %s\n" % pattern)
                            elif flag == PATTERN_NOMATCH:
                                with self.match_lock:
                                    self.plmgr_nomatched_patterns.setdefault(pattern, []).append((timestamp, log_message))
                                    nomatched_patterns.add(pattern)
                                    #print("======== Matched plmgr nomatch pattern: %s\n" % pattern)
                    # Check if all the patterns are matched
                    if force_wait == False and matched_patterns == match_patterns and nomatched_patterns == nomatch_patterns:
                        print("All the plmgr patterns are matched. Exiting the monitoring loop")
                        event.set()
        if syslog_process is not None:
            syslog_process.stdout.close()
            syslog_process.wait()

#===============================================================================

def parse_timestamp(timestamp_str):
    # Split the timestamp into date, time, and timezone offset
    timestamp_str, tz_offset = timestamp_str.rsplit('+', 1)

    # Parse the date and time
    dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")

    # Parse the timezone offset
    tz_hours, tz_minutes = map(int, tz_offset.split(':'))
    tz_delta = timedelta(hours=tz_hours, minutes=tz_minutes)

    # Adjust the datetime object for the timezone offset
    dt -= tz_delta

    return dt

#timestamp_str = '2024-05-04T21:31:58.171933+00:00'
#dt = parse_timestamp(timestamp_str)
#print(dt)
#===============================================================================

# Print usage information
def print_usage():
    print("Usage: python3 api.py [command]")
    print("Available commands:")
    print("  is_process_running <process_name>   : Check if a process is running")
    print("  wait_for_lom_services_to_start      : Wait for LoMEngine and LoMPluginMgr processes to start")
    print("  kill_process_by_name <process_name> <force> : Kill a process by its name. Set force to True to forcefully kill the process")
    print("  overwrite_file_with_json_data <json_data> <file_path> : Overwrite a file with JSON data")
    print("  get_cmd_output <cmd> : Get the output of a command")
    print("  get_mac_address <interface_name>     : Get the MAC address of a network interface")
    print("  format_mac_address <mac_address>     : Format a MAC address")
    print("  stop_service <service_name>         : Stop a service")
    print("  start_service <service_name>        : Start a service")
    print("  restart_service <service_name>      : Restart a service")
    print("  restart_service_wait <service_name> : Restart a service and wait for it to start")
    print("  copy_file <host_dir> <dest_dir> <file_name> : Copy a file from the host directory to the destination directory")
    print("  get_lomengine_pids                  : Get the PIDs of LoMEngine processes")
    print("  get_lompluginmgr_pids               : Get the PIDs of LoMPluginMgr processes")
    print("  get_procs_keys <dir_path>           : Get the keys under the 'procs' object in procs.conf.json")
    print("  validate_all_daemons                : Validate if all LoM daemons are running")
    print("  cleanup_plugin_mgr_daemon           : Cleanup the plugin manager daemon")
    print("  cleanup_lom_engine_daemon           : Cleanup the LoM engine daemon")
    print("  cleanup_lom_daemons                 : Cleanup the LoM engine and plugin manager daemons")
    print("  check_and_start_lom_engine          : Check and start the LoM engine daemon")
    print("  check_and_start_plugin_manager_deamon : Check and start the plugin manager daemon")
    print("  start_lom_daemons                   : Start the LoM engine and plugin manager daemons")
    print("  configure_interface_loopback <interface_name> <vlan_id> : Configure an interface with a VLAN ID")
    print("  remove_interface_loopback <interface_name> <vlan_id> : Remove the interface configuration with a VLAN ID")
    print("  show_hardware_counter_drop_count <counter> : Show the sum of the drop counts for a specific hardware counter")
    print("  clear_hardware_counter_drop : Clear the hardware counter drop")
    print(" parse_timestamp <timestamp_str> : Parse a timestamp string")

if __name__ == '__main__':        
    # Check the argument
    if len(sys.argv) < 2:
        print_usage()
        exit(1)

    # Create an instance of AristaSwitchEAPIHelper to execute commands via eAPI
    g_switch_eapi_handler = eapi_helper.AristaSwitchEAPIHelper()
    g_switch_eapi_handler.connect()
    print("Created an instance of AristaSwitchEAPIHelper")

    arg = sys.argv[1]
    if arg == "is_process_running":
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
    elif arg == "overwrite_file_with_json_data":
        if len(sys.argv) != 4:
            print("Error: Missing JSON data or file path argument")
            print_usage()
            exit(1)
        json_data = json.loads(sys.argv[2])
        file_path = sys.argv[3]
        print(overwrite_file_with_json_data(json_data, file_path))
    elif arg == "get_cmd_output":
        if len(sys.argv) != 3:
            print("Error: Missing command argument")
            print_usage()
            exit(1)
        status, output = get_cmd_output(sys.argv[2])
        print("Status: {}, Output: {}".format(status, output))
    elif arg == "get_mac_address":
        if len(sys.argv) != 3:
            print("Error: Missing interface name argument")
            print_usage()
            exit(1)
        print(get_mac_address(sys.argv[2]))
    elif arg == "format_mac_address":
        if len(sys.argv) != 3:
            print("Error: Missing MAC address argument")
            print_usage()
            exit(1)
        print(format_mac_address(sys.argv[2]))
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
    elif arg == "copy_file":
        if len(sys.argv) != 5:
            print("Error: Missing host directory, destination directory, or file name argument")
            print_usage()
            exit(1)
        print(copy_file(sys.argv[2], sys.argv[3], sys.argv[4]))
    elif arg == "get_lomengine_pids":
        print(get_lomengine_pids())
    elif arg == "get_lompluginmgr_pids":
        print(get_lompluginmgr_pids())
    elif arg == "validate_all_daemons":
        print(validate_all_daemons(g_switch_eapi_handler))
    elif arg == "cleanup_plugin_mgr_daemon":
        print(cleanup_plugin_mgr_daemon(g_switch_eapi_handler))
    elif arg == "cleanup_lom_engine_daemon":
        print(cleanup_lom_engine_daemon(g_switch_eapi_handler))
    elif arg == "cleanup_lom_daemons":
        print(cleanup_lom_daemons(g_switch_eapi_handler))
    elif arg == "check_and_start_lom_engine":
        print(check_and_start_lom_engine(g_switch_eapi_handler))
    elif arg == "check_and_start_plugin_manager_deamon":
        print(check_and_start_plugin_manager_deamon(g_switch_eapi_handler))
    elif arg == "start_lom_daemons":
        print(start_lom_daemons(g_switch_eapi_handler))
    elif arg == "get_procs_keys":
        if len(sys.argv) != 3:
            print("Error: Missing directory path argument")
            print_usage()
            exit(1)
        print(get_procs_keys(sys.argv[2]))
    elif arg == "configure_interface_loopback":
        if len(sys.argv) != 4:
            print("Error: Missing interface name or VLAN ID argument")
            print_usage()
            exit(1)
        configure_interface_loopback(g_switch_eapi_handler, sys.argv[2], sys.argv[3])
    elif arg == "remove_interface_loopback":
        if len(sys.argv) != 4:
            print("Error: Missing interface name or VLAN ID argument")
            print_usage()
            exit(1)
        remove_interface_loopback(g_switch_eapi_handler, sys.argv[2], sys.argv[3])
    elif arg == "show_hardware_counter_drop_count":
        if len(sys.argv) != 3:
            print("Error: Missing counter argument")
            print_usage()
            exit(1)
        print(show_hardware_counter_drop_count(g_switch_eapi_handler, sys.argv[2]))
    elif arg == "clear_hardware_counter_drop":
        clear_hardware_counter_drop(g_switch_eapi_handler)
    elif arg == "parse_timestamp":
        if len(sys.argv) != 3:
            print("Error: Missing timestamp argument")
            print_usage()
            exit(1)
        print(parse_timestamp(sys.argv[2]))
    else:
        print_usage()
        exit(1)