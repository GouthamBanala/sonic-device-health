'''



'''

from __future__ import print_function  # Python 2/3 compatibility
import os
import subprocess
import signal
import time
import json
import sys
import argparse
import shutil
import logging

import arista_eapi_helper as eapi_helper
import arista_cli_helper as cli_helper
from common import *

'''
Sample lom Installer code after extracking to default directory.

/tmp/lom-selfextract.lMQSUE/
|-- config
|   |-- actions.conf.json
|   |-- bindings.conf.json
|   |-- globals.conf.json
|   |-- procs.conf.json
|   `-- security
|       |-- client_certs
|       |   |-- client.cer
|       |   |-- client.csr
|       |   `-- client.key
|       |-- dsmsroot.cer
|       |-- dsmsroot.key
|       |-- openssl.cnf
|       |-- openssl_ca.cnf
|       |-- server.csr
|       |-- streamingtelemetryserver.cer
|       `-- streamingtelemetryserver.key
|-- install
|   |-- LoM-install.sh
|   |-- bin
|   |   |-- LoMCli
|   |   |-- LoMEngine
|   |   `-- LoMPluginMgr
|   `-- startup
|       |-- arista_cli_helper.py
|       |-- arista_eapi_helper.py
|       |-- cli_tools.py
|       |-- common.py
|       `-- do-install.py
`-- libs
    |-- libsodium.so
    |-- libsodium.so.26
    |-- libsodium.so.26.1.0
    |-- libzmq.so
    |-- libzmq.so.5
    `-- libzmq.so.5.2.6
'''

# Global variables
g_installer_dir = None
g_lom_engine_path = None
g_lom_plugin_mgr_path = None
g_lom_cli_path = None
g_config_dir = None
g_switch_cli_handler = None
g_switch_eapi_handler = None
g_procs_keys = None
g_previous_config = None

def setup(installation_dir):
    """
    Sets up the installation environment.

    This function initializes global variables, writes chip details to a file,
    enables Unix eAPI protocol, and creates instances of AristaSwitchCLIHelper
    and AristaSwitchEAPIHelper.

    Parameters:
    installation_dir (str): The directory where the installation files are located.

    Returns:
    bool: True if the setup was successful, False otherwise.
    dict: A dictionary containing the existing installation configuration.

    Raises:
    Exception: If there is an error during setup.
    """
    global g_lom_engine_path, g_lom_plugin_mgr_path, g_lom_cli_path, g_config_dir, g_procs_keys, g_installer_dir, \
            g_switch_cli_handler, g_switch_eapi_handler
    existing_install_config = {}

    # Get the lom extraction directory path e.g. /mnt/flash/lom/active
    g_installer_dir = installation_dir
    logger.log("Working Installation directory: {}".format(g_installer_dir))

    g_lom_engine_path = os.path.join(g_installer_dir, 'install', 'bin', 'LoMEngine')
    g_lom_plugin_mgr_path = os.path.join(g_installer_dir, 'install', 'bin', 'LoMPluginMgr')
    g_lom_cli_path = os.path.join(g_installer_dir, 'install', 'bin', 'LoMCli')
    g_config_dir = os.path.join(g_installer_dir, 'config')
    
    try:
        # Get the list of proc IDs from PROC_CONF_FILE
        g_procs_keys = get_procs_keys(g_config_dir)
        logger.log("Procs keys from {} : {}".format(PROC_CONF_FILE, g_procs_keys))
        
        # Write the chip details mapping to a file to be referred from needed plugins
        filename = os.path.join(g_config_dir, CHIP_DETAILS_MAPPING_FILE) 
        logger.log("Writing chip details mapping to file: {}".format(filename))                
        write_chipdetails_mapping_to_file(filename)

         # Create an instance of AristaSwitchCLIHelper to talk to switch via CLI
        g_switch_cli_handler = cli_helper.AristaSwitchCLIHelper(logger)
        logger.log("Created an instance of AristaSwitchCLIHelper")

        # Enable Unix eAPI protocol to execute commands via eAPI
        running, eapi_already_enabled = g_switch_cli_handler.check_and_enable_unix_eAPI_protocol()
        existing_install_config['eapi_already_enabled'] = eapi_already_enabled
        if running:
            if eapi_already_enabled:
                logger.log("EAPI was already enabled.")
            else:
                logger.log("EAPI has been successfully enabled.")
        else:
            logger.log("Error: Unix eAPI protocol is not running.")
            return False, None

        # Create an instance of AristaSwitchEAPIHelper to execute commands via eAPI
        g_switch_eapi_handler = eapi_helper.AristaSwitchEAPIHelper()
        g_switch_eapi_handler.connect()
        logger.log("Created an instance of AristaSwitchEAPIHelper")

    except Exception as e:
        logger.log("Error in setup: {}".format(e))
        raise e
    
    return True, existing_install_config

def start_installation(installation_path):
    """
    This function is responsible for starting the installation process.

    It performs the following steps:
    1. Setup the installation
    2. Perform pre-checks
    3. Extract and log daemon information
    4. Cleanup any existing daemons
    5. Perform common checks before installation
    6. Start the daemons in the management namespace
    7. Validate if all daemons are running
    8. Perform common checks after installation
    9. Validate the common checks
    10. Perform post-checks

    Parameters:
    installation_path (str): The path where the installation should be set up.

    Returns:
    bool: True if the installation was successful, False otherwise.
    existing_config: The existing configuration if the installation was successful, None otherwise.
    """
    try:
        logger.log("Starting installation at {}".format(installation_path))

        # Create temporary file to indicate that the installation is being triggered by an external process (like FUSE)
        # and not via the event handler(after reboot or after config/device repave). This is used to skip certain steps in the
        # installation process when its triggered via the event handler.
        with open(LOM_TEMP_INSTALLATION_FILE, 'w') as f:
            pass

        # Setup the installation
        status, existing_config = setup(installation_path)
        if not status:
            logger.log("Error: Failed to setup the installation")
            return False, None 
        logger.log("Setup successful") 
        
        # Event handler support. After reboot, the event handler is triggered and it calls install_from_event_handler() function.
        if EVENT_HANDLER_SUPPORT:            
            # Add event Handler 
            g_switch_cli_handler.add_boot_event_handler(handler_name=EVENT_HANDLER_NAME,
                                                        script_path=EVENT_HANDLER_SCRIPT_PATH, 
                                                        delay = EVENT_HANDLER_DELAY, timeout=EVENT_HANDLER_TIMEOUT,
                                                          asynchronous=EVENT_HANDLER_ASYNCHRONOUS)
            #verify if the event handler is added
            event_handler_data = g_switch_cli_handler.get_event_handler_data(EVENT_HANDLER_NAME)
            if not event_handler_data:
                logger.log("Error: Failed to add event handler")
                return False, None

            logger.log("Successfully added event handler : {}".format(EVENT_HANDLER_NAME))
            existing_config['event_handler_data'] = EVENT_HANDLER_NAME

            if WRITE_MEM_SUPPORT:
                # Write the configutation to memory
                g_switch_cli_handler.commit_config()
            
            existing_config['write_memory'] = True
            logger.log("Successfully did the write memory")

        logger.log("Existing configuration: {}".format(existing_config))

        # Pre-checks
        logger.log("Starting pre-checks...")
        if not pre_checks():
            logger.log("Error: Pre-checks failed")
            return False, None

        # Extract & print all daemon information untill now
        daemons_info = g_switch_eapi_handler.extract_daemons_info()
        logger.log("Daemons info at startup: " + json.dumps(daemons_info))
       
        ## Cleanup lom daemons if there are any
        logger.log("Starting cleanup of lom daemons...")

        if not cleanup_plugin_mgr_daemon():
            logger.log("Error: Failed to cleanup lom-plmgr daemon instances")
            return False, None        
        
        if not cleanup_lom_engine_daemon():
            logger.log("Error: Failed to cleanup lom-engine daemon")
            return False, None

        # Common checks before installation
        before_data = common_checks()

        ## Installation Start 
        # Start the daemon's in the management namespace
        if not check_and_start_lom_engine():
            logger.log("Error: Failed to start lom-engine daemon")
            return False, None

        time.sleep(DAEMON_IN_BETWEEN_WAIT_TIME)     

        if not check_and_start_plugin_manager_deamon():
            logger.log("Error: Failed to start lom-plmgr daemon")
            return False, None  

        # Validate if all daemons are running
        if not validate_all_daemons():
            logger.log("Error: Failed to validate all daemons")
            return False, None
        
        # Common checks after installation
        after_data = common_checks()

        # Validate common checks
        if not validate_common_checks(before_data, after_data):
            logger.log("Error: Common checks validation comparing before and after installation failed")
            return False, None
        
        # Post-checks
        if not post_checks():
            logger.log("Error: Post-checks failed")
            return False, None
        
        # Add the config so that external bash installer can read it to understant the status of the configuration
        data = json.dumps({"previous_config": existing_config})
        write_data_to_file(installation_path, INSTALL_PARAMS_FILE, data)

        return True, existing_config
    except Exception as e:
        logger.log("An unexpected error occurred in installation: {0}".format(e))
        raise e

def cleanup_installation(installation_path):
    """
    This function is responsible for cleaning up the installation process.

    It performs the following steps:
    1. Setup the installation
    2. Cleanup any existing daemons
    3. Wait for some time after disabling the daemons
    4. Validate if all daemons are disabled
    5. Check if the file exists and read the previous configuration
    6. Restore the previous configuration if it exists

    Parameters:
    installation_path (str): The path where the installation should be cleaned up.

    Returns:
    bool: True if the cleanup was successful, False otherwise.
    """
    cleanup_status = True

    try:
        # Setup the installation
        status, _ = setup(installation_path)
        if not status:
            logger.log("Error: Failed to setup the installation")
            return False, None

        if not cleanup_plugin_mgr_daemon():
            logger.log("Error: Failed to cleanup lom-plmgr daemon instances")
            cleanup_status = False

        if not cleanup_lom_engine_daemon():
            logger.log("Error: Failed to cleanup lom-engine daemon")
            cleanup_status = False

        # Wait for some time after disabling the daemons
        time.sleep(DAEMON_AFTER_DISABLED_WAIT_TIME)

        # Validate if all daemons are disabled
        if validate_all_daemons():
            logger.log("Error: Failed to validate all daemons")
            cleanup_status = False

        # Check if the file exists and read the previous configuration
        file_path = os.path.join(ACTIVE_INSTALLER_DIR, INSTALL_PARAMS_FILE)
        if directory_exists(ACTIVE_INSTALLER_DIR) and file_exists(file_path):
            file_content = read_data_from_file(ACTIVE_INSTALLER_DIR, INSTALL_PARAMS_FILE)
            data = json.loads(file_content)
            logger.log("Existing configuration: {}".format(data))
            previous_config = data.get('previous_config', None)

            if previous_config:
                logger.log("Restoring previous configuration...")

                # Check if EAPI was already enabled
                if 'eapi_already_enabled' in previous_config and not previous_config['eapi_already_enabled']:
                    logger.log("Disabling Unix eAPI protocol")
                    g_switch_cli_handler.disable_unix_eAPI_protocol()
                    if g_switch_cli_handler.is_unix_eapi_running():
                        logger.log("Error: Unix eAPI protocol is still running after attempting to disable it.")
                        cleanup_status = False

                # Check if the event handler was added
                if 'event_handler_data' in previous_config:
                    logger.log("Removing event handler : {}".format(previous_config['event_handler_data']))
                    g_switch_cli_handler.remove_event_handler("lom-startup")
                    if g_switch_cli_handler.get_event_handler_data("lom-startup"):
                        logger.log("Error: Failed to remove event handler")
                        cleanup_status = False

                # Check if the configuration was written to memory
                if 'write_memory' in previous_config and previous_config['write_memory']:
                    logger.log("Removing the configuration from memory")
                    g_switch_cli_handler.commit_config()

                logger.log("Previous configuration restored successfully")
            else:
                logger.log("No previous configuration found to restore")
        else:
            logger.log("No previous configuration file found to restore")

    except Exception as e:
        logger.log("An unexpected error occurred in cleanup: {0}".format(e))
        cleanup_status = False

    return cleanup_status

def cleanup_plugin_mgr_daemon():
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
        logger.log("Starting cleanup of lom-plmgr daemons...")

        # Disable all lom-plmgr daemon instances and get the list of disabled daemons
        disabled_daemons = g_switch_eapi_handler.remove_all_plmgr_daemons()

        if disabled_daemons:
            logger.log("Disabled the following lom-plmgr daemons: {}".format(', '.join(disabled_daemons)))
        else:
            logger.log("No lom-plmgr daemons were found to disable.")

        for daemon in disabled_daemons:
            logger.log("Checking if {}'s config still exists...".format(daemon))

            # Check if the daemon config still exists
            if g_switch_eapi_handler.is_daemon_config_exists(daemon):
                logger.log("Error: {}'s config still exists after attempting to disable it.".format(daemon))
                cleanup_status = False
            else:
                logger.log("{}'s config has been successfully cleaned.".format(daemon))

    except Exception as e:
        logger.log("Error occurred while removing all plmgr daemons or validating daemon config: {}".format(e))
        cleanup_status = False

    return cleanup_status

def cleanup_lom_engine_daemon():
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
        logger.log("Checking if lom-engine daemon exists...")

        # Get the lom-engine daemon info
        lom_engine_info = g_switch_eapi_handler.get_daemon_lom_engine_info()

        if not lom_engine_info:
            logger.log("No lom-engine daemon config is enabled")
            return True

        logger.log("Disabling lom-engine")
        
        # Disable the lom-engine daemon
        g_switch_eapi_handler.remove_daemon('lom-engine') # removes the config
        logger.log("lom-engine disabled successfully")

        # Check if the lom-engine daemon config still exists
        if g_switch_eapi_handler.is_daemon_config_exists('lom-engine'):
            logger.log("Error: lom-engine's config still exists after attempting to disable it.")
            return False
        else:
            logger.log("lom-engine's config has been successfully cleaned.")

    except Exception as e:
        logger.log("Error occurred while removing lom-engine daemon or validating daemon config: {}".format(e))
        raise e

    return True

def validate_all_daemons():
    """
    This function is responsible for validating if all daemons are running.

    It performs the following steps:
    1. Check if the lom-engine daemon is running
    2. Check if all lom-plmgr instances are running
    3. Check the count of lom-plmgr instances

    Returns:
    bool: True if all daemons are running, False otherwise.
    """
    try:
        # Validate if lom-engine is running
        running = g_switch_eapi_handler.is_daemon_running('lom-engine')
        if not running:
            logger.log("lom-engine is not running")
            return False

        # Validate if all lom-plmgr instances are running
        lom_plmgr_info = g_switch_eapi_handler.get_daemon_lom_plmgr_info()

        # Check the count of lom-plmgr instances
        if not lom_plmgr_info or len(lom_plmgr_info) != len(g_procs_keys):
            logger.log("lom-plmgr is not running")
            return False
        else:
            for instance_name in lom_plmgr_info.keys():
                running = g_switch_eapi_handler.is_daemon_running(instance_name)
                if not running:
                    logger.log("{} is not running".format(instance_name))
                    return False

        logger.log("All daemons are running successfully")
        return True
    except Exception as e:
        logger.log("Error while validating daemons: {}".format(e))
        raise e
    #To-Do : Goutham : call is_process_port_in_namespace() to check

def check_and_start_lom_engine():
    """
    This function is responsible for starting the lom-engine daemon and checking if it's running.

    It performs the following steps:
    1. Start the lom-engine daemon in the management namespace
    2. Wait for some time after starting the daemon
    3. Check if the lom-engine daemon is running

    Returns:
    bool: True if the lom-engine daemon is running, False otherwise.
    """
    logger.log("Starting lom-engine daemon ...")
    try:
        # Start the lom-engine daemon in management namespace
        g_switch_eapi_handler.add_lom_engine_daemon(g_lom_engine_path, g_config_dir, RUN_MODE, 6, True)
        logger.log("lom-engine started successfully")
    except Exception as e:
        logger.log("Error while starting lom-engine: {}".format(e))
        raise e
    
    # Wait for some time after starting the daemon
    time.sleep(DAEMON_AFTER_ENABLED_WAIT_TIME)

    # Check if lom-engine daemon is running
    try:
        running = g_switch_eapi_handler.is_daemon_running('lom-engine')
    except Exception as e:
        logger.log("Error while checking if lom-engine is running: {}".format(e))
        raise e

    if not running:
        logger.log("lom-engine is not running")
        return False

    logger.log("lom-engine is running successfully")
    return True
    #To-Do : Goutham : call is_process_port_in_namespace() to check
    
def check_and_start_plugin_manager_deamon():
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
    for proc_id in g_procs_keys:
        # Start the lom-plugin-manager daemon
        logger.log("Starting lom-plmgr for proc_id {} ...".format(proc_id))
        try:
            g_switch_eapi_handler.add_plugin_manager_daemon(g_lom_plugin_mgr_path, proc_id, g_config_dir, RUN_MODE, 6, True)
            logger.log("lom-plmgr started successfully for proc_id {}".format(proc_id))            
        except Exception as e:
            logger.log("Error while starting lom-plmgr for proc_id {}: {}".format(proc_id, e))
            raise e
        
        time.sleep(DAEMON_AFTER_ENABLED_WAIT_TIME)
        instance_name = "lom-plmgr-{}".format(proc_id)

        # Check if lom-plmgr daemon is running
        try:
            running = g_switch_eapi_handler.is_daemon_running(instance_name)
        except Exception as e:
            logger.log("Error while checking if {} is running: {}".format(instance_name, e))
            raise e

        if not running:
            logger.log("{} is not running".format(instance_name))
            return False
        logger.log("{} is running successfully".format(instance_name))            
    return True
    #To-Do : Goutham : call is_process_port_in_namespace() to check
        
def pre_checks():
    """
    This function is responsible for performing pre-installation checks.

    It performs the following steps:
    1. Check if each configuration file exists
    2. Check if LoMEngine binary exists
    3. Check if LoMPluginMgr binary exists
    4. Check if LoMCli binary exists
    5. Check if the TerminAttr daemon is running or not

    Returns:
    bool: True if all checks pass, False otherwise.
    """
    try:
        # Check if each configuration file exists
        config_files = [PROC_CONF_FILE, ACTIONS_CONF_FILE, BINDINGS_CONF_FILE, GLOBALS_CONF_FILE]
        config_file_path = None
        for config_file in config_files:
            config_file_path = os.path.join(g_installer_dir, 'config', config_file)
            if not os.path.exists(config_file_path):
                logger.log("Error: Configuration file {} not found.".format(config_file))
                return False

        # Check if LoMEngine binary exists    
        if not os.path.exists(g_lom_engine_path):
            logger.log("Error: LoMEngine binary not found.")
            return False

        # Check if LoMPluginMgr binary exists
        if not os.path.exists(g_lom_plugin_mgr_path):
            logger.log("Error: LoMPluginMgr binary not found.")
            return False

        # Check if the LoMCli binary exists
        if not os.path.exists(g_lom_cli_path):
            logger.log("Error: LoMCli binary not found.")
            return False

         # Check if TerminAttr daemon is running or not
        running = g_switch_eapi_handler.is_daemon_running("TerminAttr")
        if not running:
            # Just check if the TerminAttr config is present or not
            exists = g_switch_eapi_handler.is_daemon_config_exists("TerminAttr")
            if exists:
                logger.log("TerminAttr daemon is not running, but daemon config is present in running config")            
            logger.log("TerminAttr daemon is not running & also daemon config not present in running config")  
            return False          
        else:
            logger.log("TerminAttr daemon is running")
            # get the  TerminAttr daemon details
            terminattrConfig = g_switch_eapi_handler.extract_terminattr_config()
            logger.log("TerminAttr daemon details: {}".format(json.dumps(terminattrConfig)))

        return True
    except Exception as e:
        logger.log("Error during pre-checks: {}".format(e))
        raise e

def post_checks():
    """
        This function is responsible for performing post-installation checks.

        Returns:
        bool: True if all checks pass, False otherwise.
    """
    return True

def common_checks():
    """
    This function is responsible for performing common checks and gathering system information.

    It performs the following steps:
    1. Get agent uptime info if ARISTA_INSTALLATION_CHECK_AGENT_UPTIMES is True
    2. Get system core dump info if ARISTA_INSTALLATION_CHECK_CORE_DUMP is True
    3. Get hardware capacity utilization info if ARISTA_INSTALLATION_CHECK_CAPACITY is True

    Returns:
    dict: A dictionary containing the gathered system information.
    """
    data = {}
    try:
        # Read the configuration from the globals.conf.json file
        directory = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))+"/config"
        filename = GLOBALS_CONF_FILE
        config = read_json_from_file(directory, filename)

        # Get agent uptime info
        if config.get('ARISTA_INSTALLATION_CHECK_AGENT_UPTIMES', str(CHECK_AGENT_UPTIMES)).lower() == 'true':
            data['agent_uptimes'] = g_switch_eapi_handler.get_agent_uptime_info()

        # Get system core dump info
        if config.get('ARISTA_INSTALLATION_CHECK_CORE_DUMP', str(CHECK_CORE_DUMP_INFO)).lower() == 'true':
            data['core_dump_info'] = g_switch_eapi_handler.get_system_coredump()

        # Get hardware capacity utilization info
        if config.get('ARISTA_INSTALLATION_CHECK_CAPACITY', str(CHECK_CAPACITY)).lower() == 'true':
            data['capacity'] = g_switch_eapi_handler.get_hardware_capacity_utilization(10)

    except Exception as e:
        logger.log("Error during common checks: {}".format(e))
        raise e

    return data

def validate_common_checks(before_data, after_data):
    """
    This function is responsible for validating the results of common checks before and after installation.

    It performs the following steps:
    1. Compare agent uptimes before and after if CHECK_AGENT_UPTIMES is True
    2. Compare core dump info before and after if CHECK_CORE_DUMP_INFO is True
    3. Compare hardware capacity utilization before and after if CHECK_CAPACITY is True

    Parameters:
    before_data (dict): The system information gathered before installation.
    after_data (dict): The system information gathered after installation.

    Returns:
    bool: True if all checks pass, False otherwise.
    """
    status = True
    try:
        # Compare agent uptimes
        if CHECK_AGENT_UPTIMES:
            result, output = g_switch_eapi_handler.compare_agent_uptimes(before_data['agent_uptimes'], after_data['agent_uptimes'])
            if result:
                logger.log("Agent uptime is increased")
            else:
                status = False
                logger.log("Agent uptime is not increased : {}".format(output))

        # Compare core dump info
        if CHECK_CORE_DUMP_INFO:
            result, output = g_switch_eapi_handler.compare_coredump(before_data['core_dump_info'], after_data['core_dump_info'])
            if result:
                logger.log("Core dump matched. No additional core dump is generated")
            else:
                status = False
                logger.log("Core dump is not matched. Additional core dump is generated : {}".format(output))

        # Compare hardware capacity utilization
        if CHECK_CAPACITY:
            result, output = g_switch_eapi_handler.compare_hardware_capacity_utilization(before_data['capacity'], after_data['capacity'], 5)
            if result:
                logger.log("Hardware Capacity is stable")
            else:
                status = False
                logger.log("Hardware Capacity is increased : {}".format(output))

    except Exception as e:
        logger.log("Error during common checks validation: {}".format(e))
        raise e

    return status


def get_syslog_facility_level():
    """
    This function retrieves the value of the SYSLOG_FACILITY_LEVEL key from a JSON file.

    The JSON file is located at the path constructed by concatenating ACTIVE_INSTALLER_DIR, "/config/", and GLOBALS_CONF_FILE.

    If the SYSLOG_FACILITY_LEVEL key is not present in the JSON file, or if there's an error opening or reading the file, or loading its contents, the function returns the value of SYSLOG_FACILITY_DEFAULT.

    Returns:
    str: The value of the SYSLOG_FACILITY_LEVEL key from the JSON file, or the value of SYSLOG_FACILITY_DEFAULT if the key is not present or there's an error.
    """
    path = ACTIVE_INSTALLER_DIR+"/config/"+GLOBALS_CONF_FILE

    try:
        with open(path, 'r') as f:
            data = json.load(f)

        return data.get('SYSLOG_FACILITY_LEVEL', SYSLOG_FACILITY_DEFAULT)
    except (IOError, ValueError):
        return SYSLOG_FACILITY_DEFAULT
    
def main():
    global logger

    # configure logger
    logger = MyLogger(log_to_syslog=True, facility=get_syslog_facility_level())

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-si", "--start-installation", type=str, help="Start installation at the specified path")
    group.add_argument("-ci", "--cleanup-installation", type=str, help="Clean up installation at the specified path")

    args = parser.parse_args()

    try:           
            if args.start_installation:
                success, _ = start_installation(args.start_installation)
                if not success:
                    logger.log_fatal("Error: Failed to start installation")                
            elif args.cleanup_installation:
                success = cleanup_installation(args.cleanup_installation)
                if not success:
                    logger.log_fatal("Error: Failed to cleanup installation")
            else:
                parser.error("No operation specified.")
    except Exception as e:
            logger.log_fatal("Error: Unexpected error occurred. {}".format(e))

    # If the script reaches this point, it means that everything went well
    sys.exit(0)


if __name__ == "__main__":
    main()