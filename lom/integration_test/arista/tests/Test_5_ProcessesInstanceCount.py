import subprocess
import sys
import threading
import re
import time
import select
import contextlib
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import arista_eapi_helper as eapi_helper
import arista_cli_helper as cli_helper
import api

def isMandatoryPass() :
    return True

def getTestName() :
    return "Test engine process, plugin manager instance count"

def getTestDescription() :
    return "Only one instance of engine process and plugin manager instances as per procs conf"

def isEnabled() :
    return False

def run_test():
    # Overwrite config files with test specific data in Docker container
    json_data = {
        "iptcrc_detection": {
            "Name": "iptcrc_detection",
            "Type": "Detection",
            "Timeout": 0,
            "HeartbeatInt": 30,
            "Disable": False,
            "Mimic": False,
            "ActionKnobs": {			
                "initial_detection_reporting_frequency_in_mins": 1,
                "subsequent_detection_reporting_frequency_in_mins": 1,
                "initial_detection_reporting_max_count": 12,
                "periodic_subscription_interval_in_hours" : 24,
                "error_backoff_time_in_secs" : 60,
                "iptcrc_test_counter_name": "dropVoqInPortNotVlanMember",
                "chipid_name_mappings_file": "/mnt/flash/lom/active/config/chip_details_mapping.json",
                "DetectionFreqInSecs": 30
            }
        }
    }

    if api.overwrite_file_with_json_data(json_data, api.ACTIVE_INSTALLER_DIR + "/config/" + api.ACTIONS_CONFIG_FILE ):
        print("JSON data for {} overwritten at active installer directory successfully".format(api.ACTIONS_CONFIG_FILE))
    else:
        print("Error overwriting file {} active installer directory with JSON data".format(api.ACTIONS_CONFIG_FILE))
        return api.TEST_FAIL

    json_data = {
        "bindings": [
            {
                "SequenceName": "iptcrc_bind-0",
                "Priority": 0,
                "Timeout": 2,
                "Actions": [{
                    "name": "iptcrc_detection"
                }]
            }
        ]
    }

    if api.overwrite_file_with_json_data(json_data,  api.ACTIVE_INSTALLER_DIR + "/config/" + api.BINDINGS_CONFIG_FILE ):
        print("JSON data for {} overwritten at active installer directory successfully".format(api.BINDINGS_CONFIG_FILE))
    else:
        print("Error overwriting file {} active installer directory with JSON data".format(api.BINDINGS_CONFIG_FILE))
        return api.TEST_FAIL

    json_data = {
        "VENDOR": "Arista",
        "MAX_SEQ_TIMEOUT_SECS": 120,
        "MIN_PERIODIC_LOG_PERIOD_SECS": 1,
        "ENGINE_HB_INTERVAL_SECS": 10,

        "INITIAL_DETECTION_REPORTING_FREQ_IN_MINS": 5,
        "SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS": 60,
        "INITIAL_DETECTION_REPORTING_MAX_COUNT": 12,
        "PLUGIN_MIN_ERR_CNT_TO_SKIP_HEARTBEAT" : 3, 
        
        "MAX_PLUGIN_RESPONSES" : 100,
        "MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT_IN_SECS" : 60,

        "LOCAL_GNMI_SERVER_USERNAME": "admin",
        "LOCAL_GNMI_SERVER_PASSWORD": "password",
        "LOCAL_GNMI_SERVER_ADDRESS": "localhost:50051",            
        "LOCAL_GNMI_USE_TLS" : "true",
        "LOCAL_GNMI_CERTIFICATE_FILE_PATH" : "/mnt/flash/goutham/certs_new/streamingtelemetryserver.cer",
        "LOCAL_GNMI_PRIVATE_KEY_FILE_PATH" : "/mnt/flash/goutham/certs_new/streamingtelemetryserver.key",
        "LOCAL_GNMI_CA_CERTIFICATE_FILE_PATH" : "/mnt/flash/goutham/certs_new/dsmsroot.cer",
        "LOCAL_GNMI_VALIDATE_SERVER_CERTIFICATE" : "false"    ,

        "ARISTA_INSTALLATION_CHECK_AGENT_UPTIMES" : "true",
        "ARISTA_INSTALLATION_CHECK_CORE_DUMP" : "false",
        "ARISTA_INSTALLATION_CHECK_CAPACITY" : "true",

        "SYSLOG_FACILITY_LEVEL" : "LOG_LOCAL4"
    }

    if api.overwrite_file_with_json_data(json_data,  api.ACTIVE_INSTALLER_DIR + "/config/" + api.GLOBALS_CONFIG_FILE ):
        print("JSON data for {} overwritten at active installer directory successfully".format(api.GLOBALS_CONFIG_FILE))
    else:
        print("Error overwriting file {} active installer directory with JSON data".format(api.GLOBALS_CONFIG_FILE))
        return api.TEST_FAIL


    json_data = {
        "procs": {
            "proc_0": {
                "iptcrc_detection": {
                    "name": "iptcrc_detection",
                    "version": "1.0.0.0",
                    "path": ""
                }
            }
        }
    }

    if api.overwrite_file_with_json_data(json_data,  api.ACTIVE_INSTALLER_DIR + "/config/" + api.PROCS_CONFIG_FILE ):
        print("JSON data for {} overwritten at active installer directory successfully".format(api.PROCS_CONFIG_FILE))
    else:
        print("Error overwriting file {} active installer directory with JSON data".format(api.PROCS_CONFIG_FILE))
        return api.TEST_FAIL

    # Create an instance of AristaSwitchCLIHelper to talk to switch via CLI
    g_switch_cli_handler = cli_helper.AristaSwitchCLIHelper()
    print("Created an instance of AristaSwitchCLIHelper")

    # Enable Unix eAPI protocol to execute commands via eAPI
    running, eapi_already_enabled = g_switch_cli_handler.check_and_enable_unix_eAPI_protocol()
    existing_install_config = {}
    existing_install_config['eapi_already_enabled'] = eapi_already_enabled
    if running:
        if eapi_already_enabled:
            print("EAPI was already enabled.")
        else:
            print("EAPI has been successfully enabled.")
    else:
        print("Error: Unix eAPI protocol is not running.")
        return False, None
    
    # Create an instance of AristaSwitchEAPIHelper to execute commands via eAPI
    g_switch_eapi_handler = eapi_helper.AristaSwitchEAPIHelper()
    g_switch_eapi_handler.connect()
    print("Created an instance of AristaSwitchEAPIHelper")

    #clean up existing lom daemons
    if api.cleanup_lom_daemons(g_switch_eapi_handler) == False:
        return api.TEST_FAIL


    # start the lom daemons
    if api.start_lom_daemons(g_switch_eapi_handler) == False:
        return api.TEST_FAIL

    
    # Specify the plmgr instance to be monitored
    plmgr_expected_instance_name = "proc_0"
    plmgr_expected_instance_count = 1

    # Check if the plugin manager service is running
    if api.is_process_running(api.LOM_PLUGIN_MGR_PROCESS_NAME) :
        print("Success : {} process is running".format(api.LOM_PLUGIN_MGR_PROCESS_NAME))
    else:
        print("Fail: {} process is not running".format(api.LOM_PLUGIN_MGR_PROCESS_NAME))
        return api.TEST_FAIL
    
    # Check if the engine service is running
    if api.is_process_running(api.LOM_ENGINE_PROCESS_NAME) :
        print("Success : {} process is running".format(api.LOM_ENGINE_PROCESS_NAME))
    else:
        print("Fail: {} process is not running".format(api.LOM_ENGINE_PROCESS_NAME))
        return api.TEST_FAIL
    
    # check only one instance of engine process is running
    engine_instances = api.get_lomengine_pids()
    if len(engine_instances) == 1:
        print("Success : Only one instance of {} process is running".format(api.LOM_ENGINE_PROCESS_NAME))
    else:
        print("Fail: More than one instance of {} process is running".format(api.LOM_ENGINE_PROCESS_NAME))
        return api.TEST_FAIL
    
    # check only one instance of plugin manager process is running as per procs.conf.json
    plmgr_instances = api.get_lompluginmgr_pids()
    if len(plmgr_instances) == plmgr_expected_instance_count:
        print("Success : Expected instances, {} of {} process is running".format(plmgr_expected_instance_count, api.LOM_PLUGIN_MGR_PROCESS_NAME))
    else:
        print("Fail: Expected instances , {} of {} process is not running".format(plmgr_expected_instance_count, api.LOM_PLUGIN_MGR_PROCESS_NAME))
        return api.TEST_FAIL
    
    # check the instance name of plugin manager process is running as per procs.conf.json
    pid = plmgr_instances[0]
    proc_id = subprocess.check_output("ps -p {} -o args= | awk -F'-proc_id=' '{{print $2}}' | awk '{{print $1}}'".format(pid), shell=True).strip()
    print ("  PID: {}, Proc ID: {}".format(pid, proc_id))
    if proc_id == plmgr_expected_instance_name:
        print ("Success : Expected instance name, {} of {} process is running".format(plmgr_expected_instance_name, api.LOM_PLUGIN_MGR_PROCESS_NAME))
    else:
        print ("Fail: Expected instance name , {} of {} process is not running".format(plmgr_expected_instance_name, api.LOM_PLUGIN_MGR_PROCESS_NAME))
        return api.TEST_FAIL
    
    return api.TEST_PASS

