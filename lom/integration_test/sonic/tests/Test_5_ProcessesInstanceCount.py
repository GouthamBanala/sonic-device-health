import subprocess
import sys
import threading
import re
import time
import select
import contextlib
import src.api as api

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
        "link_crc_detection": {
            "Name": "link_crc_detection",
            "Type": "Detection",
            "Timeout": 0,
            "HeartbeatInt": 30,
            "Disable": False,
            "Mimic": False,
            "ActionKnobs": {
                "DetectionFreqInSecs": 30,
                "IfInErrorsDiffMinValue": 0,
                "InUnicastPacketsMinValue": 100,
                "OutUnicastPacketsMinValue": 100,
                "OutlierRollingWindowSize": 5,
                "MinCrcError": 0.000001,
                "MinOutliersForDetection": 2,
                "LookBackPeriodInSecs": 125
            }
        }
    }

    if api.overwrite_file_in_docker_with_json_data(json_data, api.ACTIONS_CONFIG_FILE):
        print(f"JSON data for {api.ACTIONS_CONFIG_FILE} overwritten in Docker container successfully")
    else:
        print(f"Error overwriting file {api.ACTIONS_CONFIG_FILE} in Docker container with JSON data")
        return api.TEST_FAIL

    json_data = {
        "bindings": [
            {
                "SequenceName": "link_crc_bind-0",
                "Priority": 0,
                "Timeout": 2,
                "Actions": [{
                    "name": "link_crc_detection"
                }]
            }
        ]
    }

    if api.overwrite_file_in_docker_with_json_data(json_data, api.BINDINGS_CONFIG_FILE):
        print(f"JSON data for {api.BINDINGS_CONFIG_FILE} overwritten in Docker container successfully")
    else:
        print(f"Error overwriting file {api.BINDINGS_CONFIG_FILE} in Docker container with JSON data")
        return api.TEST_FAIL

    json_data = {
        "MAX_SEQ_TIMEOUT_SECS": 120,
        "MIN_PERIODIC_LOG_PERIOD_SECS": 1,
        "ENGINE_HB_INTERVAL_SECS": 10,
        "INITIAL_DETECTION_REPORTING_FREQ_IN_MINS": 5,
        "SUBSEQUENT_DETECTION_REPORTING_FREQ_IN_MINS": 60,
        "INITIAL_DETECTION_REPORTING_MAX_COUNT": 12,
        "PLUGIN_MIN_ERR_CNT_TO_SKIP_HEARTBEAT": 3,
        "MAX_PLUGIN_RESPONSES": 100,
        "MAX_PLUGIN_RESPONSES_WINDOW_TIMEOUT_IN_SECS": 60
    }

    if api.overwrite_file_in_docker_with_json_data(json_data, api.GLOBALS_CONFIG_FILE):
        print(f"JSON data for {api.GLOBALS_CONFIG_FILE} overwritten in Docker container successfully")
    else:
        print(f"Error overwriting file {api.GLOBALS_CONFIG_FILE} in Docker container with JSON data")
        return api.TEST_FAIL


    json_data = {
        "procs": {
            "proc_0": {
                "link_crc_detection": {
                    "name": "link_crc_detection",
                    "version": "1.0.0.0",
                    "path": ""
                }
            }
        }
    }

    if api.overwrite_file_in_docker_with_json_data(json_data, api.PROCS_CONFIG_FILE):
        print(f"JSON data for {api.PROCS_CONFIG_FILE} overwritten in Docker container successfully")
    else:
        print(f"Error overwriting file {api.PROCS_CONFIG_FILE} in Docker container with JSON data")
        return api.TEST_FAIL

     # Restart the device health service
    if api.restart_service("device-health") == False:
        return api.TEST_FAIL   
    
    time.sleep(30)
    
    # Specify the plmgr instance to be monitored
    plmgr_expected_instance_name = "proc_0"
    plmgr_expected_instance_count = 1

    # Check if the plugin manager service is running
    if api.is_process_running(api.LOM_PLUGIN_MGR_PROCESS_NAME) :
        print(f"Success : {api.LOM_PLUGIN_MGR_PROCESS_NAME} process is running")
    else:
        print(f"Fail: {api.LOM_PLUGIN_MGR_PROCESS_NAME} process is not running")
        return api.TEST_FAIL
    
    # Check if the engine service is running
    if api.is_process_running(api.LOM_ENGINE_PROCESS_NAME) :
        print(f"Success : {api.LOM_ENGINE_PROCESS_NAME} process is running")
    else:
        print(f"Fail: {api.LOM_ENGINE_PROCESS_NAME} process is not running")
        return api.TEST_FAIL
    
    # check only one instance of engine process is running
    engine_instances = api.get_lomengine_pids()
    if len(engine_instances) == 1:
        print(f"Success : Only one instance of {api.LOM_ENGINE_PROCESS_NAME} process is running")
    else:
        print(f"Fail: More than one instance of {api.LOM_ENGINE_PROCESS_NAME} process is running")
        return api.TEST_FAIL
    
    # check only one instance of plugin manager process is running as per procs.conf.json
    plmgr_instances = api.get_lompluginmgr_pids()
    if len(plmgr_instances) == plmgr_expected_instance_count:
        print(f"Success : Expected instances, {plmgr_expected_instance_count}  of {api.LOM_PLUGIN_MGR_PROCESS_NAME} process is running")
    else:
        print(f"Fail: Expected instances , {plmgr_expected_instance_count} of {api.LOM_PLUGIN_MGR_PROCESS_NAME} process is not running")
        return api.TEST_FAIL
    
    # check the instance name of plugin manager process is running as per procs.conf.json
    pid = plmgr_instances[0]
    proc_id = subprocess.getoutput(f"ps -p {pid} -o args= | awk -F'-proc_id=' '{{print $2}}' | awk '{{print $1}}'")
    print(f"  PID: {pid}, Proc ID: {proc_id}")
    if proc_id == plmgr_expected_instance_name:
        print(f"Success : Expected instance name, {plmgr_expected_instance_name}  of {api.LOM_PLUGIN_MGR_PROCESS_NAME} process is running")
    else:
        print(f"Fail: Expected instance name , {plmgr_expected_instance_name} of {api.LOM_PLUGIN_MGR_PROCESS_NAME} process is not running")
        return api.TEST_FAIL
    
    return api.TEST_PASS

