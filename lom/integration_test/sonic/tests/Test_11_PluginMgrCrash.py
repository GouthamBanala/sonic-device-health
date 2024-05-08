import subprocess
import sys
import threading
import re
import time
import select
import contextlib
from datetime import datetime

import src.api as api

def isMandatoryPass() :
    return True

def getTestName() :
    return "Test plugin manager crash"

def getTestDescription() :
    return " When Plugin manager crashes, engine should still function \
             SInce heartbeats from plugin manager are missed, engine must report external heartbeats\
             which must not include any plugins(link_crc_detection)\
            "

def isEnabled() :
    return True

def run_test():
    
    # Specify the patterns to be matched/not matched for engine logs
    engine_pat1 = r'\{"LoM_Heartbeat":\{"Actions":\["link_crc_detection"\],"Timestamp":(\d+)\}\}'
    engine_pat2 = r'\{"LoM_Heartbeat":\{"Actions":\[\],"Timestamp":(\d+)\}\}'
    
    engine_patterns = [
          (api.PATTERN_MATCH, engine_pat1), # This pattern must match
          (api.PATTERN_MATCH, engine_pat2), # This pattern must match
    ]
    
    # Specify the patterns to be matched/not matched for plmgr syslogs 
    plugin_pat_1 = r"link_crc_detection: ExecuteCrcDetection Starting"
    plugin_pat_2 = r"In run\(\) RecvServerRequest : Received action request : Action: (\w+) InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey:  Timeout: (\d+)"
    plugin_pat_3 = r"In handleRequest\(\): Processing action request for plugin:link_crc_detection, timeout:(\d+) InstanceId:([\w-]+) AnomalyInstanceId:([\w-]+) AnomalyKey:"
    plugin_pat_4 = r"STarted Request\(\) for \((\w+)\)"
    plugin_pat_5 = r"Notified heartbeat from action \((proc_\d+/link_crc_detection)\)"
    

    plmgr_patterns = [
          (api.PATTERN_MATCH, plugin_pat_1), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_2), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_3), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_4), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_5), # This pattern must match
    ]

    # Specify the minimum and maximum detection time in seconds
    MIN_DETECTION_TIME = 60
    MAX_DETECTION_TIME = 60

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
        print("Error overwriting file {api.ACTIONS_CONFIG_FILE} in Docker container with JSON data")
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
        print("Error overwriting file {api.BINDINGS_CONFIG_FILE} in Docker container with JSON data")
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
        print("Error overwriting file {api.GLOBALS_CONFIG_FILE} in Docker container with JSON data")
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
        print("Error overwriting file {api.PROCS_CONFIG_FILE} in Docker container with JSON data")
        return api.TEST_FAIL

    # Restart the device health service
    if api.restart_service("device-health") == False:
        return api.TEST_FAIL
    
    # Specify the plmgr instance to be monitored
    plmgr_instance = "proc_0"

    # Create an instance of LogMonitor
    log_monitor = api.LogMonitor()

    # Create separate events to signal the monitoring threads to stop
    engine_stop_event = threading.Event()
    plmgr_stop_event = threading.Event()

    # Create a list to hold the monitoring threads
    monitor_threads = []

    # Start the syslog monitoring thread for engine syslogs. Force wait untill monitoring_duration is expired as need to match all dublicate logs
    monitor_engine_thread_1 = threading.Thread(target=log_monitor.monitor_engine_syslogs_noblock, args=(engine_patterns, engine_stop_event, True))
    monitor_engine_thread_1.start()
    monitor_threads.append(monitor_engine_thread_1)

    # Start the syslog monitoring thread for plmgr syslogs. Force wait untill monitoring_duration is expired as need to match all dublicate logs
    monitor_plmgr_thread_1 = threading.Thread(target=log_monitor.monitor_plmgr_syslogs_noblock, args=(plmgr_patterns, plmgr_instance, plmgr_stop_event, True))
    monitor_plmgr_thread_1.start()
    monitor_threads.append(monitor_plmgr_thread_1)

    # Wait for a some time to get both processes running
    monitoring_duration = MAX_DETECTION_TIME + 60  # Specify the duration in seconds
    time.sleep(monitoring_duration)

    with monitor_threads_context(log_monitor, monitor_threads, engine_stop_event, plmgr_stop_event):      
        # Determine the test results based on the matched patterns
        status = api.TEST_PASS  # Return code 0 for test success

        # pasue monitorint logs
        log_monitor.pause_monitoring()

        ########## check that engine logs must contain all patterns in engine_patterns of type PATTERN_MATCH
        engine_match_count = 0
        for flag, pattern in engine_patterns:
            if flag == api.PATTERN_MATCH:
                if pattern in log_monitor.engine_matched_patterns:
                    engine_match_count += 1
                    print(f"\nExpected, Matched engine pattern ------------------ \n'{pattern}' \nMatch Message ------------------")
                    for timestamp, log_message in log_monitor.engine_matched_patterns.get(pattern, []):
                        print(f"Timestamp: {timestamp}, Log Message: {log_message}")
                else:
                    print(f"\nUnExpected, No match found for engine pattern ------------------ '{pattern}'")

        expected_engine_match_count = len([p for t, p in engine_patterns if t == api.PATTERN_MATCH])
        if engine_match_count == expected_engine_match_count:
            print(f"\nSuccess, All engine match patterns matched for Test Case. Test for engine passed. Count: {engine_match_count}")
        else:
            print(f"\nFail, Expected engine match count: {expected_engine_match_count}, Actual count: {engine_match_count}. Some engine match patterns not matched for Test Case. Test for engine failed.")
            status = api.TEST_FAIL  # Return code 1 for test failure
                    
        ########### check that plmgr logs must contain all patterns in plmgr_patterns of type PATTERN_MATCH
        plmgr_match_count = 0
        for flag, pattern in plmgr_patterns:
            if flag == api.PATTERN_MATCH:
                if pattern in log_monitor.plmgr_matched_patterns:
                    plmgr_match_count += 1
                    print(f"\nExpected, Matched Plmgr pattern ------------------ \n'{pattern}' \nMatch Message ------------------")
                    for timestamp, log_message in log_monitor.plmgr_matched_patterns.get(pattern, []):
                        print(f"Timestamp: {timestamp}, Log Message: {log_message}")
                else:
                    print(f"\nUnExpected, No match found for plmgr pattern ------------------ '{pattern}'")

        expected_plmgr_match_count = len([p for t, p in plmgr_patterns if t == api.PATTERN_MATCH])
        if plmgr_match_count == expected_plmgr_match_count:
            print(f"\nSuccess, All PLMGR match patterns matched for Test Case. Test for PLMGR passed. Count: {plmgr_match_count}")
        else:
            print(f"\nFail, Expected PLMGR match count: {expected_plmgr_match_count}, Actual count: {plmgr_match_count}. Some PLMGR match patterns not matched for Test Case. Test for PLMGR failed.")
            status = api.TEST_FAIL  # Return code 1 for test failure

        if status == api.TEST_FAIL:
            return status
        
        ############# KIll the plmgr process and check that engine must be running and must report external heartbeats without including plugins
        print(f"Killing {api.LOM_PLUGIN_MGR_PROCESS_NAME} process")
        if not api.kill_process_by_name(api.LOM_PLUGIN_MGR_PROCESS_NAME, True) :
            print(f"Fail : Unable to kill {api.LOM_PLUGIN_MGR_PROCESS_NAME} process.")
            return api.TEST_FAIL
        
        time.sleep(5)

        # check if the engine process is running
        if not api.is_process_running(api.LOM_ENGINE_PROCESS_NAME) :
            print("Fail : {} process {api.LOM_ENGINE_PROCESS_NAME} is not running after killing plugin manager.")
            return api.TEST_FAIL
        print(f"Success : {api.LOM_ENGINE_PROCESS_NAME} process is running after killing {api.LOM_PLUGIN_MGR_PROCESS_NAME} process")

        # check if the device health service must be running using 
        ret, dstatus = api.check_device_health_status()
        print(f"Device health service status : {ret}, {dstatus}")
        if ret == "OK" and dstatus != True :
            print("Fail : Device health service is not running after killing plugin manager.")
            return api.TEST_FAIL
        print("Success : Device health service is running after killing plugin manager.")

        # Resume monitoring logs
        log_monitor.clear_log_buffers()
        log_monitor.resume_monitoring()

        # wait to check for engine logs
        time.sleep(60)

        # Stop the monitoring threads and join them
        stop_and_join_threads(log_monitor, monitor_threads, engine_stop_event, plmgr_stop_event)

        # Print engine matches logs for engine_pat1 & engine_pat2
        print(f"\nEngine matched patterns ------------------")
        for pattern in log_monitor.engine_matched_patterns:
            print(f"Pattern: {pattern}")
            for timestamp, log_message in log_monitor.engine_matched_patterns.get(pattern, []):
                print(f"Timestamp: {timestamp}, Log Message: {log_message}")
                
        expected_engine_match_count = len([p for t, p in engine_patterns if t == api.PATTERN_MATCH])
        if engine_match_count == expected_engine_match_count:
            print(f"\nSuccess, All engine match patterns matched for Test Case. Test for engine passed. Count: {engine_match_count}")
        else:
            print(f"\nFail, Expected engine match count: {expected_engine_match_count}, Actual count: {engine_match_count}. Some engine match patterns not matched for Test Case. Test for engine failed.")
            status = api.TEST_FAIL  # Return code 1 for test failure
                    

        # check the engine logs to see that it is reporting external heartbeats without including plugins(just engine_pat2 and not engine_pat1)
        if log_monitor.engine_matched_patterns.get(engine_pat1) :
            print(f"Fail : Engine is reporting heartbeats with plugin info. Logs contain pattern '{engine_pat1}' after killing plugin manager.")
            status = api.TEST_FAIL
        else :
            print(f"Success : Engine is reporting heartbeats without plugin. Logs do not contain pattern '{engine_pat1}' after killing plugin manager.")

        if not log_monitor.engine_matched_patterns.get(engine_pat2) :
            print(f"Fail : Engine is not reporting heartbeats without plugin link_crc. Logs do not contain pattern '{engine_pat2}' after killing plugin manager.")
            status = api.TEST_FAIL
        else :
            print(f"Success : Engine is reporting heartbeats without plugin. Logs contain pattern '{engine_pat2}' after killing plugin manager.")

    return status


def stop_and_join_threads(log_monitor, threads, engine_stop_event, plmgr_stop_event):
    # Resume monitoring logs if previously paused
    log_monitor.resume_monitoring()
    # Set the event to stop the monitoring threads
    engine_stop_event.set()
    plmgr_stop_event.set()

    # Join all the monitoring threads to wait for their completion
    for thread in threads:
        thread.join()

@contextlib.contextmanager
def monitor_threads_context(log_monitor, monitor_threads, engine_stop_event, plmgr_stop_event):
    try:
        yield monitor_threads
    finally:
        print("Stopping the monitoring threads")
        stop_and_join_threads(log_monitor, monitor_threads, engine_stop_event, plmgr_stop_event)