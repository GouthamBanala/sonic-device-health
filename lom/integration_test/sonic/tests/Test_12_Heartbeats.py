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
    return "Test heartbeats from plugin to engine"

def getTestDescription() :
    return " Plugin must send heartbeats to engine periodically. Test that period \
            When anomaly is detected, again when new request is processed, heartbeats must resume \
        "

def isEnabled() :
    return False 

def run_test():

    # Specify the patterns to be matched/not matched for engine logs
    engine_pat1 = r"{\"LoM_Action\":{\"Action\":\"link_crc_detection\",\"InstanceId\":\"([\w-]+)\",\"AnomalyInstanceId\":\"([\w-]+)\",\"AnomalyKey\":\"(\w+)\",\"Response\":\"Detected Crc\",\"ResultCode\":(\d+),\"ResultStr\":\"Success\"},\"State\":\"init\"}"
    engine_pat2 = r"{\"LoM_Action\":{\"Action\":\"link_crc_detection\",\"InstanceId\":\"([\w-]+)\",\"AnomalyInstanceId\":\"([\w-]+)\",\"AnomalyKey\":\"(\w+)\",\"Response\":\"Detected Crc\",\"ResultCode\":(\d+),\"ResultStr\":\"No follow up actions \(seq:link_crc_bind-0\)\"},\"State\":\"complete\"}"

    engine_patterns = [
          (api.PATTERN_MATCH, engine_pat1), # This pattern must match
          (api.PATTERN_MATCH, engine_pat2) # This pattern must match
    ]
    
    # Specify the patterns to be matched/not matched for plmgr syslogs 
    plugin_pat_1 = "link_crc_detection: executeCrcDetection Anomaly Detected"
    plugin_pat_2 = r"In handleRequest\(\): Received response from plugin link_crc_detection, data : Action: link_crc_detection InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey: (\w+) Response: Detected Crc ResultCode: (\d+) ResultStr: Success"
    plugin_pat_3 = r"In handleRequest\(\): Completed processing action request for plugin:link_crc_detection"
    plugin_pat_4 = r"In run\(\) : Sending response to engine : Action: link_crc_detection InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey: (\w+) Response: Detected Crc ResultCode: (\d+) ResultStr: Success"
    plugin_pat_5 = r"SendServerResponse: succeeded \(proc_0/RecvServerRequestAction\)"
    plugin_pat_6 = r"RecvServerRequest: succeeded \(proc_0/RecvServerRequestAction\)"
    plugin_pat_7 = r"In run\(\) RecvServerRequest : Received action request : Action: (\w+) InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey:  Timeout: (\d+)"
    plugin_pat_8 = r"In handleRequest\(\): Processing action request for plugin:link_crc_detection, timeout:(\d+) InstanceId:([\w-]+) AnomalyInstanceId:([\w-]+) AnomalyKey:"
    plugin_pat_9 = r"STarted Request\(\) for \((\w+)\)"
    plugin_pat_10 = r"link_crc_detection: ExecuteCrcDetection Starting"
    plugin_pat_11 = r"In run\(\) : Sending response to engine : Heartbeat notification: link_crc_detection (\d+)"


    plmgr_patterns = [
          (api.PATTERN_MATCH, plugin_pat_1), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_2), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_3), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_4), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_5), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_6), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_7), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_8), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_9), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_10), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_11) # This pattern must match
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
    
    # Specify the plmgr instance to be monitored
    plmgr_instance = "proc_0"

    # Create an instance of LogMonitor
    log_monitor = api.LogMonitor()

    # Create an instance of BinaryRunner
    binary_runner = api.BinaryRunner("../bin/linkcrc_mocker", "0", "Ethernet96")

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

    with monitor_threads_context(monitor_threads, engine_stop_event, plmgr_stop_event):   
            
        # Stop the binary
        if binary_runner.stop_binary() == False:
            return api.TEST_FAIL

        # Start the binary
        if not binary_runner.run_binary_in_background():
            print("Failed to start linkcrc_mocker")
            stop_and_join_threads(monitor_threads, engine_stop_event, plmgr_stop_event)
            return api.TEST_FAIL
        print("linkcrc_mocker started ...........")

        # Wait for a specified duration to monitor the logs(one outlier)
        monitoring_duration = MAX_DETECTION_TIME + 60  # Specify the duration in seconds
        time.sleep(monitoring_duration)

         # Stop the monitoring threads and join them
        stop_and_join_threads(monitor_threads, engine_stop_event, plmgr_stop_event)

        # Stop the binary
        if not binary_runner.stop_binary():
            print("Failed to stop linkcrc_mocker")
            return api.TEST_FAIL
        
        # Determine the test results based on the matched patterns
        status = api.TEST_PASS  # Return code 0 for test success

        ########## check that engine logs must contain all patterns in engine_patterns of type PATTERN_MATCH
        engine_match_count = 0
        for flag, pattern in engine_patterns:
            if flag == api.PATTERN_MATCH:
                with log_monitor.match_lock:  # Added lock here
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
                with log_monitor.match_lock:  # Added lock here
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
            print("Fail : Unable to proceed test further due to above failed conditions")
            return status

        ######### Chech the heartbeats from plugin i.e. plugin_pat_11. Each heartbeat must be send periodically every 30 sec
        print(f"\nChecking heartbeats are sent periodically or not from plugin\n")
        with log_monitor.match_lock:  # Added lock here
            if plugin_pat_11 in log_monitor.plmgr_matched_patterns:
                previousTimestamp = None                
                for timestamp, log_message in log_monitor.plmgr_matched_patterns.get(plugin_pat_11, []):
                    print(f"Timestamp: {timestamp}, Log Message: {log_message}")
                    if previousTimestamp is not None:                        
                        if (datetime.strptime(timestamp, "%b %d %H:%M:%S.%f") - datetime.strptime(previousTimestamp, "%b %d %H:%M:%S.%f")).total_seconds() >= 30 and \
                                (datetime.strptime(timestamp, "%b %d %H:%M:%S.%f") - datetime.strptime(previousTimestamp, "%b %d %H:%M:%S.%f")).total_seconds() <= 31:
                            print(f"\nSuccess, Heartbeats are sent periodically from plugin")
                            previousTimestamp = timestamp
                        else:
                            print(f"\nFail, Heartbeats are not sent periodically from plugin")
                            status = api.TEST_FAIL
        
        # Now to make sure after anomaly is detected, heartbeats must resume and check that heartbeats are sent periodically or not from plugin
        
        print(f"\nChecking heartbeats are sent periodically or not from plugin after anomaly is detected\n")
        
        # Get timestamp of detection(plugin_pat_1)
        timestamp_of_detection = None
        if plugin_pat_1 in log_monitor.plmgr_matched_patterns:
            for timestamp, log_message in log_monitor.plmgr_matched_patterns.get(plugin_pat_1, []):
                timestamp_of_detection = timestamp
                break

        with log_monitor.match_lock:  # Added lock here
            if plugin_pat_11 in log_monitor.plmgr_matched_patterns:
                previousTimestamp = None                
                for timestamp, log_message in log_monitor.plmgr_matched_patterns.get(plugin_pat_11, []):
                    if timestamp < timestamp_of_detection:
                        continue
                    print(f"Timestamp: {timestamp}, Log Message: {log_message}")
                    if previousTimestamp is not None:                        
                        if (datetime.strptime(timestamp, "%b %d %H:%M:%S.%f") - datetime.strptime(previousTimestamp, "%b %d %H:%M:%S.%f")).total_seconds() >= 30 and \
                                (datetime.strptime(timestamp, "%b %d %H:%M:%S.%f") - datetime.strptime(previousTimestamp, "%b %d %H:%M:%S.%f")).total_seconds() <= 31 :
                            print(f"\nSuccess, Heartbeats are sent periodically from plugin after anomaly is detected")
                            previousTimestamp = timestamp
                        else:
                            print(f"\nFail, Heartbeats are not sent periodically from plugin after anomaly is detected")
                            status = api.TEST_FAIL
       

    return status


def stop_and_join_threads(threads, engine_stop_event, plmgr_stop_event):
    # Set the event to stop the monitoring threads
    engine_stop_event.set()
    plmgr_stop_event.set()

    # Join all the monitoring threads to wait for their completion
    for thread in threads:
        thread.join()

@contextlib.contextmanager
def monitor_threads_context(monitor_threads, engine_stop_event, plmgr_stop_event):
    try:
        yield monitor_threads
    finally:
        print("Stopping the monitoring threads")
        stop_and_join_threads(monitor_threads, engine_stop_event, plmgr_stop_event)

