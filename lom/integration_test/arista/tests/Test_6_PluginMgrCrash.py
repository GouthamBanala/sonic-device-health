import subprocess
import sys
import threading
import re
import time
import select
import contextlib
from datetime import datetime
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import arista_eapi_helper as eapi_helper
import arista_cli_helper as cli_helper
import api

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
    return False 

def run_test():
    
    # Specify the patterns to be matched/not matched for engine logs
    engine_pat1 = r'\{"LoM_Heartbeat":\{"Actions":\["iptcrc_detection"\],"Timestamp":(\d+)\}\}'
    engine_pat2 = r'\{"LoM_Heartbeat":\{"Actions":\[\],"Timestamp":(\d+)\}\}'
    
    engine_patterns = [
          (api.PATTERN_MATCH, engine_pat1), # This pattern must match
          (api.PATTERN_MATCH, engine_pat2), # This pattern must match
    ]
    
    # Specify the patterns to be matched/not matched for plmgr syslogs 
    plugin_pat_1 = "IPTCRC Detection Starting"
    plugin_pat_2 = r"In run\(\) RecvServerRequest : Received action request : Action: (\w+) InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey:  Timeout: (\d+)"
    plugin_pat_3 = r"In handleRequest\(\): Processing action request for plugin:iptcrc_detection, timeout:(\d+) InstanceId:([\w-]+) AnomalyInstanceId:([\w-]+) AnomalyKey:"
    plugin_pat_4 = r"STarted Request\(\) for \((\w+)\)"
    plugin_pat_5 = r"Notified heartbeat from action \((proc_\d+/iptcrc_detection)\)"
    
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
    
    # Specify the plmgr instance to be monitored
    plmgr_instance = "proc_0"

    plmgr_process_name = "lom-plmgr" + "-" + plmgr_instance

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

     # start the lom daemons
    if api.start_lom_daemons(g_switch_eapi_handler) == False:
        return api.TEST_FAIL
        
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
                    print("\nExpected, Matched engine pattern ------------------ \n'{}' \nMatch Message ------------------".format(pattern))
                    for timestamp, log_message in log_monitor.engine_matched_patterns.get(pattern, []):
                        print("Timestamp: {}, Log Message: {}".format(timestamp, log_message))
                else:
                    print("\nUnExpected, No match found for engine pattern ------------------ '{}'".format(pattern))

        expected_engine_match_count = len([p for t, p in engine_patterns if t == api.PATTERN_MATCH])
        if engine_match_count == expected_engine_match_count:
            print("\nSuccess, All engine match patterns matched for Test Case. Test for engine passed. Count: {}".format(engine_match_count))
        else:
            print("\nFail, Expected engine match count: {}, Actual count: {}. Some engine match patterns not matched for Test Case. Test for engine failed.".format(expected_engine_match_count, engine_match_count))
            status = api.TEST_FAIL  # Return code 1 for test failure
                    
        ########### check that plmgr logs must contain all patterns in plmgr_patterns of type PATTERN_MATCH
        plmgr_match_count = 0
        for flag, pattern in plmgr_patterns:
            if flag == api.PATTERN_MATCH:
                if pattern in log_monitor.plmgr_matched_patterns:
                    plmgr_match_count += 1
                    print("\nExpected, Matched Plmgr pattern ------------------ \n'{}' \nMatch Message ------------------".format(pattern))
                    for timestamp, log_message in log_monitor.plmgr_matched_patterns.get(pattern, []):
                        print("Timestamp: {}, Log Message: {}".format(timestamp, log_message))
                else:
                    print("\nUnExpected, No match found for plmgr pattern ------------------ '{}'".format(pattern))

        expected_plmgr_match_count = len([p for t, p in plmgr_patterns if t == api.PATTERN_MATCH])
        if plmgr_match_count == expected_plmgr_match_count:
            print("\nSuccess, All PLMGR match patterns matched for Test Case. Test for PLMGR passed. Count: {}".format(plmgr_match_count))
        else:
            print("\nFail, Expected PLMGR match count: {}, Actual count: {}. Some PLMGR match patterns not matched for Test Case. Test for PLMGR failed.".format(expected_plmgr_match_count, plmgr_match_count))
            status = api.TEST_FAIL  # Return code 1 for test failure

        if status == api.TEST_FAIL:
            return status
        
        ############# KIll the plmgr process and check that engine must be running and must report external heartbeats without including plugins
        ##Here we are disabling daemon instead of killing as killing will restart the process by Arista process manager. But it will restart upto certain times.        
        print("Killing plugin manager process")
        
        g_switch_eapi_handler.remove_daemon(plmgr_process_name)
        time.sleep(5)
        if g_switch_eapi_handler.is_daemon_running(plmgr_process_name):
            print("Fail : {} process {plmgr_process_name} is running after killing plugin manager.")
            return api.TEST_FAIL

        # check if the engine process is running
        if not api.is_process_running(api.LOM_ENGINE_PROCESS_NAME) :
            print("Fail : {} process {api.LOM_ENGINE_PROCESS_NAME} is not running after killing plugin manager.")
            return api.TEST_FAIL
        print("Success : {} process {api.LOM_ENGINE_PROCESS_NAME} is running after killing plugin manager.")

        print('Sleeping for 31 seconds to check for engine logs')
        time.sleep(31)

        # Resume monitoring logs
        log_monitor.clear_log_buffers()            
        log_monitor.resume_monitoring()

        # wait to check for engine logs
        print('Sleeping for 60 seconds to check for engine logs')
        time.sleep(60)

        # Stop the monitoring threads and join them
        stop_and_join_threads(log_monitor, monitor_threads, engine_stop_event, plmgr_stop_event)

        # Print engine matches logs for engine_pat1 & engine_pat2
        print("\nEngine matched patterns ------------------")
        for pattern in log_monitor.engine_matched_patterns:
            print("Pattern: {}".format(pattern))
            for timestamp, log_message in log_monitor.engine_matched_patterns.get(pattern, []):
                print("Timestamp: {}, Log Message: {}".format(timestamp, log_message))                

        # check the engine logs to see that it is reporting external heartbeats without including plugins(just engine_pat2 and not engine_pat1)
        if log_monitor.engine_matched_patterns.get(engine_pat1) :
            print("Fail : Engine is reporting heartbeats with plugin info. Logs contain pattern '{engine_pat1}' after killing plugin manager.")
            status = api.TEST_FAIL
        else :
            print("Success : Engine is reporting heartbeats without plugin. Logs do not contain pattern '{engine_pat1}' after killing plugin manager.")

        if not log_monitor.engine_matched_patterns.get(engine_pat2) :
            print("Fail : Engine is not reporting heartbeats without plugin link_crc. Logs do not contain pattern '{engine_pat2}' after killing plugin manager.")
            status = api.TEST_FAIL
        else :
            print("Success : Engine is reporting heartbeats without plugin. Logs contain pattern '{engine_pat2}' after killing plugin manager.")

        api.check_and_start_plugin_manager_deamon(g_switch_eapi_handler)

    return status


def stop_and_join_threads(log_monitor, threads, engine_stop_event, plmgr_stop_event):
    # Resume monitoring logs if previously paused
    #log_monitor.resume_monitoring()
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