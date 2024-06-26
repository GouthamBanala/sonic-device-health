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
    return "Test Minimum detection frequence between each anomaly(link_crc) of same key"

def getTestDescription() :
    return "Test Minimum detection frequence between each anomaly of same key \
            It should be greater than INITIAL_DETECTION_REPORTING_FREQ_IN_MINS \
        "

def isEnabled() :
    return True 

def run_test():

    # Specify the patterns to be matched/not matched for engine logs
    engine_pat1 = r"{\"LoM_Action\":{\"Action\":\"iptcrc_detection\",\"InstanceId\":\"([\w-]+)\",\"AnomalyInstanceId\":\"([\w-]+)\",\"AnomalyKey\":\"([\w/]+)\",\"Response\":\"Detected IPTCRC\",\"ResultCode\":(\d+),\"ResultStr\":\"Success\"},\"State\":\"init\"}"
    engine_pat2 = r"{\"LoM_Action\":{\"Action\":\"iptcrc_detection\",\"InstanceId\":\"([\w-]+)\",\"AnomalyInstanceId\":\"([\w-]+)\",\"AnomalyKey\":\"([\w/]+)\",\"Response\":\"Detected IPTCRC\",\"ResultCode\":(\d+),\"ResultStr\":\"No follow up actions \(seq:iptcrc_bind-0\)\"},\"State\":\"complete\"}"

    engine_patterns = [
          (api.PATTERN_MATCH, engine_pat1), # This pattern must match
          (api.PATTERN_MATCH, engine_pat2) # This pattern must match
    ]
    
    # Specify the patterns to be matched/not matched for plmgr syslogs 
    plugin_pat_1 = "IPTCRCDetection Anomaly Detected"
    #plugin_pat_2 = r"In handleRequest\(\): Received response from plugin link_crc_detection, data : Action: link_crc_detection InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey: (\w+) Response: Detected Crc ResultCode: (\d+) ResultStr: Success"
    plugin_pat_2 = r"In handleRequest\(\): Completed processing action request for plugin:iptcrc_detection"
    plugin_pat_3 = r"In run\(\) : Sending response to engine : Action: iptcrc_detection InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey: ([\w/]+) Response: Detected IPTCRC ResultCode: (\d+) ResultStr: Success"
    plugin_pat_4 = r"SendServerResponse: succeeded \(proc_0/RecvServerRequestAction\)"
    plugin_pat_5 = r"RecvServerRequest: succeeded \(proc_0/RecvServerRequestAction\)"
    plugin_pat_6 = r"In run\(\) RecvServerRequest : Received action request : Action: (\w+) InstanceId: ([\w-]+) AnomalyInstanceId: ([\w-]+) AnomalyKey:  Timeout: (\d+)"
    plugin_pat_7 = r"In handleRequest\(\): Processing action request for plugin:iptcrc_detection, timeout:(\d+) InstanceId:([\w-]+) AnomalyInstanceId:([\w-]+) AnomalyKey:"
    plugin_pat_8 = r"STarted Request\(\) for \((\w+)\)"
    plugin_pat_9 = "IPTCRC Detection Starting"

    plmgr_patterns = [
          (api.PATTERN_MATCH, plugin_pat_1), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_2), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_3), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_4), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_5), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_6), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_7), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_8), # This pattern must match
          (api.PATTERN_MATCH, plugin_pat_9) # This pattern must match
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

        "INITIAL_DETECTION_REPORTING_FREQ_IN_MINS": 2, # Change Here : This is the minimum detection time
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
        
    #clear counter drops 
    api.clear_hardware_counter_drop(g_switch_eapi_handler)
    
    # Specify the plmgr instance to be monitored
    plmgr_instance = "proc_0"

    # Create an instance of LogMonitor
    log_monitor = api.LogMonitor()

    interface_name = "Et3/1/1"
    vlan_id = 10

    # Create loopback config to silulate dot1q errors to indirectly test  IPTCRC plugin
    api.remove_interface_loopback(g_switch_eapi_handler, interface_name, vlan_id)
    api.configure_interface_loopback(g_switch_eapi_handler, interface_name, vlan_id)

    # Create an instance of BinaryRunner
    mac_address = api.get_mac_address(interface_name)
    formatted_mac_address = api.format_mac_address(mac_address)

    # Stop the binary
    binary_runner = api.BinaryRunner("/usr/bin/ethxmit", "-S", formatted_mac_address, "-D", formatted_mac_address, "--ip-src", "1.1.1.1", "--ip-dst", "1.1.1.2", "-c", "et3_1_1", "-n", "1", "-b", "10", "--sleep", "1")
    if binary_runner.stop_binary() == False:
        return api.TEST_FAIL
    
    # start the lom daemons
    if api.start_lom_daemons(g_switch_eapi_handler) == False:
        return api.TEST_FAIL
    
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

    with monitor_threads_context(monitor_threads, engine_stop_event, plmgr_stop_event, binary_runner): 

        # Start the binary
        if not binary_runner.run_binary_in_background():
            print("Failed to start linkcrc_mocker")
            stop_and_join_threads(monitor_threads, engine_stop_event, plmgr_stop_event)
            return api.TEST_FAIL
        print("linkcrc_mocker started ...........")

         # Initialize total_drop_count
        total_drop_count = 0

        # Poll every second for 15 seconds
        for _ in range(15):
            total_drop_count = api.show_hardware_counter_drop_count(g_switch_eapi_handler, 'dropVoqInPortNotVlanMember')
            print("Total drop count for dropVoqInPortNotVlanMember: {}".format(total_drop_count))
            if total_drop_count > 0:
                break
            time.sleep(1)

        if total_drop_count == 0:
            print("Error: Total drop count is 0. Expected drop count is greater than 0")
            stop_and_join_threads(monitor_threads, engine_stop_event, plmgr_stop_event)
            binary_runner.stop_binary()
            return api.TEST_FAIL
        
        # Wait for a specified duration to monitor the logs
        monitoring_duration = MAX_DETECTION_TIME + 60  # Specify the duration in seconds
        print("Waiting for {} seconds to monitor the logs".format(monitoring_duration))
        time.sleep(monitoring_duration)

        # Determine the test results based on the matched patterns
        status = api.TEST_PASS  # Return code 0 for test success

        ########## check that engine logs must contain all patterns in engine_patterns of type PATTERN_MATCH
        engine_match_count = 0
        for flag, pattern in engine_patterns:
            if flag == api.PATTERN_MATCH:
                with log_monitor.match_lock:  # Added lock here
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
                with log_monitor.match_lock:  # Added lock here
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
            print("Fail : Unable to proceed test further due to above failed conditions")
            return status

        ############## wait for the INITIAL_DETECTION_REPORTING_FREQ_IN_MINS(2 min) to check the time interval between each detections
        time.sleep(120)

        # Check for second log of plugin_pat_1 in plmgr logs. Compare its timestamp with first log of plugin_pat_1 in plmgr logs. It must be greater than atleast 120 sec.    

        # Print plugin_pat_1 matched logs
        print("\n\nMatched plmgr pattern ------------------ '{}' \nMatch Message ------------------".format(plugin_pat_1))
        with log_monitor.match_lock:  # Added lock here
            if plugin_pat_1 in log_monitor.plmgr_matched_patterns:
                for timestamp, log_message in log_monitor.plmgr_matched_patterns[plugin_pat_1]:
                    print("Timestamp: {}, Log Message: {}".format(timestamp, log_message))

        timestamp_plugin_pat_1_first = log_monitor.plmgr_matched_patterns.get(plugin_pat_1, [("", "")])[0][0]
        timestamp_plugin_pat_2_second = log_monitor.plmgr_matched_patterns.get(plugin_pat_1, [("", "")])[1][0]

        timestamp_plugin_pat_1_first_dt = api.parse_timestamp(timestamp_plugin_pat_1_first) if timestamp_plugin_pat_1_first else None
        timestamp_plugin_pat_2_second_dt = api.parse_timestamp(timestamp_plugin_pat_2_second) if timestamp_plugin_pat_2_second else None        

        if timestamp_plugin_pat_1_first_dt is not None and timestamp_plugin_pat_2_second_dt is not None:
            if (timestamp_plugin_pat_2_second_dt - timestamp_plugin_pat_1_first_dt).total_seconds() >= 120:
                print("\nSuccess, Time interval between each detection is greater than  INITIAL_DETECTION_REPORTING_FREQ_IN_MINS seconds")
            else:
                print("\nFail, Time interval between each detection is less than INITIAL_DETECTION_REPORTING_FREQ_IN_MINS seconds")
                status = api.TEST_FAIL
        else:
            print("\nFail, Unable to determine time interval between each detection")
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
def monitor_threads_context(monitor_threads, engine_stop_event, plmgr_stop_event, binary_runner):
    try:
        yield monitor_threads
    finally:
         # Stop the binary
        print("Stopping ethxmit")
        binary_runner.stop_binary()
        
        print("Stopping the monitoring threads")
        stop_and_join_threads(monitor_threads, engine_stop_event, plmgr_stop_event)

