import os
import sys
import time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import arista_eapi_helper as eapi_helper
import arista_cli_helper as cli_helper
import api


def isMandatoryPass() :
    return True

def getTestName() :
    return "Check lom daemons restarted when there is crash"

def getTestDescription() :
    return  "Check lom daemons restarted when there is crash"

def isEnabled() :
    return False

def run_test():
    try:
        # Create an instance of AristaSwitchEAPIHelper to execute commands via eAPI
        g_switch_eapi_handler = eapi_helper.AristaSwitchEAPIHelper()
        g_switch_eapi_handler.connect()
        print("Created an instance of AristaSwitchEAPIHelper")

        # validate the daemons
        if api.validate_all_daemons(g_switch_eapi_handler) == False:
            print("Failed to validate daemons")
            return api.TEST_FAIL
        print("Validated all daemons")

        # Verify plugin manager daemon restart
        # Store the initial PIDs
        initial_info = g_switch_eapi_handler.get_daemon_lom_plmgr_info()
        plmgr_process_names = list(initial_info.keys())
        plmgr_process_name = plmgr_process_names[0]

        plmgr_process_pid = initial_info[plmgr_process_name]['PID']

        # Kill this process forcefully 
        if api.kill_process_by_id(plmgr_process_pid, force=True):
            print("Process '{}' killed attempted with Id {}.".format(plmgr_process_name, plmgr_process_pid))
        else:
            print("Failed to kill process '{}' with Id {}.".format(plmgr_process_name, plmgr_process_pid))
            return api.TEST_FAIL
        
        # Now check if the plmgr_process_name restarted or not (With different PID)
        time.sleep(5)
        current_info = g_switch_eapi_handler.get_daemon_lom_plmgr_info()
        current_pids = {k: v['PID'] for k, v in current_info.items()}
        current_pid = current_pids.get(plmgr_process_name)

        if current_pid is None:
            print("Error: plugin manager with name {} not found".format(plmgr_process_name))
            return api.TEST_FAIL
        elif current_pid == plmgr_process_pid:
            print("PID of {} has not changed from {}".format(plmgr_process_name, plmgr_process_pid))
            return api.TEST_FAIL
        print("PID of {} has changed from {} to {}".format(plmgr_process_name, plmgr_process_pid, current_pid))

       
        # Verify engine daemon restart
        initial_info = g_switch_eapi_handler.get_daemon_lom_engine_info()
        initial_pid = initial_info.get('PID')
        engine_process_name = 'lom-engine'

        # Kill this process forcefully
        if api.kill_process_by_id(initial_pid, force=True):
            print("Process '{}' killed attempted with Id {}.".format(engine_process_name, initial_pid))
        else:
            print("Failed to kill process '{}' with Id {}.".format(engine_process_name, initial_pid))
            return api.TEST_FAIL

        # Now check if the engine_process_name restarted or not (With different PID)
        time.sleep(5)
        current_info = g_switch_eapi_handler.get_daemon_lom_engine_info()
        current_pid = current_info.get('PID')

        if current_pid is None:
            print("Error: {} not found".format(engine_process_name))
            return api.TEST_FAIL
        elif current_pid == initial_pid:
            print("PID of {} has not changed from {}".format(engine_process_name, initial_pid))
            return api.TEST_FAIL
        print("PID of {} has changed from {} to {}".format(engine_process_name, initial_pid, current_pid))


        return api.TEST_PASS

    except Exception as e:
        print("An error occurred: {}".format(e))
        return api.TEST_FAIL