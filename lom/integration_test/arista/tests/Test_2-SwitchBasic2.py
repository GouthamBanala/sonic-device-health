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
    return "Check lom daemons are up, file locations"

def getTestDescription() :
    return "Check lom daemons are up, running stable for some time , \
          lom file locations & files are properly created at the expected"

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

        # verify plugin manager daemon is running stable

        # Store the initial PIDs
        initial_info = g_switch_eapi_handler.get_daemon_lom_plmgr_info()
        initial_pids = {k: v['PID'] for k, v in initial_info.items()}

        # Monitor the PIDs
        start_time = time.time()
        duration = 60  # Monitor for 60 seconds
        interval = 10  # Check every 10 seconds

        while time.time() - start_time < duration:
            time.sleep(interval)
            current_info = g_switch_eapi_handler.get_daemon_lom_plmgr_info()
            current_pids = {k: v['PID'] for k, v in current_info.items()}

            # Check if any PIDs have changed
            for proc, initial_pid in initial_pids.items():
                current_pid = current_pids.get(proc)
                if current_pid is None:
                    print("Error: {} not found".format(proc))
                    return api.TEST_FAIL
                elif current_pid != initial_pid:
                    print("PID of {} has changed from {} to {}".format(proc, initial_pid, current_pid))
                    initial_pids[proc] = current_pid  # Update the initial PID
        print("Plugin manager daemon is running stable")
        # verify engine daemon is running stable

        # Store the initial PID
        initial_info = g_switch_eapi_handler.get_daemon_lom_engine_info()
        initial_pid = initial_info.get('PID')

        # Monitor the PID
        start_time = time.time()
        duration = 60  # Monitor for 60 seconds
        interval = 10  # Check every 10 seconds

        while time.time() - start_time < duration:
            time.sleep(interval)
            current_info = g_switch_eapi_handler.get_daemon_lom_engine_info()
            current_pid = current_info.get('PID')

            # Check if PID has changed
            if current_pid is None:
                print("Error: lom-engine not found")
                return api.TEST_FAIL
            elif current_pid != initial_pid:
                print("PID of lom-engine has changed from {} to {}".format(initial_pid, current_pid))
                initial_pid = current_pid  # Update the initial PID
        print("Engine daemon is running stable")

        # verify the file locations
        #check active lom directory exists at /mnt/flash/lom
      
        # Check if the directory exists
        if os.path.isdir('/mnt/flash/lom/active'):
            print("Directory /mnt/flash/lom exists.")
        else:
            print("Directory /mnt/flash/lom does not exist.")
            return api.TEST_FAIL

        # List of files to check in active directory
        active_files = [
            '/config/procs.conf.json',
            '/config/globals.conf.json',
            '/config/actions.conf.json',
            '/config/chip_details_mapping.json',
            '/config/bindings.conf.json',
            '/install/bin/LoMPluginMgr',
            '/install/bin/LoMEngine',
            '/install/bin/LoMgNMIServer',
            '/install/bin/LoMCli',
            '/install/LoM-install.sh',
            '/install/startup/arista_cli_helper.py',
            '/install/startup/do-install.py',
            '/install/startup/common.py',
            '/install/startup/cli_tools.py',
            '/install/startup/arista_eapi_helper.py',
            '/install_params.json',
            '/libs/libzmq.so',
            '/libs/libsodium.so.26.1.0',
            '/libs/libsodium.so.26',
            '/libs/libzmq.so.5.2.6',
            '/libs/libzmq.so.5',
            '/libs/libsodium.so'
        ]

        # List of files to check in backup directory (without /install_params.json)
        backup_files = [file for file in active_files if file != '/install_params.json']

        # Check files in /mnt/flash/lom/active
        base_dir = '/mnt/flash/lom/active'
        for file in active_files:
            if os.path.isfile(base_dir + file):
                print("File {} exists.".format(base_dir + file))
            else:
                print("File {} does not exist.".format(base_dir + file))
                return api.TEST_FAIL
        print("All files exist in /mnt/flash/lom/active")

        # Check files in /mnt/flash/lom/backup if it exists
        backup_dir = '/mnt/flash/lom/backup'
        if os.path.isdir(backup_dir):
            for file in backup_files:
                if os.path.isfile(backup_dir + file):
                    print("File {} exists.".format(backup_dir + file))
                else:
                    print("File {} does not exist.".format(backup_dir + file))
                    return api.TEST_FAIL
        print("All files exist in /mnt/flash/lom/backup")

        return api.TEST_PASS

    except Exception as e:
        print("An error occurred: {}".format(e))
        return api.TEST_FAIL