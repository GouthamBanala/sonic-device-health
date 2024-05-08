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
    return "Check lom-inside temporary file"

def getTestDescription() :
    return "Check lom-inside temporary file at /mnt/flash/lom-inside"

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

        # Now check for the temporary file

        # Path to the file
        file_path = '/tmp/lom-inside'

        # Check if the file exists
        if os.path.isfile(file_path):
            print("File {} exists.".format(file_path))
        else:
            print("File {} does not exist.".format(file_path))
            return api.TEST_FAIL

        return api.TEST_PASS

    except Exception as e:
        print("An error occurred: {}".format(e))
        return api.TEST_FAIL