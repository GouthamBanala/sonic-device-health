import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import api
import arista_cli_helper

def isMandatoryPass() :
    return True

def getTestName() :
    return "show version, check version, check chipset "

def getTestDescription() :
    return "show version of eos, check eos version >= 4.26, check if jericho chipset is present"

def isEnabled() :
    return False


import re

def run_test():
    arista_manager = arista_cli_helper.AristaSwitchCLIHelper()
    try:
        # Execute 'show version' command
        output = arista_manager.execute_arista_command("show version", option='show', print_output=True)
        # Extract the software image version
        match = re.search(r'Software image version: (\d+\.\d+)', output)
        if match:
            version = float(match.group(1))
            if version < 4.26:
                print("Software image version is less than 4.26")
                return api.TEST_FAIL
        else:
            print("Could not find software image version in output")
            return api.TEST_FAIL
        print("Software image version: ", version)

        # Execute 'show platform fap' command
        output = arista_manager.execute_arista_command("show platform fap", option='config', print_output=True)
        # Check for 'Jericho' in the output
        if 'Jericho' not in output:
            print("'Jericho' not found in output")
            return api.TEST_FAIL
        print("Jericho chipset found in the output")
        return api.TEST_PASS
    except subprocess.CalledProcessError as e:
        error_message = unicode(e) if sys.version_info[0] == 2 else str(e)
        print("Error occurred while running command: ", error_message)
        return api.TEST_FAIL
    except Exception as e:
        error_message = unicode(e) if sys.version_info[0] == 2 else str(e)
        print("Unexpected error occurred: ", error_message)
        return api.TEST_FAIL
