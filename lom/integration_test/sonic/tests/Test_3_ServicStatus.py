import sys
import src.api as api

def isMandatoryPass() :
    return True

def getTestName() :
    return "device-health service status"

def getTestDescription() :
    return "device-health service status whether its running or not"

def isEnabled() :
    return False

def run_test():
    retStatus, is_active = api.check_device_health_status()
    if retStatus == "OK":
        print("checking device-health service status:")
        if is_active:
            print("device-health service is active (running)")
        else:
            print("device-health service is not active (running)")
        return 0  # Return code 0 for test success
    else:
        if retStatus == "COMMAND_NOT_FOUND":
            print("'systemctl status device-health' command not found")
        elif retStatus == "ERROR":
            print("Error occurred while running 'systemctl status device-health' command.")
        return 1  # Return code 1 for test failure
    
