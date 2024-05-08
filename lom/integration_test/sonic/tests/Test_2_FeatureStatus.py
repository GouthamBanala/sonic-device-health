import sys
import src.api as api

def isMandatoryPass() :
    return True

def getTestName() :
    return "device-health feature status"

def getTestDescription() :
    return "device-health feature status whether its running or not"

def isEnabled() :
    return False

def run_test():
    feature_name = "device-health"
    retStatus, state, auto_restart, set_owner = api.get_feature_status(feature_name)

    # Check if the API call was successful
    if retStatus == "OK":
        print("Running Sonic Build has device-health feature")

        # Check the state of the feature
        if state == "disabled" or state == "always_disabled":
            print("device-health feature is not enabled")
            return 1  # Return code 1 for test failure
        else:
            print("device-health feature is enabled")
            print(f"AutoRestart: {auto_restart}")
            print(f"SetOwner: {set_owner}")
            return 0  # Return code 0 for test success

    # Handle different error conditions
    else:
        print("An error occurred while checking feature status:")
        if retStatus == "COMMAND_NOT_FOUND":
            print("'show feature status' command not found")
        elif retStatus == "ERROR":
            print("Error occurred while running 'show feature status' command.")
        elif retStatus == "FEATURE_NOT_FOUND":
            print(f"Feature '{feature_name}' not found in the 'show feature status' output.")
        return 1  # Return code 1 for  failure

