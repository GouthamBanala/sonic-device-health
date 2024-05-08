import sys
import src.api as api

def isMandatoryPass() :
    return True

def getTestName() :
    return "show version, check docker-device-health docker image"

def getTestDescription() :
    return "show version of sonic build, check docker device-health image is installed or not"

def isEnabled() :
    return False


def run_test():
    output = api.get_cmd_output(["show", "version"])
    if output[0] == "OK":
        print("show version command output:")
        print(output[1])
    else:
        if output[0] == "COMMAND_NOT_FOUND":
            print("'show version' command not found which is unexpected")
        elif output[0] == "ERROR":
            print("Error occurred while running 'show version' command.")
        return 1
    
    output = api.check_docker_image()
    if output[0] == "OK":
        print("checking docker image:")
        if output[1]:
            print("docker-device-health image exists")
        else:
            print("docker-device-health image does not exist")
        return 0
    else:
        if output[0] == "COMMAND_NOT_FOUND":
            print("'Unexpected. docker images docker-device-health' command not found")
        elif output[0] == "ERROR":
            print("Unexpected. Error occurred while running 'docker images docker-device-health' command.")
        return 1
    
