
import src.api as api
import time

def isMandatoryPass() :
    return True

def getTestName() :
    return "Test the Engine process crash"

def getTestDescription() :
    return "When Engine stops, plugin nmanager must stop and device-health container must be   \
            stopped and restarted \
            "

def isEnabled() :
    return False

def run_test():
    # Restart the device health service
    if not api.restart_service_wait("device-health") :
        return api.TEST_FAIL
    
    if not api.wait_for_lom_services_to_start() :
        return api.TEST_FAIL
    
    # kill the lom-engine process
    print(f"Killing {api.LOM_ENGINE_PROCESS_NAME} process")
    if not api.kill_process_by_name(api.LOM_ENGINE_PROCESS_NAME, True) :
        print(f"Fail : Unable to kill {api.LOM_ENGINE_PROCESS_NAME} process.")
        return api.TEST_FAIL
    
    time.sleep(3)

    # check if the plugin manager service is running
    if api.is_process_running(api.LOM_PLUGIN_MGR_PROCESS_NAME) :
        print("Fail : {} process {api.LOM_PLUGIN_MGR_PROCESS_NAME} still running after kill.")
        return api.TEST_FAIL
    print(f"{api.LOM_PLUGIN_MGR_PROCESS_NAME} process killed successfully after {api.LOM_ENGINE_PROCESS_NAME} is killed")

    time.sleep(5)    
    
    # check if the device health service is running
    retStatus, is_active = api.check_device_health_status()
    if retStatus == "OK" and is_active == True:
       print("Fail : Device health container still running after Engine process is killed.")
       return api.TEST_FAIL
    print("Device health container stopped successfully after Engine process is killed.")
    
    # Wait to check if the device health container is started
    max_wait_time = 60  # Maximum time to wait in seconds
    wait_interval = 5  # Time interval to wait secs
    elapsed_time = 0

    while elapsed_time < max_wait_time:
        ret, dstatus = api.check_device_health_status() 
        if ret == "OK" and dstatus == True:
            print("Device Health container started & running")
            return api.TEST_PASS
        time.sleep(wait_interval)
        elapsed_time += wait_interval
    print("Timed out while waiting for device-health container to start.")
    return api.TEST_FAIL