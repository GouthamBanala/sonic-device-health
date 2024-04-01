import subprocess
import sys

# Function to get the PIDs of LoMEngine processes
def get_lomengine_pids():
    try:
        engine_pids = subprocess.check_output(["pgrep", "-f", "-i", "install/LoMEngine"]).decode().strip()
        if engine_pids:
            return [int(pid) for pid in engine_pids.split()]
        else:
            return []  # No matching processes found, return an empty list
    except Exception as e:
        print("Error: An unexpected error occurred - {}".format(e))
        return []  # Return an empty list on any exception

# Function to get the PIDs of LoMPluginMgr processes
def get_lompluginmgr_pids():
    try:
        pluginmgr_pids = subprocess.check_output(["pgrep", "-f", "-i", "install/LoMPluginMgr"]).decode().strip()
        if pluginmgr_pids:
            return [int(pid) for pid in pluginmgr_pids.split()]
        else:
            return []  # No matching processes found, return an empty list
    except Exception as e:
        print("Error: An unexpected error occurred - {}".format(e))
        return []  # Return an empty list on any exception

def kill_processes_by_name(process_name):
    if process_name == "LoMEngine":
        process_pids = get_lomengine_pids()
    elif process_name == "LoMPluginMgr":
        print("WARNING: This command may causes all the PuginMgr instances to be killed")
        process_pids = get_lompluginmgr_pids()
    else:
        print("Error: Unknown process name '{}'".format(process_name))
        return    
    if process_pids:
        print("Killing {} instances...".format(process_name))
        for pid in process_pids:
            try:
                subprocess.call(['sudo', "kill", str(pid)])
                print("Killing {} (PID: {})...".format(process_name, pid))
            except Exception as e:
                print("Error while killing {}: {}".format(process_name, e))
        print("{} instances killed.".format(process_name))
    else:
        print("No {} instances are running.".format(process_name))

def print_lomengine():
    engine_pids = get_lomengine_pids()
    if engine_pids:
        print("LoMEngine instances:")
        for pid in engine_pids:
            print("  PID: {}".format(pid))
    else:
        print("No LoMEngine instances are running")

def print_lompluginmgr():
    pluginmgr_pids = get_lompluginmgr_pids()
    if pluginmgr_pids:
        print("LoMPluginMgr instances:")
        for pid in pluginmgr_pids:
            try:
                ps_output = subprocess.check_output(["ps", "-p", str(pid), "-o", "args="]).decode().strip()
                proc_id = ps_output.split('-proc_id=')[1].split()[0] if '-proc_id=' in ps_output else "N/A"
                print("  PID: {}, Proc ID: {}".format(pid, proc_id))
            except Exception as e:
                print("Error while fetching information for PID {}: {}".format(pid, e))
    else:
        print("No LoMPluginMgr instances are running")

def print_all_processes():
    print("Processes:")
    print_lompluginmgr()
    print_lomengine()

def kill_all_processes():    
    kill_processes_by_name("LoMPluginMgr")
    kill_processes_by_name("LoMEngine")

# Function to print usage information
def print_usage():
    print("Usage: python helper.py <command>")
    print("Commands:")
    print("  kill <process_name> : Kill a process by name (e.g., kill LoMEngine)")
    print("  list <process_name> : List instances of a process (e.g., list LoMEngine)")
    print("  list all            : List all processes")
    print("  kill all            : Kill all processes")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "kill" and len(sys.argv) == 3:
        process_name = sys.argv[2]
        if process_name == "all":
            kill_all_processes()
        else:
            kill_processes_by_name(process_name)
    elif command == "list" and len(sys.argv) == 3:
        process_name = sys.argv[2]
        if process_name == "lomengine":
            print_lomengine()
        elif process_name == "lompluginmgr":
            print_lompluginmgr()
        elif process_name == "all":
            print_all_processes()
        else:
            print("Unknown process name: {}".format(process_name))
    else:
        print_usage()
