import subprocess
import sys

import api

# Function to kill processes by name
def kill_processes_by_name(process_name):
    if process_name == "LoMEngine":
        process_pids = api.get_lomengine_pids()
    elif process_name == "LoMPluginMgr":
        process_pids = api.get_lompluginmgr_pids()
    else:
        print(f"Error: Unknown process name '{process_name}'")
        return
    
    if process_pids:
        print(f"Killing {process_name} instances...")
        for pid in process_pids:
            print(f"Killing {process_name} (PID: {pid})...")
            subprocess.run(['sudo', "kill", str(pid)])
        print(f"{process_name} instances killed.")
    else:
        print(f"No {process_name} instances are running.")

# Print usage information
def print_usage():
    print("Usage: python kill.py [all|engine|plugin]")
    print("  all    : Kill both LoMEngine and LoMPluginMgr")
    print("  engine : Kill LoMEngine")
    print("  plugin : Kill all LoMPluginMgr instances")

if __name__ == '__main__':
    # Check the argument
    if len(sys.argv) != 2:
        print_usage()
        exit(1)

    arg = sys.argv[1]
    if arg == "all":
        kill_processes_by_name("LoMEngine")
        kill_processes_by_name("LoMPluginMgr")
    elif arg == "engine":
        kill_processes_by_name("LoMEngine")
    elif arg == "plugin":
        kill_processes_by_name("LoMPluginMgr")
    else:
        print_usage()
        exit(1)
