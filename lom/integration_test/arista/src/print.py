#!/usr/bin/env python3

import subprocess

import api


# Function to print LoMEngine processes
def print_lomengine():
    engine_pids = api.get_lomengine_pids()
    if engine_pids:
        print("LoMEngine instances:")
        for pid in engine_pids:
            print(f"  PID: {pid}")
    else:
        print("No LoMEngine instances are running")

# Function to print LoMPluginMgr processes
def print_lompluginmgr():
    pluginmgr_pids = api.get_lompluginmgr_pids()
    if pluginmgr_pids:
        print("LoMPluginMgr instances:")
        for pid in pluginmgr_pids:
            proc_id = subprocess.getoutput(f"ps -p {pid} -o args= | awk -F'-proc_id=' '{{print $2}}' | awk '{{print $1}}'")
            print(f"  PID: {pid}, Proc ID: {proc_id}")
    else:
        print("No LoMPluginMgr instances are running")

# Print both LoMEngine and LoMPluginMgr processes
def print_processes():
    print("Processes:")
    print_lomengine()
    print_lompluginmgr()

# Call the function to print processes
if __name__ == '__main__':
    print_processes()
