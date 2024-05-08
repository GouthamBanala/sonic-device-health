import os
import subprocess
import argparse
import sys
import api

def read_config_value(config_file, key):
    with open(config_file, 'r') as f:
        for line in f:
            if line.startswith(key):
                return line.split('=')[1].strip()
    return None

def copy_to_remote_host(remote_host, remote_user, remote_password, remote_path):
    # Check if sshpass is installed
    try:
        subprocess.run(["sshpass", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("sshpass is not installed. Installing it...")
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "sshpass"], check=True)
        print("sshpass installed successfully.")
    
    # SCP the tar file to the remote host
    scp_command = f"sshpass -p '{remote_password}' scp ../../build/integration_test_installer.sh {remote_user}@{remote_host}:{remote_path}"
    if subprocess.run(scp_command, shell=True).returncode != 0:
        print("Error: Failed to copy integration_test_installer.sh file to remote host")
        exit(1)
    print("Successfully copied integration_test_installer.sh file to remote host")

def main():

    # Get the path of the project's root directory
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Add the root directory to the module search path
    sys.path.insert(0, root_dir)

    # Define the path to the bins folder
    binary_folder = os.path.join(root_dir, 'bin')

    # Define the path to the bins folder
    config_folder = os.path.join(root_dir, 'config_files')

    # Check if the user didn't specify any arguments and display help message
    if len(sys.argv) == 1:
        print("Usage: python copy.py [OPTIONS]")
        print("Use '-h' or '--help' for more information.")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Copy files to remote host and container.")
    parser.add_argument("--copy_to_host", action="store_true", help="Copy test installer to the remote Switch.")
    parser.add_argument("--copy_config_to_container", action="store_true", help="Copy config files to the container.")
    parser.add_argument("--copy_services_to_container", action="store_true", help="Copy services to the container.")
    parser.add_argument("--copy_all_to_container", action="store_true", help="Copy both config files and services to the container.")
    args = parser.parse_args()

    # Read the remote host configuration from the config file
    config_file = "integration_test/src/config.txt"
    remote_host = read_config_value(config_file, "remote_host")
    remote_user = read_config_value(config_file, "remote_user")
    remote_password = read_config_value(config_file, "remote_password")
    remote_path = read_config_value(config_file, "remote_path")

    # Check if the config values are present
    if not all([remote_host, remote_user, remote_password, remote_path]):
        print("Error: Missing remote host configuration in 'config.txt'")
        exit(1)

    if args.copy_to_host:
        copy_to_remote_host(remote_host, remote_user, remote_password, remote_path)

    # Copy config files to container
    if args.copy_config_to_container or args.copy_all_to_container:
        for filename in [api.GLOBALS_CONFIG_FILE, api.BINDINGS_CONFIG_FILE, api.ACTIONS_CONFIG_FILE, api.PROCS_CONFIG_FILE] :
            if not api.copy_config_file_to_container(config_folder, api.REMOTE_CONTAINER_CONFIG_DIR, api.REMOTE_CONTAINER_NAME, filename):
                sys.exit(1)

    # Copy services to container
    if args.copy_services_to_container or args.copy_all_to_container:
        for filename in [api.LOM_ENGINE_PROCESS_NAME, api.LOM_PLUGIN_MGR_PROCESS_NAME] :
            if not api.copy_config_file_to_container(binary_folder, api.REMOTE_CONTAINER_BIN_DIR, api.REMOTE_CONTAINER_NAME, filename):
                sys.exit(1)

if __name__ == "__main__":
    main()
