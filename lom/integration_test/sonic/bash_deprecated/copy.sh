#!/bin/bash

# Read the remote host configuration from the config file
config_file="integration_test/src/config.txt"
remote_host=$(grep "remote_host" "$config_file" | awk -F '=' '{print $2}' | tr -d ' ')
remote_user=$(grep "remote_user" "$config_file" | awk -F '=' '{print $2}' | tr -d ' ')
remote_password=$(grep "remote_password" "$config_file" | awk -F '=' '{print $2}' | tr -d ' ')
remote_path=$(grep "remote_path" "$config_file" | awk -F '=' '{print $2}' | tr -d ' ')

# Check if the config values are present
if [[ -z "$remote_host" || -z "$remote_user" || -z "$remote_password" || -z "$remote_path" ]]; then
    echo "Error: Missing remote host configuration in 'config.txt'"
    exit 1
fi

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo "sshpass is not installed. Installing it..."
    sudo apt-get update
    sudo apt-get install -y sshpass    
fi

# Create a tar archive of 'integration_test'
tar -czvf integration_test.tar.gz integration_test
echo "Created tar archive 'integration_test.tar.gz'."

# SCP the tar file to the remote host
if ! sshpass -p "$remote_password" scp ./integration_test.tar.gz "$remote_user@$remote_host:$remote_path"; then
    echo "Error: Failed to copy tar file to remote host"
    exit 1
fi

echo "Successfully copied tar file to remote host"
