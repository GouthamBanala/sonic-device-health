#!/bin/bash

# LoM-install.sh
# This script is the entry point for the installation process of the LoM software for Arista. Options passed to LoM-Install.bsx are handled here.
# It is responsible for installing, cleaning, and rolling back the installation on Arista Switches.
#
# It supports following command-line arguments to control its behavior:
# -i: Triggers the installation process.
# -c: Cleans up the installation, forcing the removal of the active installer directory.
# -r: Triggers the rollback process to revert the installation.
# -e: Triggers the installation from an event handler. This is not passed directly from the LoM-Install.bsx. Used internally.
#
# If the script encounters an error during any of these processes, it logs the error and exits with a status of 1.
# If the script completes successfully, it logs a success message.
#
# Note : Installation code in this script calls the python scripts. These python scripts are responsible for the actual installation process, 
# like conencting to switch via eAPI's, CLI, etc and installing the software.


# Constants
LOM_DIR="/mnt/flash/lom"
ACTIVE_INSTALLER_DIR="/mnt/flash/lom/active"
BACKUP_INSTALLER_DIR="/mnt/flash/lom/backup"
INSTALL_PARAMS_FILE="install_params.json"
LOM_TEMP_INSTALLATION_FILE="/tmp/lom-inside" # Presence of this file indicate that the current installation 
                                                # is triggered by the external installion process like FUSE   
GLOBALS_CONF_FILE="globals.conf.json"

# Control where to log: "syslog", "console", or "both"
LOG_TO="syslog"
SYSLOG_FACILITY_DEFAULT="LOG_LOCAL4"

# This function gets the value of a key from a JSON file.
# If the file does not exist or if its contents are not valid JSON,
# it prints an empty string.
# Arguments:
#   $1: The path to the JSON file.
# Returns:
#   The value associated with the key in the JSON file, or an empty string if the file does not exist or if its contents are not valid JSON.
function get_syslog_facility_level() {
    local current_dir=$(dirname "$(readlink -f "$0")")
    local extraction_dir=$(dirname "$current_dir")
    local conf_file_path="$extraction_dir/config/$GLOBALS_CONF_FILE"
    local default_facility="$SYSLOG_FACILITY_DEFAULT"

    python -c "import json
try:
    with open('$conf_file_path', 'r') as f:
        data = json.load(f)
    facility = data.get('SYSLOG_FACILITY_LEVEL', '$default_facility')
    # Replace 'LOG_' with an empty string
    print(facility.replace('LOG_', ''))
except (IOError, ValueError):
    print('$default_facility'.replace('LOG_', ''))"
}
facility=$(get_syslog_facility_level)

# Function: log
# Description: Logs a message to the console or syslog or both, depending on the value of the LOG_TO variable.
#   The log message includes the filename, line number, function name, and the log message.
#
# Parameters:
# - message: The message to log.
# - lineno: The line number where the log function is called.
# - funcname: The name of the function where the log function is called.
function log() {
    local message="$1"
    local lineno="$2"
    local funcname="$3"
    local filename=$(basename "$0")
    local log_message="LOM-StartUp: $filename:$lineno: $funcname: $message"

    if [[ $LOG_TO == "syslog" || $LOG_TO == "both" ]]; then
        logger -p $facility.info "$log_message"
    fi

    if [[ $LOG_TO == "console" || $LOG_TO == "both" ]]; then
        if [[ $LOG_TO == "console" ]]; then
            local separator=$(printf '%0.s_' {1..30})
            echo "$separator"
        fi
        echo "$log_message"
        if [[ $LOG_TO == "console" ]]; then
            echo "$separator"
        fi
    fi
}

# This function adds a key-value pair to a JSON file.
# If the file does not exist or if its contents are not valid JSON,
# it creates an empty dictionary and adds the key-value pair to it.
# It then writes the dictionary back to the file in JSON format.
# Arguments:
#   $1: The key to add to the JSON file.
#   $2: The value to associate with the key in the JSON file.
#   $3: The path to the JSON file.
function add_config() {
    local key="$1"
    local value="$2"
    local file="$3"

    python -c "import json
try:
    with open('$file', 'r') as f:
        data = json.load(f)
except (IOError, ValueError):
    data = {}
if '$value' == 'true':
    py_value = True
elif '$value' == 'false':
    py_value = False
else:
    try:
        py_value = int('$value')
    except ValueError:
        py_value = '$value'
data['$key'] = py_value
with open('$file', 'w') as f:
    json.dump(data, f)"
}

# Function: install
# Description: Installs the software.
#   If this is the first time installation, it copies the contents from the extraction directory to the 'active' directory under /mnt/flash/lom and starts the installation. 
#       If the installation is successful, it writes the status and existing configuration on the device to a file.
#       If the installation is not successful, it cleans the installation, removes the active installer directory and returns False.
#   If there is a previous installation, it cleans the previous installation, moves it to the backup directory, copies the contents from the extraction directory 
#       to the active installer directory, and starts the installation.
#           If the installation is successful, it writes the status and existing configuration on the device to a file.
#           If the installation is not successful, it cleans the installation, removes the active installer directory, performs a rollback. If rollback is successful, 
#           it returns True else False. Failure in rollback is unrecoverable and the installation returns False.
#
# To-Do : Goutham : We are returning False in case of installation failure and 
# rollback failure. We need to differentiate between these two cases.
#
# Returns:
# 0 if the installation was successful, 1 otherwise.
# To-Do: Goutham : 1) Differentiate between full success install and failed install.
#                  2) If rollback failed, call cleanup and return false.
function install() {    
    # Create the lom persistent directory called /mnt/flash/lom
    if [ ! -d "$LOM_DIR" ]; then
        mkdir -p "$LOM_DIR"
    fi

    # Get the file dir path where current file is located e.g. /tmp/lom-selfextract.UmPKOR/install
    local current_dir=$(dirname "$(readlink -f "$0")")
    log "Current directory: $current_dir" $LINENO ${FUNCNAME[0]}

    # Get the lom extraction directory path e.g. /tmp/lom-selfextract.UmPKOR
    local extraction_dir=$(dirname "$current_dir")
    log "Extraction directory: $extraction_dir" $LINENO ${FUNCNAME[0]}

    # Check we are not running in ACTIVE_INSTALLER_DIR or BACKUP_INSTALLER_DIR
    if [ "$extraction_dir" == "$ACTIVE_INSTALLER_DIR" ] || [ "$extraction_dir" == "$BACKUP_INSTALLER_DIR" ]; then
        log "Error: Cannot run installation from $ACTIVE_INSTALLER_DIR or $BACKUP_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
        return 1
    fi

    # If there is a previous installation, move it to the backup directory    
    if [ -d "$ACTIVE_INSTALLER_DIR" ]; then 
        log "Previous Active installation exists at $ACTIVE_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
        log "Cleaning previous Active installation from $ACTIVE_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
        clean "False"
        local clean_status=$?
        if [ $clean_status -ne 0 ]; then
            log "Error: Failed to clean the previous installation" $LINENO ${FUNCNAME[0]}
            return 1
        fi
        if [ -f "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE" ]; then
            rm "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        fi

        # If there is a backup directory, delete it
        if [ -d "$BACKUP_INSTALLER_DIR" ]; then
            log "Deleting backup directory $BACKUP_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
            rm -r "$BACKUP_INSTALLER_DIR"
        fi

        # Note here that active installation may be attempted and remain in failed state too. This will happen after reboot. Se install_from_event_handler()
        # But, just ignore it and move to backup.
        log "Moving previous Active installation from $ACTIVE_INSTALLER_DIR to backup directory $BACKUP_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
        mv "$ACTIVE_INSTALLER_DIR" "$BACKUP_INSTALLER_DIR"
    else
        log "Installing for the first time" $LINENO ${FUNCNAME[0]}
    fi

    # Copy the contents from the extraction directory to the active installer directory
    log "Copying contents from $extraction_dir to $ACTIVE_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
    mkdir -p "$ACTIVE_INSTALLER_DIR"
    cp -r "$extraction_dir"/* "$ACTIVE_INSTALLER_DIR"

    # Start the installation
    log "Starting installation at $ACTIVE_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
    python "$ACTIVE_INSTALLER_DIR/install/startup/do-install.py" --start-installation "$ACTIVE_INSTALLER_DIR" 2>/dev/null
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        log "Installation successful" $LINENO ${FUNCNAME[0]}
        # Write the status to the file
        add_config "status" true "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        add_config "install_type" "\"external\"" "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"   
        return 0
    else
        log "Installation failed" $LINENO ${FUNCNAME[0]}
        # Clean the installation and remove the active installer directory
        clean "False"
        local clean_status=$?
        rm -r "$ACTIVE_INSTALLER_DIR"
        if [ $clean_status -ne 0 ]; then
            log "Error: Failed to clean the installation. Cannot perform rollback." $LINENO ${FUNCNAME[0]}
            return 1
        fi
        # Perform rollback
        if [ -d "$BACKUP_INSTALLER_DIR" ]; then
            rollback
            local rollback_status=$?
            if [ $rollback_status -eq 0 ]; then
                log "Rollback to previous installation successful" $LINENO ${FUNCNAME[0]}
            fi
        fi
        return 1 # even if rollback is successful, we are returning False as primary installation failed
    fi
}

# Function: install_from_event_handler
# This function is used to handle the installation process. It first checks if a temporary file 
# (specified by LOM_TEMP_EV_DIR) exists. If the file exists, it means the current installation 
# is being triggered by an external process (like FUSE) and not after boot up, so it skips the 
# installation.
#
# If the file does not exist, it means the installation is being triggered after boot up, so 
# the function proceeds with the installation.
#
# Note: The event handler is configured with a trigger as on-boot. When you exit the configuration 
# mode, the event handler is executed right away. This will call the install_from_event_handler() 
# function. This creates issues as your only intention is to execute the event handler upon boot.
# So we are creating a tmp file /tmp/$(LOM_TEMP_EV_FILE) during installation. When this 
# install_from_event_handler() is called, we are checking for the presence of this file. If the file
# does not exist, we proceed with the installation. If the file exists, we skip the installation,
# meaning the installation is being triggered by the external installation process like FUSE.
#
# Returns:
# 0 if the installation succeeds, 1 otherwise.
function install_from_event_handler() {
    # Check if the temporary file exists
    if [ -f "$LOM_TEMP_INSTALLATION_FILE" ]; then
        log "Skipping installation as it is not triggered after boot up" $LINENO ${FUNCNAME[0]}
        return 1
    fi

    ## If the file does not exist, proceed with the installation

    # Make sure we are running from ACTIVE_INSTALLER_DIR
     # Get the main installation path e.g. /mnt/flash/lom/active
    local extraction_dir=$(dirname "$(dirname "$(readlink -f "$0")")")
    log "Extraction directory: $extraction_dir" $LINENO ${FUNCNAME[0]}    
    if [ "$extraction_dir" == "$ACTIVE_INSTALLER_DIR" ]; then
        log "The script is running in $ACTIVE_INSTALLER_DIR after reboot" $LINENO ${FUNCNAME[0]}
    else
        log "The script is not running in $ACTIVE_INSTALLER_DIR after reboot" $LINENO ${FUNCNAME[0]}
        return 1
    fi

    # Note here that active installation may be attempted before and remain in failed state too. This will happen after reboot
    # i.e. calling this call before. We try to install again.
    log "Starting installation at $ACTIVE_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
    python "$ACTIVE_INSTALLER_DIR/install/startup/do-install.py" --start-installation "$ACTIVE_INSTALLER_DIR" 2>/dev/null
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        log "Installation successful" $LINENO ${FUNCNAME[0]}
        add_config "status" true "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        add_config "install_type" "\"after_boot\"" "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        return 0
    else
        log "Installation failed from boot event handler" $LINENO ${FUNCNAME[0]}
        clean "False"
        # Write the failed status to the file
        rm -f "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        add_config "status" false "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        add_config "install_type" "\"after_boot\"" "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"  
        # Note, We are not deleting the active installer directory as this is not new installation.      
        # Note, Rollback not needed as this not new installation 
        # To-Do : Goutham : Check if rollback & delete active dir is needed or not
        return 1
    fi
}

# Function: clean
# Description: Cleans the current installation.
#   If there is an active installation, it cleans up the installation.
#   If there is no active installation, it logs a message and does nothing.
# Note: It will not remove the active installer directory unless remove_dir is true.
#
# Parameters:
# - remove_dir: Whether to remove the active installer directory. Expected values are "True" or "False".
# Returns: 
# - 0 if the cleanup was successful, 1 otherwise.
function clean() {
        # Whether to remove the active installer directory.
        local remove_dir=$1

        log "Cleaning the current installation"
        if [ -d "$ACTIVE_INSTALLER_DIR" ]; then
            # If there is an active installation
            python "$ACTIVE_INSTALLER_DIR/install/startup/do-install.py" --cleanup-installation "$ACTIVE_INSTALLER_DIR" >/dev/null 2>&1
            local exit_code=$?
            if [ $exit_code -ne 0 ]; then
                log "Error: Failed to clean the active installation"
                return 1
            fi
            if [ "$remove_dir" = "True" ]; then
                rm -r "$ACTIVE_INSTALLER_DIR"
            fi
        else
            log "No active installation found. Nothing to clean."
        fi
        return 0
}

# Function: rollback
# Description: Rollback to the previous installation.
#   This function checks if a backup directory exists. If not, it cannot perform a rollback.
#   If the active installation does not exist, it moves the backup to active and starts the installation.
#       If the installation is successful, it writes the status and existing configuration on the device to a file.
#       If the installation is not successful, it cleans the installation, removes the active installer directory, and returns False.
#   Otherwise, it cleans the active installation, deletes active dir, moves the backup to active, and starts the installation.
#       If the installation is successful, it writes the status and existing configuration on the device to a file.
#       If the installation is not successful, it cleans the installation, removes the active installer directory, and returns False.
#
# Returns:
# 0 if the rollback was successful, 1 otherwise.
function rollback() {
    log "Rolling back to previous installation" $LINENO "rollback"
    if [ ! -d "$BACKUP_INSTALLER_DIR" ]; then
        log "No backup directory found. Cannot perform rollback." $LINENO "rollback"
        return 1
    fi

    # If the active installation exists, clean it and remove the directory.
    if [ -d "$ACTIVE_INSTALLER_DIR" ]; then
        log "Active installation exists at $ACTIVE_INSTALLER_DIR" $LINENO "rollback"
        clean "False"
        local clean_status=$?
        if [ $clean_status -ne 0 ]; then
            log "Error: Failed to clean the installation. Cannot perform rollback." $LINENO ${FUNCNAME[0]}
            return 1
        fi
        rm -rf "$ACTIVE_INSTALLER_DIR"
    else
        log "No active installation found at $ACTIVE_INSTALLER_DIR" $LINENO "rollback"
    fi

    # Move the backup dir to active and start the installation.
    log "Moving backup at $BACKUP_INSTALLER_DIR to active directory $ACTIVE_INSTALLER_DIR" $LINENO "rollback"
    mv "$BACKUP_INSTALLER_DIR" "$ACTIVE_INSTALLER_DIR"

    log "Starting installation at $ACTIVE_INSTALLER_DIR" $LINENO ${FUNCNAME[0]}
    python "$ACTIVE_INSTALLER_DIR/install/startup/do-install.py" --start-installation "$ACTIVE_INSTALLER_DIR" >/dev/null 2>&1
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        add_config "status" true "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        add_config "install_type" "\"external\"" "$ACTIVE_INSTALLER_DIR/$INSTALL_PARAMS_FILE"
        return 0
    else
        log "Rollback to previous installation failed" $LINENO ${FUNCNAME[0]}
        clean "False"
        rm -rf "$ACTIVE_INSTALLER_DIR"
        return 1
    fi
}

# Check if Python is available
if ! command -v python &> /dev/null; then
    log "Error: Python could not be found. Exiting installation."
    exit 1
fi

# Check if an argument was passed. 
# Note : -e is used internally and coming from the event handler
if [ $# -ne 1 ]; then
    log "Error: No argument was passed to the installation script." $LINENO ${FUNCNAME[0]}
    log "Expecting one of the following arguments: -i (install), -c (clean), -r (rollback), or -e (event handler)" $LINENO ${FUNCNAME[0]}
    exit 1
fi

# Parse the argument and call the appropriate function
case $1 in
    -i)
        # Call the install function
        install
        install_status=$?
        if [ $install_status -ne 0 ]; then
            log "Error: Installation failed with status $install_status." $LINENO ${FUNCNAME[0]}
            exit 1
        fi
        ;;
    -c)
        # Call the clean function forcing the removal of the active installer directory
        clean "True"
        clean_status=$?
        if [ $clean_status -ne 0 ]; then
            log "Error: Cleanup failed with status $clean_status." $LINENO ${FUNCNAME[0]}
            exit 1
        fi
        ;;
    -r)
        # Call the rollback function
        rollback
        rollback_status=$?
        if [ $rollback_status -ne 0 ]; then
            log "Error: Rollback failed with status $rollback_status." $LINENO ${FUNCNAME[0]}
            exit 1
        fi
        ;;
    -e)
        # Call the installation if called via event handler
        install_from_event_handler
        event_handler_status=$?
        if [ $event_handler_status -ne 0 ]; then
            log "Error: Event handler failed with status $event_handler_status." $LINENO ${FUNCNAME[0]}
            exit 1
        fi
        ;;
    *)
        log "Error: Invalid argument passed to the installation script." $LINENO ${FUNCNAME[0]}
        log "Expecting one of the following arguments: -i (install), -c (clean), -r (rollback), or -e (event handler)" $LINENO ${FUNCNAME[0]}
        exit 1
        ;;
esac

log "LOM Installation Script executed successfully." $LINENO ${FUNCNAME[0]}