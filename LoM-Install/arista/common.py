from __future__ import print_function # Python 2/3 compatibility
import argparse
import json
import re
import subprocess
import shutil
import sys
import os
import errno
import json
import logging
import logging.handlers
import inspect
from logging.handlers import SysLogHandler
import threading

import Tac

# Constants
LOM_DIR = "/mnt/flash/lom"
ACTIVE_INSTALLER_DIR = "/mnt/flash/lom/active"
BACKUP_INSTALLER_DIR = "/mnt/flash/lom/backup"
INSTALL_PARAMS_FILE  = "install_params.json"

PROC_CONF_FILE = 'procs.conf.json'
ACTIONS_CONF_FILE = 'actions.conf.json'
BINDINGS_CONF_FILE = 'bindings.conf.json'
GLOBALS_CONF_FILE = 'globals.conf.json'

RUN_MODE = 'PROD'

MANAGEMENT_NAMESPACE = 'ns-MGMT'
DEFAULT_NAMESPACE = 'default'

TERMINATTR_DAEMON_NAME = 'TerminAttr'

DAEMON_AFTER_ENABLED_WAIT_TIME = 3  # Seconds to wait to check after enabling a daemon
DAEMON_AFTER_DISABLED_WAIT_TIME = 3  # Seconds to wait to check after disabling a daemon 
DAEMON_IN_BETWEEN_WAIT_TIME = 10  # Seconds to wait to start plmgr after starting engine  

CHIP_DETAILS_MAPPING_FILE = "chip_details_mapping.json"

# Constants to control whether each check should be run or not
CHECK_AGENT_UPTIMES = True
CHECK_CORE_DUMP_INFO = False # Not supported on 32 bit platforms
CHECK_CAPACITY = True

# event handler related constants
EVENT_HANDLER_SUPPORT = True
WRITE_MEM_SUPPORT = True # Works in conjunction with EVENT_HANDLER_SUPPORT
EVENT_HANDLER_SCRIPT_PATH = "/mnt/flash/lom/active/install/LoM-install.sh -e"
EVENT_HANDLER_NAME = "lom-startup"
EVENT_HANDLER_DELAY = 100 #seconds
EVENT_HANDLER_TIMEOUT = 600 #seconds
EVENT_HANDLER_ASYNCHRONOUS = True

# Presence of this file indicate that the current installation is triggered by the external installion process like FUSE
LOM_TEMP_INSTALLATION_FILE = "/tmp/lom-inside"

# for arista CLI helper
CLI_CONFGURATION_WAIT_TIME = 3  # Seconds to wait for the configuration to take effect

logger = None
SYSLOG_FACILITY_DEFAULT = "LOG_LOCAL4"


def get_procs_keys(dir_path):
    """
    This function reads the procs.conf.json file and returns the keys under the "procs" object.

    Parameters:
    - dir_path: The directory path where the procs.conf.json file is located.

    Returns:
    - procs_keys: A list of keys under the "procs" object in procs.conf.json.

    Raises:
    - IOError: If the procs.conf.json file is not found, or if there's an error reading the file.
    - ValueError: If there's an error decoding the JSON.
    - Exception: If an unexpected error occurs.
    """
    try:
        with open(os.path.join(dir_path, PROC_CONF_FILE), 'r') as f:
            data = json.load(f)
        procs_keys = list(data.get('procs', {}).keys())  # Convert to list for Python 2.7 compatibility
        if not procs_keys:
            raise ValueError("Error: The 'procs' object is empty in procs.conf.json.")
        return procs_keys
    except IOError as e:
        raise IOError("Error: Failed to read procs.conf.json. {}".format(e))
    except ValueError as e:
        raise ValueError("Error: Failed to decode procs.conf.json.{}".format(e))
    except Exception as e:
        raise Exception("Error: An unexpected error occurred while reading procs.conf.json. {}".format(e))

class MyLogger(object):    
    """
    A custom logger class that logs messages to either syslog or the console.
    This class is not thread-safe and should be instantiated when needed.

    Attributes:
        logger: The underlying logger instance.
        log_to_syslog: A boolean indicating whether to log to syslog.
    
    To-Do : Goutham : When run from bash installer script, console logs may not be printed to console as bassh.
            Need to fix this for better debugging. For now, we can use syslog for debugging everywhere.
    """
    def __init__(self, level=logging.INFO, syslog_address='/dev/log', log_to_syslog=True, facility='LOG_LOCAL4'):
        """
        Initialize a new instance of the MyLogger class.

        Args:
            level: The logging level.
            syslog_address: The address of the syslog server.
            log_to_syslog: A boolean indicating whether to log to syslog.
            facility: The syslog facility to use. Defaults to 'LOG_LOCAL4'.
        """
        self.logger = logging.getLogger(__name__ + '.logger')
        self.logger.setLevel(level)
        self.log_to_syslog = log_to_syslog

        if log_to_syslog:
            # Convert facility string to corresponding constant
            facility_constant = getattr(SysLogHandler, facility)
            # Create a handler for syslog.
            syslog_handler = SysLogHandler(address=syslog_address, facility=facility_constant)
            syslog_handler.setFormatter(logging.Formatter("LOM-StartUp: %(message)s"))
            self.logger.addHandler(syslog_handler)
        else:
            # Create a handler for the console.
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter("LOM-StartUp: %(asctime)s: %(message)s"))
            self.logger.addHandler(console_handler)

    @staticmethod
    def __get_call_info():
        """
        Get information about the caller, including the filename, function name, and line number.

        Returns:
            A tuple containing the filename, function name, and line number of the caller.
        """
        stack = inspect.stack()
        fn = stack[2][1]
        ln = stack[2][2]
        func = stack[2][3]
        return fn, func, ln

    def log(self, message):
        """
        Log a message.

        Args:
            message: The message to log. Can be any type.
        Returns:
            str: The logged message.
        Raises:
            TypeError: If the message cannot be converted to a string.
        """
        message = str(message)

        # Get call info
        fn, func, ln = self.__get_call_info()
        fn = os.path.basename(fn)

        # Log message with separators if not logging to syslog
        if not self.log_to_syslog:
            separator = '_' * 30
            self.logger.info(separator)

        # Format and log the message
        message = "{}:{}: {}: {}".format(fn, ln, func, message)
        self.logger.info(message)

        # Log separator if not logging to syslog
        if not self.log_to_syslog:
            self.logger.info(separator)

        return message

    def log_fatal(self, message):
        """
        Print a fatal error message, log it, and exit the program.

        This method logs the fatal error message along with the file, line number, 
        and function name where it's called, and then exits the program.

        Args:
            message: The error message to print. Can be any type.
        """
        message = str(message)

        # Get call info
        fn, func, ln = self.__get_call_info()
        fn = os.path.basename(fn)

        # Format and log the message
        message = "Fatal: {}:{}: {}: {} Exiting...".format(fn, ln, func, message)
        self.logger.info(message)

        # Exit the program
        sys.exit(1)

def write_data_to_file(folder, filename, data):
    """
    Writes data to a file.
    If the file doesn't exist, it creates it.
    If the file exists, it overwrites it.

    Args:
        folder (str): The path of the folder where the file will be created.
        filename (str): The name of the file to write to.
        data: The data to write to the file. Must be a string.

    Raises:
        TypeError: If folder, filename, or data is not a string.
        ValueError: If folder is not a directory.
        IOError: If there is an error writing to the file.
    """
    if not isinstance(folder, str) or not isinstance(filename, str):
        raise TypeError("folder and filename must be strings")
    if not isinstance(data, str):
        raise TypeError("data must be a string")
    if not os.path.isdir(folder):
        raise ValueError("Folder {0} does not exist".format(folder))
    
    try:
        with open(os.path.join(folder, filename), 'w') as f:
            f.write(data)
    except IOError as e:
        raise IOError("Error writing to file: {0}".format(e))

def read_data_from_file(directory, filename):
    """
    Read data from a file in the specified directory.

    Parameters:
    directory (str): The directory where the file is located.
    filename (str): The name of the file.

    Returns:
    The data read from the file.

    Raises:
    TypeError: If directory or filename is not a string.
    ValueError: If directory is not a directory.
    IOError: If there is an error reading from the file.
    """
    if not isinstance(directory, str) or not isinstance(filename, str):
        raise TypeError("directory and filename must be strings")
    if not os.path.isdir(directory):
        raise ValueError("Directory {0} does not exist".format(directory))
    
    try:
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r') as file:
            data = file.read()
        return data
    except IOError as e:
        raise IOError("Error reading from file: {0}".format(e))

def read_json_from_file(directory, filename):
    """
    Read and parse JSON data from a file in the specified directory.

    Parameters:
    directory (str): The directory where the file is located.
    filename (str): The name of the file.

    Returns:
    The data read from the file as a Python object.

    Raises:
    TypeError: If directory or filename is not a string.
    ValueError: If directory is not a directory.
    IOError: If there is an error reading from the file.
    ValueError: If the file content is not valid JSON.
    """
    if not isinstance(directory, str) or not isinstance(filename, str):
        raise TypeError("directory and filename must be strings")
    if not os.path.isdir(directory):
        raise ValueError("Directory {0} does not exist".format(directory))
    
    try:
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r') as file:
            data = json.load(file)
        return data
    except IOError as e:
        raise IOError("Error reading from file: {0}".format(e))
    except ValueError as e:
        raise ValueError("Error parsing JSON: {0}".format(e))
                    
def directory_exists(directory):
    """
    Check if a directory exists.

    Parameters:
    directory (str): The directory to check.

    Returns:
    True if the directory exists, False otherwise.

    Raises:
    TypeError: If directory is not a string.
    """
    if not isinstance(directory, str):
        raise TypeError("directory must be a string")

    return os.path.isdir(directory)

def file_exists(filepath):
    """
    Check if a file exists.

    Parameters:
    filepath (str): The file path to check.

    Returns:
    True if the file exists, False otherwise.

    Raises:
    TypeError: If filepath is not a string.
    """
    if not isinstance(filepath, str):
        raise TypeError("filepath must be a string")

    return os.path.isfile(filepath)

def write_chipdetails_mapping_to_file(filename):
    """
    Writes Linecard Id to name mapping to a file in JSON format.
    If the file doesn't exist, it creates it.
    If the file exists, it overwrites it.

    Args:
        filename (str): The name of the file to write to.

    Raises:
        TypeError: If filename is not a string.
        IOError: If there's an error writing to the file.
        TypeError: If there's an error serializing the mapping to JSON.

    Sample File Output:
    {
        "FirstEntry": "0", 
        "IptCrcErrCnt": "1", 
        "UcFifoFullDrop": "2", 
        ....
    }
    """
    if not isinstance(filename, str):
        raise TypeError("filename must be a string")

    # Get the chip details mapping
    dropInfo = Tac.newInstance("Hardware::Sand::AradDropCounterInfo", None)
    mapping = dict(dropInfo.counterNameToId.items())

    try:
        with open(filename, 'w') as f:
            json.dump(mapping, f)
    except IOError as e:
        raise IOError("Error writing to file: {0}".format(e))
    except TypeError as e:
        raise TypeError("Error serializing mapping to JSON: {0}".format(e))

def read_chipdetails_mapping_from_file(filename):
    """
    Reads Linecard Id to name mapping from a file in JSON format.

    Args:
        filename (str): The name of the file to read from.

    Returns:
        The chip details mapping if successful.

    Raises:
        TypeError: If filename is not a string.
        FileNotFoundError: If the file does not exist.
        IOError: If there's an error reading from the file.
        json.JSONDecodeError: If there's an error decoding the JSON.
    """
    if not isinstance(filename, str):
        raise TypeError("filename must be a string")

    if not os.path.isfile(filename):
        raise FileNotFoundError("File {0} does not exist".format(filename))

    try:
        with open(filename, 'r') as f:
            mapping = json.load(f)
        return mapping
    except IOError as e:
        raise IOError("Error reading from file: {0}".format(e))
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError("Error decoding JSON from file: {0}".format(e))
            
def get_network_namespaces():
    """
    Get a list of network namespaces in the system.

    This function runs the 'ip netns list' command, which lists the network namespaces.
    The output is then split by newline characters to get a list of namespaces.

    Returns:
    - namespaces: A list of network namespaces.

    Raises:
    - subprocess.CalledProcessError: If the 'ip netns list' command fails.
    - Exception: If an unexpected error occurs.

    e.g. (['ns-MGMT', 'default'])
    """
    try:
        result = subprocess.check_output(['ip', 'netns', 'list'])
        if sys.version_info[0] == 3: # Python 3
            result = result.decode('utf-8')
        namespaces = result.split('\n')
        # Remove the last element if it's an empty string
        if namespaces and namespaces[-1] == '':
            namespaces.pop()
        return namespaces
    except subprocess.CalledProcessError as e:
        raise subprocess.CalledProcessError("Error executing command: {0}".format(e))
    except Exception as e:
        raise Exception("Unexpected error: {0}".format(e))

def is_process_port_in_namespace(process_name=None, port=None, namespace=None):
    """
    Check if a process and/or a specific port is part of a specific network namespace if any network ports are opened by the process.

    Parameters:
    - process_name: The name of the process to check. If None, the function will not check for a process.
    - port: The port to check. If None, the function will not check for a port.
    - namespace: The namespace to check. Must be provided.

    Returns:
    - A boolean indicating whether the process and/or port is part of the namespace. If both process_name and port are provided, both must match. If only one is provided, it must match.

    Raises:
    - ValueError: If the namespace is not provided or if it's not a string, or if neither process_name nor port are provided, or if they are not strings.
    - subprocess.CalledProcessError: If there's an error executing the command.
    - UnicodeDecodeError: If there's an error decoding the output.
    - Exception: If an unexpected error occurs.
    """

    if namespace is None or not isinstance(namespace, str):
        raise ValueError("namespace must be a string")

    if process_name is None and port is None:
        raise ValueError("At least one of process_name or port must be provided")

    if process_name is not None and not isinstance(process_name, str):
        raise ValueError("process_name must be a string")

    if port is not None and not isinstance(port, str):
        raise ValueError("port must be a string")

    try:
        # Get the list of sockets in the namespace
        result = subprocess.check_output(['ip', 'netns', 'exec', namespace, 'ss', '-tuln', '-p'])
        if sys.version_info[0] == 3: # Python 3
            result = result.decode('utf-8')
        sockets = result.split('\n')

        # Check if the process is in the list
        for socket in sockets[1:]:
            fields = socket.split()
            if len(fields) < 7:
                continue
            socket_process_name = fields[6].split('"')[1]
            socket_port = fields[4].split(':')[-1]
            if process_name and port:
                if socket_process_name == process_name and socket_port == port:
                    return True
            elif process_name:
                if socket_process_name == process_name:
                    return True
            elif port:
                if socket_port == port:
                    return True
            
        return False
    except subprocess.CalledProcessError as e:
        raise subprocess.CalledProcessError("Error executing command: {0}".format(e))
    except UnicodeDecodeError as e:
        raise UnicodeDecodeError("Error decoding output: {0}".format(e))
    except Exception as e:
        raise Exception("Unexpected error: {0}".format(e))
    
def create_dir_if_not_exists(dir_path):
    """
    Checks if a directory exists at the given path, and if it doesn't, creates it.
    If the path exists but is not a directory, it does nothing.
    If the parent directories don't exist, it creates them.

    Args:
        dir_path (str): The path of the directory to create.

    Raises:
        OSError: If there is an error creating the directory.
    """
    try:
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise OSError("Error creating directory {0}: {1}".format(dir_path, e))

def move_dir(src_dir, dst_dir):
    """
    Moves a directory from src_dir to dst_dir.
    If dst_dir already exists and is a directory, it removes it before moving src_dir.
    If src_dir doesn't exist or is not a directory, it raises an exception.
    If dst_dir exists but is not a directory, it raises an exception.

    Args:
        src_dir (str): The path of the source directory to move.
        dst_dir (str): The path of the destination directory.

    Raises:
        OSError: If there is an error moving the directory.
        ValueError: If src_dir doesn't exist, is not a directory, or if dst_dir exists but is not a directory.
    """
    if not os.path.isdir(src_dir):
        raise ValueError("Source directory {0} does not exist".format(src_dir))
    if os.path.abspath(src_dir) == os.path.abspath(dst_dir):
        return  # src_dir and dst_dir are the same, so there's nothing to do
    if os.path.exists(dst_dir):
        if os.path.isdir(dst_dir):
            try:
                shutil.rmtree(dst_dir)
            except OSError as e:
                raise OSError("Error removing directory {0}: {1}".format(dst_dir, e))
        else:
            raise ValueError("Destination {0} exists but is not a directory".format(dst_dir))
    try:
        shutil.move(src_dir, dst_dir)
    except OSError as e:
        raise OSError("Error moving directory {0} to {1}: {2}".format(src_dir, dst_dir, e))

def copy_contents(src_dir, dst_dir):
    """
    Copies the contents of src_dir to dst_dir.
    If src_dir doesn't exist or is not a directory, it raises an exception.
    If dst_dir doesn't exist, it creates it.
    If an item in src_dir already exists in dst_dir, it overwrites it.

    Args:
        src_dir (str): The path of the source directory to copy from.
        dst_dir (str): The path of the destination directory to copy to.

    Raises:
        OSError: If there is an error copying the directory.
        ValueError: If src_dir doesn't exist, is not a directory, or if dst_dir is a subdirectory of src_dir.
    """
    if not os.path.isdir(src_dir):
        raise ValueError("Source directory {0} does not exist".format(src_dir))

    src_dir = os.path.abspath(src_dir)
    dst_dir = os.path.abspath(dst_dir)

    if src_dir == dst_dir:
        raise ValueError("Source and destination directories must be different")

    if dst_dir.startswith(src_dir + os.sep):
        raise ValueError("Destination directory must not be a subdirectory of the source directory")

    try:
        if not os.path.exists(dst_dir):
            os.makedirs(dst_dir)
    except OSError as e:
        raise OSError("Error creating directory {0}: {1}".format(dst_dir, e))

    for item in os.listdir(src_dir):
        src_path = os.path.join(src_dir, item)
        dst_path = os.path.join(dst_dir, item)
        
        try:
            if os.path.isdir(src_path):
                if os.path.exists(dst_path):
                    shutil.rmtree(dst_path)
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)
        except OSError as e:
            raise OSError("Error copying {0} to {1}: {2}".format(src_path, dst_path, e))

def remove_directory(dir):
    """
    Remove a directory and all its contents.
    If the directory doesn't exist, it does nothing.

    Parameters:
    - dir: The directory to remove.

    Raises:
    - TypeError: If dir is not a string.
    - OSError: If there is an error removing the directory.
    """
    if not isinstance(dir, str):
        raise TypeError("dir must be a string")

    if not os.path.isdir(dir):
        return

    try:
        shutil.rmtree(dir)
    except OSError as e:
        raise OSError("Error removing directory {}: {}".format(dir, e))

def remove_file(directory, filename):
    """
    Remove a file from a directory.
    Note that this function does nothing if the file doesn't exist.

    Parameters:
    directory (str): The directory from which to remove the file.
    filename (str): The name of the file to remove.

    Raises:
    OSError: If there's an error other than the file not existing (like the file is open in another program).
    """
    file_path = os.path.join(directory, filename)
    if not os.path.isfile(file_path):
        return
    try:
        os.remove(file_path)
    except OSError as e:
        print("Error: {} : {}".format(file_path, e.strerror))
        raise OSError("Error removing file {}: {}".format(file_path, e))

def main():
    parser = argparse.ArgumentParser(description='Helper Functions')
    parser.add_argument('--api', choices=['get_network_namespaces', 'is_process_port_in_namespace', 'print_with_separator', 'create_dir_if_not_exists', 'move_dir', 'copy_contents', 'remove_directory', 'write_data_to_file', 'write_chipdetails_mapping_to_file', 'read_chipdetails_mapping_from_file'], help='API to run')
    parser.add_argument('--process_name', help='Process name for is_process_port_in_namespace API')
    parser.add_argument('--namespace', help='Namespace for is_process_port_in_namespace API')
    parser.add_argument('--port', help='Port for is_process_port_in_namespace API')
    parser.add_argument('--message', help='Message for print_with_separator API')
    parser.add_argument('--dir_path', help='Directory path for create_dir_if_not_exists API and directory_exists API')
    parser.add_argument('--src_dir', help='Source directory path for move_dir, copy_contents, and remove_directory APIs')
    parser.add_argument('--dst_dir', help='Destination directory path for move_dir and copy_contents APIs')
    parser.add_argument('--folder', help='Folder path for write_data_to_file API and read_data_from_file API and remove_file API')
    parser.add_argument('--filename', help='Filename for write_data_to_file API, read_data_from_file API and remove_file API and file_exists API')
    parser.add_argument('--data', help='Data for write_data_to_file API')
    parser.add_argument('--mapping_file', help='Filename for write_chipdetails_mapping_to_file and read_chipdetails_mapping_from_file APIs')

    args = parser.parse_args()

    # Check if any arguments were provided
    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.api == 'is_process_port_in_namespace' and not args.namespace:
        parser.error("--namespace is required with 'is_process_port_in_namespace' API")
    elif args.api == 'is_process_port_in_namespace' and not (args.process_name or args.port):
        parser.error("At least one of --process_name or --port must be provided with 'is_process_port_in_namespace' API")

    if args.api == 'create_dir_if_not_exists' and not args.dir_path:
        parser.error("--dir_path is required with 'create_dir_if_not_exists' API")

    if args.api == 'move_dir' and (not args.src_dir or not args.dst_dir):
        parser.error("--src_dir and --dst_dir are required with 'move_dir' API")

    if args.api == 'copy_contents' and (not args.src_dir or not args.dst_dir):
        parser.error("--src_dir and --dst_dir are required with 'copy_contents' API")

    if args.api == 'remove_directory' and not args.dir_path:
        parser.error("--dir_path is required with 'remove_directory' API")

    if args.api == 'write_data_to_file' and (not args.folder or not args.filename or not args.data):
        parser.error("--folder, --filename, and --data are required with 'write_data_to_file' API")

    if  args.api == 'read_data_from_file' and (not args.folder or not args.filename):
        parser.error("--folder and --filename are required with 'read_data_from_file' API")

    if args.api == 'write_chipdetails_mapping_to_file' and not args.mapping_file:
        parser.error("--mapping_file is required with 'write_chipdetails_mapping_to_file' API")

    if args.api == 'read_chipdetails_mapping_from_file' and not args.mapping_file:
        parser.error("--mapping_file is required with 'read_chipdetails_mapping_from_file' API")

    if args.api == 'directory_exists' and not args.dir_path:
        parser.error("--dir_path is required with 'directory_exists' API")

    if args.api == 'remove_file' and (not args.folder or not args.filename):
        parser.error("--folder and --filename are required with 'remove_file' API")

    if args.api == 'file_exists' and (not args.folder or not args.filename):
        parser.error("--folder and --filename are required with 'file_exists' API")

    global logger
    logger = MyLogger(log_to_syslog=False)

    try:
        if args.api == 'get_network_namespaces':
            namespaces = get_network_namespaces()
            logger.log("Network namespaces: {}".format(', '.join(namespaces)))
        elif args.api == 'is_process_port_in_namespace':
            result = is_process_port_in_namespace(args.process_name, args.port, args.namespace)
            logger.log("Process {} port {} is {} in namespace {}".format(args.process_name, args.port, 'in' if result else 'not in', args.namespace))
        elif args.api == 'create_dir_if_not_exists':
            create_dir_if_not_exists(args.dir_path)
        elif args.api == 'move_dir':
            move_dir(args.src_dir, args.dst_dir)
        elif args.api == 'copy_contents':
            copy_contents(args.src_dir, args.dst_dir)
        elif args.api == 'remove_directory':
            remove_directory(args.dir_path)
        elif args.api == 'write_data_to_file':
            write_data_to_file(args.folder, args.filename, args.data)
        elif args.api == 'read_data_from_file':
            data = read_data_from_file(args.folder, args.filename)
            logger.log("Data: {}".format(data))
        elif args.api == 'write_chipdetails_mapping_to_file':
            write_chipdetails_mapping_to_file(args.mapping_file)
        elif args.api == 'read_chipdetails_mapping_from_file':
            mapping = read_chipdetails_mapping_from_file(args.mapping_file)
            logger.log("Mapping: {}".format(mapping))
        elif args.api == 'directory_exists':
            exists = directory_exists(args.dir_path)
            logger.log("Directory {} exists: {}".format(args.dir_path, exists))
        elif args.api == 'remove_file':
            remove_file(os.path.join(args.folder, args.filename))
            logger.log("File {} removed".format(os.path.join(args.folder, args.filename)))
        elif args.api == 'file_exists':
            exists = file_exists(args.filename)
            logger.log("File {} exists: {}".format(args.filename, exists))
        else:
            parser.print_help()
    except Exception as e:
        logger.log("Error: {}".format(e))

if __name__ == "__main__":
    main()