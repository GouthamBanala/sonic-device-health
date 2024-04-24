from __future__ import print_function  # Compatibility for Python 2 and 3
import os
import json
import sys
import re
import argparse
import jsonrpclib

from common import *

'''
Helpers API's that uses the jsonrpclib library to connect to the switch via EAPI.
'''

class AristaSwitchEAPIHelper(object):
    """
    This class provides a helper for interacting with an Arista switch via EAPI.
    """

    def __init__(self):
        """
        Initialize the AristaSwitchEAPIHelper instance.
        """
        self.server = None

    def connect(self, socket_path='/var/run/command-api.sock'):
        """
        Connect to the Arista switch via EAPI.

        Args:
            socket_path (str): The path to the Unix socket for EAPI connection. Defaults to '/var/run/command-api.sock'.
        """
        try:
            # Format the URL for Unix socket connection
            url = 'unix://./{}'.format(socket_path)
            self.server = jsonrpclib.Server(url)
        except Exception as e:
            raise Exception("Error connecting to the switch: {0}".format(str(e)))    

    def execute_command(self, command):
        """
        Execute a command on the Arista switch via EAPI.

        Args:
            command (str): The command to be executed. Its array of words must be separated by spaces.

        Returns:
            dict: The response from the switch.

        Raises:
            ValueError: If the server is not connected.
            jsonrpclib.ProtocolError: If there's a protocol error.
            Exception: If an unexpected error occurs.
        """
        if self.server is None:
            raise ValueError("Not connected to the switch.")
        try:
            response = self.server.runCmds(1, command)
            return response
        except jsonrpclib.ProtocolError as e:
            raise jsonrpclib.ProtocolError("Protocol error: {}".format(e))
        except Exception as e:
            raise Exception("An error occurred while executing the command: {}".format(e))

    '''
    show daemon output returned by the switch via jsonrpclib:
       [
                {
                    "daemons": {
                        "lom-engine": {
                            "pid": 1234,
                            "uptime": 123456,
                            "starttime": "2019-01-01T00:00:00",
                            "running": true
                        },
                        "lom-plmgr-proc_0": {
                            "pid": 1234,
                            "uptime": 123456,
                            "starttime": "2019-01-01T00:00:00",
                            "running": true
                        },
                        "lom-plmgr-proc_1": {
                            "pid": 1234,
                            "uptime": 123456,
                            "starttime": "2019-01-01T00:00:00",
                            "running": true
                        }
                    }
                }
            ]
        or 

       [
                {
                    "daemons": {}
                }
        ]
    '''
    def extract_daemons_info(self):
        """
        Execute 'show daemon' command and extract process information from the JSON output.

        Returns:
            dict: A dictionary containing process information.

        Raises:
            Exception: If an error occurs while executing the command or processing the output.
        """
        processes = {}

        try:
            # Execute 'show daemon' command
            daemon_command = ['show daemon']
            show_daemon_output = self.execute_command(daemon_command)

            if show_daemon_output:
                daemons = show_daemon_output[0].get("daemons", {})
                
                if not daemons:  # Check if daemons dictionary is empty
                    return processes  # Return an empty processes dictionary
                    
                for process_name, process_info in daemons.items():
                    processes[process_name] = {
                        "PID": process_info.get("pid", None),
                        "Uptime": process_info.get("uptime", None),
                        "StartTime": process_info.get("starttime", None),
                        "Running": process_info.get("running", False),
                    }
        except Exception as e:
            raise Exception("An error occurred while extracting daemon info: {}".format(e))

        return processes  # Return the processes

    def is_daemon_running(self, daemon_name):
        """
        Check if a specific daemon is running, and its starttime and uptime are greater than 0.

        Parameters:
        - daemon_name: The name of the daemon to check.

        Returns:
        - running: Boolean indicating whether the daemon is running and its starttime and uptime are greater than 0.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.
        """
        try:
            processes = self.extract_daemons_info()
            daemon_info = processes.get(daemon_name, {})
            running = daemon_info.get("Running", False)
            starttime = daemon_info.get("StartTime", 0)
            uptime = daemon_info.get("Uptime", 0)
            print(str(running) + " " + str(starttime) + " " + str(uptime))
            return running and starttime > 0 and uptime > 0  # Return True if the daemon is running and starttime and uptime are greater than 0
        except Exception as e:
            raise Exception("An error occurred while checking if the daemon is running: {}".format(e))

    def is_daemon_config_exists(self, daemon_name):
        """
        Check if a specific daemon's configuration exists.

        Parameters:
        - daemon_name: The name of the daemon to check.

        Returns:
        - exists: Boolean indicating whether the daemon's configuration exists.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.
        """
        try:
            processes = self.extract_daemons_info()
            daemon_info = processes.get(daemon_name, {})
            exists = len(daemon_info) > 0  # If daemon_info is not empty, the configuration exists
            return exists  # Return the existence status
        except Exception as e:
            raise Exception("An error occurred while checking if the daemon's configuration exists: {}".format(e))
    
    def remove_daemon(self, daemon_name):
        """
        This function disables a specified daemon. This removes the daemon from the running configuration.

        Parameters:
        - daemon_name: The name of the daemon to disable.

        Raises:
        - Exception: If an error occurs while executing the command.
        """
        # Define the command sequence to disable the daemon
        command = [
            'configure',
            'no daemon {}'.format(daemon_name),
            'exit',
        ]

        try:
            self.execute_command(command)
        except Exception as e:
            raise Exception("Error occurred while removing daemon {}: {}".format(daemon_name, e))

    def remove_all_plmgr_daemons(self):
        """
        This function disables all lom-plmgr daemon instances. This removes the daemons from the running configuration.

        Returns:
        - disabled_daemons: A list of names of the disabled daemons.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.
        """

        # Get information about all lom-plmgr daemon instances. Instance daemon name is lom-plmgr-<proc_id>    
        try:
            lom_plmgr_info = self.get_daemon_lom_plmgr_info()

            if not lom_plmgr_info:
                return []

            disabled_daemons = []
            # Disable all lom-plmgr daemon instances i.e lom-plmgr-<proc_id> config is removed
            for instance_name, instance_info in lom_plmgr_info.items():
                # Disable the daemon
                self.remove_daemon(instance_name) # removes the config
                disabled_daemons.append(instance_name)

            return disabled_daemons
        except Exception as e:
            raise Exception("Error occurred while removing all plmgr daemons: {}".format(e))
    
    def shutdown_daemon(self, daemon_name):
        """
        This function issues a 'shutdown' command to a specified daemon. If the daemon is not running, then this will create inactive daemon.
        So always call is_daemon_running() before calling this function.

        Parameters:
        - daemon_name: The name of the daemon to shutdown.

        Raises:
        - Exception: If an error occurs while executing the command.
        """

        # Define the command sequence to shutdown the daemon
        command = [
            'configure',
            'daemon {}'.format(daemon_name),
            'shutdown',
            'exit',
        ]

        try:
            self.execute_command(command)
        except Exception as e:
            raise Exception("Error occurred while shutting down daemon {}: {}".format(daemon_name, e))
    
    def start_daemon(self, daemon_name):
        """
        This function issues a 'no shutdown' command to a specified daemon.

        Parameters:
        - daemon_name: The name of the daemon to start.

        Raises:
        - Exception: If an error occurs while executing the command.

        Note: This function does not check if the daemon is already running before attempting to start it.
        If the daemon does not exist, this command may create it. Therefore, it is recommended to call
        is_daemon_running() before executing this function.
        """

        # Define the command sequence to start the daemon
        command = [
            'configure',
            'daemon {}'.format(daemon_name),
            'no shutdown',
            'exit',
        ]

        try:
            self.execute_command(command)
        except Exception as e:
            raise Exception("Error occurred while starting daemon {}: {}".format(daemon_name, e))
    
    def get_daemon_lom_engine_info(self):
        """
        Execute 'show daemon' command and return the lom-engine daemon information.

        This function returns a dictionary containing the lom-engine daemon information if it exists, 
        otherwise an empty dictionary. 

        The lom-engine daemon information dictionary has the following structure:
        {
            "running": <boolean indicating if the daemon is running>,
            "option": <dictionary of daemon options>,
            "starttime": <float representing the daemon start time>,
            "pid": <integer representing the daemon process ID>,
            "enabled": <boolean indicating if the daemon is enabled>,
            "uptime": <float representing the daemon uptime>,
            "data": <dictionary of daemon data>,
            "isSdkAgent": <boolean indicating if the daemon is an SDK agent>
        }

        Returns:
            A dictionary containing the lom-engine daemon information if it exists, otherwise an empty dictionary.

        Raises:
            Exception: If an error occurs while executing the command or processing the output.
        """
        try:
            processes = self.extract_daemons_info()
            lom_engine_info = processes.get("lom-engine", {})
            return lom_engine_info  # Return the lom_engine_info
        except Exception as e:
            raise Exception("An error occurred while getting lom-engine daemon info: {}".format(e))

    def get_daemon_lom_plmgr_info(self):
        """
        Execute 'show daemon' command and return the lom-plmgr daemon information.

        This function returns a dictionary containing the lom-plmgr daemon information if it exists, 
        otherwise an empty dictionary.

        The lom-plmgr daemon information dictionary has the following structure:
        {
            "lom-plmgr-proc0": {
                "running": <boolean indicating if the daemon is running>,
                "option": <dictionary of daemon options>,
                "starttime": <float representing the daemon start time>,
                "pid": <integer representing the daemon process ID>,
                "enabled": <boolean indicating if the daemon is enabled>,
                "uptime": <float representing the daemon uptime>,
                "data": <dictionary of daemon data>,
                "isSdkAgent": <boolean indicating if the daemon is an SDK agent>
            }
        }

        Returns:
            A dictionary containing the lom-plmgr daemon information if it exists, otherwise an empty dictionary.

        Raises:
            Exception: If an error occurs while executing the command or processing the output.
        """
        try:
            processes = self.extract_daemons_info()
            lom_plmgr_info = {k: v for k, v in processes.items() if k.startswith("lom-plmgr")}
            return lom_plmgr_info  # Return the lom_plmgr_info dictionary
        except Exception as e:
            raise Exception("An error occurred while getting lom-plmgr daemon info: {}".format(e))     

    def get_agent_uptime_info(self):
        """
        Run 'show agent uptime' command and parse the output to return a dictionary of agent uptimes.
        Sample  'show agent uptime' output format :
            [
                {
                    "agents": {
                        "lldp": {
                            "agentStartTime": 123456,
                            "restartCount": 0
                        },
                        "stp": {
                            "agentStartTime": 123456,
                            "restartCount": 0
                        },
                        "dhcp_relay": {
                            "agentStartTime": 123456,
                            "restartCount": 0
                        }
                    }
                }
            ]
        Parameters:
        - None

        Returns:
        - agent_uptimes: Dictionary of agent uptimes.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.

        Output Format :
        {
            "lldp": {
                "AgentStartTime": 123456,
                "RestartCount": 0
            },
            "stp": {
                "AgentStartTime": 123456,
                "RestartCount": 0
            }
        }
        """
        show_agent_uptime_command = ['show agent uptime']

        try:
            show_agent_uptime_output = self.execute_command(show_agent_uptime_command)

            agent_uptimes = self.parse_agent_uptime_output(show_agent_uptime_output)

            if agent_uptimes is None:
                return None

            return agent_uptimes
        except Exception as e:
            raise Exception("An error occurred while getting agent uptime info: {}".format(e))
         
 
    def parse_agent_uptime_output(self, show_agent_uptime_output):
        """
        Parse the JSON 'show agent uptime' command output and return a dictionary of agent uptimes.

        Parameters:
        - show_agent_uptime_output: JSON output of 'show agent uptime' command.

        Returns:
        - agent_uptimes: Dictionary of agent uptimes.

        Raises:
        - Exception: If an error occurs while processing the output.

        Output Format :
        {
            "lldp": {
                "AgentStartTime": 123456,
                "RestartCount": 0
            },
            "stp": {
                "AgentStartTime": 123456,
                "RestartCount": 0
            }
        }
        """
        if not show_agent_uptime_output:
            return None

        agent_uptimes = {}
        
        try:
            agent_info = show_agent_uptime_output[0].get("agents", {})
            for agent_name, agent_data in agent_info.items():
                agent_uptimes[agent_name] = {
                    'AgentStartTime': agent_data.get("agentStartTime", None),
                    'RestartCount': agent_data.get("restartCount", None)
                }
        except Exception as e:
            raise Exception("An error occurred while parsing agent uptime output: {}".format(e))

        return agent_uptimes  # Return the agent uptimes
    
    def compare_agent_uptimes(self, agent_uptimes_first, agent_uptimes_second):
        """
        Compare two sets of agent uptimes based on the specified conditions.

        Parameters:
        - agent_uptimes_first: First set of agent uptimes. Format is the same as the output of parse_agent_uptime_output().
        - agent_uptimes_second: Second set of agent uptimes. Format is the same as the output of parse_agent_uptime_output().

        Returns:
        - comparison_result: Boolean indicating whether all conditions are met.
        - error_output: Dictionary with error messages for each agent.

        Raises:
        - Exception: If any condition is not met, an exception is raised with a detailed error message.

        Output Format :
        {
            true, {}
        }

        or 

        {
            false, {
                "lldp": [
                    "AgentStartTime is less than the first set of uptimes"
                ],
                "stp": [
                    "AgentStartTime is less than the first set of uptimes",
                    "RestartCount does not match"
                ]
            }
        }
        """
        comparison_result = True
        error_output = {}

        try:
            for agent_name, uptime1 in agent_uptimes_first.items():
                uptime2 = agent_uptimes_second.get(agent_name, None)

                if uptime2 is None:
                    comparison_result = False
                    error_output[agent_name] = ["Agent not found in the second set of uptimes"]
                else:
                    agent_errors = []

                    if uptime2['AgentStartTime'] != uptime1['AgentStartTime']:
                        agent_errors.append("AgentStartTime is less than the first set of uptimes")
                        comparison_result = False

                    if uptime1['RestartCount'] != uptime2['RestartCount']:
                        agent_errors.append("RestartCount does not match")
                        comparison_result = False

                    if agent_errors:
                        error_output[agent_name] = agent_errors

            return comparison_result, error_output
        except Exception as e:
            raise Exception("An error occurred while comparing agent uptimes: {}".format(e))

    # This returns error in EOS 4.21 
    def get_system_coredump(self):
        """
        Run the 'show system coredump | json' command and return the core dump information.

        Parameters:
        - None

        Returns:
        - core_dump_info: Core dump information in JSON format.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.

        Output Format :
        {
            "mode": "compressed",
            "coreFiles": []
        }
        """
        command = ['show system coredump']

        try:
            # Execute the command and get the output
            core_dump_info = self.execute_command(command)

            if core_dump_info is not None:
                core_dump_info = core_dump_info[0]

            # Return the core dump information (could be None if there was no output)
            return core_dump_info
        except Exception as e:
            raise Exception("An error occurred while getting system core dump: {}".format(e))
    
    '''

        Sample coredump outputs:

        [
            {
                "mode": "compressed", 
                "coreFiles": [
                    "core.11535.1699053220.vim.gz", 
                    "core.11488.1699053207.vim.gz", 
                    "core.11184.1699053078.vim_n.gz", 
                    "core.8716.1699051902.vim.gz", 
                    "core.8050.1699051619.vim.gz", 
                    "core.7978.1699051603.vim.gz"
                ]
            }
        ]

        or 
        [
            {
                "mode": "compressed",
                "coreFiles": []
            }
        ]

        or 

        [
            {
                "errors": [
                    "This is an unconverted command"
                ]
            }
        ]

    '''
    def compare_coredump(self, core_dump_info1, core_dump_info2):
        """
        Compare two sets of core dump information and return a boolean indicating if they match.
        Comparison is only filenames and not the content of the files.

        Parameters:
        - core_dump_info1: First set of core dump information.
        - core_dump_info2: Second set of core dump information.

        Returns:
        - match: True if the coreFiles match, False otherwise.
        - core_files: List of coreFiles in the first set.

        Raises:
        - Exception: If the coreFiles do not match, an exception is raised with a list of unmatched coreFiles.
        """
        core_files1 = set(core_dump_info1.get('coreFiles', []))
        core_files2 = set(core_dump_info2.get('coreFiles', []))

        # Check if the coreFiles match
        match = core_files1 == core_files2

        if not match:
            # Find the unmatched coreFiles
            unmatched_corefiles = list(core_files1.symmetric_difference(core_files2))
            return False, unmatched_corefiles

        return True, list(core_files1)

    # To-Do : Goutham : Add 30 sec average util to avoid false positives
    def get_hardware_capacity_utilization(self, percentage_threshold=0):
        """
        Run the 'show hardware capacity utilization percent exceed <percentage_threshold> | json' command and return
          the 'tables' output.

        command output:
        STR-ODL-7060CX-01(config)#show hardware capacity utilization percent exceed 0 | json 
        {
            "tables": [
                {
                    "highWatermark": 0,
                    "used": 0,
                    "usedPercent": 0,
                    "committed": 0,
                    "table": "VFP",
                    "chip": "Linecard0/0",
                    "maxLimit": 256,
                    "feature": "Slice-3",
                    "free": 256
                },
                {
                    "highWatermark": 55,
                    "used": 55,
                    "usedPercent": 21,
                    "committed": 0,
                    "table": "IFP",
                    "chip": "Linecard0/0",
                    "maxLimit": 256,
                    "feature": "Slice-0",
                    "free": 201
                }
            ]
        }

        Parameters:
        - percentage_threshold: Percentage threshold for capacity utilization.

        Returns:
        - output: 'tables' output in JSON format.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.

        Function Output Format :
        {
            "VFP$Slice-3$Linecard0/0": 56,
            "IFP$Slice-0$Linecard0/0": 20
        }
        """
        try:
            command = ['show hardware capacity utilization percent exceed {0} | json'.format(percentage_threshold)]
            tables_output = self.execute_command(command)
            
            if not tables_output:
                return None  # Return None if there's no output from the command
        
            tables_output = tables_output[0].get('tables', [])
            output = self.parse_hardware_capacity_utilization(tables_output)
            
            return output  # Return the tables output
        except Exception as e:
            raise Exception("An error occurred while getting hardware capacity utilization: {}".format(e))
    
    def parse_hardware_capacity_utilization(self, tables_json):
        """
        Parse capacity utilization information and generate a dictionary with unique keys.

        Parameters:
        - tables_json: List of tables with capacity utilization information.

        Returns:
        - utilization_dict: Dictionary with keys formed from 'Table, Feature, and Chip' and values as 'usedPercent'.

        Raises:
        - Exception: If an error occurs while processing the output.

        Output Format :
        {
            "VFP$Slice-3$Linecard0/0": 56,
            "IFP$Slice-0$Linecard0/0": 20
        }
        """
        utilization_dict = {}

        try:
            for table_info in tables_json:
                table = table_info['table']
                feature = table_info['feature']
                chip = table_info['chip']
                usedPercent = table_info['usedPercent']

                key = "{}${}${}".format(table, feature, chip)
                utilization_dict[key] = usedPercent

            return utilization_dict  # Return the utilization dictionary
        except Exception as e:
            raise Exception("An error occurred while parsing capacity utilization: {}".format(e))
    
    def compare_hardware_capacity_utilization(self, tables_json_before, tables_json_after, threshold=1):
        """
        Compare two sets of capacity utilization information based on the percentage threshold.

        Parameters:
        - tables_json_before: Dictionary with keys representing 'Table$Feature$Chip', and values as 'usedPercent' before.
        - tables_json_after: Dictionary with keys representing 'Table$Feature$Chip', and values as 'usedPercent' after.
        - threshold: Percentage threshold for the difference.

        Returns:
        - comparison_result: Boolean indicating whether all comparisons meet the threshold.
        - error_output: Dictionary with error messages for each key that did not meet the threshold.

        Output Format :
        {
            True, {}
        }

        or 

        {
            False, {
                "VFP$Slice-3$Linecard0/0": [
                    "usedPercent is empty post check"
                ],
                "IFP$Slice-0$Linecard0/0": [
                    "Percentage difference 4 is greater than threshold 1."
                ]
            }
        }
        """
        comparison_result = True
        error_output = {}

        for key, used_percent_before in tables_json_before.items():
            used_percent_after = tables_json_after.get(key, None)

            if used_percent_after is None:
                comparison_result = False
                error_output[key] = ["usedPercent is empty post check"]
                continue

            percentage_diff = abs(used_percent_before - used_percent_after)
            if percentage_diff > threshold:
                comparison_result = False
                if key not in error_output:
                    error_output[key] = []
                error_output[key].append("Percentage difference {} is greater than threshold {}.".format(percentage_diff, threshold))

        return comparison_result, error_output
    
    # This only works on 4.21Version
    def set_hardware_drop_counter_iptcrc(self, chipname, counter_value):
        """
        This function sets the hardware drop counter 'Ipt0CrcErrCnt' for a specific chip.

        Parameters:
        - chipname: The name of the chip for which the counter is to be set.
        - counter_value: The value to which the counter is to be set.

        Returns:
        - result: The result of the command execution.

        Raises:
        - Exception: If an error occurs while executing the command.
        """

        # Define the command sequence to set the counter
        command = [
            'configure',  # Enter configuration mode
            'platform fap {} counters set Ipt0CrcErrCnt {}'.format(chipname, counter_value),  # Set the counter for the specified chip
            'exit',  # Exit configuration mode
        ]

        try:
            result = self.execute_command(command)            
            return result 
        except Exception as e:
            raise Exception("An error occurred while setting hardware drop counter: {}".format(e))
        
    def show_hardware_counter_drop_count(self, chipname, counter):
        """
        This function retrieves the drop count for a specific hardware counter on a specific chip.

        Parameters:
        - chipname: The name of the chip for which the counter drop count is to be retrieved.
        - counter: The name of the counter for which the drop count is to be retrieved.

        Returns:
        - dropCount: The drop count for the specified counter on the specified chip.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.

        The function executes the 'show hardware counter drop' command and parses the output to find the drop count for the specified counter on the specified chip. If the counter is not found on the chip, the function returns 0 for the drop count. If an error occurs during command execution or an exception is raised, the function raises an exception.

        Output sample:
        {
            "totalPacketProcessorDrops": 64,
            "totalCongestionDrops": 0,
            "totalAdverseDrops": 1,
            "dropEvents": {
                "Jericho6/0": {
                    "dropEvent": [
                        {
                            "lastEventTime": "2024-01-09 16:49:12",
                            "eventCount": 1,
                            "dropInLastMinute": 0,
                            "initialEventTime": "2024-01-09 16:49:12",
                            "dropInLastOneDay": 0,
                            "dropInLastOneHour": 0,
                            "dropInLastTenMinute": 0,
                            "dropCount": 1,
                            "counterType": "PacketProcessor",
                            "counterId": 48,
                            "counterName": "dropVoqInMcastEmptyMcid"
                        }
                    ]
                },
                ...
            }
        }
        """

        # Define the command to show the hardware counter drop
        command = ['show hardware counter drop']

        try:
            output = self.execute_command(command)

            # Parse the command output
            for chip, data in output[0]['dropEvents'].items():
                if chip == chipname:
                    for event in data['dropEvent']:
                        if event['counterName'] == counter:
                            return event['dropCount']  # Return the drop count for the specified counter on the specified chip

            # If the counter is not found on the chip, return 0 for the drop count
            return 0
        except Exception as e:
            raise Exception("Failed to show counter drop count: {}".format(e))
        
    def add_terminattr_daemon(self, grpcaddr, grpcport, namespace, allowed_ips, certfile, keyfile, clientcafile, run_mode='PROD'):
        """
        This function enables the TerminAttr daemon.

        Parameters:
        - grpcaddr: The IP address for the gRPC server.
        - grpcport: The port for the gRPC server.
        - namespace: The namespace in which the gRPC server should run.
        - allowed_ips: The IPs allowed to connect to the gRPC server.
        - certfile: The path to the server certificate file.
        - keyfile: The path to the server key file.
        - clientcafile: The path to the client CA file.
        - run_mode: The run mode for the TerminAttr. Default is 'PROD'.

        Returns:
        - result: The result of the command execution.

        Raises:
        - Exception: If an error occurs while executing the command.
        """

        # Define the gRPC address
        if namespace:
            grpc_addr = '{}/{}:{}'.format(namespace, grpcaddr, grpcport)
        else:
            grpc_addr = '{}:{}'.format(grpcaddr, grpcport)

        # Define the base command
        exec_command = '/usr/bin/TerminAttr -grpcaddr={} --disableaaa'.format(grpc_addr)
        
        command = [
            'configure', 
            'daemon TerminAttr', 
            'exec {}'.format(exec_command), 
            'shutdown',  
            'no shutdown', 
            'exit',
        ]

        # Add allowed_ips option if provided
        if allowed_ips:
            command[2] += ' -allowed_ips {}'.format(allowed_ips)

        # Add certificate options if all are provided
        if certfile and keyfile and clientcafile:
            command[2] += ' -certfile {} -keyfile {} -clientcafile {}'.format(certfile, keyfile, clientcafile)

        try:
            result = self.execute_command(command)
            return result  # Return the result of the command execution
        except Exception as e:
            raise Exception("An error occurred while adding terminattr daemon: {}".format(e))

    def get_daemon_terminattr_info(self):
        """
        Execute 'show daemon' command and check if the 'TerminAttr' process is running.

        Returns:
        - terminattr_info: A dictionary containing information about the 'TerminAttr' process.

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.
        """

        try:
            processes = self.extract_daemons_info()            
            terminattr_info = {k: v for k, v in processes.items() if k.startswith("TerminAttr")}

            return terminattr_info  # Return the information about the 'TerminAttr' process
        except Exception as e:
            raise Exception("An error occurred while getting daemon TerminAttr info: {}".format(e))

    def extract_terminattr_config(self):
        """
        Execute 'show running-config' command and extract TerminAttr daemon configuration from the JSON output.

        The output is a dictionary with the following structure:

        {
            "shutdown": <boolean>,  # Indicates if the daemon is enabled or not. True if "no shutdown" is present in the configuration, False otherwise.
            "namespace": <string>,  # The namespace extracted from the -restaddr or -grpcaddr argument.
            "restAddr": <string>,  # The REST address extracted from the -restaddr argument.
            "restPort": <string>,  # The REST port extracted from the -restaddr argument.
            "grpcAddr": <string>,  # The gRPC address extracted from the -grpcaddr argument.
            "grpcPort": <string>,  # The gRPC port extracted from the -grpcaddr argument.
            "allowed_ips": <string>,  # The IPs allowed to connect to the gRPC server.
            "certfile": <string>,  # The path to the server certificate file.
            "keyfile": <string>,  # The path to the server key file.
            "clientcafile": <string>,  # The path to the client CA file.
        }

        Raises:
        - Exception: If an error occurs while executing the command or processing the output.
        
        """
        terminattr_config = None
        error = None

        try:
            # Execute 'show running-config' command
            running_config_command = ['show running-config']
            show_running_config_output = self.execute_command(running_config_command)

            if show_running_config_output:
                cmds = show_running_config_output[0].get("cmds", {})
                terminattr_config_raw = cmds.get("daemon TerminAttr", {}).get("cmds", {})

                if terminattr_config_raw:
                    # Initialize the configuration dictionary
                    terminattr_config = {
                        "shutdown": False,
                        "namespace": None,
                        "restAddr": None,
                        "restPort": None,
                        "grpcAddr": None,
                        "grpcPort": None,
                        "allowed_ips": None,
                        "certfile": None,
                        "keyfile": None,
                        "clientcafile": None,
                    }

                    # Check if the daemon is enabled
                    if "no shutdown" in terminattr_config_raw:
                        terminattr_config["shutdown"] = True

                    # Parse each command
                    for command in terminattr_config_raw:
                        rest_match = re.search(r"-restaddr=(?:(?P<namespace>[^/]+)/)?(?P<restAddr>[^:]+)?:(?P<restPort>\d+)?", command)
                        #grpc_match = re.search(r"-grpcaddr=(?:(?P<grpcNamespace>[^/]+)/)?(?P<grpcAddr>[^:]*)?:?(?P<grpcPort>\d+)?", command)
                        grpc_match  = re.search(r"-grpcaddr=(?P<namespace_grpcAddr>[^:]+):?(?P<grpcPort>\d+)?", command)
                        allowed_ips_match = re.search(r"-allowed_ips (?P<allowed_ips>[^ ]+)", command)
                        certfile_match = re.search(r"-certfile (?P<certfile>[^ ]+)", command)
                        keyfile_match = re.search(r"-keyfile (?P<keyfile>[^ ]+)", command)
                        clientcafile_match = re.search(r"-clientcafile (?P<clientcafile>[^ ]+)", command)

                        if rest_match:
                            terminattr_config["restAddr"] = rest_match.group("restAddr") or terminattr_config["restAddr"]
                            terminattr_config["restPort"] = rest_match.group("restPort") or terminattr_config["restPort"]
                            terminattr_config["namespace"] = rest_match.group("namespace") or terminattr_config["namespace"]

                        if grpc_match:
                            namespace_grpcAddr = grpc_match.group("namespace_grpcAddr")
                            if '/' in namespace_grpcAddr:
                                namespace, grpcAddr = namespace_grpcAddr.split('/', 1)
                            else:
                                namespace = None
                                grpcAddr = namespace_grpcAddr

                            terminattr_config["grpcAddr"] = grpcAddr or terminattr_config["grpcAddr"]
                            terminattr_config["grpcPort"] = grpc_match.group("grpcPort") or terminattr_config["grpcPort"]
                            terminattr_config["namespace"] = namespace or terminattr_config["namespace"]
                            
                        if allowed_ips_match:
                            terminattr_config["allowed_ips"] = allowed_ips_match.group("allowed_ips")

                        if certfile_match:
                            terminattr_config["certfile"] = certfile_match.group("certfile")

                        if keyfile_match:
                            terminattr_config["keyfile"] = keyfile_match.group("keyfile")

                        if clientcafile_match:
                            terminattr_config["clientcafile"] = clientcafile_match.group("clientcafile")

                        return terminattr_config  # Return the TerminAttr daemon configuration
        except Exception as e:
            raise Exception("An error occurred while extracting TerminAttr config: {}".format(e))
        
    def add_lom_engine_daemon(self, lom_engine_path, config_dir, run_mode='PROD', syslog_level=7, in_namespace=True):
        """
        This function starts the lom-engine daemon.

        Parameters:
        - lom_engine_path: The path to the lom-engine executable.
        - config_dir: The directory where the configuration files are located.
        - run_mode: The run mode for the lom-engine. Default is 'PROD'.
        - syslog_level: The syslog level for the lom-engine. Default is 7.
        - in_namespace: Boolean indicating whether to run the command in the MANAGEMENT_NAMESPACE. Default is True.

        Returns:
        - result: The result of the command execution.

        Raises:
        - Exception: If an error occurs while executing the command.
        """

        # Define the command sequence to start the lom-engine daemon
        exec_command = '{} -path={} -mode={} -syslog_level={}'.format(lom_engine_path, config_dir, run_mode, syslog_level)
        if in_namespace:
            exec_command = '/usr/sbin/ip netns exec {} {}'.format(MANAGEMENT_NAMESPACE, exec_command)

        command = [
            'configure',
            'daemon lom-engine',
            'exec {}'.format(exec_command),
            'no shutdown',
            'exit',
        ]

        try:
            result = self.execute_command(command)
            return result  # Return the result of the command execution
        except Exception as e:
            raise Exception("An error occurred while adding lom-engine daemon: {}".format(e))

    def add_plugin_manager_daemon(self, lom_plugin_mgr_path, proc_id, config_dir, run_mode='PROD', syslog_level=7, in_namespace=True):
        """
        This function starts the lom-plugin-manager daemon.

        Parameters:
        - lom_plugin_mgr_path: The path to the lom-plugin-manager executable.
        - proc_id: The process ID for the lom-plugin-manager.
        - config_dir: The directory where the configuration files are located.
        - run_mode: The run mode for the lom-plugin-manager. Default is 'PROD'.
        - syslog_level: The syslog level for the lom-plugin-manager. Default is 7.
        - in_namespace: Boolean indicating whether to run the command in the MANAGEMENT_NAMESPACE. Default is True.

        Returns:
        - result: The result of the command execution.

        Raises:
        - Exception: If an error occurs while executing the command.
        """

        # Define the command sequence to start the lom-plugin-manager daemon
        exec_command = '{} -proc_id={} -syslog_level={} -path={} -mode={}'.format(lom_plugin_mgr_path, proc_id, syslog_level, config_dir, run_mode)
        if in_namespace:
            exec_command = '/usr/sbin/ip netns exec {} {}'.format(MANAGEMENT_NAMESPACE, exec_command)

        command = [
            'configure',
            'daemon lom-plmgr-{}'.format(proc_id),
            'exec {}'.format(exec_command),
            'no shutdown',
            'exit',
        ]

        try:
            result = self.execute_command(command)
            return result  # Return the result of the command execution
        except Exception as e:
            raise Exception("An error occurred while adding lom-plugin-manager daemon: {}".format(e))
    
    def add_boot_event_handler(self, handler_name, script_path, delay=1, timeout=100, asynchronous=True):
        """
        Configure a boot event handler on the Arista switch via EAPI.

        Note : For trigger on-boot, when you exit the configuration mode, the event handler is executed right away. 
            This creates issues when your only intention is to execute the event handler on boot.
            One way to avoid this is to create a tmp file at /tmp and add the logic in the boot up script to only execute if the file do not exist.
            On boot up time, the file will not exist and the event handler will be executed.               

        Args:
            handler_name (str): The name of the event handler.
            script_path (str): The path to the script to be executed by the event handler.
            delay (int): The delay before the event handler is triggered. Default is 1.
            timeout (int): The timeout for the event handler. Default is 100.
            asynchronous (bool): Whether the event handler should be executed asynchronously. Default is True.

        Returns:
            - result: The result of the command execution.

        Raises:
            - Exception: If an error occurs while executing the command.
        """
        commands = [
            'configure',
            "no event-handler {}".format(handler_name),
            "event-handler {}".format(handler_name),
            "action bash {}".format(script_path),
            "trigger on-boot",
            "delay {}".format(delay),            
            "timeout {}".format(timeout),
            #"no trigger on-config disabled",
        ]
        if asynchronous:
            commands.append("asynchronous")

        try:
            result = self.execute_command(commands)
            return result  # Return the result of the command execution
        except Exception as e:
            raise Exception("An error occurred while adding boot event handler: {}".format(e))
    
    def remove_event_handler(self, handler_name):
        """
        Remove an event handler on the Arista switch via EAPI.

        Args:
            handler_name (str): The name of the event handler to be removed.

        Returns:
            - result: The result of the command execution.

        Raises:
            - Exception: If an error occurs while executing the command.
        """
        command = [
            'configure',
            "no event-handler {}".format(handler_name)
        ]

        try:
            result = self.execute_command(command)            
            return result  # Return the result of the command execution
        except Exception as e:
            raise Exception("An error occurred while removing event handler: {}".format(e))

    def get_event_handler_data(self, handler_name):
        """
        Get the event handler data on the Arista switch via EAPI.

        Args:
            handler_name (str): The name of the event handler.

        Returns:
            - result: The parsed event handler data as a dictionary.

        Raises:
            - Exception: If an error occurs while executing the command or parsing the data.
        """
        show_event_handler_command = ['show event-handler %s' % handler_name]

        try:
            show_event_handler_output = self.execute_command(show_event_handler_command)
            # Get the first element of the list
            event_handler_data = show_event_handler_output[0].get("eventHandlers", {}).get(handler_name, {})

            return event_handler_data  # Return the parsed result
        except IndexError as e:
            raise Exception("An error occurred while parsing the event handler data: {}".format(e))

    def commit_config(self):
        """
        This function issues a 'write memory' command to save the current configuration to the startup configuration.

        Returns:
        - result: The result of the command execution.

        Raises:
        - Exception: If an error occurs while executing the command.
        """

        # Define the command to save the configuration
        command = [
            'configure',
            'write memory'
        ]

        try:
            result = self.execute_command(command)            
            return result  # Return the result of the command execution
        except Exception as e:
            raise Exception("An error occurred while committing configuration: {}".format(e))
    
    def copy_running_config_to_file(self, filepath):
        """
        This function issues a 'copy running-config' command to save the current configuration to a file.

        Args:
            filepath (str): The full path of the file to save the configuration to.

        Returns:
        - result: The result of the command execution.

        Raises:
        - Exception: If an error occurs while executing the command.
        """

        # Define the command to save the configuration to a file
        command = [
            'configure',
            'copy running-config file:%s' % filepath
        ]

        try:
            result = self.execute_command(command)            
            return result  # Return the result of the command execution
        except Exception as e:
            raise Exception("An error occurred while copying running configuration to file: {}".format(e))
    
def main():
    parser = argparse.ArgumentParser(description='Arista Switch EAPI Helper')
    parser.add_argument(
        '--api', 
        help='''Select API to run with proper arguments. Comma separated for config commands. 
        Supported APIs are: 
        - execute_command
        - is_daemon_running
        - remove_daemon
        - is_daemon_config_exists
        - get_hardware_capacity_utilization
        - set_hardware_drop_counter_iptcrc
        - show_hardware_counter_drop_count
        - add_terminattr_daemon
        - add_lom_engine_daemon
        - add_plugin_manager_daemon
        - add_boot_event_handler
        - remove_event_handler
        - get_event_handler_data
        - copy_running_config_to_file'''
    )

    parser.add_argument('--command', help='CLI Command to execute with execute_command API. Use comma seperated for multiple commands.')
    parser.add_argument('--daemon_name', help='Daemon name for is_daemon_running command, remove_daemon command and is_daemon_config_exists command')
    parser.add_argument('--percentage_threshold', type=int, default=0, help='Percentage threshold for capacity utilization for get_hardware_capacity_utilization command. Default is 0.')
    parser.add_argument('--chipname', help='Chip name for set_hardware_drop_counter_iptcrc and show_hardware_counter_drop_count command')
    parser.add_argument('--counter', help='Counter value for set_hardware_drop_counter_iptcrc and counter name show_hardware_counter_drop_count command')    
  
    parser.add_argument('--grpcaddr', help='gRPC address for add_terminattr_daemon command')
    parser.add_argument('--grpcport', help='gRPC port for add_terminattr_daemon command')
    parser.add_argument('--namespace', default=None, help='Namespace for add_terminattr_daemon command')
    parser.add_argument('--allowed_ips', default=None, help='The IPs allowed to connect to the gRPC server for add_terminattr_daemon command')
    parser.add_argument('--certfile', default=None, help='The path to the server certificate file for add_terminattr_daemon command')
    parser.add_argument('--keyfile', default=None, help='The path to the server key file for add_terminattr_daemon command')
    parser.add_argument('--clientcafile', default=None, help='The path to the client CA file for add_terminattr_daemon command')

    parser.add_argument('--lom_engine_path', help='Path to lom-engine executable for add_lom_engine_daemon command')
    parser.add_argument('--config_dir', help='Directory where the configuration files are located for add_lom_engine_daemon command' and 'add_plugin_manager_daemon command')
    parser.add_argument('--run_mode', help='Run mode for the lom-engine for add_lom_engine_daemon command' and 'add_plugin_manager_daemon command')
    parser.add_argument('--lom_plugin_mgr_path', help='Path to lom-plugin-manager executable for add_plugin_manager_daemon command')
    parser.add_argument('--proc_id', help='Process ID for the lom-plugin-manager for add_plugin_manager_daemon command')
    parser.add_argument('--in_namespace', type=str, default='True', help='Boolean indicating whether to run the command in the MANAGEMENT_NAMESPACE for add_lom_engine_daemon command and add_plugin_manager_daemon command')
    parser.add_argument('--syslog_level', type=int, default=7, help='The syslog level for the lom-plugin-manager for add_plugin_manager_daemon command and add_lom_engine_daemon command')
    
    parser.add_argument('--handler_name', help='The name of the event handler for add_boot_event_handler, remove_event_handler and get_event_handler_data command')
    parser.add_argument('--script_path', help='The path to the script to be executed by the event handler for add_boot_event_handler command')
    parser.add_argument('--delay', type=int, default=0, help='The delay before the event handler is triggered for add_boot_event_handler command. Default is 0.')
    parser.add_argument('--timeout', type=int, default=10, help='The timeout for the event handler for add_boot_event_handler command. Default is 10.')
    parser.add_argument('--asynchronous', type=str, default='True', help='Whether the event handler should be executed asynchronously for add_boot_event_handler command. Default is False.')
    parser.add_argument('--filepath', help='The full path of the file to save the configuration to for copy_running_config_to_file command')

    args = parser.parse_args()

    # Check if any arguments were provided
    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.api == 'execute_command' and not args.command :
        parser.error("--command is required with 'execute_command' API")

    if args.api in ['set_hardware_drop_counter_iptcrc', 'show_hardware_counter_drop_count'] and (not args.chipname or not args.counter):
        parser.error("--chipname and --counter are required with 'set_hardware_drop_counter_iptcrc' and 'show_hardware_counter_drop_count' APIs")

    if args.api in ['is_daemon_running', 'is_daemon_config_exists', 'remove_daemon', 'shutdown_daemon', 'start_daemon'] and not args.daemon_name:
        parser.error("--daemon_name is required with 'is_daemon_running', 'is_daemon_config_exists', 'remove_daemon', 'shutdown_daemon' and 'start_daemon' APIs")

    if args.api == 'add_terminattr_daemon' and (not args.grpcaddr or not args.grpcport):
        parser.error("--grpcaddr and --grpcport are required with 'add_terminattr_daemon' API")

    if args.api == 'add_lom_engine_daemon' and (not args.lom_engine_path or not args.config_dir):
        parser.error("--lom_engine_path and --config_dir are required with 'add_lom_engine_daemon' API")

    if args.api == 'add_plugin_manager_daemon' and (not args.lom_plugin_mgr_path or not args.proc_id or not args.config_dir):
        parser.error("--lom_plugin_mgr_path, --proc_id and --config_dir are required with 'add_plugin_manager_daemon' API")

    if args.api == 'add_boot_event_handler' and (not args.handler_name or not args.script_path):
        parser.error("--handler_name, --script_path are required with 'add_boot_event_handler' API")

    if args.api == 'remove_event_handler' and not args.handler_name:
        parser.error("--handler_name is required with 'remove_event_handler' API")

    if args.api == 'get_event_handler_data' and not args.handler_name:
        parser.error("--handler_name is required with 'get_event_handler_data' API")

    if args.api == 'copy_running_config_to_file' and not args.filepath:
        parser.error("--filepath is required with 'copy_running_config_to_file' API")

    arista_manager = AristaSwitchEAPIHelper()

    try:
        arista_manager.connect()
    except Exception as e:
        print("Error: Failed to connect. {}".format(e))
        return

    if args.api == 'execute_command':
        try:
            command = re.sub(' +', ' ', args.command).strip()
            command_list = command.split(',')
            command_list = [cmd.strip() for cmd in command_list]
            result = arista_manager.execute_command(command_list)
            print("Result: {}".format(json.dumps(result, indent=4)))
        except Exception as e:
            print("Error: Failed to execute command. {}".format(e))

    elif args.api == 'extract_daemons_info':
        try:
            result = arista_manager.extract_daemons_info()
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to extract daemons info. {}".format(e))

    elif args.api == 'is_daemon_running':
        try:
            result = arista_manager.is_daemon_running(args.daemon_name)
            print(result)
        except Exception as e:
            print("Error: Failed to check if daemon is running. {}".format(e))
    elif args.api == 'is_daemon_config_exists':
        try:
            result = arista_manager.is_daemon_config_exists(args.daemon_name)
            print("Result: {}".format(result))
        except Exception as e:
            print("Error: Failed to check if daemon config exists. {}".format(e))

    elif args.api == 'remove_daemon':
        try:
            arista_manager.remove_daemon(args.daemon_name)
            print("Successfully disabled daemon.")
        except Exception as e:
            print("Error: Failed to disable daemon. {}".format(e))

    elif args.api == 'remove_all_plmgr_daemons':
        try:
            result = arista_manager.remove_all_plmgr_daemons()
            print(result)
        except Exception as e:
            print("Error: Failed to remove all plmgr daemons. {}".format(e))

    elif args.api == 'shutdown_daemon':
        try:
            arista_manager.shutdown_daemon(args.daemon_name)
            print("Successfully shutdown daemon.")
        except Exception as e:
            print("Error: Failed to shutdown daemon. {}".format(e))
    elif args.api == 'start_daemon':
        try:
            arista_manager.start_daemon(args.daemon_name)
            print("Successfully started daemon.")
        except Exception as e:
            print("Error: Failed to start daemon. {}".format(e))

    elif args.api == 'get_daemon_lom_engine_info':
        try:
            result = arista_manager.get_daemon_lom_engine_info()
            print(result)
        except Exception as e:
            print("Error: Failed to get lom engine info. {}".format(e))

    elif args.api == 'get_daemon_lom_plmgr_info':
        try:
            result = arista_manager.get_daemon_lom_plmgr_info()
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to get lom plmgr info. {}".format(e))

    elif args.api == 'get_agent_uptime_info':
        try:
            result = arista_manager.get_agent_uptime_info()
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to get agent uptime info. {}".format(e))

    elif args.api == 'get_system_coredump':
        try:
            result = arista_manager.get_system_coredump()
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to get system coredump. {}".format(e))

    elif args.api == 'get_hardware_capacity_utilization':
        try:
            result = arista_manager.get_hardware_capacity_utilization(args.percentage_threshold)
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to get hardware capacity utilization. {}".format(e))

    elif args.api == 'set_hardware_drop_counter_iptcrc':
        try:
            arista_manager.set_hardware_drop_counter_iptcrc(args.chipname, args.counter)
            print("Successfully set hardware drop counter.")
        except Exception as e:
            print("Error: Failed to set hardware drop counter. {}".format(e))
    elif args.api == 'show_hardware_counter_drop_count':
        try:
            result = arista_manager.show_hardware_counter_drop_count(args.chipname, args.counter)
            print("Drop count for counter '{}' on chip '{}' is {}.".format(args.counter, args.chipname, result))
        except Exception as e:
            print("Error: Failed to show counter drop count. {}".format(e))

    elif args.api == 'add_terminattr_daemon':
        try:
            arista_manager.add_terminattr_daemon(args.grpcaddr, args.grpcport, args.namespace, args.allowed_ips, args.certfile, args.keyfile, args.clientcafile)
            print("Successfully enabled TerminAttr.")
        except Exception as e:
            print("Error: Failed to enable TerminAttr. {}".format(e))

    elif args.api == 'get_daemon_terminattr_info':
        try:
            result = arista_manager.get_daemon_terminattr_info()
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to get TerminAttr info. {}".format(e))

    elif args.api == 'extract_terminattr_config':
        try:
            result = arista_manager.extract_terminattr_config()
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to extract TerminAttr config. {}".format(e))

    elif args.api == 'add_lom_engine_daemon':
        try:
            args.in_namespace = args.in_namespace.lower() in ('yes', 'true', 't', 'y', '1')
            arista_manager.add_lom_engine_daemon(args.lom_engine_path, args.config_dir, args.run_mode, args.in_namespace, args.syslog_level)
            print("Successfully started lom-engine daemon.")
        except Exception as e:
            print("Error: Failed to start lom-engine daemon. {}".format(e))

    elif args.api == 'add_plugin_manager_daemon':
        try:
            args.in_namespace = args.in_namespace.lower() in ('yes', 'true', 't', 'y', '1')
            arista_manager.add_plugin_manager_daemon(args.lom_plugin_mgr_path, args.proc_id, args.config_dir, args.run_mode, args.syslog_level, args.in_namespace)
            print("Successfully started lom-plugin-manager daemon.")
        except Exception as e:
            print("Error: Failed to start lom-plugin-manager daemon. {}".format(e))

    elif args.api == 'add_boot_event_handler':
        try:
            args.asynchronous = args.asynchronous.lower() in ('yes', 'true', 't', 'y', '1')
            arista_manager.add_boot_event_handler(args.handler_name, args.script_path, args.delay, args.timeout, args.asynchronous)
            print("Successfully configured event handler.")
        except Exception as e:
            print("Error: Failed to configure event handler. {}".format(e))
    elif args.api == 'remove_event_handler':
        try:
            arista_manager.remove_event_handler(args.handler_name)
            print("Successfully removed event handler.")
        except Exception as e:
            print("Error: Failed to remove event handler. {}".format(e))

    elif args.api == 'get_event_handler_data':
        try:
            result = arista_manager.get_event_handler_data(args.handler_name)
            print(json.dumps(result, indent=4))
        except Exception as e:
            print("Error: Failed to get event handler data. {}".format(e))

    elif args.api == 'commit_config':
        try:
            arista_manager.commit_config()
            print("Successfully wrote memory.")
        except Exception as e:
            print("Error: Failed to write memory. {}".format(e))

    elif args.api == 'copy_running_config_to_file':
        try:
            arista_manager.copy_running_config_to_file(args.filepath)
            print("Successfully copied running configuration to file.")
        except Exception as e:
            print("Error: Failed to copy running configuration to file. {}".format(e))

if __name__ == "__main__":
    main()