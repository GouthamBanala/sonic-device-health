from __future__ import print_function  # Compatibility for Python 2 and 3
import pyeapi
import os
import json
import sys
import re
import argparse

'''
Refer : https://pyeapi.readthedocs.io/en/master/configfile.html for more details on pyeapi
        https://github.com/arista-eosplus/pyeapi/blob/master/docs/quickstart.rst for more details on pyeapi
'''

def print_with_separator(message):
    separator = '_' * 50
    print(separator)
    print(message)
    print(separator)


class AristaSwitchEAPIHelper(object):
    def __init__(self):
        self.connection = None

    def connect(self):
        try:
            self.connection = pyeapi.client.connect(
                transport='socket',
            )
        except pyeapi.eapilib.SocketEapiConnection as e:
            raise ConnectionError("Socket connection error: {0}".format(e))
        except pyeapi.eapilib.ConnectionError as e:
            raise ConnectionError("Error connecting to the switch: {0}".format(e))
        except Exception as e:
            raise CustomError("An unexpected error occurred while connecting to the switch: {0}".format(e))

    def execute_command(self, command):
        if not self.connection:
            raise ConnectionError("Connection to the switch is not established. Call connect() first.")

        try:
            response = self.connection.execute(command)
            return response, None  # Return the response and indicate no exception
        except ConnectionError as e:
            return None, e  # Return None for response and the ConnectionError exception
        except CommandError as e:
            return None, e  # Return None for response and the CommandError exception
        except TimeoutError as e:
            return None, e  # Return None for response and the TimeoutError exception
        except CustomError as e:
            return None, e  # Return None for response and the CustomError exception
        except Exception as e:
            return None, e  # Return None for response and a generic exception

    '''
        show_daemon_output must be in the JSON format: Examples
        {
            "jsonrpc": "2.0",
            "result": [
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
        }
        or 

        {
            "jsonrpc": "2.0",
            "id": "139914201437648",
            "result": [
                {
                    "daemons": {}
                }
            ]
        }
    '''
    def extract_daemons_info(self, show_daemon_output):
        """
        Extract process information from 'show daemon' JSON output.
        """
        processes = {}
        error = None  # Initialize the error flag to None

        try:
            if "result" in show_daemon_output:
                daemons = show_daemon_output["result"][0].get("daemons", {})
                
                if not daemons:  # Check if daemons dictionary is empty
                    return processes, None  # Return an empty processes dictionary and no error
                
                for process_name, process_info in daemons.items():
                    processes[process_name] = {
                        "PID": process_info.get("pid", None),
                        "Uptime": process_info.get("uptime", None),
                        "StartTime": process_info.get("starttime", None),
                        "Running": process_info.get("running", False),
                    }
        except Exception as e:
            error = str(e)  # Store the exception message in the error flag

        return processes, error  # Return the processes and the error flag

    '''
        show_daemon_output must be in the JSON format
    '''
    def get_lom_engine_info(self, show_daemon_output):
        """
        Check if the 'lom-engine' process is running based on 'show daemon' JSON output.
        """
        processes, error = self.extract_daemons_info(show_daemon_output)
        if error:
            return None, error  # Return None and the error message
        lom_engine_info = processes.get("lom-engine", {})

        return lom_engine_info, None  # Return the lom_engine_info and no error

    '''
        show_daemon_output must be in the JSON format
    '''
    def get_lom_plmgr_info(self, show_daemon_output):
        """
        Check if the 'lom-plmgr' process is running based on 'show daemon' JSON output.
        """
        processes, error = self.extract_daemons_info(show_daemon_output)
        if error:
            return None, error  # Return None and the error message

        lom_plmgr_info = {k: v for k, v in processes.items() if k.startswith("lom-plmgr")}

        return lom_plmgr_info, None  # Return the lom_plmgr_info dictionary and no error

    def get_agent_uptime_info(self):
        """
        Run 'show agent uptime' command and parse the output to return a dictionary of agent uptimes.
        Sample  'show agent uptime' output format :
        {
            "jsonrpc": "2.0",
            "id": "139914201437648",
            "result": [
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
                        },
                        "dhcp_relaySyncd
        
        Parameters:
        - None

        Returns:
        - agent_uptimes: Dictionary of agent uptimes.
        - error: Error message if any.

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
        show_agent_uptime_command = 'show agent uptime'
        show_agent_uptime_output, error = self.execute_command(show_agent_uptime_command)

        if error:
            return None, error  # Return None and the error message
        
        agent_uptimes, error = self.parse_agent_uptime_output(show_agent_uptime_output)
        
        if error:
            return None, error  # Return None and the error message

        return agent_uptimes, None  # Return the agent uptimes and no error
         
 
    def parse_agent_uptime_output(self, show_agent_uptime_output):
        """
        Parse the JSON 'show agent uptime' command output and return a dictionary of agent uptimes.

        Parameters:
        - show_agent_uptime_output: JSON output of 'show agent uptime' command.

        Returns:
        - agent_uptimes: Dictionary of agent uptimes.
        - error: Error message if any.

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
        agent_uptimes = {}
        error = None  # Initialize the error flag to None

        if not show_agent_uptime_output:
            return agent_uptimes, None

        #print_with_separator(json.dumps(show_agent_uptime_output, indent=4))

        try:
            if "result" in show_agent_uptime_output:
                agent_info = show_agent_uptime_output["result"][0].get("agents", {})
                for agent_name, agent_data in agent_info.items():
                    agent_uptimes[agent_name] = {
                        'AgentStartTime': agent_data.get("agentStartTime", None),
                        'RestartCount': agent_data.get("restartCount", None)
                    }
        except Exception as e:
            error = str(e)  # Store the exception message in the error flag

        return agent_uptimes, error  # Return the agent uptimes and the error flag
    
    def compare_agent_uptimes(self, agent_uptimes_first, agent_uptimes_second):
        """
        Compare two sets of agent uptimes based on the specified conditions.

        Parameters:
        - agent_uptimes_first: First set of agent uptimes. Format is the same as the output of parse_agent_uptime_output().
        - agent_uptimes_second: Second set of agent uptimes. Format is the same as the output of parse_agent_uptime_output().

        Returns:
        - comparison_result: Boolean indicating whether all conditions are met.
        - error_output: Dictionary with error messages for each agent.

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

    def get_system_coredump(self) :
        """
        Run the 'show system coredump | json' command and return the core dump information.

        Parameters:
        - None

        Returns:
        - core_dump_info: Core dump information in JSON format.

        Output Format :
        {
            "mode": "compressed",
            "coreFiles": []
        }
        """
        command = 'show system coredump | json'
        core_dump_info, error = self.execute_command(command)
        if error:
            return None, error
        
        core_dump_info = core_dump_info.get('result', [{}])[0]

        return core_dump_info, None  # Return the core dump information and no error

    def compare_coredump(self, core_dump_info1, core_dump_info2):
        """
        Compare two sets of core dump information and return a boolean indicating if they match.

        Parameters:
        - core_dump_info1: First set of core dump information.
        - core_dump_info2: Second set of core dump information.

        Returns:
        - match: True if the coreFiles match, False otherwise.
        - unmatched_corefiles: List of coreFiles that do not match (if there are differences).
        """
        core_files1 = set(core_dump_info1.get('coreFiles', []))
        core_files2 = set(core_dump_info2.get('coreFiles', []))
        #print_with_separator("Core files in the first set: {0}".format(core_files1))
        #print_with_separator("Core files in the second set: {0}".format(core_files2))
        # Check if the coreFiles match
        match = core_files1 == core_files2

        if not match:
            # Find the unmatched coreFiles
            unmatched_corefiles = list(core_files1.symmetric_difference(core_files2))
            return False, unmatched_corefiles

        return True, list(core_files1)

    def get_hardware_capacity_utilization(self, peercentage_threshold=0):
        """
        Run the 'show hardware capacity utilization percent exceed <peercentage_threshold> | json' command and return the 'tables' output.

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
        - peercentage_threshold: Percentage threshold for capacity utilization.

        Returns:
        - output: 'tables' output in JSON format.
        - error: Error message if any.

        FUnction Output Format :
        {
            "VFP$Slice-3$Linecard0/0": 56,
            "IFP$Slice-0$Linecard0/0": 20
        }

        """

        command = 'show hardware capacity utilization percent exceed {0} | json'.format(peercentage_threshold)
        tables_output, error = self.execute_command(command)
        if error:
            return None, error # Return None and the error message
        
        tables_output = tables_output.get('result', [{}])[0].get('tables', [])
        output, error = self.parse_capacity_utilization(tables_output)

        if error:
            return None, error
        
        return output, None  # Return the tables output and no error
    
    def parse_capacity_utilization(self, tables_json):
        """
        Parse capacity utilization information and generate a dictionary with unique keys.

        Parameters:
        - tables_json: List of tables with capacity utilization information.

        Returns:
        - utilization_dict: Dictionary with keys formed from Table, Feature, and Chip and values as usedPercent.
        - error: Error message if an exception occurs.

        Output Format :
        {
            "VFP$Slice-3$Linecard0/0": 56,
            "IFP$Slice-0$Linecard0/0": 20
        }

        """
        utilization_dict = {}
        error = None

        try:
            for table_info in tables_json:
                table = table_info['table']
                feature = table_info['feature']
                chip = table_info['chip']
                usedPercent = table_info['usedPercent']

                key = "{}${}${}".format(table, feature, chip)
                utilization_dict[key] = usedPercent

        except Exception as e:
            error = "An error occurred while parsing capacity utilization: {}".format(e)

        return utilization_dict, error
    
    def compare_capacity_utilization(self, tables_json_before, tables_json_after, threshold=1):
        """
        Compare two sets of capacity utilization information based on the percentage threshold.

        Parameters:
        - tables_json_before: Dictionary with keys representing Table, Feature, and Chip, and values as usedPercent before.
        - tables_json_after: Dictionary with keys representing Table, Feature, and Chip, and values as usedPercent after.
        - threshold: Percentage threshold for the difference.

        Returns:
        - comparison_result: Boolean indicating whether all comparisons meet the threshold.
        - error_output: List of structured error messages for comparisons that exceed the threshold.
        """
        comparison_result = True
        error_output = []

        if len(tables_json_before) != len(tables_json_after):
            error_output.append("Number of tables in 'tables_json_before' and 'tables_json_after' does not match.")
            return False, error_output
        
        for key, used_percent_before in tables_json_before.items():
            used_percent_after = tables_json_after.get(key, None)
            
            table, feature, chip = key.split('$')

            if used_percent_after is None:
                error_output.append({
                    '_Table': table,
                    '_Feature': feature,
                    '_Chip': chip,
                    'error': "usedPercent is empty post check."
                })
                continue

            
            percentage_diff = abs(used_percent_before - used_percent_after)
            if percentage_diff > threshold:
                error_output.append({
                    '_Table': table,
                    '_Feature': feature,
                    '_Chip': chip,
                    'usedPercent_before': used_percent_before,
                    'usedPercent_after': used_percent_after,
                    'error': "Percentage difference {} is greater than threshold {}.".format(percentage_diff, threshold)
                })
                comparison_result = False

        return comparison_result, error_output
    

    def set_hardware_drop_counter(self, chipname, counter):
        command = [
            'configure',
            'platform fap {} counters set {}'.format(chipname, counter),
            'exit',
        ]
        try:
            self.execute_command(command)
        except Exception as e:
            print("Error: Failed to set counter. {}".format(e))

    def show_counter_drop_count(self, chipname, counter):
        command = ['show hardware counter drop']
        try:
            output = self.execute_command(command)
            result = json.loads(output)
            for chip, data in result['result'][0]['dropEvents'].items():
                if chip == chipname:
                    for event in data['dropEvent']:
                        if event['counterName'] == counter:
                            return event['dropCount']
            return 0
        except Exception as e:
            print("Error: Failed to show counter drop count. {}".format(e))
            return None
        
class CommandError(Exception):
    pass

class ConnectionError(Exception):
    pass

class TimeoutError(Exception):
    pass

class CustomError(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description='Arista Switch EAPI Helper')
    parser.add_argument(
    '--api', 
    choices=[
        'execute_command', 
        'set_hardware_drop_counter', 
        'show_counter_drop_count', 
        'get_system_coredump', 
        'get_hardware_capacity_utilization', 
        'get_agent_uptime_info'
        ], 
        default='execute_command',
        help='API to run. Choices are: execute_command, set_hardware_drop_counter, show_counter_drop_count, get_system_coredump, get_hardware_capacity_utilization, get_agent_uptime_info'
    )
    parser.add_argument('--command', help='Command for execute_command API')
    parser.add_argument('--chipname', help='Chip name for set_hardware_drop_counter and show_counter_drop_count APIs')
    parser.add_argument('--counter', help='Counter for set_hardware_drop_counter and show_counter_drop_count APIs')

    args = parser.parse_args()

    arista_manager = AristaSwitchEAPIHelper()

    try:
        arista_manager.connect()
    except Exception as e:
        print("Error: Failed to connect. {}".format(e))
        return

    if args.api == 'execute_command':
        if not args.command:
            print("Error: command is required for execute_command API.")
            return
        try:
            arista_manager.execute_command(args.command)
        except Exception as e:
            print("Error: Failed to execute command. {}".format(e))
    elif args.api == 'get_system_coredump':
        try:
            arista_manager.get_system_coredump()
        except Exception as e:
            print("Error: Failed to get system coredump. {}".format(e))
    elif args.api == 'get_hardware_capacity_utilization':
        try:
            arista_manager.get_hardware_capacity_utilization()
        except Exception as e:
            print("Error: Failed to get hardware capacity utilization. {}".format(e))
    elif args.api == 'get_agent_uptime_info':
        try:
            arista_manager.get_agent_uptime_info()
        except Exception as e:
            print("Error: Failed to get agent uptime info. {}".format(e))
    elif args.api == 'set_hardware_drop_counter':
        if not args.chipname or not args.counter:
            print("Error: chipname and counter are required for set_hardware_drop_counter API.")
            return
        try:
            arista_manager.set_hardware_drop_counter(args.chipname, args.counter)
        except Exception as e:
            print("Error: Failed to set hardware drop counter. {}".format(e))
    elif args.api == 'show_counter_drop_count':
        if not args.chipname or not args.counter:
            print("Error: chipname and counter are required for show_counter_drop_count API.")
            return
        try:
            drop_count = arista_manager.show_counter_drop_count(args.chipname, args.counter)
            if drop_count is not None:
                print("Drop count for counter {} on chip {} is {}".format(args.counter, args.chipname, drop_count))
        except Exception as e:
            print("Error: Failed to show counter drop count. {}".format(e))

if __name__ == "__main__":
    main()