"""
arista_cli_helper.py

This script provides a helper class for interacting with an Arista switch via the CLI.
"""

from __future__ import print_function  # Python 2/3 compatibility
import subprocess
import time
import argparse

from common import *

class AristaSwitchCLIHelper(object):
    def __init__(self, logger=None):
        self.logger = logger

    def _execute_arista_command(self, command, option='show', privilege_level=15, print_output=False):
        """
        Execute a command on the Arista switch.

        Parameters:
        - command: The command to execute.
        - option: The option to use. Can be 'show' or 'config'. Default is 'show'.
        - privilege_level: The privilege level to use. Default is 15.
        - print_output: Whether to print the output. Default is False.

        Returns:
        - The output of the command.

        Raises:
        - ValueError: If the option is not 'show' or 'config'.
        - subprocess.CalledProcessError: If there's an error executing the command.
        - Exception: If an unexpected error occurs.
        """
        try:
            if option == 'show':
                full_command = 'Cli -c "{}"'.format(command)
            elif option == 'config':
                full_command = 'Cli -p {} -c "{}"'.format(privilege_level, command)
            else:
                raise ValueError("Invalid option. Use 'show' or 'config'.")
            output = subprocess.check_output(
                full_command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True
            )            
            #print("Command executed: {}".format(full_command))            
            if print_output:
                self.logger.log("Output: {}".format(output))
            return output  # Return the output
        except subprocess.CalledProcessError as e:
            raise subprocess.CalledProcessError("Error executing command: {0}".format(e.output.strip()))
        except Exception as e:
            raise Exception("Unexpected error: {0}".format(str(e)))

    def is_unix_eapi_running(self):
        """
        Check if the Unix EAPI is running on the Arista switch.

        Returns:
        - A boolean indicating whether the Unix EAPI is running.

        Raises:
        - subprocess.CalledProcessError: If there's an error executing the command.
        """
        arista_command = 'show management api http-commands'
        try:
            output = self._execute_arista_command(arista_command, option='show', print_output=False)
            return 'Unix Socket server: running' in output
        except subprocess.CalledProcessError as e:
            raise

    def enable_unix_eAPI_protocol(self):
        """
        Enable the Unix EAPI protocol on the Arista switch.

        Raises:
        - subprocess.CalledProcessError: If there's an error executing the command.
        """
        arista_command = "configure\n\
                          management api http-commands\n\
                          protocol unix-socket\n\
                          no shutdown"
        try:
            self._execute_arista_command(arista_command, option='config', print_output=False)
        except subprocess.CalledProcessError as e:
            raise

    def check_and_enable_unix_eAPI_protocol(self):
        """
        Check if the Unix EAPI protocol is running on the Arista switch, and enable it if it's not.

        Returns:
        - A boolean indicating whether the Unix EAPI protocol is now running.
        - A boolean indicating whether the Unix EAPI protocol was already enabled.

        Raises:
        - subprocess.CalledProcessError: If there's an error executing a command.
        """
        try:
            running = self.is_unix_eapi_running()
            already_enabled = running
            if not running:
                # Unix eAPI Socket is not running, try to enable it
                self.enable_unix_eAPI_protocol()
                time.sleep(CLI_CONFGURATION_WAIT_TIME)  # Wait for the configuration to take effect
                running = self.is_unix_eapi_running()  # Check if the protocol is now running
            return running, already_enabled
        except subprocess.CalledProcessError as e:
            raise
    # Since 'no shutdown' enables all the configured management protocols too, similarly 'shutdown' disables all the configured management protocols too
    # So better not to use this when we want to disable only unix-socket protocol. JUst remove the protocol unix-socket config instead.
    def disable_unix_eAPI_protocol(self):
        """
        Disable the Unix EAPI protocol on the Arista switch.

        Raises:
        - subprocess.CalledProcessError: If there's an error executing the command.
        """
        arista_command = "configure\n\
                          management api http-commands\n\
                          no protocol unix-socket"
        try:
            self._execute_arista_command(arista_command, option='config', print_output=False)
        except subprocess.CalledProcessError as e:
            raise
        
    def add_boot_event_handler(self, handler_name, script_path, delay=1, timeout=100, asynchronous=True):
        """
        Configure a boot event handler on the Arista switch via CLI.

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

        Raises:
            - subprocess.CalledProcessError: If an error occurs while executing the command.
        """
        arista_command = "configure\n\
                          no event-handler {}\n\
                          event-handler {}\n\
                          action bash {}\n\
                          trigger on-boot\n\
                          delay {}\n\
                          timeout {}".format(handler_name, handler_name, script_path, delay, timeout)
        if asynchronous:
            arista_command += "\nasynchronous"
        arista_command += "\nexit"
        try:
            self._execute_arista_command(arista_command, option='config', print_output=False)
        except subprocess.CalledProcessError as e:
            raise

    def remove_event_handler(self, handler_name):
        """
        Remove an event handler on the Arista switch via CLI.

        Args:
            handler_name (str): The name of the event handler to be removed.

        Raises:
            - subprocess.CalledProcessError: If an error occurs while executing the command.
        """
        arista_command = "configure\n\
                          no event-handler {}".format(handler_name)
        try:
            self._execute_arista_command(arista_command, option='config', print_output=False)
        except subprocess.CalledProcessError as e:
            raise

    def get_event_handler_data(self, handler_name):
        """
        Get the event handler data on the Arista switch via CLI.

        Args:
            handler_name (str): The name of the event handler.

        Returns:
            - output: The output of the command execution.

        Raises:
            - subprocess.CalledProcessError: If an error occurs while executing the command.
        """
        # First, get all event handlers
        arista_command = 'show event-handler'
        try:
            output = self._execute_arista_command(arista_command, option='config', print_output=False)
            
            # Check if the specified handler exists
            if handler_name in output:
                arista_command = 'show event-handler {}'.format(handler_name)
                output = self._execute_arista_command(arista_command, option='config', print_output=False)
            else:
                output = ''
            
            return output 
        except subprocess.CalledProcessError as e:
            raise
    
    def commit_config(self):
        """
        This function issues a 'write memory' command to save the current configuration to the startup configuration.

        Returns:
        - result: The result of the command execution.

        Raises:
        - subprocess.CalledProcessError: If an error occurs while executing the command.
        """
        arista_command = "configure\n\
                          write memory"
        try:
            result = self._execute_arista_command(arista_command, option='config', print_output=False)
            return result 
        except subprocess.CalledProcessError as e:
            raise
        
def main():
    parser = argparse.ArgumentParser(description='Arista Switch CLI Helper')
    parser.add_argument('--api',
                        help='API to run. Choices are: is_unix_eapi_running, enable_unix_eAPI_protocol, disable_unix_eAPI_protocol, \
                                check_and_enable_unix_eAPI_protocol, add_boot_event_handler, remove_event_handler, get_event_handler_data, commit_config')
    
    parser.add_argument('--handler_name', help='The name of the event handler for add_boot_event_handler, remove_event_handler and get_event_handler_data command')
    parser.add_argument('--script_path', help='The path to the script to be executed by the event handler for add_boot_event_handler command')
    parser.add_argument('--delay', type=int, default=1, help='The delay before the event handler is triggered for add_boot_event_handler command. Default is 1.')
    parser.add_argument('--timeout', type=int, default=100, help='The timeout for the event handler for add_boot_event_handler command. Default is 100.')
    parser.add_argument('--asynchronous', type=str, default='True', help='Whether the event handler should be executed asynchronously for add_boot_event_handler command. Default is True.')
    
    args = parser.parse_args()

    # Check if any arguments were provided
    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.api == 'add_boot_event_handler':
        if not args.handler_name or not args.script_path:
            parser.error("--handler_name and --script_path are required for add_boot_event_handler")
        if args.asynchronous.lower() == 'true':
            args.asynchronous = True
        else:
            args.asynchronous = False

    if args.api == 'remove_event_handler' or args.api == 'get_event_handler_data':
        if not args.handler_name:
            parser.error("--handler_name is required for remove_event_handler and get_event_handler_data")


    logger = MyLogger(level=logging.INFO, syslog_address='/dev/log', log_to_syslog=False)
    arista_manager = AristaSwitchCLIHelper(logger)

    try:
        if args.api == 'is_unix_eapi_running':
            running = arista_manager.is_unix_eapi_running()
            if running:
                print("Unix eAPI Socket is running")
            else:
                print("Unix eAPI Socket is not running")
        elif args.api == 'enable_unix_eAPI_protocol':
            arista_manager.enable_unix_eAPI_protocol()
            print("Unix eAPI Socket is enabled")
        elif args.api == 'disable_unix_eAPI_protocol':
            arista_manager.disable_unix_eAPI_protocol()
            print("Unix eAPI Socket is disabled")
        elif args.api == 'check_and_enable_unix_eAPI_protocol':
            running, already_enabled = arista_manager.check_and_enable_unix_eAPI_protocol()
            if running:
                if already_enabled:
                    print("Unix eAPI Socket is already enabled")
                else:
                    print("Unix eAPI Socket is enabled")
        elif args.api == 'add_boot_event_handler':
            arista_manager.add_boot_event_handler(args.handler_name, args.script_path, args.delay, args.timeout, args.asynchronous)
            print("Event handler added")
        elif args.api == 'remove_event_handler':
            arista_manager.remove_event_handler(args.handler_name)
            print("Event handler removed")
        elif args.api == 'get_event_handler_data':
            output = arista_manager.get_event_handler_data(args.handler_name)
            print("Event handler data: {}".format(output))
        elif args.api == 'commit_config':
            result = arista_manager.commit_config()
            print("Configuration committed")
        else:
            print("Invalid API")
    except Exception as e:
        print("Error: {}".format(e))

if __name__ == "__main__":
    main()