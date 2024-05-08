import os
import imp
import sys
import time
import argparse
import api as api
import re

def print_table(headers, data):
    # Find the maximum length of data in each column
    column_lengths = [max(len(str(x)) for x in col) for col in zip(*(data + [headers]))]
    
    # Create a format string for each row of the table
    format_string = " | ".join(["{:>" + str(length) + "}" for length in column_lengths])
    
    # Print the header row
    print(format_string.format(*headers))
    print("-" * len(format_string.format(*headers)))
    
    # Print each data row
    for row in data:
        print(format_string.format(*row))


# Define a sorting key function that handles numbers in strings
def natural_sort_key(s):
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(r'(\d+)', s)]

if os.geteuid() != 0:
        print("This script requires elevated privileges. Please run it with 'sudo'.")
        sys.exit(1)
        
# Get the path of the project's root directory
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Add the root directory to the module search path
sys.path.insert(0, root_dir)

# Define the path to the tests folder
tests_folder = os.path.join(root_dir, 'tests')

# Define the path to the bins folder
binary_folder = os.path.join(root_dir, 'bin')

# Define the path to the bins folder
config_folder = os.path.join(root_dir, 'config_files')

try:
    # Get the list of test files
    test_files = [file for file in os.listdir(tests_folder) if file.endswith('.py')]
    
    # Sort the test files alphabetically
    test_files = sorted(test_files, key=natural_sort_key)

    # Check if the user didn't specify any arguments and display help message
    if len(sys.argv) == 1:
        print("Usage: python run.py [OPTIONS]")
        print("Use '-h' or '--help' for more information.")
        sys.exit(0)

    # Create an ArgumentParser object to handle command-line arguments
    parser = argparse.ArgumentParser(description="Run tests with optional filters.")
    parser.add_argument("--all", action="store_true", help="Run all tests. Default false") # sett to True if passed via command line or False
    parser.add_argument("--test_file", type=str, help="Run a specific test by file name.") # set to test file name if passed via command line or None
    parser.add_argument("--all_enable", action="store_true", help="Run all tests regardless of 'isEnabled' function.")
    parser.add_argument("--test_file_enable", type=str, help="Run a specific file by name regardless of 'isEnabled' function. Default false") # sett to True if passed via command line or False
    parser.add_argument("--copy_config_to_active", action="store_true", help="Copies all the test configs to active installation dir. Default true") # sett to False if passed via command line or True
    parser.add_argument("--copy_services_to_active", action="store_true", help="Copies lom binaries to active installation dir. Default true") # sett to False if passed via command line or True
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    args = parser.parse_args()
    print(args)
    
    # copies all the test configs to active dir
    if args.copy_config_to_active :
        dest_config_dir = os.path.join(api.ACTIVE_INSTALLER_DIR, 'config')
        for filename in [api.GLOBALS_CONFIG_FILE, api.BINDINGS_CONFIG_FILE, api.ACTIONS_CONFIG_FILE, api.PROCS_CONFIG_FILE] :
            if not api.copy_file(config_folder, dest_config_dir, filename) :
                sys.exit(1)

    # To-Do : Goutham : Add lom gnmi server 
    # copies engine & plugin mgr binaries to active dir
    if args.copy_services_to_active:
        dest_config_dir = os.path.join(api.ACTIVE_INSTALLER_DIR, 'install', 'bin')
        for filename in [api.LOM_ENGINE_PROCESS_NAME, api.LOM_PLUGIN_MGR_PROCESS_NAME]:
            if not api.copy_file(binary_folder, dest_config_dir, filename):
                sys.exit(1)

    # List to store test details for summary
    test_summary = []
    
    count = 0
    total_execution_time = 0 

    # Iterate over the test files and execute the run_test() function
    for test_file in test_files:
        test_module_name = test_file.replace(".py", "")
        test_module_path = os.path.join(tests_folder, test_file)
        
        test_result = "N/A"
        execution_time = 0
        result = 0
        is_mandatory = False
        test_name = "N/A"
        start_time = 0
        end_time = 0
        
        try:
            # Load the test module dynamically
            test_module = imp.load_source(test_module_name, test_module_path)
    
            # Get the run_test() and isMandatory() functions from the test module
            run_test_function = getattr(test_module, 'run_test', None)
            is_mandatory_function = getattr(test_module, 'isMandatoryPass', None)
            is_enable_function = getattr(test_module, 'isEnabled', None)
            get_test_name_function = getattr(test_module, 'getTestName', None)

            # Check if the run_test() and isMandatory() functions exist in the test module
            if callable(run_test_function) and callable(is_mandatory_function) and callable(is_enable_function) and callable(get_test_name_function):
                print("=========================================================================================")
                print("Running test from {}".format(test_file))
                test_name = test_module.getTestName()
                print("Test Name: {}\n\n".format(test_name))

                # Check if the test should be executed based on command-line arguments
                should_run_test = False
                if args.all_enable or (args.test_file_enable and args.test_file_enable.replace(".py", "") == test_module_name):
                    should_run_test = True
                elif args.all or (args.test_file and args.test_file.replace(".py", "") == test_module_name):
                    if not is_enable_function():
                        print("Test is disabled. Skip running.")
                        test_result = "Disabled"
                        print("=========================================================================================")
                    else:
                        should_run_test = True               

                if should_run_test:
                    # Measure test execution time
                    start_time = time.time()
                    result = run_test_function()    
                    end_time = time.time()                
                    
                    if result == 0:
                        print("\nTest {} passed.".format(test_name))
                        test_result = "Passed"
                    else:
                        print("\nTest {} failed.".format(test_name))
                        test_result = "Failed"
                        is_mandatory = is_mandatory_function()
                        if is_mandatory:
                            print("Passing this Test is mandatory. Stopping the execution sequence.")
                    print("Test execution time: {:.2f} seconds".format(end_time - start_time))
                    print("=========================================================================================")                
            else:
                print("No run_test() or isMandatory() function found in {}".format(test_file))
        except Exception as e:
            print("Error occurred while loading {}: {}".format(test_file, str(e)))
            test_result = "Error"
            print("=========================================================================================")

        # Calculate test execution time        
        execution_time = end_time - start_time
        total_execution_time += execution_time

         # Add test details to the summary list
        count += 1
        test_summary.append((count, test_name, test_result, "{:.2f} seconds".format(execution_time), test_file))                 

        # Print test summary in a tabular format
        print("\n\n=================================== Test Summary ===================================")
        headers = ["No", "Test Name", "Result", "Execution Time", "Test File"]
        print_table(headers, test_summary)
        minutes, seconds = divmod(total_execution_time, 60)
        print("Total Execution Time for All Tests: {:.0f} min {:.2f} sec".format(minutes, seconds))
        print("===================================================================================\n\n")

        # Stop the execution sequence if the test is mandatory and failed
        if result != 0 and is_mandatory:
            break    

except FileNotFoundError:
    print("Tests folder not found: {}".format(tests_folder))
    sys.exit(1)

# Exit with success code
sys.exit(0)


