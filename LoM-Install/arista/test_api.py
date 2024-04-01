'''
This script is used to test the AristaSwitchEAPIHelper claas.  Test must be run manually on a switch.
It tests the following functions:
    1. compare_agent_uptimes
    2. compare_hardware_capacity_utilization
'''



from __future__ import print_function
import arista_eapi_helper
from time import sleep

def test_compare_uptimes():
    switch_eapi = arista_eapi_helper.AristaSwitchEAPIHelper()

    try:
        switch_eapi.connect()
    except Exception as e:
        print("Error: Failed to connect. {}".format(e))
        return

    agent_uptimes_first = switch_eapi.get_agent_uptime_info()
    sleep(1)
    agent_uptimes_second = switch_eapi.get_agent_uptime_info()
    comparison_result, error_output = switch_eapi.compare_agent_uptimes(agent_uptimes_first, agent_uptimes_second)

    if comparison_result:
        print("1. Test compare_uptimes: PASSED")
    else:
        print("1. Test compare_uptimes: FAILED")
        if isinstance(error_output, dict):
            for agent, errors in error_output.items():
                print("Agent: {}".format(agent))
                for error in errors:
                    print("  Error: {}".format(error))
        else:
            print("Unexpected error output: {}".format(error_output))

    # Manipulate agent_uptimes_second for additional tests
    # Change a value
    if 'Stp' in agent_uptimes_second:
        oldValue = agent_uptimes_second['Stp']['AgentStartTime']
        agent_uptimes_second['Stp']['AgentStartTime'] = 0

        comparison_result, error_output = switch_eapi.compare_agent_uptimes(agent_uptimes_first, agent_uptimes_second)

        # comparision must fail
        if comparison_result:
            print("2. Test compare_uptimes: FAILED")
        else:
            print("2. Test compare_uptimes: PASSED")
            if isinstance(error_output, dict):
                for agent, errors in error_output.items():
                    print("Agent: {}".format(agent))
                    for error in errors:
                        print("  Error: {}".format(error))
            else:
                print("Unexpected error output: {}".format(error_output))

            agent_uptimes_second['Stp']['AgentStartTime'] = oldValue

    # Remove a key-value pair
    if 'Lldp' in agent_uptimes_second:
        del agent_uptimes_second['Lldp']

        comparison_result, error_output = switch_eapi.compare_agent_uptimes(agent_uptimes_first, agent_uptimes_second)

        # comparision must fail 
        if comparison_result:
            print("3. Test compare_uptimes: FAILED")
        else:
            print("3. Test compare_uptimes: PASSED")
            if isinstance(error_output, dict):
                for agent, errors in error_output.items():
                    print("Agent: {}".format(agent))
                    for error in errors:
                        print("  Error: {}".format(error))
            else:
                print("Unexpected error output: {}".format(error_output))
    
def test_compare_hardware_capacity_utilization():
    switch_eapi = arista_eapi_helper.AristaSwitchEAPIHelper()

    try:
        switch_eapi.connect()
    except Exception as e:
        print("Error: Failed to connect. {}".format(e))
        return

    tables_output_first = switch_eapi.get_hardware_capacity_utilization(0)
    sleep(1)
    tables_output_second = switch_eapi.get_hardware_capacity_utilization(0)
    comparison_result, error_output = switch_eapi.compare_hardware_capacity_utilization(tables_output_first, tables_output_second, 1)

    if comparison_result:
        print("1. Test compare_hardware_capacity_utilization: PASSED")
    else:
        print("2. Test compare_hardware_capacity_utilization: FAILED")
        if isinstance(error_output, dict):
            for key, errors in error_output.items():
                print("Key: {}".format(key))
                for error in errors:
                    print("  Error: {}".format(error))
        else:
            print("Unexpected error output: {}".format(error_output))

    # Vary the percentage number 
    tables_output_first = switch_eapi.get_hardware_capacity_utilization(0)
    sleep(1)
    tables_output_second = switch_eapi.get_hardware_capacity_utilization(9)
    comparison_result, error_output = switch_eapi.compare_hardware_capacity_utilization(tables_output_first, tables_output_second, 1)
    if comparison_result:
        print("2. Test compare_hardware_capacity_utilization: FAILED")
    else:
        print("2. Test compare_hardware_capacity_utilization: PASSED")
        if isinstance(error_output, dict):
            for key, errors in error_output.items():
                print("Key: {}".format(key))
                for error in errors:
                    print("  Error: {}".format(error))
        else:
            print("Unexpected error output: {}".format(error_output))

    # Vary the percentage number 
    tables_output_first = switch_eapi.get_hardware_capacity_utilization(0)
    sleep(1)
    tables_output_second = switch_eapi.get_hardware_capacity_utilization(100)
    comparison_result, error_output = switch_eapi.compare_hardware_capacity_utilization(tables_output_first, tables_output_second, 1)
    if comparison_result:
        print("3. Test compare_hardware_capacity_utilization: FAILED")
    else:
        print("3. Test compare_hardware_capacity_utilization: PASSED")
        if isinstance(error_output, dict):
            for key, errors in error_output.items():
                print("Key: {}".format(key))
                for error in errors:
                    print("  Error: {}".format(error))
        else:
            print("Unexpected error output: {}".format(error_output))

def run_tests():
    try:
        test_compare_uptimes()
        test_compare_hardware_capacity_utilization()
        # Call more test functions as needed...
    except Exception as e:
        print("An error occurred: {}".format(e))

if __name__ == "__main__":
    run_tests()
