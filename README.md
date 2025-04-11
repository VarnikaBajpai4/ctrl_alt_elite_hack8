# Guest-side changes:

file_handler.py:

Add a new function for monitoring execution and collecting results
This function should run the file, capture its behavior/output, and generate a JSON report
The monitoring logic would execute the file while tracking system changes, network activity, or other relevant metrics
Once monitoring is complete, it should save results to a JSON file in a known location


connection_handler.py:

Add a new command handler for "GET_RESULTS" or similar
When this command is received, the handler should:

Locate the results JSON file
Read and encode the file content
Send it back to the host using a format like "RESULTS:{json_data}"


You should implement this in the same area where other commands like "FILE:" and "EXECUTE:" are handled



# Host-side changes:

file_transfer.py:

Add a new function like get_execution_results(ip_address, port, file_name)
This function should:

Connect to the guest VM
Send the "GET_RESULTS" command for the specified file
Receive and decode the JSON response
Save it locally or process it as needed


You might want to add a delay between execution and requesting results


main.py:

Modify the main workflow to include retrieving execution results
Add a prompt asking if the user wants to retrieve execution results
Call the new function from file_transfer.py when appropriate