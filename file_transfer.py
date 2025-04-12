import socket
import os
import time
import base64
import json
import datetime
import ast  # Add this import for literal_eval

def send_file_to_vm(ip_address, port, file_path, execute=False):
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        return False
    
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        file_name = os.path.basename(file_path)
        
        encoded_content = base64.b64encode(file_content)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            print(f"Connecting to {ip_address}:{port}...")
            s.connect((ip_address, port))
            
            file_message = f"FILE:{file_name}:{encoded_content.decode()}"
            
            print(f"Sending file '{file_name}' ({len(file_content):,} bytes)...")
            s.sendall((file_message + "END_OF_TRANSMISSION").encode())
            
            response = s.recv(1024).decode()
            if response.startswith("SUCCESS:"):
                print(f"✓ {response[8:]}")
                
                if execute:
                    print("Requesting file execution...")
                    time.sleep(1.0)  # Increased delay for local execution
                    
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as exec_socket:
                            exec_socket.settimeout(15)  # Increased timeout
                            exec_socket.connect((ip_address, port))
                            
                            # Simplified message format
                            exec_command = f"EXECUTE:{file_name}END_OF_TRANSMISSION"
                            exec_socket.sendall(exec_command.encode())
                            
                            # More robust response handling
                            try:
                                # Read response in chunks
                                exec_response = b""
                                while True:
                                    chunk = exec_socket.recv(1024)
                                    if not chunk:  # Connection closed
                                        break
                                    exec_response += chunk
                                
                                exec_response = exec_response.decode().strip()
                                
                                # Save the response if it looks like a Python dictionary
                                if exec_response and (exec_response.startswith("SUCCESS:") or exec_response.startswith("{")):
                                    # Extract the dictionary part if it starts with SUCCESS:
                                    if exec_response.startswith("SUCCESS:"):
                                        dict_str = exec_response[8:].strip()
                                    else:
                                        dict_str = exec_response
                                    
                                    try:
                                        # Use ast.literal_eval to safely parse the Python dictionary string
                                        analysis_data = ast.literal_eval(dict_str)
                                        
                                        # Create analysis_results directory if it doesn't exist
                                        os.makedirs("analysis_results", exist_ok=True)
                                        
                                        # Create a filename based on the original file and timestamp
                                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                                        output_filename = f"analysis_results/{os.path.splitext(file_name)[0]}_{timestamp}.json"
                                        
                                        # Save the data to a JSON file
                                        with open(output_filename, 'w', encoding='utf-8') as f:
                                            json.dump(analysis_data, f, indent=4)
                                        print(f"✓ Analysis saved to {output_filename}")
                                    except (SyntaxError, ValueError) as e:
                                        print(f"✗ Could not parse response as Python dictionary: {e}")
                                
                                # Print the response for the user
                                if not exec_response:
                                    print("✓ Execution requested (no detailed response)")
                                    return True
                                elif exec_response.startswith("SUCCESS:"):
                                    print(f"✓ {exec_response[8:]}")
                                    return True
                                else:
                                    print(f"✗ Execution response: {exec_response}")
                                    return False
                            except socket.timeout:
                                # If we time out waiting for response, assume it's running
                                print("✓ Execution requested (response timed out)")
                                return True
                    except Exception as e:
                        print(f"Execution request error: {str(e)}")
                        print("The file was transferred but may not have executed.")
                        return False
                
                return True
            else:
                print(f"✗ File transfer failed: {response}")
                return False
            
    except ConnectionRefusedError:
        print("✗ Connection refused. Make sure the listener is running on the guest VM.")
        return False
    except socket.timeout:
        print("✗ Connection timed out. Check VM connectivity and firewall settings.")
        return False
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return False