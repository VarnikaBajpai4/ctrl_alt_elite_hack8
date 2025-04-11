import socket
import os
import time
import base64

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
            print("1")
            print(response)
            print("2/n")
            if response.startswith("SUCCESS:"):
                print(f"✓ {response[8:]}")
                
                if execute:
                    print("Requesting file execution...")
                    time.sleep(0.5)
                    
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as exec_socket:
                        exec_socket.settimeout(10)
                        exec_socket.connect((ip_address, port))
                        exec_socket.sendall(f"EXECUTE:{file_name}END_OF_TRANSMISSION".encode())
                        exec_response = exec_socket.recv(1024).decode()
                        
                        if exec_response.startswith("SUCCESS:"):
                            print(f"✓ {exec_response[8:]}")
                            return True
                        else:
                            print(f"✗ Execution failed: {exec_response}")
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