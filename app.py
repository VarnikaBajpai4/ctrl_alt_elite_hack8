import socket
import os
import time
import base64
import platform
import subprocess

# Guest VM IP address
VM_IP = "192.168.177.128"
PORT = 12345

def check_vm_connectivity():
    """Check if the VM is reachable via ping"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', VM_IP]
    
    try:
        subprocess.check_output(command)
        print(f"VM is reachable at {VM_IP}")
        return True
    except subprocess.CalledProcessError:
        print(f"Cannot reach VM at {VM_IP}. Please check VM connectivity.")
        return False

def send_file_to_vm(file_path):
    """Send a file to the VM and request execution"""
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        return False
    
    try:
        # Read the file content
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        # Get just the filename
        file_name = os.path.basename(file_path)
        
        # Base64 encode the content (for reliable binary transfer)
        encoded_content = base64.b64encode(file_content)
        
        # Connect to the VM
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            print(f"Connecting to {VM_IP}:{PORT}...")
            s.connect((VM_IP, PORT))
            
            # Create a protocol for our file transfer
            # Format: "FILE:<filename>:<base64_content>"
            file_message = f"FILE:{file_name}:{encoded_content.decode()}"
            
            # Send the data
            print(f"Sending file '{file_name}' ({len(file_content)} bytes)...")
            s.sendall(file_message.encode())
            
            # Get response
            response = s.recv(1024).decode()
            print(f"Response from VM: {response}")
            
            # Request execution if transfer was successful
            if "File received" in response:
                print("Requesting file execution...")
                s.sendall(f"EXECUTE:{file_name}".encode())
                exec_response = s.recv(1024).decode()
                print(f"Execution response: {exec_response}")
                
            return "File received" in response
            
    except ConnectionRefusedError:
        print("Connection refused. Make sure the listener is running on the guest VM and the firewall allows the connection.")
        return False
    except socket.timeout:
        print("Connection timed out. Check VM connectivity and firewall settings.")
        return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def main():
    print("===== VMware Guest File Transfer and Execution Tool =====")
    
    # Check VM connectivity
    if not check_vm_connectivity():
        print("\nFirewall troubleshooting instructions:")
        print("1. In the guest VM, open Windows Defender Firewall with Advanced Security")
        print("2. Select 'Inbound Rules' from the left panel")
        print("3. Click 'New Rule...' from the right panel")
        print("4. Choose 'Port' and click Next")
        print("5. Select 'TCP' and specify port '12345', then click Next")
        print("6. Select 'Allow the connection' and click Next")
        print("7. Check all profiles (Domain, Private, Public) and click Next")
        print("8. Give the rule a name (e.g., 'VM File Transfer') and click Finish")
        print("\nAlternatively, you can temporarily disable the firewall for testing:")
        print("1. Open Command Prompt as Administrator in the guest VM")
        print("2. Run: netsh advfirewall set allprofiles state off")
        print("3. Remember to turn it back on when done: netsh advfirewall set allprofiles state on")
        return
    
    # Get file path from user
    file_path = input("\nEnter the path of the file you want to transfer and execute: ")
    file_path = file_path.strip('"')  # Remove quotes if user included them
    
    print("\nBefore sending the file, you need to run the listener script on the guest VM.")
    print("Copy and run this Python script on the Windows 11 guest VM:")
    print("""
import socket
import base64
import os
import subprocess
import sys

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345      # Port to listen on

def save_and_execute_file(file_name, encoded_content):
    try:
        # Decode the base64 content
        file_content = base64.b64decode(encoded_content)
        
        # Save the file to the guest's temp directory
        save_path = os.path.join(os.environ['TEMP'], file_name)
        with open(save_path, 'wb') as f:
            f.write(file_content)
        
        print(f"File saved to: {save_path}")
        return save_path
    except Exception as e:
        print(f"Error saving file: {str(e)}")
        return None

def execute_file(file_path):
    try:
        # Get file extension
        _, ext = os.path.splitext(file_path)
        
        if ext.lower() in ['.exe', '.bat', '.cmd']:
            # Run executable files
            process = subprocess.Popen(file_path, shell=True)
            return f"Executing {os.path.basename(file_path)} with PID: {process.pid}"
        elif ext.lower() == '.py':
            # Run Python scripts
            process = subprocess.Popen([sys.executable, file_path], shell=True)
            return f"Executing Python script with PID: {process.pid}"
        elif ext.lower() in ['.ps1']:
            # Run PowerShell scripts
            process = subprocess.Popen(['powershell', '-ExecutionPolicy', 'Bypass', '-File', file_path], shell=True)
            return f"Executing PowerShell script with PID: {process.pid}"
        else:
            # For other files, open with default application
            os.startfile(file_path)
            return f"Opening {os.path.basename(file_path)} with default application"
    except Exception as e:
        return f"Error executing file: {str(e)}"

# Store received files for later execution
received_files = {}

# Start listening
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on port {PORT}...")
    
    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024*1024)  # Increase buffer size for larger files
            
            if not data:
                break
                
            message = data.decode()
            
            # Handle file transfer
            if message.startswith("FILE:"):
                try:
                    # Parse the message
                    _, file_name, encoded_content = message.split(":", 2)
                    
                    # Save the file
                    save_path = save_and_execute_file(file_name, encoded_content)
                    if save_path:
                        received_files[file_name] = save_path
                        response = f"File received and saved: {file_name}"
                    else:
                        response = "Error saving file"
                    
                except Exception as e:
                    response = f"Error processing file: {str(e)}"
                
                conn.sendall(response.encode())
            
            # Handle execution request
            elif message.startswith("EXECUTE:"):
                _, file_name = message.split(":", 1)
                
                if file_name in received_files:
                    result = execute_file(received_files[file_name])
                    conn.sendall(f"Execution initiated: {result}".encode())
                else:
                    conn.sendall(f"File not found: {file_name}".encode())
            
            # Handle regular messages
            else:
                print(f"Received: {message}")
                response = "Message received by guest VM"
                conn.sendall(response.encode())
    """)
    
    input("\nPress Enter when the listener is running on the guest VM...")
    
    # Send and execute the file
    send_file_to_vm(file_path)

if __name__ == "__main__":
    main()