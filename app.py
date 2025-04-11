

import socket
import os
import time
import base64
import platform
import subprocess
import argparse
import sys

def ping_vm(ip_address):
    """Check if the VM is reachable via ping"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip_address]
    
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        print(f"✓ VM is reachable at {ip_address}")
        return True
    except subprocess.CalledProcessError:
        print(f"✗ Cannot reach VM at {ip_address}. Please check VM connectivity.")
        return False

def test_connection(ip_address, port):
    """Test if the listener is running on the VM"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            print(f"Testing connection to {ip_address}:{port}...")
            s.connect((ip_address, port))
            
            # Send ping message
            s.sendall("PING".encode() + "END_OF_TRANSMISSION".encode())
            
            # Wait for response
            response = s.recv(1024).decode()
            if response.startswith("PONG"):
                print(f"✓ Connection successful! Listener is active.")
                return True
            else:
                print(f"✗ Unexpected response from listener: {response}")
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

def send_file_to_vm(ip_address, port, file_path, execute=False):
    """Send a file to the VM and optionally request execution"""
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
            s.settimeout(30)  # Longer timeout for large files
            print(f"Connecting to {ip_address}:{port}...")
            s.connect((ip_address, port))
            
            # Create a protocol for our file transfer
            # Format: "FILE:<filename>:<base64_content>"
            file_message = f"FILE:{file_name}:{encoded_content.decode()}"
            
            # Send the data with an end marker
            print(f"Sending file '{file_name}' ({len(file_content):,} bytes)...")
            s.sendall((file_message + "END_OF_TRANSMISSION").encode())
            
            # Get response
            response = s.recv(1024).decode()
            if response.startswith("SUCCESS:"):
                print(f"✓ {response[8:]}")  # Remove "SUCCESS:" prefix
                
                # Request execution if specified
                if execute:
                    print("Requesting file execution...")
                    time.sleep(0.5)  # Short delay before sending the next command
                    
                    # Create a new connection for execution
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as exec_socket:
                        exec_socket.settimeout(10)
                        exec_socket.connect((ip_address, port))
                        exec_socket.sendall(f"EXECUTE:{file_name}END_OF_TRANSMISSION".encode())
                        exec_response = exec_socket.recv(1024).decode()
                        
                        if exec_response.startswith("SUCCESS:"):
                            print(f"✓ {exec_response[8:]}")  # Remove "SUCCESS:" prefix
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

def print_firewall_help():
    """Print instructions for setting up the firewall in the guest VM"""
    print("\n=== Firewall Configuration Instructions ===")
    print("In your Windows 11 guest VM, run PowerShell as Administrator and execute:")
    print("\n# Create a new inbound rule to allow the listener port")
    print("New-NetFirewallRule -DisplayName \"VM File Transfer\" -Direction Inbound -Protocol TCP -LocalPort 12345 -Action Allow")
    print("\n# Or to temporarily disable the firewall for testing (not recommended for regular use)")
    print("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False")
    print("\n# Remember to turn it back on when done")
    print("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")

def main():
    parser = argparse.ArgumentParser(description="VMware File Transfer Utility")
    parser.add_argument("--ip", default="192.168.177.128", help="Guest VM IP address")
    parser.add_argument("--port", type=int, default=12345, help="Port number")
    parser.add_argument("--file", help="Path to file for transfer")
    parser.add_argument("--execute", action="store_true", help="Execute file after transfer")
    parser.add_argument("--test", action="store_true", help="Test connectivity only")
    
    args = parser.parse_args()
    
    print("===== VMware Host-to-Guest File Transfer Utility =====")
    
    # If only testing connectivity
    if args.test:
        if ping_vm(args.ip):
            test_connection(args.ip, args.port)
        return
    
    # Require file argument if not just testing
    if not args.file:
        print("Error: Please specify a file to transfer with --file")
        parser.print_help()
        return
    
    # Check VM connectivity
    if not ping_vm(args.ip):
        print_firewall_help()
        return
    
    # Test if listener is active
    if not test_connection(args.ip, args.port):
        print("\nMake sure the listener script is running on the guest VM.")
        print_firewall_help()
        return
    
    # Clean up file path
    file_path = args.file.strip('"')  # Remove quotes if user included them
    
    # Send and optionally execute the file
    send_file_to_vm(args.ip, args.port, file_path, args.execute)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)