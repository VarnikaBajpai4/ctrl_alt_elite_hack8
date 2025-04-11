import socket
import platform
import subprocess

def ping_vm(ip_address):
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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            print(f"Testing connection to {ip_address}:{port}...")
            s.connect((ip_address, port))
            
            s.sendall("PING".encode() + "END_OF_TRANSMISSION".encode())
            
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