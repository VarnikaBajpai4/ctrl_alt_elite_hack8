#this is supposed to be running on the guest machine


import socket
import base64
import os
import subprocess
import sys
import threading

# Configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345      # Port to listen on
SAVE_DIR = os.path.join(os.environ['USERPROFILE'], 'Downloads', 'VMTransfers')

# Create save directory if it doesn't exist
os.makedirs(SAVE_DIR, exist_ok=True)

def save_file(file_name, encoded_content):
    """Save received file to the designated directory"""
    try:
        # Decode the base64 content
        file_content = base64.b64decode(encoded_content)
        
        # Save the file
        save_path = os.path.join(SAVE_DIR, file_name)
        with open(save_path, 'wb') as f:
            f.write(file_content)
        
        print(f"File saved to: {save_path}")
        return save_path
    except Exception as e:
        print(f"Error saving file: {str(e)}")
        return None

def execute_file(file_path):
    """Execute the received file based on its extension"""
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

def handle_client(conn, addr):
    """Handle individual client connections"""
    print(f"Connected by {addr}")
    
    # Receive data in chunks for larger files
    buffer = b""
    while True:
        chunk = conn.recv(8192)  # 8KB chunks
        if not chunk:
            break
        buffer += chunk
        
        # Check if we received the entire message
        try:
            # Try to decode to see if we have a complete message
            message = buffer.decode()
            if message.endswith("END_OF_TRANSMISSION"):
                # Remove the transmission marker
                message = message[:-len("END_OF_TRANSMISSION")]
                break
        except UnicodeDecodeError:
            # Not a complete message yet, continue receiving
            pass
    
    if not buffer:
        conn.close()
        return
    
    try:
        message = buffer.decode()
        
        # Handle file transfer
        if message.startswith("FILE:"):
            try:
                # Parse the message (format: "FILE:<filename>:<base64_content>")
                parts = message.split(":", 2)
                if len(parts) < 3:
                    raise ValueError("Invalid file transfer format")
                
                _, file_name, encoded_content = parts
                
                # Save the file
                save_path = save_file(file_name, encoded_content)
                if save_path:
                    response = f"SUCCESS:File received and saved: {file_name}"
                    # Store the file path for potential execution
                    conn.file_path = save_path
                else:
                    response = "ERROR:Failed to save file"
                
            except Exception as e:
                response = f"ERROR:Error processing file: {str(e)}"
            
            conn.sendall(response.encode())
        
        # Handle execution request
        elif message.startswith("EXECUTE:"):
            _, file_name = message.split(":", 1)
            
            # Look for the file in our save directory
            file_path = os.path.join(SAVE_DIR, file_name)
            
            if os.path.exists(file_path):
                result = execute_file(file_path)
                conn.sendall(f"SUCCESS:{result}".encode())
            else:
                conn.sendall(f"ERROR:File not found: {file_name}".encode())
        
        # Handle simple ping message
        elif message.startswith("PING"):
            conn.sendall("PONG:Guest VM listener is active".encode())
        
        # Handle unknown commands
        else:
            conn.sendall("ERROR:Unknown command".encode())
            
    except Exception as e:
        print(f"Error handling client: {str(e)}")
    finally:
        conn.close()

def main():
    print(f"=== VM File Transfer Listener ===")
    print(f"Saving files to: {SAVE_DIR}")
    
    # Get IP address for display purposes
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    
    # Start server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow reuse of the address
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            s.bind((HOST, PORT))
            s.listen(5)  # Queue up to 5 connection requests
            print(f"Listening on {ip_address}:{PORT}...")
            
            # Accept connections in a loop
            while True:
                try:
                    conn, addr = s.accept()
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    print(f"Error accepting connection: {str(e)}")
        except Exception as e:
            print(f"Server error: {str(e)}")
            if "address already in use" in str(e).lower():
                print("Port is already in use. Make sure no other instance is running.")
            return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down server...")