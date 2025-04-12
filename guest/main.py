import socket
import os
import threading
from connection_handler import handle_client
  
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345
SAVE_DIR = os.path.join(os.environ['USERPROFILE'], 'Downloads', 'VMTransfers')

def main():
    os.makedirs(SAVE_DIR, exist_ok=True)

    try:
        # For Windows
        if os.name == 'nt':
            import stat
            os.chmod(SAVE_DIR, stat.S_IRWXU)
    except Exception as e:
        print(f"Warning: Couldn't set permissions on save directory: {e}")
    
    print(f"=== VM File Transfer Listener ===")
    print(f"Saving files to: {SAVE_DIR}")
    
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"Local IP address: {ip_address}")
    except:
        print("Could not determine IP address")
    
    print(f"Loopback address: 127.0.0.1")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            s.bind((HOST, PORT))
            s.listen(5)
            print(f"Listening on {HOST}:{PORT}...")
            
            while True:
                try:
                    conn, addr = s.accept()
                    print(f"New connection from: {addr}")
                    client_thread = threading.Thread(target=handle_client, args=(conn, addr, SAVE_DIR))
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