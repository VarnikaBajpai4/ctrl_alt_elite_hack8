import os
from file_handler import save_file, execute_file

def handle_client(conn, addr, save_dir):
    print(f"Connected by {addr}")
    
    buffer = b""
    while True:
        chunk = conn.recv(8192)
        if not chunk:
            break
        buffer += chunk
        
        try:
            message = buffer.decode()
            if message.endswith("END_OF_TRANSMISSION"):
                message = message[:-len("END_OF_TRANSMISSION")]
                break
        except UnicodeDecodeError:
            pass
    
    if not buffer:
        conn.close()
        return
    
    try:
        message = buffer.decode()
        if "END_OF_TRANSMISSION" in message:
            message = message.split("END_OF_TRANSMISSION")[0]
        
        if message.startswith("FILE:"):
            try:
                parts = message.split(":", 2)
                if len(parts) < 3:
                    raise ValueError("Invalid file transfer format")
                
                _, file_name, encoded_content = parts
                
                save_path = save_file(file_name, encoded_content, save_dir)
                if save_path:
                    response = f"SUCCESS:File received and saved: {file_name}"
                    # Store the file path globally for this module to use
                    global last_saved_file, last_saved_path
                    last_saved_file = file_name
                    last_saved_path = save_path
                else:
                    response = "ERROR:Failed to save file"
                
            except Exception as e:
                response = f"ERROR:Error processing file: {str(e)}"
            
            conn.sendall(response.encode())
        
        elif message.startswith("EXECUTE:"):
            _, file_name = message.split(":", 1)
            file_name = file_name.strip()
            
            print(f"Execution request for file: '{file_name}'")
            
            file_path = os.path.join(save_dir, file_name)
            print(f"Looking for file at: {file_path}")
            
            if os.path.exists(file_path):
                print(f"File found, executing...")
                result = execute_file(file_path)
                conn.sendall(f"SUCCESS:{result}".encode())
            else:
                print(f"File not found at path: {file_path}")
                conn.sendall(f"ERROR:File not found: {file_name}".encode())
        
        elif message.startswith("PING"):
            conn.sendall("PONG:Guest VM listener is active".encode())
        
        else:
            conn.sendall("ERROR:Unknown command".encode())
            
    except Exception as e:
        print(f"Error handling client: {str(e)}")
    finally:
        conn.close()

# Global variables to track the last saved file
last_saved_file = None
last_saved_path = None