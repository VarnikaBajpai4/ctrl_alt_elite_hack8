import os
import traceback
from file_handler import save_file, execute_file
from file_analyzer import analyze_file

def handle_client(conn, addr, save_dir):
    print(f"Connected by {addr}")
    
    buffer = b""
    try:
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            buffer += chunk
            
            try:
                message = buffer.decode()
                if "END_OF_TRANSMISSION" in message:
                    message = message.split("END_OF_TRANSMISSION")[0]
                    break
            except UnicodeDecodeError:
                pass
    except Exception as e:
        print(f"Error receiving data: {str(e)}")
    
    if not buffer:
        print("No data received")
        conn.close()
        return
    
    try:
        message = buffer.decode()
        if "END_OF_TRANSMISSION" in message:
            message = message.split("END_OF_TRANSMISSION")[0]
        
        print(f"Received command: {message[:50]}...")
        
        if message.startswith("FILE:"):
            try:
                parts = message.split(":", 2)
                if len(parts) < 3:
                    raise ValueError("Invalid file transfer format")
                
                _, file_name, encoded_content = parts
                
                save_path = save_file(file_name, encoded_content, save_dir)
                if save_path:
                    print(f"File saved successfully to: {save_path}")
                    # Store for later use
                    global last_saved_file, last_saved_path
                    last_saved_file = file_name
                    last_saved_path = save_path
                    
                    response = f"SUCCESS:File received and saved: {file_name}"
                else:
                    response = "ERROR:Failed to save file"
                
                print(f"Sending response: {response}")
                conn.sendall(response.encode())
                
            except Exception as e:
                print(f"Error in FILE command: {str(e)}")
                print(traceback.format_exc())
                response = f"ERROR:Error processing file: {str(e)}"
                conn.sendall(response.encode())
        
        elif message.startswith("EXECUTE:"):
            try:
                _, file_name = message.split(":", 1)
                file_name = file_name.strip()
                
                print(f"Execution request for file: '{file_name}'")
                
                file_path = os.path.join(save_dir, file_name)
                print(f"Looking for file at: {file_path}")
                
                if os.path.exists(file_path):
                    print(f"File found, executing...")
                    # result = execute_file(file_path)
                    result = analyze_file(file_path)
                    response = f"SUCCESS:{result}"
                    print("YOOOOOOOOOOOOOOOOOOOO", response)
                else:
                    print(f"File not found at: {file_path}")
                    # Try using the last saved file as fallback
                    if last_saved_file and last_saved_path and os.path.exists(last_saved_path):
                        print(f"Trying last saved file instead: {last_saved_path}")
                        # result = execute_file(last_saved_path)
                        result = analyze_file(last_saved_path)
                        response = f"SUCCESS:{result} (using last saved file)"
                        print("YOOOOOOOOOOOOOOOOOOOO",response)
                    else:
                        response = f"ERROR:File not found: {file_name}"
                
                print(f"Sending execution response: {response}")
                try:
                    conn.sendall(response.encode())
                except Exception as e:
                    print(f"Error sending execution response: {str(e)}")
            except Exception as e:
                print(f"Error in EXECUTE command: {str(e)}")
                print(traceback.format_exc())
                try:
                    conn.sendall(f"ERROR:Execution error: {str(e)}".encode())
                except:
                    print("Failed to send error response")
        
        elif message.startswith("PING"):
            conn.sendall("PONG:Guest VM listener is active".encode())
        
        else:
            print(f"Unknown command: {message}")
            conn.sendall("ERROR:Unknown command".encode())
            
    except Exception as e:
        print(f"Error handling client: {str(e)}")
        print(traceback.format_exc())
    finally:
        try:
            conn.close()
        except:
            pass

# Global variables to track the last saved file
last_saved_file = None
last_saved_path = None