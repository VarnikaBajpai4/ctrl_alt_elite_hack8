import base64
import os
import subprocess
import sys

def save_file(file_name, encoded_content, save_dir):
    try:
        file_content = base64.b64decode(encoded_content)
        
        save_path = os.path.join(save_dir, file_name)
        with open(save_path, 'wb') as f:
            f.write(file_content)
        
        print(f"File saved to: {save_path}")
        return save_path
    except Exception as e:
        print(f"Error saving file: {str(e)}")
        return None

def execute_file(file_path):
    try:
        _, ext = os.path.splitext(file_path)
        
        if ext.lower() in ['.exe', '.bat', '.cmd']:
            process = subprocess.Popen(file_path, shell=True)
            return f"Executing {os.path.basename(file_path)} with PID: {process.pid}"
        elif ext.lower() == '.py':
            process = subprocess.Popen([sys.executable, file_path], shell=True)
            return f"Executing Python script with PID: {process.pid}"
        elif ext.lower() in ['.ps1']:
            process = subprocess.Popen(['powershell', '-ExecutionPolicy', 'Bypass', '-File', file_path], shell=True)
            return f"Executing PowerShell script with PID: {process.pid}"
        else:
            os.startfile(file_path)
            return f"Opening {os.path.basename(file_path)} with default application"
    except Exception as e:
        return f"Error executing file: {str(e)}"