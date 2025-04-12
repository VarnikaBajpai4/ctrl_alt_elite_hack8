# behavioral_monitor.py - Comprehensive behavioral monitoring
import os
import time
import psutil
import socket
import threading
import winreg
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import json

class FileSystemWatcher(FileSystemEventHandler):
    def __init__(self):
        self.events = []
        
    def on_any_event(self, event):
        # Record file system events
        self.events.append({
            "time": datetime.now().strftime("%H:%M:%S.%f"),
            "type": event.event_type,
            "path": event.src_path,
            "is_directory": event.is_directory if hasattr(event, "is_directory") else False
        })
        
        # If it's a move event, also record destination
        if hasattr(event, "dest_path"):
            self.events[-1]["dest_path"] = event.dest_path

class NetworkMonitor:
    def __init__(self):
        self.connections = []
        self.stop_flag = threading.Event()
        
    def start(self):
        self.thread = threading.Thread(target=self._monitor)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        self.stop_flag.set()
        self.thread.join(timeout=1)
        return self.connections
        
    def _monitor(self):
        last_connections = set()
        
        while not self.stop_flag.is_set():
            current_connections = set()
            
            # Get current connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                    connection_info = (
                        conn.laddr.ip, 
                        conn.laddr.port, 
                        conn.raddr.ip, 
                        conn.raddr.port,
                        conn.status
                    )
                    current_connections.add(connection_info)
                    
                    # If this is a new connection, record it
                    if connection_info not in last_connections:
                        try:
                            remote_host = socket.gethostbyaddr(conn.raddr.ip)[0]
                        except (socket.herror, socket.gaierror):
                            remote_host = "Unknown"
                            
                        self.connections.append({
                            "time": datetime.now().strftime("%H:%M:%S.%f"),
                            "local_ip": conn.laddr.ip,
                            "local_port": conn.laddr.port,
                            "remote_ip": conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                            "remote_host": remote_host,
                            "status": conn.status,
                            "process_id": conn.pid
                        })
            
            last_connections = current_connections
            time.sleep(0.5)

class RegistryMonitor:
    def __init__(self):
        self.changes = []
        self.initial_state = {}
        self.watch_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        ]
        
    def start(self):
        # Skip if not on Windows
        if os.name != 'nt':
            return
            
        # Take initial snapshot
        for hkey, subkey in self.watch_keys:
            try:
                key_dict = {}
                try:
                    key = winreg.OpenKey(hkey, subkey)
                    i = 0
                    while True:
                        try:
                            name, value, type_id = winreg.EnumValue(key, i)
                            key_dict[name] = {"value": value, "type": type_id}
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except WindowsError:
                    pass
                
                self.initial_state[(hkey, subkey)] = key_dict
            except Exception as e:
                print(f"Error reading registry key {subkey}: {str(e)}")
        
        # Start monitoring thread
        self.stop_flag = threading.Event()
        self.thread = threading.Thread(target=self._monitor)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        # Skip if not on Windows
        if os.name != 'nt':
            return self.changes
            
        self.stop_flag.set()
        self.thread.join(timeout=1)
        return self.changes
        
    def _monitor(self):
        while not self.stop_flag.is_set():
            for hkey, subkey in self.watch_keys:
                initial_values = self.initial_state.get((hkey, subkey), {})
                current_values = {}
                
                try:
                    key = winreg.OpenKey(hkey, subkey)
                    i = 0
                    while True:
                        try:
                            name, value, type_id = winreg.EnumValue(key, i)
                            current_values[name] = {"value": value, "type": type_id}
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except WindowsError:
                    continue
                
                # Find added or modified values
                for name, data in current_values.items():
                    if name not in initial_values:
                        self.changes.append({
                            "time": datetime.now().strftime("%H:%M:%S.%f"),
                            "action": "added",
                            "key": subkey,
                            "value_name": name,
                            "value": data["value"],
                            "type": data["type"]
                        })
                    elif initial_values[name] != data:
                        self.changes.append({
                            "time": datetime.now().strftime("%H:%M:%S.%f"),
                            "action": "modified",
                            "key": subkey,
                            "value_name": name,
                            "old_value": initial_values[name]["value"],
                            "new_value": data["value"],
                            "type": data["type"]
                        })
                
                # Find deleted values
                for name in initial_values:
                    if name not in current_values:
                        self.changes.append({
                            "time": datetime.now().strftime("%H:%M:%S.%f"),
                            "action": "deleted",
                            "key": subkey,
                            "value_name": name,
                            "old_value": initial_values[name]["value"],
                            "type": initial_values[name]["type"]
                        })
            
            time.sleep(1)

class ProcessMonitor:
    def __init__(self):
        self.processes = []
        self.process_tree = {}
        self.initial_processes = {}
        
    def start(self):
        # Take snapshot of current processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'ppid']):
            try:
                proc_info = proc.info
                self.initial_processes[proc.pid] = proc_info
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Start monitoring thread
        self.stop_flag = threading.Event()
        self.thread = threading.Thread(target=self._monitor)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        self.stop_flag.set()
        self.thread.join(timeout=1)
        return self.processes
        
    def _monitor(self):
        while not self.stop_flag.is_set():
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'ppid', 'create_time']):
                try:
                    # If this is a new process
                    if proc.pid not in self.initial_processes:
                        proc_info = {
                            "time": datetime.now().strftime("%H:%M:%S.%f"),
                            "pid": proc.pid,
                            "name": proc.info['name'],
                            "username": proc.info['username'],
                            "cmdline": proc.info['cmdline'],
                            "parent_pid": proc.info['ppid'],
                            "create_time": proc.info['create_time']
                        }
                        
                        # Get memory maps and loaded modules
                        try:
                            proc_info["memory_maps"] = [m.path for m in proc.memory_maps(grouped=False)]
                        except:
                            proc_info["memory_maps"] = []
                            
                        # Get open files
                        try:
                            proc_info["open_files"] = [f.path for f in proc.open_files()]
                        except:
                            proc_info["open_files"] = []
                            
                        # Get connections
                        try:
                            proc_info["connections"] = [
                                {
                                    "local_addr": f"{c.laddr.ip}:{c.laddr.port}",
                                    "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                                    "status": c.status
                                }
                                for c in proc.connections()
                            ]
                        except:
                            proc_info["connections"] = []
                            
                        self.processes.append(proc_info)
                        self.initial_processes[proc.pid] = proc_info
                        
                        # Update process tree
                        if proc.info['ppid'] not in self.process_tree:
                            self.process_tree[proc.info['ppid']] = []
                        self.process_tree[proc.info['ppid']].append(proc.pid)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            time.sleep(0.5)

class BehavioralMonitor:
    def __init__(self, temp_dir):
        self.temp_dir = temp_dir
        self.process_monitor = ProcessMonitor()
        self.file_system_watcher = FileSystemWatcher()
        self.registry_monitor = RegistryMonitor() if os.name == 'nt' else None
        self.network_monitor = NetworkMonitor()
        self.observer = None
        
    def start(self):
        # Start process monitoring
        self.process_monitor.start()
        
        # Start file system monitoring
        self.observer = Observer()
        self.observer.schedule(self.file_system_watcher, self.temp_dir, recursive=True)
        self.observer.schedule(self.file_system_watcher, os.environ.get("TEMP", "/tmp"), recursive=True)
        self.observer.schedule(self.file_system_watcher, os.environ.get("SystemRoot", "/"), recursive=False)
        
        # Add more common paths to monitor
        system_paths = []
        if os.name == 'nt':  # Windows
            system_paths = [
                os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32"),
                os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SysWOW64"),
                os.environ.get("APPDATA", "")
            ]
        else:  # Linux/Mac
            system_paths = [
                "/usr/bin",
                "/usr/local/bin",
                "/tmp",
                os.path.join(os.environ.get("HOME", ""), ".config")
            ]
            
        for path in system_paths:
            if os.path.exists(path):
                try:
                    self.observer.schedule(self.file_system_watcher, path, recursive=False)
                except:
                    pass
        
        self.observer.start()
        
        # Start registry monitoring (Windows only)
        if self.registry_monitor:
            self.registry_monitor.start()
            
        # Start network monitoring
        self.network_monitor.start()
        
    def stop(self):
        # Collect all monitoring results
        processes = self.process_monitor.stop()
        file_events = self.file_system_watcher.events
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        registry_changes = []
        if self.registry_monitor:
            registry_changes = self.registry_monitor.stop()
            
        network_connections = self.network_monitor.stop()
        
        # Return all collected data
        return {
            "processes": processes,
            "file_system": file_events,
            "registry": registry_changes,
            "network": network_connections,
            "process_tree": self.process_monitor.process_tree
        }

    def save_to_json(self, file_path):
        """
        Save the behavioral monitoring data to a JSON file.
        
        Args:
            file_path (str): Path where the JSON file should be saved
        """
        data = self.stop()
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Save to JSON file
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)