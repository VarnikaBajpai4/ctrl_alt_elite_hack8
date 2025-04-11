import os
import time
import json
import logging
import argparse
import subprocess
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import logging

logger = logging.getLogger('win-vm-analysis')

class VMwareController:
    """Controls VMware VMs using vmrun command-line utility"""
    
    def __init__(self, vmrun_path: str, vm_path: str, snapshot_name: str = "Clean"):
        """
        Initialize VMware controller
        
        Args:
            vmrun_path: Path to vmrun executable
            vm_path: Path to .vmx file for the virtual machine
            snapshot_name: Name of snapshot to revert to before analysis
        """
        self.vmrun_path = vmrun_path
        self.vm_path = vm_path
        self.snapshot_name = snapshot_name
        self.vm_username = "analyst"  # Default credentials for the VM
        self.vm_password = "password"
        
        # Validate vmrun exists
        if not os.path.exists(vmrun_path):
            logger.error(f"vmrun executable not found at {vmrun_path}")
            raise FileNotFoundError(f"vmrun executable not found at {vmrun_path}")
        
        # Validate VM exists
        if not os.path.exists(vm_path):
            logger.error(f"VM configuration not found at {vm_path}")
            raise FileNotFoundError(f"VM configuration not found at {vm_path}")
            
        logger.info(f"Initialized VMware controller for VM: {vm_path}")
    
    def _run_vmrun(self, command: str, *args, timeout=300) -> Tuple[int, str, str]:
        """
        Run vmrun with the given command and arguments
        
        Args:
            command: VMware command to run
            args: Additional arguments for the command
            timeout: Maximum time to wait for command completion (seconds)
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        cmd = [self.vmrun_path, "-T", "ws", command, self.vm_path, *args]
        logger.debug(f"Executing VMware command: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate(timeout=timeout)
            
            # More detailed logging of command results
            if process.returncode == 0:
                logger.debug(f"VMware command successful: {command}")
                if stdout.strip():
                    logger.debug(f"Command output: {stdout.strip()}")
            else:
                logger.warning(f"VMware command failed: {command}")
                logger.warning(f"Return code: {process.returncode}")
                logger.warning(f"Error output: {stderr.strip()}")
                if stdout.strip():
                    logger.warning(f"Standard output: {stdout.strip()}")
            
            return process.returncode, stdout, stderr
            
        except subprocess.TimeoutExpired:
            logger.error(f"VMware command timed out after {timeout} seconds: {command}")
            try:
                process.kill()
            except:
                pass
            return 1, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            logger.error(f"Exception running VMware command: {str(e)}")
            return 1, "", f"Exception: {str(e)}"
    
    def revert_to_snapshot(self) -> bool:
        """Revert VM to clean snapshot"""
        logger.info(f"Reverting VM to snapshot: {self.snapshot_name}")
        
        # First check if VM is registered
        vm_check_code, vm_check_out, vm_check_err = self._run_vmrun("list", timeout=30)
        if vm_check_code != 0:
            logger.error("Failed to list VMs, VMware may not be running properly")
            return False
        
        if self.vm_path not in vm_check_out:
            logger.error(f"VM not found in registered VMs list. Check VM path: {self.vm_path}")
            logger.debug(f"Registered VMs: {vm_check_out}")
            return False
        
        # List available snapshots
        snap_code, snap_out, snap_err = self._run_vmrun("listSnapshots", timeout=30)
        if snap_code != 0:
            logger.error(f"Failed to list snapshots: {snap_err}")
            return False
        
        # Check if our snapshot exists
        if self.snapshot_name not in snap_out:
            logger.error(f"Snapshot '{self.snapshot_name}' not found")
            logger.error(f"Available snapshots: {snap_out}")
            return False
        
        # Try to revert to snapshot with explicit timeout
        returncode, stdout, stderr = self._run_vmrun("revertToSnapshot", self.snapshot_name, timeout=120)
        
        if returncode == 0:
            logger.info("Successfully reverted to snapshot")
        else:
            logger.error(f"Failed to revert to snapshot: {stderr}")
            
            # Check VM state
            state_code, state_out, state_err = self._run_vmrun("getGuestIPAddress", timeout=10)
            if state_code == 0:
                logger.info(f"VM appears to be running with IP: {state_out.strip()}")
            else:
                logger.info("VM does not appear to be running")
                
        return returncode == 0
        
    def start(self) -> bool:
        """Start the virtual machine"""
        logger.info("Starting VM")
        returncode, stdout, stderr = self._run_vmrun("start", timeout=60)
        
        if returncode == 0:
            logger.info("VM start command issued successfully")
            logger.info("Waiting 60 seconds for VM to fully boot...")
            # Wait for VM to fully boot up
            start_time = time.time()
            vm_ready = False
            
            while time.time() - start_time < 120:  # Wait up to 2 minutes
                time.sleep(10)  # Check every 10 seconds
                
                # Try to get VM's IP address as a sign it's running
                ip_code, ip_out, ip_err = self._run_vmrun("getGuestIPAddress", timeout=10)
                if ip_code == 0 and ip_out.strip():
                    logger.info(f"VM is running with IP: {ip_out.strip()}")
                    vm_ready = True
                    break
                
                logger.debug("VM not ready yet, waiting...")
            
            if not vm_ready:
                logger.warning("VM started but may not be fully booted after waiting period")
            
        else:
            logger.error(f"Failed to start VM: {stderr}")
            
        return returncode == 0
        
    def stop(self, hard: bool = False) -> bool:
        """
        Stop the virtual machine
        
        Args:
            hard: If True, hard power off; otherwise, attempt graceful shutdown
        """
        command = "stop" if not hard else "stop hard"
        logger.info(f"Stopping VM ({'hard' if hard else 'graceful'})")
        returncode, stdout, stderr = self._run_vmrun(command)
        
        if returncode == 0:
            logger.info("VM stopped successfully")
        else:
            logger.error(f"Failed to stop VM: {stderr}")
            logger.info("Attempting hard stop...")
            if not hard:
                # Try hard stop if graceful stop failed
                return self.stop(hard=True)
                
        return returncode == 0
    
    def run_command(self, command: str, interactive: bool = False) -> Tuple[int, str]:
        """
        Run a command inside the guest VM
        
        Args:
            command: Command to execute in guest
            interactive: Whether the command is interactive
            
        Returns:
            Tuple of (return_code, command_output)
        """
        program_args = ["-gu", self.vm_username, "-gp", self.vm_password]
        if interactive:
            program_args.append("-interactive")
            
        logger.info(f"Running guest command: {command}")
        
        # Use cmd.exe for Windows commands
        returncode, stdout, stderr = self._run_vmrun("runProgramInGuest", *program_args, 
                                                    "cmd.exe", "/c", command)
        
        if returncode == 0:
            logger.info("Guest command executed successfully")
            if stdout.strip():
                logger.debug(f"Command output: {stdout.strip()}")
        else:
            logger.error(f"Guest command failed: {stderr}")
            
        return returncode, stdout + stderr
    
    def run_powershell(self, ps_command: str, interactive: bool = False) -> Tuple[int, str]:
        """
        Run a PowerShell command inside the guest VM
        
        Args:
            ps_command: PowerShell command to execute
            interactive: Whether the command is interactive
            
        Returns:
            Tuple of (return_code, command_output)
        """
        program_args = ["-gu", self.vm_username, "-gp", self.vm_password]
        if interactive:
            program_args.append("-interactive")
            
        # Escape quotes for PowerShell
        ps_command = ps_command.replace('"', '\\"')
        full_command = f'powershell.exe -ExecutionPolicy Bypass -Command "{ps_command}"'
        
        logger.info(f"Running PowerShell command: {ps_command}")
        returncode, stdout, stderr = self._run_vmrun("runProgramInGuest", *program_args, 
                                                    "cmd.exe", "/c", full_command)
        
        if returncode == 0:
            logger.info("PowerShell command executed successfully")
            if stdout.strip():
                logger.debug(f"Command output: {stdout.strip()}")
        else:
            logger.error(f"PowerShell command failed: {stderr}")
            
        return returncode, stdout + stderr
    
    def copy_file_to_guest(self, local_path: str, guest_path: str) -> bool:
        """
        Copy a file from host to guest VM
        
        Args:
            local_path: Path on host machine
            guest_path: Destination path in guest VM
            
        Returns:
            True if successful
        """
        logger.info(f"Copying file to guest: {local_path} -> {guest_path}")
        
        # Check if source file exists
        if not os.path.exists(local_path):
            logger.error(f"Source file does not exist: {local_path}")
            return False
            
        returncode, stdout, stderr = self._run_vmrun("copyFileFromHostToGuest", 
                                           "-gu", self.vm_username, 
                                           "-gp", self.vm_password,
                                           local_path, guest_path)
                                           
        if returncode == 0:
            logger.info(f"File copied successfully to guest")
        else:
            logger.error(f"Failed to copy file to guest: {stderr}")
            
        return returncode == 0
                                        
    def copy_file_from_guest(self, guest_path: str, local_path: str) -> bool:
        """
        Copy a file from guest VM to host
        
        Args:
            guest_path: Path in guest VM
            local_path: Destination path on host machine
            
        Returns:
            True if successful
        """
        logger.info(f"Copying file from guest: {guest_path} -> {local_path}")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        
        returncode, stdout, stderr = self._run_vmrun("copyFileFromGuestToHost", 
                                          "-gu", self.vm_username, 
                                          "-gp", self.vm_password,
                                          guest_path, local_path)
                                          
        if returncode == 0:
            logger.info(f"File copied successfully from guest")
            if not os.path.exists(local_path):
                logger.warning(f"File copy succeeded but destination file not found: {local_path}")
        else:
            logger.error(f"Failed to copy file from guest: {stderr}")
            
        return returncode == 0
        
    def list_processes(self) -> List[Dict[str, Any]]:
        """
        List processes running in the guest VM
        
        Returns:
            List of process information dictionaries
        """
        logger.info("Listing processes in guest VM")
        returncode, stdout, stderr = self._run_vmrun("listProcessesInGuest",
                                              "-gu", self.vm_username,
                                              "-gp", self.vm_password)
        
        if returncode != 0:
            logger.error(f"Failed to list processes: {stderr}")
            return []
            
        processes = []
        lines = stdout.strip().split('\n')
        if len(lines) <= 1:  # Header only or empty
            logger.warning("No processes returned from VM")
            return []
            
        # Parse process information
        for line in lines[1:]:  # Skip header line
            parts = line.strip().split(':', 1)
            if len(parts) == 2:
                pid, cmd = parts
                processes.append({
                    'pid': pid.strip(),
                    'command': cmd.strip()
                })
                
        logger.info(f"Found {len(processes)} processes in guest VM")
        return processes
        
    def capture_screenshot(self, output_path: str) -> bool:
        """
        Capture screenshot of the VM
        
        Args:
            output_path: Path to save the screenshot
            
        Returns:
            True if successful
        """
        logger.info(f"Capturing VM screenshot to {output_path}")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        returncode, stdout, stderr = self._run_vmrun("captureScreen", output_path)
        
        if returncode == 0:
            logger.info("Screenshot captured successfully")
            if not os.path.exists(output_path):
                logger.warning(f"Screenshot capture succeeded but file not found: {output_path}")
        else:
            logger.error(f"Failed to capture screenshot: {stderr}")
            
        return returncode == 0
