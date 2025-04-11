"""
Windows VMware Dynamic Analysis Integration
------------------------------------------
This integration allows for automated dynamic analysis of samples in isolated VMware virtual machines.
Specifically optimized for Windows VMs for malware analysis.
"""

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

# Configure logging with more verbose output
logging.basicConfig(
    level=logging.DEBUG,  # Changed from INFO to DEBUG for more detailed logging
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
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
    
    def _run_vmrun(self, command: str, *args) -> Tuple[int, str, str]:
        """
        Run vmrun with the given command and arguments
        
        Args:
            command: VMware command to run
            args: Additional arguments for the command
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        cmd = [self.vmrun_path, "-T", "ws", command, self.vm_path, *args]
        logger.debug(f"Executing VMware command: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        
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
    
    def revert_to_snapshot(self) -> bool:
        """Revert VM to clean snapshot"""
        logger.info(f"Reverting VM to snapshot: {self.snapshot_name}")
        returncode, stdout, stderr = self._run_vmrun("revertToSnapshot", self.snapshot_name)
        if returncode == 0:
            logger.info("Successfully reverted to snapshot")
        else:
            logger.error(f"Failed to revert to snapshot: {stderr}")
        return returncode == 0
        
    def start(self) -> bool:
        """Start the virtual machine"""
        logger.info("Starting VM")
        returncode, stdout, stderr = self._run_vmrun("start")
        
        if returncode == 0:
            logger.info("VM start command issued successfully")
            logger.info("Waiting 60 seconds for VM to fully boot...")
            # Wait for VM to fully boot up
            time.sleep(60)  # Windows may need more time to boot
            logger.info("Wait completed, VM should be ready")
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


class WindowsDynamicAnalyzer:
    """Orchestrates dynamic analysis in a Windows VM sandbox"""
    
    def __init__(self, vm_controller: VMwareController, analysis_dir: str):
        """
        Initialize the dynamic analyzer
        
        Args:
            vm_controller: VMware controller instance
            analysis_dir: Directory to store analysis results
        """
        self.vm = vm_controller
        self.analysis_dir = Path(analysis_dir)
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        self.current_analysis_id = None
        
        # Guest paths (Windows-specific)
        self.guest_working_dir = "C:\\Analysis"
        self.guest_tools_dir = "C:\\opt\\analysis_tools"
        
        # Host monitoring tools
        self.monitoring_processes = []
        
        logger.info(f"Dynamic analyzer initialized with output dir: {analysis_dir}")
        
    def _prepare_analysis_directory(self, sample_name: str) -> str:
        """
        Create a directory for this analysis run
        
        Args:
            sample_name: Name of the sample being analyzed
            
        Returns:
            Path to analysis directory
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        analysis_id = f"{sample_name}_{timestamp}"
        self.current_analysis_id = analysis_id
        
        analysis_path = self.analysis_dir / analysis_id
        logger.info(f"Creating analysis directory: {analysis_path}")
        analysis_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        logger.debug("Creating analysis subdirectories")
        for subdir in ["network", "memory", "filesystem", "screenshots", "logs", "registry"]:
            subdir_path = analysis_path / subdir
            subdir_path.mkdir(exist_ok=True)
            logger.debug(f"Created subdirectory: {subdir_path}")
        
        logger.info(f"Analysis directory prepared: {analysis_path}")
        return str(analysis_path)
        
    def _prepare_guest_environment(self) -> bool:
        """
        Prepare guest VM environment for analysis
        
        Returns:
            True if successful
        """
        logger.info("Preparing guest environment")
        
        # Ensure working directory exists
        logger.debug(f"Creating working directory: {self.guest_working_dir}")
        ret, output = self.vm.run_command(f"mkdir {self.guest_working_dir}")
        if ret != 0 and "already exists" not in output.lower():
            logger.warning(f"Failed to create working directory: {output}")
        
        logger.info("Configuring guest security settings")
        
        # Disable Windows Defender 
        logger.debug("Disabling Windows Defender")
        ret, output = self.vm.run_powershell("Set-MpPreference -DisableRealtimeMonitoring $true")
        if ret != 0:
            logger.warning(f"Failed to disable Windows Defender: {output}")
        
        # Disable Windows Update
        logger.debug("Disabling Windows Update")
        ret, output = self.vm.run_powershell("Stop-Service wuauserv")
        if ret != 0:
            logger.warning(f"Failed to stop Windows Update service: {output}")
            
        ret, output = self.vm.run_powershell("Set-Service wuauserv -StartupType Disabled")
        if ret != 0:
            logger.warning(f"Failed to disable Windows Update startup: {output}")
        
        # Disable Windows Firewall
        logger.debug("Disabling Windows Firewall")
        ret, output = self.vm.run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False")
        if ret != 0:
            logger.warning(f"Failed to disable Windows Firewall: {output}")
        
        logger.info("Guest environment preparation complete")
        return True
        
    def _start_monitoring(self, analysis_dir: str) -> bool:
        """
        Start monitoring tools inside the VM
        
        Args:
            analysis_dir: Path to analysis directory
            
        Returns:
            True if successful
        """
        logger.info("Starting monitoring tools in guest VM")
        
        # Start network capture using PowerShell and netsh
        logger.debug("Starting network capture")
        ret, output = self.vm.run_powershell(
            f"netsh trace start capture=yes tracefile={self.guest_working_dir}\\network.etl"
        )
        if ret != 0:
            logger.warning(f"Failed to start network capture: {output}")
        
        # Start Procmon
        logger.debug("Starting Process Monitor")
        procmon_path = f"{self.guest_tools_dir}\\Procmon.exe"
        procmon_log = f"{self.guest_working_dir}\\procmon.pml"
        
        # First check if Procmon exists
        ret, output = self.vm.run_command(f"if exist {procmon_path} echo FOUND")
        if "FOUND" not in output:
            logger.warning(f"Procmon not found at {procmon_path}")
        else:
            ret, output = self.vm.run_command(
                f"start /B {procmon_path} /Quiet /Minimized /BackingFile {procmon_log}"
            )
            if ret != 0:
                logger.warning(f"Failed to start Procmon: {output}")
        
        # Start registry monitoring
        logger.debug("Taking registry snapshot (before)")
        ret, output = self.vm.run_powershell(
            f"reg export HKLM {self.guest_working_dir}\\reg_before_HKLM.reg /y"
        )
        if ret != 0:
            logger.warning(f"Failed to export HKLM registry: {output}")
            
        ret, output = self.vm.run_powershell(
            f"reg export HKCU {self.guest_working_dir}\\reg_before_HKCU.reg /y"
        )
        if ret != 0:
            logger.warning(f"Failed to export HKCU registry: {output}")
        
        # Capture pre-run memory snapshot
        logger.debug("Taking process snapshot (before)")
        ret, output = self.vm.run_powershell(
            f"tasklist /v > {self.guest_working_dir}\\memory_before.txt"
        )
        if ret != 0:
            logger.warning(f"Failed to capture process list: {output}")
        
        logger.info("All monitoring tools started")
        return True
        
    def _execute_sample(self, guest_sample_path: str, arguments: str = "") -> int:
        """
        Execute the sample in the guest VM
        
        Args:
            guest_sample_path: Path to sample in guest VM
            arguments: Command line arguments for the sample
            
        Returns:
            Return code from sample execution
        """
        logger.info(f"Executing sample: {guest_sample_path} {arguments}")
        
        # Check if sample exists in guest
        ret, output = self.vm.run_command(f"if exist {guest_sample_path} echo FOUND")
        if "FOUND" not in output:
            logger.error(f"Sample not found in guest VM: {guest_sample_path}")
            return 1
        
        # Take pre-execution screenshot
        screenshot_path = f"{self.analysis_dir}/{self.current_analysis_id}/screenshots/pre_exec.png"
        logger.debug(f"Taking pre-execution screenshot: {screenshot_path}")
        self.vm.capture_screenshot(screenshot_path)
        
        # Execute the sample
        logger.debug(f"Executing command: start /B {guest_sample_path} {arguments}")
        command = f"start /B {guest_sample_path} {arguments}"
        returncode, output = self.vm.run_command(command)
        
        if returncode == 0:
            logger.info("Sample execution started successfully")
        else:
            logger.error(f"Failed to execute sample: {output}")
        
        # Give the sample time to execute and perform actions
        logger.info("Waiting 120 seconds for sample execution...")
        time.sleep(120)  # Adjust based on expected sample runtime
        logger.info("Wait completed")
        
        # Take post-execution screenshot
        screenshot_path = f"{self.analysis_dir}/{self.current_analysis_id}/screenshots/post_exec.png"
        logger.debug(f"Taking post-execution screenshot: {screenshot_path}")
        self.vm.capture_screenshot(screenshot_path)
        
        return returncode
        
    def _stop_monitoring(self) -> None:
        """Stop all monitoring processes"""
        logger.info("Stopping monitoring tools")
        
        # Stop network tracing
        logger.debug("Stopping network trace")
        ret, output = self.vm.run_powershell("netsh trace stop")
        if ret != 0:
            logger.warning(f"Failed to stop network trace: {output}")
        
        # Stop Procmon
        logger.debug("Stopping Process Monitor")
        procmon_path = f"{self.guest_tools_dir}\\Procmon.exe"
        ret, output = self.vm.run_command(f"if exist {procmon_path} echo FOUND")
        if "FOUND" in output:
            ret, output = self.vm.run_command(f"{procmon_path} /Terminate")
            if ret != 0:
                logger.warning(f"Failed to terminate Procmon: {output}")
        
        # Take post-run registry snapshot
        logger.debug("Taking registry snapshot (after)")
        ret, output = self.vm.run_powershell(
            f"reg export HKLM {self.guest_working_dir}\\reg_after_HKLM.reg /y"
        )
        if ret != 0:
            logger.warning(f"Failed to export HKLM registry: {output}")
            
        ret, output = self.vm.run_powershell(
            f"reg export HKCU {self.guest_working_dir}\\reg_after_HKCU.reg /y"
        )
        if ret != 0:
            logger.warning(f"Failed to export HKCU registry: {output}")
        
        # Capture post-run memory snapshot
        logger.debug("Taking process snapshot (after)")
        ret, output = self.vm.run_powershell(
            f"tasklist /v > {self.guest_working_dir}\\memory_after.txt"
        )
        if ret != 0:
            logger.warning(f"Failed to capture process list: {output}")
        
        logger.info("All monitoring tools stopped")
            
    def _collect_artifacts(self, analysis_dir: str) -> bool:
        """
        Collect analysis artifacts from the guest VM
        
        Args:
            analysis_dir: Path to analysis directory
            
        Returns:
            True if successful
        """
        logger.info("Collecting artifacts from guest VM")
        success = True
        
        # Collect network capture
        logger.debug("Collecting network capture")
        if not self.vm.copy_file_from_guest(
            f"{self.guest_working_dir}\\network.etl",
            f"{analysis_dir}/network/capture.etl"
        ):
            logger.warning("Failed to copy network.etl file")
            success = False
        
        # Convert ETL to PCAP if available in guest
        logger.debug("Attempting to convert ETL to PCAPNG")
        self.vm.run_powershell(
            f"if (Test-Path 'C:\\Program Files\\Wireshark\\etl2pcapng.exe') {{ " +
            f"& 'C:\\Program Files\\Wireshark\\etl2pcapng.exe' '{self.guest_working_dir}\\network.etl' " +
            f"'{self.guest_working_dir}\\network.pcapng' }}"
        )
        
        # Copy PCAP if it was created
        logger.debug("Collecting PCAPNG file if available")
        ret, output = self.vm.run_command(f"if exist {self.guest_working_dir}\\network.pcapng echo FOUND")
        if "FOUND" in output:
            if not self.vm.copy_file_from_guest(
                f"{self.guest_working_dir}\\network.pcapng",
                f"{analysis_dir}/network/capture.pcapng"
            ):
                logger.warning("Failed to copy network.pcapng file")
        else:
            logger.debug("No PCAPNG file was created")
        
        # Collect Procmon logs
        logger.debug("Collecting Procmon logs")
        ret, output = self.vm.run_command(f"if exist {self.guest_working_dir}\\procmon.pml echo FOUND")
        if "FOUND" in output:
            if not self.vm.copy_file_from_guest(
                f"{self.guest_working_dir}\\procmon.pml",
                f"{analysis_dir}/logs/procmon.pml"
            ):
                logger.warning("Failed to copy procmon.pml file")
                success = False
        else:
            logger.warning("Procmon log file not found")
        
        # Collect registry snapshots
        logger.debug("Collecting registry snapshots")
        for reg_file in ["reg_before_HKLM.reg", "reg_before_HKCU.reg", 
                          "reg_after_HKLM.reg", "reg_after_HKCU.reg"]:
            ret, output = self.vm.run_command(f"if exist {self.guest_working_dir}\\{reg_file} echo FOUND")
            if "FOUND" in output:
                if not self.vm.copy_file_from_guest(
                    f"{self.guest_working_dir}\\{reg_file}",
                    f"{analysis_dir}/registry/{reg_file}"
                ):
                    logger.warning(f"Failed to copy {reg_file} file")
                    success = False
            else:
                logger.warning(f"Registry file not found: {reg_file}")
        
        # Collect memory info
        logger.debug("Collecting memory snapshots")
        for mem_file in ["memory_before.txt", "memory_after.txt"]:
            ret, output = self.vm.run_command(f"if exist {self.guest_working_dir}\\{mem_file} echo FOUND")
            if "FOUND" in output:
                if not self.vm.copy_file_from_guest(
                    f"{self.guest_working_dir}\\{mem_file}",
                    f"{analysis_dir}/memory/{mem_file}"
                ):
                    logger.warning(f"Failed to copy {mem_file} file")
                    success = False
            else:
                logger.warning(f"Memory file not found: {mem_file}")
        
        # Collect Windows event logs
        logger.debug("Collecting Windows event logs")
        for evt_log in ["Application", "Security", "System"]:
            evt_file = f"{evt_log}.evtx"
            logger.debug(f"Exporting {evt_log} event log")
            ret, output = self.vm.run_powershell(
                f"wevtutil epl {evt_log} {self.guest_working_dir}\\{evt_file}"
            )
            if ret != 0:
                logger.warning(f"Failed to export {evt_log} event log: {output}")
                continue
                
            if not self.vm.copy_file_from_guest(
                f"{self.guest_working_dir}\\{evt_file}",
                f"{analysis_dir}/logs/{evt_file}"
            ):
                logger.warning(f"Failed to copy {evt_file} file")
                success = False
        
        logger.info(f"Artifact collection {'completed successfully' if success else 'had some failures'}")
        return success
    
    def _cleanup_guest(self) -> None:
        """Clean up guest VM after analysis"""
        logger.info("Cleaning up guest VM")
        
        # Check if working directory exists before removal
        ret, output = self.vm.run_command(f"if exist {self.guest_working_dir} echo FOUND")
        if "FOUND" in output:
            logger.debug(f"Removing working directory: {self.guest_working_dir}")
            ret, output = self.vm.run_command(f"rmdir /S /Q {self.guest_working_dir}")
            if ret != 0:
                logger.warning(f"Failed to remove working directory: {output}")
        
        # Re-enable Windows Defender (optional)
        logger.debug("Re-enabling Windows Defender")
        ret, output = self.vm.run_powershell("Set-MpPreference -DisableRealtimeMonitoring $false")
        if ret != 0:
            logger.warning(f"Failed to re-enable Windows Defender: {output}")
        
        # Re-enable Windows Firewall (optional)
        logger.debug("Re-enabling Windows Firewall")
        ret, output = self.vm.run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
        if ret != 0:
            logger.warning(f"Failed to re-enable Windows Firewall: {output}")
        
        logger.info("Guest cleanup completed")
        
    def analyze(self, sample_path: str, arguments: str = "") -> str:
        """
        Run complete analysis of a sample
        
        Args:
            sample_path: Path to sample on host
            arguments: Command line arguments for the sample
            
        Returns:
            Path to analysis results directory
        """
        sample_name = os.path.basename(sample_path)
        analysis_dir = self._prepare_analysis_directory(sample_name)
        
        logger.info(f"Starting analysis of sample: {sample_path}")
        
        if not os.path.exists(sample_path):
            logger.error(f"Sample file not found: {sample_path}")
            return analysis_dir
        
        try:
            # Prepare VM: revert to clean snapshot and start
            logger.info("STEP 1: Preparing VM")
            if not self.vm.revert_to_snapshot():
                logger.error("Failed to revert VM to snapshot, aborting analysis")
                return analysis_dir
                
            logger.info("STEP 2: Starting VM")
            if not self.vm.start():
                logger.error("Failed to start VM, aborting analysis")
                return analysis_dir
            
            # Prepare environment
            logger.info("STEP 3: Preparing guest environment")
            self._prepare_guest_environment()
            
            # Copy sample to guest
            logger.info("STEP 4: Copying sample to guest")
            guest_sample_path = f"{self.guest_working_dir}\\{sample_name}"
            if not self.vm.copy_file_to_guest(sample_path, guest_sample_path):
                logger.error("Failed to copy sample to guest, aborting analysis")
                return analysis_dir
            
            # Start monitoring
            logger.info("STEP 5: Starting monitoring tools")
            self._start_monitoring(analysis_dir)
            
            # Execute sample
            logger.info("STEP 6: Executing sample")
            self._execute_sample(guest_sample_path, arguments)
            
            # Stop monitoring
            logger.info("STEP 7: Stopping monitoring tools")
            self._stop_monitoring()
            
            # Collect results
            logger.info("STEP 8: Collecting analysis artifacts")
            self._collect_artifacts(analysis_dir)
            
            # Clean up guest
            logger.info("STEP 9: Cleaning up guest environment")
# Clean up guest
            logger.info("STEP 9: Cleaning up guest environment")
            self._cleanup_guest()
            
        except Exception as e:
            logger.error(f"Analysis failed with exception: {str(e)}")
            logger.error(traceback.format_exc())
            
        finally:
            # Always shut down VM
            logger.info("STEP 10: Shutting down VM")
            vm_stopped = self.vm.stop()
            if not vm_stopped:
                logger.warning("Failed to stop VM gracefully, attempting hard stop")
                self.vm.stop(hard=True)
            
        # Generate report
        logger.info("STEP 11: Generating analysis report")
        self._generate_report(analysis_dir)
        
        logger.info(f"Analysis completed. Results available in: {analysis_dir}")
        return analysis_dir
    
    def _generate_report(self, analysis_dir: str) -> None:
        """
        Generate analysis report
        
        Args:
            analysis_dir: Path to analysis directory
        """
        logger.info("Generating analysis report")
        
        try:
            report = {
                "analysis_id": self.current_analysis_id,
                "timestamp": datetime.now().isoformat(),
                "sample": os.path.basename(analysis_dir),
                "summary": {
                    "network_connections": self._analyze_network_traffic(f"{analysis_dir}/network"),
                    "file_system_changes": self._analyze_filesystem_changes(f"{analysis_dir}/logs/procmon.pml"),
                    "registry_changes": self._analyze_registry_changes(f"{analysis_dir}/registry"),
                    "process_activity": self._analyze_process_activity(f"{analysis_dir}/memory"),
                    "screenshots": os.listdir(f"{analysis_dir}/screenshots"),
                },
                "conclusion": self._draw_conclusions(analysis_dir)
            }
            
            # Write report to JSON file
            report_path = f"{analysis_dir}/report.json"
            logger.info(f"Writing JSON report to {report_path}")
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
                
            # Write HTML report for easier viewing
            html_path = f"{analysis_dir}/report.html"
            logger.info(f"Writing HTML report to {html_path}")
            self._generate_html_report(report, html_path)
            
            logger.info("Report generation completed")
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            logger.error(traceback.format_exc())
    
    # Analysis functions - simplified implementations
    def _analyze_network_traffic(self, network_dir: str) -> List[Dict[str, Any]]:
        """Analyze network traffic from capture files"""
        logger.debug(f"Analyzing network traffic from {network_dir}")
        # This is a simplified placeholder
        # In a real implementation, you'd use a library to parse pcap/etl files
        result = [{"dst_ip": "1.2.3.4", "dst_port": 80, "protocol": "HTTP"}]
        logger.debug(f"Network analysis found {len(result)} connections")
        return result
    
    def _analyze_filesystem_changes(self, procmon_log: str) -> Dict[str, List[str]]:
        """Analyze filesystem changes from procmon log"""
        logger.debug(f"Analyzing filesystem changes from {procmon_log}")
        
        if not os.path.exists(procmon_log):
            logger.warning(f"Procmon log file not found: {procmon_log}")
            return {"created": [], "modified": [], "deleted": []}
            
        # This is a simplified placeholder
        # In a real implementation, you'd parse the PML file
        result = {
            "created": ["C:\\Users\\analyst\\AppData\\Local\\Temp\\malware_dropper.exe"],
            "modified": ["C:\\Windows\\System32\\hosts"],
            "deleted": []
        }
        logger.debug(f"Filesystem analysis found changes: {result}")
        return result
    
    def _analyze_registry_changes(self, registry_dir: str) -> List[Dict[str, Any]]:
        """Compare before/after registry exports to find changes"""
        logger.debug(f"Analyzing registry changes from {registry_dir}")
        
        # Check if registry files exist
        before_files = [os.path.join(registry_dir, f) for f in ["reg_before_HKLM.reg", "reg_before_HKCU.reg"]]
        after_files = [os.path.join(registry_dir, f) for f in ["reg_after_HKLM.reg", "reg_after_HKCU.reg"]]
        
        for f in before_files + after_files:
            if not os.path.exists(f):
                logger.warning(f"Registry file not found: {f}")
        
        # This is a simplified placeholder
        # In a real implementation, you'd parse and compare the registry files
        result = [
            {
                "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "Malware",
                "data": "C:\\malware.exe",
                "change_type": "added"
            }
        ]
        logger.debug(f"Registry analysis found {len(result)} changes")
        return result
    
    def _analyze_process_activity(self, memory_dir: str) -> List[Dict[str, Any]]:
        """Analyze process activity from memory snapshots"""
        logger.debug(f"Analyzing process activity from {memory_dir}")
        
        before_file = os.path.join(memory_dir, "memory_before.txt")
        after_file = os.path.join(memory_dir, "memory_after.txt")
        
        if not os.path.exists(before_file):
            logger.warning(f"Process snapshot before not found: {before_file}")
        if not os.path.exists(after_file):
            logger.warning(f"Process snapshot after not found: {after_file}")
        
        # This is a simplified placeholder
        # In a real implementation, you'd parse and compare the process lists
        result = [
            {
                "process": "malware.exe",
                "pid": 1234,
                "parent_process": "explorer.exe",
                "parent_pid": 4567
            }
        ]
        logger.debug(f"Process analysis found {len(result)} new processes")
        return result
    
    def _draw_conclusions(self, analysis_dir: str) -> Dict[str, Any]:
        """Draw conclusions from analysis artifacts"""
        logger.debug(f"Drawing conclusions from analysis results")
        
        # This is a simplified placeholder
        # In a real implementation, you'd have logic to classify behavior
        result = {
            "threat_level": "high",
            "classification": "trojan",
            "behavior": ["persistence", "data_exfiltration"],
            "ioc": ["1.2.3.4:80", "C:\\malware.exe"]
        }
        logger.debug(f"Analysis conclusion: {result}")
        return result
    
    def _generate_html_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """Generate HTML report from report data"""
        logger.debug(f"Generating HTML report at {output_path}")
        
        # Simplified HTML report generator
        html = f"""
        <html>
        <head>
            <title>Analysis Report: {report_data['sample']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .section {{ margin-bottom: 20px; }}
                .evidence {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; }}
                .high {{ color: red; font-weight: bold; }}
                .medium {{ color: orange; font-weight: bold; }}
                .low {{ color: green; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Analysis Report: {report_data['sample']}</h1>
            <div class="section">
                <h2>Summary</h2>
                <p>Threat Level: <span class="{report_data['conclusion']['threat_level']}">
                    {report_data['conclusion']['threat_level'].upper()}</span></p>
                <p>Classification: {report_data['conclusion']['classification']}</p>
                <p>Behaviors: {', '.join(report_data['conclusion']['behavior'])}</p>
            </div>
            <div class="section">
                <h2>Screenshots</h2>
                <p>See screenshots directory for execution evidence.</p>
            </div>
            <div class="section">
                <h2>Network Activity</h2>
                <table>
                    <tr><th>Destination IP</th><th>Port</th><th>Protocol</th></tr>
                    {''.join(
                        f"<tr><td>{conn['dst_ip']}</td><td>{conn['dst_port']}</td><td>{conn['protocol']}</td></tr>"
                        for conn in report_data['summary']['network_connections']
                    )}
                </table>
            </div>
            <!-- More sections would go here -->
        </body>
        </html>
        """
        
        try:
            with open(output_path, "w") as f:
                f.write(html)
            logger.debug("HTML report generated successfully")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {str(e)}")


def find_vmrun_path():
    """Find the vmrun executable path based on OS"""
    # Common VMware paths
    if os.name == 'nt':  # Windows
        potential_paths = [
            r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
            r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
            r"C:\Program Files (x86)\VMware\VMware Player\vmrun.exe",
            r"C:\Program Files\VMware\VMware Player\vmrun.exe"
        ]
    else:  # Linux/Mac
        potential_paths = [
            "/usr/bin/vmrun",
            "/usr/local/bin/vmrun",
            "/Applications/VMware Fusion.app/Contents/Library/vmrun"
        ]
    
    logger.debug("Searching for vmrun executable")
    for path in potential_paths:
        if os.path.exists(path):
            logger.debug(f"Found vmrun at: {path}")
            return path
    
    logger.warning("Could not find vmrun executable in standard locations")
    return None


def main():
    """Main entry point for the Windows VM analysis tool"""
    parser = argparse.ArgumentParser(description='Windows VMware Dynamic Analysis Tool')
    parser.add_argument('sample', help='Path to sample file to analyze')
    
    # Try to auto-detect vmrun path
    default_vmrun = find_vmrun_path()
    parser.add_argument('--vmrun', default=default_vmrun, 
                       help='Path to vmrun executable')
    
    parser.add_argument('--vm', required=True, help='Path to .vmx file for analysis VM')
    parser.add_argument('--snapshot', default='Clean', help='VM snapshot name to revert to')
    parser.add_argument('--output', default='./analysis_results', help='Output directory for results')
    parser.add_argument('--args', default='', help='Arguments to pass to the sample')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    logger.info(f"Starting Windows VM analysis tool")
    logger.info(f"Sample: {args.sample}")
    logger.info(f"VM Path: {args.vm}")
    logger.info(f"VM Snapshot: {args.snapshot}")
    logger.info(f"Output Directory: {args.output}")
    
    # Validate vmrun path
    if not args.vmrun:
        logger.error("Could not find vmrun executable. Please specify with --vmrun")
        print("ERROR: Could not find vmrun executable. Please specify with --vmrun")
        return 1
    
    if not os.path.exists(args.vmrun):
        logger.error(f"vmrun not found at {args.vmrun}")
        print(f"ERROR: vmrun not found at {args.vmrun}")
        return 1
    
    # Validate sample exists
    if not os.path.exists(args.sample):
        logger.error(f"Sample not found at {args.sample}")
        print(f"ERROR: Sample not found at {args.sample}")
        return 1
    
    # Validate VM path
    if not os.path.exists(args.vm):
        logger.error(f"VM configuration not found at {args.vm}")
        print(f"ERROR: VM configuration not found at {args.vm}")
        return 1
    
    try:
        # Initialize controller and analyzer
        logger.info("Initializing VMware controller")
        vm_controller = VMwareController(args.vmrun, args.vm, args.snapshot)
        
        logger.info("Initializing dynamic analyzer")
        analyzer = WindowsDynamicAnalyzer(vm_controller, args.output)
        
        # Run analysis
        logger.info("Starting analysis")
        results_dir = analyzer.analyze(args.sample, args.args)
        
        print(f"Analysis complete. Results available in: {results_dir}")
        print(f"HTML report: {results_dir}/report.html")
        logger.info(f"Analysis complete. Results in: {results_dir}")
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        print(f"ERROR: Analysis failed: {str(e)}")
        return 1
        
    return 0


if __name__ == "__main__":
    exit(main())