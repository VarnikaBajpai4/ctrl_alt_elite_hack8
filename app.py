#!/usr/bin/env python3
"""
VMware Dynamic Analysis Integration
-----------------------------------
This integration allows for automated dynamic analysis of samples in isolated VMware virtual machines.
It handles VM lifecycle management, sample deployment, execution monitoring, and artifact collection.
"""

import os
import time
import json
import logging
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vm-analysis')

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
            raise FileNotFoundError(f"vmrun executable not found at {vmrun_path}")
        
        # Validate VM exists
        if not os.path.exists(vm_path):
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
        logger.debug(f"Running command: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logger.warning(f"vmrun command failed: {stderr}")
        
        return process.returncode, stdout, stderr
    
    def revert_to_snapshot(self) -> bool:
        """Revert VM to clean snapshot"""
        logger.info(f"Reverting VM to snapshot: {self.snapshot_name}")
        returncode, _, stderr = self._run_vmrun("revertToSnapshot", self.snapshot_name)
        return returncode == 0
        
    def start(self) -> bool:
        """Start the virtual machine"""
        logger.info("Starting VM")
        returncode, _, _ = self._run_vmrun("start")
        
        # Wait for VM to fully boot up
        time.sleep(30)  # Adjust based on VM boot time
        return returncode == 0
        
    def stop(self, hard: bool = False) -> bool:
        """
        Stop the virtual machine
        
        Args:
            hard: If True, hard power off; otherwise, attempt graceful shutdown
        """
        command = "stop" if not hard else "stop hard"
        logger.info(f"Stopping VM ({'hard' if hard else 'graceful'})")
        returncode, _, _ = self._run_vmrun(command)
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
        returncode, stdout, stderr = self._run_vmrun("runProgramInGuest", *program_args, 
                                                    "/bin/bash", "-c", command)
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
        returncode, _, _ = self._run_vmrun("copyFileFromHostToGuest", 
                                           "-gu", self.vm_username, 
                                           "-gp", self.vm_password,
                                           local_path, guest_path)
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
        returncode, _, _ = self._run_vmrun("copyFileFromGuestToHost", 
                                          "-gu", self.vm_username, 
                                          "-gp", self.vm_password,
                                          guest_path, local_path)
        return returncode == 0
        
    def list_processes(self) -> List[Dict[str, Any]]:
        """
        List processes running in the guest VM
        
        Returns:
            List of process information dictionaries
        """
        returncode, stdout, _ = self._run_vmrun("listProcessesInGuest",
                                              "-gu", self.vm_username,
                                              "-gp", self.vm_password)
        
        if returncode != 0:
            return []
            
        processes = []
        lines = stdout.strip().split('\n')
        if len(lines) <= 1:  # Header only or empty
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
        returncode, _, _ = self._run_vmrun("captureScreen", output_path)
        return returncode == 0


class DynamicAnalyzer:
    """Orchestrates dynamic analysis in a VM sandbox"""
    
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
        
        # Guest paths
        self.guest_working_dir = "/tmp/analysis"
        self.guest_tools_dir = "/opt/analysis_tools"
        
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
        analysis_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (analysis_path / "network").mkdir()
        (analysis_path / "memory").mkdir()
        (analysis_path / "filesystem").mkdir()
        (analysis_path / "screenshots").mkdir()
        (analysis_path / "logs").mkdir()
        
        return str(analysis_path)
        
    def _prepare_guest_environment(self) -> bool:
        """
        Prepare guest VM environment for analysis
        
        Returns:
            True if successful
        """
        # Ensure working directory exists
        self.vm.run_command(f"mkdir -p {self.guest_working_dir}")
        
        # Copy monitoring tools to guest if needed
        # (In a real implementation, you'd deploy your monitoring tools here)
        
        # Disable Windows Defender (if Windows guest)
        # self.vm.run_command("powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true")
        
        return True
        
    def _start_monitoring(self, analysis_dir: str) -> bool:
        """
        Start monitoring tools inside and outside the VM
        
        Args:
            analysis_dir: Path to analysis directory
            
        Returns:
            True if successful
        """
        # Start network capture (example using tcpdump inside VM)
        self.vm.run_command(
            f"tcpdump -i any -w {self.guest_working_dir}/network.pcap &>/dev/null &"
        )
        
        # Start process monitoring (example using procmon or similar tool)
        self.vm.run_command(
            f"{self.guest_tools_dir}/procmon -o {self.guest_working_dir}/procmon.log &"
        )
        
        # Start memory dumping at intervals (example)
        # self.vm.run_command(
        #     f"bash -c 'while true; do {self.guest_tools_dir}/memdump > "
        #     f"{self.guest_working_dir}/memdump_$(date +%s).raw; sleep 60; done &'"
        # ) 
        
        # Start screenshots at intervals
        screenshot_dir = f"{analysis_dir}/screenshots"
        # Use a separate thread to take screenshots every few seconds
        # (simplified example - real implementation would use threading)
        
        logger.info("Started all monitoring tools")
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
        
        # Make sure sample is executable
        self.vm.run_command(f"chmod +x {guest_sample_path}")
        
        # Take pre-execution screenshot
        self.vm.capture_screenshot(f"{self.analysis_dir}/{self.current_analysis_id}/screenshots/pre_exec.png")
        
        # Execute the sample (non-blocking to allow monitoring to continue)
        command = f"{guest_sample_path} {arguments} &"
        returncode, output = self.vm.run_command(command)
        
        # Give the sample time to start and perform actions
        time.sleep(120)  # Adjust based on expected sample runtime
        
        # Take post-execution screenshot
        self.vm.capture_screenshot(f"{self.analysis_dir}/{self.current_analysis_id}/screenshots/post_exec.png")
        
        return returncode
        
    def _stop_monitoring(self) -> None:
        """Stop all monitoring processes"""
        # Stop tcpdump
        self.vm.run_command("pkill tcpdump")
        
        # Stop process monitor
        self.vm.run_command("pkill -f procmon")
        
        # Stop any other monitoring processes
        for proc_pattern in ["memdump"]:
            self.vm.run_command(f"pkill -f {proc_pattern}")
            
        logger.info("Stopped all monitoring tools")
            
    def _collect_artifacts(self, analysis_dir: str) -> bool:
        """
        Collect analysis artifacts from the guest VM
        
        Args:
            analysis_dir: Path to analysis directory
            
        Returns:
            True if successful
        """
        # Collect network capture
        self.vm.copy_file_from_guest(
            f"{self.guest_working_dir}/network.pcap",
            f"{analysis_dir}/network/capture.pcap"
        )
        
        # Collect process monitoring logs
        self.vm.copy_file_from_guest(
            f"{self.guest_working_dir}/procmon.log",
            f"{analysis_dir}/logs/procmon.log"
        )
        
        # Collect memory dumps
        self.vm.run_command(
            f"find {self.guest_working_dir} -name 'memdump_*.raw' -exec cp {{}} {self.guest_working_dir}/to_extract/ \\;"
        )
        # Then copy directory contents...
        
        # Collect modified files
        # (In a real implementation you'd determine which files were modified)
        
        # Collect system logs
        self.vm.run_command(
            f"cp /var/log/syslog {self.guest_working_dir}/syslog.txt"
        )
        self.vm.copy_file_from_guest(
            f"{self.guest_working_dir}/syslog.txt",
            f"{analysis_dir}/logs/syslog.txt"
        )
        
        logger.info(f"Collected all artifacts to {analysis_dir}")
        return True
    
    def _cleanup_guest(self) -> None:
        """Clean up guest VM after analysis"""
        self.vm.run_command(f"rm -rf {self.guest_working_dir}/*")
        logger.info("Cleaned up guest environment")
        
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
        
        try:
            # Prepare VM: revert to clean snapshot and start
            self.vm.revert_to_snapshot()
            self.vm.start()
            
            # Prepare environment
            self._prepare_guest_environment()
            
            # Copy sample to guest
            guest_sample_path = f"{self.guest_working_dir}/{sample_name}"
            self.vm.copy_file_to_guest(sample_path, guest_sample_path)
            
            # Start monitoring
            self._start_monitoring(analysis_dir)
            
            # Execute sample
            self._execute_sample(guest_sample_path, arguments)
            
            # Stop monitoring
            self._stop_monitoring()
            
            # Collect results
            self._collect_artifacts(analysis_dir)
            
            # Clean up guest
            self._cleanup_guest()
            
        finally:
            # Always shut down VM
            self.vm.stop()
            
        # Generate report
        self._generate_report(analysis_dir)
        
        return analysis_dir
    
    def _generate_report(self, analysis_dir: str) -> None:
        """
        Generate analysis report
        
        Args:
            analysis_dir: Path to analysis directory
        """
        report = {
            "analysis_id": self.current_analysis_id,
            "timestamp": datetime.now().isoformat(),
            "sample": os.path.basename(analysis_dir),
            "summary": {
                "network_connections": self._analyze_network_traffic(f"{analysis_dir}/network/capture.pcap"),
                "created_files": self._find_created_files(f"{analysis_dir}/filesystem"),
                "modified_files": self._find_modified_files(f"{analysis_dir}/filesystem"),
                "registry_changes": self._find_registry_changes(f"{analysis_dir}/logs/procmon.log"),
                "processes": self._analyze_process_activity(f"{analysis_dir}/logs/procmon.log"),
                "screenshots": os.listdir(f"{analysis_dir}/screenshots"),
            },
            "conclusion": self._draw_conclusions(analysis_dir)
        }
        
        # Write report to JSON file
        with open(f"{analysis_dir}/report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Write HTML report for easier viewing
        self._generate_html_report(report, f"{analysis_dir}/report.html")
        
        logger.info(f"Generated analysis report: {analysis_dir}/report.json")
    
    # Simplified implementations of analysis functions
    def _analyze_network_traffic(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Analyze network traffic from pcap file"""
        # In a real implementation, you'd use a library like pyshark or scapy
        return [{"dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "DNS"}]
    
    def _find_created_files(self, filesystem_dir: str) -> List[str]:
        """Find files created by the sample"""
        # Simplified implementation
        return ["C:\\Users\\analyst\\AppData\\Local\\Temp\\malware_dropper.exe"]
    
    def _find_modified_files(self, filesystem_dir: str) -> List[str]:
        """Find files modified by the sample"""
        # Simplified implementation
        return ["C:\\Windows\\System32\\hosts"]
    
    def _find_registry_changes(self, procmon_log: str) -> List[Dict[str, Any]]:
        """Find registry changes made by the sample"""
        # Simplified implementation
        return [{"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                "value": "Malware", "data": "C:\\malware.exe"}]
    
    def _analyze_process_activity(self, procmon_log: str) -> List[Dict[str, Any]]:
        """Analyze process activity"""
        # Simplified implementation
        return [{"process": "malware.exe", "pid": 1234, "parent_pid": 4567}]
    
    def _draw_conclusions(self, analysis_dir: str) -> Dict[str, Any]:
        """Draw conclusions from analysis"""
        # Simplified implementation
        return {
            "threat_level": "high",
            "classification": "trojan",
            "behavior": ["persistence", "data_exfiltration"]
        }
    
    def _generate_html_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """Generate HTML report from report data"""
        # Simplified implementation - in a real system you'd use a template engine
        html = f"""
        <html>
        <head>
            <title>Analysis Report: {report_data['sample']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .section {{ margin-bottom: 20px; }}
                .evidence {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Analysis Report: {report_data['sample']}</h1>
            <div class="section">
                <h2>Summary</h2>
                <p>Threat Level: {report_data['conclusion']['threat_level']}</p>
                <p>Classification: {report_data['conclusion']['classification']}</p>
            </div>
            <!-- More sections would go here -->
        </body>
        </html>
        """
        
        with open(output_path, "w") as f:
            f.write(html)


def main():
    """Main entry point for the VM analysis tool"""
    parser = argparse.ArgumentParser(description='VMware Dynamic Analysis Tool')
    parser.add_argument('sample', help='Path to sample file to analyze')
    parser.add_argument('--vmrun', default='/usr/bin/vmrun', help='Path to vmrun executable')
    parser.add_argument('--vm', required=True, help='Path to .vmx file for analysis VM')
    parser.add_argument('--snapshot', default='Clean', help='VM snapshot name to revert to')
    parser.add_argument('--output', default='./analysis_results', help='Output directory for results')
    parser.add_argument('--args', default='', help='Arguments to pass to the sample')
    
    args = parser.parse_args()
    
    try:
        # Initialize controller and analyzer
        vm_controller = VMwareController(args.vmrun, args.vm, args.snapshot)
        analyzer = DynamicAnalyzer(vm_controller, args.output)
        
        # Run analysis
        results_dir = analyzer.analyze(args.sample, args.args)
        
        print(f"Analysis complete. Results available in: {results_dir}")
        print(f"HTML report: {results_dir}/report.html")
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        return 1
        
    return 0


if __name__ == "__main__":
    exit(main())