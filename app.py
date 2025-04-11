
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
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
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
        
        try:
            # Add timeout to prevent hanging
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate(timeout=180)  # 3 minute timeout
            
            if process.returncode != 0:
                logger.warning(f"vmrun command failed: {stderr}")
            
            return process.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            logger.error(f"vmrun command timed out after 180 seconds: {' '.join(cmd)}")
            return 1, "", "Command timed out"
    
    def revert_to_snapshot(self) -> bool:
        """Revert VM to clean snapshot"""
        logger.info(f"Reverting VM to snapshot: {self.snapshot_name}")
        returncode, stdout, stderr = self._run_vmrun("revertToSnapshot", self.snapshot_name)
        logger.info(f"Revert result: code={returncode}, stdout={stdout}, stderr={stderr}")
        return returncode == 0
        
    def start(self) -> bool:
        """Start the virtual machine"""
        logger.info("Starting VM")
        returncode, stdout, stderr = self._run_vmrun("start")
        logger.info(f"VM start result: code={returncode}, stdout={stdout}, stderr={stderr}")
        
        # Wait for VM to fully boot up
        logger.info("Waiting 60 seconds for VM to boot...")
        time.sleep(60)  # Windows may need more time to boot
        logger.info("Boot wait completed")
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
        
        # Use cmd.exe for Windows commands
        returncode, stdout, stderr = self._run_vmrun("runProgramInGuest", *program_args, 
                                                    "cmd.exe", "/c", command)
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
        analysis_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (analysis_path / "network").mkdir()
        (analysis_path / "memory").mkdir()
        (analysis_path / "filesystem").mkdir()
        (analysis_path / "screenshots").mkdir()
        (analysis_path / "logs").mkdir()
        (analysis_path / "registry").mkdir()
        
        return str(analysis_path)
        
    def _prepare_guest_environment(self) -> bool:
        """
        Prepare guest VM environment for analysis
        
        Returns:
            True if successful
        """
        # Ensure working directory exists
        self.vm.run_command(f"mkdir {self.guest_working_dir}")
        
        # Disable Windows Defender 
        self.vm.run_powershell("Set-MpPreference -DisableRealtimeMonitoring $true")
        
        # Disable Windows Update
        self.vm.run_powershell("Stop-Service wuauserv")
        self.vm.run_powershell("Set-Service wuauserv -StartupType Disabled")
        
        # Disable Windows Firewall
        self.vm.run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False")
        
        return True
        
    def _start_monitoring(self, analysis_dir: str) -> bool:
        """
        Start monitoring tools inside the VM
        
        Args:
            analysis_dir: Path to analysis directory
            
        Returns:
            True if successful
        """
        # Start network capture using PowerShell and netsh
        self.vm.run_powershell(
            f"netsh trace start capture=yes tracefile={self.guest_working_dir}\\network.etl"
        )
        
        # Start Procmon
        procmon_path = f"{self.guest_tools_dir}\\Procmon.exe"
        procmon_log = f"{self.guest_working_dir}\\procmon.pml"
        self.vm.run_command(
            f"start /B {procmon_path} /Quiet /Minimized /BackingFile {procmon_log}"
        )
        
        # Start registry monitoring
        self.vm.run_powershell(
            f"reg export HKLM {self.guest_working_dir}\\reg_before_HKLM.reg /y"
        )
        self.vm.run_powershell(
            f"reg export HKCU {self.guest_working_dir}\\reg_before_HKCU.reg /y"
        )
        
        # Capture pre-run memory snapshot
        self.vm.run_powershell(
            f"tasklist /v > {self.guest_working_dir}\\memory_before.txt"
        )
        
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
        
        # Take pre-execution screenshot
        self.vm.capture_screenshot(f"{self.analysis_dir}/{self.current_analysis_id}/screenshots/pre_exec.png")
        
        # Execute the sample
        command = f"start /B {guest_sample_path} {arguments}"
        returncode, output = self.vm.run_command(command)
        
        # Give the sample time to execute and perform actions
        time.sleep(120)  # Adjust based on expected sample runtime
        
        # Take post-execution screenshot
        self.vm.capture_screenshot(f"{self.analysis_dir}/{self.current_analysis_id}/screenshots/post_exec.png")
        
        return returncode
        
    def _stop_monitoring(self) -> None:
        """Stop all monitoring processes"""
        # Stop network tracing
        self.vm.run_powershell("netsh trace stop")
        
        # Stop Procmon
        self.vm.run_command(f"{self.guest_tools_dir}\\Procmon.exe /Terminate")
        
        # Take post-run registry snapshot
        self.vm.run_powershell(
            f"reg export HKLM {self.guest_working_dir}\\reg_after_HKLM.reg /y"
        )
        self.vm.run_powershell(
            f"reg export HKCU {self.guest_working_dir}\\reg_after_HKCU.reg /y"
        )
        
        # Capture post-run memory snapshot
        self.vm.run_powershell(
            f"tasklist /v > {self.guest_working_dir}\\memory_after.txt"
        )
        
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
            f"{self.guest_working_dir}\\network.etl",
            f"{analysis_dir}/network/capture.etl"
        )
        
        # Convert ETL to PCAP if available in guest
        self.vm.run_powershell(
            f"if (Test-Path 'C:\\Program Files\\Wireshark\\etl2pcapng.exe') {{ " +
            f"& 'C:\\Program Files\\Wireshark\\etl2pcapng.exe' '{self.guest_working_dir}\\network.etl' " +
            f"'{self.guest_working_dir}\\network.pcapng' }}"
        )
        
        # Copy PCAP if it was created
        self.vm.copy_file_from_guest(
            f"{self.guest_working_dir}\\network.pcapng",
            f"{analysis_dir}/network/capture.pcapng"
        )
        
        # Collect Procmon logs
        self.vm.copy_file_from_guest(
            f"{self.guest_working_dir}\\procmon.pml",
            f"{analysis_dir}/logs/procmon.pml"
        )
        
        # Collect registry snapshots
        for reg_file in ["reg_before_HKLM.reg", "reg_before_HKCU.reg", 
                          "reg_after_HKLM.reg", "reg_after_HKCU.reg"]:
            self.vm.copy_file_from_guest(
                f"{self.guest_working_dir}\\{reg_file}",
                f"{analysis_dir}/registry/{reg_file}"
            )
        
        # Collect memory info
        for mem_file in ["memory_before.txt", "memory_after.txt"]:
            self.vm.copy_file_from_guest(
                f"{self.guest_working_dir}\\{mem_file}",
                f"{analysis_dir}/memory/{mem_file}"
            )
        
        # Collect Windows event logs
        self.vm.run_powershell(
            f"wevtutil epl Application {self.guest_working_dir}\\Application.evtx"
        )
        self.vm.run_powershell(
            f"wevtutil epl Security {self.guest_working_dir}\\Security.evtx"
        )
        self.vm.run_powershell(
            f"wevtutil epl System {self.guest_working_dir}\\System.evtx"
        )
        
        # Copy event logs
        for evt_file in ["Application.evtx", "Security.evtx", "System.evtx"]:
            self.vm.copy_file_from_guest(
                f"{self.guest_working_dir}\\{evt_file}",
                f"{analysis_dir}/logs/{evt_file}"
            )
        
        logger.info(f"Collected all artifacts to {analysis_dir}")
        return True
    
    def _cleanup_guest(self) -> None:
        """Clean up guest VM after analysis"""
        self.vm.run_command(f"rmdir /S /Q {self.guest_working_dir}")
        
        # Re-enable Windows Defender (optional)
        self.vm.run_powershell("Set-MpPreference -DisableRealtimeMonitoring $false")
        
        # Re-enable Windows Firewall (optional)
        self.vm.run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
        
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
            guest_sample_path = f"{self.guest_working_dir}\\{sample_name}"
            self.vm.copy_file_to_guest(sample_path, guest_sample_path)

            logger.info(f"Attempting to copy sample to {guest_sample_path}")
            result = self.vm.copy_file_to_guest(sample_path, guest_sample_path)
            logger.info(f"Copy operation result: {result}")
            
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
                "network_connections": self._analyze_network_traffic(f"{analysis_dir}/network"),
                "file_system_changes": self._analyze_filesystem_changes(f"{analysis_dir}/logs/procmon.pml"),
                "registry_changes": self._analyze_registry_changes(f"{analysis_dir}/registry"),
                "process_activity": self._analyze_process_activity(f"{analysis_dir}/memory"),
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
    
    # Analysis functions - simplified implementations
    def _analyze_network_traffic(self, network_dir: str) -> List[Dict[str, Any]]:
        """Analyze network traffic from capture files"""
        # This is a simplified placeholder
        # In a real implementation, you'd use a library to parse pcap/etl files
        return [{"dst_ip": "1.2.3.4", "dst_port": 80, "protocol": "HTTP"}]
    
    def _analyze_filesystem_changes(self, procmon_log: str) -> Dict[str, List[str]]:
        """Analyze filesystem changes from procmon log"""
        # This is a simplified placeholder
        # In a real implementation, you'd parse the PML file
        return {
            "created": ["C:\\Users\\analyst\\AppData\\Local\\Temp\\malware_dropper.exe"],
            "modified": ["C:\\Windows\\System32\\hosts"],
            "deleted": []
        }
    
    def _analyze_registry_changes(self, registry_dir: str) -> List[Dict[str, Any]]:
        """Compare before/after registry exports to find changes"""
        # This is a simplified placeholder
        # In a real implementation, you'd parse and compare the registry files
        return [
            {
                "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "Malware",
                "data": "C:\\malware.exe",
                "change_type": "added"
            }
        ]
    
    def _analyze_process_activity(self, memory_dir: str) -> List[Dict[str, Any]]:
        """Analyze process activity from memory snapshots"""
        # This is a simplified placeholder
        # In a real implementation, you'd parse and compare the process lists
        return [
            {
                "process": "malware.exe",
                "pid": 1234,
                "parent_process": "explorer.exe",
                "parent_pid": 4567
            }
        ]
    
    def _draw_conclusions(self, analysis_dir: str) -> Dict[str, Any]:
        """Draw conclusions from analysis artifacts"""
        # This is a simplified placeholder
        # In a real implementation, you'd have logic to classify behavior
        return {
            "threat_level": "high",
            "classification": "trojan",
            "behavior": ["persistence", "data_exfiltration"],
            "ioc": ["1.2.3.4:80", "C:\\malware.exe"]
        }
    
    def _generate_html_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """Generate HTML report from report data"""
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
        
        with open(output_path, "w") as f:
            f.write(html)


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
    
    for path in potential_paths:
        if os.path.exists(path):
            return path
    
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
    
    args = parser.parse_args()
    
    # Validate vmrun path
    if not args.vmrun:
        print("ERROR: Could not find vmrun executable. Please specify with --vmrun")
        return 1
    
    if not os.path.exists(args.vmrun):
        print(f"ERROR: vmrun not found at {args.vmrun}")
        return 1
    
    try:
        # Initialize controller and analyzer
        vm_controller = VMwareController(args.vmrun, args.vm, args.snapshot)
        analyzer = WindowsDynamicAnalyzer(vm_controller, args.output)
        
        print("About to run analysis...")
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