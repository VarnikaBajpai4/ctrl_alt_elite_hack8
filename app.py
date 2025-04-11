"""
Windows VMware Dynamic Analysis Integration
------------------------------------------
This integration allows for automated dynamic analysis of samples in isolated VMware virtual machines.
Specifically optimized for Windows VMs for malware analysis.
"""
from utils.find_vmrun_path import find_vmrun_path
from dynamic_analyzer import WindowsDynamicAnalyzer
from vmware_controller import VMwareController
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