import os
import logging

logger = logging.getLogger('win-vm-analysis')

def find_vmrun_path():
    """Find the vmrun executable path based on OS"""
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



