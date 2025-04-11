import subprocess
import os
import time
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

def test_procmon(procmon_path="C:\\Tools\\Procmon\\Procmon.exe",  # Updated path
                log_file="C:\\Tools\\Procmon\\Log\\procmon_test.pml",
                duration=10,
                target_executable="notepad.exe"):
    """
    Simple test of Process Monitor:
    1. Start Procmon
    2. Launch a test executable
    3. Wait for specified duration
    4. Stop Procmon and save the log
    """
    # Ensure log directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Terminate any existing Procmon instances
    logger.info("Terminating any existing Procmon instances...")
    try:
        subprocess.run(["taskkill", "/f", "/im", "Procmon.exe"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)  # Give it time to shut down
    except Exception as e:
        logger.warning(f"Failed to kill existing Procmon: {e}")
    
    # Start Procmon
    logger.info("Starting Process Monitor...")
    start_cmd = [
        procmon_path,
        "/AcceptEula",   # Accept EULA automatically
        "/Quiet",        # Run quietly
        "/Minimized",    # Start minimized
        "/BackingFile",  # Specify log file
        log_file
    ]
    
    try:
        subprocess.Popen(start_cmd)
        logger.info(f"Started Process Monitor, logging to {log_file}")
        time.sleep(2)  # Give Procmon time to initialize
    except Exception as e:
        logger.error(f"Failed to start Process Monitor: {e}")
        return False
    
    # Launch the test executable
    logger.info(f"Launching test executable: {target_executable}")
    try:
        test_process = subprocess.Popen(target_executable)
        logger.info(f"Launched {target_executable} with PID: {test_process.pid}")
    except Exception as e:
        logger.error(f"Failed to start test executable: {e}")
        # Stop Procmon anyway
        subprocess.run([procmon_path, "/Terminate"])
        return False
    
    # Wait for the specified duration
    logger.info(f"Monitoring for {duration} seconds...")
    time.sleep(duration)
    
    # Terminate test process
    logger.info("Terminating test process...")
    test_process.terminate()
    
    # Stop Procmon and save the log
    logger.info("Stopping Process Monitor...")
    try:
        subprocess.run([procmon_path, "/Terminate"])
        logger.info("Stopped Process Monitor")
        if os.path.exists(log_file):
            logger.info(f"Log file saved to: {log_file}")
            logger.info(f"Log file size: {os.path.getsize(log_file)} bytes")
            return True
        else:
            logger.error("Log file not found")
            return False
    except Exception as e:
        logger.error(f"Failed to stop Process Monitor: {e}")
        return False

if __name__ == "__main__":
    # Adjust paths as needed for your environment
    result = test_procmon(
        procmon_path="C:\\Tools\\Procmon\\Procmon.exe",  # Update if you use a different path
        log_file="C:\\Logs\\procmon_test.pml",
        duration=10,  # Monitor for 10 seconds
        target_executable="notepad.exe"  # A harmless executable to test with
    )
    
    if result:
        print("Process Monitor test completed successfully!")
    else:
        print("Process Monitor test failed")