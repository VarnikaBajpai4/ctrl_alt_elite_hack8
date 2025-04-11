import subprocess
import os
import time
import logging
import ctypes
import sys

# Set up logging to file and console
log_file = "C:\\Logs\\regshot_test_log.txt"
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def is_admin():
    """Check if the script is running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def test_regshot(regshot_path="C:\\Tools\\Regshot\\Regshot-x64-Unicode.exe",
                output_dir="C:\\Logs",
                duration=10,
                target_executable="notepad.exe"):
    """Simple test of Regshot with manual GUI interaction"""
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "regshot_test.txt")
    
    # Start Regshot
    logger.info(f"Starting Regshot from: {regshot_path}")
    try:
        # Launch Regshot
        regshot_process = subprocess.Popen(regshot_path)
        logger.info("Regshot launched successfully")
        
        # Instructions for the user
        print("\n" + "-"*60)
        print("MANUAL STEPS:")
        print("1. In Regshot window, click '1st shot' button")
        print("2. Wait for the first snapshot to complete")
        print("3. Press ENTER in this console when 1st shot is done")
        print("-"*60 + "\n")
        
        input("Press ENTER after taking 1st shot...")
        
        # Launch test executable
        logger.info(f"Launching test program: {target_executable}")
        try:
            test_process = subprocess.Popen(target_executable)
            logger.info(f"Test program launched with PID: {test_process.pid}")
        except Exception as e:
            logger.error(f"Failed to launch test program: {e}")
            return False
        
        # Wait for specified duration
        logger.info(f"Monitoring for {duration} seconds...")
        time.sleep(duration)
        
        # Close test program
        logger.info("Closing test program...")
        test_process.terminate()
        time.sleep(1)
        
        # Instructions for second shot
        print("\n" + "-"*60)
        print("MANUAL STEPS:")
        print("1. In Regshot window, click '2nd shot' button")
        print("2. Wait for the second snapshot to complete")
        print("3. Click 'Compare' button")
        print(f"4. Save the comparison file to: {output_file}")
        print("5. Press ENTER in this console when done")
        print("-"*60 + "\n")
        
        input("Press ENTER after completing the comparison...")
        
        # Check for output file
        if os.path.exists(output_file):
            logger.info(f"Successfully created comparison file: {output_file}")
            return True
        else:
            logger.warning(f"Comparison file not found at: {output_file}")
            alt_file = input("Enter path to the saved comparison file (or press ENTER if none): ")
            if alt_file and os.path.exists(alt_file):
                logger.info(f"Found comparison file at alternate location: {alt_file}")
                return True
                
            return False
            
    except Exception as e:
        logger.error(f"Error during Regshot test: {e}")
        return False

if __name__ == "__main__":
    # Log admin status
    logger.info(f"Running with admin privileges: {is_admin()}")
    
    if not is_admin():
        logger.warning("This script requires administrator privileges")
        print("\nThis script needs to run as Administrator.")
        print("Please right-click on PowerShell/Command Prompt and select 'Run as administrator'")
        print("Then navigate to the script directory and run the script again.\n")
        input("Press ENTER to exit...")
        sys.exit(1)
    
    # Run the test
    print("\nStarting Regshot test...")
    result = test_regshot(
        regshot_path="C:\\Tools\\Regshot\\Regshot-x64-Unicode.exe",
        output_dir="C:\\Logs",
        duration=10, 
        target_executable="notepad.exe"
    )
    
    if result:
        print("\nRegshot test completed successfully!")
    else:
        print("\nRegshot test failed! Check the log file for details.")
    
    print(f"Log file location: {log_file}")
    input("\nPress ENTER to exit...")