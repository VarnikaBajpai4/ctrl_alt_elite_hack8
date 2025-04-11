import os
import sys
from connection import ping_vm, test_connection
from file_transfer import send_file_to_vm

VM_IP = "127.0.0.1"
PORT = 12345

def print_firewall_help():
    print("\n=== Firewall Configuration Instructions ===")
    print("In your Windows 11 guest VM, run PowerShell as Administrator and execute:")
    print("\n# Create a new inbound rule to allow the listener port")
    print("New-NetFirewallRule -DisplayName \"VM File Transfer\" -Direction Inbound -Protocol TCP -LocalPort 12345 -Action Allow")
    print("\n# Or to temporarily disable the firewall for testing")
    print("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False")
    print("\n# Remember to turn it back on when done")
    print("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")

def main():
    print("===== VMware Host-to-Guest File Transfer Utility =====")
    
    if not ping_vm(VM_IP):
        print_firewall_help()
        return
    
    if not test_connection(VM_IP, PORT):
        print("\nMake sure the listener script is running on the guest VM.")
        print_firewall_help()
        return
    
    file_path = r"C:\Users\aarus\Downloads\Alpharithm Lesson 21 - Google Slides - 15 October 2024 (online-video-cutter.com)-2.txt".strip('"')
    
    execute = input("Execute file after transfer? (y/n): ").lower() == 'y'
    
    send_file_to_vm(VM_IP, PORT, file_path, execute)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)