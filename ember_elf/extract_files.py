import os
import zipfile
from pathlib import Path

def extract_elf_files(source_dir, target_dir, password=None):
    # Create target directory if it doesn't exist
    os.makedirs(target_dir, exist_ok=True)
    
    # Get all zip files in source directory
    zip_files = [f for f in os.listdir(source_dir) if f.endswith('.zip')]
    
    # Extract each zip file
    for zip_file in zip_files:
        zip_path = os.path.join(source_dir, zip_file)
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Get the ELF file name (should be the same as zip name but with .elf extension)
                elf_name = os.path.splitext(zip_file)[0] + '.elf'
                if elf_name in zip_ref.namelist():
                    # Extract the ELF file to target directory
                    if password:
                        zip_ref.extract(elf_name, target_dir, pwd=password.encode())
                    else:
                        zip_ref.extract(elf_name, target_dir)
                    print(f"Extracted {elf_name}")
                else:
                    print(f"Warning: {elf_name} not found in {zip_file}")
        except Exception as e:
            print(f"Error extracting {zip_file}: {str(e)}")

if __name__ == "__main__":
    source_dir = "/Users/varnikabajpai/Desktop/Testing/data"
    target_dir = "/Users/varnikabajpai/Desktop/Gajshield/ember_elf/data/train/malicious"
    # You'll need to provide the correct password here
    password = "infected"  # This is a common default password for malware samples
    extract_elf_files(source_dir, target_dir, password) 