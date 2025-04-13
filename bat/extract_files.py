import os
import zipfile
from pathlib import Path

def extract_bat_files(source_dir, target_dir, password=None):
    
    os.makedirs(target_dir, exist_ok=True)
    
    
    zip_files = [f for f in os.listdir(source_dir) if f.endswith('.zip')]
    
   
    for zip_file in zip_files:
        zip_path = os.path.join(source_dir, zip_file)
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                
                bat_name = os.path.splitext(zip_file)[0] + '.bat'
                if bat_name in zip_ref.namelist():
                    
                    if password:
                        zip_ref.extract(bat_name, target_dir, pwd=password.encode())
                    else:
                        zip_ref.extract(bat_name, target_dir)
                    print(f"Extracted {bat_name}")
                else:
                    print(f"Warning: {bat_name} not found in {zip_file}")
        except Exception as e:
            print(f"Error extracting {zip_file}: {str(e)}")