import os
import requests
import time

API_URL = "https://mb-api.abuse.ch/api/v1/"
API_KEY = "08629a3194f9bcbc86155103af04660e82076d61051c7ba9"
OUTPUT_DIR = "data"

def fetch_hashes(file_type: str, count: int):
    payload = {
        "query": "get_file_type",
        "file_type": file_type,
        "limit": count
    }
    headers = {"API-KEY": API_KEY}
    response = requests.post(API_URL, data=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    return [entry["sha256_hash"] for entry in data.get("data", [])]

def download_file(sha256: str, file_type: str):
    payload = {
        "query": "get_file",
        "sha256_hash": sha256
    }
    headers = {"API-KEY": API_KEY}
    response = requests.post(API_URL, data=payload, headers=headers)

    # Create type-specific directory
    type_dir = os.path.join(OUTPUT_DIR, file_type)
    os.makedirs(type_dir, exist_ok=True)

    if response.status_code == 200 and response.content[:2] == b'PK':
        file_path = os.path.join(type_dir, f"{sha256}.zip")
        with open(file_path, "wb") as f:
            f.write(response.content)
        print(f"✅ Downloaded {file_type}: {sha256}")
        return True
    else:
        print(f"❌ Failed {file_type}: {sha256}")
        return False

def main():
    # Create main output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # File types to download
    file_types = ["ps1", "js", "bat"]
    
    # How many of each type to attempt to download
    count_per_type = 200
    
    for file_type in file_types:
        print(f"\n📥 Fetching {count_per_type} {file_type.upper()} file hashes...")
        hashes = fetch_hashes(file_type, count_per_type)
        print(f"Found {len(hashes)} {file_type.upper()} hashes")
        
        successful = 0
        for h in hashes:
            if download_file(h, file_type):
                successful += 1
            
            # Add a small delay to avoid rate limiting
            time.sleep(0.5)
        
        print(f"\n✅ Successfully downloaded {successful} {file_type.upper()} files")

if __name__ == "__main__":
    main()