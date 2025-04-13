import os
import numpy as np
from tqdm import tqdm
from generate_features import BatFeatureExtractor

def vectorize_features(data_dir, output_dir):
    extractor = BatFeatureExtractor()
    
    X_train = []
    y_train = []
    
    # Process training data
    benign_dir = os.path.join(data_dir, "benign")
    malicious_dir = os.path.join(data_dir, "malicious")
    
    print("Processing training data...")
    
    # Process benign files
    print("Processing benign files...")
    for bat_file in tqdm(os.listdir(benign_dir)):
        with open(os.path.join(benign_dir, bat_file), 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            features = extractor.feature_vector(content)
            X_train.append(features)
            y_train.append(0)  # Benign label
    
    # Process malicious files
    print("Processing malicious files...")
    for bat_file in tqdm(os.listdir(malicious_dir)):
        with open(os.path.join(malicious_dir, bat_file), 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            features = extractor.feature_vector(content)
            X_train.append(features)
            y_train.append(1)  # Malicious label
    
    # Convert to numpy arrays and save
    X_train = np.array(X_train, dtype=np.float32)
    y_train = np.array(y_train, dtype=np.float32)
    
    # Create vectorized directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Save to .dat files
    X_train.tofile(os.path.join(output_dir, "X_train.dat"))
    y_train.tofile(os.path.join(output_dir, "y_train.dat"))
    
    print(f"Vectorization complete!")
    print(f"Training samples: {len(X_train)}")
    print(f"Vectorized data saved to: {output_dir}")

def main():
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define paths
    data_dir = os.path.join(script_dir, "data")
    vectorized_dir = os.path.join(script_dir, "vectorized")
    
    # Run vectorization
    vectorize_features(data_dir, vectorized_dir)

if __name__ == "__main__":
    main()