import os
import json
import numpy as np
from tqdm import tqdm
from generate_features import ELFFeatureExtractor

def vectorize_features(data_dir, output_dir):
    """
    Vectorize features from ELF files and save them as .dat files
    """
    # Initialize feature extractor
    extractor = ELFFeatureExtractor()
    
    # Initialize lists to store features and labels
    X_train = []
    y_train = []
    X_test = []
    y_test = []
    
    # Process training data
    train_benign_dir = os.path.join(data_dir, "train", "benign")
    train_mal_dir = os.path.join(data_dir, "train", "malicious")
    
    print("Processing training data...")
    
    # Process benign training files
    for elf_file in tqdm(os.listdir(train_benign_dir)):
        with open(os.path.join(train_benign_dir, elf_file), 'rb') as f:
            bytez = f.read()
            features = extractor.feature_vector(bytez)
            X_train.append(features)
            y_train.append(0)  # Benign label
    
    # Process malicious training files
    for elf_file in tqdm(os.listdir(train_mal_dir)):
        with open(os.path.join(train_mal_dir, elf_file), 'rb') as f:
            bytez = f.read()
            features = extractor.feature_vector(bytez)
            X_train.append(features)
            y_train.append(1)  # Malicious label
    
    # Process test data
    test_benign_dir = os.path.join(data_dir, "test", "benign")
    test_mal_dir = os.path.join(data_dir, "test", "malicious")
    
    print("Processing test data...")
    
    # Process benign test files
    for elf_file in tqdm(os.listdir(test_benign_dir)):
        with open(os.path.join(test_benign_dir, elf_file), 'rb') as f:
            bytez = f.read()
            features = extractor.feature_vector(bytez)
            X_test.append(features)
            y_test.append(0)
    
    # Process malicious test files
    for elf_file in tqdm(os.listdir(test_mal_dir)):
        with open(os.path.join(test_mal_dir, elf_file), 'rb') as f:
            bytez = f.read()
            features = extractor.feature_vector(bytez)
            X_test.append(features)
            y_test.append(1)
    
    # Convert to numpy arrays
    X_train = np.array(X_train, dtype=np.float32)
    y_train = np.array(y_train, dtype=np.float32)
    X_test = np.array(X_test, dtype=np.float32)
    y_test = np.array(y_test, dtype=np.float32)
    
    # Save to .dat files
    print("Saving vectorized features...")
    X_train.tofile(os.path.join(output_dir, "X_train.dat"))
    y_train.tofile(os.path.join(output_dir, "y_train.dat"))
    X_test.tofile(os.path.join(output_dir, "X_test.dat"))
    y_test.tofile(os.path.join(output_dir, "y_test.dat"))
    
    print(f"Vectorization complete!")
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")

if __name__ == "__main__":
    data_dir = "data"  
    output_dir = "vectorized"  
    os.makedirs(output_dir, exist_ok=True)
    vectorize_features(data_dir, output_dir) 