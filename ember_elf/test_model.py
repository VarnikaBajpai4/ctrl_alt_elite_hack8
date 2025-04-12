import os
import sys
import numpy as np
import lightgbm as lgb
from generate_features import ELFFeatureExtractor

def load_model():
    """Load the trained LightGBM model"""
    try:
        model = lgb.Booster(model_file='vectorized/elf_model.txt')
        return model
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        sys.exit(1)

def predict_file(file_path, model, extractor):
    """Make prediction on a single ELF file"""
    try:
        with open(file_path, 'rb') as f:
            bytez = f.read()
        
        # Extract features
        features = extractor.feature_vector(bytez)
        
        # Make prediction
        prob = model.predict([features])[0]
        
        # Get file name
        file_name = os.path.basename(file_path)
        
        return {
            'file': file_name,
            'probability': float(prob),
            'prediction': 'MALICIOUS' if prob >= 0.5 else 'BENIGN'
        }
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_model.py <path_to_elf_file> [additional_files...]")
        sys.exit(1)
    
    # Load model and feature extractor
    print("Loading model...")
    model = load_model()
    extractor = ELFFeatureExtractor()
    
    # Process each file
    print("\nMaking predictions:")
    print("-" * 50)
    print(f"{'File':<30} {'Probability':<15} {'Prediction':<10}")
    print("-" * 50)
    
    for file_path in sys.argv[1:]:
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            continue
            
        result = predict_file(file_path, model, extractor)
        if result:
            print(f"{result['file']:<30} {result['probability']:<15.4f} {result['prediction']:<10}")

if __name__ == "__main__":
    main() 