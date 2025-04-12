import sys
import os
import numpy as np
import lightgbm as lgb
from generate_features import ELFFeatureExtractor

def load_model():
    """Load the trained LightGBM model"""
    model_path = 'elf_model.txt'
    if not os.path.exists(model_path):
        print(f"Error: Model file not found at {model_path}")
        print("Please make sure you've trained the model first using train_and_save.py")
        sys.exit(1)
    
    try:
        model = lgb.Booster(model_file=model_path)
        return model
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        sys.exit(1)

def predict_elf_file(file_path, model, extractor):
    """Make prediction on a single ELF file"""
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return None
    
    try:
        # Read the file
        with open(file_path, 'rb') as f:
            bytez = f.read()
        
        # Extract features
        features = extractor.feature_vector(bytez)
        
        # Ensure we have the correct number of features (1237)
        if len(features) != 1237:
            print(f"Warning: Got {len(features)} features, expected 1237")
            # If we have more features, take only the first 1237
            if len(features) > 1237:
                features = features[:1237]
            # If we have fewer features, pad with zeros
            else:
                features = np.pad(features, (0, 1237 - len(features)))
        
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
    if len(sys.argv) != 2:
        print("Usage: python predict.py <path_to_elf_file>")
        print("Example: python predict.py /path/to/suspicious.elf")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Load model and feature extractor
    print("Loading model...")
    model = load_model()
    extractor = ELFFeatureExtractor()
    
    # Make prediction
    print(f"\nAnalyzing {file_path}...")
    result = predict_elf_file(file_path, model, extractor)
    
    if result:
        print("\nPrediction Results:")
        print("-" * 50)
        print(f"File: {result['file']}")
        print(f"Malicious Probability: {result['probability']:.4f}")
        print(f"Prediction: {result['prediction']}")
        print("-" * 50)
        
        # Print interpretation
        if result['probability'] >= 0.5:
            print("\nThis file is likely MALICIOUS")
            print(f"Confidence: {(result['probability'] * 100):.1f}%")
        else:
            print("\nThis file is likely BENIGN")
            print(f"Confidence: {((1 - result['probability']) * 100):.1f}%")

if __name__ == "__main__":
    main() 