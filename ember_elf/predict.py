import sys
import os
import numpy as np
import lightgbm as lgb
import json
from generate_features import ELFFeatureExtractor

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)

def load_model():
    """Load the trained LightGBM model"""
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, 'elf_model.txt')
    
    if not os.path.exists(model_path):
        return {"error": f"Model file not found at {model_path}"}
    
    try:
        model = lgb.Booster(model_file=model_path)
        return {"model": model, "error": None}
    except Exception as e:
        return {"error": f"Error loading model: {str(e)}"}

def predict_elf_file(file_path, model, extractor):
    """Make prediction on a single ELF file"""
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}
    
    try:
        # Read the file
        with open(file_path, 'rb') as f:
            bytez = f.read()
        
        # Extract features
        features = extractor.feature_vector(bytez)
        raw_features = extractor.raw_features(bytez)  # Get raw features
        
        # Ensure we have the correct number of features (1237)
        if len(features) != 1237:
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
        
        # Convert numpy types to Python native types, preserving strings and lists
        prob = float(prob)  # Convert numpy float to Python float
        
        def convert_value(v):
            if isinstance(v, (list, np.ndarray)):
                return [convert_value(x) for x in v]
            elif isinstance(v, str):
                return str(v)
            elif isinstance(v, np.integer):
                return int(v)
            elif isinstance(v, (np.floating, float)):
                return float(v)
            else:
                return v
        
        raw_features = {k: convert_value(v) for k, v in raw_features.items()}
        
        return {
            'elf_file': file_name,
            'elf_probability': prob,
            'elf_prediction': 'MALICIOUS' if prob >= 0.5 else 'BENIGN',
            'elf_features': raw_features,
            'error': None
        }
    except Exception as e:
        return {"error": f"Error processing {file_path}: {str(e)}"}

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python predict.py <path_to_elf_file>"}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Load model and feature extractor
    model_result = load_model()
    if model_result.get("error"):
        print(json.dumps(model_result))
        sys.exit(1)
    
    model = model_result["model"]
    extractor = ELFFeatureExtractor()
    
    # Make prediction
    result = predict_elf_file(file_path, model, extractor)
    print(json.dumps(result, cls=NumpyEncoder))

if __name__ == "__main__":
    main() 