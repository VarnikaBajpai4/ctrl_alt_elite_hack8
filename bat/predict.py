import sys
import os
import numpy as np
import lightgbm as lgb
import json
from generate_features import BatFeatureExtractor

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
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, 'vectorized/bat_model.txt')
    
    if not os.path.exists(model_path):
        return {"error": f"Model file not found at {model_path}"}
    
    try:
        model = lgb.Booster(model_file=model_path)
        return {"model": model, "error": None}
    except Exception as e:
        return {"error": f"Error loading model: {str(e)}"}

def predict_bat_file(file_path, model, extractor):
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        features = extractor.feature_vector(content)
        raw_features = extractor.raw_features(content)
        
        # Get the feature dimension from the model
        feature_dim = model.num_feature()
        
        # Ensure features match the model's expected dimension
        if len(features) != feature_dim:
            if len(features) > feature_dim:
                features = features[:feature_dim]
            else:
                features = np.pad(features, (0, feature_dim - len(features)))
        
        prob = model.predict([features])[0]
        file_name = os.path.basename(file_path)
        
        return {
            'bat_file': file_name,
            'bat_probability': float(prob),
            'bat_prediction': 'MALICIOUS' if prob >= 0.5 else 'BENIGN',
            'bat_features': raw_features,
            'error': None
        }
    except Exception as e:
        return {"error": f"Error processing {file_path}: {str(e)}"}

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python predict.py <path_to_bat_file>"}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    model_result = load_model()
    if model_result.get("error"):
        print(json.dumps(model_result))
        sys.exit(1)
    
    model = model_result["model"]
    extractor = BatFeatureExtractor()
    result = predict_bat_file(file_path, model, extractor)
    print(json.dumps(result, cls=NumpyEncoder))

if __name__ == "__main__":
    main()