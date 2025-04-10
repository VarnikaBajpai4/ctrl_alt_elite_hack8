import sys
import os
import json
import ember
import lightgbm as lgb
import numpy as np

# Load the trained EMBER model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "ember_model_final.txt")
lgbm_model = lgb.Booster(model_file=MODEL_PATH)

if len(sys.argv) != 2:
    print("Usage: python predict.py <path-to-pe-file>", file=sys.stderr)
    sys.exit(1)
filename = sys.argv[1]

with open(filename, "rb") as f:
    file_data = f.read()

# Extract all raw features
extractor = ember.PEFeatureExtractor(feature_version=2)
raw = extractor.raw_features(file_data)

# Process to numeric vector and predict
feature_vector = extractor.process_raw_features(raw)
prob = float(lgbm_model.predict([feature_vector])[0])

# Output everything as JSON
output = {
    "sha256": raw.get("sha256"),
    "features": raw,
    "probability": prob
}
print(json.dumps(output, indent=4))
