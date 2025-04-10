import ember
import lightgbm as lgb
import numpy as np
import pandas as pd

# Load data and model
X_test, y_test = ember.read_vectorized_features("./data/", subset="test")
model = lgb.Booster(model_file="./ember_model_finetuned.txt")

# Predict
predictions = model.predict(X_test)

# Save results
df = pd.DataFrame({"malicious_prob": predictions, "true_label": y_test})
df.to_csv("ember_test_predictions.csv", index=False)

print("✅ Predictions saved to ember_test_predictions.csv")
