# sample_usage.py
"""
Sample script demonstrating how to use the trained model to classify a new sample.
"""

import numpy as np
from tensorflow.keras.models import load_model
import lightgbm as lgb
from sklearn import preprocessing

def load_and_preprocess_sample(file_path):
    """
    Load and preprocess a sample file.
    
    In a real-world scenario, this function would extract features from a binary file
    using the same feature extraction technique used in the EMBER dataset.
    
    Args:
        file_path (str): Path to the binary file
    
    Returns:
        numpy.ndarray: Preprocessed features
    """
    # This is just a placeholder
    # In a real scenario, you would use feature extraction code similar to EMBER
    
    # Let's create a dummy feature vector with the correct shape
    features = np.random.random((2381,))
    
    # Normalize and reshape as done during training
    features = np.delete(features, np.s_[-77:])  # Remove last 77 features
    
    scaler = preprocessing.MinMaxScaler((0, 255))
    features = scaler.fit_transform(features.reshape(1, -1))
    features = features / 255.0
    
    # For CNN
    features_cnn = features.reshape(1, 48, 48, 1)
    
    # For other models
    features_flat = features.reshape(1, -1)
    
    return features_cnn, features_flat

def classify_sample(file_path, model_path, model_type='cnn'):
    """
    Classify a binary file as malicious or benign.
    
    Args:
        file_path (str): Path to the binary file
        model_path (str): Path to the trained model
        model_type (str): Type of model ('cnn', 'lightgbm', or 'nn')
    
    Returns:
        tuple: (prediction_probability, prediction_class)
    """
    # Load and preprocess the sample
    features_cnn, features_flat = load_and_preprocess_sample(file_path)
    
    # Load the model
    if model_type == 'cnn' or model_type == 'nn':
        model = load_model(model_path)
        features = features_cnn if model_type == 'cnn' else features_flat
        pred_prob = model.predict(features)[0][0]
    elif model_type == 'lightgbm':
        model = lgb.Booster(model_file=model_path)
        pred_prob = model.predict(features_flat)[0]
    else:
        raise ValueError(f"Unsupported model type: {model_type}")
    
    # Classify based on probability threshold
    pred_class = 'malicious' if pred_prob >= 0.5 else 'benign'
    
    return pred_prob, pred_class

def main():
    """Main function demonstrating sample usage."""
    # In a real scenario, this would be the path to a binary file
    file_path = "example_binary.exe"
    
    # Path to the trained model
    model_path = "models/cnn_malware_classification.h5"
    
    # Classify the sample
    try:
        pred_prob, pred_class = classify_sample(file_path, model_path, model_type='cnn')
        print(f"Prediction Probability: {pred_prob:.4f}")
        print(f"Prediction Class: {pred_class}")
    except FileNotFoundError:
        print("Model not found. Please train the model first.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()