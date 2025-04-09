# predict.py
"""Script to make predictions using trained malware detection models."""

import os
import argparse
import numpy as np
from sklearn.metrics import accuracy_score

from config import *
from data_processing import load_data, preprocess_data
from models import (
    load_saved_cnn_model,
    load_saved_lightgbm_model,
    predict_malware
)
from visualization import (
    plot_confusion_matrix,
    plot_roc_curve
)

def create_arg_parser():
    """Create argument parser for the prediction script."""
    parser = argparse.ArgumentParser(description='Make predictions using trained malware detection models')
    
    parser.add_argument('--data_path', type=str, required=True,
                        help='Path to the EMBER dataset')
    parser.add_argument('--model', type=str, default='cnn',
                        choices=['cnn', 'lightgbm', 'nn'],
                        help='Model to use for prediction (default: cnn)')
    parser.add_argument('--model_path', type=str, default=None,
                        help='Path to the trained model (default: use config path)')
    parser.add_argument('--max_samples', type=int, default=10000,
                        help='Maximum number of samples to use (default: 10000)')
    parser.add_argument('--visualize', action='store_true',
                        help='Visualize prediction results')
    
    return parser

def main():
    """Main function for prediction."""
    parser = create_arg_parser()
    args = parser.parse_args()
    
    # Determine model path
    if args.model_path:
        model_path = args.model_path
    else:
        if args.model == 'cnn':
            model_path = CNN_MODEL_PATH
        elif args.model == 'lightgbm':
            model_path = LGBM_MODEL_PATH
        elif args.model == 'nn':
            model_path = NN_MODEL_PATH
    
    # Check if model file exists
    if not os.path.exists(model_path):
        print(f"Error: Model file not found at {model_path}")
        print("Please train the model first or provide a valid model path.")
        return
    
    # Load test data
    x_test, y_test = load_data(args.data_path, train=False, max_samples=args.max_samples)
    
    # Preprocess test data
    x_test_cnn, x_test_flat, y_test = preprocess_data(x_test, y_test, for_training=False)
    
    # Load the model
    print(f"Loading model from {model_path}...")
    if args.model == 'cnn':
        model = load_saved_cnn_model(model_path)
        test_features = x_test_cnn
    elif args.model == 'lightgbm':
        model = load_saved_lightgbm_model(model_path)
        test_features = x_test_flat
    elif args.model == 'nn':
        model = load_saved_cnn_model(model_path)  # Use the same function as CNN
        test_features = x_test_flat
    
    # Make predictions
    print("Making predictions...")
    pred_prob, pred_binary = predict_malware(model, test_features, model_type=args.model)
    
    # Calculate accuracy
    accuracy = accuracy_score(y_test, pred_binary)
    print(f"Accuracy: {accuracy:.4f}")
    
    # Visualize results if requested
    if args.visualize:
        plot_confusion_matrix(y_test, pred_binary, 
                              title=f"Confusion Matrix - {args.model.upper()}")
        plot_roc_curve(y_test, pred_prob, 
                       label=args.model.upper())
    
    print("\nPrediction complete!")

def predict_single_sample(model, features, model_type='cnn'):
    """
    Make a prediction for a single sample.
    
    This is a function that could be used in a production environment.
    
    Args:
        model: Trained model
        features (numpy.ndarray): Features to predict
        model_type (str): Type of model ('cnn', 'lightgbm', or 'nn')
    
    Returns:
        float: Probability of the sample being malicious
    """
    # Make sure features have the right shape
    if model_type == 'cnn':
        if features.ndim == 2:
            features = features.reshape(1, *features.shape)
        elif features.ndim == 3:
            features = features.reshape(1, *features.shape, 1)
    else:
        if features.ndim == 1:
            features = features.reshape(1, -1)
    
    # Make prediction
    pred_prob, _ = predict_malware(model, features, model_type=model_type)
    
    return pred_prob[0]

if __name__ == '__main__':
    main()