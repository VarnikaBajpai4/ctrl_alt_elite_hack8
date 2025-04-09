# train.py
"""Script to train malware detection models."""

import os
import argparse
import numpy as np
from sklearn.metrics import accuracy_score

from config import *
from data_processing import load_data, preprocess_data
from models import (
    train_cnn_model, 
    train_lightgbm_model, 
    train_nn_dropout_model
)
from visualization import (
    plot_sample_images, 
    plot_learning_curves, 
    plot_confusion_matrix, 
    plot_roc_curve
)

def create_arg_parser():
    """Create argument parser for the training script."""
    parser = argparse.ArgumentParser(description='Train malware detection models')
    
    parser.add_argument('--data_path', type=str, required=True,
                        help='Path to the EMBER dataset')
    parser.add_argument('--model', type=str, default='cnn',
                        choices=['cnn', 'lightgbm', 'nn', 'all'],
                        help='Model to train (default: cnn)')
    parser.add_argument('--max_samples', type=int, default=None,
                        help='Maximum number of samples to use (default: all)')
    parser.add_argument('--epochs', type=int, default=EPOCHS,
                        help=f'Number of epochs for training (default: {EPOCHS})')
    parser.add_argument('--batch_size', type=int, default=BATCH_SIZE,
                        help=f'Batch size for training (default: {BATCH_SIZE})')
    parser.add_argument('--visualize', action='store_true',
                        help='Visualize training process and results')
    
    return parser

def main():
    """Main function for training."""
    parser = create_arg_parser()
    args = parser.parse_args()
    
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Load data
    x_train, y_train = load_data(args.data_path, train=True, max_samples=args.max_samples)
    
    # Preprocess data
    x_train_cnn, x_train_flat, y_train = preprocess_data(x_train, y_train)
    
    if args.visualize:
        # Visualize some samples
        plot_sample_images(x_train_cnn, y_train, num_images=25, start_index=0)
    
    # Train the selected model
    if args.model == 'cnn' or args.model == 'all':
        print("\n=== Training CNN Model ===")
        cnn_model, cnn_history = train_cnn_model(
            x_train_cnn, y_train,
            epochs=args.epochs,
            batch_size=args.batch_size,
            model_path=CNN_MODEL_PATH
        )
        
        if args.visualize:
            plot_learning_curves(cnn_history)
    
    if args.model == 'lightgbm' or args.model == 'all':
        print("\n=== Training LightGBM Model ===")
        lgbm_model = train_lightgbm_model(
            x_train_flat, y_train,
            num_boost_round=100,
            model_path=LGBM_MODEL_PATH
        )
    
    if args.model == 'nn' or args.model == 'all':
        print("\n=== Training Neural Network with Dropout ===")
        nn_model, nn_history = train_nn_dropout_model(
            x_train_flat, y_train,
            epochs=args.epochs,
            batch_size=args.batch_size,
            model_path=NN_MODEL_PATH
        )
        
        if args.visualize:
            plot_learning_curves(nn_history)
    
    print("\nTraining complete!")

if __name__ == '__main__':
    main()