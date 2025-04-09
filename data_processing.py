# data_processing.py
"""Module for data processing functions."""

import numpy as np
import pandas as pd
from sklearn import preprocessing
import os

def load_data(path, train=True, max_samples=None):
    """
    Load the EMBER dataset.
    
    Args:
        path (str): Path to the EMBER dataset
        train (bool): Whether to load the training or testing dataset
        max_samples (int, optional): Maximum number of samples to load
    
    Returns:
        tuple: (features, labels) as numpy arrays
    """
    print(f"Loading {'training' if train else 'testing'} data from {path}")
    
    prefix = 'X_train' if train else 'X_test'
    shape = (800000, 2381) if train else (200000, 2381)
    
    features = np.memmap(os.path.join(path, f'{prefix}.dat'), 
                         mode="r", 
                         shape=shape, 
                         dtype=np.float32)
    
    prefix = 'y_train' if train else 'y_test'
    labels = np.memmap(os.path.join(path, f'{prefix}.dat'), 
                       mode="r", 
                       dtype=np.float32)
    
    # Convert to DataFrame for easier manipulation
    features_df = pd.DataFrame(features)
    labels_df = pd.DataFrame(labels)
    
    # If max_samples is provided, reduce the number of samples
    if max_samples is not None:
        start_idx = len(features_df) - max_samples
        features_df = features_df.iloc[start_idx:]
        labels_df = labels_df.iloc[start_idx:]
    
    print(f"Loaded {len(features_df)} samples")
    
    # Remove unlabeled samples (-1)
    unlabeled_indices = labels_df[labels_df[0] == -1].index
    features_df.drop(unlabeled_indices, inplace=True)
    labels_df.drop(unlabeled_indices, inplace=True)
    
    print(f"After removing unlabeled samples: {len(features_df)} samples")
    
    return features_df.values, labels_df.values

def preprocess_data(features, labels, for_training=True):
    """
    Preprocess the data for model training or inference.
    
    Args:
        features (numpy.ndarray): Feature array
        labels (numpy.ndarray): Label array
        for_training (bool): Whether preprocessing is for training or inference
    
    Returns:
        tuple: (processed_features, labels) ready for model input
    """
    print("Preprocessing data...")
    
    # Dimension reduction (remove the last 77 features)
    features = np.delete(features, np.s_[-77:], axis=1)
    
    # Normalize data to [0, 255] range and then scale to [0, 1]
    min_max_scaler = preprocessing.MinMaxScaler((0, 255), copy=False)
    features = min_max_scaler.fit_transform(features)
    features = features / 255.0
    
    # Reshape data to image-like format (48x48)
    features = np.reshape(features, (features.shape[0], 48, 48))
    
    # For CNN, reshape to (samples, height, width, channels)
    features_cnn = np.reshape(features, (features.shape[0], 48, 48, 1))
    
    # For other models, flatten the data
    features_flat = features.reshape(features.shape[0], -1)
    
    print("Preprocessing complete")
    
    return features_cnn, features_flat, labels