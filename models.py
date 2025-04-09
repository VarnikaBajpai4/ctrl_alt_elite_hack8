# models.py
"""Module containing model definitions."""

from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Dense, Flatten, Dropout
import lightgbm as lgb
import numpy as np
import os

def create_cnn_model(input_shape=(48, 48, 1)):
    """
    Create a CNN model for malware classification.
    
    Args:
        input_shape (tuple): Shape of the input data
    
    Returns:
        tensorflow.keras.models.Sequential: Compiled CNN model
    """
    model = Sequential()
    
    model.add(Conv2D(filters=32, kernel_size=(3, 3), activation='relu', input_shape=input_shape))
    model.add(MaxPooling2D(pool_size=(2, 2)))
    model.add(Conv2D(filters=64, kernel_size=(3, 3), activation='relu'))
    model.add(MaxPooling2D(pool_size=(2, 2)))
    model.add(Conv2D(filters=128, kernel_size=(3, 3), activation='relu'))
    model.add(Flatten())
    
    model.add(Dense(400, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    return model

def create_nn_dropout_model(input_dim):
    """
    Create a Neural Network with Dropout for malware classification.
    
    Args:
        input_dim (int): Dimension of the input data
    
    Returns:
        tensorflow.keras.models.Sequential: Compiled NN model
    """
    model = Sequential()
    
    model.add(Dense(64, activation='sigmoid', input_shape=(input_dim,)))
    model.add(Dropout(0.5))
    
    model.add(Dense(32, activation='sigmoid'))
    model.add(Dropout(0.5))
    
    model.add(Dense(1, activation='sigmoid'))
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    return model

def train_cnn_model(x_train, y_train, epochs=5, batch_size=32, validation_split=0.2, model_path=None):
    """
    Train a CNN model.
    
    Args:
        x_train (numpy.ndarray): Training features
        y_train (numpy.ndarray): Training labels
        epochs (int): Number of epochs to train
        batch_size (int): Batch size for training
        validation_split (float): Fraction of data to use for validation
        model_path (str): Path to save the trained model
    
    Returns:
        tuple: (model, history)
    """
    model = create_cnn_model()
    
    history = model.fit(
        x_train, y_train,
        epochs=epochs,
        batch_size=batch_size,
        validation_split=validation_split
    )
    
    if model_path:
        model.save(model_path)
        print(f"Model saved to {model_path}")
    
    return model, history

def train_lightgbm_model(x_train, y_train, num_boost_round=100, model_path=None):
    """
    Train a LightGBM model.
    
    Args:
        x_train (numpy.ndarray): Training features
        y_train (numpy.ndarray): Training labels
        num_boost_round (int): Number of boosting rounds
        model_path (str): Path to save the trained model
    
    Returns:
        lightgbm.Booster: Trained LightGBM model
    """
    # Create LightGBM dataset
    train_data = lgb.Dataset(x_train, label=y_train)
    
    # Set parameters
    params = {
        'boosting_type': 'gbdt',
        'objective': 'binary',
        'metric': 'binary_logloss',
    }
    
    # Train model
    model = lgb.train(params, train_data, num_boost_round=num_boost_round)
    
    if model_path:
        # Save model
        model.save_model(model_path)
        print(f"LightGBM model saved to {model_path}")
    
    return model

def train_nn_dropout_model(x_train, y_train, epochs=100, batch_size=128, validation_split=0.2, model_path=None):
    """
    Train a Neural Network with Dropout.
    
    Args:
        x_train (numpy.ndarray): Training features
        y_train (numpy.ndarray): Training labels
        epochs (int): Number of epochs to train
        batch_size (int): Batch size for training
        validation_split (float): Fraction of data to use for validation
        model_path (str): Path to save the trained model
    
    Returns:
        tuple: (model, history)
    """
    model = create_nn_dropout_model(x_train.shape[1])
    
    history = model.fit(
        x_train, y_train,
        epochs=epochs,
        batch_size=batch_size,
        validation_split=validation_split
    )
    
    if model_path:
        model.save(model_path)
        print(f"Model saved to {model_path}")
    
    return model, history

def load_saved_cnn_model(model_path):
    """
    Load a saved CNN model.
    
    Args:
        model_path (str): Path to the saved model
    
    Returns:
        tensorflow.keras.models.Model: Loaded model
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    return load_model(model_path)

def load_saved_lightgbm_model(model_path):
    """
    Load a saved LightGBM model.
    
    Args:
        model_path (str): Path to the saved model
    
    Returns:
        lightgbm.Booster: Loaded model
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    return lgb.Booster(model_file=model_path)

def predict_malware(model, features, model_type='cnn'):
    """
    Make predictions using a trained model.
    
    Args:
        model: Trained model (CNN, LightGBM, or NN)
        features (numpy.ndarray): Features to predict
        model_type (str): Type of model ('cnn', 'lightgbm', or 'nn')
    
    Returns:
        tuple: (predictions_prob, predictions_binary)
    """
    if model_type.lower() == 'cnn' or model_type.lower() == 'nn':
        predictions_prob = model.predict(features)
    elif model_type.lower() == 'lightgbm':
        predictions_prob = model.predict(features)
    else:
        raise ValueError(f"Unsupported model type: {model_type}")
    
    # Convert probabilities to binary predictions
    predictions_binary = np.where(predictions_prob > 0.5, 1, 0)
    
    return predictions_prob, predictions_binary