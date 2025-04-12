import numpy as np
import lightgbm as lgb
import os

def load_training_data():
    """Load the vectorized training data"""
    # Get the size of the training data
    X_train_size = os.path.getsize('vectorized/X_train.dat')
    y_train_size = os.path.getsize('vectorized/y_train.dat')
    
    # Calculate number of samples
    num_samples = y_train_size // 4  # 4 bytes per float32
    feature_dim = 1237  # Your feature dimension
    
    # Load the data with correct shape
    X_train = np.memmap('vectorized/X_train.dat', dtype=np.float32, mode='r', 
                        shape=(num_samples, feature_dim))
    y_train = np.memmap('vectorized/y_train.dat', dtype=np.float32, mode='r', 
                        shape=(num_samples,))
    
    return X_train, y_train

def train_model():
    """Train the LightGBM model and save it"""
    print("Loading training data...")
    X_train, y_train = load_training_data()
    
    print(f"Loaded {len(X_train)} training samples")
    print("Training model...")
    
    # LightGBM parameters
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.9
    }
    
    # Create dataset
    train_data = lgb.Dataset(X_train, label=y_train)
    
    # Train model
    model = lgb.train(params, train_data, num_boost_round=100)
    
    # Save model
    model_path = 'vectorized/elf_model.txt'
    model.save_model(model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_model() 