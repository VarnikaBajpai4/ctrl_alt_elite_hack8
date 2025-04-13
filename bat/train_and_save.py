import numpy as np
import lightgbm as lgb
import os

def load_training_data():
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    vectorized_dir = os.path.join(script_dir, "vectorized")
    
    # Load the vectorized data
    X_train = np.fromfile(os.path.join(vectorized_dir, "X_train.dat"), dtype=np.float32)
    y_train = np.fromfile(os.path.join(vectorized_dir, "y_train.dat"), dtype=np.float32)
    
    # Calculate the correct feature dimension
    num_samples = len(y_train)
    feature_dim = len(X_train) // num_samples
    
    # Reshape X_train
    X_train = X_train.reshape(num_samples, feature_dim)
    
    print(f"Loaded {num_samples} samples with {feature_dim} features each")
    return X_train, y_train

def train_model():
    print("Loading training data...")
    X_train, y_train = load_training_data()
    
    print(f"Loaded {len(X_train)} training samples")
    print("Training model...")
    
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.9
    }
    
    train_data = lgb.Dataset(X_train, label=y_train)
    model = lgb.train(params, train_data, num_boost_round=100)
    
    # Save model to vectorized directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "vectorized", "bat_model.txt")
    model.save_model(model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_model()