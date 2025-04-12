import os
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import TimeSeriesSplit
from sklearn.metrics import roc_auc_score, make_scorer

def load_vectorized_features(data_dir):
    """Load vectorized features from .dat files"""
    X_train = np.fromfile(os.path.join(data_dir, "X_train.dat"), dtype=np.float32)
    y_train = np.fromfile(os.path.join(data_dir, "y_train.dat"), dtype=np.float32)
    X_test = np.fromfile(os.path.join(data_dir, "X_test.dat"), dtype=np.float32)
    y_test = np.fromfile(os.path.join(data_dir, "y_test.dat"), dtype=np.float32)
    
    # Reshape X arrays (assuming feature dimension is known)
    feature_dim = 1237  # Updated to match generate_features.py total dimension
    X_train = X_train.reshape(-1, feature_dim)
    X_test = X_test.reshape(-1, feature_dim)
    
    return X_train, y_train, X_test, y_test

def optimize_model(X_train, y_train):
    """Run grid search to find optimal parameters"""
    # Score by roc auc with focus on low FPR rates
    score = make_scorer(roc_auc_score, max_fpr=5e-3)
    
    # Define search grid
    param_grid = {
        'boosting_type': ['gbdt'],
        'objective': ['binary'],
        'num_iterations': [500, 1000],
        'learning_rate': [0.005, 0.05],
        'num_leaves': [512, 1024, 2048],
        'feature_fraction': [0.5, 0.8, 1.0],
        'bagging_fraction': [0.5, 0.8, 1.0]
    }
    
    model = lgb.LGBMClassifier(boosting_type="gbdt", n_jobs=-1, silent=True)
    
    # Use time series split for validation
    progressive_cv = TimeSeriesSplit(n_splits=3).split(X_train)
    
    grid = GridSearchCV(
        estimator=model,
        cv=progressive_cv,
        param_grid=param_grid,
        scoring=score,
        n_jobs=1,
        verbose=3
    )
    
    grid.fit(X_train, y_train)
    return grid.best_params_

def train_model(X_train, y_train, params=None):
    """Train the LightGBM model"""
    if params is None:
        params = {
            'boosting_type': 'gbdt',
            'objective': 'binary',
            'num_iterations': 1000,
            'learning_rate': 0.05,
            'num_leaves': 1024,
            'feature_fraction': 0.8,
            'bagging_fraction': 0.8
        }
    
    # Create LightGBM dataset
    train_data = lgb.Dataset(X_train, label=y_train)
    
    # Train model
    model = lgb.train(params, train_data)
    return model

def main():
    # Load vectorized features
    data_dir = "vectorized"
    X_train, y_train, X_test, y_test = load_vectorized_features(data_dir)
    
    # Optimize model parameters
    print("Optimizing model parameters...")
    best_params = optimize_model(X_train, y_train)
    print(f"Best parameters: {best_params}")
    
    # Train model with optimized parameters
    print("Training model...")
    model = train_model(X_train, y_train, best_params)
    
    # Save model
    model.save_model("elf_model.txt")
    print("Model saved as elf_model.txt")
    
    # Evaluate on test set
    predictions = model.predict(X_test)
    auc = roc_auc_score(y_test, predictions)
    print(f"Test AUC: {auc:.4f}")

if __name__ == "__main__":
    main() 