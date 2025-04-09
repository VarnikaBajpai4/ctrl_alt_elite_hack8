# config.py
"""Configuration parameters for the malware detection system."""

# Data parameters
TRAIN_SHAPE = (800000, 2381)
TEST_SHAPE = (200000, 2381)
DATA_TYPE = 'float32'
IMAGE_SHAPE = (48, 48)
INPUT_SHAPE = (48, 48, 1)

# Training parameters
VALIDATION_SPLIT = 0.2
EPOCHS = 5
BATCH_SIZE = 128

# Model paths
CNN_MODEL_PATH = 'models/cnn_malware_classification.h5'
LGBM_MODEL_PATH = 'models/lightgbm_model.txt'
NN_MODEL_PATH = 'models/nn_dropout_model.h5'

# Dataset paths (should be configured by the user)
DATASET_PATH = None  # To be configured by the user