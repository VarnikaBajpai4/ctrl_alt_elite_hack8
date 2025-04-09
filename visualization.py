# visualization.py
"""Module for visualization functions."""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn import metrics

def plot_sample_images(images, labels, num_images=25, start_index=0):
    """
    Plot sample images from the dataset.
    
    Args:
        images (numpy.ndarray): Array of images
        labels (numpy.ndarray): Array of labels
        num_images (int): Number of images to plot
        start_index (int): Starting index for images
    """
    classes = ['benign', 'malicious']
    
    plt.figure(figsize=(10, 10))
    
    for i in range(num_images):
        plt.subplot(5, 5, i + 1)
        plt.xticks([])
        plt.yticks([])
        plt.grid(False)
        
        idx = start_index + i
        if idx < len(images):
            plt.imshow(images[idx].reshape(48, 48), cmap='gray')
            plt.xlabel(classes[int(labels[idx])])
    
    plt.tight_layout()
    plt.show()

def plot_learning_curves(history):
    """
    Plot the learning curves for a model.
    
    Args:
        history: Training history from model.fit()
    """
    # Extract the relevant data
    history_df = pd.DataFrame(history.history)
    
    plt.figure(figsize=(15, 5))
    
    # Plot the learning curves for loss
    plt.subplot(1, 2, 1)
    if 'loss' in history_df and 'val_loss' in history_df:
        plt.plot(history_df['loss'], label='Training Loss')
        plt.plot(history_df['val_loss'], label='Validation Loss')
        plt.legend()
        plt.title("Model Loss", fontsize=14)
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
    
    # Plot the learning curves for accuracy
    plt.subplot(1, 2, 2)
    if 'accuracy' in history_df and 'val_accuracy' in history_df:
        plt.plot(history_df['accuracy'], label='Training Accuracy')
        plt.plot(history_df['val_accuracy'], label='Validation Accuracy')
        plt.legend()
        plt.title("Model Accuracy", fontsize=14)
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
    
    plt.tight_layout()
    plt.show()

def plot_confusion_matrix(y_true, y_pred, title="Confusion Matrix"):
    """
    Plot the confusion matrix.
    
    Args:
        y_true (numpy.ndarray): True labels
        y_pred (numpy.ndarray): Predicted labels
        title (str): Title for the plot
    """
    cm = metrics.confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(pd.DataFrame(cm), annot=True, cmap="YlGnBu", fmt='g')
    plt.title(title, y=1.1)
    plt.ylabel('Actual label')
    plt.xlabel('Predicted label')
    plt.show()

def plot_roc_curve(y_true, y_pred_prob, label="Model"):
    """
    Plot the ROC curve.
    
    Args:
        y_true (numpy.ndarray): True labels
        y_pred_prob (numpy.ndarray): Predicted probabilities
        label (str): Label for the curve
    """
    fpr, tpr, threshold = metrics.roc_curve(y_true, y_pred_prob)
    auc = metrics.roc_auc_score(y_true, y_pred_prob)
    
    plt.figure(figsize=(10, 8))
    plt.title(f'Receiver Operating Characteristic - {label}')
    plt.plot(fpr, tpr, label=f'{label} (AUC = {auc:.2f})')
    plt.plot([0, 1], ls="--")
    plt.plot([0, 0], [1, 0], c=".7")
    plt.plot([1, 1], [1, 0], c=".7")
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    plt.legend()
    plt.show()
    
    print(f'AUC: {auc:.2f}')
    
    return auc