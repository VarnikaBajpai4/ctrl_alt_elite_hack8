from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import pandas as pd

# Load predictions
df = pd.read_csv("ember_test_predictions.csv")

# Define thresholds and convert to predicted labels
threshold = 0.5
pred_labels = (df["malicious_prob"] >= threshold).astype(int)
true_labels = df["true_label"].astype(int)

# Classification report
print("📊 Classification Report:")
print(classification_report(true_labels, pred_labels))

# Confusion matrix
print("📉 Confusion Matrix:")
print(confusion_matrix(true_labels, pred_labels))

# AUC score
print("🔥 ROC AUC Score:", roc_auc_score(true_labels, df["malicious_prob"]))
