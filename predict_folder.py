import os
import joblib
import pandas as pd
from pathlib import Path
from malware_classifier import extract_features

def load_model():
    """Load the trained model and vectorizer."""
    try:
        model = joblib.load("models/malware_classifier.joblib")
        vectorizer = joblib.load("models/vectorizer.joblib")
        return model, vectorizer
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return None, None

def predict_file(file_path, model, vectorizer):
    """Predict if a single file is malware or benign."""
    features = extract_features(file_path)
    if not features:
        return None
    
    # Convert features to DataFrame
    df = pd.DataFrame([features])
    
    # Vectorize the content
    X = vectorizer.transform(df['content'])
    
    # Make prediction
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]
    
    return {
        'prediction': 'MALWARE' if prediction == 1 else 'BENIGN',
        'malware_probability': probability[1],
        'benign_probability': probability[0],
        'features': features
    }

def predict_directory(folder_path):
    """Predict all files in a directory."""
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        return
    
    results = []
    
    # Get all files in the directory and subdirectories
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(('.bat', '.js', '.ps1')):
                file_path = os.path.join(root, file)
                result = predict_file(file_path, model, vectorizer)
                if result:
                    results.append({
                        'file': file,
                        'path': os.path.relpath(file_path, folder_path),
                        'type': os.path.splitext(file)[1][1:],  # Get extension without dot
                        **result
                    })
    
    return results

def print_results(results):
    """Print prediction results in a formatted way."""
    if not results:
        print("No results to display.")
        return
    
    print("\nPrediction Results:")
    print("-" * 120)
    print(f"{'File':<30} {'Type':<8} {'Prediction':<10} {'Malware Prob':<12} {'Benign Prob':<12} {'Path':<40}")
    print("-" * 120)
    
    for result in results:
        print(f"{result['file'][:30]:<30} {result['type']:<8} {result['prediction']:<10} "
              f"{result['malware_probability']:.4f}      {result['benign_probability']:.4f}      "
              f"{result['path']}")
    
    # Calculate statistics
    total = len(results)
    malware_count = sum(1 for r in results if r['prediction'] == 'MALWARE')
    benign_count = total - malware_count
    
    print("\nSummary:")
    print(f"Total files analyzed: {total}")
    print(f"Predicted malware: {malware_count}")
    print(f"Predicted benign: {benign_count}")

def main():
    # Specify the folder to analyze here
    folder_to_analyze = R"C:\\Users\\meena\\Downloads\\scripting_model\\testing\\js\\benign"  # Replace this with your folder path
    
    if not os.path.exists(folder_to_analyze):
        print(f"Folder '{folder_to_analyze}' not found.")
        return
    
    print(f"Analyzing files in: {folder_to_analyze}")
    results = predict_directory(folder_to_analyze)
    print_results(results)

if __name__ == "__main__":
    main() 