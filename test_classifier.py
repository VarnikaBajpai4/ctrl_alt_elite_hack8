import os
import pandas as pd
import joblib
from malware_classifier import extract_features
import re
from pathlib import Path

def sanitize_path(path):
    """Sanitize file path to handle invalid characters."""
    # Convert to Path object and normalize
    path = Path(path)
    # Get the directory and filename separately
    dir_path = path.parent
    filename = path.name
    # Sanitize filename (remove or replace invalid characters)
    sanitized_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Reconstruct path
    return str(dir_path / sanitized_filename)

def load_model():
    """Load the trained model and vectorizer."""
    try:
        model = joblib.load("models/malware_classifier.joblib")
        vectorizer = joblib.load("models/vectorizer.joblib")
        return model, vectorizer
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        print("Please make sure you have trained the model first by running malware_classifier.py")
        return None, None

def classify_file(file_path, model, vectorizer):
    """Classify a single file."""
    try:
        # Sanitize the file path
        sanitized_path = sanitize_path(file_path)
        
        # Extract features
        features = extract_features(sanitized_path)
        if not features:
            return None
        
        # Convert to DataFrame
        df = pd.DataFrame([features])
        
        # Vectorize the content
        X = vectorizer.transform(df['content'])
        
        # Predict
        prediction = model.predict(X)[0]
        probability = model.predict_proba(X)[0]
        
        return {
            'prediction': 'MALWARE' if prediction == 1 else 'BENIGN',
            'malware_probability': probability[1],
            'benign_probability': probability[0]
        }
    except Exception as e:
        print(f"Error classifying {file_path}: {str(e)}")
        return None

def test_directory(test_dir):
    """Test all files in a directory."""
    model, vectorizer = load_model()
    if not model or not vectorizer:
        return
    
    results = []
    error_count = 0
    
    for file_type in ['bat', 'js', 'ps1']:
        type_dir = os.path.join(test_dir, file_type)
        if not os.path.exists(type_dir):
            print(f"Directory not found: {type_dir}")
            continue
            
        # Test benign files
        benign_dir = os.path.join(type_dir, 'benign')
        if os.path.exists(benign_dir):
            for file in os.listdir(benign_dir):
                if file.endswith(f'.{file_type}'):
                    file_path = os.path.join(benign_dir, file)
                    result = classify_file(file_path, model, vectorizer)
                    if result:
                        results.append({
                            'file': file,
                            'type': file_type,
                            'actual': 'BENIGN',
                            **result
                        })
                    else:
                        error_count += 1
        
        # Test malware files
        malware_dir = os.path.join(type_dir, 'malware')
        if os.path.exists(malware_dir):
            for file in os.listdir(malware_dir):
                if file.endswith(f'.{file_type}'):
                    file_path = os.path.join(malware_dir, file)
                    result = classify_file(file_path, model, vectorizer)
                    if result:
                        results.append({
                            'file': file,
                            'type': file_type,
                            'actual': 'MALWARE',
                            **result
                        })
                    else:
                        error_count += 1
    
    # Print results
    if results:
        print("\nClassification Results:")
        print("-" * 80)
        print(f"{'File':<30} {'Type':<8} {'Actual':<10} {'Predicted':<10} {'Malware Prob':<12} {'Benign Prob':<12}")
        print("-" * 80)
        
        for result in results:
            print(f"{result['file'][:30]:<30} {result['type']:<8} {result['actual']:<10} "
                  f"{result['prediction']:<10} {result['malware_probability']:.4f}        "
                  f"{result['benign_probability']:.4f}")
        
        # Calculate accuracy
        correct = sum(1 for r in results if r['actual'] == r['prediction'])
        total = len(results)
        print(f"\nOverall Accuracy: {correct/total:.2%}")
        print(f"Successfully classified: {len(results)} files")
        print(f"Failed to classify: {error_count} files")
    else:
        print("No files were successfully classified. Please check your testing directory structure.")

def main():
    test_dir = "testing"
    if not os.path.exists(test_dir):
        print(f"Testing directory '{test_dir}' not found.")
        return
    
    test_directory(test_dir)

if __name__ == "__main__":
    main() 