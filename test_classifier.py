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

def test_file(file_path, model, vectorizer):
    """Test a single file and return prediction."""
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

def test_directory(test_dir):
    """Test all files in a directory."""
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        return
    
    results = []
    
    for file_type in ['bat', 'js', 'ps1']:
        type_dir = os.path.join(test_dir, file_type)
        if not os.path.exists(type_dir):
            continue
            
        # Test benign files
        benign_dir = os.path.join(type_dir, 'benign')
        if os.path.exists(benign_dir):
            for file in os.listdir(benign_dir):
                if file.endswith(f'.{file_type}'):
                    file_path = os.path.join(benign_dir, file)
                    result = test_file(file_path, model, vectorizer)
                    if result:
                        results.append({
                            'file': file,
                            'type': file_type,
                            'actual': 'BENIGN',
                            **result
                        })
        
        # Test malware files
        malware_dir = os.path.join(type_dir, 'malware')
        if os.path.exists(malware_dir):
            for file in os.listdir(malware_dir):
                if file.endswith(f'.{file_type}'):
                    file_path = os.path.join(malware_dir, file)
                    result = test_file(file_path, model, vectorizer)
                    if result:
                        results.append({
                            'file': file,
                            'type': file_type,
                            'actual': 'MALWARE',
                            **result
                        })
    
    return results

def print_results(results):
    """Print test results in a formatted way."""
    if not results:
        print("No results to display.")
        return
    
    print("\nTest Results:")
    print("-" * 100)
    print(f"{'File':<30} {'Type':<8} {'Actual':<10} {'Prediction':<10} {'Malware Prob':<12} {'Benign Prob':<12}")
    print("-" * 100)
    
    for result in results:
        print(f"{result['file'][:30]:<30} {result['type']:<8} {result['actual']:<10} "
              f"{result['prediction']:<10} {result['malware_probability']:.4f}      "
              f"{result['benign_probability']:.4f}")
    
    # Calculate accuracy
    correct = sum(1 for r in results if r['actual'] == r['prediction'])
    total = len(results)
    accuracy = correct / total if total > 0 else 0
    
    print("\nSummary:")
    print(f"Total files tested: {total}")
    print(f"Correct predictions: {correct}")
    print(f"Accuracy: {accuracy:.4f}")

def main():
    test_dir = "testing"
    
    if not os.path.exists(test_dir):
        print(f"Testing directory '{test_dir}' not found.")
        return
    
    print("Testing files...")
    results = test_directory(test_dir)
    print_results(results)

if __name__ == "__main__":
    main() 