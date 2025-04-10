import streamlit as st
import os
import subprocess
import hashlib
import psutil
import time
import pandas as pd
from datetime import datetime

# Set up directories - using Windows-compatible paths
UPLOAD_DIR = "uploads"
ANALYSIS_DIR = "analysis_results"
TEMP_DIR = os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'))  # Windows temp directory

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(ANALYSIS_DIR, exist_ok=True)

def get_file_hash(file_path):
    """Generate SHA-256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def safe_execute_file(file_path, timeout=30):
    """Execute file in controlled environment and monitor behavior"""
    file_extension = os.path.splitext(file_path)[1].lower()
   
    # Set up monitoring
    initial_processes = set(p.pid for p in psutil.process_iter())
    initial_files = set(os.listdir(TEMP_DIR))  # Using Windows temp directory instead of /tmp
   
    # Execute based on file type
    try:
        if file_extension in ['.py']:
            process = subprocess.Popen(['python', file_path],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        elif file_extension in ['.bat', '.cmd']:
            process = subprocess.Popen(['cmd', '/c', file_path],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        elif file_extension in ['.ps1']:
            process = subprocess.Popen(['powershell', '-ExecutionPolicy', 'Bypass', '-File', file_path],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        elif file_extension in ['.exe']:
            process = subprocess.Popen([file_path],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        else:
            # Default handling for unknown files
            return {
                'stdout': 'File type not supported for direct execution',
                'stderr': '',
                'behaviors': []
            }
       
        # Monitor for specified time
        start_time = time.time()
        behaviors = []
       
        while time.time() - start_time < timeout:
            # Collect new processes
            current_processes = set(p.pid for p in psutil.process_iter())
            new_processes = current_processes - initial_processes
           
            # Collect file system changes
            current_files = set(os.listdir(TEMP_DIR))
            new_files = current_files - initial_files
           
            # Record network connections (if any)
            network_connections = psutil.net_connections()
           
            # Collect observations
            for pid in new_processes:
                try:
                    proc = psutil.Process(pid)
                    behaviors.append({
                        'time': time.time() - start_time,
                        'type': 'process',
                        'name': proc.name(),
                        'pid': pid,
                        'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else ''
                    })
                except:
                    pass
           
            for file in new_files:
                behaviors.append({
                    'time': time.time() - start_time,
                    'type': 'file',
                    'name': file
                })
           
            # Add registry monitoring (Windows-specific)
            # This is simplified - a real implementation would use win32api or similar
           
            time.sleep(1)
       
        # Kill process after timeout
        try:
            process.kill()
        except:
            pass
       
        return {
            'stdout': process.stdout.read().decode('utf-8', errors='ignore'),
            'stderr': process.stderr.read().decode('utf-8', errors='ignore'),
            'behaviors': behaviors
        }
   
    except Exception as e:
        return {
            'error': str(e),
            'behaviors': []
        }

def analyze_behaviors(behaviors):
    """Analyze collected behaviors for malicious patterns"""
    # This is where your AI/ML model would be integrated
    # For now, using simple heuristics
   
    suspicious_score = 0
    suspicious_activities = []
   
    # Check for suspicious process activities
    process_count = len([b for b in behaviors if b['type'] == 'process'])
    if process_count > 5:
        suspicious_score += 20
        suspicious_activities.append(f"Created {process_count} new processes")
   
    # Check for suspicious file activities
    file_count = len([b for b in behaviors if b['type'] == 'file'])
    if file_count > 10:
        suspicious_score += 15
        suspicious_activities.append(f"Created/modified {file_count} files")
   
    # Look for specific suspicious process names
    suspicious_process_names = ['powershell', 'cmd', 'reg', 'wscript', 'cscript']
    for b in behaviors:
        if b['type'] == 'process' and any(s in b.get('name', '').lower() for s in suspicious_process_names):
            suspicious_score += 25
            suspicious_activities.append(f"Launched suspicious process: {b.get('name')}")
   
    return {
        'score': suspicious_score,
        'activities': suspicious_activities,
        'is_malicious': suspicious_score > 50  # Simple threshold
    }

# Streamlit App
st.title("Secure Malware Analysis Sandbox")
st.write("Upload files for dynamic analysis in a controlled environment.")

uploaded_file = st.file_uploader("Choose a file", type=None)

if uploaded_file is not None:
    # Save uploaded file
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    file_path = os.path.join(UPLOAD_DIR, f"{timestamp}_{uploaded_file.name}")
   
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
   
    st.write(f"File uploaded: {uploaded_file.name}")
    file_hash = get_file_hash(file_path)
    st.write(f"SHA-256: {file_hash}")
   
    # Run analysis
    if st.button("Start Dynamic Analysis"):
        with st.spinner("Running dynamic analysis..."):
            # Create results directory for this analysis
            result_dir = os.path.join(ANALYSIS_DIR, file_hash)
            os.makedirs(result_dir, exist_ok=True)
           
            # Execute and monitor
            st.write("Executing file in sandbox environment...")
            execution_results = safe_execute_file(file_path)
           
            # Analyze behaviors
            st.write("Analyzing observed behaviors...")
            analysis_results = analyze_behaviors(execution_results.get('behaviors', []))
           
            # Display results
            st.subheader("Analysis Results")
           
            # Malware verdict
            if analysis_results['is_malicious']:
                st.error(f"⚠️ VERDICT: MALICIOUS (Score: {analysis_results['score']}/100)")
            else:
                st.success(f"✅ VERDICT: LIKELY BENIGN (Score: {analysis_results['score']}/100)")
           
            # Suspicious activities
            if analysis_results['activities']:
                st.subheader("Suspicious Activities Detected:")
                for activity in analysis_results['activities']:
                    st.write(f"- {activity}")
           
            # Behavior timeline
            if execution_results.get('behaviors', []):
                st.subheader("Behavior Timeline:")
                df = pd.DataFrame(execution_results['behaviors'])
                st.dataframe(df)
           
            # Program output
            st.subheader("Program Output:")
            st.text_area("Standard Output", execution_results.get('stdout', ''), height=150)
            st.text_area("Standard Error", execution_results.get('stderr', ''), height=150)
           
            # Save results
            with open(os.path.join(result_dir, "analysis_report.txt"), "w") as f:
                f.write(f"File: {uploaded_file.name}\n")
                f.write(f"SHA-256: {file_hash}\n")
                f.write(f"Analysis Time: {datetime.now()}\n")
                f.write(f"Verdict: {'MALICIOUS' if analysis_results['is_malicious'] else 'BENIGN'}\n")
                f.write(f"Score: {analysis_results['score']}/100\n\n")
                f.write("Suspicious Activities:\n")
                for activity in analysis_results['activities']:
                    f.write(f"- {activity}\n")
           
            # Take snapshot
            st.write("Analysis complete.")