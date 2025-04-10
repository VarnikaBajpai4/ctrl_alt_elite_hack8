# main.py - Main Streamlit application
import os
import time
import json
import tempfile
import threading
import subprocess
import streamlit as st
import google.generativeai as genai
from behavioral_monitor import BehavioralMonitor

# Set page configuration
st.set_page_config(
    page_title="Dynamic File Analysis",
    page_icon="🔍",
    layout="wide"
)

# Configure Gemini API
def configure_gemini():
    api_key = st.secrets.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        api_key = st.text_input("Enter your Gemini API key:", type="password")
        if not api_key:
            st.warning("Please enter your Gemini API key to continue.")
            st.stop()
    
    genai.configure(api_key=api_key)
    return genai.GenerativeModel('gemini-1.5-pro')

# Function to analyze behaviors using Gemini
def analyze_with_gemini(behaviors, file_info, model):
    prompt = f"""
    Analyze the following behavioral data collected from a file execution and determine if the file exhibits malicious behavior.
    
    File Information:
    {json.dumps(file_info, indent=2)}
    
    Behavioral Data:
    {json.dumps(behaviors, indent=2)}
    
    Please analyze this data for signs of:
    1. Suspicious process activities (unusual process creation, injection techniques)
    2. Suspicious file operations (creating executables, modifying system files)
    3. Registry modifications that suggest persistence
    4. Unusual network connections or data exfiltration attempts
    5. Any other behaviors that indicate malicious intent
    
    Provide your analysis in this JSON format:
    {
        "verdict": "malicious|suspicious|benign",
        "confidence": 0-100,
        "reasoning": "detailed explanation of your reasoning",
        "key_behaviors": ["list", "of", "concerning", "behaviors"],
        "recommendations": ["list", "of", "recommendations"]
    }
    """
    
    response = model.generate_content(prompt)
    
    try:
        analysis = json.loads(response.text)
        return analysis
    except json.JSONDecodeError:
        # Fallback if Gemini doesn't return valid JSON
        return {
            "verdict": "error",
            "confidence": 0,
            "reasoning": "Failed to parse Gemini response. Raw response: " + response.text,
            "key_behaviors": [],
            "recommendations": ["Try analyzing again", "Check the raw behavioral data manually"]
        }

# Function to run file in a controlled environment and monitor behavior
def run_and_monitor(file_path, timeout=30):
    with tempfile.TemporaryDirectory() as temp_dir:
        monitor = BehavioralMonitor(temp_dir)
        
        # Start monitoring
        monitor.start()
        
        # Run the file based on extension
        file_ext = os.path.splitext(file_path)[1].lower()
        file_info = {
            "name": os.path.basename(file_path),
            "extension": file_ext,
            "size": os.path.getsize(file_path),
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        try:
            if file_ext in ['.exe', '.bat', '.cmd']:
                process = subprocess.Popen([file_path], 
                                         shell=True, 
                                         cwd=temp_dir,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            elif file_ext in ['.docx', '.xlsx', '.pptx', '.pdf']:
                # For documents, we might use default applications
                # This is simplified; in reality, you might need a more secure sandbox
                if os.name == 'nt':  # Windows
                    process = subprocess.Popen(['start', '', file_path], shell=True)
                else:  # Linux/Mac
                    process = subprocess.Popen(['xdg-open' if os.name != 'darwin' else 'open', file_path])
            elif file_ext in ['.py']:
                process = subprocess.Popen(['python', file_path], 
                                         cwd=temp_dir,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            else:
                # For other files, we'll just report that we can't execute them
                monitor.stop()
                return {"error": f"Unsupported file type: {file_ext}"}, file_info
            
            # Wait for the process to finish or timeout
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
            
            # Stop monitoring and get results
            behaviors = monitor.stop()
            return behaviors, file_info
            
        except Exception as e:
            monitor.stop()
            return {"error": str(e)}, file_info

# Main Streamlit app
def main():
    st.title("Dynamic File Analysis System")
    st.write("Upload a file to analyze its behavior and detect potential malicious activity.")
    
    # Initialize Gemini model
    with st.spinner("Initializing Gemini..."):
        model = configure_gemini()
    
    # File upload
    uploaded_file = st.file_uploader("Choose a file to analyze", type=["exe", "bat", "cmd", "py", "docx", "xlsx", "pptx", "pdf", "csv", "txt"])
    
    if uploaded_file:
        # Save the uploaded file to disk
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            temp_file_path = tmp_file.name
        
        st.write(f"Analyzing: {uploaded_file.name}")
        
        # Run analysis in a separate thread to avoid blocking the UI
        with st.spinner("Running file in monitored environment..."):
            behaviors, file_info = run_and_monitor(temp_file_path)
        
        # Check if there was an error
        if "error" in behaviors:
            st.error(f"Error during analysis: {behaviors['error']}")
        else:
            # Analyze with Gemini
            with st.spinner("Analyzing behaviors with Gemini..."):
                analysis = analyze_with_gemini(behaviors, file_info, model)
            
            # Display results
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Analysis Results")
                verdict_color = {
                    "malicious": "red",
                    "suspicious": "orange",
                    "benign": "green",
                    "error": "gray"
                }.get(analysis["verdict"], "gray")
                
                st.markdown(f"<h3 style='color: {verdict_color};'>Verdict: {analysis['verdict'].upper()}</h3>", unsafe_allow_html=True)
                st.progress(analysis["confidence"] / 100)
                st.write(f"Confidence: {analysis['confidence']}%")
                
                st.subheader("Reasoning")
                st.write(analysis["reasoning"])
                
                st.subheader("Key Behaviors")
                for behavior in analysis["key_behaviors"]:
                    st.write(f"• {behavior}")
                    
                st.subheader("Recommendations")
                for rec in analysis["recommendations"]:
                    st.write(f"• {rec}")
            
            with col2:
                st.subheader("Raw Behavioral Data")
                st.json(behaviors)
        
        # Clean up the temporary file
        os.unlink(temp_file_path)

if __name__ == "__main__":
    main()