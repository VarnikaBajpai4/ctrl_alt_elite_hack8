# main.py - Main Streamlit application
import os
import time
import json
import tempfile
import threading
import subprocess
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
from behavioral_monitor import BehavioralMonitor

# Load environment variables from .env file
load_dotenv()

# Set page configuration
st.set_page_config(
    page_title="Dynamic File Analysis",
    page_icon="🔍",
    layout="wide"
)

# Configure Gemini API
def configure_gemini():
    # Try to get API key from environment or secrets
    api_key = os.environ.get("GEMINI_API_KEY")
    
    if not api_key:
        # Fall back to streamlit secrets if available
        api_key = st.secrets.get("GEMINI_API_KEY") if hasattr(st, "secrets") else None
        
    if not api_key:
        # If still no API key, ask the user
        api_key = st.text_input("Enter your Gemini API key:", type="password")
        if not api_key:
            st.warning("Please enter your Gemini API key to continue.")
            st.stop()
    
    genai.configure(api_key=api_key)
    return genai.GenerativeModel('gemini-1.5-flash')

# Function to analyze behaviors using Gemini
def analyze_with_gemini(behaviors, file_info, model):
    prompt = f"""
    Analyze the following behavioral data collected from a file execution and determine if the file exhibits malicious behavior.
    
    File Information:
    {json.dumps(file_info, indent=2)}
    
    Behavioral Data:
    {json.dumps(behaviors, indent=2)}
    
    Please analyze this data:

    DO NOT FALSELY LABEL ANY STUFF AS MALICIOUS OR SUSPICIOUS UNLESS ANY DEFINITIVE MALICIOUS ACTION. Pls note that you need to look for SUSPICIOUS STUFF. All exe files add files. If you notice something SERIOUSLY SUSPICIOUS LIKE SOME REQUEST TO AN IP THAT LOOKS WEIRD ONLY THEN MARK IT AS MALICIOUS or SUSPICIOUS. We don't want to falsely flag benign files
    STUFF LIKE THIS IS NOT MALICIOUS: Execution from the temporary directory, Creation and deletion of multiple temporary files and directories, Obfuscated command-line arguments passed to the child process tmpf0f7nl8t.tmp., Parent process chain involving cmd.exe, Connection to unknown external IP address (20.7.1.246) on port 443( not every IP is harmful you know), Large file size (4.4 MB) for what appears to be a bootstrapper, Creation of a complex temporary directory structure and subsequent deletion of its contents, Network connections established in other processes.
    
    You are a malware analysis expert tasked with evaluating dynamic analysis results to determine if a file is benign, suspicious, or malicious. Follow these guidelines:

    CLASSIFICATION CRITERIA:

    BENIGN (Default classification):
    - Network connections to well-known legitimate domains or a small number of IPs (1-5) with clear purpose
    - Expected registry modifications limited to the software's own settings
    - File operations primarily in the application's directory or standard user folders
    - Normal process creation patterns related to the application's function

    SUSPICIOUS (Requires multiple indicators):
    - Connections to unusual domains or IPs with no clear legitimate purpose
    - Registry modifications touching autorun locations but with clear attribution
    - File operations creating executables outside application directories
    - Attempts to modify security settings but failing or requiring user permission
    - Unusual process relationships or short-lived processes

    MALICIOUS (Strong indicators needed):
    - High frequency network connections to multiple different IPs/domains (10+ in short period)
    - Connections to known malicious infrastructure or unusual communication patterns (beaconing)
    - Registry modifications that disable security features or establish persistence
    - File operations involving self-replication, hidden files, or tampering with system files
    - Process injection, privilege escalation, or attempts to kill security software
    - Encrypted or obfuscated command execution
    - Unexplained data exfiltration

    ANALYSIS INSTRUCTIONS:
    1. Always begin with the assumption that the file is benign
    2. Evaluate the dynamic analysis data in context of what the application claims to do
    3. Recognize that installers, updaters, and some applications legitimately make system changes
    4. Focus on combinations of suspicious behaviors rather than individual actions
    5. Consider the severity and purpose of each observed activity
    6. Provide clear justification for your classification with specific observations
    7. Recommend additional analysis if behavior is ambiguous


    Provide your analysis in this JSON format:
    {{
        "verdict": "malicious|suspicious|benign",
        "confidence": 0-100,
        "reasoning": "detailed explanation of your reasoning",
        "key_behaviors": ["list", "of", "concerning", "behaviors"],
        "recommendations": ["list", "of", "recommendations"]
    }}
    """
    
    response = model.generate_content(prompt)
    
    try:
        # Extract JSON from the response
        text_content = response.text
        # Look for JSON in the response
        json_start = text_content.find('{')
        json_end = text_content.rfind('}') + 1
        
        if json_start >= 0 and json_end > json_start:
            json_str = text_content[json_start:json_end]
            analysis = json.loads(json_str)
            return analysis
        else:
            # If no JSON found, try to extract it from markdown code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*({[\s\S]*?})\s*```', text_content)
            if json_match:
                analysis = json.loads(json_match.group(1))
                return analysis
            else:
                raise ValueError("No JSON found in response")
    except Exception as e:
        # Fallback if Gemini doesn't return valid JSON
        return {
            "verdict": "error",
            "confidence": 0,
            "reasoning": f"Failed to parse Gemini response: {str(e)}. Raw response: {response.text[:500]}...",
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
            elif file_ext in ['.js']:
                process = subprocess.Popen(['node', file_path],
                                         cwd=temp_dir,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            elif file_ext in ['.sh', '.bash']:
                process = subprocess.Popen(['bash', file_path],
                                         cwd=temp_dir,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            elif file_ext in ['.ps1']:
                if os.name == 'nt':  # Windows only
                    process = subprocess.Popen(['powershell', '-ExecutionPolicy', 'Bypass', '-File', file_path],
                                            cwd=temp_dir,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                else:
                    monitor.stop()
                    return {"error": "PowerShell scripts can only be executed on Windows"}, file_info
            elif file_ext in ['.vbs', '.vbe']:
                if os.name == 'nt':  # Windows only
                    process = subprocess.Popen(['cscript', '//nologo', file_path],
                                            cwd=temp_dir,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                else:
                    monitor.stop()
                    return {"error": "VBScript can only be executed on Windows"}, file_info
            elif file_ext in ['.jar']:
                process = subprocess.Popen(['java', '-jar', file_path],
                                         cwd=temp_dir,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            else:
                # For other files like csv, txt, etc. we'll just report that we can't execute them
                # but we'll still collect any file access patterns
                st.info(f"Note: File type {file_ext} is not directly executable. Monitoring file access only.")
                # Wait a few seconds to capture any file access activity
                time.sleep(5)
                behaviors = monitor.stop()
                return behaviors, file_info
            
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
    uploaded_file = st.file_uploader("Choose a file to analyze", 
                                    )
    
    # Analysis timeout setting
    timeout = st.slider("Analysis timeout (seconds)", min_value=5, max_value=60, value=30)
    
    if uploaded_file:
        # Save the uploaded file to disk
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            temp_file_path = tmp_file.name
        
        st.write(f"Analyzing: {uploaded_file.name}")
        
        # Run analysis in a separate thread to avoid blocking the UI
        with st.spinner("Running file in monitored environment..."):
            behaviors, file_info = run_and_monitor(temp_file_path, timeout=timeout)
        
        # Check if there was an error
        if "error" in behaviors and isinstance(behaviors, dict):
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
                }.get(analysis["verdict"].lower(), "gray")
                
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
                
                # Add tabs for different types of behavioral data
                tabs = st.tabs(["Process Activity", "File System", "Registry", "Network"])
                
                with tabs[0]:
                    st.subheader("Processes Created")
                    st.json(behaviors["processes"])
                    
                    st.subheader("Process Tree")
                    st.json(behaviors["process_tree"])
                
                with tabs[1]:
                    st.subheader("File System Activity")
                    st.json(behaviors["file_system"])
                
                with tabs[2]:
                    st.subheader("Registry Changes")
                    st.json(behaviors["registry"])
                
                with tabs[3]:
                    st.subheader("Network Connections")
                    st.json(behaviors["network"])
        
        # Clean up the temporary file
        os.unlink(temp_file_path)

if __name__ == "__main__":
    main()