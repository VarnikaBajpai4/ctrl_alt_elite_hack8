import os
import time
import json
import tempfile
import subprocess
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
from behavioral_monitor import BehavioralMonitor

load_dotenv()

st.set_page_config(
    page_title="Dynamic File Analysis",
    page_icon="🔍",
    layout="wide"
)

def configure_gemini():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        api_key = st.secrets.get("GEMINI_API_KEY") if hasattr(st, "secrets") else None
    if not api_key:
        api_key = st.text_input("Enter your Gemini API key:", type="password")
        if not api_key:
            st.warning("Please enter your Gemini API key to continue.")
            st.stop()
    genai.configure(api_key=api_key)
    return genai.GenerativeModel('gemini-1.5-flash')

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
        text_content = response.text
        json_start = text_content.find('{')
        json_end = text_content.rfind('}') + 1
        if json_start >= 0 and json_end > json_start:
            json_str = text_content[json_start:json_end]
            analysis = json.loads(json_str)
            return analysis
        else:
            import re
            json_match = re.search(r'```(?:json)?\s*({[\s\S]*?})\s*```', text_content)
            if json_match:
                analysis = json.loads(json_match.group(1))
                return analysis
            else:
                raise ValueError("No JSON found in response")
    except Exception as e:
        return {
            "verdict": "error",
            "confidence": 0,
            "reasoning": f"Failed to parse Gemini response: {str(e)}. Raw response: {response.text[:500]}...",
            "key_behaviors": [],
            "recommendations": ["Try analyzing again", "Check the raw behavioral data manually"]
        }

def run_and_monitor(file_path, timeout=30):
    with tempfile.TemporaryDirectory() as temp_dir:
        monitor = BehavioralMonitor(temp_dir)
        monitor.start()
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
                if os.name == 'nt':
                    process = subprocess.Popen(['start', '', file_path], shell=True)
                else:
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
                if os.name == 'nt':
                    process = subprocess.Popen(['powershell', '-ExecutionPolicy', 'Bypass', '-File', file_path],
                                            cwd=temp_dir,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                else:
                    monitor.stop()
                    return {"error": "PowerShell scripts can only be executed on Windows"}, file_info
            elif file_ext in ['.vbs', '.vbe']:
                if os.name == 'nt':
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
                st.info(f"Note: File type {file_ext} is not directly executable. Monitoring file access only.")
                time.sleep(5)
                behaviors = monitor.stop()
                return behaviors, file_info
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
            behaviors = monitor.stop()
            # analysis_dir = os.path.join("analysis_results", os.path.basename(file_path))
            # os.makedirs(analysis_dir, exist_ok=True)
            # json_path = os.path.join(analysis_dir, "behavioral_data.json")
            # monitor.save_to_json(json_path)
            return behaviors, file_info
        except Exception as e:
            monitor.stop()
            return {"error": str(e)}, file_info

def format_final_result(analysis):
    """Format the final result based on confidence threshold."""
    classification = "Malicious" if analysis["confidence"] > 90 else "Benign"
    
    result = {
        "classification": classification,
        "reasoning": analysis["reasoning"]
    }
    
    return result

def analyze_file(file_path = r"C:\Users\meena\Downloads\case studies final.pdf", timeout=30):
    model = configure_gemini()

    # Run and monitor the file behavior
    print(f"Running file in monitored environment with timeout of {timeout} seconds...")
    behaviors, file_info = run_and_monitor(file_path, timeout=timeout)
    
    # Check for errors in behaviors
    if isinstance(behaviors, dict) and "error" in behaviors:
        print(f"Error during analysis: {behaviors['error']}")
        return
    
    # Analyze behaviors with Gemini
    print("Analyzing behaviors with Gemini...")
    analysis = analyze_with_gemini(behaviors, file_info, model)
    
    # Format the final result
    final_result = format_final_result(analysis)
    
    # Output the result
    print("\n==== ANALYSIS RESULTS ====")
    print(f"Classification: {final_result['classification']}")
    print(f"\nReasoning: {final_result['reasoning']}")


def main():
    analyze_file()

if __name__ == "__main__":
    main()