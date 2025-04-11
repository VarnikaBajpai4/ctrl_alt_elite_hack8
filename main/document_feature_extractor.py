import re
import os
import zipfile
import binascii
import json
import google.generativeai as genai
from dotenv import load_dotenv
from oletools.olevba import VBA_Parser
from olefile import isOleFile, OleFileIO
from oletools.crypto import is_encrypted
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from io import StringIO
import subprocess
from typing import Dict, List, Any

class DocumentAnalyzer:
    def __init__(self):
        # Load environment variables from ML_Models/.env
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        load_dotenv(env_path)
        
        # Initialize Gemini
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        self.model = genai.GenerativeModel("models/gemini-1.5-flash")
        
        self.known_headers = {
            "D0CF11E0A1B11AE1": "OLE Compound File",
            "4D5A": "Windows Executable",
            "25504446": "PDF Document",
            "504B0304": "ZIP Archive",
            "7B5C727466": "RTF Document",
        }
        
        self.suspicious_keywords = [
            "Shell", "CreateObject", "WScript.Shell", "powershell", "cmd.exe",
            "AutoOpen", "Document_Open", "Workbook_Open", "ExecuteExcel4Macro",
            "GetObject", "Run", "URLDownloadToFile", "Msxml2.XMLHTTP"
        ]

    def fetch_urls(self, buffer: str) -> List[str]:
        urls = re.findall(r"http[s]?://[a-zA-Z0-9./?=_%:-]*", buffer)
        return list(set(urls))

    def detect_dde(self, text: str) -> bool:
        return "DDEAUTO" in text or bool(re.search(r"DDE\s*\(|DDEAUTO", text, re.IGNORECASE))

    def detect_suspicious_keywords(self, text: str) -> List[str]:
        return [k for k in self.suspicious_keywords if k.lower() in text.lower()]

    def binary_analysis(self, name: str, data: bytes) -> Dict[str, str]:
        header = binascii.hexlify(data[:12]).upper().decode()
        for sig, desc in self.known_headers.items():
            if header.startswith(sig):
                return {"name": name, "type": desc}
        return {"name": name, "type": "Unknown binary"}

    def analyze_zip_structure(self, filepath: str) -> Dict[str, Any]:
        result = {"files": [], "binary_analysis": []}
        try:
            zipdoc = zipfile.ZipFile(filepath)
            result["files"] = zipdoc.namelist()
            
            for name in zipdoc.namelist():
                if "embedding" in name or name.endswith(".bin"):
                    result["binary_analysis"].append(self.binary_analysis(name, zipdoc.read(name)))
        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_ole_streams(self, filepath: str) -> Dict[str, Any]:
        result = {"streams": [], "urls": []}
        try:
            ole = OleFileIO(filepath)
            result["streams"] = ["/".join(stream) for stream in ole.listdir()]
            
            for stream in ole.listdir():
                data = ole.openstream(stream).read()
                strings = re.findall(rb"[a-zA-Z0-9:/\\._-]{6,}", data)
                for s in strings:
                    if b"http" in s:
                        result["urls"].append(s.decode('latin1'))
            ole.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_macros(self, filepath: str) -> Dict[str, Any]:
        result = {"vba_macros": [], "xlm_macros": [], "suspicious_keywords": [], "dde_detected": False, "urls": []}
        try:
            vbaparser = VBA_Parser(filepath)
            
            if vbaparser.detect_vba_macros():
                for (_, _, fname, code) in vbaparser.extract_macros():
                    macro_info = {
                        "name": fname,
                        "code_preview": code.strip()[:1000],
                        "suspicious_keywords": self.detect_suspicious_keywords(code),
                        "dde_detected": self.detect_dde(code),
                        "urls": self.fetch_urls(code)
                    }
                    result["vba_macros"].append(macro_info)
            
            if vbaparser.detect_xlm_macros():
                for macro in vbaparser.xlm_macros:
                    macro_info = {
                        "code_preview": macro.strip()[:1000],
                        "suspicious_keywords": self.detect_suspicious_keywords(macro),
                        "dde_detected": self.detect_dde(macro),
                        "urls": self.fetch_urls(macro)
                    }
                    result["xlm_macros"].append(macro_info)
        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_rtf(self, filepath: str) -> Dict[str, Any]:
        result = {"patterns": [], "verdict_keywords": set()}
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                content = f.read()

            patterns = [
                (r'%[0-9A-Fa-f]{2,}', "Hex-encoded obfuscation", "obfuscation"),
                (r'Enable Editing', "Lure to enable editing (social engineering)", "phishing"),
                (r'\\objdata', "Embedded OLE object", "embedding"),
                (r'\\bin', "Binary block in RTF", "binary"),
                (r'\\pict', "Embedded image (can hide shellcode)", "embedding"),
                (r'objautlink', "Auto-executing object link", "execution"),
                (r'nonshppict', "Suspicious shape image trigger", "obfuscation"),
                (r'DDEAUTO|DDE', "DDE execution trigger", "execution"),
                (r'URLMON\.DLL', "URL handling library (download behavior)", "download"),
                (r'MSHTML\.DLL', "HTML rendering library (IE exploit)", "exploit"),
                (r'OLE32\.DLL', "OLE automation trigger", "exploit"),
                (r'SHELL32\.DLL', "Shell execution from embedded objects", "exploit"),
                (r'pkgobj|OLE Package', "Executable packaged as embedded object", "embedding"),
                (r'EQUATION\.3|EQNEDT32', "Equation editor exploit (CVE-2017-11882)", "exploit"),
                (r'ActiveX|CLSID|ClassID', "Embedded control object", "exploit"),
                (r'rundll32\.exe', "Shell execution via DLLs", "execution"),
                (r'cmd\.exe|powershell', "Command-line payloads", "payload"),
            ]

            for pattern, desc, tag in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    result["verdict_keywords"].add(tag)
                    result["patterns"].append({
                        "pattern": pattern[:40],
                        "description": desc,
                        "count": len(matches)
                    })

        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_pdf(self, filepath: str) -> Dict[str, Any]:
        result = {"metadata": {}, "urls": [], "dde_detected": False, "suspicious_keywords": []}
        try:
            with open(filepath, "rb") as f:
                parser = PDFParser(f)
                doc = PDFDocument(parser)
                if doc.info:
                    result["metadata"] = {str(k): str(v) for k, v in doc.info[0].items()}
                output = StringIO()
                rsrcmgr = PDFResourceManager()
                device = TextConverter(rsrcmgr, output, laparams=LAParams())
                interpreter = PDFPageInterpreter(rsrcmgr, device)
                for page in PDFPage.create_pages(doc):
                    interpreter.process_page(page)

                text = output.getvalue()
                device.close()
                output.close()

                result["urls"] = self.fetch_urls(text)
                result["dde_detected"] = self.detect_dde(text)
                result["suspicious_keywords"] = self.detect_suspicious_keywords(text)

        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_office(self, filepath: str) -> Dict[str, Any]:
        result = {
            "is_ole": False,
            "is_encrypted": False,
            "zip_structure": {},
            "ole_streams": {},
            "macros": {}
        }
        
        try:
            with open(filepath, 'rb') as f:
                header = f.read(1024)
                if header.lstrip().startswith(b'{\\rt'):
                    return self.analyze_rtf(filepath)

            result["is_ole"] = isOleFile(filepath)
            result["is_encrypted"] = is_encrypted(filepath)
            result["zip_structure"] = self.analyze_zip_structure(filepath)
            result["ole_streams"] = self.analyze_ole_streams(filepath)
            result["macros"] = self.analyze_macros(filepath)

        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_with_gemini(self, analysis_result: Dict[str, Any]) -> Dict[str, str]:
        prompt = f"""You are a malware detection assistant. You will be given JSON-like output from a static analysis tool for a document file (PDF or DOCX). Your task is to identify and flag **any potentially malicious or suspicious elements**.

Only output your response in valid **JSON format**. Each flag should be a key-value pair where:
- The **key** is a short description of the issue (e.g., "suspicious macro", "suspicious embedding", "external URL found", etc.)
- The **value** is a brief explanation of why it's suspicious.

Do **not** include benign or empty values.
Do **not** assign scores or confidence percentages.
Only include key-value pairs if there's something **flag-worthy**.
If nothing is suspicious, return an **empty JSON object**: `{{}}`

Examples of things that should be flagged include:
- Embedded macros (VBA or XLM)
- Embedded spreadsheets or OLE files
- Suspicious keywords like `Run`, `Shell`, `Execute`
- External URLs in the file
- DDE (Dynamic Data Exchange) links
- Encrypted documents
- Hidden streams or payloads

Here is the input for you to analyze:

{json.dumps(analysis_result, indent=2)}"""

        try:
            response = self.model.generate_content(prompt)
            # Extract JSON from the response
            response_text = response.text
            # Find JSON object in the response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            if json_start != -1 and json_end != -1:
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
            return {}
        except Exception as e:
            print(f"Error in Gemini analysis: {e}")
            return {}

    def analyze_document(self, filepath: str, mode: str) -> Dict[str, Any]:
        if mode == "pdf":
            analysis_result = self.analyze_pdf(filepath)
        elif mode == "doc":
            analysis_result = self.analyze_office(filepath)
        else:
            return {"error": "Invalid mode selected"}
        
        # Get Gemini's analysis of the results
        gemini_analysis = self.analyze_with_gemini(analysis_result)
        
        return {
            "raw_analysis": analysis_result,
            "gemini_analysis": gemini_analysis
        }

# For testing purposes
if __name__ == "__main__":
    analyzer = DocumentAnalyzer()
    result = analyzer.analyze_document("mal.doc", "doc")
    print(json.dumps(result, indent=2))
