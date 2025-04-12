import re
import os
import zipfile
import binascii
import json
import subprocess
from typing import Dict, List, Any, Tuple
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
import yara
import logging
from dotenv import load_dotenv
import google.generativeai as genai

logger = logging.getLogger(__name__)

class DocumentAnalyzer:
    def __init__(self):
        self.known_headers = {
            "D0CF11E0A1B11AE1": "OLE Compound File",  # DOC, XLS, PPT
            "4D5A": "Windows Executable",
            "25504446": "PDF Document",
            "504B0304": "ZIP Archive",  # DOCX, XLSX, PPTX
            "7B5C727466": "RTF Document",  # RTF signature
            "CF11E0": "DOC File",  # Specific DOC signature
            "ECA5C100": "DOC File",  # Another DOC signature
        }
        
        self.suspicious_keywords = [
            "Shell", "CreateObject", "WScript.Shell", "powershell", "cmd.exe",
            "AutoOpen", "Document_Open", "Workbook_Open", "ExecuteExcel4Macro",
            "GetObject", "Run", "URLDownloadToFile", "Msxml2.XMLHTTP",
            "RegRead", "RegWrite", "RegDelete", "WScript.Network",
            "ADODB.Stream", "Scripting.FileSystemObject", "eval", "Execute",
            "ActiveXObject", "new ActiveXObject", "WScript.CreateObject"
        ]

        self.pdf_suspicious_patterns = [
            "/JavaScript", "/JS", "/AcroForm", "/OpenAction", 
            "/Launch", "/LaunchUrl", "/EmbeddedFile", "/URI", 
            "/Action", "cmd.exe", "system32", "%HOMEDRIVE%",
            "<script>"
        ]

        # Add DOC-specific suspicious patterns
        self.doc_suspicious_patterns = [
            "\\object", "\\objupdate", "\\objdata", "\\objclass",  # OLE objects
            "\\bin", "\\pict", "\\macpict",  # Embedded objects
            "\\fldinst", "\\fldrslt",  # Fields
            "\\ddeauto", "\\dde",  # DDE
            "\\oleobj", "\\objemb",  # OLE embedding
            "\\objlink", "\\objocx",  # OLE linking
            "\\objupdate", "\\objautlink",  # OLE auto-update
            "\\objalias", "\\objhtml"  # OLE HTML
        ]

        # Add RTF-specific suspicious patterns
        self.rtf_suspicious_patterns = [
            "\\object", "\\objclass", "\\objdata",  # OLE objects
            "\\bin", "\\pict", "\\macpict",  # Embedded objects
            "\\fldinst", "\\fldrslt",  # Fields
            "\\ddeauto", "\\dde",  # DDE
            "\\oleobj", "\\objemb",  # OLE embedding
            "\\objlink", "\\objocx",  # OLE linking
            "\\objupdate", "\\objautlink",  # OLE auto-update
            "\\objalias", "\\objhtml",  # OLE HTML
            "\\objupdate", "\\objautlink",  # OLE auto-update
            "\\objalias", "\\objhtml",  # OLE HTML
            "\\objocx", "\\objupdate",  # OLE controls
            "\\objautlink", "\\objalias",  # OLE auto-linking
            "\\objhtml", "\\objocx",  # OLE HTML and controls
            "\\objupdate", "\\objautlink",  # OLE auto-update
            "\\objalias", "\\objhtml"  # OLE HTML
        ]

        # Initialize YARA rules
        self.yara_rules = self.load_yara_rules()

    def load_yara_rules(self):
        """Load YARA rules from the YaraRules_Multiple directory"""
        try:
            # Get the directory where the script is located
            script_dir = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(script_dir, "Systems", "Multiple", "YaraRules_Multiple")
            
            if not os.path.exists(rules_dir):
                print(f"Warning: YARA rules directory not found at {rules_dir}")
                return None
            
            rules = {}
            for rule_file in os.listdir(rules_dir):
                if rule_file.endswith(('.yara', '.yar')):
                    try:
                        rules[rule_file] = yara.compile(os.path.join(rules_dir, rule_file))
                    except yara.SyntaxError as e:
                        print(f"Error compiling rule {rule_file}: {str(e)}")
            return rules
        except Exception as e:
            print(f"Error loading YARA rules: {str(e)}")
            return None

    def scan_with_yara(self, filepath: str) -> List[str]:
        """Scan a file with YARA rules"""
        if not self.yara_rules:
            return []
        
        try:
            matches = []
            file_data = open(filepath, "rb").read()
            
            for rule_name, rule in self.yara_rules.items():
                try:
                    rule_matches = rule.match(data=file_data)
                    if rule_matches:
                        for match in rule_matches:
                            matches.append({
                                "rule": rule_name,
                                "description": match.meta.get("description", ""),
                                "severity": match.meta.get("severity", "unknown"),
                                "category": match.meta.get("category", "unknown")
                            })
                except Exception as e:
                    print(f"Error scanning with rule {rule_name}: {str(e)}")
            
            return matches
        except Exception as e:
            print(f"Error during YARA scanning: {str(e)}")
            return []

    def detect_file_type(self, filepath: str) -> str:
        """Detect file type using both magic numbers and file command"""
        try:
            # Check magic numbers
            with open(filepath, 'rb') as f:
                header = binascii.hexlify(f.read(8)).upper().decode()
                
                # Check for Office file signatures
                if header.startswith("D0CF11E0A1B11AE1"):  # OLE Compound File
                    # Check for specific Office file types
                    f.seek(0)
                    content = f.read()
                    if b"Word.Document" in content:
                        return "doc"
                    elif b"Excel.Sheet" in content:
                        return "xlsm"
                    return "ole compound file"
                elif header.startswith("504B0304"):  # ZIP header
                    # Check if it's an Office Open XML file
                    try:
                        with zipfile.ZipFile(filepath) as zip_ref:
                            if 'word/document.xml' in zip_ref.namelist():
                                return "doc"
                            elif 'xl/workbook.xml' in zip_ref.namelist():
                                # Check for VBA project to confirm XLSM
                                if 'xl/vbaProject.bin' in zip_ref.namelist():
                                    return "xlsm"
                                return "xlsx"
                            elif 'ppt/presentation.xml' in zip_ref.namelist():
                                return "ppt"
                    except:
                        pass
                    return "zip archive"
                elif header.startswith("25504446"):  # PDF
                    return "pdf document"
                elif header.startswith("7B5C727466"):  # RTF
                    return "rtf document"
            
            # Use file command as fallback
            result = subprocess.run(['file', filepath], capture_output=True, text=True)
            if "Microsoft Word" in result.stdout:
                return "doc"
            elif "Microsoft Excel" in result.stdout:
                return "xlsm"
            elif "Microsoft PowerPoint" in result.stdout:
                return "ppt"
            elif "PDF document" in result.stdout:
                return "pdf"
            elif "Rich Text Format" in result.stdout:
                return "rtf"
            return "unknown"
        except:
            return "unknown"

    def analyze_pdf(self, filepath: str) -> Dict[str, Any]:
        result = {
            "metadata": {},
            "catalog": [],
            "suspicious_strings": [],
            "embedded_files": [],
            "urls": [],
            "streams": [],
            "yara_matches": self.scan_with_yara(filepath)
        }
        
        try:
            # Basic PDF parsing
            with open(filepath, "rb") as f:
                parser = PDFParser(f)
                doc = PDFDocument(parser)
                
                # Extract metadata
                if doc.info:
                    result["metadata"] = {str(k): str(v) for k, v in doc.info[0].items()}
                
                # Analyze catalog
                for key in doc.catalog:
                    if key not in ["Type"]:
                        result["catalog"].append(key)
                
                # Extract text and analyze content
                output = StringIO()
                rsrcmgr = PDFResourceManager()
                device = TextConverter(rsrcmgr, output, laparams=LAParams())
                interpreter = PDFPageInterpreter(rsrcmgr, device)
                
                # Process each page
                for page in PDFPage.create_pages(doc):
                    interpreter.process_page(page)
                    text = output.getvalue()
                    
                    # Check for suspicious strings
                    for pattern in self.pdf_suspicious_patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            result["suspicious_strings"].append(pattern)
                    
                    # Extract URLs
                    urls = re.findall(r"http[s]?://[a-zA-Z0-9./?=_%:-]*", text)
                    result["urls"].extend(urls)
                
                device.close()
                output.close()
                
                # Analyze streams
                for xref in doc.xrefs:
                    for obj_id in xref.get_objids():
                        try:
                            obj = doc.getobj(obj_id)
                            if "PDFStream" in str(obj):
                                stream_data = obj.get_rawdata()
                                # Check for embedded files
                                if "EmbeddedFile" in str(obj):
                                    result["embedded_files"].append({
                                        "object_id": obj_id,
                                        "size": len(stream_data)
                                    })
                                # Check for suspicious content
                                if any(pattern.encode() in stream_data for pattern in self.pdf_suspicious_patterns):
                                    result["streams"].append({
                                        "object_id": obj_id,
                                        "suspicious_content": True
                                    })
                        except:
                            continue
                
        except Exception as e:
            result["error"] = str(e)
        
        return result

    def detect_suspicious_keywords(self, code: str) -> List[str]:
        """Detect suspicious keywords in macro code"""
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in code:
                found_keywords.append(keyword)
        return found_keywords

    def analyze_office(self, filepath: str) -> Dict[str, Any]:
        result = {
            "is_ole": False,
            "is_encrypted": False,
            "structure": [],
            "macros": {
                "vba_macros": [],
                "xlm_macros": [],
                "suspicious_keywords": [],
                "auto_exec_triggers": [],
                "extracted_macros": []
            },
            "embedded_files": {
                "ole_objects": [],
                "extracted_files": []
            },
            "urls": [],
            "ole_streams": [],
            "doc_specific": {  # New field for DOC-specific analysis
                "ole_objects": [],
                "fields": [],
                "dde_objects": [],
                "embedded_objects": []
            },
            "yara_matches": self.scan_with_yara(filepath)
        }
        
        try:
            # Check if it's an OLE file
            result["is_ole"] = isOleFile(filepath)
            result["is_encrypted"] = is_encrypted(filepath)
            
            # If file is encrypted, try to extract what we can
            if result["is_encrypted"]:
                print("Warning: File is encrypted. Some analysis may be limited.")
            
            # Analyze structure and extract embedded files
            if zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath) as zipdoc:
                    result["structure"] = zipdoc.namelist()
                    
                    # Extract and analyze embedded files
                    for name in zipdoc.namelist():
                        if "embedding" in name or name.endswith(('.bin', '.exe', '.dll', '.vbs', '.ps1')):
                            try:
                                data = zipdoc.read(name)
                                file_info = {
                                    "name": name,
                                    "size": len(data),
                                    "type": self.binary_analysis(name, data)["type"],
                                    "content_preview": data[:1000].hex() if len(data) > 1000 else data.hex()
                                }
                                result["embedded_files"]["extracted_files"].append(file_info)
                            except Exception as e:
                                print(f"Error extracting embedded file {name}: {str(e)}")
            
            # Analyze OLE streams and extract OLE objects
            if result["is_ole"]:
                ole = OleFileIO(filepath)
                result["ole_streams"] = ["/".join(stream) for stream in ole.listdir()]
                
                # Extract OLE objects and their content
                for stream in ole.listdir():
                    try:
                        data = ole.openstream(stream).read()
                        # Extract strings from streams
                        strings = re.findall(rb"[a-zA-Z0-9:/\\._-]{6,}", data)
                        for s in strings:
                            if b"http" in s:
                                result["urls"].append(s.decode('latin1'))
                        
                        # Check for OLE objects
                        if b"OLEObject" in data or b"Package" in data:
                            ole_obj = {
                                "stream": "/".join(stream),
                                "size": len(data),
                                "content_preview": data[:1000].hex() if len(data) > 1000 else data.hex()
                            }
                            result["embedded_files"]["ole_objects"].append(ole_obj)
                        
                        # DOC-specific analysis
                        if b"Word.Document" in data:
                            # Check for fields
                            if b"\\fldinst" in data or b"\\fldrslt" in data:
                                result["doc_specific"]["fields"].append({
                                    "stream": "/".join(stream),
                                    "content": data.decode('latin1', errors='ignore')[:1000]
                                })
                            
                            # Check for DDE
                            if b"\\ddeauto" in data or b"\\dde" in data:
                                result["doc_specific"]["dde_objects"].append({
                                    "stream": "/".join(stream),
                                    "content": data.decode('latin1', errors='ignore')[:1000]
                                })
                            
                            # Check for embedded objects
                            for pattern in self.doc_suspicious_patterns:
                                if pattern.encode() in data:
                                    result["doc_specific"]["embedded_objects"].append({
                                        "stream": "/".join(stream),
                                        "type": pattern,
                                        "content": data.decode('latin1', errors='ignore')[:1000]
                                    })
                    except Exception as e:
                        print(f"Error processing OLE stream {stream}: {str(e)}")
                ole.close()
            
            # Enhanced macro analysis
            vbaparser = VBA_Parser(filepath)
            if vbaparser.detect_vba_macros():
                for (_, _, fname, code) in vbaparser.extract_macros():
                    # Extract full macro content
                    full_code = code.strip()
                    suspicious_keywords = self.detect_suspicious_keywords(full_code)
                    macro_info = {
                        "name": fname,
                        "code_preview": full_code[:1000],
                        "full_code": full_code,
                        "suspicious_keywords": suspicious_keywords,
                        "auto_exec": any(trigger in full_code for trigger in ["AutoOpen", "Document_Open", "Workbook_Open"]),
                        "has_shell": "WScript.Shell" in full_code or "Shell" in full_code,
                        "has_download": "URLDownloadToFile" in full_code,
                        "has_createobject": "CreateObject" in full_code
                    }
                    result["macros"]["vba_macros"].append(macro_info)
                    result["macros"]["suspicious_keywords"].extend(suspicious_keywords)
                    result["macros"]["extracted_macros"].append({
                        "name": fname,
                        "type": "VBA",
                        "content": full_code
                    })
            
            # Enhanced XLM macro analysis
            if vbaparser.detect_xlm_macros():
                for macro in vbaparser.xlm_macros:
                    full_code = macro.strip()
                    suspicious_keywords = self.detect_suspicious_keywords(full_code)
                    macro_info = {
                        "code_preview": full_code[:1000],
                        "full_code": full_code,
                        "suspicious_keywords": suspicious_keywords,
                        "auto_exec": "AUTO_OPEN" in full_code.upper(),
                        "has_shell": "SHELL" in full_code.upper(),
                        "has_download": "DOWNLOAD" in full_code.upper(),
                        "has_createobject": "CREATEOBJECT" in full_code.upper()
                    }
                    result["macros"]["xlm_macros"].append(macro_info)
                    result["macros"]["suspicious_keywords"].extend(suspicious_keywords)
                    result["macros"]["extracted_macros"].append({
                        "name": "XLM_Macro",
                        "type": "XLM",
                        "content": full_code
                    })
                
        except Exception as e:
            result["error"] = str(e)
        
        return result

    def analyze_rtf(self, filepath: str) -> Dict[str, Any]:
        """Analyze RTF document for embedded objects and suspicious content"""
        result = {
            "metadata": {},
            "embedded_objects": [],
            "ole_objects": [],
            "dde_objects": [],
            "suspicious_patterns": [],
            "urls": [],
            "macros": [],
            "yara_matches": self.scan_with_yara(filepath)
        }
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
                # Extract metadata
                metadata_match = re.search(rb'\\info\{([^}]*)\}', content)
                if metadata_match:
                    metadata_text = metadata_match.group(1).decode('latin1', errors='ignore')
                    result["metadata"] = {
                        "info": metadata_text
                    }
                
                # Check for embedded objects with proper regex escaping
                for pattern in self.rtf_suspicious_patterns:
                    # Create a properly escaped pattern for regex
                    pattern_bytes = pattern.encode()
                    escaped_pattern = re.escape(pattern_bytes)
                    
                    if pattern_bytes in content:
                        result["suspicious_patterns"].append(pattern)
                        
                        # Extract object data with improved regex
                        obj_pattern = rb'(?:' + escaped_pattern + rb')([^\\\{\}]+)'
                        for match in re.finditer(obj_pattern, content):
                            try:
                                obj_data = match.group(1).decode('latin1', errors='ignore')
                                if pattern.startswith("\\obj"):
                                    result["ole_objects"].append({
                                        "type": pattern,
                                        "content": obj_data[:1000],  # Preview of content
                                        "offset": match.start()
                                    })
                                elif pattern.startswith("\\dde"):
                                    result["dde_objects"].append({
                                        "type": pattern,
                                        "content": obj_data[:1000],
                                        "offset": match.start()
                                    })
                                else:
                                    result["embedded_objects"].append({
                                        "type": pattern,
                                        "content": obj_data[:1000],
                                        "offset": match.start()
                                    })
                            except Exception as e:
                                print(f"Error processing object data: {str(e)}")
                
                # Extract URLs with improved regex
                url_patterns = [
                    rb'\\field\{\\fldinst HYPERLINK "([^"]*)"\}',
                    rb'\\field\{\\fldinst HYPERLINK ([^}]*)\}',
                    rb'\\url ([^\\\{\}]+)'
                ]
                
                for pattern in url_patterns:
                    for match in re.finditer(pattern, content):
                        try:
                            url = match.group(1).decode('latin1', errors='ignore')
                            result["urls"].append({
                                "url": url,
                                "offset": match.start()
                            })
                        except Exception as e:
                            print(f"Error processing URL: {str(e)}")
                
                # Check for macros with improved regex
                macro_patterns = [
                    rb'\\vba\\',
                    rb'\\mac\\',
                    rb'\\objocx\\',
                    rb'\\objupdate\\'
                ]
                
                for pattern in macro_patterns:
                    for match in re.finditer(pattern, content):
                        try:
                            result["macros"].append({
                                "type": pattern.decode('latin1'),
                                "found": True,
                                "offset": match.start()
                            })
                        except Exception as e:
                            print(f"Error processing macro: {str(e)}")
                
                # Check for OLE objects with improved regex
                ole_patterns = [
                    rb'\\object\\objocx',
                    rb'\\object\\objupdate',
                    rb'\\object\\objautlink'
                ]
                
                for pattern in ole_patterns:
                    for match in re.finditer(pattern, content):
                        try:
                            result["ole_objects"].append({
                                "type": "OLE Object",
                                "pattern": pattern.decode('latin1'),
                                "found": True,
                                "offset": match.start()
                            })
                        except Exception as e:
                            print(f"Error processing OLE object: {str(e)}")
                
                # Additional analysis for exploit patterns
                exploit_patterns = [
                    rb'\\rtf1\\ansi\\ansicpg1252\\uc1\\deff0\\deflang1033',
                    rb'\\object\\objocx\\objupdate\\objautlink',
                    rb'\\objdata'
                ]
                
                for pattern in exploit_patterns:
                    if pattern in content:
                        result["suspicious_patterns"].append({
                            "type": "exploit_pattern",
                            "pattern": pattern.decode('latin1'),
                            "found": True
                        })
                
                # Check for CVE-2017-11882 specific patterns
                cve_patterns = [
                    rb'\\object\\objocx\\objupdate\\objautlink',
                    rb'\\objdata\\objocx\\objupdate',
                    rb'\\objdata\\objocx\\objautlink'
                ]
                
                for pattern in cve_patterns:
                    if pattern in content:
                        result["suspicious_patterns"].append({
                            "type": "CVE-2017-11882_pattern",
                            "pattern": pattern.decode('latin1'),
                            "found": True,
                            "cve": "CVE-2017-11882"
                        })
                
        except Exception as e:
            result["error"] = str(e)
        
        return result

    def binary_analysis(self, filename: str, data: bytes) -> Dict[str, Any]:
        """Analyze binary data to determine file type and extract information"""
        result = {
            "type": "unknown",
            "is_executable": False,
            "is_script": False,
            "suspicious": False
        }
        
        # Check file extension
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.exe', '.dll']:
            result["type"] = "executable"
            result["is_executable"] = True
        elif ext in ['.vbs', '.ps1', '.js']:
            result["type"] = "script"
            result["is_script"] = True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            b"MZ",  # Windows executable
            b"WScript.Shell",
            b"CreateObject",
            b"powershell",
            b"cmd.exe"
        ]
        
        for pattern in suspicious_patterns:
            if pattern in data:
                result["suspicious"] = True
                break
        
        return result

    def analyze_document(self, filepath: str) -> Dict[str, Any]:
        """Analyze document and return results with Gemini analysis"""
        try:
            logger.debug("Starting document analysis...")
            file_type = self.detect_file_type(filepath)
            logger.debug(f"Detected file type: {file_type}")
            
            # Get base analysis result
            if file_type == "pdf document":
                logger.debug("Analyzing PDF document...")
                analysis_result = self.analyze_pdf(filepath)
            elif file_type in ["ole compound file", "zip archive", "xlsm", "xlsx"]:
                logger.debug("Analyzing Office document...")
                analysis_result = self.analyze_office(filepath)
            elif file_type == "rtf document":
                logger.debug("Analyzing RTF document...")
                analysis_result = self.analyze_rtf(filepath)
            else:
                logger.error(f"Unsupported file type: {file_type}")
                return {"error": f"Unsupported file type: {file_type}"}
            
            # Add file type to result
            # analysis_result["file_type"] = file_type
            logger.debug(f"Base analysis completed: {analysis_result}")
            
            # Get Gemini analysis - FORCE IT TO RUN
            logger.debug("Starting Gemini analysis...")
            gemini_result = self.analyze_with_gemini(analysis_result)
            logger.debug(f"Gemini analysis completed: {gemini_result}")
            
            # Create final result with both analyses
            final_result = {
                "file_type": file_type,
                "is_ole": analysis_result.get("is_ole", False),
                "is_encrypted": analysis_result.get("is_encrypted", False),
                "structure": analysis_result.get("structure", []),
                "macros": analysis_result.get("macros", {}),
                "embedded_files": analysis_result.get("embedded_files", {}),
                "urls": analysis_result.get("urls", []),
                "ole_streams": analysis_result.get("ole_streams", []),
                "doc_specific": analysis_result.get("doc_specific", {}),
                "yara_matches": analysis_result.get("yara_matches", []),
                "gemini_analysis": gemini_result,  # Include full Gemini result
                "error": None
            }
            
            logger.debug(f"Final analysis result: {final_result}")
            return final_result
            
        except Exception as e:
            logger.error(f"Error in document analysis: {str(e)}")
            return {"error": str(e)}

    def analyze_with_gemini(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze document features using Gemini to detect malware patterns"""
        try:
            logger.debug("Starting Gemini analysis with features...")
            
            # Load Gemini API key from .env
            load_dotenv()
            GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
            if not GEMINI_API_KEY:
                raise Exception("Gemini API key not found in .env file")
            
            # Configure Gemini
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            # Safely extract analysis data with proper type handling
            def safe_get(data, key, default=None):
                if isinstance(data, dict):
                    return data.get(key, default)
                return default

            # Prepare the analysis data for the prompt
            analysis_data = {
                "file_type": safe_get(analysis_result, "file_type", "unknown"),
                "is_ole": safe_get(analysis_result, "is_ole", False),
                "is_encrypted": safe_get(analysis_result, "is_encrypted", False),
                "macros": safe_get(analysis_result, "macros", {}),
                "embedded_files": safe_get(analysis_result, "embedded_files", {}),
                "urls": safe_get(analysis_result, "urls", []),
                "suspicious_patterns": safe_get(analysis_result, "suspicious_patterns", []),
                "yara_matches": safe_get(analysis_result, "yara_matches", [])
            }
            
            # Create a detailed prompt for Gemini
            prompt = f"""
            You are a malware analysis expert. Analyze this document for potential malware based on the following features:
            
            File Type: {analysis_data['file_type']}
            Is OLE: {analysis_data['is_ole']}
            Is Encrypted: {analysis_data['is_encrypted']}
            
            Macros:
            - VBA Macros: {len(safe_get(analysis_data['macros'], 'vba_macros', []))}
            - Suspicious Keywords: {safe_get(analysis_data['macros'], 'suspicious_keywords', [])}
            - Auto-exec Triggers: {safe_get(analysis_data['macros'], 'auto_exec_triggers', [])}
            
            Embedded Files:
            - OLE Objects: {len(safe_get(analysis_data['embedded_files'], 'ole_objects', []))}
            - Extracted Files: {len(safe_get(analysis_data['embedded_files'], 'extracted_files', []))}
            
            URLs: {analysis_data['urls']}
            Suspicious Patterns: {analysis_data['suspicious_patterns']}
            YARA Matches: {analysis_data['yara_matches']}
            
            Based on this analysis:
            1. List suspicious indicators found
            2. Describe behavioral patterns
            3. Assess potential impact
            4. Provide relevant tags
            5. Give a confidence score (0.0 to 1.0)
            
            IMPORTANT: Respond ONLY with a valid JSON object in this exact format:
            {{
                "confidence_score": float,
                "suspicious_indicators": ["string"],
                "behavioral_patterns": ["string"],
                "potential_impact": "string",
                "tags": ["string"],
                "description": "string"
            }}
            
            Do not include any other text or explanation outside the JSON object.
            """
            
            # Get Gemini's analysis
            response = model.generate_content(prompt)
            
            # Extract the JSON from the response
            try:
                # Try to find JSON in the response
                response_text = response.text
                # Find the first { and last } to extract the JSON
                start = response_text.find('{')
                end = response_text.rfind('}') + 1
                if start != -1 and end != -1:
                    json_str = response_text[start:end]
                    gemini_result = json.loads(json_str)
                else:
                    raise ValueError("No JSON object found in response")
            except Exception as e:
                logger.error(f"Error parsing Gemini response: {str(e)}")
                # Return a default result if parsing fails
                gemini_result = {
                    "confidence_score": 0.0,
                    "suspicious_indicators": [],
                    "behavioral_patterns": [],
                    "potential_impact": "Analysis failed",
                    "tags": [],
                    "description": f"Error parsing response: {str(e)}"
                }
            
            logger.debug(f"Gemini analysis completed with result: {gemini_result}")
            return gemini_result
            
        except Exception as e:
            logger.error(f"Error in Gemini analysis: {str(e)}")
            return {
                "confidence_score": 0.0,
                "suspicious_indicators": [],
                "behavioral_patterns": [],
                "potential_impact": "Analysis failed",
                "tags": [],
                "description": f"Error during analysis: {str(e)}"
            }

# For testing purposes
if __name__ == "__main__":
    analyzer = DocumentAnalyzer()
    result = analyzer.analyze_document("./data/test1.docx")
    print(json.dumps(result, indent=2)) 