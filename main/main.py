import os
import sys
from pathlib import Path
import numpy as np

# Set up paths before any other imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable is not set")

import google.generativeai as genai
genai.configure(api_key=GEMINI_API_KEY)

import shutil
import tempfile
import asyncio
import subprocess
import json
import logging
import magic
import zipfile
from typing import Dict, Any, Union, List, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import docker
from datetime import datetime
from document_feature_extractor import DocumentAnalyzer
from ML_Models.ember.windows_static_analyzer import WindowsExecutableAnalyzer
from ML_Models.ember_elf.predict import predict_elf_file, load_model
from ML_Models.ember_elf.generate_features import ELFFeatureExtractor

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Malware Analysis API",
    description="RetDec + Ember pipeline",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware with specific configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,
)

# Paths
BASE_DIR = Path(__file__).resolve().parent
# RETBEC_DIR = BASE_DIR.parent / "retbec"    # ../retbec
EMBER_DIR = BASE_DIR.parent / "ember"      # ../ember
EMBER_ELF_DIR = BASE_DIR.parent / "ember_elf"  # ../ember_elf
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"

# Create directories with proper permissions
for d in (DATA_DIR, OUTPUT_DIR):
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o755)  # Ensure proper permissions

class AnalysisResult(BaseModel):
    # Type of analysis
    type: str  # "document" or "executable"
    
    # Document Analysis Results
    document_analysis: Dict[str, Any] = {}
    
    # Executable Analysis Results
    ember_probability: float = 0.0
    # gemini_probability: float = 0.0
    ember_sha256: str = ""
    ember_important_features: Dict[str, Any] = {}
    static_analysis: Dict[str, Any] = {}
    malware_categorization: List[Dict[str, Any]] = []
    # retdec_architecture: Dict[str, Any] = {}
    # retdec_file_format: str = ""
    # retdec_imports: Dict[str, Any] = {}
    # retdec_suspicious_calls: Dict[str, bool] = {}
    # suspicious_indicators: list[str] = []
    # behavioral_patterns: list[str] = []
    # potential_impact: str = ""
    # confidence_score: float = 0.0
    
    error: Union[str, None] = None

    class Config:
        json_encoders = {
            float: lambda v: round(float(v), 5),  # Format floats to 5 decimal places
            np.integer: lambda v: int(v),  # Convert numpy integers to Python integers
            np.floating: lambda v: float(v),  # Convert numpy floats to Python floats
            np.ndarray: lambda v: v.tolist()  # Convert numpy arrays to lists
        }

class MultiFileAnalysisResult(BaseModel):
    results: List[AnalysisResult]
    errors: List[str]

def is_zip_file(file_path: Path) -> bool:
    """Check if file is a zip file"""
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) == b'PK\x03\x04'
    except:
        return False

async def extract_zip(file_path: Path, extract_dir: Path) -> List[Path]:
    """Extract zip file and return list of extracted files"""
    extracted_files = []
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
            extracted_files = [extract_dir / f for f in zip_ref.namelist()]
    except Exception as e:
        logger.error(f"Failed to extract zip file: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid zip file: {str(e)}")
    return extracted_files

async def process_nested_zip(file_path: Path, extract_dir: Path) -> Optional[Path]:
    """Process nested zip files until a non-zip file is found"""
    current_file = file_path
    depth = 0
    max_depth = 10  # Prevent infinite recursion
    
    while is_zip_file(current_file) and depth < max_depth:
        try:
            # Create a unique filename for the extracted file
            unique_name = f"extracted_{os.urandom(8).hex()}_{current_file.name}"
            extract_path = extract_dir / unique_name
            
            # Extract the first file from the ZIP
            with zipfile.ZipFile(current_file, 'r') as zip_ref:
                # Get the first file in the ZIP
                first_file = zip_ref.namelist()[0]
                # Extract it to the unique path
                zip_ref.extract(first_file, extract_dir)
                extracted_file = extract_dir / first_file
                
                # Rename to our unique name
                extracted_file.rename(extract_path)
                current_file = extract_path
                depth += 1
                
        except Exception as e:
            logger.error(f"Error processing nested ZIP: {str(e)}")
            return None
            
    if depth >= max_depth:
        logger.warning(f"Reached maximum depth of {max_depth} nested ZIPs")
        return None
        
    return current_file

def detect_file_type(file_path: Path) -> str:
    """Detect file type using python-magic, with fallback for .exe detection on macOS"""
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(str(file_path))

    # 🔍 Debug print for MIME type
    logger.debug(f"MIME Type detected by libmagic: {file_type}")

    # Check for ELF files first
    if file_type in ['application/x-executable', 'application/x-sharedlib', 'application/octet-stream']:
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                # Check for ELF magic number
                if header == b'\x7fELF':
                    logger.debug("Detected ELF header — classifying as elf")
                    return 'elf'
        except Exception as e:
            logger.error(f"Error reading file header: {e}")

    # Check for PE/EXE files
    if file_type in ['application/octet-stream', 'application/x-mach-binary', 'application/x-binary', 'application/x-msdownload', 'application/vnd.microsoft.portable-executable']:
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2)
                # Check for 'MZ' header used in PE files (Windows executables)
                if header == b'MZ':
                    logger.debug("Detected 'MZ' header — classifying as executable")
                    return 'executable'
        except Exception as e:
            logger.error(f"Error reading file header: {e}")

    # If we get here and it's an executable type, default to executable
    if file_type in ['application/x-dosexec', 'application/x-executable', 'application/x-sharedlib']:
        return 'executable'

    # Check for RTF files specifically
    if file_type == 'application/rtf' or file_type == 'text/rtf':
        logger.debug("Detected RTF file")
        return 'rtf document'

    # Check for DOCX files specifically
    if file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        return 'doc'
    elif file_type == 'application/pdf':
        return 'pdf'
    elif file_type in ['application/msword', 'application/vnd.ms-word']:
        return 'doc'
    elif file_type in ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                      'application/vnd.ms-excel',
                      'application/vnd.ms-excel.sheet.macroEnabled.12']:
        return 'doc'  # Treat Excel files as documents
    elif file_type == 'application/zip':
        # Additional check to distinguish between DOCX and regular ZIP
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                if header == b'PK\x03\x04':  # ZIP header
                    # Check if it's a DOCX by looking for specific files
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        if 'word/document.xml' in zip_ref.namelist():
                            return 'doc'
                        elif 'xl/workbook.xml' in zip_ref.namelist():
                            return 'doc'
            return 'zip'
        except Exception as e:
            logger.error(f"Error checking ZIP contents: {e}")
            return 'zip'
    else:
        return 'unknown'

async def analyze_document(file_path: Path, file_type: str) -> Dict[str, Any]:
    """Analyze a document file using the DocumentAnalyzer"""
    try:
        # Initialize document analyzer
        analyzer = DocumentAnalyzer()
        
        # Use the complete analyze_document method that includes Gemini analysis
        analysis_result = analyzer.analyze_document(str(file_path))
        
        logger.debug(f"Document analysis result: {analysis_result}")
        
        if analysis_result.get("error"):
            return {"error": analysis_result["error"]}
        
        # Combine results
        result = {
            "analysis": analysis_result,
            "error": None
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing document: {str(e)}")
        return {"error": str(e)}

async def run_ember_analysis(file_path: Path) -> Dict[str, Any]:
    """Run EMBER analysis on the executable"""
    try:
        logger.info(f"[EMBER] Starting analysis at {datetime.now().strftime('%H:%M:%S')}")
        
        # Get the directory containing the file
        file_dir = str(file_path.parent).replace('\\', '/')
        ember_proc = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{file_dir}:/data",  # Mount the directory containing the file
             "-v", f"{EMBER_DIR}:/ember",
             "ember",  # Keep original image name
             "python", "/ember/predict.py", f"/data/{file_path.name}"],
            capture_output=True,
            text=True
        )
        logger.info(f"[EMBER] Analysis completed at {datetime.now().strftime('%H:%M:%S')}")
        
        if ember_proc.returncode != 0:
            raise Exception(f"EMBER prediction failed: {ember_proc.stderr}")
            
        ember_res = json.loads(ember_proc.stdout.strip())
        return {
            "ember_probability": round(float(ember_res["probability"]), 5),
            "ember_sha256": ember_res.get("sha256", ""),
            "ember_important_features": ember_res.get("features", {})
        }
    except Exception as e:
        logger.error(f"[EMBER] Analysis failed: {str(e)}")
        return {
            "ember_probability": 0.0,
            "ember_sha256": "",
            "ember_important_features": {}
        }

async def run_retdec_gemini_analysis(file_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Run RetDec decompilation and Gemini analysis"""
    try:
        logger.info(f"[RetDec] Starting analysis at {datetime.now().strftime('%H:%M:%S')}")
        # Convert Windows paths to Docker-compatible paths
        data_path = str(DATA_DIR).replace('\\', '/')
        output_path = str(OUTPUT_DIR).replace('\\', '/')
        output_subdir = file_path.stem
        
        # Run RetDec decompiler
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{data_path}:/data",
            "-v", f"{output_path}:/output",
            "retdec",
            "retdec-decompiler",
            f"/data/{file_path.name}",
            "-o", f"/output/{output_subdir}/{file_path.stem}.c"
        ]
        
        logger.debug(f"[RetDec] Running Docker command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        logger.info(f"[RetDec] Decompilation completed at {datetime.now().strftime('%H:%M:%S')}")
        
        if result.returncode != 0:
            error_msg = f"RetDec decompilation failed with return code {result.returncode}\n"
            if result.stderr:
                error_msg += f"Error output: {result.stderr}\n"
            if result.stdout:
                error_msg += f"Standard output: {result.stdout}\n"
            raise Exception(error_msg)
            
        # Check if output files were created
        output_files = list(out_dir.glob("*"))
        if not output_files:
            raise Exception(f"No output files were created in {out_dir}")
            
        # Run RetDec feature extraction
        logger.info(f"[RetDec] Starting feature extraction at {datetime.now().strftime('%H:%M:%S')}")
        retbec_proc = subprocess.run(
            [sys.executable, str(RETBEC_DIR / "retbec_check.py"), str(out_dir)],
            capture_output=True,
            text=True
        )
        logger.info(f"[RetDec] Feature extraction completed at {datetime.now().strftime('%H:%M:%S')}")
        
        if retbec_proc.returncode != 0:
            raise Exception(f"RetDec feature extraction failed: {retbec_proc.stderr}")
            
        retbec_res = json.loads(retbec_proc.stdout.strip())
        if not retbec_res.get("retbec_success"):
            raise Exception("Failed to extract features from RetDec output")
            
        # Extract important features from RetDec
        retdec_features = retbec_res["retbec_features"]
        suspicious_calls = {
            "VirtualAlloc": retdec_features.get("kw_VirtualAlloc", False),
            "WriteProcessMemory": retdec_features.get("kw_WriteProcessMemory", False),
            "CreateRemoteThread": retdec_features.get("kw_CreateRemoteThread", False),
            "GetProcAddress": retdec_features.get("kw_GetProcAddress", False),
            "LoadLibrary": retdec_features.get("kw_LoadLibrary", False)
        }
        
        # Run Gemini analysis
        logger.info(f"[Gemini] Starting analysis at {datetime.now().strftime('%H:%M:%S')}")
        gemini_proc = subprocess.run(
            [sys.executable, str(RETBEC_DIR / "malware_analysis.py"), str(out_dir)],
            capture_output=True,
            text=True
        )
        logger.info(f"[Gemini] Analysis completed at {datetime.now().strftime('%H:%M:%S')}")
        
        if gemini_proc.returncode != 0:
            raise Exception(f"Gemini analysis failed: {gemini_proc.stderr}")
            
        gemini_res = json.loads(gemini_proc.stdout.strip())
        if "error" in gemini_res:
            raise Exception(gemini_res["error"])
            
        return {
            # "gemini_probability": round(float(gemini_res.get("malware_probability", 0.0)), 5),
            # "retdec_architecture": retdec_features.get("architecture", {}),
            # "retdec_file_format": retdec_features.get("file_format", ""),
            # "retdec_imports": retdec_features.get("retdec_imports", {}),
            # "retdec_suspicious_calls": suspicious_calls,
            # "suspicious_indicators": gemini_res.get("suspicious_indicators", []),
            # "behavioral_patterns": gemini_res.get("behavioral_patterns", []),
            # "potential_impact": gemini_res.get("potential_impact", ""),
            # "confidence_score": round(float(gemini_res.get("confidence_score", 0.0)), 5)
        }
        
    except Exception as e:
        logger.error(f"[RetDec+Gemini] Analysis failed: {str(e)}")
        return {
            # "gemini_probability": 0.0,
            # "retdec_architecture": {},
            # "retdec_file_format": "",
            # "retdec_imports": {},
            # "retdec_suspicious_calls": {},
            # "suspicious_indicators": [],
            # "behavioral_patterns": [],
            # "potential_impact": "",
            # "confidence_score": 0.0
        }

async def analyze_executable(file_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Analyze executable files using parallel EMBER and RetDec+Gemini paths"""
    try:
        logger.info(f"Starting parallel analysis at {datetime.now().strftime('%H:%M:%S')}")
        # Run both analyses in parallel
        ember_result = await run_ember_analysis(file_path)
        windows_static_result = await run_windows_static_analysis(file_path)
        logger.info(f"Parallel analysis completed at {datetime.now().strftime('%H:%M:%S')}")
        
        # Combine results into a structured format
        result = {
            "ember_probability": ember_result.get("ember_probability", 0.0),
            "ember_sha256": ember_result.get("ember_sha256", ""),
            "ember_important_features": ember_result.get("ember_important_features", {}),
            "static_analysis": windows_static_result.get("static_analysis", {}),
            "malware_categorization": windows_static_result.get("malware_categorization", {}),
            "error": None
        }
        
        # Log the complete result for debugging
        logger.debug(f"Complete analysis result: {json.dumps(result, indent=2)}")
        
        return result
        
    except Exception as e:
        logger.error(f"Executable analysis failed: {str(e)}")
        return {
            "error": f"Executable analysis failed: {str(e)}"
        }

async def run_cmd(cmd, cwd=None):
    logger.debug(f"Running command: {' '.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )
    out, err = await proc.communicate()
    if proc.returncode != 0:
        error_msg = f"Command {' '.join(cmd)} failed: {err.decode()}"
        logger.error(error_msg)
        raise Exception(error_msg)
    logger.debug(f"Command output: {out.decode()}")
    return out.decode()

async def process_single_file(file: UploadFile, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Process a single file and return its analysis result"""
    try:
        if not file.filename:
            return {"results": [], "errors": ["No file provided"]}

        # Generate unique filename
        unique_filename = f"{os.urandom(8).hex()}_{file.filename}"
        fp = DATA_DIR / unique_filename
        out_dir = OUTPUT_DIR / unique_filename.rsplit(".", 1)[0]

        logger.debug(f"Processing file: {unique_filename}")
        logger.debug(f"Data directory: {DATA_DIR}")
        logger.debug(f"Output directory: {out_dir}")

        # Save uploaded file
        try:
            with open(fp, "wb") as f:
                content = await file.read()
                if not content:
                    return {"results": [], "errors": ["Empty file provided"]}
                logger.debug(f"File size: {len(content)} bytes")
                f.write(content)
        except Exception as e:
            return {"results": [], "errors": [f"Failed to save file: {str(e)}"]}

        # Check if file exists and is accessible
        if not fp.exists():
            return {"results": [], "errors": [f"Failed to save file to {fp}"]}
        
        # Create output directory
        os.makedirs(out_dir, exist_ok=True)
        
        # Detect file type
        file_type = detect_file_type(fp)
        logger.debug(f"Detected file type: {file_type}")
        
        # Handle ZIP files
        if file_type == 'zip':
            try:
                # Process nested ZIPs until we get a non-ZIP file
                final_file = await process_nested_zip(fp, out_dir)
                if final_file is None:
                    return {
                        "results": [],
                        "errors": ["Failed to process nested ZIP file"]
                    }
                
                # Detect file type of the final file
                final_file_type = detect_file_type(final_file)
                logger.debug(f"Processing file {final_file.name} of type {final_file_type}")
                
                # Process based on file type
                if final_file_type == 'executable':
                    exe_result = await analyze_executable(final_file, out_dir)
                    if not exe_result.get("error"):
                        return {
                            "results": [{
                                "type": "executable",
                                "ember_probability": exe_result.get("ember_probability", 0.0),
                                "ember_sha256": exe_result.get("ember_sha256", ""),
                                "ember_important_features": exe_result.get("ember_important_features", {}),
                                "static_analysis": exe_result.get("static_analysis", {}),
                                "malware_categorization": exe_result.get("malware_categorization", {}),
                                "error": None
                            }],
                            "errors": []
                        }
                    else:
                        return {
                            "results": [],
                            "errors": [f"Error analyzing executable: {exe_result.get('error')}"]
                        }
                elif final_file_type == 'elf':
                    try:
                        extractor = ELFFeatureExtractor()
                        model_result = load_model()
                        if not model_result.get("error"):
                            model = model_result["model"]
                            elf_result = predict_elf_file(str(final_file), model, extractor)
                            if not elf_result.get("error"):
                                return {
                                    "results": [{
                                        "type": "elf",
                                        "ember_probability": float(elf_result.get("elf_probability", 0.0)),
                                        "ember_sha256": elf_result.get("sha256", ""),
                                        "ember_important_features": elf_result.get("elf_features", {}),
                                        "static_analysis": {},
                                        "malware_categorization": [],
                                        "error": None
                                    }],
                                    "errors": []
                                }
                            else:
                                return {
                                    "results": [],
                                    "errors": [f"Error analyzing ELF file: {elf_result.get('error')}"]
                                }
                        else:
                            return {
                                "results": [],
                                "errors": [f"Error loading model for ELF analysis: {model_result.get('error')}"]
                            }
                    except Exception as e:
                        logger.error(f"Error analyzing ELF file: {str(e)}")
                        return {
                            "results": [],
                            "errors": [f"Error analyzing ELF file: {str(e)}"]
                        }
                else:
                    analyzer = DocumentAnalyzer()
                    doc_result = analyzer.analyze_document(str(final_file))
                    if not doc_result.get("error"):
                        return {
                            "results": [{
                                "type": final_file_type,
                                "document_analysis": doc_result,
                                "ember_probability": 0,
                                "ember_sha256": "",
                                "ember_important_features": {},
                                "static_analysis": {},
                                "malware_categorization": [],
                                "error": None
                            }],
                            "errors": []
                        }
                    else:
                        return {
                            "results": [],
                            "errors": [f"Error analyzing document: {doc_result.get('error')}"]
                        }
            except Exception as e:
                return {
                    "results": [],
                    "errors": [str(e)]
                }
        
        # Handle non-ZIP files
        try:
            result = {}
            if file_type == 'executable':
                # Handle executables
                exe_result = await analyze_executable(fp, out_dir)
                if exe_result.get("error"):
                    return {
                        "results": [],
                        "errors": [f"Error analyzing executable: {exe_result.get('error')}"]
                    }
                else:
                    result = {
                        "type": "executable",
                        "ember_probability": exe_result.get("ember_probability", 0.0),
                        "ember_sha256": exe_result.get("ember_sha256", ""),
                        "ember_important_features": exe_result.get("ember_important_features", {}),
                        "static_analysis": exe_result.get("static_analysis", {}),
                        "malware_categorization": exe_result.get("malware_categorization", {}),
                        "error": None
                    }
            elif file_type == 'elf':
                # Handle ELF files
                try:
                    extractor = ELFFeatureExtractor()
                    model_result = load_model()
                    if model_result.get("error"):
                        return {
                            "results": [],
                            "errors": [f"Error loading model for ELF analysis: {model_result.get('error')}"]
                        }
                    else:
                        model = model_result["model"]
                        elf_result = predict_elf_file(str(fp), model, extractor)
                        
                        if elf_result.get("error"):
                            return {
                                "results": [],
                                "errors": [f"Error analyzing ELF file: {elf_result.get('error')}"]
                            }
                        else:
                            result = {
                                "type": "elf",
                                "ember_probability": float(elf_result.get("elf_probability", 0.0)),
                                "ember_sha256": elf_result.get("sha256", ""),
                                "ember_important_features": elf_result.get("elf_features", {}),
                                "static_analysis": {},
                                "malware_categorization": [],
                                "error": None
                            }
                except Exception as e:
                    logger.error(f"Error analyzing ELF file: {str(e)}")
                    return {
                        "results": [],
                        "errors": [f"Error analyzing ELF file: {str(e)}"]
                    }
            else:
                # Handle documents using DocumentAnalyzer
                analyzer = DocumentAnalyzer()
                doc_result = analyzer.analyze_document(str(fp))
                if doc_result.get("error"):
                    return {
                        "results": [],
                        "errors": [f"Error analyzing document: {doc_result.get('error')}"]
                    }
                else:
                    result = {
                        "type": file_type,
                        "document_analysis": doc_result,
                        "ember_probability": 0,
                        "ember_sha256": "",
                        "ember_important_features": {},
                        "static_analysis": {},
                        "malware_categorization": [],
                        "error": None
                    }

            return {
                "results": [result],
                "errors": []
            }

        except Exception as e:
            logger.error(f"Error processing file: {str(e)}")
            return {
                "results": [],
                "errors": [str(e)]
            }

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            "results": [],
            "errors": [str(e)]
        }

@app.post("/analyze", response_model=MultiFileAnalysisResult)
async def analyze_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...)
):
    """Analyze multiple files in parallel"""
    try:
        if not files:
            raise HTTPException(status_code=400, detail="No files provided")

        # Process all files in parallel
        tasks = [process_single_file(file, background_tasks) for file in files]
        results = await asyncio.gather(*tasks)

        # Combine all results and errors
        all_results = []
        all_errors = []
        
        for result in results:
            if isinstance(result, dict):
                if "results" in result:
                    all_results.extend(result["results"])
                if "errors" in result:
                    all_errors.extend(result["errors"])
            else:
                all_errors.append(f"Unexpected result format: {result}")

        return MultiFileAnalysisResult(results=all_results, errors=all_errors)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return MultiFileAnalysisResult(results=[], errors=[str(e)])

def check_directory_access(path: Path):
    """Check if directory exists and is accessible"""
    if not path.exists():
        raise HTTPException(500, f"Directory {path} does not exist")
    if not os.access(path, os.R_OK | os.W_OK):
        raise HTTPException(500, f"Directory {path} is not accessible")

@app.on_event("startup")
async def startup_event():
    try:
        logger.info("Starting API initialization...")
        
        # Create and check directories
        for d in (DATA_DIR, OUTPUT_DIR):
            logger.info(f"Creating directory: {d}")
            os.makedirs(d, exist_ok=True)
            check_directory_access(d)
            logger.info(f"Directory {d} created and accessible")
        
        # Check Docker availability
        logger.info("Checking Docker availability...")
        await check_docker_availability()
        
        logger.info("API startup complete")
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}")
        raise

async def check_docker_availability():
    """Check if Docker is available and the retdec image exists"""
    try:
        logger.info("Checking if Docker is running...")
        # Check if Docker is running using subprocess.run
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            error_msg = f"Docker is not running: {result.stderr}"
            logger.error(error_msg)
            raise Exception(error_msg)
            
        logger.info("Docker is running. Checking for RetDec image...")
        # Check if retdec image exists
        result = subprocess.run(
            ["docker", "images", "retdec"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0 or not result.stdout:
            error_msg = "RetDec Docker image not found. Please pull the image using 'docker pull retdec'"
            logger.error(error_msg)
            raise Exception(error_msg)
            
        logger.info("Docker and RetDec image are available")
        
    except Exception as e:
        logger.error(f"Docker check failed: {str(e)}")
        raise HTTPException(500, f"Docker check failed: {str(e)}")

async def run_windows_static_analysis(file_path: Path) -> Dict[str, Any]:
    """Run Windows static analysis and malware categorization"""
    try:
        logger.info(f"[Windows Static] Starting analysis at {datetime.now().strftime('%H:%M:%S')}")
        
        # Run Windows static analyzer
        analyzer = WindowsExecutableAnalyzer(str(file_path))
        static_result = analyzer.analyze()
        
        # The report file is saved in the same directory as the input file
        report_file = file_path.parent / f"{file_path.name}_analysis_report.json"
        if not report_file.exists():
            raise FileNotFoundError(f"Analysis report file not found: {report_file}")
            
        with open(report_file, "r") as f:
            malware_data = json.load(f)
            
        # Pass the result to malware categorization
        logger.info(f"[Malware Categorization] Starting analysis at {datetime.now().strftime('%H:%M:%S')}")
        
        prompt = f"""
        You are a world-class malware analyst AI specialized in static analysis, malware classification, and behavioral profiling.

        You will be given a JSON-formatted malware analysis report, including (but not limited to):
        - YARA rule matches (rule names and tags)
        - Imported API calls or system functions
        - File metadata (hashes, filename)
        - Registry key indicators, strings, shellcode tags, or section names

        Your tasks:
        1. Parse the JSON input and identify:
           - Any suspicious or malicious behavior based on API calls (e.g., registry manipulation, process injection, privilege escalation, evasion, etc.).
           - What the YARA rule names and matched keywords suggest about the malware.
           - Any other key features suggesting the malwares objective or tactics.

        2. Use that behavioral analysis to assign a probability (in %) that the file belongs to each of the following malware families:

           ["Trojan Family", 
            "Backdoor and C2", 
            "Info Stealers", 
            "Exploitation and Execution Techniques", 
            "Payload Delivery & Infection Vectors", 
            "System Disruption Malware", 
            "Botnet / Worm / Beaconing"]

        3. The output must be a list of top four dicts, **sorted by descending probability**, where each dict contains:
           - `family`: Malware family name
           - `probability`: A float percentage (e.g., 42.5)
           - `rationale`: A short explanation (1-2 lines max) why this probability is assigned, referring to behavior, imports, and YARA rules

        Example Output Format:
        [
          {{
            "family": "Info Stealers",
            "probability": 41.7,
            "rationale": "YARA rule RustyStealer_Detect and registry-related APIs strongly suggest credential and token theft."
          }},
          ...
        ]

        Now analyze the following malware file:

        {json.dumps(malware_data, indent=2)}
        """

        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        
        # Try to parse the response text as JSON
        try:
            # Clean up the response text to ensure it's valid JSON
            response_text = response.text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            categorization_result = json.loads(response_text)
            
            # Validate the structure
            if not isinstance(categorization_result, list):
                raise ValueError("Expected a list of malware family categorizations")
            
            # Ensure each item has the required fields
            for item in categorization_result:
                if not all(key in item for key in ['family', 'probability', 'rationale']):
                    raise ValueError("Missing required fields in categorization result")
                
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse malware categorization result: {str(e)}")
            logger.error(f"Raw response: {response.text}")
            categorization_result = {
                "error": f"Failed to parse malware categorization result: {str(e)}",
                "raw_response": response.text
            }
            
        # Log the results for debugging
        logger.debug(f"Static analysis result: {json.dumps(static_result, indent=2)}")
        logger.debug(f"Malware categorization result: {json.dumps(categorization_result, indent=2)}")
            
        return {
            "static_analysis": static_result,
            "malware_categorization": categorization_result
        }
        
    except Exception as e:
        logger.error(f"[Windows Static] Analysis failed: {str(e)}")
        return {
            "static_analysis": {},
            "malware_categorization": {"error": str(e)}
        }

if __name__ == "__main__":
    import uvicorn
    try:
        logger.info("Starting uvicorn server...")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            workers=1,
            log_level="debug"
        )
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        raise
