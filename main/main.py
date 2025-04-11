import os
import shutil
import tempfile
import asyncio
import subprocess
import sys
import json
import logging
import magic
from pathlib import Path
from typing import Dict, Any, Union
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import docker

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
RETBEC_DIR = BASE_DIR.parent / "retbec"    # ../retbec
EMBER_DIR = BASE_DIR.parent / "ember"      # ../ember
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
    gemini_probability: float = 0.0
    ember_sha256: str = ""
    ember_important_features: Dict[str, Any] = {}
    retdec_architecture: Dict[str, Any] = {}
    retdec_file_format: str = ""
    retdec_imports: Dict[str, Any] = {}
    retdec_suspicious_calls: Dict[str, bool] = {}
    suspicious_indicators: list[str] = []
    behavioral_patterns: list[str] = []
    potential_impact: str = ""
    confidence_score: float = 0.0
    
    error: Union[str, None] = None

    class Config:
        json_encoders = {
            float: lambda v: round(float(v), 5)  # Format floats to 5 decimal places
        }

def detect_file_type(file_path: Path) -> str:
    """Detect file type using python-magic"""
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(str(file_path))
    
    # Map MIME types to our categories
    if file_type == 'application/pdf':
        return 'pdf'
    elif file_type in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                      'application/msword',
                      'application/vnd.ms-word']:
        return 'doc'
    elif file_type in ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                      'application/vnd.ms-excel',
                      'application/vnd.ms-excel.sheet.macroEnabled.12']:
        return 'doc'  # Treat Excel files as documents
    elif file_type in ['application/x-msdownload',
                      'application/x-dosexec',
                      'application/x-ms-dos-executable',
                      'application/x-executable',
                      'application/x-sharedlib']:
        return 'executable'
    else:
        return 'unknown'

async def analyze_document(file_path: Path, file_type: str) -> Dict[str, Any]:
    """Analyze document files using document_feature_extractor"""
    try:
        from document_feature_extractor import DocumentAnalyzer
        analyzer = DocumentAnalyzer()
        result = analyzer.analyze_document(str(file_path), file_type)
        return {
            "document_analysis": result,
            "error": None
        }
    except Exception as e:
        logger.error(f"Document analysis failed: {str(e)}")
        return {
            "document_analysis": {},
            "error": f"Document analysis failed: {str(e)}"
        }

async def analyze_executable(file_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Analyze executable files using the existing pipeline"""
    try:
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
        
        logger.debug(f"Running Docker command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
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
        retbec_proc = subprocess.run(
            [sys.executable, str(RETBEC_DIR / "retbec_check.py"), str(out_dir)],
            capture_output=True,
            text=True
        )
        if retbec_proc.returncode != 0:
            raise Exception(f"RetDec feature extraction failed: {retbec_proc.stderr}")
            
        retbec_res = json.loads(retbec_proc.stdout.strip())
        if not retbec_res.get("retbec_success"):
            return {
                "error": "Failed to extract features from RetDec output"
            }
            
        # Run EMBER prediction
        ember_proc = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{data_path}:/data",
             "-v", f"{EMBER_DIR}:/ember",
             "ember",
             "python", "/ember/predict.py", f"/data/{file_path.name}"],
            capture_output=True,
            text=True
        )
        if ember_proc.returncode != 0:
            raise Exception(f"EMBER prediction failed: {ember_proc.stderr}")
            
        ember_res = json.loads(ember_proc.stdout.strip())
        ember_prob = round(float(ember_res["probability"]), 5)
        
        # Run Gemini analysis
        gemini_proc = subprocess.run(
            [sys.executable, str(RETBEC_DIR / "malware_analysis.py"), str(out_dir)],
            capture_output=True,
            text=True
        )
        if gemini_proc.returncode != 0:
            raise Exception(f"Gemini analysis failed: {gemini_proc.stderr}")
            
        gemini_res = json.loads(gemini_proc.stdout.strip())
        if "error" in gemini_res:
            return {
                "error": gemini_res["error"]
            }
            
        # Extract important features from RetDec
        retdec_features = retbec_res["retbec_features"]
        suspicious_calls = {
            "VirtualAlloc": retdec_features.get("kw_VirtualAlloc", False),
            "WriteProcessMemory": retdec_features.get("kw_WriteProcessMemory", False),
            "CreateRemoteThread": retdec_features.get("kw_CreateRemoteThread", False),
            "GetProcAddress": retdec_features.get("kw_GetProcAddress", False),
            "LoadLibrary": retdec_features.get("kw_LoadLibrary", False)
        }
        
        return {
            "ember_probability": ember_prob,
            "gemini_probability": round(float(gemini_res.get("malware_probability", 0.0)), 5),
            "ember_sha256": ember_res.get("sha256", ""),
            "ember_important_features": ember_res.get("features", {}),
            "retdec_architecture": retdec_features.get("architecture", {}),
            "retdec_file_format": retdec_features.get("file_format", ""),
            "retdec_imports": retdec_features.get("retdec_imports", {}),
            "retdec_suspicious_calls": suspicious_calls,
            "suspicious_indicators": gemini_res.get("suspicious_indicators", []),
            "behavioral_patterns": gemini_res.get("behavioral_patterns", []),
            "potential_impact": gemini_res.get("potential_impact", ""),
            "confidence_score": round(float(gemini_res.get("confidence_score", 0.0)), 5),
            "error": None
        }
        
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

def cleanup_files(file_path: Path, output_dir: Path):
    """Cleanup files after analysis"""
    try:
        if file_path.exists():
            file_path.unlink()
        if output_dir.exists():
            shutil.rmtree(output_dir)
    except Exception as e:
        print(f"Error during cleanup: {e}")

def check_directory_access(path: Path):
    """Check if directory exists and is accessible"""
    if not path.exists():
        raise HTTPException(500, f"Directory {path} does not exist")
    if not os.access(path, os.R_OK | os.W_OK):
        raise HTTPException(500, f"Directory {path} is not accessible")

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")

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
                    raise HTTPException(status_code=400, detail="Empty file provided")
                logger.debug(f"File size: {len(content)} bytes")
                f.write(content)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

        # Check if file exists and is accessible
        if not fp.exists():
            raise HTTPException(status_code=500, detail=f"Failed to save file to {fp}")
        
        # Create output directory
        os.makedirs(out_dir, exist_ok=True)
        
        # Detect file type
        file_type = detect_file_type(fp)
        logger.debug(f"Detected file type: {file_type}")
        
        if file_type in ['pdf', 'doc']:
            # Handle document files
            result = await analyze_document(fp, file_type)
            if result.get("error"):
                return AnalysisResult(type="document", error=result["error"])
            return AnalysisResult(type="document", document_analysis=result)
        elif file_type == 'executable':
            # Handle executable files using existing pipeline
            result = await analyze_executable(fp, out_dir)
            if result.get("error"):
                return AnalysisResult(type="executable", error=result["error"])
            return AnalysisResult(type="executable", **result)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {file_type}. Supported types: PDF, Office documents, executables"
            )

    except HTTPException:
        raise  # Re-raise HTTP exceptions as is
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return AnalysisResult(type="unknown", error=str(e))

    finally:
        # Schedule cleanup regardless of success/failure
        background_tasks.add_task(cleanup_files, fp, out_dir)

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
