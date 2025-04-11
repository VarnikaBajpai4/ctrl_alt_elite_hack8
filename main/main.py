import os
import shutil
import tempfile
import asyncio
import subprocess
import sys
import json
import logging
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
    # Probabilities
    ember_probability: float
    gemini_probability: float
    
    # EMBER Features
    ember_sha256: str
    ember_important_features: Dict[str, Any]
    
    # RetDec Features
    retdec_architecture: Dict[str, Any]
    retdec_file_format: str
    retdec_imports: Dict[str, Any]
    retdec_suspicious_calls: Dict[str, bool]
    
    # Gemini Analysis
    suspicious_indicators: list[str]
    behavioral_patterns: list[str]
    potential_impact: str
    confidence_score: float
    
    error: str = None

    class Config:
        json_encoders = {
            float: lambda v: round(float(v), 5)  # Format floats to 5 decimal places
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
        
        # Run RetDec decompiler with proper output path
        logger.debug("Starting RetDec decompilation")
        try:
            # Convert Windows paths to Docker-compatible paths
            data_path = str(DATA_DIR).replace('\\', '/')
            output_path = str(OUTPUT_DIR).replace('\\', '/')
            output_subdir = unique_filename.rsplit('.', 1)[0]
            
            # Ensure directories exist and are accessible
            os.makedirs(DATA_DIR, exist_ok=True)
            os.makedirs(out_dir, exist_ok=True)
            
            # Run Docker with proper path handling and error capture
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{data_path}:/data",
                "-v", f"{output_path}:/output",
                "retdec",
                "retdec-decompiler",
                f"/data/{unique_filename}",
                "-o", f"/output/{output_subdir}/{unique_filename.rsplit('.', 1)[0]}.c"
            ]
            
            logger.debug(f"Running Docker command: {' '.join(cmd)}")
            
            # Run the command and capture both stdout and stderr
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                error_msg = f"RetDec decompilation failed with return code {result.returncode}\n"
                if result.stderr:
                    error_msg += f"Error output: {result.stderr}\n"
                if result.stdout:
                    error_msg += f"Standard output: {result.stdout}\n"
                error_msg += f"Data path: {data_path}\n"
                error_msg += f"Output path: {output_path}\n"
                error_msg += f"File: {unique_filename}"
                logger.error(error_msg)
                raise HTTPException(500, error_msg)
                
            logger.debug(f"RetDec decompilation output: {result.stdout}")
            
            # Check if output files were created in the correct location
            output_files = list(out_dir.glob("*"))
            if not output_files:
                error_msg = f"No output files were created in {out_dir}"
                logger.error(error_msg)
                raise HTTPException(500, error_msg)
            logger.debug(f"Output files created: {[f.name for f in output_files]}")
            
        except Exception as e:
            logger.error(f"RetDec decompilation failed: {str(e)}")
            error_msg = f"RetDec decompilation failed: {str(e)}\n"
            error_msg += f"Data path: {data_path}\n"
            error_msg += f"Output path: {output_path}\n"
            error_msg += f"File: {unique_filename}"
            raise HTTPException(500, error_msg)

        # 3) Run RetDec feature extraction
        try:
            retbec_proc = subprocess.run(
                [sys.executable, str(RETBEC_DIR / "retbec_check.py"), str(out_dir)],
                capture_output=True,
                text=True
            )
            if retbec_proc.returncode != 0:
                logger.error(f"RetDec feature extraction failed: {retbec_proc.stderr}")
                raise Exception(f"RetDec feature extraction failed: {retbec_proc.stderr}")
                
            retbec_res = json.loads(retbec_proc.stdout.strip())
            
            if not retbec_res.get("retbec_success"):
                return AnalysisResult(
                    ember_probability=0.0,
                    gemini_probability=0.0,
                    ember_sha256="",
                    ember_important_features={},
                    retdec_architecture={},
                    retdec_file_format="",
                    retdec_imports={},
                    retdec_suspicious_calls={},
                    suspicious_indicators=[],
                    behavioral_patterns=[],
                    potential_impact="",
                    confidence_score=0.0,
                    error="Failed to extract features from RetDec output"
                )

            # 4) Run EMBER prediction
            try:
                ember_proc = subprocess.run(
                    ["docker", "run", "--rm",
                     "-v", f"{data_path}:/data",
                     "-v", f"{EMBER_DIR}:/ember",
                     "ember",
                     "python", "/ember/predict.py", f"/data/{unique_filename}"],
                    capture_output=True,
                    text=True
                )
                if ember_proc.returncode != 0:
                    logger.error(f"EMBER prediction failed: {ember_proc.stderr}")
                    raise Exception(f"EMBER prediction failed: {ember_proc.stderr}")
                
                # Debug log the raw output
                logger.debug(f"Raw EMBER output: {ember_proc.stdout}")
                
                # Clean and parse the JSON output
                cleaned_output = ember_proc.stdout.strip()
                ember_res = json.loads(cleaned_output)
                
                # Debug log the parsed result
                logger.debug(f"Parsed EMBER result: {ember_res}")
                
                # Ensure we have a valid probability
                if "probability" not in ember_res or not isinstance(ember_res["probability"], (int, float)):
                    logger.error(f"Invalid EMBER probability format: {ember_res.get('probability')}")
                    raise Exception("Invalid EMBER probability format")
                
                # Convert scientific notation to decimal and round
                ember_prob = float(ember_res["probability"])
                ember_prob = round(ember_prob, 5)
                
                logger.debug(f"Formatted EMBER probability: {ember_prob}")
                
                ember_res["probability"] = ember_prob
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse EMBER output: {e}")
                logger.error(f"EMBER output: {ember_proc.stdout}")
                raise HTTPException(status_code=500, detail=f"Failed to parse EMBER output: {e}")
            except Exception as e:
                logger.error(f"EMBER analysis failed: {str(e)}")
                raise HTTPException(status_code=500, detail=f"EMBER analysis failed: {str(e)}")

            # 5) Run Gemini analysis
            try:
                gemini_proc = subprocess.run(
                    [sys.executable, str(RETBEC_DIR / "malware_analysis.py"), str(out_dir)],
                    capture_output=True,
                    text=True
                )
                if gemini_proc.returncode != 0:
                    logger.error(f"Gemini analysis failed: {gemini_proc.stderr}")
                    raise Exception(f"Gemini analysis failed: {gemini_proc.stderr}")
                    
                gemini_res = json.loads(gemini_proc.stdout.strip())
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Gemini output: {e}")
                logger.error(f"Gemini output: {gemini_proc.stdout}")
                raise Exception(f"Failed to parse Gemini output: {e}")

            if "error" in gemini_res:
                return AnalysisResult(
                    ember_probability=0.0,
                    gemini_probability=0.0,
                    ember_sha256="",
                    ember_important_features={},
                    retdec_architecture={},
                    retdec_file_format="",
                    retdec_imports={},
                    retdec_suspicious_calls={},
                    suspicious_indicators=[],
                    behavioral_patterns=[],
                    potential_impact="",
                    confidence_score=0.0,
                    error=gemini_res["error"]
                )

            # Extract important features from RetDec
            retdec_features = retbec_res["retbec_features"]
            suspicious_calls = {
                "VirtualAlloc": retdec_features.get("kw_VirtualAlloc", False),
                "WriteProcessMemory": retdec_features.get("kw_WriteProcessMemory", False),
                "CreateRemoteThread": retdec_features.get("kw_CreateRemoteThread", False),
                "GetProcAddress": retdec_features.get("kw_GetProcAddress", False),
                "LoadLibrary": retdec_features.get("kw_LoadLibrary", False)
            }

            # Format probabilities before returning
            result = AnalysisResult(
                ember_probability=ember_prob,  # Use the formatted probability
                gemini_probability=round(float(gemini_res.get("malware_probability", 0.0)), 5),
                ember_sha256=ember_res.get("sha256", ""),
                ember_important_features=ember_res.get("features", {}),
                retdec_architecture=retdec_features.get("architecture", {}),
                retdec_file_format=retdec_features.get("file_format", ""),
                retdec_imports=retdec_features.get("retdec_imports", {}),
                retdec_suspicious_calls=suspicious_calls,
                suspicious_indicators=gemini_res.get("suspicious_indicators", []),
                behavioral_patterns=gemini_res.get("behavioral_patterns", []),
                potential_impact=gemini_res.get("potential_impact", ""),
                confidence_score=round(float(gemini_res.get("confidence_score", 0.0)), 5)
            )

            return result

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to parse analysis results: {str(e)}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Process error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Analysis process failed: {str(e)}")
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    except HTTPException:
        raise  # Re-raise HTTP exceptions as is
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    finally:
        # Schedule cleanup regardless of success/failure
        background_tasks.add_task(cleanup_files, fp, out_dir)

async def check_docker_availability():
    """Check if Docker is available and the retdec image exists"""
    try:
        # Check if Docker is running using subprocess.run
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise Exception(f"Docker is not running: {result.stderr}")
            
        # Check if retdec image exists
        result = subprocess.run(
            ["docker", "images", "retdec"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0 or not result.stdout:
            raise Exception("RetDec Docker image not found. Please pull the image using 'docker pull retdec'")
            
        logger.info("Docker and RetDec image are available")
        
    except Exception as e:
        logger.error(f"Docker check failed: {str(e)}")
        raise HTTPException(500, f"Docker check failed: {str(e)}")

@app.on_event("startup")
async def startup_event():
    # Create and check directories
    for d in (DATA_DIR, OUTPUT_DIR):
        os.makedirs(d, exist_ok=True)
        check_directory_access(d)
    
    # Check Docker availability
    await check_docker_availability()
    
    logger.info("API startup complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        workers=1
    )
