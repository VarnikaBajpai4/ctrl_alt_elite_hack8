import os
import shutil
import tempfile
import asyncio
import subprocess
import sys
import json
from pathlib import Path
from typing import Dict, Any, Union
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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

for d in (OUTPUT_DIR, DATA_DIR):
    os.makedirs(d, exist_ok=True)

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

async def run_cmd(cmd, cwd=None):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise Exception(f"Command {' '.join(cmd)} failed: {err.decode()}")
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

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    try:
        # Generate unique filename to prevent conflicts
        unique_filename = f"{os.urandom(8).hex()}_{file.filename}"
        fp = DATA_DIR / unique_filename
        out_dir = OUTPUT_DIR / unique_filename.rsplit(".", 1)[0]

        # 1) Save uploaded binary
        with open(fp, "wb") as f:
            f.write(await file.read())

        # 2) RetDec decompile into a temp dir via Docker
        with tempfile.TemporaryDirectory() as tmp:
            tmp_bin = os.path.join(tmp, unique_filename)
            shutil.copy2(fp, tmp_bin)

            await run_cmd([
                "docker", "run", "--rm",
                "-v", f"{tmp}:/destination",
                "retdec",
                "retdec-decompiler", f"/destination/{unique_filename}"
            ])

            # Move all outputs to OUTPUT_DIR/<sample>/
            if out_dir.exists():
                shutil.rmtree(out_dir)
            shutil.copytree(tmp, out_dir)

        # 3) Run RetDec feature extraction
        retbec_proc = subprocess.check_output([
            sys.executable,
            str(RETBEC_DIR / "retbec_check.py"),
            str(out_dir)
        ])
        retbec_res = json.loads(retbec_proc)
        
        if not retbec_res["retbec_success"]:
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
        ember_proc = subprocess.check_output([
            "docker", "run", "--rm",
            "-v", f"{DATA_DIR}:/data",
            "-v", f"{EMBER_DIR}:/ember",
            "ember",
            "python", "/ember/predict.py", f"/data/{unique_filename}"
        ])
        ember_res = json.loads(ember_proc)

        # 5) Run Gemini analysis
        gemini_proc = subprocess.check_output([
            sys.executable,
            str(RETBEC_DIR / "malware_analysis.py"),
            str(out_dir)
        ])
        gemini_res = json.loads(gemini_proc)

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

        result = AnalysisResult(
            ember_probability=ember_res["probability"],
            gemini_probability=gemini_res["malware_probability"],
            ember_sha256=ember_res["sha256"],
            ember_important_features=ember_res["features"],
            retdec_architecture=retdec_features.get("architecture", {}),
            retdec_file_format=retdec_features.get("file_format", ""),
            retdec_imports=retdec_features.get("retdec_imports", {}),
            retdec_suspicious_calls=suspicious_calls,
            suspicious_indicators=gemini_res["suspicious_indicators"],
            behavioral_patterns=gemini_res["behavioral_patterns"],
            potential_impact=gemini_res["potential_impact"],
            confidence_score=gemini_res["confidence_score"]
        )

        # Schedule cleanup
        background_tasks.add_task(cleanup_files, fp, out_dir)

        return result

    except Exception as e:
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
            error=str(e)
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        workers=1
    )
