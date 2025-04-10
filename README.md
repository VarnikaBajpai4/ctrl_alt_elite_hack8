# ctrl_alt_elite_hack8

## Setup Instructions

### Prerequisites
- Docker installed on your system
- Python 3.8+ installed
- Docker Compose (for the main API)

### Setup Steps

1. Clone the repository:
```bash
git clone <your-repo-url>
cd ctrl_alt_elite_hack8
```

2. Build the required Docker images:
```bash
# Build RetDec image
cd ML_Models/retbec
docker build -t retdec .

# Build EMBER image
cd ../ember
docker build -t ember .
```

3. Install Python dependencies for the main API:
```bash
cd ../main
pip install -r requirements.txt
```

### Important Notes
- The EMBER model requires three model files that need to be obtained separately:
  - ember_model_final.txt
  - ember_model_finetuned.txt
  - ember_model_2018.txt
- These model files should be placed in the root directory of the project
- The data directory is used for storing PE files for analysis

### Running the API
```bash
cd ML_Models/main
python main.py
```
The API will be available at http://localhost:8000

### Documentation
Once the API is running, you can access:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Repository Structure
The repository contains multiple components:
- EMBER malware detection system
- RetDec decompiler
- Main API service
- Data processing utilities

Each component has its own Docker container and requirements, but they work together to provide a complete malware analysis system.