# EMBER Malware Detection System

This repository contains the EMBER (Endgame Malware BEnchmark for Research) malware detection system with pre-trained models.

## Prerequisites

- Docker installed on your system
- The three model files (these need to be obtained separately):
  - ember_model_final.txt
  - ember_model_finetuned.txt
  - ember_model_2018.txt

## Setup Instructions

### For Windows PowerShell Users

1. Clone this repository:
```powershell
git clone <your-repo-url>
cd ember
```

2. Place the three model files in the root directory of the project:
   - ember_model_final.txt
   - ember_model_finetuned.txt
   - ember_model_2018.txt

3. Create a data directory for your PE files:
```powershell
mkdir data
```

4. Build the Docker image:
```
docker build -t ember .
```

5. Run the Docker container:
```powershell
docker run -d -v ${PWD}:/ember -v ${PWD}/data:/ember/data ember tail -f /dev/null
```

6. Get your container ID (it will look like `bbc7776cd33a`):
```powershell
docker ps
```

7. Get into the container's bash shell:
```powershell
docker exec -it <containerID> /bin/bash
```

### For Mac/Linux Users

1. Clone this repository:
```bash
git clone <your-repo-url>
cd ember
```

2. Place the three model files in the root directory of the project:
   - ember_model_final.txt
   - ember_model_finetuned.txt
   - ember_model_2018.txt

3. Create a data directory for your PE files:
```bash
mkdir data
```

4. Build the Docker image:
```bash
docker build -t ember .
```

5. Run the Docker container:
```bash
docker run -d -v "$PWD":/ember -v "$PWD/data":/ember/data ember tail -f /dev/null
```

6. Get your container ID (it will look like `bbc7776cd33a`):
```bash
docker ps
```

7. Get into the container's bash shell:
```bash
docker exec -it bbc7776cd33a /bin/bash
```

## Usage

Once you're in the container's bash shell, you can run any of these commands directly:

### Running Predictions
```bash
python predict.py
```

### Running Tests
```bash
python test.py
```

### Checking Precision
```bash
python precision.py
```

## File Structure

```
ember/
├── Dockerfile              # Docker configuration
├── README.md               # This file
├── requirements.txt        # Python package requirements
├── requirements_conda.txt  # Conda package requirements
├── setup.py                # EMBER package setup
├── predict.py              # Prediction script
├── test.py                 # Test script
├── precision.py            # Precision checking script
├── ember/                  # EMBER package
│   ├── __init__.py
│   └── features.py
└── data/                   # Directory for your PE files
```

## Model Files

The following model files are required but not included in the repository due to size constraints:
- ember_model_final.txt
- ember_model_finetuned.txt
- ember_model_2018.txt

Please obtain these files from the official EMBER repository or contact the maintainers.

## Notes

- All paths in the scripts are relative to the project root
- The Docker container mounts the entire project directory to /workspace, so changes to any file will be immediately available without rebuilding
- Make sure your PE files are in the `data` directory before running predictions
- To exit the bash shell: type `exit` or press Ctrl+D
- To stop the Docker container when you're done: `docker stop bbc7776cd33a`
- To restart the container later: `docker start bbc7776cd33a`
