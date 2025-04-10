# Malware Analysis API

This API provides endpoints for analyzing malware samples using RetDec for decompilation and EMBER for prediction.

## Prerequisites

- Docker and Docker Compose installed
- Python 3.8+ installed
- The RetDec and EMBER Docker images built

## Setup

1. Build the Docker images for RetDec and EMBER:

```bash
# Build RetDec image
cd ../retbec
docker build -t retdec .

# Build EMBER image
cd ../ember
docker build -t ember .
```

2. Install the Python dependencies:

```bash
cd ../ml
pip install -r requirements.txt
```

## Running the API

Start the API server:

```bash
python main.py
```

The API will be available at http://localhost:8000.

## API Endpoints

### POST /analyze

Upload a malware sample for analysis.

**Request:**
- Form data with a file field containing the malware sample

**Response:**
```json
{
  "success": true,
  "message": "Analysis completed successfully",
  "features": {
    // Extracted features from RetDec
  },
  "prediction": null  // Will be updated by background task
}
```

### GET /health

Check if the API is running.

**Response:**
```json
{
  "status": "ok"
}
```

## API Documentation

Once the API is running, you can access the interactive API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc 