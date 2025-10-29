# --- ExposureShield API launcher ---
Write-Host "Starting ExposureShield backend (FastAPI)..." -ForegroundColor Cyan

# Activate virtual environment
if (Test-Path ".\.venv\Scripts\activate") {
    .\.venv\Scripts\activate
} else {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
    .\.venv\Scripts\activate
    pip install -r requirements.txt
}

# Ensure email validator is installed
pip install "pydantic[email]" --quiet

# Start the API server
uvicorn main:app --host 0.0.0.0 --port 8889
