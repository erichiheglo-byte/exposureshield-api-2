$ErrorActionPreference = "Stop"

$proj   = "C:\exposureshield-api-3"
$python = Join-Path $proj ".venv\Scripts\python.exe"

# Start uvicorn minimized & detached from this window
Start-Process -FilePath $python `
  -ArgumentList '-m uvicorn main:app --host 0.0.0.0 --port 8888' `
  -WorkingDirectory $proj `
  -WindowStyle Minimized
