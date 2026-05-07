# Enterprise SIEM Platform - Startup Script
Write-Host "`n=== Enterprise Security Monitoring Platform ===" -ForegroundColor Cyan
Write-Host "Starting all services...`n" -ForegroundColor Gray

$RootDir = Split-Path $PSScriptRoot -Parent
Set-Location $RootDir

# Check Python (try both py launcher and python)
$pythonCmd = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } elseif (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { $null }
if (-not $pythonCmd) {
    Write-Host "[ERROR] Python not found. Install Python 3.10+ from python.org" -ForegroundColor Red
    exit 1
}
$pythonVersion = & $pythonCmd --version 2>&1
Write-Host "[OK] Python: $pythonVersion" -ForegroundColor Green

# Check Node
try {
    $nodeVersion = node --version 2>&1
    Write-Host "[OK] Node.js: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Node.js not found. Install from nodejs.org" -ForegroundColor Red
    exit 1
}

# Install Python deps
Write-Host "`nInstalling Python dependencies..." -ForegroundColor Yellow
& $pythonCmd -m pip install -r requirements.txt -q
Write-Host "[OK] Python dependencies installed" -ForegroundColor Green

# Generate demo data if DB doesn't exist
if (-not (Test-Path "siem.db")) {
    Write-Host "`nGenerating demo data (first run)..." -ForegroundColor Yellow
    & $pythonCmd scripts/generate_demo_data.py
} else {
    Write-Host "[OK] Database exists, skipping demo data generation" -ForegroundColor Green
}

# Install frontend deps if needed
if (-not (Test-Path "frontend/node_modules")) {
    Write-Host "`nInstalling frontend dependencies..." -ForegroundColor Yellow
    Set-Location frontend
    npm install --legacy-peer-deps -q
    Set-Location $RootDir
    Write-Host "[OK] Frontend dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[OK] Frontend node_modules exist" -ForegroundColor Green
}

# Start backend in background
Write-Host "`nStarting FastAPI backend on http://localhost:8000..." -ForegroundColor Yellow
$backend = Start-Process -PassThru -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/c $pythonCmd -m backend.main"
Start-Sleep 2

# Test backend
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8000/api/health" -TimeoutSec 5
    Write-Host "[OK] Backend running: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Backend health check failed - it may still be starting" -ForegroundColor Yellow
}

# Start frontend
Write-Host "`nStarting React frontend on http://localhost:5173..." -ForegroundColor Yellow
Write-Host "`n=== Services Running ===" -ForegroundColor Cyan
Write-Host "  Backend API:  http://localhost:8000" -ForegroundColor White
Write-Host "  Frontend:     http://localhost:5173" -ForegroundColor White
Write-Host "  API Docs:     http://localhost:8000/docs" -ForegroundColor White
Write-Host "`nPress Ctrl+C to stop the frontend. Backend PID: $($backend.Id)`n" -ForegroundColor Gray

Set-Location frontend
npm run dev
