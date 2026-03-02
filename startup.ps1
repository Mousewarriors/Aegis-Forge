# Aegis Forge: Unified Startup Script
# This script ensures all dependencies and services are running.

function Write-Step {
    param([string]$Message)
    Write-Host "`n🚀 [STEP] $Message" -ForegroundColor Cyan
}

# 1. Check Docker
Write-Step "Verifying Docker..."
try {
    docker ps > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⏳ Starting Docker Desktop..." -ForegroundColor Yellow
        Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        Start-Sleep -Seconds 15
    } else {
        Write-Host "✅ Docker is running." -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Docker not found." -ForegroundColor Red
}

# 2. Check Ollama
Write-Step "Verifying Ollama and Llama3.1:8b..."
try {
    $ollamaCheck = ollama list 2>&1
    if ($ollamaCheck -like "*error*") {
        Write-Host "⏳ Starting Ollama..." -ForegroundColor Yellow
        Start-Process "ollama" "serve"
        Start-Sleep -Seconds 5
    }
    Write-Host "⏳ Pulling llama3.1:8b (if missing)..." -ForegroundColor Yellow
    ollama pull llama3.1:8b
    Write-Host "✅ Ollama is ready." -ForegroundColor Green
} catch {
    Write-Host "❌ Ollama not found." -ForegroundColor Red
}

# 3. Start Backend
Write-Step "Starting Backend Service (Port 8000)..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd backend; .\venv\Scripts\activate; python main.py"
Write-Host "✅ Backend initiated in background." -ForegroundColor Green

# 4. Start Frontend
Write-Step "Starting Frontend App (Port 3000)..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd frontend; npm run dev"
Write-Host "✅ Frontend initiated in background." -ForegroundColor Green

# 5. Start Promptfoo View
Write-Step "Starting Promptfoo Viewer (Port 15500)..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd promptfoo-eval; npx promptfoo@latest view -p 15500 -y"
Write-Host "✅ Promptfoo viewer initiated in background." -ForegroundColor Green

Write-Host "`n✨ Aegis Forge Environment is coming online!" -ForegroundColor Magenta
Write-Host "--------------------------------------------------" -ForegroundColor Gray
Write-Host "Frontend:   http://localhost:3000"
Write-Host "Backend:    http://localhost:8000" 
Write-Host "Promptfoo:  http://localhost:15500"
Write-Host "--------------------------------------------------" -ForegroundColor Gray
