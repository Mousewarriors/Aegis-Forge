# Aegis Forge: Unified Startup Script
# This script ensures all dependencies and services are running.

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $scriptRoot "backend"
$frontendDir = Join-Path $scriptRoot "frontend"
$promptfooDir = Join-Path $scriptRoot "promptfoo-eval"
$backendPython = Join-Path $backendDir "venv\Scripts\python.exe"
$runtimeDir = Join-Path $scriptRoot ".tmp"
$managedPidFile = Join-Path $runtimeDir "startup-managed-pids.json"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[STEP] $Message" -ForegroundColor Cyan
}

function Start-ServiceWindow {
    param(
        [string]$WorkingDirectory,
        [string]$Command
    )

    $escapedWorkingDirectory = $WorkingDirectory -replace "'", "''"
    $fullCommand = "Set-Location -LiteralPath '$escapedWorkingDirectory'; $Command"

    Start-Process powershell `
        -WindowStyle Hidden `
        -WorkingDirectory $WorkingDirectory `
        -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $fullCommand `
        -PassThru
}

function Get-ManagedStartupPids {
    if (-not (Test-Path $managedPidFile)) {
        return @()
    }
    try {
        $raw = Get-Content $managedPidFile -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return @()
        }
        $items = ConvertFrom-Json $raw
        if ($items -is [System.Array]) {
            return $items
        }
        if ($null -ne $items) {
            return @($items)
        }
    } catch {
    }
    return @()
}

function Save-ManagedStartupPids {
    param(
        [int[]]$Pids
    )

    if (-not (Test-Path $runtimeDir)) {
        New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
    }
    $safePids = @($Pids | Where-Object { $_ -gt 0 } | Select-Object -Unique)
    $safePids | ConvertTo-Json | Set-Content -Encoding UTF8 $managedPidFile
}

function Stop-ManagedStartupProcesses {
    $managedPids = Get-ManagedStartupPids
    foreach ($pidItem in $managedPids) {
        $pidValue = 0
        if ([int]::TryParse([string]$pidItem, [ref]$pidValue)) {
            Stop-ProcessTree -ProcessId $pidValue
        }
    }
    Save-ManagedStartupPids -Pids @()
}

function Stop-ProcessTree {
    param(
        [int]$ProcessId
    )
    if ($ProcessId -le 0) {
        return
    }
    try {
        taskkill /PID $ProcessId /T /F > $null 2>&1
    } catch {
    }
}

function Get-ProtectedProcessIds {
    $protected = @{}
    try {
        $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId
        $parentMap = @{}
        foreach ($proc in $all) {
            $parentMap[[int]$proc.ProcessId] = [int]$proc.ParentProcessId
        }

        $cursor = [int]$PID
        while ($cursor -gt 0) {
            $protected[$cursor] = $true
            if (-not $parentMap.ContainsKey($cursor)) {
                break
            }
            $next = [int]$parentMap[$cursor]
            if ($next -le 0 -or $protected.ContainsKey($next)) {
                break
            }
            $cursor = $next
        }
    } catch {
        $protected[[int]$PID] = $true
    }
    return $protected
}

function Is-AegisServiceProcess {
    param(
        [string]$CommandLine,
        [string]$RootPath
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }

    $lower = $CommandLine.ToLowerInvariant()
    $normalized = $lower.Replace("\", "/")
    $rootMarker = [string]$RootPath
    $rootMarker = $rootMarker.ToLowerInvariant().Replace("\", "/")

    $looksLikeAegis = $normalized.Contains($rootMarker) -or $lower.Contains("aegis-forge")
    $isServiceCmd = $lower.Contains("main.py") -or $lower.Contains("npm run dev") -or ($lower.Contains("promptfoo") -and $lower.Contains("15500"))
    return $looksLikeAegis -and $isServiceCmd
}

function Is-LegacyServiceCommand {
    param(
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }

    $lower = $CommandLine.ToLowerInvariant()
    $isLegacyPowerShellService =
        ($lower.Contains("-noexit") -and $lower.Contains("-command npm run dev")) -or
        ($lower.Contains("-noexit") -and $lower.Contains("-command npx promptfoo@latest view -p 15500 -y")) -or
        ($lower.Contains("-noexit") -and $lower.Contains("-command python main.py"))
    return $isLegacyPowerShellService
}

function Stop-ListenersOnPort {
    param(
        [int]$Port,
        [string]$RootPath,
        [hashtable]$ProtectedPids
    )
    try {
        $lines = netstat -ano | Select-String ":$Port"
        foreach ($line in $lines) {
            $parts = ($line.ToString() -split "\s+") | Where-Object { $_ -ne "" }
            if ($parts.Length -ge 5) {
                $pidText = $parts[-1]
                $pidValue = 0
                if ([int]::TryParse($pidText, [ref]$pidValue)) {
                    if ($ProtectedPids.ContainsKey($pidValue)) {
                        continue
                    }
                    $owner = Get-CimInstance Win32_Process -Filter "ProcessId=$pidValue" -ErrorAction SilentlyContinue
                    $cmd = [string]($owner.CommandLine)
                    if ((Is-AegisServiceProcess -CommandLine $cmd -RootPath $RootPath) -or (Is-LegacyServiceCommand -CommandLine $cmd)) {
                        Stop-ProcessTree -ProcessId $pidValue
                    }
                }
            }
        }
    } catch {
    }
}

function Stop-AegisServiceProcesses {
    param(
        [string]$RootPath
    )

    # First kill launcher shells from previous startup runs.
    Stop-ManagedStartupProcesses

    $protectedPids = Get-ProtectedProcessIds
    $targets = @()
    try {
        $processes = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe' OR Name='node.exe' OR Name='python.exe'"
        foreach ($proc in $processes) {
            $procId = [int]$proc.ProcessId
            if ($protectedPids.ContainsKey($procId)) {
                continue
            }
            $cmd = [string]($proc.CommandLine)
            if (Is-AegisServiceProcess -CommandLine $cmd -RootPath $RootPath) {
                $targets += $procId
            }
        }
    } catch {
    }

    foreach ($procId in ($targets | Sort-Object -Unique)) {
        Stop-ProcessTree -ProcessId $procId
    }

    # Belt-and-braces: ensure service ports are free.
    Stop-ListenersOnPort -Port 8000 -RootPath $RootPath -ProtectedPids $protectedPids
    Stop-ListenersOnPort -Port 3000 -RootPath $RootPath -ProtectedPids $protectedPids
    Stop-ListenersOnPort -Port 15500 -RootPath $RootPath -ProtectedPids $protectedPids
}

function Wait-ForHttpReady {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -UseBasicParsing $Url -TimeoutSec 5 > $null
            return $true
        } catch {
            Start-Sleep -Seconds 2
        }
    }

    return $false
}

Write-Step "Verifying Docker..."
try {
    docker ps > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Starting Docker Desktop..." -ForegroundColor Yellow
        Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        Start-Sleep -Seconds 15
    } else {
        Write-Host "Docker is running." -ForegroundColor Green
    }
} catch {
    Write-Host "Docker not found." -ForegroundColor Red
}

Write-Step "Verifying Ollama and llama3.1:8b..."
try {
    $ollamaCheck = ollama list 2>&1
    if ($ollamaCheck -like "*error*") {
        Write-Host "Starting Ollama..." -ForegroundColor Yellow
        Start-Process "ollama" "serve"
        Start-Sleep -Seconds 5
    }
    Write-Host "Pulling llama3.1:8b (if missing)..." -ForegroundColor Yellow
    ollama pull llama3.1:8b
    Write-Host "Ollama is ready." -ForegroundColor Green
} catch {
    Write-Host "Ollama not found." -ForegroundColor Red
}

Write-Step "Stopping existing Aegis service instances..."
Stop-AegisServiceProcesses -RootPath $scriptRoot
Start-Sleep -Seconds 1

Write-Step "Starting Backend Service (Port 8000)..."
$managedServicePids = @()
if (-not (Test-Path $backendPython)) {
    Write-Host "Backend virtualenv not found at $backendPython" -ForegroundColor Red
    Write-Host "Bootstrap it with:" -ForegroundColor Yellow
    Write-Host "  py -3.13 -m venv backend\\venv" -ForegroundColor Gray
    Write-Host "  backend\\venv\\Scripts\\python.exe -m pip install --upgrade pip" -ForegroundColor Gray
    Write-Host "  backend\\venv\\Scripts\\python.exe -m pip install -r backend\\requirements-dev.txt" -ForegroundColor Gray
} else {
    $backendProc = Start-ServiceWindow -WorkingDirectory $backendDir -Command "& '$backendPython' main.py"
    if ($backendProc) {
        $managedServicePids += [int]$backendProc.Id
    }
    Write-Host "Backend initiated in background." -ForegroundColor Green
}

Write-Step "Starting Frontend App (Port 3000)..."
if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Write-Host "Frontend dependencies not found. Run 'cd frontend; cmd /c npm ci' before startup." -ForegroundColor Yellow
}
$frontendProc = Start-ServiceWindow -WorkingDirectory $frontendDir -Command "npm run dev"
if ($frontendProc) {
    $managedServicePids += [int]$frontendProc.Id
}
Write-Host "Frontend initiated in background." -ForegroundColor Green

Write-Step "Starting Promptfoo Viewer (Port 15500, no auto-open)..."
$promptfooProc = Start-ServiceWindow -WorkingDirectory $promptfooDir -Command "npx promptfoo@latest view -p 15500 -n"
if ($promptfooProc) {
    $managedServicePids += [int]$promptfooProc.Id
}
Write-Host "Promptfoo viewer initiated in background." -ForegroundColor Green
Save-ManagedStartupPids -Pids $managedServicePids

Write-Step "Waiting for services to become ready..."
$backendReady = Wait-ForHttpReady -Url "http://localhost:8000/health" -TimeoutSeconds 60
$frontendReady = Wait-ForHttpReady -Url "http://localhost:3000" -TimeoutSeconds 90
$promptfooReady = Wait-ForHttpReady -Url "http://localhost:15500" -TimeoutSeconds 60

if ($backendReady -and $frontendReady -and $promptfooReady) {
    Write-Host "All services are responding." -ForegroundColor Green
} else {
    Write-Host "One or more services did not report ready before timeout. Check logs/processes." -ForegroundColor Yellow
}

Write-Host "`nAegis Forge environment is ready." -ForegroundColor Magenta
Write-Host "--------------------------------------------------" -ForegroundColor Gray
Write-Host "Frontend:   http://localhost:3000"
Write-Host "Backend:    http://localhost:8000"
Write-Host "Promptfoo:  http://localhost:15500"
Write-Host "--------------------------------------------------" -ForegroundColor Gray
