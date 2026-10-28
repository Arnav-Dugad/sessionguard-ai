<#
    SessionGuard AI - start backend + frontend for a local demo.
    Usage:  powershell -ExecutionPolicy Bypass -File .\start.ps1
            .\start.ps1 -NoBrowser
#>
[CmdletBinding()]
param([switch]$NoBrowser, [int]$BackendPort = 8000, [int]$FrontendPort = 5173)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root
$pyexe = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $pyexe)) { Write-Host "[error] .venv missing - run .\setup.ps1 first." -ForegroundColor Red; exit 1 }
if (-not (Test-Path "frontend\node_modules")) { Write-Host "[error] frontend deps missing - run .\setup.ps1 first." -ForegroundColor Red; exit 1 }

Write-Host "Starting SessionGuard AI..." -ForegroundColor Cyan

$backend = Start-Process -PassThru -NoNewWindow -FilePath $pyexe `
    -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$BackendPort") `
    -WorkingDirectory (Join-Path $root "backend")
Write-Host "    backend  pid $($backend.Id)  ->  http://localhost:$BackendPort"

Write-Host "    waiting for backend readiness..." -NoNewline
$ready = $false
foreach ($i in 1..40) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$BackendPort/api/health" -UseBasicParsing -TimeoutSec 2
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Milliseconds 500 }
    Write-Host "." -NoNewline
}
if ($ready) { Write-Host " ready" -ForegroundColor Green } else {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "    Backend did not become ready. Check the log above (common causes: port $BackendPort in use, missing deps)." -ForegroundColor Yellow
    if (-not $backend.HasExited) { $backend.Kill() }
    exit 1
}

$env:VITE_BACKEND_PORT = "$BackendPort"
$frontend = Start-Process -PassThru -NoNewWindow -FilePath "npm" `
    -ArgumentList @("run", "dev", "--", "--port", "$FrontendPort", "--strictPort") `
    -WorkingDirectory (Join-Path $root "frontend")
Write-Host "    frontend pid $($frontend.Id)  ->  http://localhost:$FrontendPort"

Write-Host "`nSessionGuard AI is running:" -ForegroundColor Green
Write-Host "    App         http://localhost:$FrontendPort" -ForegroundColor White
Write-Host "    API         http://localhost:$BackendPort" -ForegroundColor Gray
Write-Host "    API docs    http://localhost:$BackendPort/docs" -ForegroundColor Gray
Write-Host "    Accounts    ada / Demo-User!2027   |   admin / Admin-SOC!2027" -ForegroundColor Gray
Write-Host "`nPress Ctrl+C to stop both services." -ForegroundColor DarkGray

if (-not $NoBrowser) { Start-Sleep -Seconds 3; Start-Process "http://localhost:$FrontendPort" }

try {
    while (-not $backend.HasExited -and -not $frontend.HasExited) { Start-Sleep -Seconds 1 }
} finally {
    Write-Host "`nStopping services..." -ForegroundColor Cyan
    if (-not $frontend.HasExited) { Stop-Process -Id $frontend.Id -Force -ErrorAction SilentlyContinue }
    if (-not $backend.HasExited) { Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue }
}
