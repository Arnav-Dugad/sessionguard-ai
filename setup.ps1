<#
    SessionGuard AI - one-time setup for Windows 11.
    Verifies toolchain, builds the backend venv and frontend deps, initialises the database,
    seeds demo accounts, generates the synthetic dataset, trains + evaluates the ML models,
    and validates the install. Safe to re-run (idempotent).

    Usage:  powershell -ExecutionPolicy Bypass -File .\setup.ps1
            .\setup.ps1 -SkipTrain      # skip dataset generation + training
            .\setup.ps1 -Sessions 2000  # larger synthetic dataset
#>
[CmdletBinding()]
param([switch]$SkipTrain, [int]$Sessions = 1400, [int]$Seed = 42)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    [ok] $msg" -ForegroundColor Green }
function Die($msg)  { Write-Host "    [error] $msg" -ForegroundColor Red; exit 1 }

Write-Host "SessionGuard AI - setup" -ForegroundColor White

Step "Checking prerequisites"
try { $py = (python --version) 2>&1 } catch { Die "Python not found. Install Python 3.12+ from python.org and re-open PowerShell." }
if ($py -notmatch "3\.(1[2-9]|[2-9]\d)") { Write-Host "    [warn] $py detected; 3.12+ recommended." -ForegroundColor Yellow } else { Ok $py }
try { $node = (node --version) 2>&1; Ok "Node $node" } catch { Die "Node.js not found. Install Node.js LTS from nodejs.org." }
try { $npm = (npm --version) 2>&1; Ok "npm $npm" } catch { Die "npm not found (ships with Node.js)." }

Step "Creating Python virtual environment (.venv)"
if (-not (Test-Path ".venv")) { python -m venv .venv; Ok "created" } else { Ok "already exists" }
$pyexe = Join-Path $root ".venv\Scripts\python.exe"

Step "Installing backend + ML dependencies"
& $pyexe -m pip install --upgrade pip -q
& $pyexe -m pip install -q -r requirements.txt
if ($LASTEXITCODE -ne 0) { Die "pip install failed" }
Ok "backend dependencies installed"

Step "Installing frontend dependencies (npm install)"
Push-Location frontend
npm install --no-fund --no-audit
if ($LASTEXITCODE -ne 0) { Pop-Location; Die "npm install failed" }
Pop-Location
Ok "frontend dependencies installed"

if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env"; Ok "created .env from template" }

Step "Initialising database + seeding demo accounts"
& $pyexe -c "import sys; sys.path.insert(0,'backend'); from app.database import Base, engine, SessionLocal; from app.database.seed import seed; Base.metadata.create_all(bind=engine); db=SessionLocal(); print('   ', seed(db)); db.close()"
if ($LASTEXITCODE -ne 0) { Die "database init failed" }
Ok "database ready"

if ($SkipTrain) {
    Write-Host "    [skip] dataset generation + training (rule-only scoring until trained)" -ForegroundColor Yellow
} else {
    Step "Generating synthetic dataset (seed $Seed, $Sessions sessions)"
    & $pyexe ml\datasets\generate.py --seed $Seed --sessions $Sessions
    if ($LASTEXITCODE -ne 0) { Die "dataset generation failed" }

    Step "Training + evaluating models (rules / logreg / xgboost / aexgb)"
    & $pyexe ml\training\train.py --seed $Seed
    if ($LASTEXITCODE -ne 0) { Die "training failed" }

    Step "Writing RESULTS.md and loading evaluations"
    & $pyexe ml\evaluation\report.py
    if ($LASTEXITCODE -ne 0) { Die "report generation failed" }
    Ok "models trained and evaluated"
}

Step "Validating installation"
& $pyexe -c "import sys; sys.path.insert(0,'backend'); from fastapi.testclient import TestClient; from app.main import app; c=TestClient(app); r=c.get('/api/health'); assert r.status_code==200, r.text; print('    health:', r.json()['status'], '| model:', r.json()['model']['active_model'], '| loaded:', r.json()['model']['loaded'])"
if ($LASTEXITCODE -ne 0) { Die "validation failed" }

Write-Host "`nSetup complete." -ForegroundColor Green
Write-Host "Next:  .\start.ps1" -ForegroundColor White
Write-Host "Demo accounts:  ada / Demo-User!2027   grace / Demo-User!2027   admin / Admin-SOC!2027" -ForegroundColor Gray
