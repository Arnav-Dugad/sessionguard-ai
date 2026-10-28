# Regenerate the synthetic dataset, train + evaluate all models, and write RESULTS.md.
[CmdletBinding()] param([int]$Seed = 42, [int]$Sessions = 1400)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$py = Join-Path $root ".venv\Scripts\python.exe"
& $py (Join-Path $root "ml\datasets\generate.py") --seed $Seed --sessions $Sessions
& $py (Join-Path $root "ml\training\train.py") --seed $Seed
& $py (Join-Path $root "ml\evaluation\report.py")
Write-Host "Done. See docs/RESULTS.md" -ForegroundColor Green
