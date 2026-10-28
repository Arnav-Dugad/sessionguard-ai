# Run the backend test suite.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
& (Join-Path $root ".venv\Scripts\python.exe") -m pytest (Join-Path $root "backend") -v
