$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Virtual environment not found. Run scripts\setup.ps1 first."
}
$env:PYTHONUTF8 = "1"
Set-Location -LiteralPath $repoRoot
& $pythonPath app.py
