$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$venvPath = Join-Path $repoRoot ".venv"

python -m venv $venvPath
& (Join-Path $venvPath "Scripts\python.exe") -m pip install --upgrade pip
& (Join-Path $venvPath "Scripts\python.exe") -m pip install -r (Join-Path $repoRoot "requirements.txt")
Write-Host "Setup complete. Run scripts\run.ps1 from the repository root."
