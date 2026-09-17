# Build a portable Cascade.exe (Windows). No network at runtime.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
.\.venv\Scripts\python -m pip install -e ".[packaging]"
.\.venv\Scripts\pyinstaller --noconfirm --clean packaging\cascade.spec
Write-Host "Output: dist\Cascade.exe"
