@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Premier lancement : installation...
  py -3 -m venv .venv 2>nul || python -m venv .venv
  if not exist ".venv\Scripts\python.exe" (
    echo Python 3 introuvable. Installe-le puis relance Cascade.bat
    pause
    exit /b 1
  )
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)

set "PYTHONPATH=%~dp0src"
set "PY=.venv\Scripts\pythonw.exe"
if not exist "%PY%" set "PY=.venv\Scripts\python.exe"
start "" "%PY%" -m cascade
