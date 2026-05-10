@echo off
setlocal
cd /d "%~dp0\.."

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" "lab\lab_manager.py" stop
  exit /b %errorlevel%
)

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "lab\lab_manager.py" stop
  exit /b %errorlevel%
)

python "lab\lab_manager.py" stop
