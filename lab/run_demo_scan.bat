@echo off
setlocal
cd /d "%~dp0\.."
set SCAN_NAME=%~1
if "%SCAN_NAME%"=="" set SCAN_NAME=demo_lab_scan

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" "lab\lab_manager.py" scan --name "%SCAN_NAME%"
  exit /b %errorlevel%
)

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "lab\lab_manager.py" scan --name "%SCAN_NAME%"
  exit /b %errorlevel%
)

python "lab\lab_manager.py" scan --name "%SCAN_NAME%"
