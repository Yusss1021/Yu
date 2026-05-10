@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\pythonw.exe" (
  start "" ".venv\Scripts\pythonw.exe" "main.py" gui
  exit /b 0
)

where pyw >nul 2>nul
if %errorlevel%==0 (
  start "" pyw -3 "main.py" gui
  exit /b 0
)

where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw "main.py" gui
  exit /b 0
)

where py >nul 2>nul
if %errorlevel%==0 (
  start "" py -3 "main.py" gui
  exit /b 0
)

where python >nul 2>nul
if %errorlevel%==0 (
  start "" python "main.py" gui
  exit /b 0
)

echo No usable Python interpreter was found.
echo Expected one of:
echo   .venv\Scripts\pythonw.exe
echo   pyw
echo   pythonw
echo   py
echo   python
pause
