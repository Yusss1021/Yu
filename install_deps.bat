@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================
echo  企业内网脆弱性扫描系统 - 依赖安装脚本
echo ============================================
echo.

:: --- Step 1: Find a usable Python interpreter ---
set PYTHON_EXE=

if exist ".venv\Scripts\python.exe" (
  set PYTHON_EXE=.venv\Scripts\python.exe
  echo [1/5] 检测到已有虚拟环境 .venv
  goto :found_python
)

where python >nul 2>nul
if %errorlevel%==0 (
  for /f "delims=" %%i in ('where python') do (
    set PYTHON_EXE=%%i
    goto :found_python
  )
)

where py >nul 2>nul
if %errorlevel%==0 (
  set PYTHON_EXE=py -3
  goto :found_python
)

where python3 >nul 2>nul
if %errorlevel%==0 (
  set PYTHON_EXE=python3
  goto :found_python
)

echo [错误] 未找到可用的 Python 解释器。
echo 请先安装 Python 3.11+ (https://www.python.org/downloads/)
echo 安装时务必勾选 "Add Python to PATH"
pause
exit /b 1

:found_python
echo [1/5] 使用 Python: %PYTHON_EXE%

:: --- Step 2: Check Python version ---
for /f "tokens=2" %%v in ('%PYTHON_EXE% --version 2^>^&1') do set PY_VER=%%v
echo        Python 版本: %PY_VER%

:: --- Step 3: Create virtual environment (only if .venv doesn't exist) ---
if exist ".venv\Scripts\python.exe" (
  echo [2/5] 虚拟环境 .venv 已存在，跳过创建
  set PYTHON_EXE=.venv\Scripts\python.exe
  goto :install_deps
)

echo [2/5] 正在创建虚拟环境 .venv ...
%PYTHON_EXE% -m venv .venv
if %errorlevel% neq 0 (
  echo [错误] 虚拟环境创建失败，请检查 Python 安装是否完整。
  pause
  exit /b 1
)
echo        .venv 创建完成
set PYTHON_EXE=.venv\Scripts\python.exe

:: --- Step 4: Install main dependencies ---
:install_deps
echo [3/5] 正在安装主路径依赖 (requirements.txt) ...
%PYTHON_EXE% -m pip install --quiet --upgrade pip
%PYTHON_EXE% -m pip install --quiet -r requirements.txt
if %errorlevel% neq 0 (
  echo [错误] 主依赖安装失败，请检查网络连接后重试。
  pause
  exit /b 1
)
echo        requirements.txt 安装完成 (jinja2 + flask)

:: --- Step 5: Check nmap ---
echo [4/5] 正在检查 nmap ...

where nmap >nul 2>nul
if %errorlevel%==0 (
  for /f "delims=" %%i in ('where nmap') do echo        nmap 已就绪: %%i
) else (
  echo        [警告] 未检测到 nmap
  echo        GUI 第二页"漏洞匹配与服务识别"硬依赖 nmap
  echo        请从 https://nmap.org/download.html 下载安装
  echo        安装时务必勾选 "Register Path variable"
)

:: --- Step 6: Offer advanced dependencies ---
echo [5/5] 高级依赖 (scapy/paramiko/pymysql) 用于 ARP/SYN 发现和弱口令探测
set /p ADVANCED="        是否安装高级依赖？[y/N]: "
if /i "%ADVANCED%"=="y" (
  echo        正在安装 requirements-advanced.txt ...
  %PYTHON_EXE% -m pip install --quiet -r requirements-advanced.txt
  if %errorlevel% neq 0 (
    echo        [警告] 部分高级依赖安装失败，GUI 主路径仍可运行
  ) else (
    echo        requirements-advanced.txt 安装完成
  )
) else (
  echo        跳过高级依赖。后续如需安装，执行:
  echo        .venv\Scripts\pip install -r requirements-advanced.txt
)

:: --- Done ---
echo.
echo ============================================
echo  安装完成！
echo.
echo  启动方式:
echo    1. 双击 start_gui.bat
echo    2. 或命令行执行: .venv\Scripts\python main.py gui
echo ============================================
pause
endlocal
