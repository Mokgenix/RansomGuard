@echo off
title RansomGuard v2 - Setup
color 0A
echo.
echo  +==============================================+
echo  ^|   RansomGuard v2 - One-Click Setup           ^|
echo  +==============================================+
echo.

echo [1/5] Checking Python...
python --version 2>nul
if errorlevel 1 (
    echo.
    echo  ERROR: Python not found!
    echo  Please install Python from https://www.python.org/downloads/
    echo  IMPORTANT: Check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

echo.
echo [2/5] Upgrading pip...
python -m pip install --upgrade pip --quiet

echo.
echo [3/5] Installing required packages...
pip install flask psutil requests --quiet
if errorlevel 1 (
    echo  ERROR: Package installation failed.
    echo  Try running this file as Administrator.
    pause
    exit /b 1
)

echo.
echo [4/5] Installing optional packages (password-protected backups)...
pip install pyminizip --quiet
if errorlevel 1 (
    echo  Note: pyminizip not installed - backups will still work.
    echo  For stronger encryption install 7-Zip: https://www.7-zip.org
)

echo.
echo [5/5] Creating required folders...
if not exist "backups"     mkdir backups
if not exist "honeypots"   mkdir honeypots
if not exist "threat_data" mkdir threat_data
if not exist "logs"        mkdir logs
if not exist "core"        mkdir core
if not exist "templates"   mkdir templates

echo.
echo  +==============================================+
echo   ^|  Setup complete!                            ^|
echo   ^|                                             ^|
echo   ^|  Default dashboard password: ransomguard    ^|
echo   ^|  Default backup password:    11223344       ^|
echo   ^|                                             ^|
echo   ^|  Double-click START.bat to launch           ^|
echo   ^|  Then open: http://localhost:5000           ^|
echo  +==============================================+
echo.
pause