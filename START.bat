@echo off
title RansomGuard v2 - Running
color 0A
echo.
echo  +==============================================+
echo  ^|   RansomGuard v2 - Ransomware Prevention   ^|
echo  +==============================================+
echo.
echo  Starting dashboard server...
echo  Open your browser and go to:
echo  +==============================================+
echo  ^|  Setup complete!                            ^|
echo  ^|                                             ^|
echo  ^|  Default dashboard password: ransomguard    ^|
echo  ^|  Default backup password:    11223344       ^|
echo  ^|                                             ^|
echo  ^|  Double-click START.bat to launch           ^|
echo  ^|  Then open: http://localhost:5000           ^|
echo  ^|    Press Ctrl+C to stop the tool.            ^|
echo  +==============================================+
echo.
cd /d "%~dp0"
python app.py
echo.
echo  Server stopped.
pause
echo  Press Ctrl+C to stop the tool.