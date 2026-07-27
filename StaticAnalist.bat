@echo off
title Static Analyzer
color 0A

:: Check if Python is installed
py --version >nul 2>&1
if %errorlevel% neq 0 (
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Python is not installed or not found in PATH.
        echo Please install Python from https://www.python.org/ and make sure to check "Add Python to PATH".
        echo.
        pause
        exit /b
    )
)

echo Checking dependencies...
pip install requests pyinstaller --quiet

cls
echo ========================================
echo   Starting StaticAnalist ...
echo ========================================
python .\StaticAnalist\main.py

pause