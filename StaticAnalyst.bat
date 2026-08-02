@echo off
title Static Analyzer
color 07

set "PYEXE="

call :ResolvePython

if not defined PYEXE (
    color 0C
    echo [ERROR] Python 3 is not installed or not found in PATH.
    echo Please install Python from https://www.python.org/ and make sure to check "Add Python to PATH".
    echo.
    pause
    exit /b
)

echo Checking dependencies...
"%PYEXE%" -m pip install requests pyinstaller --quiet --disable-pip-version-check --trusted-host pypi.org --trusted-host files.pythonhosted.org
if errorlevel 1 (
    color 0C
    echo [ERROR] Failed to install dependencies.
    echo Please check your internet connection, Python installation, proxy, and certificate settings.
    echo.
    pause
    exit /b
)

"%PYEXE%" -c "import requests" >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] requests is not available in the selected Python interpreter.
    echo The installer may have used a different Python than the one that runs the app.
    echo.
    pause
    exit /b
)

cls
echo ========================================
echo   Starting StaticAnalyst ...
echo ========================================
"%PYEXE%" "%~dp0StaticAnalyst\main.py"

pause

exit /b

:ResolvePython
if defined PYTHON_EXE if exist "%PYTHON_EXE%" (
    set "PYEXE=%PYTHON_EXE%"
    goto :eof
)

for /f "usebackq delims=" %%I in (`py -3 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYEXE=%%I"
if defined PYEXE goto :eof

for /f "usebackq delims=" %%I in (`python -c "import sys; print(sys.executable)" 2^>nul`) do set "PYEXE=%%I"
if defined PYEXE goto :eof

call :TryCommonPythonPaths
if defined PYEXE goto :eof

call :TryRegistryPython
goto :eof

:TryCommonPythonPaths
for %%R in ("%LocalAppData%\Programs\Python" "%LocalAppData%\Python" "%ProgramFiles%\Python" "%ProgramFiles(x86)%\Python") do (
    if not defined PYEXE (
        for /d %%D in (%%~R\Python3*) do (
            if not defined PYEXE if exist "%%~fD\python.exe" set "PYEXE=%%~fD\python.exe"
        )
        for /d %%D in (%%~R\pythoncore-3.*) do (
            if not defined PYEXE if exist "%%~fD\python.exe" set "PYEXE=%%~fD\python.exe"
        )
    )
)
goto :eof

:TryRegistryPython
for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command "$roots = @('HKCU:\Software\Python\PythonCore','HKLM:\Software\Python\PythonCore','HKLM:\Software\WOW6432Node\Python\PythonCore'); foreach ($root in $roots) { if (Test-Path $root) { foreach ($key in Get-ChildItem $root) { try { $installPath = (Get-ItemProperty -Path $key.PSPath).'(default)'; if ($installPath) { $candidate = Join-Path $installPath 'python.exe'; if (Test-Path $candidate) { Write-Output $candidate; exit 0 } } } catch {} } } }" 2^>nul`) do set "PYEXE=%%I"
goto :eof