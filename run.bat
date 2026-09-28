@echo off
setlocal

set "VENV_PY=%~dp0.venv\Scripts\python.exe"

if exist "%~dp0.venv\.recap-installed" goto run_cli

where py >nul 2>nul
if not errorlevel 1 goto use_py_launcher

where python >nul 2>nul
if errorlevel 1 goto missing_python
set "PY_LAUNCHER=python"
goto setup

:use_py_launcher
set "PY_LAUNCHER=py -3"

:setup
if not exist "%VENV_PY%" (
    %PY_LAUNCHER% -m venv "%~dp0.venv"
    if errorlevel 1 exit /b 1
)

"%VENV_PY%" -m pip install --upgrade pip
if errorlevel 1 exit /b 1

"%VENV_PY%" -m pip install -e "%~dp0."
if errorlevel 1 exit /b 1

> "%~dp0.venv\.recap-installed" echo installed

:run_cli
"%VENV_PY%" "%~dp0cli.py" %*
exit /b %errorlevel%

:missing_python
echo Python 3.10 or newer is required. Install Python, then try again.
exit /b 1