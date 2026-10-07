@echo off
setlocal

set "APP_DIR=%~dp0"
set "REPO_DIR=%APP_DIR%.."
set "APP_FILE=%APP_DIR%app.py"
set "PYTHONW=%REPO_DIR%\.venv\Scripts\pythonw.exe"

if not exist "%APP_FILE%" (
    echo Could not find desktop_app\app.py.
    pause
    exit /b 1
)

if exist "%PYTHONW%" (
    start "" "%PYTHONW%" "%APP_FILE%"
    exit /b 0
)

where pyw.exe >nul 2>nul
if not errorlevel 1 (
    start "" pyw -3 "%APP_FILE%"
    exit /b 0
)

where pythonw.exe >nul 2>nul
if not errorlevel 1 (
    start "" pythonw "%APP_FILE%"
    exit /b 0
)

echo Python with Tkinter was not found.
echo Install Python 3 and make sure the Python Launcher or pythonw.exe is available.
pause
exit /b 1
