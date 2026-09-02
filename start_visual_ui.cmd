@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "UI_HOST=127.0.0.1"
set "UI_PORT=8002"
set "UI_URL=http://%UI_HOST%:%UI_PORT%/"

if not exist "run.py" (
    echo [ERROR] run.py was not found in %CD%
    pause
    exit /b 1
)

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found in PATH.
    pause
    exit /b 1
)

curl.exe -fsS -m 2 "%UI_URL%" >nul 2>&1
if not errorlevel 1 goto :ready

echo [INFO] Starting AI-WAF visual platform on port %UI_PORT%...
start "AI-WAF Visual Platform :8002" cmd /k "python run.py ui --host %UI_HOST% --port %UI_PORT%"

for /L %%I in (1,1,30) do (
    curl.exe -fsS -m 2 "%UI_URL%" >nul 2>&1 && goto :ready
    timeout /t 1 /nobreak >nul
)

echo [ERROR] The visual platform did not become ready within 30 seconds.
pause
exit /b 1

:ready
echo [OK] AI-WAF visual platform: %UI_URL%
start "" "%UI_URL%"
exit /b 0
