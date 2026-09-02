@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist "Dockerfile" cd /d "%~dp0server_runtime"

if not exist "Dockerfile" (
    echo [ERROR] Dockerfile was not found. Run this script from the runtime bundle.
    pause
    exit /b 1
)

set "WAD_ADMIN_PASSWORD=%~1"
if not defined WAD_ADMIN_PASSWORD set "WAD_ADMIN_PASSWORD=Wad2026Control9K4M7Q2P"
if not defined WAD_BACKEND set "WAD_BACKEND=http://host.docker.internal:8080"
if not defined WAD_MODE set "WAD_MODE=monitor"

where docker >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker was not found in PATH.
    pause
    exit /b 1
)

docker info >nul 2>&1
if not errorlevel 1 goto :docker_ready

if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
    echo [INFO] Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    for /L %%I in (1,1,24) do (
        timeout /t 5 /nobreak >nul
        docker info >nul 2>&1 && goto :docker_ready
    )
)

echo [ERROR] Docker Engine is not running.
pause
exit /b 1

:docker_ready
echo [1/5] Building ai-waf-runtime:latest...
docker build -t ai-waf-runtime:latest .
if errorlevel 1 goto :failed

echo [2/5] Preparing shared runtime volume...
docker volume create server_runtime_wad-runtime >nul
if errorlevel 1 goto :failed

echo [3/5] Recreating proxy on port 8081...
docker rm -f ai-waf-proxy >nul 2>&1
docker run -d --name ai-waf-proxy --restart unless-stopped --no-healthcheck ^
  -p 8081:8081 ^
  -v server_runtime_wad-runtime:/app/runtime ^
  -e WAD_PROXY_HOST=0.0.0.0 ^
  -e WAD_PROXY_PORT=8081 ^
  -e "WAD_PROXY_BACKEND=%WAD_BACKEND%" ^
  -e "WAD_PROXY_MODE=%WAD_MODE%" ^
  -e WAD_PROXY_FAIL_POLICY=closed ^
  -e WAD_PROXY_LOG_FILE=/app/runtime/proxy_access.jsonl ^
  -e "WAD_PROXY_FIELD_ALLOWLIST=%WAD_PROXY_FIELD_ALLOWLIST%" ^
  ai-waf-runtime:latest python -m src.proxy >nul
if errorlevel 1 goto :failed

echo [4/5] Recreating monitoring service on port 8000...
docker rm -f ai-waf-api >nul 2>&1
docker run -d --name ai-waf-api --restart unless-stopped ^
  -p 127.0.0.1:8000:8000 ^
  -v server_runtime_wad-runtime:/app/runtime ^
  -e WAD_PROXY_LOG_FILE=/app/runtime/proxy_access.jsonl ^
  -e "WAD_PROXY_BACKEND=%WAD_BACKEND%" ^
  -e "WAD_PROXY_MODE=%WAD_MODE%" ^
  -e WAD_PROXY_FAIL_POLICY=closed ^
  -e WAD_DASHBOARD_USERNAME=admin ^
  -e "WAD_DASHBOARD_PASSWORD=%WAD_ADMIN_PASSWORD%" ^
  ai-waf-runtime:latest uvicorn src.runtime_api:app --host 0.0.0.0 --port 8000 >nul
if errorlevel 1 goto :failed

docker port ai-waf-api 8000/tcp | findstr /C:"127.0.0.1:8000" >nul
if errorlevel 1 (
    echo [ERROR] Port 8000 was not published. Stop the process occupying 8000 and retry.
    docker rm -f ai-waf-api >nul 2>&1
    goto :failed
)

echo [5/5] Waiting for services...
for /L %%I in (1,1,30) do (
    curl.exe -fsS -m 2 http://127.0.0.1:8000/health >nul 2>&1 && goto :api_ready
    timeout /t 1 /nobreak >nul
)
echo [ERROR] Monitoring service did not become ready within 30 seconds.
docker logs --tail 50 ai-waf-api
goto :failed

:api_ready
curl.exe -fsS -m 3 http://127.0.0.1:8081/_wad/health >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Proxy health check failed.
    docker logs --tail 50 ai-waf-proxy
    goto :failed
)

curl.exe -fsS -m 3 http://127.0.0.1:8080/ >nul 2>&1
if errorlevel 1 echo [WARN] Backend 8080 is unavailable; proxy requests may return 502.

echo.
echo [OK] AI-WAF monitoring and proxy are ready.
echo      Monitoring: http://127.0.0.1:8000/
echo      Proxy:      http://127.0.0.1:8081/
echo      Username:   admin
echo      Password:   %WAD_ADMIN_PASSWORD%
echo      Mode:       %WAD_MODE%
start "" "http://127.0.0.1:8000/"
exit /b 0

:failed
echo.
echo [ERROR] AI-WAF startup failed. Review the output above.
pause
exit /b 1
