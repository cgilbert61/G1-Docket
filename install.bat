@echo off
setlocal EnableDelayedExpansion

echo =====================================================================
echo    G1 Docket - Automated Docker Stack Installer
echo =====================================================================
echo.

:: 1. Check Docker CLI
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker is not installed or not in PATH!
    echo Please install Docker Desktop from: https://www.docker.com/products/docker-desktop
    echo.
    pause
    exit /b 1
)

:: 2. Check Docker Daemon Status
docker info >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker daemon is not running!
    echo Please launch Docker Desktop and wait until the engine is fully started.
    echo.
    pause
    exit /b 1
)
echo [OK] Docker engine is running.

:: 3. Ensure D: drive is mounted in Docker Desktop WSL if running on D:
set "CURR_DRIVE=%~d0"
if /i "%CURR_DRIVE%"=="D:" (
    echo [*] Checking D: drive mount in Docker Desktop WSL VM...
    wsl -d docker-desktop -u root -e sh -c "mkdir -p /mnt/host/d /mnt/d; mountpoint -q /mnt/host/d || mount -t drvfs D: /mnt/host/d -o metadata; mountpoint -q /mnt/d || mount --bind /mnt/host/d /mnt/d" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        echo [OK] Drive D: mount verified in Docker Desktop WSL.
    ) else (
        echo [WARN] WSL mount check returned non-zero code. Continuing...
    )
)

:: 4. Prepare Environment
if not exist .env (
    if exist .env.example (
        echo [*] Creating .env from .env.example...
        copy .env.example .env >nul
    )
)

:: 5. Build and Start Docker Compose Demo Stack
echo [*] Building and starting all G1 Docket services (demo profile)...
echo     - PostgreSQL 15 (Port 15432)
echo     - Registry API ^& Store (Port 18080)
echo     - Signed Snapshot Publisher (Port 18081)
echo     - AI Gateway Prevalidator (Port 18082)
echo     - Attestation Engine ^& Discovery (Port 18083)
echo     - Local AI Gateway Mock (Port 14000)
echo.

docker compose --profile demo up -d --build
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Docker Compose failed to build or launch the stack!
    echo Please inspect the error messages above.
    pause
    exit /b 1
)

:: 6. Wait for Services to Pass Health Checks
echo.
echo [*] Waiting for services to initialize and pass health checks...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$urls = @('http://localhost:18080/docs', 'http://localhost:18081/docs', 'http://localhost:18082/healthz', 'http://localhost:18083/healthz', 'http://localhost:14000/healthz'); " ^
    "$allOk = $false; " ^
    "for ($i=1; $i -le 40; $i++) { " ^
    "  $pending = 0; " ^
    "  foreach ($u in $urls) { " ^
    "    try { $r = Invoke-WebRequest -Uri $u -TimeoutSec 2 -UseBasicParsing; if ($r.StatusCode -ne 200) { $pending++ } } catch { $pending++ } " ^
    "  } " ^
    "  if ($pending -eq 0) { $allOk = $true; break } " ^
    "  Write-Host -NoNewline '.'; Start-Sleep -Seconds 2 " ^
    "}; " ^
    "Write-Host ''; " ^
    "if ($allOk) { Write-Host '[+] All G1 Docket services are HEALTHY and ACTIVE!' -ForegroundColor Green } else { Write-Host '[!] Services started; some health checks are still stabilizing.' -ForegroundColor Yellow }"

echo.
echo =====================================================================
echo    G1 Docket Platform is live!
echo =====================================================================
echo  - Prevalidator Proxy:    http://localhost:18082
echo  - Registry API Docs:     http://localhost:18080/docs
echo  - Snapshot Publisher:    http://localhost:18081/docs
echo  - Attestation Engine:    http://localhost:18083/docs
echo  - Local Mock Gateway:    http://localhost:14000
echo  - PostgreSQL DB:        localhost:15432 (user: pod, db: pod_registry)
echo =====================================================================
echo.
pause
