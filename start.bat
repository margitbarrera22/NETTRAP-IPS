@echo off
REM NetTrap-IPS · Script de arranque (Windows)
REM Equipo CyberDefender — Clase 2/5
REM
REM USO: ejecutar como ADMINISTRADOR (necesario para netsh y puertos <1024)
REM
REM NOTA: No es PowerShell. Es CMD puro.

echo.
echo  ==============================================
echo   NetTrap-IPS · CyberDefender
echo   Motor IPS con Honeypots y Dashboard Web
echo  ==============================================
echo.

REM ── Verificar Python ─────────────────────────────────────────────────────
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python no encontrado. Instala Python 3.11+ desde https://python.org
    pause
    exit /b 1
)

REM ── Instalar dependencias si no existen ──────────────────────────────────
echo [*] Verificando dependencias...
pip install -r requirements.txt --quiet --disable-pip-version-check
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Fallo al instalar dependencias.
    pause
    exit /b 1
)

REM ── Crear directorios de datos ───────────────────────────────────────────
if not exist "src\data\logs"  mkdir "src\data\logs"
if not exist "src\data\pcap"  mkdir "src\data\pcap"

echo.
echo [*] Iniciando NetTrap-IPS...
echo [*] Dashboard disponible en: http://127.0.0.1:8000
echo [*] Usuario: admin  |  Contraseña: nettrap2026
echo [*] Presiona Ctrl+C para detener.
echo.

cd src\backend
python main.py

pause

