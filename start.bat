@echo off
REM NetTrap-SIEM / IPS · Script de arranque (Windows CMD)
REM Equipo CyberDefender (UNIPAZ)
REM USO: Clic derecho -> "Ejecutar como administrador"

echo.
echo  ==============================================================
echo   NetTrap-SIEM / IPS  Enterprise SOC v3.2 (UNIPAZ)
echo   CyberDefender: Margit Barrera, Michel Bayona, Said Pacheco
echo  ==============================================================
echo.

REM ── Detectar Python 3 ────────────────────────────────────────────────────────
set "PY_BIN=python"
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PY_BIN=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else if exist "C:\Python312\python.exe" (
        set "PY_BIN=C:\Python312\python.exe"
    ) else (
        echo [ERROR] No se encontro Python 3.12 en el sistema.
        pause
        exit /b 1
    )
)

REM ── Crear directorios de datos ───────────────────────────────────────────────
if not exist "src\data\logs" mkdir "src\data\logs"
if not exist "src\data\pcap" mkdir "src\data\pcap"

echo [*] Iniciando NetTrap-SIEM Engine...
echo [*] Conectando 3 Sensores Nativos de Windows (EventLog, Firewall, Red)...
echo [*] Dashboard SOC Web: http://127.0.0.1:8000
echo [*] Credenciales: Usuario: admin  ^|  Clave: nettrap2026
echo.
echo Presiona Ctrl+C en esta ventana para detener el servidor.
echo ==============================================================
echo.

cd src\backend
"%PY_BIN%" main.py

pause
