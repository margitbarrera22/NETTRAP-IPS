@echo off
REM NetTrap-SIEM / IPS · Script de Arranque en Red Local (Windows CMD)
REM Equipo CyberDefender (UNIPAZ)
REM Auto-eleva a Administrador para control de Windows Defender Firewall

:: ── Comprobar elevación de Administrador ─────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Solicitando permisos de Administrador para Windows Defender Firewall...
    powershell -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

title NetTrap-SIEM SOC Engine [Escucha Activa en Red 0.0.0.0]
cls

echo.
echo  ========================================================================
echo   NetTrap-SIEM / IPS  Enterprise SOC v3.2 (UNIPAZ)
echo   Equipo CyberDefender: Margit Barrera, Michel Bayona, Said Pacheco
echo  ========================================================================
echo.

REM ── Detectar IP Local del Equipo ───────────────────────────────────────────
for /f "tokens=4" %%a in ('route print 0.0.0.0 ^| findstr "0.0.0.0.*0.0.0.0"') do (
    set "LOCAL_IP=%%a"
    goto :ip_found
)
:ip_found
if "%LOCAL_IP%"=="" set "LOCAL_IP=192.168.88.234"

REM ── Detectar Python 3.12 ───────────────────────────────────────────────────
set "PY_BIN=python"
where python >nul 2>&1
if %errorlevel% neq 0 (
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

REM ── Crear directorios de datos ─────────────────────────────────────────────
if not exist "src\data\logs" mkdir "src\data\logs"
if not exist "src\data\pcap" mkdir "src\data\pcap"

REM ── Habilitar puerto 8000 y logging en Windows Defender Firewall ───────────
echo [*] Configurando Windows Defender Firewall para recibir trafico de la red...
netsh advfirewall firewall delete rule name="NetTrap-Inbound-SOC" >nul 2>&1
netsh advfirewall firewall add rule name="NetTrap-Inbound-SOC" dir=in action=allow protocol=TCP localport=8000,8080 enable=yes >nul 2>&1
netsh advfirewall set allprofiles logging droppedconnections enable >nul 2>&1

echo [*] MODO: ESCUCHA ACTIVA EN TODA LA RED LOCAL (HOST = 0.0.0.0)
echo [*] Tu IP local para recibir ataques: %LOCAL_IP%
echo.
echo [*] Tu Dashboard Web (en este PC): http://localhost:8000
echo [*] Dashboard Web (desde otro PC):  http://%LOCAL_IP%:8000
echo [*] Credenciales: Usuario: admin  ^|  Clave: nettrap2026
echo.
echo  ------------------------------------------------------------------------
echo   INSTRUCCIONES PARA TU COMPANERO (DESDE SU COMPUTADOR):
echo   Para lanzar el ataque de reconocimiento Nmap, tu companero debe escribir:
echo.
echo     nmap -sS -p 80,135,445,3389,8000 %LOCAL_IP%
echo.
echo   O para probar con sondeo web:
echo     curl http://%LOCAL_IP%:8000/login
echo  ------------------------------------------------------------------------
echo.
echo Presiona Ctrl+C en esta consola para detener el servidor defensivo.
echo.

cd /d "%~dp0src\backend"
"%PY_BIN%" main.py

pause
