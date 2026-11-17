@echo off
REM ============================================================================
REM  NetTrap-SIEM / IPS - Launcher Autonomo "Out-of-the-Box" (Zero-Config)
REM  Equipo CyberDefender (UNIPAZ): Margit Barrera, Michel Bayona, Said Pacheco
REM ============================================================================

REM -- 1. AUTO-ELEVACION A ADMINISTRADOR (UAC) ---------------------------------
fltmc >nul 2>&1 || net session >nul 2>&1
if %errorlevel% equ 0 goto :admin_ok

echo [*] Solicitando permisos de Administrador para Firewall y Event Logs...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -WorkingDirectory '%~dp0' -Verb RunAs" >nul 2>&1
if %errorlevel% equ 0 exit /b
echo [!] Continuando en la consola actual sin elevacion UAC...

:admin_ok
REM Asegurar siempre la ruta raiz del proyecto (Admin cambia a C:\Windows\System32)
cd /d "%~dp0"
title NetTrap-SIEM SOC Engine [Escucha Activa en Red 0.0.0.0]

cls
echo.
echo  ========================================================================
echo   NetTrap-SIEM / IPS  Enterprise SOC v3.2 (UNIPAZ)
echo   Equipo CyberDefender: Margit Barrera, Michel Bayona, Said Pacheco
echo  ========================================================================
echo.

REM -- 2. VALIDACION Y DETECCION DE PYTHON -------------------------------------
set "SYS_PY="

python --version >nul 2>&1
if %errorlevel% equ 0 set "SYS_PY=python"
if defined SYS_PY goto :py_found

py -3 --version >nul 2>&1
if %errorlevel% equ 0 set "SYS_PY=py -3"
if defined SYS_PY goto :py_found

if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "SYS_PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if defined SYS_PY goto :py_found

if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "SYS_PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined SYS_PY goto :py_found

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "SYS_PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if defined SYS_PY goto :py_found

if exist "C:\Python313\python.exe" set "SYS_PY=C:\Python313\python.exe"
if defined SYS_PY goto :py_found

if exist "C:\Python312\python.exe" set "SYS_PY=C:\Python312\python.exe"
if defined SYS_PY goto :py_found

echo [ERROR CRITICO] No se detecto Python 3 instalado en este equipo.
echo Por favor instale Python 3.11+ desde https://www.python.org/downloads/
echo marcando la casilla "Add python.exe to PATH".
pause
exit /b 1

:py_found
echo [OK] Interprete Python verificado correctamente.

REM -- 3. CREACION / REPARACION AUTOMATICA DE ENTORNO VIRTUAL (.venv) ----------
set "VENV_PY=%~dp0.venv\Scripts\python.exe"

"%VENV_PY%" -c "import sys" >nul 2>&1
if %errorlevel% equ 0 goto :venv_ready

if exist ".venv" rmdir /s /q ".venv" >nul 2>&1
echo [*] Creando entorno virtual aislado .venv...
%SYS_PY% -m venv ".venv"
if %errorlevel% equ 0 goto :venv_ready

echo [!] Usando Python del sistema como respaldo...
set "VENV_PY=%SYS_PY%"

:venv_ready
REM -- 4. INSTALACION SILENCIOSA DE DEPENDENCIAS (CON FALLBACK) ----------------
"%VENV_PY%" -c "import fastapi, uvicorn, jinja2, yaml, websockets, multipart" >nul 2>&1
if %errorlevel% equ 0 goto :deps_ready

echo [*] Instalando dependencias de NetTrap-IPS en segundo plano...
"%VENV_PY%" -m pip install --upgrade pip --quiet --disable-pip-version-check >nul 2>&1
"%VENV_PY%" -m pip install -r requirements.txt --quiet --disable-pip-version-check >nul 2>&1
if %errorlevel% equ 0 goto :deps_ready

echo [*] Ajustando paquetes precompilados compatibles...
"%VENV_PY%" -m pip install fastapi uvicorn jinja2 python-multipart websockets pyyaml argon2-cffi jsonschema --quiet --disable-pip-version-check

:deps_ready
echo [OK] Dependencias de Python verificadas correctamente.

REM -- 5. MANEJO AUTOMATICO DE PUERTOS (PUERTO 8000 / FALLBACK 8001) -----------
set "NETTRAP_PORT=8000"

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 " ^| findstr "LISTENING"') do (
    if not "%%a"=="0" (
        echo [*] Liberando instancia previa en el puerto 8000 [PID %%a]...
        taskkill /F /PID %%a >nul 2>&1
        timeout /t 1 /nobreak >nul
    )
)

netstat -aon | findstr ":8000 " | findstr "LISTENING" >nul 2>&1
if %errorlevel% neq 0 goto :port_ready

echo [!] El puerto 8000 esta reservado por otro servicio del sistema.
set "NETTRAP_PORT=8001"

:port_ready
echo [OK] Puerto %NETTRAP_PORT% disponible para la Consola SOC.

REM -- 6. PREPARAR DIRECTORIOS Y POLITICAS DE WINDOWS (FIREWALL + EVENT LOG) ---
if not exist "src\data\logs" mkdir "src\data\logs"
if not exist "src\data\pcap" mkdir "src\data\pcap"

echo [*] Configurando Windows Defender Firewall y Auditoria de Eventos...
netsh advfirewall firewall delete rule name="NetTrap-Inbound-SOC" >nul 2>&1
netsh advfirewall firewall add rule name="NetTrap-Inbound-SOC" dir=in action=allow protocol=TCP localport=%NETTRAP_PORT%,8080 enable=yes >nul 2>&1
netsh advfirewall firewall delete rule name="NetTrap-Inbound-ICMP" >nul 2>&1
netsh advfirewall firewall add rule name="NetTrap-Inbound-ICMP" dir=in action=allow protocol=icmpv4:8,any enable=yes >nul 2>&1
netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" >nul 2>&1
netsh advfirewall set allprofiles logging maxfilesize 4096 >nul 2>&1
netsh advfirewall set allprofiles logging droppedconnections enable >nul 2>&1
auditpol /set /subcategory:"Logon" /success:enable /failure:enable >nul 2>&1

REM -- 7. DETECTAR IP DE RED LOCAL PARA ATAQUES --------------------------------
set "LOCAL_IP="
for /f "tokens=4" %%a in ('route print 0.0.0.0 ^| findstr "0.0.0.0.*0.0.0.0"') do (
    if not defined LOCAL_IP set "LOCAL_IP=%%a"
)
if not defined LOCAL_IP set "LOCAL_IP=127.0.0.1"

echo.
echo  ========================================================================
echo   ENTORNO NETTRAP-IPS LISTO Y EN ESCUCHA ACTIVA (HOST = 0.0.0.0)
echo  ========================================================================
echo   [+] Consola Web SOC (en este PC) : http://127.0.0.1:%NETTRAP_PORT%
echo   [+] Acceso al Dashboard SOC      : Directo sin login en el navegador
echo   [+] IP de este equipo en la red  : %LOCAL_IP%
echo  ------------------------------------------------------------------------
echo   COMO SIMULAR O LANZAR EL ATAQUE:
echo     Opcion A - En este mismo PC, abre otra terminal en esta carpeta:
echo       python ataque_prueba.py
echo.
echo     Opcion B - Desde el PC de otro companero en la red con Nmap:
echo       nmap -Pn -sT -sV -p 21,22,80,135,139,445,3389,%NETTRAP_PORT% %LOCAL_IP%
echo  ========================================================================
echo.
echo Presiona Ctrl+C en esta consola para detener el servidor defensivo.
echo.

cd /d "%~dp0src\backend"
"%VENV_PY%" main.py

pause
