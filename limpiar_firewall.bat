@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs -Wait"
    exit /b
)
for /f "tokens=2 delims=:" %%a in ('netsh advfirewall firewall show rule name^=all ^| findstr "NETTRAP-BLOCK"') do (
    call :del_rule "%%a"
)
goto :done

:del_rule
set "rname=%~1"
set "rname=%rname:~1%"
echo Eliminando %rname%...
netsh advfirewall firewall delete rule name="%rname%"
exit /b

:done
echo.
echo Limpieza de Firewall completada. Todas las reglas temporales de NetTrap fueron eliminadas.
pause
