<#
.SYNOPSIS
  Compila NetTrap-IPS en ejecutables Windows (.exe) y genera el instalador Setup.exe.
#>

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  NetTrap-IPS · Constructor de Ejecutables e Instalador (.exe)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. Localizar Python del entorno virtual
$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPy)) {
    Write-Host "[*] Creando entorno virtual .venv..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "[*] Verificando dependencias de compilacion..." -ForegroundColor Yellow
& $VenvPy -m pip install -r (Join-Path $Root "requirements-build.txt") --quiet --disable-pip-version-check

# 2. Regenerar icono oficial
Write-Host "[*] Generando icono nettrap.ico..." -ForegroundColor Yellow
& $VenvPy (Join-Path $Root "installer\generate_icon.py")

# 3. Limpiar compilaciones anteriores
$DistDir = Join-Path $Root "dist"
$BuildDir = Join-Path $Root "build"
if (Test-Path $DistDir) { Remove-Item $DistDir -Recurse -Force }
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }

# 4. Compilar con PyInstaller (onedir + portable onefile)
Write-Host "[*] Compilando NetTrap-IPS.exe y NetTrap-IPS-Portable.exe con PyInstaller..." -ForegroundColor Yellow
& $VenvPy -m PyInstaller --clean --noconfirm (Join-Path $Root "installer\NetTrap-IPS.spec")
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller fallo con codigo $LASTEXITCODE"
}

# 5. Compilar el instalador con Inno Setup (ISCC.exe) si esta disponible
$IsccCandidates = @(
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7\ISCC.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 7\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 7\ISCC.exe"
)
$Iscc = $IsccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Iscc) {
    $Cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($Cmd) { $Iscc = $Cmd.Source }
}

if ($Iscc) {
    Write-Host "[*] Compilando instalador NetTrap-IPS-Setup.exe con Inno Setup..." -ForegroundColor Yellow
    & $Iscc (Join-Path $Root "installer\NetTrap-IPS.iss")
    if ($LASTEXITCODE -ne 0) {
        throw "ISCC fallo con codigo $LASTEXITCODE"
    }
} else {
    Write-Warning "Inno Setup (ISCC.exe) no esta instalado. Se generaron NetTrap-IPS.exe y NetTrap-IPS-Portable.exe sin el Setup.exe."
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  COMPILACION COMPLETADA" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Get-ChildItem $DistDir -File | ForEach-Object {
    $mb = [math]::Round($_.Length / 1MB, 2)
    Write-Host ("  [+] {0} ({1} MB)" -f $_.FullName, $mb) -ForegroundColor White
}
$DirExe = Join-Path $DistDir "NetTrap-IPS\NetTrap-IPS.exe"
if (Test-Path $DirExe) {
    Write-Host ("  [+] {0} (carpeta de aplicacion instalada)" -f $DirExe) -ForegroundColor White
}
