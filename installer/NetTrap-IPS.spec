# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec para NetTrap-IPS:
  1) dist/NetTrap-IPS/NetTrap-IPS.exe   (--onedir, empaquetado por el instalador Setup.exe)
  2) dist/NetTrap-IPS-Portable.exe      (--onefile, ejecutable portable directo sin instalador)
"""

from pathlib import Path

SPEC_DIR = Path(SPECPATH)
ROOT_DIR = SPEC_DIR.parent
SRC_DIR = ROOT_DIR / "src"
BACKEND_DIR = SRC_DIR / "backend"

HIDDEN_IMPORTS = [
    # Módulos propios de NetTrap-IPS
    "config",
    "collectors",
    "correlator",
    "dispatcher",
    "mitigator",
    "soc_tools",
    "main",
    # Uvicorn y servidores ASGI / WebSockets
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.http.httptools_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "h11",
    "httptools",
    "websockets",
    "websockets.legacy",
    "websockets.legacy.server",
    "websockets.asyncio",
    "websockets.asyncio.server",
    # FastAPI / Starlette / AnyIO
    "fastapi",
    "starlette",
    "starlette.routing",
    "starlette.middleware",
    "starlette.staticfiles",
    "starlette.templating",
    "starlette.websockets",
    "anyio",
    "anyio._backends",
    "anyio._backends._asyncio",
    "pydantic",
    "pydantic_core",
    # Plantillas, YAML, Seguridad
    "jinja2",
    "markupsafe",
    "yaml",
    "jsonschema",
    "argon2",
    "cffi",
    "_cffi_backend",
    "multipart",
    "python_multipart",
    # Bandeja del sistema e iconos
    "pystray",
    "pystray._win32",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    "PIL._imaging",
]

DATAS = [
    (str(SRC_DIR / "frontend"), "frontend"),
    (str(SRC_DIR / "rules"), "rules"),
    (str(SPEC_DIR / "nettrap.ico"), "installer"),
]

a = Analysis(
    [str(SRC_DIR / "nettrap_desktop.py")],
    pathex=[str(SRC_DIR), str(BACKEND_DIR)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "bandit", "rich", "pygments"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

# 1. Build --onedir para el Instalador (arranque instantáneo)
exe_dir = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NetTrap-IPS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
    icon=[str(SPEC_DIR / "nettrap.ico")],
)

coll = COLLECT(
    exe_dir,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="NetTrap-IPS",
)

# 2. Build --onefile portable (un solo archivo listo para ejecutar sin instalar)
exe_portable = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NetTrap-IPS-Portable",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
    icon=[str(SPEC_DIR / "nettrap.ico")],
)
