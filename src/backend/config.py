"""
NetTrap-IPS · Configuración central
Equipo CyberDefender — Clase 2/5
Norma: NIST SP 800-218 (SSDF) PW.9.1 — datos de configuración separados del código
"""

import os
import socket
import subprocess
import sys
from pathlib import Path

IS_FROZEN = bool(getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"))
BUNDLE_DIR = Path(sys._MEIPASS) if IS_FROZEN else Path(__file__).resolve().parent.parent  # src/ o _MEIPASS
BASE_DIR = BUNDLE_DIR
FRONTEND_DIR = BUNDLE_DIR / "frontend"
SUBPROC_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _is_dir_writable(path: Path) -> bool:
    """Comprueba si el directorio puede crearse y escribirse sin errores de permisos."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _resolve_data_dir() -> Path:
    """Resuelve el directorio persistente y escribible para logs y capturas .pcap."""
    env_override = os.environ.get("NETTRAP_DATA_DIR", "").strip()
    if env_override:
        return Path(env_override)
    if not IS_FROZEN:
        return BUNDLE_DIR / "data"

    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NetTrap-IPS" / "data"
    if _is_dir_writable(program_data):
        return program_data
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "NetTrap-IPS" / "data"


def get_local_host_ip() -> str:
    """Detecta dinámicamente la IP local de red de este equipo (ej. 192.168.x.x)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_default_gateway() -> str | None:
    """Detecta la puerta de enlace por defecto en Windows mediante route print."""
    if os.name != "nt":
        return None
    import ipaddress
    try:
        res = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True,
            timeout=4,
            check=False,
            creationflags=SUBPROC_FLAGS,
        )
        text = (res.stdout or b"").decode("cp1252", errors="ignore")
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                try:
                    gw = str(ipaddress.ip_address(parts[2].strip()))
                    if gw != "0.0.0.0":
                        return gw
                except ValueError:
                    continue
    except Exception:
        pass
    return None


LOCAL_HOST_IP = get_local_host_ip()

# ── Directorios de datos ─────────────────────────────────────────────────────
DATA_DIR  = _resolve_data_dir()
LOG_DIR   = DATA_DIR / "logs"
PCAP_DIR  = DATA_DIR / "pcap"
RULES_FILE = BUNDLE_DIR / "rules" / "detection_rules.yaml"

# ── Servidor web ──────────────────────────────────────────────────────────────
# 0.0.0.0 permite recibir tráfico y pruebas de ataque desde otros PCs de la red local
HOST        = os.environ.get("NETTRAP_HOST", "0.0.0.0")
PORT        = int(os.environ.get("NETTRAP_PORT", "8000"))
SECRET_KEY  = os.environ.get("NETTRAP_SECRET", "cambiar_en_produccion_32bytes!!")

# ── Autenticación (OWASP ASVS V2.1 / V3.1) ───────────────────────────────────
ADMIN_USER          = os.environ.get("NETTRAP_USER", "admin")
# Hash Argon2id de la contraseña; aquí se inicializa con "nettrap2026"
ADMIN_PASS_HASH     = os.environ.get(
    "NETTRAP_PASS_HASH",
    "$argon2id$v=19$m=65536,t=3,p=4$"
    "dGVzdHNhbHQxMjM0NQ$"
    "placeholder_will_be_set_on_first_run"
)
SESSION_EXPIRE_SECS = 1800   # 30 minutos — OWASP ASVS V3.2
MAX_FAILED_LOGINS   = 5
LOCKOUT_SECS        = 900    # 15 minutos

# ── Honeypot ports ────────────────────────────────────────────────────────────
HONEYPOT_PORTS = [21, 2222, 8080, 3389]

# ── TShark ────────────────────────────────────────────────────────────────────
TSHARK_PATH    = r"C:\Program Files\Wireshark\tshark.exe"
PCAP_DURATION  = 10          # segundos de captura por incidente

# ── Motor de correlación ──────────────────────────────────────────────────────
QUEUE_MAX_SIZE = 1000        # buffer limit → mitiga DoS (ISO 27033-1 Cl. 10.2)
BLOCK_TIMEOUT  = 300         # segundos antes de liberar regla de firewall

