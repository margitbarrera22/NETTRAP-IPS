"""
NetTrap-IPS · Configuración central
Equipo CyberDefender — Clase 2/5
Norma: NIST SP 800-218 (SSDF) PW.9.1 — datos de configuración separados del código
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # src/

# ── Directorios de datos ─────────────────────────────────────────────────────
DATA_DIR  = BASE_DIR / "data"
LOG_DIR   = DATA_DIR / "logs"
PCAP_DIR  = DATA_DIR / "pcap"
RULES_FILE = BASE_DIR / "rules" / "detection_rules.yaml"

# ── Servidor web ──────────────────────────────────────────────────────────────
HOST        = "127.0.0.1"   # solo local — no exponer a toda la red
PORT        = 8000
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

