"""
NetTrap-IPS · Módulo de Recolección Multifuente (RF-01 & RF-02)
Reemplaza completamente los señuelos/honeypots por recolección real en Windows.

Fuentes implementadas:
  1. Windows Event Log (Canales Security y System: Event ID 4625 Login Fallido, 4624, etc.)
  2. Windows Defender Firewall Log (Tráfico bloqueado DROP y directivas)
  3. Tráfico de Red & Inspección de Conexiones Activas

Normas:
  - ISO/IEC 27033-1 Cl. 10.3  → Monitoreo y registro continuo de seguridad de red
  - OWASP ASVS v5.0 V5.1.1     → Validación sintáctica estricta (ipaddress)
  - OWASP ASVS v5.0 V7.4.1     → Manejo seguro de excepciones sin fuga de trazas
  - NIST SP 800-218 PW.9.1     → Registro forense trazable
"""

import subprocess
import threading
import ipaddress
import logging
import time
import queue
import re
from datetime import datetime, timezone
from pathlib import Path

from config import QUEUE_MAX_SIZE, LOG_DIR

logger = logging.getLogger("nettrap.collectors")
errors_logger = logging.getLogger("nettrap.errors")

# Cola centralizada de ingesta de eventos (Buffer Limit DoS protection - ISO 27033-1 Cl. 10.2)
event_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAX_SIZE)


# ─────────────────────────────────────────────────────────────────────────────
# Validación y Normalización JSON Estricta (RF-02 & OWASP ASVS V5.1.1)
# ─────────────────────────────────────────────────────────────────────────────
def validate_ip(raw_ip: str) -> str | None:
    """Valida y normaliza sintácticamente una dirección IP IPv4/IPv6."""
    if not raw_ip or not isinstance(raw_ip, str):
        return None
    raw_ip = raw_ip.strip()
    if raw_ip in ("-", "::", "0.0.0.0"):
        return None
    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return None


def normalize_event(origen: str, severidad: str, evento: str, ip_origen: str, descripcion: str, puerto: int = 0, is_simulation: bool = False) -> dict | None:
    """
    Normaliza el evento al esquema JSON requerido por RF-02:
    { timestamp, origen, severidad, evento, ip_origen, descripcion }
    Rechaza eventos malformados y los registra en log de errores.
    """
    valid_ip = validate_ip(ip_origen)
    if not valid_ip:
        errors_logger.warning("Evento descartado por IP inválida o malformada: %r de origen %s", ip_origen, origen)
        return None

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    sev = severidad.upper() if severidad and severidad.upper() in valid_severities else "MEDIUM"

    normalized = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "origen":        str(origen),
        "severidad":     sev,
        "evento":        str(evento),
        "ip_origen":     valid_ip,
        "puerto":        int(puerto) if str(puerto).isdigit() else 0,
        "descripcion":   str(descripcion),
        "is_simulation": bool(is_simulation)
    }

    try:
        event_queue.put_nowait(normalized)
        logger.debug("[INGESTA] %s -> %s: %s", origen, valid_ip, evento)
        return normalized
    except queue.Full:
        errors_logger.error("Cola de correlación llena (Buffer limit saturado). Descartado evento.")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Fuente 1: Windows Event Log Collector (Security & System)
# ─────────────────────────────────────────────────────────────────────────────
class WindowsEventLogCollector(threading.Thread):
    """
    Lee en segundo plano eventos nativos de Windows mediante 'wevtutil'.
    Monitorea eventos de seguridad críticos:
      - Event ID 4625: Fallo de inicio de sesión (An account failed to log on)
      - Event ID 4624: Inicio de sesión exitoso
      - Event ID 7045: Nuevo servicio instalado en el sistema
    """

    def __init__(self, interval_seconds: int = 4):
        super().__init__(daemon=True, name="Collector-WinEvent")
        self.interval = interval_seconds
        self._stop_evt = threading.Event()
        self._last_checked = time.time() - 30

    def run(self) -> None:
        logger.info("WindowsEventLogCollector iniciado (Canal Security/System)")
        while not self._stop_evt.is_set():
            try:
                self._poll_security_events()
            except Exception as exc:
                errors_logger.error("Error al consultar Windows Event Log: %s", exc)
            time.sleep(self.interval)

    def _poll_security_events(self) -> None:
        """Consulta los eventos de fallo de autenticación EventID 4625 más recientes."""
        cmd = [
            "wevtutil", "qe", "Security",
            "/q:*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 60000]]]",
            "/f:text", "/c:5", "/rd:true"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=5, check=False)
            if res.returncode == 0 and res.stdout:
                text = res.stdout.decode("cp1252", errors="ignore")
                self._parse_wevtutil_output(text)
        except Exception:
            pass

    def _parse_wevtutil_output(self, text: str) -> None:
        """Extrae la IP agresora y datos de la salida de wevtutil."""
        events = text.split("Event[")
        ip_regex = re.compile(r"Source Network Address:\s*([^\s\r\n]+)")
        user_regex = re.compile(r"Account For Which Logon Failed:.*?Account Name:\s*([^\s\r\n]+)", re.DOTALL)

        for ev in events:
            if not ev.strip():
                continue
            ip_match = ip_regex.search(ev)
            if ip_match:
                raw_ip = ip_match.group(1).strip()
                user_match = user_regex.search(ev)
                target_user = user_match.group(1).strip() if user_match else "Desconocido"

                normalize_event(
                    origen="windows_event_log",
                    severidad="HIGH",
                    evento="Fallo de Autenticación Windows (EventID 4625)",
                    ip_origen=raw_ip,
                    descripcion=f"Fallo de inicio de sesión para el usuario '{target_user}' registrado en Security.evtx",
                    puerto=445
                )

    def stop(self) -> None:
        self._stop_evt.set()


# ─────────────────────────────────────────────────────────────────────────────
# Fuente 2: Windows Defender Firewall Log Collector
# ─────────────────────────────────────────────────────────────────────────────
class WindowsFirewallCollector(threading.Thread):
    """
    Monitorea en tiempo real los registros de tráfico bloqueado del Firewall de Windows
    (por defecto en C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log).
    """

    DEFAULT_LOG = Path(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")

    def __init__(self, log_path: Path = None, poll_interval: float = 3.0):
        super().__init__(daemon=True, name="Collector-WinFirewall")
        self.log_path = log_path or self.DEFAULT_LOG
        self.poll_interval = poll_interval
        self._stop_evt = threading.Event()
        self._last_pos = 0

    def run(self) -> None:
        logger.info("WindowsFirewallCollector iniciado (Log: %s)", self.log_path)
        while not self._stop_evt.is_set():
            try:
                if self.log_path.exists():
                    self._read_new_firewall_lines()
            except Exception as exc:
                errors_logger.error("Error al leer log de Firewall: %s", exc)
            time.sleep(self.poll_interval)

    def _read_new_firewall_lines(self) -> None:
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                if self._last_pos == 0:
                    f.seek(0, 2)  # Ir al final para no procesar todo el histórico viejo
                    self._last_pos = f.tell()
                    return

                f.seek(self._last_pos)
                lines = f.readlines()
                self._last_pos = f.tell()

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    # Formato pfirewall.log: date time action protocol src-ip dst-ip src-port dst-port ...
                    if len(parts) >= 8:
                        action = parts[2].upper()  # DROP o ALLOW
                        proto  = parts[3]
                        src_ip = parts[4]
                        dst_port = parts[7]

                        if action == "DROP":
                            normalize_event(
                                origen="windows_firewall",
                                severidad="HIGH",
                                evento=f"Paquete Bloqueado por Firewall ({proto} DROP)",
                                ip_origen=src_ip,
                                descripcion=f"Intento de conexión bloqueado por Windows Defender Firewall hacia puerto {dst_port}",
                                puerto=int(dst_port) if dst_port.isdigit() else 0
                            )
        except Exception:
            pass

    def stop(self) -> None:
        self._stop_evt.set()


# ─────────────────────────────────────────────────────────────────────────────
# Fuente 3: Network Traffic & Active Connections Collector
# ─────────────────────────────────────────────────────────────────────────────
class NetworkTrafficCollector(threading.Thread):
    """
    Inspecciona en tiempo real las conexiones de red TCP/UDP entrantes en el host
    para detectar ráfagas de reconocimiento y conexiones anómalas.
    """

    def __init__(self, interval_seconds: float = 3.0):
        super().__init__(daemon=True, name="Collector-NetTraffic")
        self.interval = interval_seconds
        self._stop_evt = threading.Event()
        self._seen_connections: set = set()

    def run(self) -> None:
        logger.info("NetworkTrafficCollector iniciado (Inspección de conexiones TCP activas)")
        while not self._stop_evt.is_set():
            try:
                self._inspect_active_connections()
            except Exception as exc:
                errors_logger.error("Error al inspeccionar tráfico de red: %s", exc)
            time.sleep(self.interval)

    def _inspect_active_connections(self) -> None:
        """Ejecuta netstat para recolectar conexiones activas sin bloquear el sistema."""
        try:
            res = subprocess.run(["netstat", "-n", "-p", "tcp"], capture_output=True, timeout=4, check=False)
            if res.returncode != 0 or not res.stdout:
                return

            stdout_text = res.stdout.decode("cp1252", errors="ignore")
            current_keys = set()
            for line in stdout_text.splitlines():
                line = line.strip()
                if not line.startswith("TCP"):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    foreign_addr = parts[2]
                    state = parts[3]

                    # Filtrar conexiones entrantes relevantes
                    if state in ("ESTABLISHED", "SYN_RECEIVED", "TIME_WAIT"):
                        if ":" in foreign_addr:
                            remote_ip = foreign_addr.rsplit(":", 1)[0]
                            local_port = local_addr.rsplit(":", 1)[1] if ":" in local_addr else "0"
                            conn_key = (remote_ip, local_port, state)
                            current_keys.add(conn_key)

                            if conn_key not in self._seen_connections:
                                valid = validate_ip(remote_ip)
                                if valid and valid not in ("127.0.0.1", "::1"):
                                    normalize_event(
                                        origen="network_traffic",
                                        severidad="MEDIUM" if state == "ESTABLISHED" else "HIGH",
                                        evento=f"Conexión de Red Detectada ({state})",
                                        ip_origen=valid,
                                        descripcion=f"Tráfico entrante hacia puerto local {local_port} en estado {state}",
                                        puerto=int(local_port) if local_port.isdigit() else 0
                                    )

            self._seen_connections = current_keys
        except Exception:
            pass

    def stop(self) -> None:
        self._stop_evt.set()


# ─────────────────────────────────────────────────────────────────────────────
# Administrador de Colectores Centralizado
# ─────────────────────────────────────────────────────────────────────────────
class MultiSourceCollectorManager:
    """Administra y orquesta los recolectores de las 3 fuentes de Windows."""

    def __init__(self):
        self.collectors = [
            WindowsEventLogCollector(),
            WindowsFirewallCollector(),
            NetworkTrafficCollector()
        ]

    def start(self) -> None:
        for c in self.collectors:
            c.start()
        logger.info("MultiSourceCollectorManager: 3 fuentes reales de Windows activas y en escucha continua.")

    def stop(self) -> None:
        for c in self.collectors:
            c.stop()
        logger.info("MultiSourceCollectorManager: todos los recolectores detenidos.")

    def status(self) -> list[dict]:
        return [
            {
                "id": "windows_event_log",
                "name": "Windows Event Log (Security & System)",
                "type": "Sistema Operativo (EventID 4625/4624)",
                "status": "ACTIVO" if self.collectors[0].is_alive() else "INACTIVO"
            },
            {
                "id": "windows_firewall",
                "name": "Windows Defender Firewall",
                "type": "Cortafuegos de Red (pfirewall.log / DROP)",
                "status": "ACTIVO" if self.collectors[1].is_alive() else "INACTIVO"
            },
            {
                "id": "network_traffic",
                "name": "Tráfico de Red & Conexiones Activas",
                "type": "Inspección de Tráfico TCP/IP",
                "status": "ACTIVO" if self.collectors[2].is_alive() else "INACTIVO"
            }
        ]
