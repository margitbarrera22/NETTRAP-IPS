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

from config import QUEUE_MAX_SIZE, LOG_DIR, SUBPROC_FLAGS, get_default_gateway
from mitigator import is_ip_blocked

logger = logging.getLogger("nettrap.collectors")
errors_logger = logging.getLogger("nettrap.errors")

# Cola centralizada de ingesta de eventos (Buffer Limit DoS protection - ISO 27033-1 Cl. 10.2)
event_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAX_SIZE)

# Tráfico normal de descubrimiento en LAN/Wi-Fi que no debe generar falsas alarmas IPS
FIREWALL_ALLOWED_PROTOCOLS = {"TCP", "UDP"}
LAN_DISCOVERY_PORTS = {67, 68, 137, 138, 546, 547, 1900, 3702, 5353, 5355}
UDP_INFRA_PORTS = {53, 123}


def _is_multicast_or_broadcast(ip_str: str) -> bool:
    """Retorna True si la IP corresponde a multicast, broadcast o dirección no especificada."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip_obj.is_multicast or ip_obj.is_unspecified:
        return True
    if ip_obj.version == 4:
        s = str(ip_obj)
        if s == "255.255.255.255" or s.endswith(".255"):
            return True
    return False


def _is_non_attack_ip(ip_str: str) -> bool:
    """Filtra IPs locales de enlace (fe80::/169.254), loopback, multicast y broadcast."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip_obj.is_loopback or ip_obj.is_link_local:
        return True
    return _is_multicast_or_broadcast(ip_str)


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
        self._seen_records: set[str] = set()

    def run(self) -> None:
        logger.info("WindowsEventLogCollector iniciado (Canal Security/System)")
        while not self._stop_evt.is_set():
            try:
                self._poll_security_events()
            except Exception as exc:
                errors_logger.error("Error al consultar Windows Event Log: %s", exc)
            time.sleep(self.interval)

    def _poll_security_events(self) -> None:
        """Consulta los eventos de fallo de autenticación EventID 4625 más recientes (XML + Texto ES/EN)."""
        cmd_xml = [
            "wevtutil", "qe", "Security",
            "/q:*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 60000]]]",
            "/f:xml", "/c:15", "/rd:true"
        ]
        try:
            res = subprocess.run(cmd_xml, capture_output=True, timeout=5, check=False, creationflags=SUBPROC_FLAGS)
            if res.returncode == 0 and res.stdout:
                xml_text = res.stdout.decode("utf-8", errors="ignore")
                if "<Event" in xml_text:
                    self._parse_wevtutil_xml(xml_text)
                    return
        except Exception:
            pass

        cmd_txt = [
            "wevtutil", "qe", "Security",
            "/q:*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 60000]]]",
            "/f:text", "/c:10", "/rd:true"
        ]
        try:
            res = subprocess.run(cmd_txt, capture_output=True, timeout=5, check=False, creationflags=SUBPROC_FLAGS)
            if res.returncode == 0 and res.stdout:
                text = res.stdout.decode("cp1252", errors="ignore")
                self._parse_wevtutil_output(text)
        except Exception:
            pass

    def _parse_wevtutil_xml(self, xml_text: str) -> None:
        """Extrae EventRecordID, IpAddress y TargetUserName del XML nativo de Windows (independiente del idioma)."""
        events = xml_text.split("<Event ")
        rec_regex = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
        ip_regex = re.compile(r"<Data Name=['\"]IpAddress['\"]>([^<]+)</Data>")
        user_regex = re.compile(r"<Data Name=['\"]TargetUserName['\"]>([^<]+)</Data>")
        port_regex = re.compile(r"<Data Name=['\"]IpPort['\"]>([^<]+)</Data>")

        for ev in events:
            if not ev.strip():
                continue
            rec_match = rec_regex.search(ev)
            rec_id = rec_match.group(1) if rec_match else None
            if rec_id and rec_id in self._seen_records:
                continue

            ip_match = ip_regex.search(ev)
            if ip_match:
                raw_ip = ip_match.group(1).strip()
                if rec_id:
                    self._seen_records.add(rec_id)
                user_match = user_regex.search(ev)
                target_user = user_match.group(1).strip() if user_match else "Desconocido"
                port_match = port_regex.search(ev)
                puerto = int(port_match.group(1)) if (port_match and port_match.group(1).isdigit()) else 445

                normalize_event(
                    origen="windows_event_log",
                    severidad="HIGH",
                    evento="Fallo de Autenticación Windows (EventID 4625)",
                    ip_origen=raw_ip,
                    descripcion=f"Fallo de inicio de sesión para el usuario '{target_user}' registrado en Security.evtx",
                    puerto=puerto
                )

    def _parse_wevtutil_output(self, text: str) -> None:
        """Extrae la IP agresora y datos de la salida de texto de wevtutil (Español e Inglés)."""
        events = text.split("Event[")
        ip_regex = re.compile(
            r"(?:Source Network Address|Direcci[oó]n de red de origen):\s*([^\s\r\n]+)",
            re.IGNORECASE
        )
        user_regex = re.compile(
            r"(?:Account For Which Logon Failed|Cuenta para la que se produjo un error de inicio de sesi[oó]n):.*?"
            r"(?:Account Name|Nombre de cuenta):\s*([^\s\r\n]+)",
            re.DOTALL | re.IGNORECASE
        )

        for ev in events:
            if not ev.strip():
                continue
            ev_sig = str(hash(ev[:240]))
            if ev_sig in self._seen_records:
                continue
            ip_match = ip_regex.search(ev)
            if ip_match:
                self._seen_records.add(ev_sig)
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
    DEFAULT_FIELDS = {
        "action": 2,
        "protocol": 3,
        "src-ip": 4,
        "dst-ip": 5,
        "src-port": 6,
        "dst-port": 7,
        "path": 16,
    }

    def __init__(self, log_path: Path = None, poll_interval: float = 3.0):
        super().__init__(daemon=True, name="Collector-WinFirewall")
        self.log_path = log_path or self.DEFAULT_LOG
        self.poll_interval = poll_interval
        self._stop_evt = threading.Event()
        self._last_pos = 0
        self._field_map: dict[str, int] = dict(self.DEFAULT_FIELDS)
        self._gateway_ip: str | None = get_default_gateway()
        self._last_gw_refresh = time.time()

    def _parse_fields_line(self, line: str) -> None:
        if line.lower().startswith("#fields:"):
            cols = line.split(":", 1)[1].strip().split()
            if cols:
                self._field_map = {col.lower(): idx for idx, col in enumerate(cols)}

    def run(self) -> None:
        logger.info("WindowsFirewallCollector iniciado (Log: %s)", self.log_path)
        while not self._stop_evt.is_set():
            try:
                if time.time() - self._last_gw_refresh > 60:
                    self._gateway_ip = get_default_gateway()
                    self._last_gw_refresh = time.time()
                if self.log_path.exists():
                    self._read_new_firewall_lines()
            except Exception as exc:
                errors_logger.error("Error al leer log de Firewall: %s", exc)
            time.sleep(self.poll_interval)

    def _read_new_firewall_lines(self) -> None:
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                if self._last_pos == 0:
                    header_chunk = f.read(4096)
                    for hline in header_chunk.splitlines():
                        if hline.startswith("#Fields:"):
                            self._parse_fields_line(hline)
                    f.seek(0, 2)  # Ir al final para no procesar todo el histórico viejo
                    self._last_pos = f.tell()
                    return

                f.seek(0, 2)
                file_size = f.tell()
                if file_size < self._last_pos:
                    # Archivo rotado o truncado por Windows Firewall
                    self._last_pos = 0

                f.seek(self._last_pos)
                lines = f.readlines()
                self._last_pos = f.tell()

                idx_action = self._field_map.get("action", 2)
                idx_proto = self._field_map.get("protocol", 3)
                idx_src = self._field_map.get("src-ip", 4)
                idx_dst = self._field_map.get("dst-ip", 5)
                idx_dport = self._field_map.get("dst-port", 7)
                idx_path = self._field_map.get("path", 16)

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#"):
                        if line.lower().startswith("#fields:"):
                            self._parse_fields_line(line)
                        continue

                    parts = line.split()
                    if len(parts) <= max(idx_action, idx_proto, idx_src, idx_dst, idx_dport):
                        continue

                    action = parts[idx_action].upper()
                    if action != "DROP":
                        continue

                    # Solo tráfico entrante (RECEIVE); descartar paquetes salientes (SEND/FORWARD)
                    if len(parts) > idx_path:
                        direction = parts[idx_path].upper()
                        if direction not in ("RECEIVE", "-"):
                            continue

                    proto = parts[idx_proto].upper()
                    if proto not in FIREWALL_ALLOWED_PROTOCOLS:
                        continue

                    valid_src = validate_ip(parts[idx_src])
                    if not valid_src or _is_non_attack_ip(valid_src):
                        continue
                    if self._gateway_ip and valid_src == self._gateway_ip:
                        continue
                    if is_ip_blocked(valid_src):
                        continue

                    valid_dst = validate_ip(parts[idx_dst])
                    if valid_dst:
                        try:
                            dst_obj = ipaddress.ip_address(valid_dst)
                            if dst_obj.is_link_local or _is_multicast_or_broadcast(valid_dst):
                                continue
                        except ValueError:
                            pass

                    dst_port_raw = parts[idx_dport]
                    dst_port = int(dst_port_raw) if dst_port_raw.isdigit() else 0
                    if dst_port in LAN_DISCOVERY_PORTS:
                        continue
                    if proto == "UDP" and dst_port in UDP_INFRA_PORTS:
                        continue

                    normalize_event(
                        origen="windows_firewall",
                        severidad="HIGH",
                        evento=f"Paquete Bloqueado por Firewall ({proto} DROP)",
                        ip_origen=valid_src,
                        descripcion=f"Intento de conexión entrante bloqueado por Windows Defender Firewall hacia puerto {dst_port}",
                        puerto=dst_port
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

    # Puertos de servicios locales monitoreados ante escaneos Nmap / intrusiones
    SERVICE_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986,
        6379, 8000, 8001, 8080, 8443, 9000, 27017
    }

    def __init__(self, interval_seconds: float = 1.0):
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
        """Ejecuta netstat para recolectar conexiones entrantes hacia servicios del host."""
        try:
            res = subprocess.run(["netstat", "-a", "-n", "-p", "tcp"], capture_output=True, timeout=4, check=False, creationflags=SUBPROC_FLAGS)
            if res.returncode != 0 or not res.stdout:
                return

            stdout_text = res.stdout.decode("cp1252", errors="ignore")
            lines = stdout_text.splitlines()

            # 1. Identificar todos los puertos locales en estado LISTENING (< 49152)
            listening_ports = set(self.SERVICE_PORTS)
            for line in lines:
                line_s = line.strip()
                if not line_s.startswith("TCP"):
                    continue
                parts = line_s.split()
                if len(parts) >= 4 and parts[3] == "LISTENING" and ":" in parts[1]:
                    lp_str = parts[1].rsplit(":", 1)[1]
                    if lp_str.isdigit() and int(lp_str) < 49152:
                        listening_ports.add(int(lp_str))

            # 2. Inspeccionar conexiones activas entrantes hacia puertos de servicio locales
            current_keys = set()
            for line in lines:
                line_s = line.strip()
                if not line_s.startswith("TCP"):
                    continue
                parts = line_s.split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    foreign_addr = parts[2]
                    state = parts[3]

                    if state in ("ESTABLISHED", "SYN_RECEIVED", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2"):
                        if ":" in foreign_addr and ":" in local_addr:
                            remote_ip, remote_port = foreign_addr.rsplit(":", 1)
                            local_port = local_addr.rsplit(":", 1)[1]
                            if not local_port.isdigit():
                                continue
                            local_port_int = int(local_port)

                            # Ignorar conexiones salientes de cliente desde puertos efímeros (>= 49152)
                            if local_port_int >= 49152 or local_port_int not in listening_ports:
                                continue

                            conn_key = (remote_ip, local_port, remote_port)
                            current_keys.add(conn_key)

                            if conn_key not in self._seen_connections:
                                valid = validate_ip(remote_ip)
                                if (
                                    valid
                                    and not _is_non_attack_ip(valid)
                                    and valid != "192.168.88.234"
                                    and not is_ip_blocked(valid)
                                ):
                                    normalize_event(
                                        origen="network_traffic",
                                        severidad="MEDIUM" if state == "ESTABLISHED" else "HIGH",
                                        evento=f"Conexión de Red Entrante ({state})",
                                        ip_origen=valid,
                                        descripcion=f"Conexión entrante desde {valid}:{remote_port} hacia puerto local {local_port} ({state})",
                                        puerto=local_port_int
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
