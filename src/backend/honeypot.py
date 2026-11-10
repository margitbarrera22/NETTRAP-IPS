"""
NetTrap-IPS · Módulo de Trampas (Honeypot Sockets)
Componente 1 de 5 — Clase 2/5

Abre puertos señuelo y registra cualquier intento de conexión.
Al detectar un toque, extrae IP/puerto/timestamp y cierra el socket inmediatamente.

Normas:
  - ISO/IEC 27033-1 Cl. 10.3  → registro cronológico de cada intento
  - OWASP ASVS V7.4.1          → manejo seguro de excepciones
  - NIST SP 800-218 PW.9.1     → datos forenses trazables

CVEs que este módulo ayuda a detectar/mitigar:
  - CVE-2024-37032  (Ollama RCE por exposición de servicios en red local)
  - CVE-2019-0708   (BlueKeep RDP — detectado si se toca el puerto 3389 señuelo)
  - CVE-2023-38408  (OpenSSH RCE — detectado si se toca el puerto 2222 señuelo)
"""

import socket
import threading
import ipaddress
import logging
import time
import queue
from datetime import datetime, timezone

from config import HONEYPOT_PORTS, QUEUE_MAX_SIZE, LOG_DIR

# ── Logger del módulo ─────────────────────────────────────────────────────────
logger = logging.getLogger("nettrap.honeypot")

# Cola compartida entre hilos (buffer limit → mitiga DoS ISO 27033-1 Cl. 10.2)
event_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAX_SIZE)


# ─────────────────────────────────────────────────────────────────────────────
# Validación de IP — OWASP ASVS V5.1.1
# Sanitizar ANTES de enviar a cualquier componente del sistema
# ─────────────────────────────────────────────────────────────────────────────
def validate_ip(raw_ip: str) -> str | None:
    """
    Valida y normaliza una dirección IP (IPv4 o IPv6).
    Devuelve la IP en formato canónico o None si es inválida.
    NUNCA lanza excepción al exterior (OWASP ASVS V7.4.1).
    """
    try:
        # ipaddress rechaza cualquier entrada que no sea IP válida
        return str(ipaddress.ip_address(raw_ip.strip()))
    except ValueError:
        logger.warning("IP inválida descartada: %r", raw_ip)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Listener individual por puerto
# ─────────────────────────────────────────────────────────────────────────────
class HoneypotListener(threading.Thread):
    """
    Hilo daemon que escucha en un único puerto señuelo.
    Ante cualquier conexión entrante:
      1. Extrae IP de origen (validada con ipaddress).
      2. Cierra el socket inmediatamente (no permite interacción).
      3. Encola un evento JSON hacia el motor de correlación.
    """

    def __init__(self, port: int, label: str):
        super().__init__(daemon=True, name=f"Honeypot-{port}")
        self.port  = port
        self.label = label
        self._stop_event = threading.Event()

    def run(self) -> None:
        # Reintentar si el puerto está temporalmente ocupado
        while not self._stop_event.is_set():
            try:
                self._listen()
            except OSError as exc:
                # OWASP ASVS V7.4.1 — excepción interna, no se expone al exterior
                logger.error("[%s] Error en socket puerto %d: %s — reintentando en 5 s",
                             self.label, self.port, exc)
                time.sleep(5)

    def _listen(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(0.5)          # no bloquear para poder revisar _stop_event
            srv.bind(("0.0.0.0", self.port))
            srv.listen(5)
            logger.info("[%s] Trampa activa en puerto %d", self.label, self.port)

            while not self._stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                    conn.close()         # cerrar inmediatamente — no hay interacción

                    raw_ip = addr[0]
                    valid_ip = validate_ip(raw_ip)
                    if valid_ip is None:
                        continue         # IP malformada descartada

                    event = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "origen":    "honeypot",
                        "puerto":    self.port,
                        "label":     self.label,
                        "ip_origen": valid_ip,
                        "severidad": "HIGH",
                        "evento":    f"Conexión detectada en trampa {self.label}",
                        "descripcion": (
                            f"IP {valid_ip} tocó el puerto señuelo {self.port} "
                            f"({self.label}) — posible reconocimiento/escaneo."
                        ),
                    }

                    # Encolar sin bloquear (protección DoS — ISO 27033-1 Cl. 10.2)
                    try:
                        event_queue.put_nowait(event)
                        logger.warning("EVENTO → %s", event)
                    except queue.Full:
                        logger.error("Cola llena — evento descartado (DoS protection)")

                except socket.timeout:
                    continue   # timeout normal, revisar _stop_event
                except Exception as exc:
                    # OWASP ASVS V7.4.1 — capturar sin exponer stack trace
                    logger.error("[%s] Excepción interna: %s", self.label, exc)

    def stop(self) -> None:
        self._stop_event.set()


# ─────────────────────────────────────────────────────────────────────────────
# Gestor del módulo
# ─────────────────────────────────────────────────────────────────────────────
class HoneypotManager:
    """
    Lanza y controla todos los listeners en sus hilos daemon.
    Uso:
        manager = HoneypotManager()
        manager.start()
        ...
        manager.stop()
    """

    PORT_LABELS = {
        21:   "FTP-Trap",
        2222: "SSH-Trap",
        8080: "HTTP-Trap",
        3389: "RDP-Trap",
    }

    def __init__(self, ports: list[int] | None = None):
        self.ports     = ports or HONEYPOT_PORTS
        self._listeners: list[HoneypotListener] = []

    def start(self) -> None:
        for port in self.ports:
            label = self.PORT_LABELS.get(port, f"PORT-{port}-Trap")
            listener = HoneypotListener(port, label)
            listener.start()
            self._listeners.append(listener)
        logger.info("HoneypotManager: %d trampas activas", len(self._listeners))

    def stop(self) -> None:
        for listener in self._listeners:
            listener.stop()
        logger.info("HoneypotManager: todas las trampas detenidas")

    def status(self) -> list[dict]:
        return [
            {
                "port":  lst.port,
                "label": lst.label,
                "alive": lst.is_alive(),
            }
            for lst in self._listeners
        ]

