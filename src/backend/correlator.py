"""
NetTrap-IPS · Motor de Correlación y Análisis
Componente 2 de 5 — Clase 2/5

Consume eventos de la cola del Honeypot, aplica reglas YAML configurables,
detecta patrones de escaneo y dispara la mitigación si se supera el umbral.

Normas:
  - ISO/IEC 27033-4 Cl. 9.2   → política default-deny / aislamiento
  - OWASP ASVS V5.1.1          → validación estricta de entradas (IP ya validada)
  - NIST SP 800-218 PW.9.1     → trazabilidad de alertas

CVEs mitigados por las reglas de este motor:
  RULE-001 → CVE-2024-37032, CVE-2019-0708
  RULE-002 → CVE-2015-3306
  RULE-003 → CVE-2023-38408
  RULE-004 → CVE-2021-44228
"""

import yaml
import logging
import threading
import queue
import time
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from config import RULES_FILE, LOG_DIR, QUEUE_MAX_SIZE
from honeypot import event_queue

logger = logging.getLogger("nettrap.correlator")

# Cola de ALERTAS → consumida por el backend FastAPI para WebSocket
alert_queue: queue.Queue = queue.Queue(maxsize=500)

# Buffer circular en memoria con las últimas 150 alertas para carga instantánea al refrescar
recent_alerts_history: deque = deque(maxlen=150)
recent_events_history: deque = deque(maxlen=150)


# ─────────────────────────────────────────────────────────────────────────────
# Carga de reglas YAML — validadas con esquema básico
# ─────────────────────────────────────────────────────────────────────────────
def load_rules(path: Path = RULES_FILE) -> tuple[list[dict], list[str], list[dict]]:
    """
    Carga detection_rules.yaml y devuelve (rules, whitelist, honeypot_ports).
    Valida que cada regla tenga los campos requeridos.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    required_keys = {"id", "name", "threshold", "window_seconds", "severity", "action"}
    rules = []
    for rule in data.get("rules", []):
        missing = required_keys - rule.keys()
        if missing:
            logger.warning("Regla incompleta ignorada (faltan %s): %s", missing, rule.get("id"))
            continue
        rules.append(rule)

    whitelist = data.get("whitelist", [])
    ports     = data.get("honeypot_ports", [])

    logger.info("Reglas cargadas: %d | IPs en whitelist: %d", len(rules), len(whitelist))
    return rules, whitelist, ports


# ─────────────────────────────────────────────────────────────────────────────
# Ventana deslizante por IP/regla
# ─────────────────────────────────────────────────────────────────────────────
class SlidingWindowCounter:
    """
    Cuenta eventos de una IP dentro de una ventana temporal deslizante.
    Thread-safe mediante RLock.
    """

    def __init__(self):
        self._lock   = threading.RLock()
        # {rule_id: {ip: deque([timestamp, ...])}}
        self._windows: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))

    def add(self, rule_id: str, ip: str, now: float) -> int:
        """Registra el evento y devuelve cuántos eventos hay en la ventana."""
        with self._lock:
            dq = self._windows[rule_id][ip]
            dq.append(now)
            return len(dq)

    def prune(self, rule_id: str, ip: str, window: float, now: float) -> int:
        """Elimina eventos fuera de la ventana y devuelve el conteo actualizado."""
        with self._lock:
            dq = self._windows[rule_id][ip]
            while dq and (now - dq[0]) > window:
                dq.popleft()
            return len(dq)


# ─────────────────────────────────────────────────────────────────────────────
# Motor principal
# ─────────────────────────────────────────────────────────────────────────────
class CorrelationEngine(threading.Thread):
    """
    Hilo principal del motor de correlación.
    Lee eventos de event_queue, aplica reglas y emite alertas a alert_queue.
    También registra en el log de auditoría (append-only).
    """

    def __init__(self):
        super().__init__(daemon=True, name="CorrelationEngine")
        self.rules, self.whitelist, _ = load_rules()
        self._counter  = SlidingWindowCounter()
        self._stop_evt = threading.Event()
        self._audit_path = LOG_DIR / "audit.jsonl"

    # ── Logging de auditoría append-only (OWASP ASVS V8.1.1) ─────────────────
    def _audit(self, record: dict) -> None:
        try:
            with open(self._audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as exc:
            # OWASP ASVS V7.4.1 — nunca detiene el motor por error de log
            logger.error("Error al escribir auditoría: %s", exc)

    # ── Lógica principal ──────────────────────────────────────────────────────
    def run(self) -> None:
        logger.info("Motor de correlación iniciado")
        while not self._stop_evt.is_set():
            try:
                event = event_queue.get(timeout=0.5)
                self._process(event)
            except queue.Empty:
                continue
            except Exception as exc:
                logger.error("Error inesperado en motor: %s", exc)

    def _process(self, event: dict) -> None:
        ip  = event.get("ip_origen", "")
        now = time.time()
        is_simulation = event.get("is_simulation", False)

        # Registrar en historial de telemetría de eventos crudos
        recent_events_history.append(event)

        # 1. Whitelist check → mitiga IP Spoofing (ISO 27033-4 Cl. 9.2)
        # En modo simulación/demo deliberada se permite la correlación
        if ip in self.whitelist and not is_simulation:
            logger.debug("IP %s en whitelist — ignorada", ip)
            return

        matched_rules = []

        for rule in self.rules:
            rid      = rule["id"]
            window   = float(rule["window_seconds"])
            threshold = int(rule["threshold"])

            # Añadir y limpiar ventana
            self._counter.add(rid, ip, now)
            count = self._counter.prune(rid, ip, window, now)

            if count >= threshold:
                matched_rules.append((rule, count))

        if not matched_rules:
            return

        # Tomar la regla de mayor severidad
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        best_rule, count = max(
            matched_rules,
            key=lambda x: sev_order.get(x[0]["severity"], 0)
        )

        alert = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "type":        "ALERT",
            "rule_id":     best_rule["id"],
            "rule_name":   best_rule["name"],
            "ip_origen":   ip,
            "puerto":      event.get("puerto"),
            "label":       event.get("label"),
            "severidad":   best_rule["severity"],
            "accion":      best_rule["action"],
            "count":       count,
            "threshold":   best_rule["threshold"],
            "cve_mitigated": best_rule.get("cve_mitigated", []),
            "descripcion": (
                f"[{best_rule['id']}] {ip} activó {count}/{best_rule['threshold']} "
                f"eventos en {best_rule['window_seconds']}s — {best_rule['name']}"
            ),
        }

        logger.warning("ALERTA GENERADA: %s", alert)
        self._audit(alert)
        recent_alerts_history.append(alert)

        # Encolar alerta para WebSocket (sin bloquear)
        try:
            alert_queue.put_nowait(alert)
        except queue.Full:
            logger.error("Cola de alertas llena")

    def stop(self) -> None:
        self._stop_evt.set()

    def reload_rules(self) -> None:
        """Recarga reglas en caliente sin reiniciar el hilo."""
        self.rules, self.whitelist, _ = load_rules()
        logger.info("Reglas recargadas en caliente")

