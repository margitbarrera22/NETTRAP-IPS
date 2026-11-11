"""
NetTrap-IPS · Motor de Correlación y Análisis SIEM/IPS (RF-03)
Evalúa eventos entrantes de las 3 fuentes reales de Windows contra reglas YAML.

Normas:
  - ISO/IEC 27033-4 Cl. 9.2   → Política default-deny / Aislamiento preventivo
  - OWASP ASVS v5.0 V5.1.1     → Validación estricta de entradas
  - NIST SP 800-218 PW.9.1     → Registro forense trazable
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
from collectors import event_queue

logger = logging.getLogger("nettrap.correlator")

# Cola de ALERTAS → consumida por AlertDispatcher para bloqueo y WebSocket
alert_queue: queue.Queue = queue.Queue(maxsize=500)

# Buffer circular persistente en memoria para las últimas alertas y eventos (RF-05)
recent_alerts_history: deque = deque(maxlen=200)
recent_events_history: deque = deque(maxlen=200)


def load_rules(path: Path = RULES_FILE) -> tuple[list[dict], list[str]]:
    """Carga y valida las reglas desde el archivo YAML."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        logger.error("Error al cargar reglas YAML: %s", exc)
        return [], []

    required_keys = {"id", "name", "threshold", "window_seconds", "severity", "action"}
    rules = []
    for rule in data.get("rules", []):
        if not required_keys.issubset(rule.keys()):
            logger.warning("Regla descartada por faltar campos requeridos: %s", rule.get("id"))
            continue
        rules.append(rule)

    whitelist = data.get("whitelist", [])
    logger.info("Reglas SIEM activas: %d | Whitelist protegida: %d", len(rules), len(whitelist))
    return rules, whitelist


class SlidingWindowCounter:
    """Mantiene contadores de eventos por IP y Regla dentro de una ventana temporal deslizante."""

    def __init__(self):
        self._lock = threading.RLock()
        self._windows: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))

    def add_and_count(self, rule_id: str, ip: str, window_seconds: float, now: float) -> int:
        with self._lock:
            dq = self._windows[rule_id][ip]
            dq.append(now)
            while dq and (now - dq[0]) > window_seconds:
                dq.popleft()
            return len(dq)

    def reset_for_ip(self, ip: str) -> None:
        with self._lock:
            for rule_id in self._windows:
                if ip in self._windows[rule_id]:
                    self._windows[rule_id][ip].clear()


class CorrelationEngine(threading.Thread):
    """
    Motor central de análisis y correlación en tiempo real.
    Consume la cola de eventos normalizados, aplica las reglas activas
    y despacha alertas de seguridad ante umbrales cumplidos.
    """

    def __init__(self):
        super().__init__(daemon=True, name="CorrelationEngine")
        self.rules, self.whitelist = load_rules()
        self._counter = SlidingWindowCounter()
        self._stop_evt = threading.Event()
        self._audit_path = LOG_DIR / "audit.jsonl"

    def _audit(self, record: dict) -> None:
        """Almacena auditoría en modo append-only (OWASP ASVS V8.1.1)."""
        try:
            with open(self._audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.error("Fallo al escribir en audit.jsonl: %s", exc)

    def run(self) -> None:
        logger.info("Motor de Correlación SIEM/IPS iniciado exitosamente.")
        while not self._stop_evt.is_set():
            try:
                event = event_queue.get(timeout=0.4)
                self._process_event(event)
            except queue.Empty:
                continue
            except Exception as exc:
                logger.error("Error inesperado en motor de correlación: %s", exc)

    def _process_event(self, event: dict) -> None:
        ip = event.get("ip_origen", "")
        now = time.time()
        is_simulation = event.get("is_simulation", False)
        event_source = event.get("origen", "")

        # Registrar en telemetría de eventos crudos en vivo
        recent_events_history.append(event)

        # 1. Whitelist anti-spoofing (ISO/IEC 27033-4 Cl. 9.2)
        if ip in self.whitelist and not is_simulation:
            logger.debug("IP %s en lista blanca — exenta de aislamiento", ip)
            return

        matched_alerts = []

        for rule in self.rules:
            rid = rule["id"]
            rule_source = rule.get("source", "")
            window = float(rule.get("window_seconds", 60))
            threshold = int(rule.get("threshold", 5))

            # Verificar coincidencia de fuente o aplicar correlación general
            source_matches = (
                not rule_source or 
                rule_source == event_source or
                is_simulation
            )

            if not source_matches:
                continue

            count = self._counter.add_and_count(rid, ip, window, now)

            if count >= threshold:
                matched_alerts.append((rule, count))

        if not matched_alerts:
            return

        # Priorizar la regla de mayor severidad
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        best_rule, count = max(matched_alerts, key=lambda x: sev_rank.get(x[0].get("severity", "LOW"), 0))

        alert = {
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "type":          "ALERT",
            "rule_id":       best_rule["id"],
            "rule_name":     best_rule["name"],
            "origen":        event_source,
            "ip_origen":     ip,
            "puerto":        event.get("puerto", 0),
            "severidad":     best_rule["severity"],
            "accion":        best_rule["action"],
            "count":         count,
            "threshold":     best_rule["threshold"],
            "cve_mitigated": best_rule.get("cve_mitigated", []),
            "descripcion": (
                f"[{best_rule['id']}] {ip} activó {count}/{best_rule['threshold']} eventos en "
                f"{best_rule['window_seconds']}s mediante {event_source} — {best_rule['name']}"
            )
        }

        logger.warning("🚨 [ALERTA CORRELACIONADA] %s", alert["descripcion"])
        self._audit(alert)
        recent_alerts_history.append(alert)

        # Reiniciar contador de esta IP para evitar disparos en cascada continuos
        self._counter.reset_for_ip(ip)

        # Encolar para despacho hacia firewall y WebSockets
        try:
            alert_queue.put_nowait(alert)
        except queue.Full:
            logger.error("Cola de alertas saturada")

    def stop(self) -> None:
        self._stop_evt.set()

    def reload_rules(self) -> None:
        self.rules, self.whitelist = load_rules()
        logger.info("Reglas SIEM recargadas dinámicamente")
