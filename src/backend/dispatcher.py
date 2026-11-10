"""
NetTrap-IPS · Worker de despacho de alertas
Consume alert_queue y ejecuta block_ip + capture_pcap según la acción de la regla.
"""
import threading
import logging
import queue

from correlator import alert_queue
from mitigator import block_ip, capture_pcap

logger = logging.getLogger("nettrap.dispatcher")

# Cola de alertas procesadas → para transmitir por WebSocket al frontend
ws_broadcast_queue: queue.Queue = queue.Queue(maxsize=500)


class AlertDispatcher(threading.Thread):
    """
    Hilo que toma alertas del motor de correlación y:
      1. Llama a block_ip si la acción es 'block_and_capture'
      2. Llama a capture_pcap para evidencia forense
      3. Reencola la alerta enriquecida en ws_broadcast_queue para WebSocket
    """

    def __init__(self):
        super().__init__(daemon=True, name="AlertDispatcher")
        self._stop_evt = threading.Event()

    def run(self) -> None:
        logger.info("AlertDispatcher iniciado")
        while not self._stop_evt.is_set():
            try:
                alert = alert_queue.get(timeout=0.5)
                self._dispatch(alert)
            except queue.Empty:
                continue
            except Exception as exc:
                logger.error("Error en dispatcher: %s", exc)

    def _dispatch(self, alert: dict) -> None:
        ip     = alert.get("ip_origen", "")
        port   = alert.get("puerto", 80)
        action = alert.get("accion", "alert_only")

        pcap_path = None
        block_result = {"success": False}

        if action == "block_and_capture":
            block_result = block_ip(ip, alert.get("rule_id", "NETTRAP"))
            pcap = capture_pcap(ip, port=port)
            pcap_path = str(pcap) if pcap else ""

        # Enriquecer la alerta con resultado de acciones
        alert["blocked"]          = block_result.get("success", False)
        alert["firewall_applied"] = block_result.get("firewall_applied", False)
        alert["block_details"]    = block_result.get("details", "")
        alert["pcap_path"]        = pcap_path
        alert["pcap_filename"]    = str(pcap_path).split("\\")[-1].split("/")[-1] if pcap_path else ""

        # Transmitir al frontend vía WebSocket
        try:
            ws_broadcast_queue.put_nowait(alert)
        except queue.Full:
            logger.error("ws_broadcast_queue llena — alerta no transmitida")

    def stop(self) -> None:
        self._stop_evt.set()

