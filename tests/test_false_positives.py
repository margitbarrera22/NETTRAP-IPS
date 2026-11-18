"""
Pruebas de filtrado de ruido LAN/Wi-Fi y prevención de falsos positivos en NetTrap-IPS.
Verifica que tráfico legítimo (mDNS 5353, SSDP 1900, IGMP, fe80::, router, navegador)
no dispare bloqueos falsos mientras los ataques reales y simulaciones sí se detectan.
"""

from __future__ import annotations

import queue
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "src" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _drain_queue(q: queue.Queue) -> list:
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


def test_firewall_collector_filters_lan_noise_and_outbound(tmp_path: Path, monkeypatch) -> None:
    import collectors
    import mitigator

    _drain_queue(collectors.event_queue)

    fw_log = tmp_path / "pfirewall.log"
    fw_log.write_text(
        "#Software: Microsoft Windows Firewall\n"
        "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(collectors, "get_default_gateway", lambda: "192.168.101.1")
    monkeypatch.setattr(collectors, "is_ip_blocked", lambda ip: ip == "198.51.100.200")

    col = collectors.WindowsFirewallCollector(log_path=fw_log, poll_interval=1.0)
    # Primera lectura: posicionarse al final
    col._read_new_firewall_lines()
    assert _drain_queue(collectors.event_queue) == []

    # Anexar ruido típico de red Wi-Fi + tráfico legítimo + un escaneo TCP real
    with open(fw_log, "a", encoding="utf-8") as f:
        # 1. Router haciendo IGMP (proto 2) y SSDP (1900)
        f.write("2026-11-17 17:50:15 DROP 2 192.168.101.1 224.0.0.1 - - 32 - - - - - - - RECEIVE\n")
        f.write("2026-11-17 17:50:15 DROP UDP 192.168.101.1 239.255.255.250 1900 1900 180 - - - - - - - RECEIVE\n")
        # 2. IPv6 link-local haciendo mDNS (5353)
        f.write("2026-11-17 17:50:15 DROP UDP fe80::8614:58ba:893c:85d4 ff02::fb 5353 5353 96 - - - - - - - RECEIVE\n")
        # 3. Otro PC en LAN haciendo mDNS / SSDP / NetBIOS / WS-Discovery / LLMNR
        f.write("2026-11-17 17:50:16 DROP UDP 192.168.101.4 224.0.0.251 5353 5353 96 - - - - - - - RECEIVE\n")
        f.write("2026-11-17 17:50:16 DROP UDP 192.168.101.4 239.255.255.250 55123 1900 180 - - - - - - - RECEIVE\n")
        f.write("2026-11-17 17:50:16 DROP UDP 192.168.101.4 192.168.101.255 137 137 78 - - - - - - - RECEIVE\n")
        f.write("2026-11-17 17:50:16 DROP UDP 192.168.101.4 239.255.255.250 55124 3702 180 - - - - - - - RECEIVE\n")
        f.write("2026-11-17 17:50:16 DROP UDP 192.168.101.4 224.0.0.252 55125 5355 64 - - - - - - - RECEIVE\n")
        # 4. Paquete saliente (SEND) no debe contar como ataque entrante
        f.write("2026-11-17 17:50:16 DROP TCP 192.168.101.4 192.168.101.27 51200 445 52 S 0 0 64240 - - - SEND\n")
        # 5. IP ya bloqueada por NetTrap (no debe re-disparar bucle cada 12s)
        f.write("2026-11-17 17:50:16 DROP TCP 198.51.100.200 192.168.101.27 51201 8000 52 S 0 0 64240 - - - RECEIVE\n")
        # 6. Escaneo entrante real TCP hacia puerto 22 y 3389
        f.write("2026-11-17 17:50:17 DROP TCP 203.0.113.50 192.168.101.27 40001 22 52 S 0 0 64240 - - - RECEIVE\n")
        f.write("2026-11-17 17:50:17 DROP TCP 203.0.113.50 192.168.101.27 40002 3389 52 S 0 0 64240 - - - RECEIVE\n")

    col._read_new_firewall_lines()
    events = _drain_queue(collectors.event_queue)
    assert len(events) == 2
    assert all(ev["ip_origen"] == "203.0.113.50" for ev in events)
    assert [ev["puerto"] for ev in events] == [22, 3389]


def test_correlator_protects_gateway_and_browser_but_catches_attacks(monkeypatch) -> None:
    import correlator

    _drain_queue(correlator.alert_queue)
    monkeypatch.setattr(correlator, "get_default_gateway", lambda: "192.168.101.1")
    monkeypatch.setattr(correlator, "is_ip_blocked", lambda ip: False)

    eng = correlator.CorrelationEngine()
    assert "192.168.101.1" in eng.whitelist

    # 1. Tráfico del gateway/router o enlace local nunca genera alerta
    for _ in range(6):
        eng._process_event({
            "origen": "windows_firewall",
            "ip_origen": "192.168.101.1",
            "puerto": 445,
            "evento": "Paquete Bloqueado por Firewall (TCP DROP)",
            "is_simulation": False,
        })
        eng._process_event({
            "origen": "windows_firewall",
            "ip_origen": "fe80::8614:58ba:893c:85d4",
            "puerto": 5353,
            "evento": "Paquete Bloqueado por Firewall (UDP DROP)",
            "is_simulation": False,
        })
    assert _drain_queue(correlator.alert_queue) == []

    # 2. Navegador legítimo abriendo 5 sockets al puerto 8000 no dispara RULE-002
    for _ in range(5):
        eng._process_event({
            "origen": "network_traffic",
            "ip_origen": "192.168.101.4",
            "puerto": 8000,
            "evento": "Conexión de Red Entrante (ESTABLISHED)",
            "is_simulation": False,
        })
    assert _drain_queue(correlator.alert_queue) == []

    # 3. Escaneo multipuerto real (4 puertos distintos) SÍ dispara RULE-002
    for p in (21, 22, 445, 3389):
        eng._process_event({
            "origen": "network_traffic",
            "ip_origen": "203.0.113.99",
            "puerto": p,
            "evento": "Conexión de Red Entrante (SYN_RECEIVED)",
            "is_simulation": False,
        })
    alerts = _drain_queue(correlator.alert_queue)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-002"
    assert alerts[0]["ip_origen"] == "203.0.113.99"

    # 4. Simulación en 1 clic (repeat=5 al mismo puerto) sigue disparando RULE-003
    for _ in range(5):
        eng._process_event({
            "origen": "windows_firewall",
            "ip_origen": "198.51.100.77",
            "puerto": 445,
            "evento": "Paquete Bloqueado por Firewall [Ataque Firewall DROP]",
            "is_simulation": True,
        })
    sim_alerts = _drain_queue(correlator.alert_queue)
    assert len(sim_alerts) == 1
    assert sim_alerts[0]["rule_id"] == "RULE-003"


def test_http_middleware_allows_normal_browser_and_flags_scanners(tmp_path: Path, monkeypatch) -> None:
    import asyncio
    import importlib
    import httpx

    monkeypatch.setenv("NETTRAP_DATA_DIR", str(tmp_path / "mw_data"))
    import config
    importlib.reload(config)
    import collectors
    importlib.reload(collectors)
    import main
    importlib.reload(main)

    _drain_queue(collectors.event_queue)

    async def _run_checks() -> None:
        transport = httpx.ASGITransport(app=main.app, client=("192.168.101.4", 54321))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            browser_ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0"}
            assert (await client.get("/", headers=browser_ua)).status_code == 200
            assert (await client.get("/api/status", headers=browser_ua)).status_code == 200
            assert (await client.get("/api/alerts", headers=browser_ua)).status_code == 200
            assert (await client.get("/api/events", headers=browser_ua)).status_code == 200
            assert _drain_queue(collectors.event_queue) == []

            scanner_ua = {"User-Agent": "Nmap Scripting Engine"}
            await client.get("/.env", headers=scanner_ua)
            events = _drain_queue(collectors.event_queue)
            assert len(events) == 1
            assert events[0]["ip_origen"] == "192.168.101.4"
            assert events[0]["origen"] == "network_traffic"

    asyncio.run(_run_checks())

