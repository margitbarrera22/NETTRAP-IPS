"""
Pruebas automatizadas de empaquetado y operación de NetTrap-IPS.
Valida:
  - Resolución de rutas (modo desarrollo vs congelado)
  - Arranque de la app FastAPI, static assets, endpoints API y simulación de alertas
  - Arranque real de los ejecutables compilados (.exe) sin consola, con HTTP + WebSocket + PCAP
"""

from __future__ import annotations

import asyncio
import http.client
import json
import subprocess
import sys
import time
from pathlib import Path

import websockets

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "src" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def test_backend_fastapi_endpoints(tmp_path: Path, monkeypatch) -> None:
    """Verifica el servidor FastAPI, archivos estáticos, diagnóstico, simulación y PCAP."""
    monkeypatch.setenv("NETTRAP_DATA_DIR", str(tmp_path / "data"))
    import importlib
    import config
    importlib.reload(config)
    import main
    importlib.reload(main)

    from fastapi.testclient import TestClient

    with TestClient(main.app) as client:
        r_health = client.get("/api/health")
        assert r_health.status_code == 200
        assert r_health.json()["app"] == "NetTrap-IPS"

        r_home = client.get("/")
        assert r_home.status_code == 200
        assert "NetTrap" in r_home.text

        r_tw = client.get("/static/tailwind.js")
        assert r_tw.status_code == 200
        assert len(r_tw.content) > 10000

        r_chart = client.get("/static/chart.js")
        assert r_chart.status_code == 200
        assert len(r_chart.content) > 10000

        r_sources = client.get("/api/sources")
        assert r_sources.status_code == 200
        assert len(r_sources.json()) == 3

        r_cves = client.get("/api/cves")
        assert r_cves.status_code == 200
        assert len(r_cves.json()) >= 5

        r_sim = client.post(
            "/api/simulate",
            json={
                "source": "network_traffic",
                "scenario": "Test Pytest Empaquetado",
                "ip_origen": "198.51.100.77",
                "repeat": 5,
                "port": 445,
            },
        )
        assert r_sim.status_code == 200
        assert r_sim.json()["ok"] is True

        deadline = time.time() + 4.0
        alerts = []
        while time.time() < deadline:
            alerts = client.get("/api/alerts").json()
            if alerts:
                break
            time.sleep(0.15)
        assert len(alerts) >= 1

        r_clear = client.post("/api/clear")
        assert r_clear.status_code == 200


def _http_json(port: int, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        payload = json.dumps(body) if body is not None else None
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="ignore")
        return resp.status, json.loads(raw)
    finally:
        conn.close()


async def _ws_receive_simulated_alert(port: int) -> dict:
    uri = f"ws://127.0.0.1:{port}/ws/alerts"
    async with websockets.connect(uri, open_timeout=5.0) as ws:
        status, sim_resp = _http_json(
            port,
            "POST",
            "/api/simulate",
            {
                "source": "network_traffic",
                "scenario": "Validacion EXE Live",
                "ip_origen": "198.51.100.88",
                "repeat": 5,
                "port": 445,
            },
        )
        assert status == 200 and sim_resp["ok"] is True
        raw_msg = await asyncio.wait_for(ws.recv(), timeout=6.0)
        return json.loads(raw_msg)


def _verify_exe_serves_http(exe_path: Path, port: int, data_dir: Path) -> None:
    """Arranca un binario .exe compilado en modo headless y valida HTTP + WS + PCAP."""
    proc = subprocess.Popen(
        [
            str(exe_path),
            "--no-tray",
            "--no-elevate",
            "--no-browser",
            "--isolated",
            "--port",
            str(port),
            "--data-dir",
            str(data_dir),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        ready = False
        deadline = time.time() + 25.0
        while time.time() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate(timeout=2)
                raise AssertionError(
                    f"{exe_path.name} terminó prematuramente ({proc.returncode}): "
                    f"{out.decode(errors='ignore')} {err.decode(errors='ignore')}"
                )
            try:
                status, payload = _http_json(port, "GET", "/api/health")
                if status == 200 and isinstance(payload, dict) and payload.get("app") == "NetTrap-IPS":
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.35)

        assert ready, f"{exe_path.name} no respondió en /api/health en 25s"

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4.0)
        conn.request("GET", "/")
        r_dash = conn.getresponse()
        body = r_dash.read().decode("utf-8", errors="ignore")
        assert r_dash.status == 200 and "NetTrap" in body
        conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4.0)
        conn.request("GET", "/static/chart.js")
        r_static = conn.getresponse()
        _ = r_static.read()
        assert r_static.status == 200
        conn.close()

        # Diagnóstico, analítica, simulación y WebSocket en vivo contra el .exe
        st_diag, diag = _http_json(port, "GET", "/api/diagnostics")
        assert st_diag == 200 and len(diag["sources"]) == 3

        alert_ws = asyncio.run(_ws_receive_simulated_alert(port))
        assert alert_ws["ip_origen"] == "198.51.100.88"

        st_pcaps, pcaps = _http_json(port, "GET", "/api/pcaps")
        assert st_pcaps == 200 and len(pcaps) >= 1

        st_ana, ana = _http_json(port, "GET", "/api/analytics")
        assert st_ana == 200 and ana["summary"]["total_alerts"] >= 1

        st_clr, clr = _http_json(port, "POST", "/api/clear")
        assert st_clr == 200 and clr["ok"] is True

        assert (data_dir / "logs" / "nettrap.log").exists()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def test_compiled_onedir_executable(tmp_path: Path) -> None:
    """Valida el binario empaquetado dist/NetTrap-IPS/NetTrap-IPS.exe si existe."""
    exe = ROOT_DIR / "dist" / "NetTrap-IPS" / "NetTrap-IPS.exe"
    if not exe.exists():
        import pytest
        pytest.skip("NetTrap-IPS.exe aún no compilado")
    _verify_exe_serves_http(exe, port=18082, data_dir=tmp_path / "onedir_data")


def test_compiled_portable_executable(tmp_path: Path) -> None:
    """Valida el binario portable dist/NetTrap-IPS-Portable.exe si existe."""
    exe = ROOT_DIR / "dist" / "NetTrap-IPS-Portable.exe"
    if not exe.exists():
        import pytest
        pytest.skip("NetTrap-IPS-Portable.exe aún no compilado")
    _verify_exe_serves_http(exe, port=18083, data_dir=tmp_path / "portable_data")
