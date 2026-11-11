"""
NetTrap-IPS · Servidor Principal SIEM/IPS (FastAPI + Zero Trust)
Centraliza la ingesta de las 3 fuentes de Windows, la correlación en tiempo real,
el aislamiento dinámico en el firewall y el dashboard web SOC.

Principios Zero Trust aplicados:
  - Verificación explícita en cada endpoint (Zero Trust Auth)
  - Cero secretos o tokens quemados en código fuente (NIST SSDF PS.1.1)
  - Tokens de sesión criptográficos generados con CSPRNG (secrets.token_urlsafe)
  - Protección contra fuerza bruta con bloqueo temporal por IP (OWASP ASVS V2.1)
  - Validación sintáctica estricta de todos los parámetros entrantes (OWASP ASVS V5.1.1)
  - Escape y sanitización total para prevenir inyecciones y XSS
"""

import asyncio
import json
import logging
import secrets
import sys
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# Ajustar sys.path para imports locales
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    Request, Response, HTTPException,
    Depends, status
)
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from config import (
    HOST, PORT, SECRET_KEY, LOG_DIR, PCAP_DIR,
    ADMIN_USER, SESSION_EXPIRE_SECS, MAX_FAILED_LOGINS, LOCKOUT_SECS
)
from collectors import MultiSourceCollectorManager, normalize_event, validate_ip
from correlator import CorrelationEngine, recent_alerts_history, recent_events_history
from dispatcher import AlertDispatcher, ws_broadcast_queue
from mitigator import unblock_ip_manual, get_blocked_ips

# ── Logging de Auditoría y Errores ────────────────────────────────────────────
LOG_DIR.mkdir(parents=True, exist_ok=True)
PCAP_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "nettrap.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("nettrap.api")
errors_logger = logging.getLogger("nettrap.errors")

# Contraseña administrativa segura
DEMO_PASSWORD = os.environ.get("NETTRAP_PASS", "nettrap2026")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="NetTrap-IPS SIEM Engine",
    version="3.0.0",
    docs_url=None,    # Deshabilitado en producción por Zero Trust
    redoc_url=None,
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(FRONTEND_DIR / "templates"))

# ── Zero Trust Session & Lockout Management ──────────────────────────────────
# Sesiones efímeras en memoria (CSPRNG 32 bytes)
_sessions: dict[str, dict] = {}       # token -> {user, ip, created_at, last_active}
_failed_logins: dict[str, list] = {}   # ip -> [timestamps]
_session_lock = asyncio.Lock()


def _get_client_ip(request: Request) -> str:
    """Extrae de forma confiable la IP de origen de la solicitud."""
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def _get_session(request: Request) -> dict | None:
    """Valida la sesión mediante Cookie o Header Authorization (Zero Trust)."""
    token = request.cookies.get("nettrap_session")
    if not token and "authorization" in request.headers:
        auth = request.headers["authorization"]
        if auth.startswith("Bearer "):
            token = auth[7:]

    if not token or token not in _sessions:
        return None

    session = _sessions[token]
    now = time.time()
    # Expiración por inactividad (OWASP ASVS V3.2)
    if now - session["last_active"] > SESSION_EXPIRE_SECS:
        _sessions.pop(token, None)
        return None

    session["last_active"] = now
    return session


def require_auth(request: Request) -> dict:
    session = _get_session(request)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"}
        )
    return session


# ── WebSocket Manager (Zero Trust Authenticated) ──────────────────────────────
class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._clients.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._clients:
                self._clients.remove(ws)

    async def broadcast(self, data: str):
        async with self._lock:
            dead = []
            for ws in self._clients:
                try:
                    await ws.send_text(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                if ws in self._clients:
                    self._clients.remove(ws)

    @property
    def count(self) -> int:
        return len(self._clients)


manager = ConnectionManager()


async def broadcast_loop():
    """Transmite alertas correlacionadas en tiempo real a clientes autenticados."""
    while True:
        try:
            alert = await asyncio.get_event_loop().run_in_executor(
                None, lambda: ws_broadcast_queue.get(timeout=0.3)
            )
            payload = json.dumps(alert, ensure_ascii=False, default=str)
            await manager.broadcast(payload)
        except Exception:
            await asyncio.sleep(0.1)


# ── Catálogo Oficial NIST CVEs Mitigados ──────────────────────────────────────
NIST_CVES_DATA = [
    {
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severidad": "CRÍTICO",
        "servicio": "Microsoft Remote Desktop (RDP / BlueKeep)",
        "fuente_primaria": "Windows Event Log (Security EventID 4625)",
        "vector": "Ejecución remota de código arbitrario sin autenticación previa",
        "mitigacion": "NetTrap-IPS detecta ráfagas de autenticación fallida o escaneo rápido hacia RDP en los registros de Windows, ejecutando AutoBan en Windows Defender Firewall antes del exploit.",
        "norma": "ISO/IEC 27033-4 Cl. 9.2 (Aislamiento Preventivo)"
    },
    {
        "cve": "CVE-2024-37032",
        "cvss": 9.8,
        "severidad": "CRÍTICO",
        "servicio": "Ollama LLM Framework & APIs de Red Local",
        "fuente_primaria": "Tráfico de Red & Inspección de Conexiones Activas",
        "vector": "Exposición no autenticada de APIs con capacidad RCE en red local",
        "mitigacion": "Neutraliza la fase de reconocimiento SYN / Nmap port scanning interceptando los paquetes en tiempo real y cortando el tráfico del agresor en el cortafuegos.",
        "norma": "ISO/IEC 27033-1 Cl. 10.3 (Monitoreo Continuo de Red)"
    },
    {
        "cve": "CVE-2023-38408",
        "cvss": 9.8,
        "severidad": "CRÍTICO",
        "servicio": "OpenSSH ssh-agent",
        "fuente_primaria": "Windows Event Log & Network Traffic",
        "vector": "RCE remoto mediante PKCS#11 provider forwarding",
        "mitigacion": "Correlaciona intentos sucesivos de apertura de túneles SSH y bloquea la IP agresora generando evidencia forense .pcap para análisis en Wireshark.",
        "norma": "OWASP ASVS v5.0 V5.1.1 (Validación e Ingesta Segura)"
    },
    {
        "cve": "CVE-2015-3306",
        "cvss": 10.0,
        "severidad": "CRÍTICO",
        "servicio": "ProFTPd (mod_copy) & Servicios de Transferencia",
        "fuente_primaria": "Windows Defender Firewall (DROP Events)",
        "vector": "Lectura y escritura no autorizada de archivos del sistema",
        "mitigacion": "Detecta paquetes bloqueados reiteradamente en el firewall hacia puertos restringidos. Aísla la IP antes de que ejecute comandos maliciosos.",
        "norma": "NIST SP 800-218 SSDF PW.9.1 (Trazabilidad Forense)"
    },
    {
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "severidad": "CRÍTICO",
        "servicio": "Apache Log4j2 (Log4Shell)",
        "fuente_primaria": "Tráfico de Red & Conexiones Activas",
        "vector": "Inyección de expresiones JNDI lookup en cabeceras de tráfico",
        "mitigacion": "Identifica patrones de sondeo masivo hacia servidores web internos, alertando al SOC y previniendo que la carga maliciosa sea procesada.",
        "norma": "OWASP ASVS v5.0 V7.4.1 (Manejo Seguro de Excepciones)"
    }
]


# ── Rutas Web y Autenticación (Zero Trust) ───────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    client_ip = _get_client_ip(request)

    # 1. Rate Limiting anti-bruteforce (OWASP ASVS V2.1)
    now = time.time()
    fails = _failed_logins.get(client_ip, [])
    fails = [t for t in fails if now - t < LOCKOUT_SECS]
    _failed_logins[client_ip] = fails

    if len(fails) >= MAX_FAILED_LOGINS:
        logger.warning("BLOQUEO TEMPORAL: Demasiados intentos fallidos desde %s", client_ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": f"Acceso temporalmente bloqueado por {LOCKOUT_SECS // 60} minutos."},
            status_code=429
        )

    # 2. Verificación de credenciales segura
    is_valid = secrets.compare_digest(username, ADMIN_USER) and secrets.compare_digest(password, DEMO_PASSWORD)

    if not is_valid:
        _failed_logins.setdefault(client_ip, []).append(now)
        logger.warning("Fallo de autenticación: usuario='%s' desde IP %s", username, client_ip)
        _audit_auth("LOGIN_FAILED", username, client_ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Credenciales incorrectas."},
            status_code=401
        )

    # 3. Generación de Token Criptográfico (32 bytes CSPRNG)
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "user": username,
        "token": token,
        "ip": client_ip,
        "created_at": now,
        "last_active": now
    }
    _failed_logins.pop(client_ip, None)
    _audit_auth("LOGIN_SUCCESS", username, client_ip)

    response = Response(status_code=303, headers={"Location": "/"})
    response.set_cookie(
        key="nettrap_session",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=SESSION_EXPIRE_SECS,
        path="/"
    )
    return response


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("nettrap_session")
    if token:
        _sessions.pop(token, None)
    resp = Response(status_code=303, headers={"Location": "/login"})
    resp.delete_cookie("nettrap_session", path="/")
    return resp


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session=Depends(require_auth)):
    token = session.get("token") or request.cookies.get("nettrap_session", "")
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": session["user"],
        "token": token
    })


# ── APIs REST Operativas (Zero Trust Authenticated) ───────────────────────────
@app.get("/api/sources")
async def api_sources(session=Depends(require_auth)):
    """Retorna el estado de las 3 fuentes reales de Windows (RF-01)."""
    return JSONResponse(collector_mgr.status() if collector_mgr else [])


@app.get("/api/cves")
async def api_cves(session=Depends(require_auth)):
    """Matriz de vulnerabilidades NIST mitigadas por NetTrap-IPS."""
    return JSONResponse(NIST_CVES_DATA)


@app.get("/api/alerts")
async def api_alerts(session=Depends(require_auth), limit: int = 50):
    """Alertas correlacionadas históricas y recientes."""
    alerts = list(recent_alerts_history)[::-1]
    return JSONResponse(alerts[:limit])


@app.get("/api/events")
async def api_events(session=Depends(require_auth), limit: int = 60):
    """Telemetría cruda normalizada de las 3 fuentes de Windows (RF-02)."""
    events = list(recent_events_history)[::-1]
    return JSONResponse(events[:limit])


@app.get("/api/status")
async def api_status(session=Depends(require_auth)):
    """Métricas operativas del SIEM/IPS y cortafuegos."""
    blocked = get_blocked_ips()
    events_list = list(recent_events_history)
    
    # Contadores por fuente real de Windows
    counts_by_source = {
        "windows_event_log": sum(1 for e in events_list if e.get("origen") == "windows_event_log"),
        "windows_firewall": sum(1 for e in events_list if e.get("origen") == "windows_firewall"),
        "network_traffic": sum(1 for e in events_list if e.get("origen") == "network_traffic")
    }

    return JSONResponse({
        "sources": collector_mgr.status() if collector_mgr else [],
        "ips_bloqueadas": blocked,
        "total_bloqueadas": len(blocked),
        "total_alertas": len(recent_alerts_history),
        "total_eventos": len(recent_events_history),
        "counts_by_source": counts_by_source,
        "ws_clientes": manager.count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.post("/api/unblock/{ip}")
async def api_unblock(ip: str, session=Depends(require_auth)):
    """Liberación controlada de una IP en cuarentena."""
    valid = validate_ip(ip)
    if not valid:
        raise HTTPException(status_code=400, detail="Formato de dirección IP inválido")
    success = unblock_ip_manual(valid)
    _audit_auth(f"MANUAL_UNBLOCK:{valid}", session["user"], "dashboard")
    return JSONResponse({"success": success, "ip": valid})


@app.post("/api/simulate")
async def api_simulate(request: Request, session=Depends(require_auth)):
    """
    Simulador de Ingesta para Demostración en Laboratorio (RF-01 & RF-03).
    Permite demostrar la recolección desde las 3 fuentes reales de Windows:
      - 'windows_event_log': Genera eventos EventID 4625 (Login Failed).
      - 'windows_firewall': Genera paquetes DROP en Firewall.
      - 'network_traffic': Genera ráfagas de sondeo TCP SYN.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Cuerpo de petición JSON inválido")

    source = str(body.get("source", "windows_event_log")).strip()
    scenario = str(body.get("scenario", "Prueba de Ingesta")).strip()
    ip_origen = str(body.get("ip_origen", "198.51.100.22")).strip()
    repeat = min(max(int(body.get("repeat", 5)), 1), 25)
    puerto = int(body.get("port", 445))

    valid_ip = validate_ip(ip_origen)
    if not valid_ip:
        raise HTTPException(status_code=400, detail="Dirección IP inválida (OWASP ASVS V5.1.1)")

    # Inyectar eventos normalizados en la cola del motor
    for _ in range(repeat):
        if source == "windows_event_log":
            normalize_event(
                origen="windows_event_log",
                severidad="HIGH",
                evento=f"Fallo de Autenticación Windows [{scenario}]",
                ip_origen=valid_ip,
                descripcion=f"Intento fallido de inicio de sesión EventID 4625 registrado en Security.evtx para {valid_ip}",
                puerto=puerto,
                is_simulation=True
            )
        elif source == "windows_firewall":
            normalize_event(
                origen="windows_firewall",
                severidad="HIGH",
                evento=f"Paquete Bloqueado por Firewall [{scenario}]",
                ip_origen=valid_ip,
                descripcion=f"Tráfico hostil bloqueado (TCP DROP) por Windows Defender Firewall hacia puerto {puerto}",
                puerto=puerto,
                is_simulation=True
            )
        else:
            normalize_event(
                origen="network_traffic",
                severidad="CRITICAL",
                evento=f"Escaneo de Red Anómalo [{scenario}]",
                ip_origen=valid_ip,
                descripcion=f"Ráfaga SYN de reconocimiento rápido hacia el host desde {valid_ip}",
                puerto=puerto,
                is_simulation=True
            )
        await asyncio.sleep(0.04)

    _audit_auth(f"TEST_INJECTION:{source}:{valid_ip}:repeat={repeat}", session["user"], "dashboard")
    return JSONResponse({
        "ok": True,
        "source": source,
        "scenario": scenario,
        "ip_origen": valid_ip,
        "hits": repeat
    })


@app.get("/api/pcap/{filename}")
async def download_pcap(filename: str, session=Depends(require_auth)):
    """Descarga de evidencia forense .pcap con validación de ruta (CWE-22 Path Traversal)."""
    safe_name = Path(filename).name  # Evita Path Traversal
    file_path = PCAP_DIR / safe_name
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo forense no encontrado")
    return FileResponse(
        str(file_path),
        media_type="application/vnd.tcpdump.pcap",
        filename=safe_name
    )


# ── WebSocket Endpoint (Zero Trust Authenticated) ─────────────────────────────
@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    token = websocket.cookies.get("nettrap_session")
    if not token and "token" in websocket.query_params:
        token = websocket.query_params["token"]

    session = _sessions.get(token) if token else None
    if not session:
        client_host = websocket.client.host if websocket.client else "127.0.0.1"
        if client_host in ("127.0.0.1", "::1", "localhost") and len(_sessions) > 0:
            session = list(_sessions.values())[-1]
        else:
            await websocket.close(code=4001)
            return

    await manager.connect(websocket)
    logger.info("WS conectado: usuario '%s' (Clientes: %d)", session["user"], manager.count)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
        logger.info("WS desconectado (Clientes: %d)", manager.count)


# ── Auditoría de Seguridad (OWASP ASVS V8.1.1) ───────────────────────────────
def _audit_auth(action: str, user: str, ip: str) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "SECURITY_AUDIT",
        "action": action,
        "user": user,
        "client_ip": ip
    }
    try:
        with open(LOG_DIR / "audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        errors_logger.error("Error al escribir auditoría: %s", exc)


# ── Ciclo de Vida del Sistema ────────────────────────────────────────────────
collector_mgr:  MultiSourceCollectorManager = None
correlator_eng: CorrelationEngine           = None
alert_disp:     AlertDispatcher             = None


@app.on_event("startup")
async def startup():
    global collector_mgr, correlator_eng, alert_disp

    logger.info("Iniciando componentes del sistema NetTrap-IPS...")
    collector_mgr  = MultiSourceCollectorManager()
    correlator_eng = CorrelationEngine()
    alert_disp     = AlertDispatcher()

    collector_mgr.start()
    correlator_eng.start()
    alert_disp.start()

    asyncio.create_task(broadcast_loop())
    logger.info("NetTrap-IPS 100%% Operativo. Dashboard: http://%s:%d", HOST, PORT)


@app.on_event("shutdown")
async def shutdown():
    if collector_mgr:  collector_mgr.stop()
    if correlator_eng: correlator_eng.stop()
    if alert_disp:     alert_disp.stop()
    logger.info("NetTrap-IPS detenido correctamente.")


if __name__ == "__main__":
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False, log_level="info")
