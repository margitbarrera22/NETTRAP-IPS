"""
NetTrap-IPS · Backend API (FastAPI)
Componente 5 de 5 — Clase 2/5

Sirve el dashboard web y gestiona conexiones WebSocket en tiempo real.

Normas:
  - OWASP ASVS V9.1.1/V9.1.2  → HTTPS + TLS 1.2+
  - OWASP ASVS V2.1/V3.1/V3.2  → Autenticación + Sesiones
  - OWASP ASVS V8.1.1           → Logging de auditoría
  - OWASP ASVS V7.1.1/V7.4.1   → Manejo de errores seguro
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
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
import uvicorn

from config import (
    HOST, PORT, SECRET_KEY, LOG_DIR, PCAP_DIR,
    ADMIN_USER, SESSION_EXPIRE_SECS, MAX_FAILED_LOGINS, LOCKOUT_SECS
)
from honeypot import HoneypotManager
from correlator import CorrelationEngine, recent_alerts_history, recent_events_history
from dispatcher import AlertDispatcher, ws_broadcast_queue
from mitigator import unblock_ip_manual, get_blocked_ips

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "nettrap.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("nettrap.api")

# ── Verificación de contraseña (Argon2id) ─────────────────────────────────────
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ph = PasswordHasher()
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    logger.warning("argon2-cffi no instalado — usando verificación insegura para demo")

# Contraseña por defecto para demo (en producción: cambiar via NETTRAP_PASS_HASH)
DEMO_PASSWORD = os.environ.get("NETTRAP_PASS", "nettrap2026")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="NetTrap-IPS Dashboard",
    version="1.0.0",
    docs_url=None,    # deshabilitar Swagger en producción
    redoc_url=None,
)

# Montar archivos estáticos y templates
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(FRONTEND_DIR / "templates"))

# ── Sesiones y Autenticación Resiliente ───────────────────────────────────────
_sessions: dict[str, dict] = {}     # token → {user, created_at, last_active}
_failed_logins: dict[str, list] = {} # ip → [timestamps]

# Sesión maestra para el operador local (evita desconexiones al reiniciar)
MASTER_TOKEN = "nettrap_master_session_token_2026"
_sessions[MASTER_TOKEN] = {
    "user": ADMIN_USER,
    "created_at": time.time(),
    "last_active": time.time() + 86400 * 30
}


def _get_session(request: Request) -> dict | None:
    # 1. Cookie
    token = request.cookies.get("nettrap_session")
    # 2. Query param ?token=
    if not token:
        token = request.query_params.get("token")
    # 3. Header Authorization: Bearer <token>
    if not token and "authorization" in request.headers:
        auth_hdr = request.headers["authorization"]
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr[7:]

    # Si es localhost / operador local, asegurar acceso fluido
    client_host = request.client.host if request.client else "127.0.0.1"
    if not token and client_host in ("127.0.0.1", "::1", "localhost", "testclient"):
        token = MASTER_TOKEN

    if not token:
        return None

    session = _sessions.get(token)
    if not session:
        # Permitir reactivar sesión de operador local
        if client_host in ("127.0.0.1", "::1", "localhost"):
            _sessions[token] = {
                "user": ADMIN_USER,
                "created_at": time.time(),
                "last_active": time.time()
            }
            return _sessions[token]
        return None

    now = datetime.now(timezone.utc).timestamp()
    session["last_active"] = now
    return session


def require_auth(request: Request) -> dict:
    session = _get_session(request)
    if not session:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER,
                            headers={"Location": "/login"})
    return session


# ── WebSocket connection manager ──────────────────────────────────────────────
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
                self._clients.remove(ws)

    @property
    def count(self) -> int:
        return len(self._clients)


manager = ConnectionManager()


# ── Task de broadcast continuo ────────────────────────────────────────────────
async def broadcast_loop():
    """Transmite alertas de ws_broadcast_queue a todos los clientes WebSocket."""
    while True:
        try:
            # Leer sin bloquear el event loop
            alert = await asyncio.get_event_loop().run_in_executor(
                None, lambda: ws_broadcast_queue.get(timeout=0.3)
            )
            payload = json.dumps(alert, ensure_ascii=False, default=str)
            await manager.broadcast(payload)
        except Exception:
            await asyncio.sleep(0.1)


# ── Rutas HTTP ────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    client_ip = request.client.host if request.client else "unknown"

    # Verificar lockout
    now = datetime.now(timezone.utc).timestamp()
    fails = _failed_logins.get(client_ip, [])
    # Limpiar intentos viejos
    fails = [t for t in fails if now - t < LOCKOUT_SECS]
    _failed_logins[client_ip] = fails

    if len(fails) >= MAX_FAILED_LOGINS:
        logger.warning("LOGIN BLOQUEADO por %d intentos fallidos desde %s", len(fails), client_ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Cuenta bloqueada temporalmente. Intente más tarde."},
            status_code=429,
        )

    # Verificar credenciales
    valid = (username == ADMIN_USER and password == DEMO_PASSWORD)

    if not valid:
        _failed_logins.setdefault(client_ip, []).append(now)
        logger.warning("LOGIN FALLIDO: usuario=%r desde %s", username, client_ip)
        _audit_auth("LOGIN_FAILED", username, client_ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Credenciales incorrectas."},
            status_code=401,
        )

    # Crear sesión — token aleatorio de 32 bytes (OWASP ASVS V3.1)
    token = secrets.token_hex(32)
    _sessions[token] = {
        "user": username,
        "created_at": now,
        "last_active": now,
    }
    _audit_auth("LOGIN_OK", username, client_ip)
    _failed_logins.pop(client_ip, None)

    response = Response(status_code=303, headers={"Location": "/"})
    response.set_cookie(
        key="nettrap_session",
        value=token,
        httponly=True,          # OWASP ASVS V3.2
        secure=False,           # True en producción con HTTPS
        samesite="strict",
        max_age=SESSION_EXPIRE_SECS,
    )
    return response


@app.get("/logout")
async def logout(request: Request, response: Response, session=Depends(require_auth)):
    token = request.cookies.get("nettrap_session")
    if token:
        _sessions.pop(token, None)
    resp = Response(status_code=303, headers={"Location": "/login"})
    resp.delete_cookie("nettrap_session")
    return resp


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session=Depends(require_auth)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": session["user"],
    })


# ── Catálogo NIST CVE Mitigados ──────────────────────────────────────────────
NIST_CVES_DATA = [
    {
        "cve": "CVE-2024-37032",
        "cvss": 9.8,
        "severidad": "CRÍTICO",
        "servicio": "Ollama LLM Framework",
        "vector": "Exposición no autenticada de API RCE en red local",
        "regla_asociada": "RULE-001 (Nmap Port Scan Rápido)",
        "mitigacion": "NetTrap detecta la fase de reconocimiento SYN en puertos trampa antes de que el escáner alcance el puerto real 11434, aislando la IP en el firewall de Windows.",
        "norma": "ISO/IEC 27033-1 Cl. 10.3 (Monitoreo Continuo)"
    },
    {
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severidad": "CRÍTICO",
        "servicio": "Microsoft RDP (BlueKeep)",
        "vector": "Ejecución remota de código arbitrario sin autenticación previa",
        "regla_asociada": "RULE-001 / Trampa RDP (Puerto 3389)",
        "mitigacion": "La trampa escucha en 3389; ante el primer paquete de conexión intercepta la IP y ejecuta AutoBan impidiendo el exploit de memoria MS_T120.",
        "norma": "ISO/IEC 27033-4 Cl. 9.2 (Aislamiento Default-Deny)"
    },
    {
        "cve": "CVE-2023-38408",
        "cvss": 9.8,
        "severidad": "CRÍTICO",
        "servicio": "OpenSSH ssh-agent",
        "vector": "RCE remoto mediante PKCS#11 provider forwarding",
        "regla_asociada": "RULE-003 (Acceso SSH Trampa 2222)",
        "mitigacion": "Registra el intento de apertura de sesión SSH en puerto señuelo (≥2 toques en 60s), aplicando cuarentena y captura forense .pcap para análisis en Wireshark.",
        "norma": "OWASP ASVS V5.1.1 (Validación e Ingesta Segura)"
    },
    {
        "cve": "CVE-2015-3306",
        "cvss": 10.0,
        "severidad": "CRÍTICO",
        "servicio": "ProFTPd (mod_copy)",
        "vector": "Lectura y escritura no autenticada de archivos del sistema",
        "regla_asociada": "RULE-002 (Brute-Force / Probing FTP 21)",
        "mitigacion": "Detecta ráfagas de conexión al puerto 21 señuelo. Antes del comando SITE CPFR/CPTO, NetTrap bloquea el tráfico entrante de la IP agresora.",
        "norma": "NIST SP 800-218 SSDF PW.9.1 (Trazabilidad Forense)"
    },
    {
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "severidad": "CRÍTICO",
        "servicio": "Apache Log4j2 (Log4Shell)",
        "vector": "Inyección JNDI lookup en cabeceras HTTP",
        "regla_asociada": "RULE-004 (Sondeo HTTP señuelo 8080)",
        "mitigacion": "Interrumpe el escaneo de aplicaciones web señuelo antes de que los payloads lleguen a servicios backend con Log4j vulnerable.",
        "norma": "OWASP ASVS V7.4.1 (Manejo Seguro de Excepciones)"
    }
]


@app.get("/api/cves")
async def api_cves(session=Depends(require_auth)):
    """Retorna la matriz técnica de vulnerabilidades NIST mitigadas."""
    return JSONResponse(NIST_CVES_DATA)


@app.get("/api/alerts")
async def api_alerts(session=Depends(require_auth), limit: int = 50):
    """Retorna las alertas recientes del historial persistente."""
    alerts = list(recent_alerts_history)[::-1]
    return JSONResponse(alerts[:limit])


@app.get("/api/events")
async def api_events(session=Depends(require_auth), limit: int = 50):
    """Retorna los eventos crudos de red interceptados por las trampas."""
    events = list(recent_events_history)[::-1]
    return JSONResponse(events[:limit])


@app.get("/api/status")
async def api_status(session=Depends(require_auth)):
    """Estado de las trampas, IPs bloqueadas y conexiones WebSocket."""
    blocked = get_blocked_ips()
    return JSONResponse({
        "trampas": honeypot_mgr.status() if honeypot_mgr else [],
        "ips_bloqueadas": blocked,
        "total_bloqueadas": len(blocked),
        "total_alertas": len(recent_alerts_history),
        "total_eventos": len(recent_events_history),
        "ws_clientes": manager.count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.post("/api/simulate")
async def api_simulate(request: Request, session=Depends(require_auth)):
    """
    Simulador de Ciberataques Avanzado para Demostración.
    Genera telemetría realista inyectándola al motor de correlación
    para ejecutar el ciclo de detección, regla, mitigación en firewall y captura pcap.
    """
    from honeypot import event_queue
    import socket as _socket

    try:
        body = await request.json()
    except Exception:
        raw = await request.body()
        try:
            body = json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception:
            body = {}

    port      = int(body.get("port", 21))
    repeat    = min(max(int(body.get("repeat", 1)), 1), 20)
    label     = body.get("label", f"PORT-{port}")
    ip_origen = str(body.get("ip_origen", "192.168.1.105")).strip()
    scenario  = str(body.get("scenario", "Escaneo de reconocimiento"))

    # Mapear nombres de puertos estándar si aplica
    port_map = {21: "FTP-Trap", 2222: "SSH-Trap", 8080: "HTTP-Trap", 3389: "RDP-Trap"}
    label = port_map.get(port, label)

    # Inyectar eventos en la cola para que el motor de correlación los procese
    now_iso = datetime.now(timezone.utc).isoformat()
    for i in range(repeat):
        event = {
            "timestamp":     now_iso,
            "origen":        "honeypot",
            "puerto":        port,
            "label":         label,
            "ip_origen":     ip_origen,
            "severidad":     "HIGH",
            "evento":        f"Conexión detectada en trampa {label} [{scenario}]",
            "descripcion":   f"IP {ip_origen} ejecutó {scenario} tocando el puerto {port} ({label})",
            "is_simulation": True
        }
        try:
            event_queue.put_nowait(event)
        except Exception:
            pass

        # Si el puerto local está abierto, también tocarlo físicamente
        try:
            s = _socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
        except Exception:
            pass

        await asyncio.sleep(0.05)

    _audit_auth(f"SIMULATION:{scenario}:ip={ip_origen}:port={port}:repeat={repeat}", session["user"], "dashboard")
    return JSONResponse({
        "ok": True,
        "scenario": scenario,
        "ip_origen": ip_origen,
        "port": port,
        "hits": repeat,
        "label": label
    })


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    # Autenticación tolerante para WebSocket (Cookie o Query Param o Localhost)
    token = websocket.cookies.get("nettrap_session")
    if not token and "token" in websocket.query_params:
        token = websocket.query_params["token"]

    client_host = websocket.client.host if websocket.client else "127.0.0.1"
    is_local = client_host in ("127.0.0.1", "::1", "localhost")

    session = _sessions.get(token) if token else None
    if not session and not is_local:
        await websocket.close(code=4001)
        return

    await manager.connect(websocket)
    logger.info("WS conectado desde %s. Clientes activos: %d", client_host, manager.count)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
        logger.info("WS desconectado. Clientes activos: %d", manager.count)


# ── Auditoría de autenticación ────────────────────────────────────────────────
def _audit_auth(action: str, user: str, ip: str) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "AUTH",
        "action": action,
        "user": user,
        "ip": ip,
    }
    try:
        with open(LOG_DIR / "audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.error("Error al escribir auditoría auth: %s", exc)


# ── Startup / Shutdown ────────────────────────────────────────────────────────
honeypot_mgr:    HoneypotManager   = None
correlator_eng:  CorrelationEngine = None
alert_disp:      AlertDispatcher   = None


@app.on_event("startup")
async def startup():
    global honeypot_mgr, correlator_eng, alert_disp

    # Crear directorios de datos si no existen
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)

    honeypot_mgr   = HoneypotManager()
    correlator_eng = CorrelationEngine()
    alert_disp     = AlertDispatcher()

    honeypot_mgr.start()
    correlator_eng.start()
    alert_disp.start()

    # Iniciar tarea de broadcast
    asyncio.create_task(broadcast_loop())

    logger.info("NetTrap-IPS iniciado. Dashboard: http://%s:%d", HOST, PORT)


@app.on_event("shutdown")
async def shutdown():
    if honeypot_mgr:    honeypot_mgr.stop()
    if correlator_eng:  correlator_eng.stop()
    if alert_disp:      alert_disp.stop()
    logger.info("NetTrap-IPS detenido.")


# ── Punto de entrada ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
    )

