"""
NetTrap-IPS · Módulos Auxiliares SOC (Diagnóstico, Analítica/Reportes y Radar LAN)
Provee verificación en tiempo real de sensores/permisos de Windows, agregación
estadística con informe exportable imprimible a PDF, y descubrimiento pasivo/ARP
de dispositivos en la red local.
"""

import ctypes
import html
import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from collectors import WindowsFirewallCollector, validate_ip
from config import IS_FROZEN, SUBPROC_FLAGS, get_default_gateway

logger = logging.getLogger("nettrap.tools")

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB / CIFS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8000: "NetTrap SOC",
    8001: "NetTrap Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    9000: "Service Alt",
    27017: "MongoDB",
}

SENSOR_LABELS = {
    "network_traffic": "Red TCP / HTTP",
    "windows_firewall": "Firewall Windows",
    "windows_event_log": "Event Log Windows",
}


# ─────────────────────────────────────────────────────────────────────────────
# 1. Diagnóstico de Sistema y Sensores (Health Check)
# ─────────────────────────────────────────────────────────────────────────────
def _check_is_admin() -> dict:
    """Comprueba si el proceso corre con privilegios elevados de Administrador."""
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else (os.geteuid() == 0)
    except Exception:
        is_admin = False

    if is_admin:
        return {
            "id": "admin",
            "title": "Permisos de Administrador",
            "ok": True,
            "status_label": "LISTO",
            "detail": "Proceso ejecutándose con privilegios elevados (netsh, EventLog y Firewall habilitados).",
            "recommendation": "Listo para bloquear atacantes reales en Windows Defender Firewall.",
        }
    return {
        "id": "admin",
        "title": "Permisos de Administrador",
        "ok": False,
        "status_label": "REQUIERE ATENCIÓN",
        "detail": "Sin elevación UAC: Windows bloquea la lectura de Security.evtx y las reglas netsh.",
        "recommendation": (
            "Cierra NetTrap-IPS desde la bandeja del sistema y ábrelo con clic derecho -> Ejecutar como administrador."
            if IS_FROZEN
            else "Cierra y vuelve a abrir start.bat con clic derecho -> Ejecutar como administrador."
        ),
    }


def _check_firewall_log() -> dict:
    """Verifica pfirewall.log y la política LogDroppedConnections de Windows Firewall."""
    log_path = WindowsFirewallCollector.DEFAULT_LOG
    exists = False
    readable = False
    size_kb = 0.0
    logging_enabled = False

    try:
        exists = log_path.exists()
        if exists:
            size_kb = round(log_path.stat().st_size / 1024.0, 1)
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.read(64)
            readable = True
    except Exception:
        readable = False

    if os.name == "nt":
        try:
            res = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True,
                timeout=4,
                check=False,
                creationflags=SUBPROC_FLAGS,
            )
            out = res.stdout.decode("cp1252", errors="ignore").lower()
            if re.search(r"(?:droppedconnections|descartadas)\s+(?:enable|habilitad|s[ií])", out):
                logging_enabled = True
        except Exception:
            pass

    ok = readable or (exists and logging_enabled)
    if ok:
        extra = f"{size_kb} KB" if readable else "habilitado"
        return {
            "id": "firewall_log",
            "title": "Log de Firewall (pfirewall.log)",
            "ok": True,
            "status_label": "ACTIVO",
            "detail": f"Archivo {log_path} accesible ({extra}). Detección DROP operativa.",
            "recommendation": "Registrará escaneos hacia puertos cerrados (RULE-003).",
        }
    return {
        "id": "firewall_log",
        "title": "Log de Firewall (pfirewall.log)",
        "ok": False,
        "status_label": "INACTIVO / RESTRINGIDO",
        "detail": f"No se pudo leer {log_path} o droppedconnections está deshabilitado.",
        "recommendation": (
            "Ejecuta NetTrap-IPS como Administrador para activar LogDroppedConnections automáticamente."
            if IS_FROZEN
            else "Ejecuta start.bat como Administrador para activar LogDroppedConnections."
        ),
    }


def _check_event_log_4625() -> dict:
    """Verifica acceso al canal Security para lectura de EventID 4625."""
    if os.name != "nt":
        return {
            "id": "event_log",
            "title": "Event Log Windows (4625)",
            "ok": False,
            "status_label": "NO WINDOWS",
            "detail": "Entorno actual no es Windows.",
            "recommendation": "Este sensor requiere host Windows.",
        }
    try:
        res = subprocess.run(
            ["wevtutil", "gli", "Security"],
            capture_output=True,
            timeout=4,
            check=False,
            creationflags=SUBPROC_FLAGS,
        )
        if res.returncode == 0:
            return {
                "id": "event_log",
                "title": "Event Log Windows (4625)",
                "ok": True,
                "status_label": "RESPONDE",
                "detail": "Canal Security.evtx accesible vía wevtutil para detectar fallos de inicio de sesión (4625).",
                "recommendation": "Sensor listo para detectar fuerza bruta SMB y RDP (RULE-001).",
            }
        err_msg = res.stderr.decode("cp1252", errors="ignore").strip() or "Acceso denegado"
        return {
            "id": "event_log",
            "title": "Event Log Windows (4625)",
            "ok": False,
            "status_label": "SIN ACCESO",
            "detail": f"wevtutil Security devolvió código {res.returncode}: {err_msg[:90]}",
            "recommendation": "Ejecuta la consola como Administrador para leer Security.evtx.",
        }
    except Exception as exc:
        return {
            "id": "event_log",
            "title": "Event Log Windows (4625)",
            "ok": False,
            "status_label": "ERROR",
            "detail": f"Error al consultar wevtutil: {exc}",
            "recommendation": "Verifica el servicio Registro de eventos de Windows (EventLog).",
        }


def _check_tshark(tshark_path: str) -> dict:
    """Verifica si Wireshark / TShark está disponible para captura real de paquetes."""
    path_obj = Path(tshark_path)
    which_path = shutil.which("tshark")
    resolved = str(path_obj) if path_obj.exists() else which_path
    if resolved:
        return {
            "id": "tshark",
            "title": "Wireshark / TShark CLI",
            "ok": True,
            "status_label": "INSTALADO",
            "detail": f"Binario encontrado en {resolved}. Captura de tráfico en vivo habilitada.",
            "recommendation": "Cada incidente guardará evidencia .pcap compatible con Wireshark.",
        }
    return {
        "id": "tshark",
        "title": "Wireshark / TShark CLI",
        "ok": False,
        "status_label": "OPCIONAL / NO DETECTADO",
        "detail": f"No encontrado en {tshark_path}. NetTrap generará archivos .pcap base sintéticos.",
        "recommendation": "Instala Wireshark (con TShark y Npcap) para capturas de paquetes en vivo.",
    }


def run_system_diagnostics(collector_mgr, tshark_path: str, host_ip: str, port: int) -> dict:
    """Ejecuta el Health Check completo de permisos, logs de Windows, TShark y sensores."""
    checks = [
        _check_is_admin(),
        _check_firewall_log(),
        _check_event_log_4625(),
        _check_tshark(tshark_path),
    ]
    sources = collector_mgr.status() if collector_mgr else []
    sources_ok = all(s.get("status") == "ACTIVO" for s in sources) if sources else False
    core_ok = all(c["ok"] for c in checks[:3]) and sources_ok

    return {
        "overall_ready": core_ok,
        "overall_status": "LISTO PARA PRODUCCIÓN" if core_ok else "MODO PARCIAL (REVISAR REQUISITOS)",
        "checks": checks,
        "sources": sources,
        "host_ip": host_ip,
        "port": port,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. Analítica SOC y Reporte Exportable (HTML / PDF Imprimible)
# ─────────────────────────────────────────────────────────────────────────────
def compute_analytics(
    alerts: list[dict],
    events: list[dict],
    blocked: list,
    pcap_dir: Path,
    cves_data: list[dict],
) -> dict:
    """Calcula rankings de IPs, puertos más sondeados, reglas y CVEs mitigados."""
    blocked_set = {
        (b["ip"] if isinstance(b, dict) else str(b))
        for b in (blocked or [])
    }

    ip_stats: dict[str, dict] = defaultdict(lambda: {
        "ip": "",
        "alerts": 0,
        "events": 0,
        "last_rule": "-",
        "last_seen": "",
        "is_blocked": False,
    })
    port_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    rule_names: dict[str, str] = {}
    sensor_counts: Counter = Counter()
    cve_hits: Counter = Counter()

    for ev in events or []:
        ip = ev.get("ip_origen")
        if ip:
            st = ip_stats[ip]
            st["ip"] = ip
            st["events"] += 1
            ts = ev.get("timestamp", "")
            if ts > st["last_seen"]:
                st["last_seen"] = ts
        p = ev.get("puerto")
        if isinstance(p, int) and p > 0:
            port_counts[p] += 1

    for al in alerts or []:
        ip = al.get("ip_origen")
        rid = al.get("rule_id") or "IPS"
        rname = al.get("rule_name") or rid
        origen = al.get("origen") or "network_traffic"

        if ip:
            st = ip_stats[ip]
            st["ip"] = ip
            st["alerts"] += 1
            st["last_rule"] = rid
            ts = al.get("timestamp", "")
            if ts > st["last_seen"]:
                st["last_seen"] = ts
            st["is_blocked"] = ip in blocked_set

        rule_counts[rid] += 1
        rule_names[rid] = rname
        sensor_counts[origen] += 1

        ports = al.get("puertos_afectados") or ([al["puerto"]] if al.get("puerto") else [])
        for p in ports:
            try:
                p_int = int(p)
                if p_int > 0:
                    port_counts[p_int] += 1
            except (TypeError, ValueError):
                continue

        for cve in al.get("cve_mitigated") or []:
            cve_hits[cve] += 1

    for ip, st in ip_stats.items():
        st["is_blocked"] = ip in blocked_set

    top_attackers = sorted(
        ip_stats.values(),
        key=lambda x: (x["alerts"], x["events"]),
        reverse=True,
    )[:8]

    top_ports = [
        {
            "port": port,
            "service": PORT_SERVICES.get(port, f"TCP/{port}"),
            "count": count,
        }
        for port, count in port_counts.most_common(8)
    ]

    by_rule = [
        {"rule_id": rid, "rule_name": rule_names.get(rid, rid), "count": cnt}
        for rid, cnt in rule_counts.most_common()
    ]

    by_sensor = [
        {"origen": orig, "label": SENSOR_LABELS.get(orig, orig), "count": cnt}
        for orig, cnt in sensor_counts.most_common()
    ]

    pcap_files = []
    if pcap_dir.exists():
        for p in sorted(pcap_dir.glob("*.pcap"), key=os.path.getmtime, reverse=True):
            try:
                st = p.stat()
                parts = p.stem.split("_")
                ip_part = parts[1] if len(parts) >= 2 else "Desconocida"
                pcap_files.append({
                    "filename": p.name,
                    "ip": ip_part,
                    "size_bytes": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                })
            except Exception:
                continue

    cves_summary = [
        {
            "cve": item["cve"],
            "cvss": item["cvss"],
            "servicio": item["servicio"],
            "norma": item["norma"],
            "hits": cve_hits.get(item["cve"], 0),
        }
        for item in (cves_data or [])
    ]

    return {
        "summary": {
            "total_alerts": len(alerts or []),
            "total_events": len(events or []),
            "total_blocked": len(blocked_set),
            "total_pcaps": len(pcap_files),
            "unique_attackers": sum(1 for s in ip_stats.values() if s["alerts"] > 0),
        },
        "top_attackers": top_attackers,
        "top_ports": top_ports,
        "by_rule": by_rule,
        "by_sensor": by_sensor,
        "cve_hits": cves_summary,
        "recent_pcaps": pcap_files[:10],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def render_executive_report_html(
    analytics: dict,
    host_ip: str,
    port: int,
    diagnostics: dict | None = None,
) -> str:
    """Genera un informe HTML ejecutivo listo para imprimir o guardar como PDF desde el navegador."""
    summary = analytics.get("summary", {})
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    e = html.escape

    attackers_rows = "".join(
        f"""
        <tr>
          <td class="mono bold">{e(item['ip'])}</td>
          <td class="mono">{e(str(item['alerts']))}</td>
          <td class="mono">{e(str(item['events']))}</td>
          <td class="mono">{e(item['last_rule'])}</td>
          <td><span class="pill {'pill-red' if item['is_blocked'] else 'pill-gray'}">{'Bloqueada' if item['is_blocked'] else 'Libre / Histórica'}</span></td>
        </tr>
        """
        for item in analytics.get("top_attackers", [])
    ) or '<tr><td colspan="5" class="empty">Sin IPs agresoras registradas durante esta sesión.</td></tr>'

    ports_rows = "".join(
        f"""
        <tr>
          <td class="mono bold">{e(str(item['port']))}/TCP</td>
          <td>{e(item['service'])}</td>
          <td class="mono">{e(str(item['count']))}</td>
        </tr>
        """
        for item in analytics.get("top_ports", [])
    ) or '<tr><td colspan="3" class="empty">Sin sondeos a puertos registrados aún.</td></tr>'

    cves_rows = "".join(
        f"""
        <tr>
          <td class="mono bold">{e(item['cve'])}</td>
          <td class="mono">CVSS {e(str(item['cvss']))}</td>
          <td>{e(item['servicio'])}</td>
          <td class="mono">{e(str(item['hits']))} alertas</td>
        </tr>
        """
        for item in analytics.get("cve_hits", [])
    )

    pcaps_rows = "".join(
        f"""
        <tr>
          <td class="mono">{e(p['filename'])}</td>
          <td class="mono">{e(p['ip'])}</td>
          <td class="mono">{e(str(p['size_bytes']))} B</td>
        </tr>
        """
        for p in analytics.get("recent_pcaps", [])[:8]
    ) or '<tr><td colspan="3" class="empty">Sin capturas .pcap almacenadas.</td></tr>'

    diag_badge = "LISTO" if (diagnostics and diagnostics.get("overall_ready")) else "VERIFICAR PERMISOS"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Informe Ejecutivo SOC · NetTrap-IPS</title>
  <style>
    @page {{ size: letter; margin: 14mm; }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      color: #0F172A;
      background: #F1F5F9;
      margin: 0;
      padding: 24px;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }}
    .toolbar {{
      max-width: 920px;
      margin: 0 auto 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      background: #0B0D13;
      color: #fff;
      padding: 12px 18px;
      border-radius: 12px;
    }}
    .toolbar button {{
      background: #10B981;
      color: #04140E;
      border: none;
      padding: 9px 16px;
      border-radius: 8px;
      font-weight: 700;
      cursor: pointer;
      font-size: 13px;
    }}
    .toolbar button.sec {{
      background: #1E293B;
      color: #E2E8F0;
    }}
    .sheet {{
      max-width: 920px;
      margin: 0 auto;
      background: #FFFFFF;
      border: 1px solid #CBD5E1;
      border-radius: 14px;
      padding: 28px 32px;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid #10B981;
      padding-bottom: 14px;
      margin-bottom: 20px;
      gap: 16px;
    }}
    .title {{ font-size: 22px; font-weight: 800; margin: 0; color: #0F172A; }}
    .sub {{ font-size: 12.5px; color: #475569; margin-top: 4px; }}
    .meta {{ text-align: right; font-size: 12px; color: #475569; line-height: 1.5; }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 22px;
    }}
    .kpi {{
      border: 1px solid #E2E8F0;
      background: #F8FAFC;
      border-radius: 10px;
      padding: 12px 14px;
    }}
    .kpi-label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; color: #64748B; }}
    .kpi-val {{ font-size: 24px; font-weight: 800; color: #0F172A; margin-top: 4px; }}
    h2 {{
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #0F766E;
      margin: 20px 0 8px;
      border-bottom: 1px solid #E2E8F0;
      padding-bottom: 5px;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 8px; }}
    th, td {{ border-bottom: 1px solid #E2E8F0; padding: 8px 10px; text-align: left; }}
    th {{ background: #F8FAFC; font-size: 11px; text-transform: uppercase; color: #475569; }}
    .mono {{ font-family: Consolas, 'JetBrains Mono', monospace; }}
    .bold {{ font-weight: 700; }}
    .empty {{ text-align: center; color: #64748B; padding: 14px; }}
    .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
    .pill-red {{ background: #FEE2E2; color: #B91C1C; }}
    .pill-gray {{ background: #E2E8F0; color: #334155; }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
    .footer {{
      margin-top: 24px;
      padding-top: 12px;
      border-top: 1px solid #E2E8F0;
      font-size: 11.5px;
      color: #64748B;
      display: flex;
      justify-content: space-between;
    }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      .toolbar {{ display: none; }}
      .sheet {{ border: none; border-radius: 0; padding: 0; max-width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="toolbar">
    <div><strong>NetTrap-IPS</strong> · Vista previa de Informe Ejecutivo SOC</div>
    <div style="display:flex; gap:8px;">
      <button onclick="window.print()">Imprimir / Guardar PDF</button>
      <button class="sec" onclick="window.close()">Cerrar</button>
    </div>
  </div>

  <div class="sheet">
    <div class="header">
      <div>
        <h1 class="title">Informe Ejecutivo de Incidentes SOC · NetTrap-IPS</h1>
        <div class="sub">Superficie Protegida: <span class="mono">{e(host_ip)}:{e(str(port))}</span> · Estado Diagnóstico: <strong>{e(diag_badge)}</strong></div>
      </div>
      <div class="meta">
        <div><strong>Generado:</strong> {e(now_str)}</div>
        <div><strong>Autores:</strong> Margit Barrera, Daniela Bayona, Said Pacheco</div>
        <div>Ingeniería Informática · UNIPAZ</div>
      </div>
    </div>

    <div class="kpis">
      <div class="kpi"><div class="kpi-label">Eventos Analizados</div><div class="kpi-val">{e(str(summary.get('total_events', 0)))}</div></div>
      <div class="kpi"><div class="kpi-label">Ataques Detectados</div><div class="kpi-val">{e(str(summary.get('total_alerts', 0)))}</div></div>
      <div class="kpi"><div class="kpi-label">IPs en Cuarentena</div><div class="kpi-val">{e(str(summary.get('total_blocked', 0)))}</div></div>
      <div class="kpi"><div class="kpi-label">Evidencias .pcap</div><div class="kpi-val">{e(str(summary.get('total_pcaps', 0)))}</div></div>
    </div>

    <div class="grid-2">
      <div>
        <h2>Top IPs Atacantes</h2>
        <table>
          <thead><tr><th>IP</th><th>Alertas</th><th>Eventos</th><th>Última Regla</th><th>Estado</th></tr></thead>
          <tbody>{attackers_rows}</tbody>
        </table>
      </div>
      <div>
        <h2>Puertos Más Sondeados</h2>
        <table>
          <thead><tr><th>Puerto</th><th>Servicio</th><th>Sondeos</th></tr></thead>
          <tbody>{ports_rows}</tbody>
        </table>
      </div>
    </div>

    <h2>Vulnerabilidades Críticas Mitigadas (NIST CVE)</h2>
    <table>
      <thead><tr><th>CVE</th><th>Severidad</th><th>Servicio Protegido</th><th>Incidentes Mitigados</th></tr></thead>
      <tbody>{cves_rows}</tbody>
    </table>

    <h2>Evidencias Forenses Capturadas (.pcap)</h2>
    <table>
      <thead><tr><th>Archivo</th><th>IP Relacionada</th><th>Tamaño</th></tr></thead>
      <tbody>{pcaps_rows}</tbody>
    </table>

    <div class="footer">
      <span>NetTrap-IPS · Sistema de Detección y Prevención de Intrusiones</span>
      <span>ISO/IEC 27033 · NIST SP 800-218 · OWASP ASVS</span>
    </div>
  </div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# 3. Radar de Red Local (Equipos en la LAN)
# ─────────────────────────────────────────────────────────────────────────────
def _get_default_gateway() -> str | None:
    """Detecta la puerta de enlace por defecto en Windows mediante config.get_default_gateway."""
    return get_default_gateway()


def _nudge_subnet_arp(local_ip: str) -> str:
    """Envía datagramas UDP vacíos para refrescar la tabla ARP local de forma rápida."""
    try:
        ip_obj = ipaddress.IPv4Address(local_ip)
        if ip_obj.is_loopback:
            return "127.0.0.0/24"
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    except Exception:
        return "192.168.1.0/24"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for host in net.hosts():
            h_str = str(host)
            if h_str == local_ip:
                continue
            try:
                sock.sendto(b"", (h_str, 9))
            except Exception:
                continue
    finally:
        sock.close()

    time.sleep(0.35)
    return str(net)


def _resolve_hostname_quick(ip: str) -> str:
    """Resuelve el nombre de host en red local de forma acotada."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.split(".")[0] if name else ""
    except Exception:
        return ""


def scan_local_network(local_host_ip: str, blocked_ips: list, whitelist: list[str] | None = None) -> dict:
    """Descubre equipos activos en la subred local combinando refresco ARP y arp -a."""
    subnet = _nudge_subnet_arp(local_host_ip)
    gateway = _get_default_gateway()
    blocked_set = {(b["ip"] if isinstance(b, dict) else str(b)) for b in (blocked_ips or [])}
    wl_set = set(whitelist or [])

    try:
        target_net = ipaddress.IPv4Network(subnet, strict=False)
    except Exception:
        target_net = None

    discovered: dict[str, dict] = {}
    if validate_ip(local_host_ip):
        discovered[local_host_ip] = {
            "ip": local_host_ip,
            "mac": "Interfaz Local",
            "arp_type": "local",
            "role": "Este Equipo (NetTrap-IPS)",
            "hostname": socket.gethostname(),
            "is_self": True,
            "is_gateway": False,
            "is_blocked": False,
            "is_whitelisted": local_host_ip in wl_set,
        }

    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, timeout=4, check=False, creationflags=SUBPROC_FLAGS)
        raw = res.stdout or b""
        text = raw.decode("cp850", errors="ignore")
        current_iface = None

        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            m_iface = re.search(r"(?:Interfaz|Interface):\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", s, re.IGNORECASE)
            if m_iface:
                current_iface = m_iface.group(1)
                continue

            parts = s.split()
            if len(parts) < 3:
                continue
            ip_str = validate_ip(parts[0])
            mac_str = parts[1].lower()
            arp_type = parts[2].lower()

            if not ip_str or mac_str == "ff-ff-ff-ff-ff-ff":
                continue

            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                if ip_obj.is_multicast or ip_obj.is_unspecified or ip_str.endswith(".255"):
                    continue
                if target_net and ip_obj not in target_net and current_iface != local_host_ip:
                    continue
            except Exception:
                continue

            if ip_str not in discovered:
                is_gw = (ip_str == gateway)
                role = "Router / Gateway" if is_gw else "Equipo en LAN"
                discovered[ip_str] = {
                    "ip": ip_str,
                    "mac": mac_str,
                    "arp_type": "dinámico" if "din" in arp_type or "dyn" in arp_type else "estático",
                    "role": role,
                    "hostname": "",
                    "is_self": False,
                    "is_gateway": is_gw,
                    "is_blocked": ip_str in blocked_set,
                    "is_whitelisted": ip_str in wl_set,
                }
    except Exception as exc:
        logger.debug("Error leyendo tabla ARP: %s", exc)

    other_ips = [ip for ip, info in discovered.items() if not info["is_self"]]
    if other_ips:
        with ThreadPoolExecutor(max_workers=12) as pool:
            fut_map = {pool.submit(_resolve_hostname_quick, ip): ip for ip in other_ips[:24]}
            try:
                for fut in as_completed(fut_map, timeout=1.0):
                    ip_k = fut_map[fut]
                    try:
                        hn = fut.result()
                        if hn:
                            discovered[ip_k]["hostname"] = hn
                    except Exception:
                        pass
            except Exception:
                pass

    hosts_sorted = sorted(
        discovered.values(),
        key=lambda h: (
            0 if h["is_self"] else (1 if h["is_gateway"] else 2),
            tuple(int(x) for x in h["ip"].split(".")) if "." in h["ip"] else (0,),
        ),
    )

    return {
        "subnet": subnet,
        "host_ip": local_host_ip,
        "gateway": gateway or "No detectado",
        "total_hosts": len(hosts_sorted),
        "hosts": hosts_sorted,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
