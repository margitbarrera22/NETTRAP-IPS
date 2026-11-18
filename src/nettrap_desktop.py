"""
NetTrap-IPS · Lanzador Nativo de Escritorio y Bandeja del Sistema (Windows)
Mantiene el servidor FastAPI/Uvicorn activo en segundo plano sin consolas ni comandos,
configura Firewall/EventLog automáticamente y abre el Dashboard SOC en el navegador.
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

# ── Resolución de rutas de backend (fuente o PyInstaller _MEIPASS) ───────────
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    _BASE_SRC = Path(sys._MEIPASS)
else:
    _BASE_SRC = Path(__file__).resolve().parent

_BACKEND_DIR = _BASE_SRC / "backend"
if _BACKEND_DIR.exists() and str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))
elif str(_BASE_SRC) not in sys.path:
    sys.path.insert(0, str(_BASE_SRC))

import config  # noqa: E402


def _ensure_stdio(log_dir: Path) -> None:
    """En modo --noconsole (PyInstaller), sys.stdout/sys.stderr valen None; redirige a archivo."""
    if sys.stdout is None or sys.stderr is None:
        log_dir.mkdir(parents=True, exist_ok=True)
        stream = open(log_dir / "runtime_stdio.log", "a", encoding="utf-8", buffering=1)
        if sys.stdout is None:
            sys.stdout = stream
        if sys.stderr is None:
            sys.stderr = stream


def is_admin() -> bool:
    """Retorna True si el proceso actual corre con privilegios elevados de Administrador."""
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _probe_nettrap_health(port: int, timeout: float = 0.6) -> bool:
    """Verifica si ya existe un servidor NetTrap-IPS respondiendo en 127.0.0.1:<port>."""
    conn = None
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request("GET", "/api/health")
        resp = conn.getresponse()
        if resp.status != 200:
            return False
        payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        return payload.get("app") == "NetTrap-IPS" and payload.get("status") == "ok"
    except Exception:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _find_running_port(preferred: int = 8000) -> int | None:
    """Busca una instancia viva de NetTrap-IPS en los puertos habituales."""
    candidates = []
    for p in (preferred, 8000, 8001):
        if p not in candidates:
            candidates.append(p)
    for port in candidates:
        if _probe_nettrap_health(port):
            return port
    return None


def _is_port_free(port: int) -> bool:
    """Comprueba si es posible enlazar 0.0.0.0:<port>."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _pick_available_port(preferred: int = 8000) -> int:
    """Selecciona el puerto de escucha disponible (8000 o fallback 8001..8010)."""
    candidates = [preferred] + [p for p in (8000, 8001, 8002, 8003, 8088) if p != preferred]
    for port in candidates:
        if _is_port_free(port):
            return port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 0))
    free_port = int(sock.getsockname()[1])
    sock.close()
    return free_port


def _acquire_single_instance_mutex():
    """Adquiere un Mutex de Windows para evitar carreras entre arranques simultáneos."""
    if os.name != "nt":
        return None, False
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, "Local\\NetTrapIPS_SingleInstance_Mutex")
    already_exists = (kernel32.GetLastError() == 183)  # ERROR_ALREADY_EXISTS
    return handle, already_exists


def _release_mutex(handle) -> None:
    if os.name == "nt" and handle:
        import ctypes
        try:
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass


def _request_uac_elevation(raw_argv: list[str]) -> str:
    """
    Reintenta ejecutar el proceso como Administrador mediante UAC.
    Retorna: 'elevated' (lanzado hijo elevado), 'continue_limited' o 'abort'.
    """
    import ctypes

    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = subprocess.list2cmdline(raw_argv)
        workdir = str(Path(sys.executable).parent)
    else:
        exe = sys.executable
        params = subprocess.list2cmdline([str(Path(__file__).resolve()), *raw_argv])
        workdir = str(Path(__file__).resolve().parent)

    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
    if rc > 32:
        return "elevated"

    # Usuario rechazó el diálogo UAC -> ofrecer modo limitado o cancelar
    MB_YESNO = 0x00000004
    MB_ICONWARNING = 0x00000030
    IDYES = 6
    choice = ctypes.windll.user32.MessageBoxW(
        None,
        (
            "NetTrap-IPS requiere permisos de Administrador para leer el Visor de Eventos "
            "(EventID 4625) y aplicar bloqueos automáticos en Windows Defender Firewall.\n\n"
            "¿Deseas iniciar de todas formas en modo limitado (solo red local y simulador)?"
        ),
        "NetTrap-IPS · Permisos de Administrador",
        MB_YESNO | MB_ICONWARNING,
    )
    return "continue_limited" if choice == IDYES else "abort"


def _configure_windows_host(port: int) -> None:
    """Configura reglas entrantes del Firewall, logging pfirewall.log y auditoría de logon."""
    if os.name != "nt" or not is_admin():
        return

    cmds = [
        ["netsh", "advfirewall", "firewall", "delete", "rule", "name=NetTrap-Inbound-SOC"],
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=NetTrap-Inbound-SOC", "dir=in", "action=allow",
            "protocol=TCP", f"localport={port},8080", "enable=yes",
        ],
        ["netsh", "advfirewall", "firewall", "delete", "rule", "name=NetTrap-Inbound-ICMP"],
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=NetTrap-Inbound-ICMP", "dir=in", "action=allow",
            "protocol=icmpv4:8,any", "enable=yes",
        ],
        [
            "netsh", "advfirewall", "set", "allprofiles", "logging",
            "filename", r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log",
        ],
        ["netsh", "advfirewall", "set", "allprofiles", "logging", "maxfilesize", "4096"],
        ["netsh", "advfirewall", "set", "allprofiles", "logging", "droppedconnections", "enable"],
        ["auditpol", "/set", "/subcategory:Logon", "/success:enable", "/failure:enable"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=6,
                check=False,
                creationflags=config.SUBPROC_FLAGS,
            )
        except Exception:
            pass


# ── Gestión de Inicio Automático con Windows ─────────────────────────────────
TASK_NAME = "NetTrap-IPS Server"
RUN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_REG_NAME = "NetTrapIPS"


def _autostart_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --autostart'
    return f'"{sys.executable}" "{Path(__file__).resolve()}" --autostart'


def is_autostart_enabled() -> bool:
    """Verifica si el inicio automático (Tarea Programada o HKCU Run) está activo."""
    if os.name != "nt":
        return False
    try:
        res = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_NAME],
            capture_output=True,
            timeout=4,
            check=False,
            creationflags=config.SUBPROC_FLAGS,
        )
        if res.returncode == 0:
            return True
    except Exception:
        pass

    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, RUN_REG_NAME)
            return True
    except Exception:
        return False


def set_autostart(enabled: bool) -> bool:
    """Activa o desactiva el arranque automático silencioso al iniciar Windows."""
    if os.name != "nt":
        return False
    cmd_str = _autostart_command()

    if enabled:
        if is_admin():
            res = subprocess.run(
                [
                    "schtasks", "/Create",
                    "/TN", TASK_NAME,
                    "/TR", cmd_str,
                    "/SC", "ONLOGON",
                    "/RL", "HIGHEST",
                    "/F",
                ],
                capture_output=True,
                timeout=6,
                check=False,
                creationflags=config.SUBPROC_FLAGS,
            )
            if res.returncode == 0:
                return True
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, RUN_REG_NAME, 0, winreg.REG_SZ, cmd_str)
            return True
        except Exception:
            return False
    else:
        ok = False
        try:
            res = subprocess.run(
                ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                capture_output=True,
                timeout=5,
                check=False,
                creationflags=config.SUBPROC_FLAGS,
            )
            if res.returncode == 0:
                ok = True
        except Exception:
            pass
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, RUN_REG_NAME)
            ok = True
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return ok


def _cleanup_temp_firewall_rules() -> int:
    """Elimina todas las reglas NETTRAP-BLOCK-* de Windows Defender Firewall."""
    if os.name != "nt":
        return 0
    removed = 0
    try:
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True,
            timeout=8,
            check=False,
            creationflags=config.SUBPROC_FLAGS,
        )
        text = (res.stdout or b"").decode("cp1252", errors="ignore")
        seen = set()
        for line in text.splitlines():
            if "NETTRAP-BLOCK-" in line:
                idx = line.find("NETTRAP-BLOCK-")
                rule_name = line[idx:].strip()
                if rule_name and rule_name not in seen:
                    seen.add(rule_name)
                    del_res = subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                        capture_output=True,
                        timeout=4,
                        check=False,
                        creationflags=config.SUBPROC_FLAGS,
                    )
                    if del_res.returncode == 0:
                        removed += 1
    except Exception:
        pass
    return removed


def _load_tray_image():
    """Carga el icono de NetTrap o lo dibuja dinámicamente con Pillow."""
    from PIL import Image, ImageDraw

    candidates = [
        _BASE_SRC / "installer" / "nettrap.ico",
        _BASE_SRC.parent / "installer" / "nettrap.ico",
        _BASE_SRC / "nettrap.ico",
    ]
    for p in candidates:
        if p.exists():
            try:
                return Image.open(p).convert("RGBA")
            except Exception:
                pass

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([4, 4, 60, 60], radius=14, fill=(11, 13, 19, 255), outline=(16, 185, 129, 255), width=3)
    pts = [(32, 12), (49, 18), (47, 36), (32, 53), (17, 36), (15, 18)]
    draw.polygon(pts, fill=(16, 185, 129, 60), outline=(0, 229, 153, 255))
    draw.ellipse([27, 27, 37, 37], fill=(0, 229, 153, 255))
    return img


def _copy_text_to_clipboard(text: str) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["clip"],
                input=text.encode("utf-8"),
                capture_output=True,
                timeout=3,
                check=False,
                creationflags=config.SUBPROC_FLAGS,
            )
            return
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="NetTrap-IPS Desktop & Background Server")
    parser.add_argument("--autostart", action="store_true", help="Inicia en segundo plano sin abrir el navegador")
    parser.add_argument("--no-browser", action="store_true", help="No abrir el navegador automáticamente")
    parser.add_argument("--no-tray", action="store_true", help="Ejecutar sin icono de bandeja (modo consola/headless)")
    parser.add_argument("--no-elevate", action="store_true", help="No solicitar elevación UAC automáticamente")
    parser.add_argument("--isolated", action="store_true", help="Ejecutar instancia aislada en el puerto indicado (pruebas)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("NETTRAP_PORT", "8000")), help="Puerto TCP del servidor")
    parser.add_argument("--data-dir", type=str, default="", help="Directorio personalizado para logs y pcaps")
    args, _unknown = parser.parse_known_args()

    if args.data_dir:
        os.environ["NETTRAP_DATA_DIR"] = args.data_dir
        config.DATA_DIR = Path(args.data_dir)
        config.LOG_DIR = config.DATA_DIR / "logs"
        config.PCAP_DIR = config.DATA_DIR / "pcap"

    _ensure_stdio(config.LOG_DIR)

    # 1. Si el servidor ya está activo, solo abrir Dashboard (sin duplicar ni pedir UAC)
    if not args.isolated:
        running_port = _find_running_port(args.port)
        if running_port is not None:
            if not args.autostart and not args.no_browser:
                webbrowser.open(f"http://127.0.0.1:{running_port}")
            return 0

    # 2. Solicitar elevación UAC si es necesario antes de tomar el Mutex
    if os.name == "nt" and not args.no_elevate and not is_admin():
        status = _request_uac_elevation(sys.argv[1:])
        if status in ("elevated", "abort"):
            return 0

    # 3. Evitar doble arranque simultáneo con Mutex de Windows
    mutex_handle = None
    if not args.isolated:
        mutex_handle, already_exists = _acquire_single_instance_mutex()
        if already_exists:
            for _ in range(16):
                rp = _find_running_port(args.port)
                if rp is not None:
                    if not args.autostart and not args.no_browser:
                        webbrowser.open(f"http://127.0.0.1:{rp}")
                    _release_mutex(mutex_handle)
                    return 0
                time.sleep(0.35)
            _release_mutex(mutex_handle)
            return 0

    try:
        # 4. Seleccionar puerto y configurar entorno Windows
        chosen_port = _pick_available_port(args.port)
        os.environ["NETTRAP_PORT"] = str(chosen_port)
        config.PORT = chosen_port

        _configure_windows_host(chosen_port)

        # 5. Importar FastAPI app y arrancar Uvicorn embebido en segundo plano
        import uvicorn
        import main as backend_main

        logger = logging.getLogger("nettrap.desktop")
        logger.info("Iniciando NetTrap-IPS Desktop en http://127.0.0.1:%d (Admin=%s)", chosen_port, is_admin())

        uv_config = uvicorn.Config(
            backend_main.app,
            host=config.HOST,
            port=chosen_port,
            reload=False,
            log_level="info",
            log_config=None,
            access_log=False,
        )
        uv_server = uvicorn.Server(uv_config)

        server_thread = threading.Thread(target=uv_server.run, daemon=True, name="NetTrap-Uvicorn")
        server_thread.start()

        # Esperar hasta que /api/health responda OK
        server_ready = False
        for _ in range(60):
            if _probe_nettrap_health(chosen_port, timeout=0.4):
                server_ready = True
                break
            if not server_thread.is_alive():
                break
            time.sleep(0.25)

        dashboard_url = f"http://127.0.0.1:{chosen_port}"
        lan_url = f"http://{config.LOCAL_HOST_IP}:{chosen_port}"

        if server_ready and not args.autostart and not args.no_browser:
            webbrowser.open(dashboard_url)

        if args.no_tray:
            try:
                while server_thread.is_alive():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                uv_server.should_exit = True
                server_thread.join(timeout=5)
            return 0

        # 6. Icono persistente en la Bandeja del Sistema (System Tray)
        import pystray

        restart_flag = {"requested": False}

        def on_open_dashboard(icon, item):
            webbrowser.open(dashboard_url)

        def on_copy_lan_url(icon, item):
            _copy_text_to_clipboard(lan_url)
            try:
                icon.notify(f"URL de red local copiada: {lan_url}", "NetTrap-IPS")
            except Exception:
                pass

        def on_open_data(icon, item):
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                os.startfile(str(config.DATA_DIR))

        def on_toggle_autostart(icon, item):
            new_state = not is_autostart_enabled()
            ok = set_autostart(new_state)
            try:
                if ok:
                    msg = (
                        "Inicio automático con Windows ACTIVADO."
                        if new_state
                        else "Inicio automático con Windows DESACTIVADO."
                    )
                else:
                    msg = "No se pudo cambiar el inicio automático (requiere permisos de Administrador)."
                icon.notify(msg, "NetTrap-IPS")
                icon.update_menu()
            except Exception:
                pass

        def on_clean_firewall(icon, item):
            count = _cleanup_temp_firewall_rules()
            try:
                icon.notify(f"Reglas temporales NETTRAP eliminadas: {count}", "NetTrap-IPS Firewall")
            except Exception:
                pass

        def on_restart(icon, item):
            restart_flag["requested"] = True
            uv_server.should_exit = True
            icon.stop()

        def on_exit(icon, item):
            uv_server.should_exit = True
            icon.stop()

        mode_label = "Administrador (Protección Total)" if is_admin() else "Modo Limitado (Sin UAC)"
        menu = pystray.Menu(
            pystray.MenuItem(f"NetTrap-IPS Activo · {lan_url}", lambda i, it: None, enabled=False),
            pystray.MenuItem(mode_label, lambda i, it: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Abrir Dashboard SOC", on_open_dashboard, default=True),
            pystray.MenuItem(f"Copiar IP de Red ({lan_url})", on_copy_lan_url),
            pystray.MenuItem("Abrir Carpeta de Evidencias (.pcap y logs)", on_open_data),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Iniciar automáticamente con Windows",
                on_toggle_autostart,
                checked=lambda item: is_autostart_enabled(),
            ),
            pystray.MenuItem("Limpiar Reglas Temporales de Firewall", on_clean_firewall),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Reiniciar Servidor", on_restart),
            pystray.MenuItem("Detener Servidor y Salir", on_exit),
        )

        tray_icon = pystray.Icon(
            "NetTrap-IPS",
            _load_tray_image(),
            f"NetTrap-IPS SIEM/IPS · Activo en {dashboard_url}",
            menu=menu,
        )

        def _after_tray_ready(icon):
            icon.visible = True
            if args.autostart:
                try:
                    icon.notify(
                        f"Servidor defensivo activo en segundo plano ({dashboard_url})",
                        "NetTrap-IPS Iniciado",
                    )
                except Exception:
                    pass

        tray_icon.run(setup=_after_tray_ready)

        # Apagado ordenado del servidor Uvicorn
        uv_server.should_exit = True
        server_thread.join(timeout=5)
        _release_mutex(mutex_handle)
        mutex_handle = None

        if restart_flag["requested"]:
            relaunch_args = ["--no-browser"]
            if args.no_elevate:
                relaunch_args.append("--no-elevate")
            if getattr(sys, "frozen", False):
                subprocess.Popen([sys.executable, *relaunch_args], close_fds=True, creationflags=config.SUBPROC_FLAGS)
            else:
                subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *relaunch_args], close_fds=True, creationflags=config.SUBPROC_FLAGS)

        return 0
    finally:
        _release_mutex(mutex_handle)


if __name__ == "__main__":
    raise SystemExit(main())
