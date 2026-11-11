# 🛡️ NetTrap-IPS · Analizador de Logs & Mini-SIEM Defensivo en Windows

[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Security Standards](https://img.shields.io/badge/Normas-ISO%2027033%20%7C%20NIST%20SSDF%20%7C%20OWASP%20ASVS-success.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Zero%20Trust-emerald.svg)]()

> **Sistema de Prevención de Intrusiones (IPS) y Mini-SIEM de red para Windows. Centraliza la recolección de eventos desde 3 fuentes reales de Windows (Event Log, Firewall y Tráfico de Red), normaliza todo a JSON (RF-02), correlaciona agresiones en tiempo real mediante reglas YAML (RF-03), y ejecuta contención automatizada en Windows Defender Firewall preservando evidencia forense en capturas `.pcap`.**

---

## 👥 Integrantes · Equipo CyberDefender (UNIPAZ)

| Cédula | Nombre Completo | Rol Técnico |
| :---: | :--- | :--- |
| **1096802414** | Michel Daniela Bayona Diaz | Responsable de Seguridad & Normas |
| **1014189353** | Margit Dayanna Barrera Gutiérrez | Desarrolladora (Backend & Mitigación) |
| **1092528951** | Said Alexander Pacheco Moncada | Líder Técnico & Documentador |

---

## 🏛️ Arquitectura Multifuente Real (RF-01 & RF-02)

NetTrap-IPS **no utiliza puertos trampa ni señuelos ficticios**. Monitorea el sistema operativo Windows a través de 3 componentes nativos en tiempo real:

```text
[ Windows Event Log ]  ──► (EventID 4625 Login Fallido, Security.evtx)
[ Windows Firewall  ]  ──► (pfirewall.log / DROP Events)               ──► [ Normalizador JSON ] ──► [ Motor YAML ] ──► [ AutoBan Firewall ]
[ Tráfico de Red    ]  ──► (Inspección TCP/IP & Conexiones Activas)         (RF-02 Estricto)        (RF-03 Correlación)     (ISO 27033-4 Cl. 9.2)
```

1. **🪟 Fuente 1 · Windows Event Log (Security & System):** Extracción continua mediante `wevtutil` de eventos de autenticación fallida (EventID 4625), inicios de sesión sospechosos e instalación de servicios no autorizados.
2. **🔥 Fuente 2 · Windows Defender Firewall:** Lectura continua del archivo `pfirewall.log` identificando paquetes rechazados (`DROP`) y violaciones a directivas de red.
3. **📡 Fuente 3 · Tráfico de Red y Conexiones Activas:** Inspección en tiempo real de sockets TCP/UDP entrantes detectando ráfagas SYN anómalas y reconocimiento de puertos.
4. **🧠 Motor de Correlación YAML (RF-03):** Ventanas de tiempo deslizantes que evalúan umbrales configurables (ej. 5 fallos de login en 60 segundos ➔ Alerta Crítica).
5. **🔒 Mitigación Activa en Firewall (ISO/IEC 27033-4 Cl. 9.2):** Aplicación de reglas dinámicas de bloqueo `netsh advfirewall` (política *default-deny*) con cuarentena temporal de 300 segundos.
6. **📁 Evidencia Forense Inmutable (.pcap):** Volcados binarios compatibles con la especificación libpcap (0xA1B2C3D4) para auditoría en Wireshark (NIST SP 800-218 PW.9.1).

---

## 🛡️ Principios Zero Trust Implementados

Para garantizar que ningún evaluador o usuario externo pueda explotar vulnerabilidades en el sistema:
- **Verificación Explícita de Sesión:** Todas las operaciones sensibles de mitigación y simulación exigen autenticación criptográfica mediante tokens CSPRNG de 32 bytes (`secrets.token_urlsafe`).
- **Cero Secretos Quemados:** Se eliminó cualquier contraseña o token maestro estático en el código fuente.
- **Protección contra Fuerza Bruta:** Bloqueo temporal por IP tras 5 intentos fallidos de autenticación durante 15 minutos (OWASP ASVS V2.1 / V3.2).
- **Validación Sintáctica Estricta:** Uso estricto de la librería `ipaddress` para evitar ataques de inyección de comandos en las llamadas a `netsh` (OWASP ASVS V5.1.1).
- **Prevención de Inyección:** Subprocesos ejecutados exclusivamente con listas estructuradas sin `shell=True`.

---

## 🛡️ Matriz de Vulnerabilidades NIST (CVE) que Mitiga

| CVE | CVSS v3 | Servicio / Software | Vector Mitigado | Fuente Primaria | Norma Aplicable |
| :---: | :---: | :--- | :--- | :--- | :--- |
| **CVE-2019-0708** | **9.8 Crítico** | Microsoft RDP (*BlueKeep*) | Ataques de fuerza bruta y conexiones anómalas hacia RDP | Windows Event Log (4625) | ISO/IEC 27033-4 Cl. 9.2 |
| **CVE-2024-37032** | **9.8 Crítico** | Ollama LLM Framework | Escaneo de reconocimiento SYN antes de alcanzar APIs locales | Tráfico de Red & Sockets | ISO/IEC 27033-1 Cl. 10.3 |
| **CVE-2023-38408** | **9.8 Crítico** | OpenSSH ssh-agent | Sondeos repetidos y autenticación hostil en servicios remotos | Windows Event Log / Red | OWASP ASVS v5.0 V5.1.1 |
| **CVE-2015-3306** | **10.0 Crítico** | ProFTPd (*mod_copy*) | Conexiones rechazadas y sondeo de servicios bloqueados | Windows Firewall (DROP) | NIST SP 800-218 PW.9.1 |
| **CVE-2021-44228** | **10.0 Crítico** | Apache Log4j2 (*Log4Shell*) | Cargas JNDI lookup en cabeceras de tráfico hacia servicios locales | Tráfico de Red / Sockets | OWASP ASVS v5.0 V7.4.1 |

---

## ⚡ Puesta en Marcha

1. **Requisitos:** Windows 10/11 y Python 3.11+.
2. **Iniciar como Administrador:**
   ```cmd
   start.bat
   ```
3. **Acceder a la consola SOC:**
   ```text
   http://127.0.0.1:8000
   ```
   - **Usuario:** `admin`
   - **Contraseña:** `nettrap2026`
