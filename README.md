# 🛡️ NetTrap-IPS · Sistema de Prevención de Intrusiones con Trampas Señuelo

[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Security Standards](https://img.shields.io/badge/Normas-ISO%2027033%20%7C%20NIST%20SSDF%20%7C%20OWASP%20ASVS-success.svg)]()
[![License](https://img.shields.io/badge/License-Academic%20Project-lightgrey.svg)]()

> **Herramienta defensiva activa diseñada para centralizar la recolección de eventos de tráfico anómalo en Windows, correlacionar escaneos de reconocimiento en tiempo real, aislar agresores automáticamente en Windows Defender Firewall y preservar evidencia forense en capturas `.pcap`.**

---

## 👥 Integrantes · Equipo CyberDefender (UNIPAZ)

| Cédula | Nombre Completo | Rol Técnico |
| :---: | :--- | :--- |
| **1096802414** | Michel Daniela Bayona Diaz | Responsable de Seguridad & Normas |
| **1014189353** | Margit Dayanna Barrera Gutiérrez | Desarrolladora (Backend & Mitigación) |
| **1092528951** | Said Alexander Pacheco Moncada | Líder Técnico & Documentador |

---

## 🚀 Características Principales

1. **🪤 Módulo de Trampas (Honeypot Sockets):** Escucha multihilo activa en puertos señuelo (`21 FTP`, `2222 SSH`, `8080 HTTP`, `3389 RDP`). Captura la IP y cierra el socket inmediatamente sin interactuar.
2. **🧠 Motor de Correlación en Tiempo Real:** Evalúa ventanas deslizantes de tiempo basadas en reglas configurables en YAML (`src/rules/detection_rules.yaml`).
3. **🔒 Mitigación Activa (AutoBan):** Bloqueo dinámico de IPs hostiles mediante `netsh advfirewall` (política *default-deny*) con temporizador de cuarentena de 300 segundos.
4. **📁 Captura Forense Automática (.pcap):** Invoca TShark o sintetiza paquetes binarios compatibles con la especificación estándar libpcap para análisis en Wireshark.
5. **📊 Dashboard Web SOC en Tiempo Real:** Interfaz construida con FastAPI, WebSockets, Tailwind CSS y Chart.js con telemetría en vivo, simulador de ataques Red Team y control de cuarentena.

---

## 🛡️ Matriz de Vulnerabilidades NIST (CVE) que Mitiga

NetTrap-IPS neutraliza activamente la fase de reconocimiento previo requerida para explotar las siguientes vulnerabilidades críticas catalogadas en el NVD de NIST:

| CVE | CVSS v3 | Servicio / Software | Vector Mitigado | Regla Asociada | Norma Aplicable |
| :---: | :---: | :--- | :--- | :--- | :--- |
| **CVE-2024-37032** | **9.8 Crítico** | Ollama LLM Server | Detección previa de escaneo SYN antes de que alcance la API no autenticada en el puerto 11434. | `RULE-001` (≥5 toques / 60s) | ISO/IEC 27033-1 Cl. 10.3 |
| **CVE-2019-0708** | **9.8 Crítico** | Microsoft RDP (*BlueKeep*) | Intercepta intentos en el puerto 3389 señuelo y bloquea la IP en el firewall antes del exploit MS_T120. | `RULE-001` (Trampa RDP 3389) | ISO/IEC 27033-4 Cl. 9.2 |
| **CVE-2023-38408** | **9.8 Crítico** | OpenSSH ssh-agent | Detecta sondeos en puerto SSH señuelo 2222 y bloquea la IP ante intentos repetidos de acceso. | `RULE-003` (Trampa SSH 2222) | OWASP ASVS V5.1.1 |
| **CVE-2015-3306** | **10.0 Crítico** | ProFTPd (*mod_copy*) | Detecta ráfagas de fuerza bruta en puerto señuelo 21 y aísla la IP antes de comandos `SITE CPFR/CPTO`. | `RULE-002` (Trampa FTP 21) | NIST SP 800-218 PW.9.1 |
| **CVE-2021-44228** | **10.0 Crítico** | Apache Log4j2 (*Log4Shell*) | Intercepta cabeceras de inyección JNDI en puerto 8080 señuelo impidiendo que lleguen a servidores reales. | `RULE-004` (Trampa HTTP 8080) | OWASP ASVS V7.4.1 |

---

## 🏛️ Estructura del Proyecto

```text
NETTRAP/
├── .gitignore                      # Exclusiones de control de versiones
├── requirements.txt                # Dependencias Python (FastAPI, Uvicorn, Argon2, etc.)
├── start.bat                       # Script de arranque para Windows (CMD)
├── generate_pdf_report.py          # Generador de informes técnicos en PDF
├── bandit_report.json              # Auditoría SAST con Bandit (0 vulnerabilidades altas)
├── src/
│   ├── backend/
│   │   ├── config.py               # Configuración centralizada de puertos y rutas
│   │   ├── honeypot.py             # Sockets señuelo multihilo (puertos 21, 2222, 8080, 3389)
│   │   ├── correlator.py           # Motor de correlación con ventana deslizante
│   │   ├── mitigator.py            # Bloqueo netsh advfirewall + generación .pcap
│   │   ├── dispatcher.py           # Despachador de alertas hacia WebSocket
│   │   └── main.py                 # Servidor FastAPI y endpoints REST/WebSocket
│   ├── frontend/
│   │   ├── static/                 # Archivos estáticos
│   │   └── templates/
│   │       ├── login.html          # Login seguro con protección contra fuerza bruta
│   │       └── dashboard.html      # Consola SOC interactiva en tiempo real
│   ├── rules/
│   │   └── detection_rules.yaml    # Reglas configurables de detección y umbrales
│   └── data/
│       ├── logs/                   # Registros de auditoría (audit.jsonl)
│       └── pcap/                   # Evidencia forense de paquetes (.pcap)
└── docs/                           # Informes técnicos de las Clases 1, 2 y 3
```

---

## ⚡ Instalación y Puesta en Marcha

### Requisitos Previos
- **Windows 10 / 11**
- **Python 3.11 o superior** instalado y agregado al `PATH`
- *(Opcional)* Wireshark / TShark instalado en `C:\Program Files\Wireshark\`

### Opción 1: Ejecución Rápida
Ejecuta el archivo batch como **Administrador** (necesario para gestionar reglas en Windows Firewall):
```cmd
start.bat
```

### Opción 2: Ejecución Manual
1. Instala las dependencias del proyecto:
   ```cmd
   pip install -r requirements.txt
   ```
2. Inicia el servidor backend:
   ```cmd
   cd src\backend
   python main.py
   ```
3. Abre tu navegador web en:
   ```text
   http://127.0.0.1:8000
   ```
4. Credenciales de acceso por defecto:
   - **Usuario:** `admin`
   - **Contraseña:** `nettrap2026`

---

## 🔍 Análisis Estático de Seguridad (SAST)
El proyecto fue auditado exhaustivamente mediante **Bandit v1.8.3**:
- **Líneas analizadas:** 1.002 líneas de código.
- **Vulnerabilidades de Severidad Alta:** 0 (0%).
- **Cumplimiento:** Toda invocación a subprocesos se realiza con listas estructuradas sin `shell=True` y con validación previa estricta mediante `ipaddress`.

---

## 📜 Licencia
Proyecto con fines académicos para el programa de Ingeniería de la **Universidad de la Paz (UNIPAZ)**.
