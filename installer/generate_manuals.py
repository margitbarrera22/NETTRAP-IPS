"""
Generador oficial de los 3 Manuales PDF de NetTrap-IPS v3.2.0:
  1. Manual_1_Instalacion_NetTrap.pdf
  2. Manual_2_Uso_NetTrap.pdf
  3. Manual_3_Funcionamiento_NetTrap.pdf

Renderiza HTML+CSS+SVG de alta calidad mediante Chrome/Edge headless a PDF Carta.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

BROWSER_CANDIDATES = [
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
]

COMMON_CSS = """
@page {
  size: letter;
  margin: 19mm 15mm 18mm 15mm;
  @top-left {
    content: "NETTRAP-IPS v3.2.0 · DOCUMENTACIÓN OFICIAL";
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 7.5pt;
    font-weight: 700;
    color: #64748B;
    letter-spacing: 0.05em;
    border-bottom: 1px solid #CBD5E1;
    padding-bottom: 4pt;
    white-space: nowrap;
  }
  @top-right {
    content: "Equipo CyberDefender · UNIPAZ";
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 7.5pt;
    color: #475569;
    border-bottom: 1px solid #CBD5E1;
    padding-bottom: 4pt;
    white-space: nowrap;
  }
  @bottom-left {
    content: "NetTrap-IPS · Margit Barrera, Michel Bayona, Said Pacheco · ISO 27033 / NIST / OWASP";
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 7.3pt;
    color: #64748B;
    border-top: 1px solid #CBD5E1;
    padding-top: 4pt;
    white-space: nowrap;
  }
  @bottom-right {
    content: "Página " counter(page) " de " counter(pages);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 7.5pt;
    font-weight: 700;
    color: #0F172A;
    border-top: 1px solid #CBD5E1;
    padding-top: 4pt;
    white-space: nowrap;
  }
}

@page :first {
  @top-left { content: none; }
  @top-right { content: none; }
}

* {
  box-sizing: border-box;
}

body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  font-size: 9.4pt;
  line-height: 1.48;
  color: #1E293B;
  margin: 0;
  padding: 0;
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}

.cover-banner {
  background: linear-gradient(135deg, #0B0D13 0%, #111827 65%, #064E3B 100%);
  color: #F8FAFC;
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 14px;
  border-bottom: 4px solid #10B981;
}

.cover-kicker {
  display: inline-block;
  font-size: 7.5pt;
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #34D399;
  background: rgba(16, 185, 129, 0.16);
  border: 1px solid rgba(52, 211, 153, 0.35);
  padding: 3px 9px;
  border-radius: 999px;
  margin-bottom: 8px;
}

.cover-title {
  font-size: 20pt;
  font-weight: 800;
  margin: 0 0 4px 0;
  line-height: 1.15;
  color: #FFFFFF;
}

.cover-sub {
  font-size: 10pt;
  color: #CBD5E1;
  margin: 0;
}

.meta-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-bottom: 16px;
}

.meta-box {
  background: #F8FAFC;
  border: 1px solid #CBD5E1;
  border-radius: 8px;
  padding: 8px 10px;
}

.meta-label {
  font-size: 7pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #64748B;
}

.meta-val {
  font-size: 8.6pt;
  font-weight: 700;
  color: #0F172A;
  margin-top: 2px;
}

h2 {
  font-size: 12pt;
  font-weight: 800;
  color: #0F172A;
  margin: 15px 0 7px 0;
  padding-bottom: 4px;
  border-bottom: 2px solid #10B981;
  page-break-after: avoid;
  break-after: avoid;
}

h3 {
  font-size: 10pt;
  font-weight: 700;
  color: #065F46;
  margin: 11px 0 5px 0;
  page-break-after: avoid;
  break-after: avoid;
}

p {
  margin: 0 0 7px 0;
}

ul, ol {
  margin: 4px 0 8px 0;
  padding-left: 18px;
}

li {
  margin-bottom: 3.5px;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin: 7px 0 11px 0;
  font-size: 8.5pt;
}

th {
  background: #0F172A;
  color: #FFFFFF;
  text-align: left;
  padding: 6.5px 8px;
  font-size: 7.8pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

td {
  border-bottom: 1px solid #E2E8F0;
  padding: 6px 8px;
  vertical-align: top;
}

tr:nth-child(even) td {
  background: #F8FAFC;
}

tr, .card, .step-box, .callout, .diagram-box, .code-block {
  break-inside: avoid;
  page-break-inside: avoid;
}

.callout {
  border-radius: 8px;
  padding: 9px 12px;
  margin: 8px 0 10px 0;
  font-size: 8.8pt;
}

.callout-green {
  background: #ECFDF5;
  border: 1px solid #A7F3D0;
  border-left: 4px solid #10B981;
  color: #064E3B;
}

.callout-amber {
  background: #FFFBEB;
  border: 1px solid #FDE68A;
  border-left: 4px solid #F59E0B;
  color: #78350F;
}

.callout-blue {
  background: #EFF6FF;
  border: 1px solid #BFDBFE;
  border-left: 4px solid #3B82F6;
  color: #1E3A8A;
}

.callout-rose {
  background: #FFF1F2;
  border: 1px solid #FECDD3;
  border-left: 4px solid #F43F5E;
  color: #881337;
}

.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin: 6px 0 10px 0;
}

.grid-3 {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 9px;
  margin: 6px 0 10px 0;
}

.card {
  background: #F8FAFC;
  border: 1px solid #CBD5E1;
  border-radius: 8px;
  padding: 9px 11px;
}

.card-title {
  font-weight: 800;
  font-size: 9.2pt;
  color: #0F172A;
  margin-bottom: 4px;
}

.step-box {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  background: #F8FAFC;
  border: 1px solid #CBD5E1;
  border-radius: 8px;
  padding: 9px 11px;
  margin-bottom: 7px;
}

.step-num {
  width: 24px;
  height: 24px;
  border-radius: 999px;
  background: #0F172A;
  color: #34D399;
  font-weight: 800;
  font-size: 9pt;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-top: 1px;
}

.code-block {
  background: #0B0D13;
  color: #E2E8F0;
  font-family: Consolas, 'Courier New', monospace;
  font-size: 8.2pt;
  padding: 9px 12px;
  border-radius: 8px;
  border-left: 3px solid #10B981;
  margin: 6px 0 9px 0;
  white-space: pre-wrap;
  word-break: break-word;
}

code {
  font-family: Consolas, 'Courier New', monospace;
  font-size: 8.4pt;
  background: #F1F5F9;
  color: #0F172A;
  padding: 1px 4px;
  border-radius: 4px;
  border: 1px solid #E2E8F0;
}

.badge {
  display: inline-block;
  padding: 1.5px 6px;
  border-radius: 999px;
  font-size: 7.2pt;
  font-weight: 700;
  font-family: Consolas, monospace;
  white-space: nowrap;
}

.badge-green { background: #D1FAE5; color: #065F46; }
.badge-amber { background: #FEF3C7; color: #92400E; }
.badge-red   { background: #FFE4E6; color: #9F1239; }
.badge-slate { background: #E2E8F0; color: #1E293B; }

.diagram-box {
  background: #F8FAFC;
  border: 1px solid #CBD5E1;
  border-radius: 10px;
  padding: 10px;
  margin: 8px 0 12px 0;
  text-align: center;
}

.page-break {
  page-break-before: always;
  break-before: page;
}
"""


def _wrap_html(title: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>{COMMON_CSS}</style>
</head>
<body>
{body_html}
</body>
</html>
"""


def build_manual_1_html() -> str:
    body = r"""
<div class="cover-banner">
  <div class="cover-kicker">Manual 1 de 3 · Instalación y Puesta en Marcha</div>
  <h1 class="cover-title">Manual de Instalación de NetTrap-IPS</h1>
  <p class="cover-sub">Guía completa paso a paso para instalar desde el archivo ZIP con <code>NetTrap-IPS-Setup.exe</code>, sin instalar Python ni ejecutar comandos manuales.</p>
</div>

<div class="meta-grid">
  <div class="meta-box">
    <div class="meta-label">Producto</div>
    <div class="meta-val">NetTrap-IPS SIEM/IPS v3.2</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Instalador</div>
    <div class="meta-val">NetTrap-IPS-Setup.exe</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Sistema</div>
    <div class="meta-val">Windows 10 / 11 (64-bit)</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Equipo · Institución</div>
    <div class="meta-val">CyberDefender · UNIPAZ</div>
  </div>
</div>

<h2>1. Contenido del Paquete Recibido (.ZIP)</h2>
<p>El paquete comprimido que recibiste incluye todo lo necesario para instalar y utilizar la herramienta de inmediato en un computador con Windows:</p>
<table>
  <thead>
    <tr>
      <th style="width: 34%;">Archivo incluido en el ZIP</th>
      <th>Descripción y propósito</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>NetTrap-IPS-Setup.exe</code></td>
      <td><strong>Instalador oficial todo-en-uno (~19.4 MB).</strong> Contiene el motor en Python embebido, todas las librerías (FastAPI, Uvicorn, PyYAML, WebSockets), la interfaz web SOC, las reglas YAML de detección y el controlador de bandeja del sistema.</td>
    </tr>
    <tr>
      <td><code>Manual_1_Instalacion_NetTrap.pdf</code></td>
      <td>Este documento: requisitos, asistente de instalación, arranque automático y solución de problemas.</td>
    </tr>
    <tr>
      <td><code>Manual_2_Uso_NetTrap.pdf</code></td>
      <td>Guía práctica de navegación por las 7 vistas del Dashboard SOC, simulador, pruebas con Nmap y reportes PDF.</td>
    </tr>
    <tr>
      <td><code>Manual_3_Funcionamiento_NetTrap.pdf</code></td>
      <td>Explicación técnica detallada de la arquitectura interna, filtros anti-ruido, correlación, firewall y normas.</td>
    </tr>
  </tbody>
</table>

<div class="callout callout-amber">
  <strong>Importante antes de empezar:</strong> Descomprime primero todo el contenido del archivo <code>.zip</code> en una carpeta normal (por ejemplo en <em>Descargas</em> o el <em>Escritorio</em> usando clic derecho → <em>Extraer todo...</em>). No ejecutes el instalador directamente desde la vista previa del ZIP sin extraerlo.
</div>

<h2>2. Requisitos Previos del Equipo</h2>
<table>
  <thead>
    <tr>
      <th style="width: 24%;">Componente</th>
      <th style="width: 26%;">Requisito</th>
      <th>Para qué se utiliza</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Sistema Operativo</strong></td>
      <td>Windows 10 o Windows 11 (64 bits)</td>
      <td>Soporte nativo de <code>wevtutil</code>, Visor de Eventos de Seguridad y <code>netsh advfirewall</code>.</td>
    </tr>
    <tr>
      <td><strong>Permisos de Usuario</strong></td>
      <td>Cuenta con privilegios de Administrador (UAC)</td>
      <td>Necesario para habilitar <code>pfirewall.log</code>, leer el canal <code>Security</code> (EventID 4625) y aplicar bloqueos reales en el Firewall de Windows.</td>
    </tr>
    <tr>
      <td><strong>Python / Librerías</strong></td>
      <td><span class="badge badge-green">NO REQUERIDO</span></td>
      <td>El instalador empaqueta Python 3.13 y todas las dependencias internamente. No debes instalar nada aparte.</td>
    </tr>
    <tr>
      <td><strong>Wireshark / TShark</strong></td>
      <td>Opcional (Wireshark 4.x)</td>
      <td>Si está instalado en <code>C:\Program Files\Wireshark\tshark.exe</code>, captura paquetes reales en vivo durante 10 s. Si no está, NetTrap genera evidencias <code>.pcap</code> estándar compatibles automáticamente.</td>
    </tr>
    <tr>
      <td><strong>Nmap (Equipo Atacante)</strong></td>
      <td>Opcional (en otro PC)</td>
      <td>Solo si deseas lanzar escaneos reales desde otro computador de la red Wi-Fi/LAN.</td>
    </tr>
  </tbody>
</table>

<h2>3. Instalación Paso a Paso con <code>NetTrap-IPS-Setup.exe</code></h2>

<div class="step-box">
  <div class="step-num">1</div>
  <div>
    <strong>Ejecutar el instalador:</strong> Haz doble clic sobre el archivo extraído <code>NetTrap-IPS-Setup.exe</code>.
  </div>
</div>

<div class="step-box">
  <div class="step-num">2</div>
  <div>
    <strong>Si aparece Windows SmartScreen ("Windows protegió su PC"):</strong> Como es una aplicación académica sin certificado comercial de Microsoft, Windows puede mostrar un aviso preventivo. Haz clic en <strong>Más información</strong> y luego en el botón <strong>Ejecutar de todas formas</strong>.
  </div>
</div>

<div class="step-box">
  <div class="step-num">3</div>
  <div>
    <strong>Aceptar Control de Cuentas de Usuario (UAC):</strong> Windows pedirá permiso para que el instalador realice cambios en el equipo. Pulsa <strong>Sí</strong>. Esto solo se pide durante la instalación.
  </div>
</div>

<div class="step-box">
  <div class="step-num">4</div>
  <div>
    <strong>Seguir el asistente en español:</strong><br>
    • <em>Carpeta de destino:</em> Deja la ruta recomendada <code>C:\Program Files\NetTrap-IPS</code> y pulsa <strong>Siguiente</strong>.<br>
    • <em>Tareas adicionales (dejar ambas casillas marcadas):</em><br>
    &nbsp;&nbsp;☑ <strong>Crear un acceso directo en el Escritorio</strong> (crea <em>NetTrap-IPS SOC</em>).<br>
    &nbsp;&nbsp;☑ <strong>Mantener el servidor activo automáticamente al iniciar Windows (sin consola ni comandos)</strong>.<br>
    • Pulsa <strong>Instalar</strong> y espera unos segundos a que se copien todos los archivos.
  </div>
</div>

<div class="step-box">
  <div class="step-num">5</div>
  <div>
    <strong>Primer arranque inmediato:</strong> En la pantalla final, deja marcada la casilla ☑ <strong>Iniciar servidor NetTrap-IPS y abrir el Dashboard SOC ahora</strong> y pulsa <strong>Finalizar</strong>. El servidor arrancará en segundo plano y abrirá automáticamente tu navegador en <code>http://127.0.0.1:8000</code>.
  </div>
</div>

<h2>4. ¿Qué Configura Automáticamente el Programa al Instalar y Arrancar?</h2>
<p>No tienes que abrir terminales ni ejecutar scripts adicionales. Al finalizar la instalación e iniciarse <code>NetTrap-IPS.exe</code> con permisos elevados, el sistema realiza de forma automática:</p>

<div class="diagram-box">
  <svg width="100%" height="108" viewBox="0 0 700 108" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <marker id="arrow-green" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#10B981"/>
      </marker>
    </defs>
    <rect x="6" y="14" width="154" height="78" rx="8" fill="#0F172A"/>
    <text x="83" y="37" text-anchor="middle" fill="#34D399" font-family="Segoe UI, sans-serif" font-size="10" font-weight="700">1. Instalador Setup.exe</text>
    <text x="83" y="54" text-anchor="middle" fill="#E2E8F0" font-family="Segoe UI, sans-serif" font-size="8.5">Copia app en Program Files</text>
    <text x="83" y="68" text-anchor="middle" fill="#E2E8F0" font-family="Segoe UI, sans-serif" font-size="8.5">Crea carpeta ProgramData</text>
    <text x="83" y="82" text-anchor="middle" fill="#94A3B8" font-family="Segoe UI, sans-serif" font-size="8">Registra Tarea Programada</text>

    <path d="M163 53 L180 53" stroke="#10B981" stroke-width="2" marker-end="url(#arrow-green)"/>

    <rect x="184" y="14" width="162" height="78" rx="8" fill="#ECFDF5" stroke="#10B981" stroke-width="1.4"/>
    <text x="265" y="37" text-anchor="middle" fill="#065F46" font-family="Segoe UI, sans-serif" font-size="10" font-weight="700">2. Política Windows</text>
    <text x="265" y="54" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="8.5">Abre TCP 8000 / ICMP</text>
    <text x="265" y="68" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="8.5">Activa pfirewall.log DROP</text>
    <text x="265" y="82" text-anchor="middle" fill="#475569" font-family="Segoe UI, sans-serif" font-size="8">Habilita auditpol Logon</text>

    <path d="M349 53 L366 53" stroke="#10B981" stroke-width="2" marker-end="url(#arrow-green)"/>

    <rect x="370" y="14" width="154" height="78" rx="8" fill="#ECFDF5" stroke="#10B981" stroke-width="1.4"/>
    <text x="447" y="37" text-anchor="middle" fill="#065F46" font-family="Segoe UI, sans-serif" font-size="10" font-weight="700">3. Motor Siempre Activo</text>
    <text x="447" y="54" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="8.5">Escucha en 0.0.0.0:8000</text>
    <text x="447" y="68" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="8.5">Icono en Bandeja (Tray)</text>
    <text x="447" y="82" text-anchor="middle" fill="#475569" font-family="Segoe UI, sans-serif" font-size="8">3 sensores activos en vivo</text>

    <path d="M527 53 L544 53" stroke="#10B981" stroke-width="2" marker-end="url(#arrow-green)"/>

    <rect x="548" y="14" width="146" height="78" rx="8" fill="#0F172A"/>
    <text x="621" y="37" text-anchor="middle" fill="#34D399" font-family="Segoe UI, sans-serif" font-size="10" font-weight="700">4. Dashboard Web</text>
    <text x="621" y="54" text-anchor="middle" fill="#E2E8F0" font-family="Segoe UI, sans-serif" font-size="8.5">Abre navegador directo</text>
    <text x="621" y="68" text-anchor="middle" fill="#E2E8F0" font-family="Segoe UI, sans-serif" font-size="8.5">http://127.0.0.1:8000</text>
    <text x="621" y="82" text-anchor="middle" fill="#94A3B8" font-family="Segoe UI, sans-serif" font-size="8">Sin login obligatorio</text>
  </svg>
</div>

<ul>
  <li><strong>Rutas instaladas en tu equipo:</strong>
    <ul>
      <li>Programa ejecutable y manuales: <code>C:\Program Files\NetTrap-IPS\</code></li>
      <li>Logs y capturas forenses <code>.pcap</code>: <code>C:\ProgramData\NetTrap-IPS\data\</code> (carpetas <code>logs\</code> y <code>pcap\</code>)</li>
      <li>Tarea automática de Windows: <code>NetTrap-IPS Server</code> (arranca al iniciar sesión con privilegios máximos sin mostrar consola negra ni volver a pedir UAC).</li>
    </ul>
  </li>
</ul>

<h2>5. Funcionamiento en Segundo Plano y Bandeja del Sistema</h2>
<p>Una vez instalado, <strong>si cierras la pestaña o la ventana del navegador, el servidor NO se apaga</strong>. Sigue protegiendo tu PC de forma silenciosa mediante un icono de <strong>escudo verde</strong> en la bandeja del sistema (esquina inferior derecha, junto al reloj o dentro de la flecha <code>^</code> de iconos ocultos).</p>

<table>
  <thead>
    <tr>
      <th style="width: 38%;">Opción del Menú (Clic derecho en el escudo)</th>
      <th>Acción que realiza</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Abrir Dashboard SOC</strong> <em>(clic izquierdo)</em></td>
      <td>Abre <code>http://127.0.0.1:8000</code> (o el puerto activo) en tu navegador predeterminado.</td>
    </tr>
    <tr>
      <td><strong>Copiar IP de Red</strong></td>
      <td>Copia tu dirección LAN (ej. <code>http://192.168.101.27:8000</code>) para compartirla o probar ataques.</td>
    </tr>
    <tr>
      <td><strong>Abrir Carpeta de Evidencias (.pcap y logs)</strong></td>
      <td>Abre en el Explorador de Windows <code>C:\ProgramData\NetTrap-IPS\data</code>.</td>
    </tr>
    <tr>
      <td><strong>Iniciar automáticamente con Windows</strong></td>
      <td>Marca o desmarca si deseas que el servidor arranque solo al encender el PC.</td>
    </tr>
    <tr>
      <td><strong>Limpiar Reglas Temporales de Firewall</strong></td>
      <td>Elimina de inmediato cualquier regla <code>NETTRAP-BLOCK-*</code> creada durante pruebas.</td>
    </tr>
    <tr>
      <td><strong>Reiniciar Servidor / Detener Servidor y Salir</strong></td>
      <td>Reinicia el motor web o apaga por completo el servicio defensivo.</td>
    </tr>
  </tbody>
</table>

<div class="callout callout-green">
  <strong>Cómo volver a abrirlo otro día:</strong> Haz doble clic en el icono <strong>NetTrap-IPS SOC</strong> del Escritorio o busca <em>NetTrap-IPS</em> en el Menú Inicio. Si el servidor ya está corriendo en segundo plano, detectará la instancia activa y abrirá la página web al instante sin duplicar procesos ni pedir UAC.
</div>

<h2>6. Verificación Post-Instalación y Solución de Problemas</h2>
<ol>
  <li>En el menú lateral izquierdo del Dashboard, haz clic en <strong>Diagnóstico</strong>.</li>
  <li>Comprueba que las tarjetas <strong>Permisos de Administrador</strong>, <strong>Log de Firewall (pfirewall.log)</strong> y <strong>Event Log Windows (4625)</strong> aparezcan en verde (<em>LISTO / ACTIVO / RESPONDE</em>) y que los 3 sensores figuren como <strong>ACTIVO</strong>.</li>
</ol>

<table>
  <thead>
    <tr>
      <th style="width: 30%;">Situación</th>
      <th>Causa y solución rápida</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Diagnóstico muestra <strong>Modo Parcial</strong> o sin permisos Admin</td>
      <td>Se rechazó el permiso UAC al iniciar manualmente. Haz clic derecho en el icono de la bandeja → <em>Detener Servidor y Salir</em>, y vuelve a abrir <em>NetTrap-IPS SOC</em> aceptando el aviso UAC.</td>
    </tr>
    <tr>
      <td>Otro programa ya usaba el puerto <code>8000</code></td>
      <td>NetTrap selecciona automáticamente el puerto de respaldo <code>8001</code> (u otro libre) y abre el navegador en ese puerto sin fallar.</td>
    </tr>
    <tr>
      <td>Actualizar a una versión más reciente</td>
      <td>Solo ejecuta el nuevo <code>NetTrap-IPS-Setup.exe</code>: el instalador detiene la versión anterior en ejecución, actualiza los archivos y conserva tus logs.</td>
    </tr>
    <tr>
      <td>Desinstalar completamente</td>
      <td>Desde <em>Configuración de Windows → Aplicaciones</em> o Menú Inicio → <em>Desinstalar NetTrap-IPS</em>. Detiene el servidor, elimina la tarea programada y limpia las reglas <code>NetTrap-Inbound-*</code>.</td>
    </tr>
  </tbody>
</table>
"""
    return _wrap_html("Manual 1 · Instalación de NetTrap-IPS", body)


def build_manual_2_html() -> str:
    body = r"""
<div class="cover-banner">
  <div class="cover-kicker">Manual 2 de 3 · Operación de la Consola SOC</div>
  <h1 class="cover-title">Manual de Uso de NetTrap-IPS</h1>
  <p class="cover-sub">Guía práctica para navegar las 7 vistas del Dashboard SOC, ejecutar simulaciones o ataques reales con Nmap, inspeccionar evidencias <code>.pcap</code> y exportar reportes PDF.</p>
</div>

<div class="meta-grid">
  <div class="meta-box">
    <div class="meta-label">Acceso Local</div>
    <div class="meta-val">http://127.0.0.1:8000</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Acceso al Dashboard</div>
    <div class="meta-val">Directo (sin login)</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Cuarentena AutoBan</div>
    <div class="meta-val">300 seg (5 minutos)</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Equipo · Institución</div>
    <div class="meta-val">CyberDefender · UNIPAZ</div>
  </div>
</div>

<h2>1. Acceso al Panel Web y Controles de la Barra Superior</h2>
<p>Al abrir <strong>NetTrap-IPS SOC</strong> (o ir a <code>http://127.0.0.1:8000</code>), entras directamente al panel de monitoreo sin pantalla de bloqueo previa. En el equipo servidor utiliza siempre <code>127.0.0.1</code> para consultar el Dashboard y evitar que tu propia sesión se vea afectada durante pruebas locales.</p>

<table>
  <thead>
    <tr>
      <th style="width: 28%;">Elemento en Barra Superior</th>
      <th>Función operativa</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Botón Menú (☰)</strong></td>
      <td>Despliega o colapsa la barra lateral izquierda de navegación.</td>
    </tr>
    <tr>
      <td><strong>Insignia IP:Puerto</strong> (ej. <code>192.168.101.27:8000</code>)</td>
      <td>Muestra la dirección IP real de tu computador en la red local; esa es la IP que debe atacar otro compañero con Nmap.</td>
    </tr>
    <tr>
      <td><strong>Indicador EN VIVO</strong></td>
      <td>Confirma conexión WebSocket activa (<code>/ws/alerts</code>) para recibir alertas al instante sin recargar la página.</td>
    </tr>
    <tr>
      <td><strong>Sol / Luna</strong></td>
      <td>Alterna en vivo entre el tema oscuro SOC y el tema claro.</td>
    </tr>
    <tr>
      <td><strong>Altavoz (Sonido)</strong></td>
      <td>Activa o silencia las alertas sonoras cuando se detecta una intrusión crítica.</td>
    </tr>
    <tr>
      <td><strong>Reiniciar (Flechas circulares)</strong></td>
      <td>Limpia los contadores de pantalla y <strong>desbloquea todas las IPs en cuarentena</strong> para comenzar una nueva prueba desde cero.</td>
    </tr>
    <tr>
      <td><strong>Descarga verde (JSON)</strong></td>
      <td>Exporta el historial completo de alertas detectadas en formato JSON estructurado.</td>
    </tr>
  </tbody>
</table>

<h2>2. Las 7 Vistas del Menú Lateral</h2>

<div class="grid-2">
  <div class="card">
    <div class="card-title">1. Monitor en Vivo</div>
    <p>Centro de control principal en tiempo real:</p>
    <ul>
      <li><strong>4 KPIs:</strong> <em>Estado de la Red</em> (PROTEGIDA / BAJO ATAQUE), <em>Eventos Analizados</em> (<code>Red</code>, <code>FW</code>, <code>Win</code>), <em>Ataques Detectados</em> e <em>IPs Bloqueadas</em>.</li>
      <li><strong>Panel de Incidente Activo:</strong> Al ocurrir un ataque cambia a rojo mostrando IP atacante, regla disparada, CVEs mitigados, puertos afectados y botones <em>Descargar Evidencia (.pcap)</em> y <em>Desbloquear IP ahora</em>.</li>
      <li><strong>Tabla de Historial:</strong> Alterna entre <em>Ataques Detectados</em> y <em>Conexiones Paso a Paso</em>, con buscador por IP o puerto.</li>
      <li><strong>Cuarentena y PCAPs:</strong> Muestra IPs bloqueadas con cuenta regresiva de 300 s, bloqueo manual por IP y descargas <code>.pcap</code>.</li>
      <li><strong>Gráfica Live Stream + Bitácora:</strong> Curva continua de eventos vs ataques y consola de registros del motor.</li>
    </ul>
  </div>

  <div class="card">
    <div class="card-title">2. Radar LAN</div>
    <p>Descubrimiento táctico de equipos en tu subred Wi-Fi o cableada:</p>
    <ul>
      <li>Muestra <em>Subred Local</em>, <em>Este Equipo</em>, <em>Router / Gateway</em> y total de <em>Equipos Detectados</em> vía tabla ARP.</li>
      <li><strong>Radar Táctico 360° LIVE:</strong> Mapa interactivo donde cada punto representa un dispositivo (verde = equipo LAN, cian = router/whitelist, rojo = IP bloqueada).</li>
      <li><strong>Tabla de Dispositivos:</strong> Muestra IP, dirección MAC, rol/nombre del equipo y botones para bloquear/desbloquear rápidamente.</li>
      <li><strong>Copiar Comando Nmap:</strong> Copia al portapapeles el comando listo para lanzar pruebas desde otro computador.</li>
    </ul>
  </div>

  <div class="card">
    <div class="card-title">3. Reportes y Analítica</div>
    <p>Consolidado estadístico e informes ejecutivos:</p>
    <ul>
      <li><strong>Mini-KPIs:</strong> <em>Atacantes Únicos</em>, <em>Puerto Más Atacado</em>, <em>Regla Más Activa</em> y total de <em>Evidencias .pcap</em>.</li>
      <li><strong>Gráficas:</strong> Barras de <em>Puertos Más Sondeados</em> y dona de <em>Distribución por Regla SIEM</em>.</li>
      <li><strong>Tablas:</strong> <em>Top IPs Atacantes</em> y <em>Detalle de Puertos Atacados</em>.</li>
      <li><strong>Exportación:</strong> Botones <em>Actualizar Datos</em>, <em>Descargar HTML</em> y <strong>Generar Informe PDF / Imprimir</strong>.</li>
    </ul>
  </div>

  <div class="card">
    <div class="card-title">4. Diagnóstico</div>
    <p>Verificación de salud del equipo Windows (Health Check):</p>
    <ul>
      <li>Banner global: <strong>LISTO PARA PRODUCCIÓN</strong> o <strong>MODO PARCIAL</strong>.</li>
      <li>Evalúa 4 requisitos: <em>Permisos de Administrador</em>, <em>Log de Firewall (pfirewall.log)</em>, <em>Event Log Windows (4625)</em> y <em>Wireshark / TShark CLI</em>.</li>
      <li>Muestra el estado vivo (<em>ACTIVO</em> / <em>INACTIVO</em>) de los 3 hilos recolectores del sistema.</li>
    </ul>
  </div>

  <div class="card">
    <div class="card-title">5. Simulador y Pruebas</div>
    <p>Laboratorio integrado para probar los 3 sensores sin herramientas externas:</p>
    <ul>
      <li><strong>Simular Escaneo Nmap:</strong> Envía 5 eventos desde <code>198.51.100.44:3389</code> (dispara <code>RULE-002</code>).</li>
      <li><strong>Simular Rechazos Firewall:</strong> Inyecta 5 eventos DROP desde <code>198.51.100.77:445</code> (dispara <code>RULE-003</code>).</li>
      <li><strong>Simular Fuerza Bruta (4625):</strong> Inyecta 5 fallos de logon desde <code>203.0.113.66:445</code> (dispara <code>RULE-001</code>).</li>
      <li><strong>Auditoría de Puertos Locales:</strong> Botón para comprobar puertos <code>21, 22, 80, 135, 445, 3389, 8000</code> en <code>127.0.0.1</code>.</li>
    </ul>
  </div>

  <div class="card">
    <div class="card-title">6. Reglas y CVEs &nbsp;|&nbsp; 7. Guía Rápida</div>
    <ul>
      <li><strong>Reglas y CVEs:</strong> Resume las 4 reglas SIEM activas (<code>RULE-001</code> a <code>RULE-004</code>) y la matriz de las 5 vulnerabilidades críticas NIST CVE mitigadas con su puntuación CVSS y norma.</li>
      <li><strong>Guía Rápida:</strong> Tarjetas interactivas con el flujo en 4 pasos dentro del propio panel web y referencia de los botones de la barra superior.</li>
    </ul>
  </div>
</div>

<h2>3. Cómo Probar el Sistema (Dos Modalidades)</h2>

<h3>Modalidad A · Prueba Rápida en un Solo Equipo (Simulador en 1 Clic)</h3>
<ol>
  <li>Opcional: activa <strong>Altavoz</strong> arriba para escuchar el aviso sonoro de ataque.</li>
  <li>En <strong>Simulador y Pruebas</strong> pulsa cualquier botón (ej. <em>Lanzar Prueba de Escaneo</em>).</li>
  <li>Volverás al <strong>Monitor en Vivo</strong>: verás la alerta roja, la IP en cuarentena (<code>300 s</code>) y el botón <strong>Descargar Evidencia (.pcap)</strong>.</li>
</ol>

<h3>Modalidad B · Prueba Real Desde Otro Computador en la Red Local</h3>
<p>Conecta dos PCs a la misma red Wi-Fi. En el equipo con NetTrap-IPS, revisa tu IP en la barra superior o en <strong>Radar LAN</strong> (ej. <code>192.168.101.27</code>) y ejecuta desde el otro computador:</p>

<div class="code-block">nmap -Pn -sT -sV -p 21,22,80,135,139,445,3389,8000,8080 &lt;IP_DEL_SERVIDOR&gt;
curl -A "Nmap Scripting Engine" http://&lt;IP_DEL_SERVIDOR&gt;:8000/.env</div>

<div class="callout callout-green">
  <strong>Sin falsas alarmas en red Wi-Fi:</strong> NetTrap-IPS filtra automáticamente el ruido LAN normal (SSDP <code>1900</code>, mDNS <code>5353</code>, IGMP, link-local <code>fe80::</code> y el router) y permite abrir el Dashboard desde otro navegador sin bloquearlo.
</div>

<h2>4. Cuarentena, Evidencias (.pcap) y Reporte PDF</h2>
<ul>
  <li><strong>Desbloquear antes de 300 s:</strong> Usa el botón <em>Desbloquear</em> en <em>IPs Bloqueadas</em>, <em>Reiniciar</em> arriba o clic derecho en el escudo de la bandeja → <em>Limpiar Reglas Temporales de Firewall</em>.</li>
  <li><strong>Wireshark (.pcap):</strong> Descarga la evidencia desde la alerta o <em>Archivos .pcap</em> y ábrela con <code>wireshark -r archivo.pcap</code> (también se guardan en <code>C:\ProgramData\NetTrap-IPS\data\pcap\</code>).</li>
  <li><strong>Informe PDF:</strong> En <em>Reportes y Analítica</em> → <strong>Generar Informe PDF / Imprimir</strong> → <em>Guardar como PDF</em>.</li>
</ul>
"""
    return _wrap_html("Manual 2 · Uso y Operación de NetTrap-IPS", body)


def build_manual_3_html() -> str:
    body = r"""
<div class="cover-banner">
  <div class="cover-kicker">Manual 3 de 3 · Arquitectura Técnica e Ingeniería</div>
  <h1 class="cover-title">Manual de Funcionamiento de NetTrap-IPS</h1>
  <p class="cover-sub">Arquitectura interna completa del motor Mini-SIEM/IPS: ingesta multifuente, filtros de ruido LAN, normalización JSON, correlación en ventanas deslizantes, mitigación en Firewall, evidencias libpcap y controles Zero Trust.</p>
</div>

<div class="meta-grid">
  <div class="meta-box">
    <div class="meta-label">Backend</div>
    <div class="meta-val">FastAPI + Uvicorn + Python 3.13</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Fuentes Reales</div>
    <div class="meta-val">EventLog · Firewall · Red TCP</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Evidencia Forense</div>
    <div class="meta-val">libpcap 2.4 / TShark</div>
  </div>
  <div class="meta-box">
    <div class="meta-label">Marco Normativo</div>
    <div class="meta-val">ISO 27033 · NIST · OWASP</div>
  </div>
</div>

<h2>1. Arquitectura General del Sistema</h2>
<p><strong>NetTrap-IPS</strong> es un Sistema de Detección y Prevención de Intrusiones (IPS) y Mini-SIEM nativo para Windows. En lugar de depender de puertos trampa ficticios, observa en paralelo <strong>tres fuentes reales del sistema operativo</strong>, normaliza cada evento a JSON validado, correlaciona patrones por ventana de tiempo deslizante y ejecuta contención automática en Windows Defender Firewall generando captura forense <code>.pcap</code>.</p>

<div class="diagram-box">
  <svg width="100%" height="156" viewBox="0 0 700 156" xmlns="http://www.w3.org/2000/svg">
    <!-- Columna 1: Fuentes -->
    <rect x="6" y="10" width="150" height="38" rx="6" fill="#0F172A"/>
    <text x="81" y="27" text-anchor="middle" fill="#38BDF8" font-family="Segoe UI, sans-serif" font-size="8.8" font-weight="700">1. Windows Event Log</text>
    <text x="81" y="40" text-anchor="middle" fill="#CBD5E1" font-family="Segoe UI, sans-serif" font-size="7.5">wevtutil Security (ID 4625)</text>

    <rect x="6" y="58" width="150" height="38" rx="6" fill="#0F172A"/>
    <text x="81" y="75" text-anchor="middle" fill="#FBBF24" font-family="Segoe UI, sans-serif" font-size="8.8" font-weight="700">2. Windows Firewall</text>
    <text x="81" y="88" text-anchor="middle" fill="#CBD5E1" font-family="Segoe UI, sans-serif" font-size="7.5">pfirewall.log (DROP filtrado)</text>

    <rect x="6" y="106" width="150" height="38" rx="6" fill="#0F172A"/>
    <text x="81" y="123" text-anchor="middle" fill="#34D399" font-family="Segoe UI, sans-serif" font-size="8.8" font-weight="700">3. Tráfico de Red &amp; HTTP</text>
    <text x="81" y="136" text-anchor="middle" fill="#CBD5E1" font-family="Segoe UI, sans-serif" font-size="7.5">netstat TCP + Middleware HTTP</text>

    <!-- Flechas a Normalizador -->
    <line x1="156" y1="29" x2="188" y2="75" stroke="#64748B" stroke-width="1.6"/>
    <line x1="156" y1="77" x2="188" y2="77" stroke="#64748B" stroke-width="1.6"/>
    <line x1="156" y1="125" x2="188" y2="79" stroke="#64748B" stroke-width="1.6"/>

    <!-- Columna 2: Normalizador -->
    <rect x="190" y="38" width="128" height="78" rx="8" fill="#ECFDF5" stroke="#10B981" stroke-width="1.5"/>
    <text x="254" y="59" text-anchor="middle" fill="#065F46" font-family="Segoe UI, sans-serif" font-size="9" font-weight="800">Normalizador (RF-02)</text>
    <text x="254" y="74" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="7.8">normalize_event()</text>
    <text x="254" y="88" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="7.8">Valida IP (ipaddress)</text>
    <text x="254" y="102" text-anchor="middle" fill="#475569" font-family="Segoe UI, sans-serif" font-size="7.5">event_queue (max 1000)</text>

    <line x1="318" y1="77" x2="342" y2="77" stroke="#10B981" stroke-width="2"/>

    <!-- Columna 3: Correlador -->
    <rect x="344" y="30" width="146" height="94" rx="8" fill="#FFFBEB" stroke="#F59E0B" stroke-width="1.5"/>
    <text x="417" y="51" text-anchor="middle" fill="#92400E" font-family="Segoe UI, sans-serif" font-size="9" font-weight="800">Correlador (RF-03)</text>
    <text x="417" y="66" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="7.8">CorrelationEngine</text>
    <text x="417" y="80" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="7.8">Ventanas deslizantes</text>
    <text x="417" y="94" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="7.8">Reglas YAML + Whitelist</text>
    <text x="417" y="108" text-anchor="middle" fill="#78350F" font-family="Segoe UI, sans-serif" font-size="7.5">Gateway protegido + Cooldown</text>

    <line x1="490" y1="77" x2="514" y2="77" stroke="#F59E0B" stroke-width="2"/>

    <!-- Columna 4: Dispatcher y Mitigación -->
    <rect x="516" y="14" width="178" height="58" rx="8" fill="#FFF1F2" stroke="#F43F5E" stroke-width="1.5"/>
    <text x="605" y="34" text-anchor="middle" fill="#9F1239" font-family="Segoe UI, sans-serif" font-size="9" font-weight="800">Mitigador (AutoBan)</text>
    <text x="605" y="49" text-anchor="middle" fill="#1E293B" font-family="Segoe UI, sans-serif" font-size="7.8">netsh advfirewall BLOCK (300s)</text>
    <text x="605" y="62" text-anchor="middle" fill="#475569" font-family="Segoe UI, sans-serif" font-size="7.5">Captura .pcap (libpcap / TShark)</text>

    <rect x="516" y="84" width="178" height="58" rx="8" fill="#0F172A"/>
    <text x="605" y="104" text-anchor="middle" fill="#34D399" font-family="Segoe UI, sans-serif" font-size="9" font-weight="800">WebSocket &amp; Auditoría</text>
    <text x="605" y="119" text-anchor="middle" fill="#E2E8F0" font-family="Segoe UI, sans-serif" font-size="7.8">ws_broadcast_queue → /ws/alerts</text>
    <text x="605" y="132" text-anchor="middle" fill="#94A3B8" font-family="Segoe UI, sans-serif" font-size="7.5">audit.jsonl &amp; firewall_audit.jsonl</text>
  </svg>
</div>

<h2>2. Ciclo de Vida del Ejecutable y Servidor Siempre Activo</h2>
<p>El módulo <code>src/nettrap_desktop.py</code> envuelve el backend FastAPI/Uvicorn dentro de una aplicación de escritorio Windows sin ventana de consola (<code>console=False</code>):</p>
<ul>
  <li><strong>Detección de instancia única:</strong> Consulta <code>GET http://127.0.0.1:&lt;puerto&gt;/api/health</code> y utiliza el Mutex de Windows <code>Local\NetTrapIPS_SingleInstance_Mutex</code>. Si el servidor ya está activo, abre directamente el navegador y evita instancias duplicadas.</li>
  <li><strong>Elevación UAC y Tarea Programada:</strong> Si no corre como Administrador (y no se especificó <code>--no-elevate</code>), solicita elevación UAC mediante <code>ShellExecuteW("runas")</code>. Durante la instalación con <code>NetTrap-IPS-Setup.exe</code>, la tarea programada <code>NetTrap-IPS Server</code> (<code>/SC ONLOGON /RL HIGHEST</code>) deja el servidor corriendo en segundo plano en cada inicio de sesión sin mostrar consola ni repetir avisos UAC.</li>
  <li><strong>Supresión de parpadeo CMD:</strong> Todos los subprocesos nativos (<code>wevtutil</code>, <code>netstat</code>, <code>netsh</code>, <code>route</code>, <code>arp</code>, <code>tshark</code>) se lanzan con <code>SUBPROC_FLAGS = subprocess.CREATE_NO_WINDOW</code>.</li>
  <li><strong>Resolución de rutas congeladas (<code>config.py</code>):</strong> Al ejecutarse empaquetado (<code>IS_FROZEN</code>), los recursos de solo lectura (<code>frontend/</code> y <code>rules/detection_rules.yaml</code>) se cargan desde <code>sys._MEIPASS</code>, mientras que los datos persistentes (<code>logs/</code> y <code>pcap/</code>) se guardan en <code>C:\ProgramData\NetTrap-IPS\data\</code> (con respaldo a <code>%LOCALAPPDATA%\NetTrap-IPS\data</code>).</li>
</ul>

<h2>3. Detalle Técnico de las 4 Etapas del Pipeline</h2>

<h3>Etapa 1 · Recolección Multifuente (<code>src/backend/collectors.py</code>) y Middleware HTTP</h3>
<table>
  <thead>
    <tr>
      <th style="width: 24%;">Componente</th>
      <th style="width: 20%;">Frecuencia / Origen</th>
      <th>Funcionamiento y Filtrado Anti-Falsos Positivos</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>WindowsEventLogCollector</strong></td>
      <td>Cada <code>4 s</code><br><code>wevtutil qe Security</code></td>
      <td>Consulta eventos <code>EventID=4625</code> de los últimos 60 s. Prioriza XML nativo (independiente del idioma) extrayendo <code>EventRecordID</code>, <code>IpAddress</code>, <code>TargetUserName</code> e <code>IpPort</code>, con respaldo en parser de texto español/inglés y control de duplicados en <code>_seen_records</code>.</td>
    </tr>
    <tr>
      <td><strong>WindowsFirewallCollector</strong></td>
      <td>Cada <code>3 s</code><br><code>pfirewall.log</code></td>
      <td>Parsea dinámicamente el encabezado <code>#Fields:</code> y maneja rotación de archivo. Solo procesa líneas <code>DROP</code> entrantes (<code>path</code> = <code>RECEIVE</code> o <code>-</code>) en protocolos <code>TCP</code>/<code>UDP</code>. Filtra tráfico IGMP (<code>2</code>), direcciones link-local (<code>fe80::/10</code>, <code>169.254.0.0/16</code>), multicast/broadcast, puertos normales de descubrimiento LAN/Wi-Fi (<code>67, 68, 137, 138, 546, 547, 1900, 3702, 5353, 5355</code> y <code>53/123 UDP</code>), el router/gateway e IPs ya en cuarentena (<code>is_ip_blocked</code>).</td>
    </tr>
    <tr>
      <td><strong>NetworkTrafficCollector</strong></td>
      <td>Cada <code>1 s</code><br><code>netstat -a -n -p tcp</code></td>
      <td>Detecta puertos locales en estado <code>LISTENING (&lt; 49152)</code> y nuevas conexiones entrantes (<code>ESTABLISHED</code>, <code>SYN_RECEIVED</code>, <code>TIME_WAIT</code>, etc.), ignorando tráfico local, link-local, multicast e IPs ya bloqueadas.</td>
    </tr>
    <tr>
      <td><strong>Middleware <code>audit_external_traffic</code></strong></td>
      <td>Por cada petición HTTP<br><code>src/backend/main.py</code></td>
      <td>Bloquea con HTTP <code>403</code> si <code>is_ip_blocked(ip)</code> es verdadero. Solo genera eventos de sondeo HTTP cuando detecta User-Agents ofensivos (<code>nmap</code>, <code>nikto</code>, <code>sqlmap</code>, <code>curl</code>, <code>python</code>, <code>hydra</code>, <code>gobuster</code>, <code>dirbuster</code>, <code>wfuzz</code>, <code>masscan</code>, <code>${jndi:</code>), rutas/parámetros sospechosos (<code>/.env</code>, <code>/admin</code>, <code>/wp-admin</code>, <code>/config</code>, <code>/backup</code>, <code>union select</code>, <code>../</code>) o intentos <code>POST /login</code>.</td>
    </tr>
  </tbody>
</table>

<h3>Etapa 2 · Normalización Estricta JSON (RF-02)</h3>
<p>La función <code>normalize_event()</code> convierte cada evento en un esquema uniforme y lo inserta sin bloqueo en <code>event_queue</code> (límite máximo de <code>1000</code> eventos para prevenir saturación de memoria):</p>
<div class="code-block">{ "timestamp": "UTC ISO-8601", "origen": "windows_event_log | windows_firewall | network_traffic",
  "severidad": "CRITICAL | HIGH | MEDIUM | LOW | INFO", "evento": "...",
  "ip_origen": "IP validada por ipaddress", "puerto": 445, "descripcion": "...", "is_simulation": false }</div>

<h3>Etapa 3 · Correlación en Tiempo Real (<code>src/backend/correlator.py</code>, RF-03)</h3>
<p><code>CorrelationEngine</code> evalúa eventos contra <code>src/rules/detection_rules.yaml</code> usando <code>SlidingWindowCounter</code> (conteo por IP y puertos distintos dentro de la ventana deslizante). Además, <code>_append_dynamic_whitelist()</code> protege automáticamente la puerta de enlace real de la red activa (<code>get_default_gateway()</code>) y filtra direcciones link-local e IPs ya bloqueadas:</p>

<table>
  <thead>
    <tr>
      <th style="width: 12%;">Regla</th>
      <th style="width: 24%;">Fuente y Amenaza</th>
      <th style="width: 28%;">Criterio de Disparo</th>
      <th style="width: 16%;">Severidad</th>
      <th>Acción y CVEs</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>RULE-001</code></td>
      <td><code>windows_event_log</code><br>Fuerza bruta (4625)</td>
      <td><code>≥ 5</code> eventos en <code>60 s</code></td>
      <td><span class="badge badge-red">CRITICAL</span></td>
      <td><code>block_and_capture</code><br>CVE-2019-0708, CVE-2023-38408</td>
    </tr>
    <tr>
      <td><code>RULE-002</code></td>
      <td><code>network_traffic</code><br>Escaneo TCP/SYN</td>
      <td>Real: <code>≥ 4</code> en <code>45 s</code> con <code>≥ 3</code> puertos distintos (o ráfaga <code>≥ 8</code>). Simulador: <code>≥ 4</code>.</td>
      <td><span class="badge badge-red">CRITICAL</span></td>
      <td><code>block_and_capture</code><br>CVE-2024-37032</td>
    </tr>
    <tr>
      <td><code>RULE-003</code></td>
      <td><code>windows_firewall</code><br>Violaciones DROP</td>
      <td>Real: <code>≥ 4</code> en <code>60 s</code> con <code>≥ 3</code> puertos distintos (o ráfaga <code>≥ 6</code>). Simulador: <code>≥ 4</code>.</td>
      <td><span class="badge badge-amber">HIGH</span></td>
      <td><code>block_and_capture</code><br>CVE-2015-3306</td>
    </tr>
    <tr>
      <td><code>RULE-004</code></td>
      <td><code>network_traffic</code><br>Sondeo HTTP / Log4Shell</td>
      <td><code>≥ 4</code> peticiones sospechosas en <code>60 s</code></td>
      <td><span class="badge badge-red">CRITICAL</span></td>
      <td><code>block_and_capture</code><br>CVE-2021-44228</td>
    </tr>
  </tbody>
</table>

<h3>Etapa 4 · Despacho, AutoBan en Firewall y Captura Forense (<code>dispatcher.py</code> y <code>mitigator.py</code>)</h3>
<ul>
  <li><strong>Aislamiento dinámico en Windows Defender Firewall:</strong> <code>block_ip()</code> valida la IP con <code>ipaddress.ip_address()</code> (<code>_safe_ip()</code>) y ejecuta sin shell: <code>netsh advfirewall firewall add rule name=NETTRAP-BLOCK-&lt;ip&gt; dir=in action=block remoteip=&lt;ip&gt; enable=yes</code>. Programa un <code>threading.Timer</code> de <code>300 s</code> para retirar la regla automáticamente (<code>_unblock_ip</code>) y registra la acción en <code>firewall_audit.jsonl</code>.</li>
  <li><strong>Captura Forense Inmutable (<code>.pcap</code>):</strong> <code>capture_pcap()</code> genera de inmediato un archivo binario estándar <strong>libpcap 2.4</strong> (magic <code>0xA1B2C3D4</code>, cabeceras Ethernet + IPv4 + TCP SYN) compatible con Wireshark. Si existe <code>tshark.exe</code>, ejecuta además una captura en vivo de 10 s filtrada por <code>host &lt;ip&gt;</code> y actualiza el archivo si captura paquetes reales.</li>
  <li><strong>Difusión WebSocket:</strong> <code>AlertDispatcher</code> coloca la alerta enriquecida en <code>ws_broadcast_queue</code> y la corrutina <code>broadcast_loop()</code> la envía en milisegundos a todos los navegadores conectados en <code>/ws/alerts</code>.</li>
</ul>

<h2>4. Módulos Auxiliares SOC, APIs y Controles Zero Trust</h2>

<div class="grid-2">
  <div class="card">
    <div class="card-title">Módulos Auxiliares (<code>soc_tools.py</code>)</div>
    <ul>
      <li><strong>Diagnóstico:</strong> Verifica <code>IsUserAnAdmin()</code>, legibilidad y política de <code>pfirewall.log</code>, acceso a <code>wevtutil gli Security</code> y presencia de TShark.</li>
      <li><strong>Analítica y Reporte HTML/PDF:</strong> Agrupa rankings de IPs, puertos (<code>PORT_SERVICES</code>), reglas, sensores y CVEs mitigados; escapa salidas con <code>html.escape()</code>.</li>
      <li><strong>Radar LAN:</strong> Refresca caché ARP enviando datagramas UDP vacíos al puerto <code>9</code> en la subred <code>/24</code>, lee <code>arp -a</code> y resuelve nombres en paralelo (<code>ThreadPoolExecutor</code>).</li>
    </ul>
  </div>

  <div class="card">
    <div class="card-title">Seguridad Aplicada (ISO / NIST / OWASP)</div>
    <ul>
      <li><strong>Validación estricta (OWASP ASVS V5.1.1):</strong> Uso obligatorio de <code>ipaddress</code> antes de invocar <code>netsh</code> o <code>tshark</code>; cero subprocesos con <code>shell=True</code>.</li>
      <li><strong>Anti-Path Traversal (CWE-22):</strong> Sanitización con <code>Path(filename).name</code> en descargas e inspecciones <code>/api/pcap/*</code>.</li>
      <li><strong>Protección DoS y Auth (OWASP V2.1/V3.2):</strong> Colas acotadas (<code>1000</code>/<code>500</code>), tokens CSPRNG de 32 bytes (<code>secrets.token_urlsafe</code>), <code>secrets.compare_digest</code> y lockout de 15 min tras 5 fallos en <code>/login</code>.</li>
      <li><strong>Trazabilidad (NIST PW.9.1 / OWASP V8.1.1):</strong> Registros append-only en <code>nettrap.log</code>, <code>audit.jsonl</code> y <code>firewall_audit.jsonl</code>.</li>
    </ul>
  </div>
</div>

<h2>5. Matriz Oficial de Vulnerabilidades NIST (CVE) Mitigadas</h2>
<table>
  <thead>
    <tr>
      <th style="width: 17%;">CVE / CVSS</th>
      <th style="width: 23%;">Servicio Afectado</th>
      <th style="width: 21%;">Fuente Primaria</th>
      <th>Vector y Mitigación Preventiva en NetTrap-IPS</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>CVE-2019-0708</strong><br><span class="badge badge-red">CVSS 9.8 Crítico</span></td>
      <td>Microsoft RDP (<em>BlueKeep</em>)</td>
      <td>Windows Event Log (EventID 4625)</td>
      <td>Detecta ráfagas de autenticación fallida o sondeos RDP en los registros de Windows y bloquea la IP en Firewall antes del exploit (ISO/IEC 27033-4 Cl. 9.2).</td>
    </tr>
    <tr>
      <td><strong>CVE-2024-37032</strong><br><span class="badge badge-red">CVSS 9.8 Crítico</span></td>
      <td>Ollama LLM Framework y APIs LAN</td>
      <td>Tráfico de Red y Sockets Activos</td>
      <td>Neutraliza la fase de reconocimiento SYN / escaneo Nmap cortando el tráfico del agresor antes de alcanzar APIs locales (ISO/IEC 27033-1 Cl. 10.3).</td>
    </tr>
    <tr>
      <td><strong>CVE-2023-38408</strong><br><span class="badge badge-red">CVSS 9.8 Crítico</span></td>
      <td>OpenSSH <code>ssh-agent</code></td>
      <td>Windows Event Log y Red</td>
      <td>Correlaciona intentos repetidos hacia servicios SSH y aísla al origen preservando captura forense <code>.pcap</code> (OWASP ASVS v5.0 V5.1.1).</td>
    </tr>
    <tr>
      <td><strong>CVE-2015-3306</strong><br><span class="badge badge-red">CVSS 10.0 Crítico</span></td>
      <td>ProFTPd (<code>mod_copy</code>)</td>
      <td>Windows Firewall (<code>DROP</code>)</td>
      <td>Identifica paquetes bloqueados reiteradamente hacia puertos restringidos y aplica AutoBan perimetral (NIST SP 800-218 PW.9.1).</td>
    </tr>
    <tr>
      <td><strong>CVE-2021-44228</strong><br><span class="badge badge-red">CVSS 10.0 Crítico</span></td>
      <td>Apache Log4j2 (<em>Log4Shell</em>)</td>
      <td>Tráfico HTTP y Sockets</td>
      <td>Detecta patrones de sondeo web malicioso e inyecciones JNDI lookup en cabeceras/rutas aislando la IP atacante (OWASP ASVS v5.0 V7.4.1).</td>
    </tr>
  </tbody>
</table>

<h2>6. APIs REST / WebSocket y Estructura del Proyecto</h2>
<table>
  <thead>
    <tr>
      <th style="width: 34%;">Endpoint HTTP / WebSocket</th>
      <th>Propósito operativo</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>GET /</code> · <code>GET /api/health</code></td>
      <td>Renderiza el Dashboard SOC principal (<code>dashboard.html</code>) y expone la sonda liviana de instancia activa (<code>{"app":"NetTrap-IPS","status":"ok"}</code>).</td>
    </tr>
    <tr>
      <td><code>GET /api/status</code> · <code>/api/sources</code> · <code>/api/cves</code></td>
      <td>Métricas globales por fuente, estado vivo de los 3 hilos recolectores y matriz oficial de CVEs mitigados.</td>
    </tr>
    <tr>
      <td><code>GET /api/alerts</code> · <code>GET /api/events</code> · <code>WS /ws/alerts</code></td>
      <td>Historial de alertas correlacionadas, eventos crudos normalizados y canal WebSocket en tiempo real hacia la consola web.</td>
    </tr>
    <tr>
      <td><code>POST /api/simulate</code> · <code>/api/block</code> · <code>/api/unblock/{ip}</code> · <code>/api/clear</code></td>
      <td>Simulador de laboratorio, bloqueo/desbloqueo manual en Windows Firewall y reinicio completo de contadores/cuarentena.</td>
    </tr>
    <tr>
      <td><code>GET /api/pcaps</code> · <code>/api/pcap/{f}</code> · <code>/api/pcap/inspect/{f}</code></td>
      <td>Listado, descarga segura anti-traversal y decodificación de encabezados Ethernet/IPv4/TCP de archivos <code>.pcap</code>.</td>
    </tr>
    <tr>
      <td><code>GET /api/diagnostics</code> · <code>/api/analytics</code> · <code>/api/report/html</code> · <code>/api/lan/scan</code> · <code>POST /api/nmap/audit</code></td>
      <td>Health check de Windows, analítica agregada, informe ejecutivo exportable a PDF, escáner ARP LAN y auditoría local de puertos.</td>
    </tr>
  </tbody>
</table>

<div class="callout callout-blue">
  <strong>Integrantes del Proyecto · Equipo CyberDefender (UNIPAZ):</strong> Michel Daniela Bayona Diaz (Seguridad &amp; Normas) · Margit Dayanna Barrera Gutiérrez (Backend &amp; Mitigación) · Said Alexander Pacheco Moncada (Líder Técnico &amp; Documentador).
</div>
"""
    return _wrap_html("Manual 3 · Funcionamiento Técnico de NetTrap-IPS", body)


def _find_browser() -> Path:
    for candidate in BROWSER_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("No se encontró Chrome ni Edge para renderizar los manuales PDF.")


def _render_html_to_pdf(browser_exe: Path, html_text: str, out_pdf: Path) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        html_path = Path(tmpdir) / f"{out_pdf.stem}.html"
        html_path.write_text(html_text, encoding="utf-8")
        cmd = [
            str(browser_exe),
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--no-pdf-header-footer",
            f"--print-to-pdf={out_pdf}",
            html_path.as_uri(),
        ]
        res = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
        if res.returncode != 0 or not out_pdf.exists() or out_pdf.stat().st_size < 1000:
            raise RuntimeError(
                f"Error generando {out_pdf.name}: rc={res.returncode} "
                f"{(res.stderr or b'').decode(errors='ignore')}"
            )


def main() -> None:
    browser = _find_browser()
    targets = [
        (ROOT_DIR / "Manual_1_Instalacion_NetTrap.pdf", build_manual_1_html()),
        (ROOT_DIR / "Manual_2_Uso_NetTrap.pdf", build_manual_2_html()),
        (ROOT_DIR / "Manual_3_Funcionamiento_NetTrap.pdf", build_manual_3_html()),
    ]
    for pdf_path, html_content in targets:
        _render_html_to_pdf(browser, html_content, pdf_path)
        kb = round(pdf_path.stat().st_size / 1024.0, 1)
        print(f"[OK] Generado {pdf_path.name} ({kb} KB)")


if __name__ == "__main__":
    main()
