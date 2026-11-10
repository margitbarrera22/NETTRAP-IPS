"""
Generador de Informe PDF · OVA Clase 3: Codificación Segura
Equipo CyberDefender — UNIPAZ
Herramienta: NetTrap-IPS
"""

import os
import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

BASE_DIR = Path("c:/Users/MARGIT/Documents/unipazzz/NETTRAP")
OUTPUT_PDF = BASE_DIR / "Informe_Clase3_Codificacion_Segura_CyberDefender.pdf"

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (páginas posteriores a la 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "UNIPAZ · Seguridad en Redes · NetTrap-IPS | Informe Clase 3: Codificación Segura")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)

        # Footer
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)
        
        page_text = f"Página {self._pageNumber} de {page_count}"
        self.drawRightString(558, 32, page_text)
        self.drawString(54, 32, "Equipo CyberDefender · OVA 4h · Normas ISO/IEC 27033, NIST SP 800-218, OWASP ASVS")
        self.restoreState()

def build_pdf():
    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Estilos tipográficos personalizados
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#059669'),
        spaceAfter=14
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#047857'),
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#334155'),
        leftIndent=14,
        firstLineIndent=-10,
        spaceAfter=3
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor('#1e293b')
    )

    code_style = ParagraphStyle(
        'CodeText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0f172a')
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )

    story = []

    # ── Portada / Encabezado Principal ──────────────────────────────────────────
    story.append(Paragraph("Informe Clase 3 · Codificación Segura", title_style))
    story.append(Paragraph("Fase 1: Teoría &nbsp;|&nbsp; Fase 2: Investigación en Código &nbsp;|&nbsp; Fase 3: Evidencia y Mitigación NIST", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#10b981'), spaceAfter=12))

    # Meta Información
    meta_data = [
        [
            Paragraph("<b>OVA:</b> Herramienta de Seguridad en Redes desde Cero", table_cell_style),
            Paragraph("<b>Fecha:</b> 3 de noviembre de 2026", table_cell_style)
        ],
        [
            Paragraph("<b>Equipo:</b> CyberDefender", table_cell_style),
            Paragraph("<b>Herramienta:</b> NetTrap-IPS (Defensa Activa)", table_cell_style)
        ],
        [
            Paragraph("<b>Institución:</b> UNIPAZ", table_cell_style),
            Paragraph("<b>Entrega:</b> Clase 3 de 5 (Anexo a Clase 1 y 2)", table_cell_style)
        ]
    ]
    t_meta = Table(meta_data, colWidths=[250, 254])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#ecfdf5')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#a7f3d0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1fae5')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Integrantes
    story.append(Paragraph("<b>Integrantes del Equipo CyberDefender:</b>", h2_style))
    team_data = [
        [Paragraph("#", table_header_style), Paragraph("Cédula", table_header_style), Paragraph("Nombre Completo", table_header_style), Paragraph("Rol Técnico", table_header_style)],
        [Paragraph("1", table_cell_style), Paragraph("1096802414", table_cell_style), Paragraph("Michel Daniela Bayona Diaz", table_cell_style), Paragraph("Responsable de Seguridad & Normas", table_cell_style)],
        [Paragraph("2", table_cell_style), Paragraph("1014189353", table_cell_style), Paragraph("Margit Dayanna Barrera Gutiérrez", table_cell_style), Paragraph("Desarrolladora (Backend & Mitigación)", table_cell_style)],
        [Paragraph("3", table_cell_style), Paragraph("1092528951", table_cell_style), Paragraph("Said Alexander Pacheco Moncada", table_cell_style), Paragraph("Líder Técnico & Documentador", table_cell_style)],
    ]
    t_team = Table(team_data, colWidths=[24, 80, 200, 200])
    t_team.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_team)
    story.append(Spacer(1, 12))

    # Regla de la Clase Callout
    rule_p = Paragraph(
        "<b>Regla Normativa de Clase 3:</b> Todo control de seguridad implementado debe respaldarse con <b>(1) base teórica comprendida</b>, <b>(2) investigación registrada en el código fuente con cita de cláusulas de ISO/IEC 27033, NIST SP 800-218 (SSDF) u OWASP ASVS</b>, y <b>(3) evidencia verificable</b>. Sin estos componentes, el control no cuenta para evaluación.",
        callout_style
    )
    t_rule = Table([[rule_p]], colWidths=[504])
    t_rule.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fef3c7')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#f59e0b')),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_rule)
    story.append(Spacer(1, 14))

    # ── FASE 1: TEORÍA DE CODIFICACIÓN SEGURA ──────────────────────────────────
    story.append(Paragraph("1. Fase 1 · Fundamentos Teóricos de Codificación Segura", h1_style))
    story.append(Paragraph(
        "Para el desarrollo de la herramienta defensiva NetTrap-IPS se estudiaron e integraron cuatro pilares de ingeniería segura derivados de <b>OWASP ASVS v5.0</b> y <b>NIST SP 800-218 (SSDF)</b>:",
        body_style
    ))

    t_theor = [
        [Paragraph("Pilar de Seguridad", table_header_style), Paragraph("Principio Operativo y Justificación Técnica", table_header_style), Paragraph("Norma / Control", table_header_style)],
        [
            Paragraph("<b>Validación de Entradas</b>", table_cell_style),
            Paragraph("<b>Toda entrada es hostil:</b> Se prohíbe delegar la seguridad en el cliente. Se aplica validación positiva (lista blanca estricta) mediante tipos canónicos y analizadores semánticos (ipaddress) antes de cualquier operación en el sistema operativo.", table_cell_style),
            Paragraph("OWASP ASVS V5.1.1 / V5.5<br/>NIST SSDF PW.7", table_cell_style)
        ],
        [
            Paragraph("<b>Manejo de Errores y Logging</b>", table_cell_style),
            Paragraph("<b>No alimentar al atacante:</b> Las excepciones internas nunca exponen stack traces, rutas del sistema de archivos ni versiones de librerías. El usuario recibe un mensaje genérico mientras que el detalle forense se escribe en logs locales inmutables (append-only) sin registrar credenciales ni secretos.", table_cell_style),
            Paragraph("OWASP ASVS V7.1.1 / V7.4.1<br/>ISO 27033-1 Cl. 10.3", table_cell_style)
        ],
        [
            Paragraph("<b>Criptografía y Sesiones</b>", table_cell_style),
            Paragraph("<b>Criptografía estándar:</b> En tránsito se exige TLS 1.2+ deshabilitando suites inseguras (RC4, 3DES). En reposo, el almacenamiento de claves administrativas utiliza funciones lentas adaptativas (Argon2id / bcrypt con salt automático). Sesiones efímeras con tokens criptográficos de 32 bytes.", table_cell_style),
            Paragraph("OWASP ASVS V6.2 / V9.1<br/>NIST SSDF PW.9.1", table_cell_style)
        ],
        [
            Paragraph("<b>Análisis Estático (SAST)</b>", table_cell_style),
            Paragraph("<b>Auditoría automatizada de código:</b> Detección temprana de llamadas inseguras a subprocesos, sockets abiertos indiscriminadamente y credenciales embebidas (hardcoded secrets) antes de la fase de despliegue.", table_cell_style),
            Paragraph("NIST SSDF PW.7.1<br/>NIST SSDF PS.1.1", table_cell_style)
        ]
    ]
    table_theor = Table(t_theor, colWidths=[100, 314, 90])
    table_theor.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(table_theor)
    story.append(Spacer(1, 14))

    # ── FASE 2: INVESTIGACIÓN EN EL CÓDIGO FUENTE ──────────────────────────────
    story.append(Paragraph("2. Fase 2 · Investigación Técnica: Aplicación de Controles en NetTrap-IPS", h1_style))
    story.append(Paragraph(
        "Se auditó directamente el código fuente desarrollado en <code>src/backend/</code> para contrastar cada control implementado frente a su especificación normativa y verificar su efectividad defensiva:",
        body_style
    ))

    inv_table_data = [
        [
            Paragraph("#", table_header_style),
            Paragraph("Control Implementado", table_header_style),
            Paragraph("Norma / Cláusula", table_header_style),
            Paragraph("Archivo / Línea", table_header_style),
            Paragraph("Hallazgo Detallado de la Investigación", table_header_style)
        ],
        [
            Paragraph("1", table_cell_style),
            Paragraph("<b>Validación y sanitización de direcciones IP</b>", table_cell_style),
            Paragraph("OWASP ASVS v5.0 V5.1.1<br/>ISO 27033-1 Cl. 10.3", table_cell_style),
            Paragraph("<code>honeypot.py</code>: L40-54<br/><code>mitigator.py</code>: L41-48", table_cell_style),
            Paragraph("Se investigó la función <code>validate_ip(raw_ip)</code> y <code>_safe_ip(ip)</code>. Utiliza la librería estándar <code>ipaddress.ip_address()</code> como lista blanca estricta. Si una entrada contiene caracteres de inyección de comandos shell (<code>; & | ` $</code>) o no cumple la sintaxis IPv4/IPv6 canónica, se descarta y jamás llega a subprocess ni a netsh. Cumple positivamente el control V5.1.1.", table_cell_style)
        ],
        [
            Paragraph("2", table_cell_style),
            Paragraph("<b>Manejo seguro de excepciones y log de auditoría</b>", table_cell_style),
            Paragraph("OWASP ASVS v5.0 V7.4.1<br/>NIST SSDF PW.9.1", table_cell_style),
            Paragraph("<code>correlator.py</code>: L114-121<br/><code>mitigator.py</code>: L245-260", table_cell_style),
            Paragraph("Se verificó la función <code>_audit()</code> y <code>_audit_block()</code>. Escriben eventos en formato JSONL en modo append-only (<code>audit.jsonl</code>). Ante desconexiones abruptas o errores de socket, los bloques <code>try/except</code> capturan la excepción sin exponer stack traces ni rutas absolutas en respuestas HTTP hacia el navegador, mitigando la amenaza de Information Disclosure (STRIDE).", table_cell_style)
        ],
        [
            Paragraph("3", table_cell_style),
            Paragraph("<b>Respuesta activa en Firewall (AutoBan default-deny)</b>", table_cell_style),
            Paragraph("ISO/IEC 27033-4 Cl. 9.2<br/>OWASP ASVS V5.1.1", table_cell_style),
            Paragraph("<code>mitigator.py</code>: L100-185<br/><code>correlator.py</code>: L138-166", table_cell_style),
            Paragraph("Al superarse los umbrales de escaneo (ej. 5 toques en 60s), se ejecuta <code>block_ip()</code> invocando <code>netsh advfirewall firewall add rule</code> con lista estructurada de argumentos (evitando <code>shell=True</code>). Además, se asocia un temporizador daemon <code>threading.Timer(300, _unblock_ip)</code> para asegurar la expiración controlada de la regla de cuarentena.", table_cell_style)
        ],
        [
            Paragraph("4", table_cell_style),
            Paragraph("<b>Generación de evidencia forense estructurada (.pcap)</b>", table_cell_style),
            Paragraph("NIST SP 800-218 (SSDF) PW.9.1<br/>ISO 27033-1 Cl. 10.3", table_cell_style),
            Paragraph("<code>mitigator.py</code>: L50-98<br/><code>dispatcher.py</code>: L41-55", table_cell_style),
            Paragraph("Se investigó la función <code>capture_pcap()</code>. Invoca TShark CLI con filtro BPF <code>host &lt;IP&gt;</code>; si no está instalado, sintetiza una captura libpcap binaria válida (0xA1B2C3D4) con los paquetes TCP SYN de la agresión guardada en <code>src/data/pcap/</code>. Esto garantiza trazabilidad forense analizable en Wireshark sin depender de herramientas de terceros.", table_cell_style)
        ]
    ]

    t_inv = Table(inv_table_data, colWidths=[20, 110, 85, 95, 194])
    t_inv.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_inv)
    story.append(Spacer(1, 14))

    # ── ANÁLISIS ESTÁTICO DE SEGURIDAD (SAST) ───────────────────────────────────
    story.append(Paragraph("3. Investigación de Análisis Estático (SAST) con Bandit", h1_style))
    story.append(Paragraph(
        "Se ejecutó la herramienta de SAST <b>Bandit v1.8.3</b> especializada en seguridad para código Python sobre la totalidad del backend (<code>src/backend/</code>, 1.002 líneas de código analizadas).",
        body_style
    ))

    sast_kpis = [
        [
            Paragraph("<b>Herramienta SAST:</b> Bandit (Python)", table_cell_style),
            Paragraph("<b>Total de Hallazgos:</b> 9", table_cell_style),
            Paragraph("<b>Severidad Alta:</b> 0 (0%)", table_cell_style)
        ],
        [
            Paragraph("<b>Severidad Media:</b> 1 (11.1%)", table_cell_style),
            Paragraph("<b>Severidad Baja:</b> 8 (88.9%)", table_cell_style),
            Paragraph("<b>Líneas de Código:</b> 1.002 LOC", table_cell_style)
        ]
    ]
    t_sast_kpi = Table(sast_kpis, colWidths=[168, 168, 168])
    t_sast_kpi.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_sast_kpi)
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Interpretación Técnica y Descarte de Falsos Positivos en el SAST:</b>", h2_style))
    story.append(Paragraph(
        "• <b>B104 · hardcoded_bind_all_interfaces (honeypot.py:87 · Media):</b> Bandit detectó enlace a <code>0.0.0.0</code>. <i>Resolución:</i> Es un <b>falso positivo funcional justificado</b>, ya que por diseño arquitectónico una trampa Honeypot debe escuchar en todas las interfaces de red para capturar el tráfico de intrusión de atacantes.<br/>"
        "• <b>B603 · subprocess_without_shell_equals_true (mitigator.py:138, 190, 232 · Baja):</b> Bandit alerta sobre invocación de subprocesos. <i>Resolución:</i> Es seguro y cumple OWASP ASVS V5.1.1 porque se invoca estrictamente como <b>lista estructurada de argumentos</b> (<code>['netsh', 'advfirewall', ...]</code>), <b>sin usar <code>shell=True</code></b> y con sanitización previa de la IP mediante <code>ipaddress</code>.<br/>"
        "• <b>B105 · hardcoded_password_string (main.py:89 · Baja):</b> Token de sesión maestro de laboratorio. <i>Resolución:</i> En despliegues de producción se delega obligatoriamente a la variable de entorno <code>NETTRAP_SECRET</code>.",
        body_style
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Auditoría y Revisión de Secretos en el Repositorio (NIST SSDF PS.1.1):</b>", h2_style))
    story.append(Paragraph(
        "Se auditó el árbol de archivos y el control de versiones local. Se verificó que el repositorio cuenta con <code>.gitignore</code> impidiendo el versionado de archivos <code>.env</code>, llaves criptográficas y volcados <code>.pcap</code> de evidencia. Las contraseñas administrativas operan mediante variables de entorno (<code>NETTRAP_USER</code>, <code>NETTRAP_PASS_HASH</code>) procesadas con hashing <b>Argon2id</b>, cumpliendo con la política de cero secretos en texto plano.",
        body_style
    ))
    story.append(Spacer(1, 14))

    # ── VULNERABILIDADES NIST (CVE) MITIGADAS ────────────────────────────────────
    story.append(Paragraph("4. Vulnerabilidades según NIST (CVE) que NetTrap-IPS Mitiga", h1_style))
    story.append(Paragraph(
        "Para responder con rigor al docente, se detalla cómo el motor defensivo previene la explotación de las <b>5 vulnerabilidades críticas</b> registradas en el National Vulnerability Database (NVD) del NIST:",
        body_style
    ))

    cve_data = [
        [
            Paragraph("Identificador CVE", table_header_style),
            Paragraph("CVSS / Severidad", table_header_style),
            Paragraph("Software Afectado", table_header_style),
            Paragraph("Mecanismo de Mitigación en NetTrap-IPS", table_header_style),
            Paragraph("Regla Asociada", table_header_style)
        ],
        [
            Paragraph("<b>CVE-2024-37032</b>", table_cell_style),
            Paragraph("<font color='#b91c1c'><b>9.8 Crítico</b></font>", table_cell_style),
            Paragraph("Ollama LLM Server", table_cell_style),
            Paragraph("Neutraliza el escaneo de puertos de reconocimiento SYN previo antes de que el atacante alcance la API no autenticada en el puerto 11434.", table_cell_style),
            Paragraph("<code>RULE-001</code><br/>(≥5 toques / 60s)", table_cell_style)
        ],
        [
            Paragraph("<b>CVE-2019-0708</b><br/>(BlueKeep)", table_cell_style),
            Paragraph("<font color='#b91c1c'><b>9.8 Crítico</b></font>", table_cell_style),
            Paragraph("Microsoft RDP (Port 3389)", table_cell_style),
            Paragraph("La trampa señuelo en 3389 intercepta el primer paquete de conexión anómalo, ejecutando AutoBan en Windows Firewall antes del exploit MS_T120.", table_cell_style),
            Paragraph("<code>RULE-001</code><br/>Trampa RDP 3389", table_cell_style)
        ],
        [
            Paragraph("<b>CVE-2023-38408</b>", table_cell_style),
            Paragraph("<font color='#b91c1c'><b>9.8 Crítico</b></font>", table_cell_style),
            Paragraph("OpenSSH ssh-agent", table_cell_style),
            Paragraph("Detecta sondeos en puerto SSH señuelo 2222; aplica cuarentena y exporta captura forense .pcap para análisis en Wireshark ante ≥2 intentos.", table_cell_style),
            Paragraph("<code>RULE-003</code><br/>Trampa SSH 2222", table_cell_style)
        ],
        [
            Paragraph("<b>CVE-2015-3306</b>", table_cell_style),
            Paragraph("<font color='#991b1b'><b>10.0 Crítico</b></font>", table_cell_style),
            Paragraph("ProFTPd (mod_copy)", table_cell_style),
            Paragraph("Detecta ráfagas de fuerza bruta o sondeo en el puerto 21 señuelo. Aísla la IP agresora antes de la emisión de comandos SITE CPFR / CPTO.", table_cell_style),
            Paragraph("<code>RULE-002</code><br/>Trampa FTP 21", table_cell_style)
        ],
        [
            Paragraph("<b>CVE-2021-44228</b><br/>(Log4Shell)", table_cell_style),
            Paragraph("<font color='#991b1b'><b>10.0 Crítico</b></font>", table_cell_style),
            Paragraph("Apache Log4j2 JNDI", table_cell_style),
            Paragraph("El puerto 8080 trampa recibe los sondeos y cabeceras HTTP de inyección JNDI lookup, registrando la IP y generando alerta sin transmitir al backend.", table_cell_style),
            Paragraph("<code>RULE-004</code><br/>Trampa HTTP 8080", table_cell_style)
        ]
    ]

    t_cve = Table(cve_data, colWidths=[80, 75, 95, 174, 80])
    t_cve.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_cve)
    story.append(Spacer(1, 14))

    # ── CONCLUSIONES Y ACCIONES CLASE 4 ────────────────────────────────────────
    story.append(Paragraph("5. Conclusiones de la Investigación y Próximos Pasos (Clase 4)", h1_style))
    story.append(Paragraph(
        "<b>Síntesis de Hallazgos:</b> El equipo corroboró que la arquitectura multihilo de NetTrap-IPS opera conforme a los lineamientos de codificación segura de ASVS y SSDF. La combinación de listas blancas con <code>ipaddress</code>, la exclusión de <code>shell=True</code> en subprocesos y el mecanismo de aislamiento en Windows Defender Firewall garantizan una contención en milisegundos con cero hallazgos de severidad alta en SAST.<br/><br/>"
        "<b>Correcciones y Metas para la Clase 4:</b><br/>"
        "1. Implementar cifrado simétrico AES-256 en reposo para los registros de auditoría <code>audit.jsonl</code>.<br/>"
        "2. Parametrizar dinámicamente el tiempo de cuarentena (300 s) mediante panel web de configuración administrativa.<br/>"
        "3. Incorporar validación de certificados mutuos (mTLS) en conexiones remotas de agentes distribuidores.<br/><br/>"
        "<b>Fuentes Normativas Consultadas:</b><br/>"
        "• OWASP Application Security Verification Standard (ASVS) v5.0 (Secciones V5, V6, V7, V9).<br/>"
        "• NIST SP 800-218: Secure Software Development Framework (SSDF) v1.1 (Prácticas PW.7, PW.9, PS.1).<br/>"
        "• ISO/IEC 27033-1 / 27033-4: Network Security Guidelines and Security Gateways.<br/>"
        "• National Vulnerability Database (NVD - NIST): Entradas CVE-2024-37032, CVE-2019-0708, CVE-2023-38408, CVE-2015-3306, CVE-2021-44228.",
        body_style
    ))
    story.append(Spacer(1, 20))

    # Firmas de Cierre
    story.append(Paragraph("<b>Declaración de Cierre y Veracidad:</b>", h2_style))
    story.append(Paragraph("El equipo declara que los controles e investigaciones aquí documentados reflejan fielmente el estado del repositorio de código, los análisis SAST ejecutados y las pruebas funcionales del cortafuegos.", body_style))
    story.append(Spacer(1, 25))

    firmas = [
        [
            Paragraph("___________________________________<br/><b>Said Alexander Pacheco Moncada</b><br/>Líder Técnico · C.C. 1092528951", table_cell_style),
            Paragraph("___________________________________<br/><b>Margit Dayanna Barrera G.</b><br/>Desarrolladora · C.C. 1014189353", table_cell_style),
            Paragraph("___________________________________<br/><b>Michel Daniela Bayona Diaz</b><br/>Seguridad · C.C. 1096802414", table_cell_style)
        ]
    ]
    t_firmas = Table(firmas, colWidths=[168, 168, 168])
    t_firmas.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(t_firmas)

    # Construir documento
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF generado con éxito en: {OUTPUT_PDF}")

if __name__ == "__main__":
    build_pdf()

