#!/usr/bin/env python3
# =============================================================================
# ███████╗██████╗ ██╗██████╗ ███████╗██████╗ 
# ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
# ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
# ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
# ███████║██║     ██║██████╔╝███████╗██║  ██║
# ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
#
# ███╗   ██╗ ██████╗ ██╗██████╗ 
# ████╗  ██║██╔═══██╗██║██╔══██╗
# ██╔██╗ ██║██║   ██║██║██████╔╝
# ██║╚██╗██║██║   ██║██║██╔══██╗
# ██║ ╚████║╚██████╔╝██║██║  ██║
# ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
#
# Spider Noir — Recon Pipeline v2.0
# Autor: rk103
# Descripción: Framework de recon web que unifica subfinder, katana y ffuf
#              en un grafo SVG interactivo con panel de acciones.
# Target: Parrot OS / Kali Linux | HTB / Bug Bounty Environments
# =============================================================================

import os
import sys
import json
import subprocess
import shutil
import re
import time
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urljoin

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCIA PRINCIPAL: pyvis para el grafo interactivo
# Instalación: pip install pyvis
# ─────────────────────────────────────────────────────────────────────────────
try:
    from pyvis.network import Network
except ImportError:
    print("\n[!] pyvis no está instalado. Ejecutá: pip install pyvis")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCIA SECUNDARIA: rich para progreso visual en tiempo real
# Instalación: pip install rich
# ─────────────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, MofNCompleteColumn,
    )
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None
    print("\n[!] rich no está instalado (progreso visual desactivado). Ejecutá: pip install rich")


# =============================================================================
# CONSTANTES DE COLOR Y ESTILO DEL GRAFO
# =============================================================================
COLOR_SEED      = "#FFD700"   # Dorado  → Nodo raíz / semilla
COLOR_VHOST     = "#9B59B6"   # Violeta → Nodos de VHOST / subdominio
COLOR_SUBDOMAIN = "#8E44AD"   # Violeta oscuro → Subdominios descubiertos por subfinder
COLOR_VISIBLE   = "#1f77b4"   # Azul    → URLs descubiertas por Katana (crawling)
COLOR_HIDDEN_OK = "#FF8C00"   # Naranja → ffuf: HTTP 200 / 301 (rutas ocultas)
COLOR_HIDDEN_F  = "#E74C3C"   # Rojo    → ffuf: HTTP 403 Forbidden
COLOR_INFO      = "#2ECC71"   # Verde   → Metadatos / nodos informativos
COLOR_FORM      = "#E91E63"   # Rosa    → Nodos con formularios/inputs detectados

# Paleta de tecnología detectada (para colorear nodos según stack)
TECH_COLORS = {
    "php":    "#8892BF",   # Azul PHP
    "asp":    "#5C2D91",   # Violeta ASP.NET
    "java":   "#F89820",   # Naranja Java/JSP
    "python": "#3776AB",   # Azul Python
    "ruby":   "#CC342D",   # Rojo Ruby
    "node":   "#68A063",   # Verde Node.js
    "nginx":  "#009900",   # Verde Nginx
    "apache": "#D22128",   # Rojo Apache
}

def detect_tech(headers: dict, content_type: str, url: str) -> str:
    """
    Detecta la tecnología del servidor a partir de headers HTTP y la URL.
    Retorna un string con la tecnología detectada o "" si no se identifica.
    Prioriza la info más específica (lenguaje sobre servidor web).
    """
    # Normalizar headers a lowercase para comparación uniforme
    h = {k.lower(): v.lower() if isinstance(v, str) else v
         for k, v in (headers or {}).items()}

    powered = h.get("x-powered-by", "")
    server  = h.get("server", "")
    cookie  = h.get("set-cookie", "")

    # Detectar por extensión de URL (más confiable)
    url_lower = url.lower()
    if url_lower.endswith((".php", ".php5", ".phtml")):
        return "php"
    if url_lower.endswith((".asp", ".aspx", ".ashx")):
        return "asp"
    if url_lower.endswith((".jsp", ".jspa", ".do", ".action")):
        return "java"
    if url_lower.endswith(".py"):
        return "python"
    if url_lower.endswith(".rb"):
        return "ruby"

    # Detectar por X-Powered-By
    if "php" in powered:
        return "php"
    if "asp.net" in powered or "aspnet" in powered:
        return "asp"
    if "express" in powered or "node" in powered:
        return "node"

    # Detectar por Server header
    if "nginx" in server:
        return "nginx"
    if "apache" in server:
        return "apache"
    if "iis" in server:
        return "asp"
    if "gunicorn" in server or "uvicorn" in server or "werkzeug" in server:
        return "python"
    if "tomcat" in server or "jetty" in server:
        return "java"

    # Detectar por cookies de sesión
    if "phpsessid" in cookie:
        return "php"
    if "jsessionid" in cookie:
        return "java"
    if "asp.net_sessionid" in cookie or "aspsessionid" in cookie:
        return "asp"

    return ""

# =============================================================================
# SECCIÓN 1: UTILIDADES DE CONSOLA
# =============================================================================

def banner():
    """
    Imprime el banner ASCII completo con degradado de color ANSI,
    arte ASCII del título y firma del autor (rk103).

    Técnica de degradado: se itera línea a línea del arte ASCII y se
    asigna un código de color ANSI 256 distinto por línea, creando
    una transición visual de cian → azul → violeta.
    """

    # Arte ASCII del título generado con estilo "ANSI Shadow"
    # Cada línea se colorea individualmente para el efecto degradado
    title_lines = [
        r" ███████╗██████╗ ██╗██████╗ ███████╗██████╗ ",
        r" ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗",
        r" ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝",
        r" ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗",
        r" ███████║██║     ██║██████╔╝███████╗██║  ██║",
        r" ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝",
        r"",
        r"  ███╗   ██╗ ██████╗ ██╗██████╗ ",
        r"  ████╗  ██║██╔═══██╗██║██╔══██╗",
        r"  ██╔██╗ ██║██║   ██║██║██████╔╝",
        r"  ██║╚██╗██║██║   ██║██║██╔══██╗",
        r"  ██║ ╚████║╚██████╔╝██║██║  ██║",
        r"  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝",
    ]

    # Paleta noir: gris oscuro → blanco puro
    gradient = [
        245, 248, 251, 254, 251, 248,
        0,
        240, 243, 247, 250, 253, 255,
    ]

    print()  # Margen superior

    for i, line in enumerate(title_lines):
        color_code = gradient[i] if i < len(gradient) else 99
        if line.strip():
            print(f"\033[38;5;{color_code}m{line}\033[0m")
        else:
            print()

    # ── Separador y subtítulo ────────────────────────────────────────────────
    sep   = "─" * 72
    print(f"\033[38;5;240m  {sep}\033[0m")

    # Línea de descripción centrada
    desc  = "  Subfinder  ►  Katana Crawler  ►  ffuf Fuzzer  ►  SVG Graph"
    tags  = "  HTB  ·  Bug Bounty  ·  Web Auditing  ·  Red Team Recon"
    print(f"\033[38;5;75m{desc}\033[0m")
    print(f"\033[38;5;240m{tags}\033[0m")

    print(f"\033[38;5;240m  {sep}\033[0m")

    # ── Firma del autor y versión ────────────────────────────────────────────
    version  = "v2.0"
    author   = "rk103"
    year     = datetime.now().strftime("%Y")

    print(
        f"  \033[38;5;240mFramework by\033[0m "
        f"\033[38;5;208m{author}\033[0m"
        f"\033[38;5;240m  ·  {version}  ·  {year}  ·  "
        f"github.com/{author}\033[0m"
    )
    print()


def log(level: str, msg: str):
    """
    Logger con colores ANSI para la consola.
    Niveles: INFO, OK, WARN, ERROR, PHASE
    """
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO":  "\033[94m[*]\033[0m",   # Azul
        "OK":    "\033[92m[+]\033[0m",   # Verde
        "WARN":  "\033[93m[!]\033[0m",   # Amarillo
        "ERROR": "\033[91m[✗]\033[0m",   # Rojo
        "PHASE": "\033[95m[►]\033[0m",   # Magenta
    }
    prefix = colors.get(level, "[?]")
    print(f"  {prefix} \033[90m{ts}\033[0m  {msg}")


def check_tool(tool_name: str) -> bool:
    """
    Verifica si una herramienta externa está disponible en el PATH del sistema.
    Retorna True si existe, False si no.
    """
    if shutil.which(tool_name) is None:
        log("WARN", f"'{tool_name}' no found in PATH. Instalalo antes de continuar.")
        return False
    log("OK", f"'{tool_name}' found in PATH.")
    return True


def sanitize_filename(name: str) -> str:
    """
    Limpia un string para usarlo como nombre de archivo seguro,
    reemplazando caracteres especiales por guiones bajos.
    """
    return re.sub(r"[^\w\-_.]", "_", name)


# =============================================================================
# SECCIÓN 2: RECOLECCIÓN DE PARÁMETROS INTERACTIVOS
# =============================================================================

def parse_hackerone_csv(filepath: str) -> dict:
    """
    Parsea el CSV de scope exportado desde HackerOne y extrae los targets
    web (URL y WILDCARD) que están in-scope (eligible_for_submission=true).

    Formato del CSV de HackerOne:
      identifier, asset_type, instruction, eligible_for_bounty,
      eligible_for_submission, availability_requirement, ...

    Retorna un dict con:
      {
        "wildcards":   ["*.gogoflight.com", "*.gogoair.com"],
        "exact_urls":  ["api.gogo.com", "portal.gogo.com"],
        "out_of_scope":["hr.gogo.com"],
        "skipped":     ["Android App", "iOS App"],  # assets no-web
        "raw_rows":    [...]  # todas las filas para referencia
      }
    """
    import csv

    result = {
        "wildcards":    [],
        "exact_urls":   [],
        "out_of_scope": [],
        "skipped":      [],
        "raw_rows":     [],
    }

    WEB_TYPES = {"url", "wildcard", "domain"}   # asset_types web relevantes

    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            # Detectar el delimitador automáticamente (HackerOne usa coma)
            sample  = f.read(2048)
            f.seek(0)
            dialect = csv.Sniffer().sniff(sample, delimiters=",;	")
            reader  = csv.DictReader(f, dialect=dialect)

            for row in reader:
                result["raw_rows"].append(row)

                # Normalizar nombres de columnas (pueden tener espacios o mayúsculas)
                norm = {k.strip().lower(): v.strip() for k, v in row.items()}

                identifier   = norm.get("identifier", "").strip()
                asset_type   = norm.get("asset_type", "").strip().lower()
                eligible     = norm.get("eligible_for_submission", "true").strip().lower()

                if not identifier:
                    continue

                # Filtrar assets no-web (mobile apps, source code, etc.)
                if asset_type not in WEB_TYPES and asset_type != "":
                    result["skipped"].append(f"{identifier} ({asset_type})")
                    continue

                # Separar in-scope vs out-of-scope
                if eligible in ("false", "no", "0"):
                    result["out_of_scope"].append(identifier)
                    continue

                # Clasificar wildcards vs URLs exactas
                if identifier.startswith("*."):
                    result["wildcards"].append(identifier)
                elif "*" in identifier:
                    # Wildcard en otro formato (ej: *.*.gogo.com) → tratar como wildcard
                    result["wildcards"].append(identifier)
                else:
                    # Limpiar esquema si lo tiene (el CSV a veces incluye https://)
                    clean = identifier.replace("https://", "").replace("http://", "").rstrip("/")
                    result["exact_urls"].append(clean)

    except FileNotFoundError:
        log("ERROR", f"CSV no encontrado: {filepath}")
    except Exception as e:
        log("ERROR", f"Error al parsear CSV de HackerOne: {e}")

    return result


def parse_burp_scope(filepath: str) -> dict:
    """
    Parsea el archivo de configuración de scope de Burp Suite (JSON).
    Burp exporta el scope como un JSON con estructura:
      { "target": { "scope": { "include": [...], "exclude": [...] } } }

    Retorna el mismo formato que parse_hackerone_csv para uniformidad.
    """
    import json

    result = {
        "wildcards":    [],
        "exact_urls":   [],
        "out_of_scope": [],
        "skipped":      [],
        "raw_rows":     [],
    }

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        scope   = data.get("target", {}).get("scope", {})
        include = scope.get("include", [])
        exclude = scope.get("exclude", [])

        for entry in include:
            host = entry.get("host", "").strip()
            if not host:
                continue
            if host.startswith(".*") or "*" in host:
                # Convertir regex de Burp a wildcard estándar
                # Burp usa ".*\.gogo\.com" → "*.gogo.com"
                clean = host.replace(".*.", "*.").replace("\\.", ".")
                result["wildcards"].append(clean)
            else:
                result["exact_urls"].append(host)

        for entry in exclude:
            host = entry.get("host", "").strip()
            if host:
                result["out_of_scope"].append(host)

    except FileNotFoundError:
        log("ERROR", f"Archivo Burp no encontrado: {filepath}")
    except Exception as e:
        log("ERROR", f"Error al parsear scope de Burp: {e}")

    return result


def _load_vhosts_input(prompt_label: str) -> list:
    """
    Helper reutilizable: pide al usuario una lista de VHOSTs
    ya sea como texto separado por comas o como ruta a un archivo .txt.
    Retorna la lista limpia o [] si no se ingresó nada.
    """
    print(f"\n      Podés ingresar para {prompt_label}:")
    print("        · Lista separada por comas: dev.htb,admin.htb,api.htb")
    print("        · Ruta a un archivo .txt con un VHOST por línea\n")
    raw = input(f"  \033[96m[?]\033[0m [{prompt_label}] VHOSTs o ruta al archivo: ").strip()
    if not raw:
        return []
    if Path(raw).is_file():
        with open(raw, "r") as fh:
            vhosts = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        log("OK", f"{prompt_label}: {len(vhosts)} VHOSTs cargados desde archivo.")
        return vhosts
    vhosts = [v.strip() for v in raw.split(",") if v.strip()]
    log("OK", f"{prompt_label}: {len(vhosts)} VHOSTs cargados desde input manual.")
    return vhosts


def collect_inputs() -> dict:
    """
    Interfaz interactiva por consola organizada en bloques temáticos:

      BLOQUE 0a — Perfil del tester: headers de identificación y rate limit.
      BLOQUE 0  — Target global (URL + puerto): base común a todo el pipeline.
      BLOQUE 0b — Subfinder: enumeración pasiva de subdomains.
      BLOQUE 1  — Katana (Crawler): qué hosts crawlear. SIN wordlist.
      BLOQUE 2  — ffuf (Fuzzer): qué hosts fuzzear + wordlist obligatoria.
      BLOQUE 3  — Scope: filtro de URLs aplicado a Katana.
      BLOQUE 4  — Grafo: profundidad y límite de nodos en PyVis.

    Retorna un diccionario con toda la configuración de la sesión.
    """

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 0a — TESTER PROFILE
    # Configuración global que aplica a TODAS las herramientas del pipeline.
    # Algunos programas de Bug Bounty exigen identificar el tráfico de recon
    # con un header HTTP custom para diferenciarlo de actividad maliciosa.
    # Rate limit protects the target and prevents IP blocking.
    # ══════════════════════════════════════════════════════════════════════════
    print("\n\033[38;5;220m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;220m  ║  BLOCK 0a — TESTER PROFILE                                   ║\033[0m")
    print("\033[38;5;220m  ║  Identification headers + rate limit for Bug Bounty.         ║\033[0m")
    print("\033[38;5;220m  ║  Applied to Katana, ffuf and subfinder automatically.           ║\033[0m")
    print("\033[38;5;220m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    config = {}

    # ── Header de identificación (e.g. X-HackerOne-Research: your-username) ──────
    # Requerido por algunos programas BB para distinguir tráfico legítimo.
    # Podés ingresar múltiples headers separados por coma:
    #   X-HackerOne-Research: tu-usuario, X-Bug-Bounty: true
    print("  \033[38;5;240m  Some BB programs require identifying your traffic with a custom\033[0m")
    print("  \033[38;5;240m  HTTP header. E.g. HackerOne requires X-HackerOne-Research: your-username\033[0m\n")

    headers_input = input(
        "  \033[96m[?]\033[0m Identification headers (Enter to skip)\n"
        "      e.g. X-HackerOne-Research: your-username\n"
        "      e.g. X-HackerOne-Research: your-username, X-Custom: valor > "
    ).strip()

    config["custom_headers"] = []
    if headers_input:
        # Parsear headers: cada "Nombre: Valor" separado por coma
        # Manejar el caso donde el valor del header también tiene comas
        # usando split en ": " como delimitador principal
        raw_headers = []
        # Split por coma solo si va seguido de un nombre de header (contiene ":")
        import re as _re
        parts = _re.split(r",\s*(?=[A-Za-z-]+:)", headers_input)
        for part in parts:
            part = part.strip()
            if ":" in part:
                raw_headers.append(part)

        config["custom_headers"] = raw_headers
        log("OK", f"Headers configured: {raw_headers}")
    else:
        log("INFO", "No identification headers. Continuing without custom headers.")

    # ── Rate limit (requests por segundo) ────────────────────────────────────
    # Controla la agresividad del scanner. Valores de referencia:
    #   Conservador (BB corporativo)  : 5-10 req/s
    #   Moderado (HTB / BB permisivo) : 20-50 req/s
    #   No limit (lab / local)      : 0 (usa defaults de cada herramienta)
    print()
    print("  \033[38;5;240m  Rate limit protects the target and prevents IP blocking.\033[0m")
    print("  \033[38;5;240m  Some BB programs specify a maximum (e.g. Gogo: 10 req/s)\033[0m\n")

    rate_input = input(
        "  \033[96m[?]\033[0m Rate limit in req/second [0 = no limit / tool defaults]\n"
        "      Conservative BB: 10  |  Moderate: 30  |  HTB/lab: 0 > "
    ).strip()

    try:
        config["rate_limit"] = int(rate_input) if rate_input else 0
    except ValueError:
        config["rate_limit"] = 0
        log("WARN", "Invalid value, no rate limit (using tool defaults).")

    if config["rate_limit"] > 0:
        log("OK", f"Rate limit: {config['rate_limit']} req/s "
                  f"(Katana: -rl {config['rate_limit']} | ffuf: -rate {config['rate_limit']})")
    else:
        log("INFO", "No rate limit: Katana -c 20 | ffuf -t 50 (defaults)")

    # ── Restricciones del programa BB ────────────────────────────────────────
    # Algunos programas prohíben explícitamente enviar formularios o hacer
    # login. Esto deshabilita los botones de Hydra/SQLMap-forms en el grafo.
    print()
    no_forms_input = input(
        "  \033[96m[?]\033[0m Does the program prohibit submitting forms? (y/N)\n"
        "      Disables Hydra and SQLMap-forms in the graph action panel > "
    ).strip().lower()
    config["no_forms"] = no_forms_input in ("y", "yes", "s", "si", "sí")
    if config["no_forms"]:
        log("WARN", "Forms disabled — Hydra and SQLMap-forms unavailable in the graph.")

    # ══════════════════════════════════════════════════════════════════════════
    # BLOQUE 0 — GLOBAL TARGET
    # ══════════════════════════════════════════════════════════════════════════
    print("\n\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━  GLOBAL TARGET  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print("  URL or IP that serves as entry point for the entire pipeline.\n")

    while True:
        target = input("  \033[96m[?]\033[0m Target URL or IP (e.g. http://10.10.11.20 or http://target.htb): ").strip()
        if not target:
            print("      \033[91m[!] Target cannot be empty.\033[0m")
            continue
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        config["target"] = target
        parsed = urlparse(target)
        config["host"] = parsed.hostname or target
        break

    port_input = input("  \033[96m[?]\033[0m Port [Enter = 80 for http / 443 for https]: ").strip()
    if port_input.isdigit():
        config["port"] = int(port_input)
        parsed = urlparse(config["target"])
        if not parsed.port:
            config["target"] = f"{parsed.scheme}://{parsed.hostname}:{config['port']}{parsed.path or '/'}"
    else:
        config["port"] = 443 if config["target"].startswith("https://") else 80
        log("INFO", f"Port inferred from scheme: {config['port']}")

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 0c — SCOPE FROM FILE (HackerOne CSV o Burp JSON)
    # El tester puede cargar directamente el archivo de scope exportado desde
    # HackerOne o Burp Suite. El framework extrae automáticamente wildcards
    # y URLs exactas in-scope, y las aplica al BLOQUE 3 (filtro de Katana).
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;39m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;39m  ║  BLOCK 0c — SCOPE FROM FILE                                 ║\033[0m")
    print("\033[38;5;39m  ║  Load CSV from HackerOne or JSON from Burp Suite.              ║\033[0m")
    print("\033[38;5;39m  ║  Wildcards and in-scope URLs are extracted automatically.           ║\033[0m")
    print("\033[38;5;39m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    print("  \033[38;5;240m  Download scope from:\033[0m")
    print("  \033[38;5;240m    HackerOne → program → Policy → Download CSV\033[0m")
    print("  \033[38;5;240m    Burp Suite → Target → Scope → Save to file\033[0m\n")

    scope_file_input = input(
        "  \033[96m[?]\033[0m Path to scope file (Enter to skip)\n"
        "      ej: ~/Downloads/gogo_vdp_scope.csv  o  ~/burp_scope.json > "
    ).strip()

    config["scope_file_wildcards"] = []
    config["scope_file_exact"]     = []
    config["scope_file_excluded"]  = []

    if scope_file_input:
        # Expandir ~ si está presente
        scope_path = Path(scope_file_input).expanduser()

        if not scope_path.exists():
            log("WARN", f"File not found: {scope_path}")
        else:
            # Detectar formato por extensión
            ext = scope_path.suffix.lower()
            if ext == ".csv":
                log("INFO", f"Parsing HackerOne CSV: {scope_path}")
                parsed = parse_hackerone_csv(str(scope_path))
                fmt    = "HackerOne CSV"
            elif ext in (".json", ".burp"):
                log("INFO", f"Parsing Burp Suite scope: {scope_path}")
                parsed = parse_burp_scope(str(scope_path))
                fmt    = "Burp Suite JSON"
            else:
                # Intentar como CSV por defecto
                log("INFO", f"Unknown extension, trying as CSV: {scope_path}")
                parsed = parse_hackerone_csv(str(scope_path))
                fmt    = "CSV (auto-detectado)"

            config["scope_file_wildcards"] = parsed["wildcards"]
            config["scope_file_exact"]     = parsed["exact_urls"]
            config["scope_file_excluded"]  = parsed["out_of_scope"]

            # Mostrar resumen del scope cargado
            log("OK", f"Scope loaded from {fmt}:")
            log("INFO", f"  Wildcards in-scope  : {len(parsed['wildcards'])}")
            for wc in parsed["wildcards"][:10]:
                log("INFO", f"    ✓ {wc}")
            if len(parsed["wildcards"]) > 10:
                log("INFO", f"    ... y {len(parsed['wildcards'])-10} más")

            log("INFO", f"  Exact URLs in-scope: {len(parsed['exact_urls'])}")
            for url in parsed["exact_urls"][:10]:
                log("INFO", f"    ✓ {url}")
            if len(parsed["exact_urls"]) > 10:
                log("INFO", f"    ... y {len(parsed['exact_urls'])-10} más")

            if parsed["out_of_scope"]:
                log("WARN", f"  Out of scope ({len(parsed['out_of_scope'])}): {parsed['out_of_scope'][:5]}")

            if parsed["skipped"]:
                log("INFO", f"  Skipped (non-web): {parsed['skipped'][:5]}")

    # ══════════════════════════════════════════════════════════════════════════
    # BLOQUE 0b — SUBFINDER (Enumeración de subdomains) — OPCIONAL
    # Para targets de Bug Bounty corporativos, enumerar subdomains antes de
    # crawlear es fundamental: admin., api., dev., staging. tienen mucha más
    # superficie de ataque que www. y mucho menos ruido.
    # Requiere: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;208m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;208m  ║  BLOCK 0b — SUBFINDER  (Subdomain enumeration)             ║\033[0m")
    print("\033[38;5;208m  ║  Discovers admin., api., dev., staging. before crawling.        ║\033[0m")
    print("\033[38;5;208m  ║  Highly recommended for Bug Bounty. Optional for HTB.             ║\033[0m")
    print("\033[38;5;208m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    # Separar el texto explicativo del prompt de input para que quede claro
    # dónde escribir. Verificar también si subfinder está instalado antes de preguntar.
    subfinder_available = shutil.which("subfinder") is not None
    if not subfinder_available:
        print("  \033[93m[!]\033[0m subfinder not found in PATH — skipping this phase.")
        print("      Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n")

    print("  \033[38;5;240m──────────────────────────────────────────────────────────────────────\033[0m")
    use_subfinder = input("  \033[96m[?]\033[0m Run subfinder? (y/N): ").strip().lower()
    config["use_subfinder"] = (use_subfinder in ("y", "yes", "s", "si", "sí")) and subfinder_available
    config["subfinder_results"] = []

    if use_subfinder in ("y", "yes", "s", "si", "sí") and not subfinder_available:
        log("WARN", "You chose 'y' but subfinder is not installed. Skipping phase 0.")
    elif config["use_subfinder"]:
        # Extraer el dominio raíz del target para pasarlo a subfinder
        # ej: https://www.mheducation.com/ → mheducation.com
        parsed_target = urlparse(config["target"])
        host_parts    = (parsed_target.hostname or "").split(".")
        if len(host_parts) >= 2 and not host_parts[-1].isdigit():
            root_domain = ".".join(host_parts[-2:])
        else:
            root_domain = parsed_target.hostname or config["host"]
        config["subfinder_domain"] = root_domain
        log("OK", f"subfinder enabled → root domain: {root_domain}")

        # ── Filtro 1: palabras clave ─────────────────────────────────────────
        # Subfinder puede devolver miles de subdomains en targets corporativos.
        # El filtro de keywords conserva solo los subdomains que contienen
        # al menos una de las palabras clave ingresadas.
        # Palabras típicamente interesantes: admin, api, dev, staging, test,
        # internal, vpn, portal, dashboard, jenkins, gitlab, jira, kibana.
        print()
        kw_input = input(
            "  \033[96m[?]\033[0m Filter subdomains by keywords (recommended)\n"
            "      Only subdomains containing any of these words will be processed.\n"
            "      [Enter = no keyword filter, process all]\n"
            "      e.g. admin,api,dev,staging,test,portal,internal,vpn > "
        ).strip()

        config["subfinder_keywords"] = []
        if kw_input:
            keywords = [k.strip().lower() for k in kw_input.split(",") if k.strip()]
            config["subfinder_keywords"] = keywords
            log("OK", f"Filter keywords: {keywords}")
        else:
            log("INFO", "No keyword filter — all subdomains will be processed.")

        # ── Filtro 2: límite máximo ──────────────────────────────────────────
        # Incluso con keywords, en targets grandes pueden quedar muchos.
        # El límite evita crawlear/fuzzear cientos de subdomains en una sesión.
        # Los subdomains se ordenan por longitud (más cortos primero) antes
        # de aplicar el límite: admin.target.com antes que qastg-admin.target.com.
        print()
        limit_input = input(
            "  \033[96m[?]\033[0m Maximum subdomains to process [20]\n"
            "      Shortest (most important) are prioritized automatically.\n"
            "      [0 = no limit, not recommended for large targets] > "
        ).strip()

        try:
            config["subfinder_limit"] = int(limit_input) if limit_input else 20
        except ValueError:
            config["subfinder_limit"] = 20
            log("WARN", "Invalid value, using default limit: 20")
        log("OK", f"Subdomain limit: {config['subfinder_limit'] or 'No limit'}")

    else:
        log("INFO", "subfinder skipped. Continuing without subdomain enumeration.")
        config["subfinder_keywords"] = []
        config["subfinder_limit"]    = 20

    # ══════════════════════════════════════════════════════════════════════════
    # BLOQUE 1 — KATANA (Crawler)
    # Katana NO usa wordlist. Parte de la URL semilla y sigue los links
    # que encuentra en el HTML/JS de forma autónoma.
    # Lo único configurable aquí es sobre qué VHOSTs crawlear.
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;51m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;51m  ║  BLOCK 1 — KATANA  (Crawler)                                    ║\033[0m")
    print("\033[38;5;51m  ║  Katana follows HTML/JS links automatically. No wordlist needed. ║\033[0m")
    print("\033[38;5;51m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    # Mostrar los VHOSTs ya cargados por subfinder (si corrió)
    subfinder_vhosts = config.get("subfinder_results", [])
    if subfinder_vhosts:
        print(f"  \033[92m[+]\033[0m Subfinder already added {len(subfinder_vhosts)} subdomain(s) to the crawling scope:")
        for sv in subfinder_vhosts:
            print(f"       \033[96m→ {sv}\033[0m")
        print()
        print("  \033[38;5;240m  You can add extra VHOSTs (HTB) or leave empty if subfinder was enough.\033[0m\n")
    
    # Timeout global por scope de Katana
    print()
    timeout_in = input(
        "  \033[96m[?]\033[0m Katana global timeout per scope in seconds [300]\n"
        "      Targets with aggressive WAF: 60-120s  |  Permissive targets: 300s+\n"
        "      If no new URLs arrive in 45s → scope is abandoned automatically > "
    ).strip()
    try:
        config["katana_timeout"] = int(timeout_in) if timeout_in else 300
    except ValueError:
        config["katana_timeout"] = 300
    log("OK", f"Katana timeout: {config['katana_timeout']}s por scope (stall: 45s, WAF: 20x403)")

    use_k = input("\n  \033[96m[?]\033[0m Add extra VHOSTs/subdomains for Katana? (y/N): ").strip().lower()
    config["use_katana_vhosts"] = use_k in ("y", "yes", "s", "si", "sí")
    config["katana_vhosts"] = []

    if config["use_katana_vhosts"]:
        config["katana_vhosts"] = _load_vhosts_input("KATANA")
        if not config["katana_vhosts"]:
            log("WARN", "Empty list. No extra VHOSTs added.")
            config["use_katana_vhosts"] = False

    # ══════════════════════════════════════════════════════════════════════════
    # BLOQUE 2 — FFUF (Fuzzer)
    # Dos wordlists independientes con propósitos distintos:
    #   wordlist_dirs  → palabras tipo ruta: admin, backup, api, config
    #                    usada en pasada 1: /FUZZ
    #   wordlist_files → nombres de archivo: config, index, settings, readme
    #                    usada en pasadas con extensión: /FUZZ.php, /FUZZ.bak
    # Si no se especifica wordlist_files, se reutiliza wordlist_dirs como fallback.
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;214m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;214m  ║  BLOCK 2 — FFUF  (Directory and file fuzzer)             ║\033[0m")
    print("\033[38;5;214m  ║  Pass 1: directory wordlist  →  /FUZZ                     ║\033[0m")
    print("\033[38;5;214m  ║  Pass 2+: file wordlist     →  /FUZZ.ext (optional)      ║\033[0m")
    print("\033[38;5;214m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    # ── Wordlist de directories (Pass 1, obligatoria) ──────────────────────
    # Contiene palabras pensadas como nombres de ruta/directorio.
    # Ej de listas recomendadas:
    #   /usr/share/wordlists/dirb/common.txt
    #   /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
    #   /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
    print("  \033[38;5;214m── Pass 1: Directories (/FUZZ) ───────────────────────────────────\033[0m\n")
    while True:
        wordlist = input(
            "  \033[96m[?]\033[0m DIRECTORY wordlist (required)\n"
            "      Words intended as paths: admin, backup, api, config\n"
            "      [Enter = search for default wordlist on system]: "
        ).strip()
        if not wordlist:
            defaults = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/opt/SecLists/Discovery/Web-Content/common.txt",
            ]
            for d in defaults:
                if Path(d).exists():
                    wordlist = d
                    log("INFO", f"Default directory wordlist: {wordlist}")
                    break
            else:
                print("      \033[91m[!] Default wordlist not found. Specify a path.\033[0m")
                continue
        if not Path(wordlist).is_file():
            print(f"      \033[91m[!] File not found: {wordlist}\033[0m")
            continue
        config["wordlist"] = wordlist
        log("OK", f"Wordlist dirs: {wordlist} ({Path(wordlist).stat().st_size // 1024} KB)")
        break

    # ── Auto-calibración (-ac) ───────────────────────────────────────────────
    # -ac filtra respuestas que parecen la respuesta "base" del servidor.
    # MUY ÚTIL en targets simples (HTB). PROBLEMÁTICO en targets con WAF o
    # respuestas uniformes (sitios corporativos) donde puede filtrar todo.
    print()
    ac_input = input(
        "  \033[96m[?]\033[0m Enable ffuf auto-calibration? (-ac) [Y/n]\n"
        "      Y → filters false positives automatically (recommended for HTB)\n"
        "      n → no filter (recommended if ffuf returns 0 results with -ac) > "
    ).strip().lower()
    config["ffuf_ac"] = ac_input not in ("n", "no")
    log("OK", f"ffuf auto-calibration: {'ENABLED' if config['ffuf_ac'] else 'DESENABLED'}")

    # Mostrar los VHOSTs ya cargados por subfinder (si corrió)
    if subfinder_vhosts:
        print(f"\n  \033[92m[+]\033[0m Subfinder already added {len(subfinder_vhosts)} subdomain(s) to the fuzzing scope.")
        print("  \033[38;5;240m  You can add extra VHOSTs (HTB) or leave empty if subfinder was enough.\033[0m\n")

    use_f = input("\n  \033[96m[?]\033[0m Add extra VHOSTs/subdomains for ffuf? (y/N): ").strip().lower()
    config["use_ffuf_vhosts"] = use_f in ("y", "yes", "s", "si", "sí")
    config["ffuf_vhosts"] = []

    if config["use_ffuf_vhosts"]:
        config["ffuf_vhosts"] = _load_vhosts_input("FFUF")
        if not config["ffuf_vhosts"]:
            log("WARN", "Empty list. No extra VHOSTs added.")
            config["use_ffuf_vhosts"] = False

    # ── Extensiones + Wordlist de archivos (Passs 2..N, opcionales) ────────
    # Si el usuario quiere probar extensiones, puede especificar una wordlist
    # de archivos separada (nombres pensados para archivos, no directories).
    # Ej de listas recomendadas:
    #   /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
    #   /usr/share/seclists/Discovery/Web-Content/common-files.txt
    print()
    print("  \033[38;5;214m── Additional passes: Files (/FUZZ.ext) ───────────────────────\033[0m\n")

    ext_input = input(
        "  \033[96m[?]\033[0m Extensions to try (Enter to skip file passes)\n"
        "      Unknown technology : .php,.html,.bak,.zip,.txt,.xml\n"
        "      PHP                    : .php,.php5,.phtml,.bak,.old\n"
        "      Java / JSP             : .jsp,.jspa,.do,.action,.war\n"
        "      ASP.NET                : .asp,.aspx,.ashx,.config,.cs\n"
        "      Sensitive files     : .bak,.sql,.log,.zip,.tar.gz\n"
        "      > "
    ).strip()

    config["ffuf_extensions"] = []
    config["wordlist_files"]  = None   # None = usar wordlist_dirs como fallback

    if ext_input:
        # Normalizar extensiones: asegurar que empiecen con punto
        exts = []
        for e in ext_input.split(","):
            e = e.strip().lower()
            if e and not e.startswith("."):
                e = "." + e
            if e:
                exts.append(e)
        config["ffuf_extensions"] = exts
        log("OK", f"Extensions configured: {exts}")

        # Wordlist de archivos: opcional pero recomendada para pasadas con extensión
        # Una wordlist de archivos contiene nombres como config, index, settings,
        # readme, db, database — sin extensión, que ffuf combina con el .ext.
        print()
        wordlist_files = input(
            "  \033[96m[?]\033[0m FILE wordlist for extension passes\n"
            "      Words intended as filenames: config, index, db\n"
            "      [Enter = reuse directory wordlist as fallback]: "
        ).strip()

        if wordlist_files:
            if not Path(wordlist_files).is_file():
                log("WARN", f"File not found: {wordlist_files}. Using directory wordlist.")
                config["wordlist_files"] = None
            else:
                config["wordlist_files"] = wordlist_files
                log("OK", f"File wordlist: {wordlist_files} ({Path(wordlist_files).stat().st_size // 1024} KB)")
        else:
            log("INFO", "File wordlist: reusing directory wordlist.")

        total_passes = 1 + len(exts)
        wl_files_label = config["wordlist_files"] or config["wordlist"]
        log("INFO", f"ffuf correrá {total_passes} pasada(s) en total:")
        log("INFO", f"  Pass 1      : {config['wordlist']}  →  /FUZZ")
        for ext in exts:
            log("INFO", f"  Pass ext    : {wl_files_label}  →  /FUZZ{ext}")
    else:
        log("INFO", "No extensions: ffuf will only run the directory pass.")

    # Unión deduplicada de todos los VHOSTs (para los nodos del grafo)
    all_vhosts = list(dict.fromkeys(config["katana_vhosts"] + config["ffuf_vhosts"]))
    config["all_vhosts"] = all_vhosts

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 3 — SCOPE
    # Filtra qué URLs Katana puede seguir. Soporta 3 formatos combinables:
    #   [A] Dominios exact   → hostname exacto (target.htb, 10.10.11.20)
    #   [B] Wildcards BB       → *.mheducation.com  (cualquier subdominio)
    #   [C] Regex custom       → .*\.htb$  (patrón libre sobre la URL completa)
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;99m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;99m  ║  BLOCK 3 — SCOPE  (aplica a Katana)                             ║\033[0m")
    print("\033[38;5;99m  ║  Sin scope, Katana sigue links externos fuera del target.        ║\033[0m")
    print("\033[38;5;99m  ║  Podés combinar los 3 formatos en la misma sesión.               ║\033[0m")
    print("\033[38;5;99m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    # Pre-cargar scope desde archivo si se cargó en BLOQUE 0c
    file_wildcards = config.get("scope_file_wildcards", [])
    file_exact     = config.get("scope_file_exact", [])

    if file_wildcards or file_exact:
        print(f"  \033[92m[+]\033[0m Scope pre-loaded from file:")
        if file_wildcards:
            print(f"       Wildcards : {', '.join(file_wildcards[:5])}"
                  + (f" (+{len(file_wildcards)-5} más)" if len(file_wildcards) > 5 else ""))
        if file_exact:
            print(f"       Exactos   : {', '.join(file_exact[:5])}"
                  + (f" (+{len(file_exact)-5} más)" if len(file_exact) > 5 else ""))
        print("  \033[38;5;240m  You can add more below or leave empty to use only the file scope.\033[0m\n")

    # [A] Dominios exact
    scope_in = input(
        "  \033[96m[?]\033[0m [A] Additional exact domains (Enter = use file scope or target base)\n"
        "      ej: target.htb,admin.htb,10.10.11.20 > "
    ).strip()

    if scope_in:
        manual_exact = [d.strip().lower() for d in scope_in.split(",") if d.strip()]
    else:
        manual_exact = []

    # Combinar: archivo + manual + defaults
    if file_exact or manual_exact:
        scope_domains = list(dict.fromkeys(
            [e.lower() for e in file_exact] +
            manual_exact
        ))
    else:
        # Incluir: host base + VHOSTs manuales + subdomains de subfinder
        # Los subdomains de subfinder se añadieron DESPUÉS de que se configuró
        # all_vhosts, así que hay que incluirlos explícitamente aquí.
        subfinder_subs = config.get("subfinder_results", [])
        scope_domains  = list(dict.fromkeys(
            [config["host"].lower()] +
            [v.lower() for v in all_vhosts] +
            [s.lower() for s in subfinder_subs]
        ))

    config["scope_domains"] = scope_domains
    log("OK", f"Total exact domains: {len(scope_domains)} "
              f"(host + {len(config.get('all_vhosts',[]))} VHOSTs + "
              f"{len(config.get('subfinder_results',[]))} subfinder)")

    # [B] Wildcards Bug Bounty (*.dominio.com)
    print()
    wc_in = input(
        "  \033[96m[?]\033[0m [B] Additional wildcards (Enter = use file scope)\n"
        "      ej: *.target.com,*.empresa.com > "
    ).strip()

    config["scope_wildcards"] = []
    config["scope_wildcard_patterns"] = []

    # Combinar wildcards del archivo + manuales
    all_wildcards = list(dict.fromkeys(
        [w.lower() for w in file_wildcards] +
        ([w.strip().lower() for w in re.split(r"[,\n]+", wc_in) if w.strip()] if wc_in else [])
    ))

    for wc in all_wildcards:
        if wc.startswith("*."):
            base    = re.escape(wc[2:])
            pattern = re.compile(rf"^(.+[.])?{base}$", re.IGNORECASE)
        else:
            pattern = re.compile(rf"^{re.escape(wc)}$", re.IGNORECASE)
        config["scope_wildcards"].append(wc)
        config["scope_wildcard_patterns"].append(pattern)

    if config["scope_wildcards"]:
        log("OK", f"Total wildcards: {len(config['scope_wildcards'])}")
        for wc, pat in zip(config["scope_wildcards"][:5], config["scope_wildcard_patterns"][:5]):
            log("INFO", f"  {wc}  →  {pat.pattern}")
        if len(config["scope_wildcards"]) > 5:
            log("INFO", f"  ... y {len(config['scope_wildcards'])-5} más")

    # [C] Regex custom
    # Caso de uso: cuando A y B no alcanzan porque necesitás filtrar
    # por PATH además de por dominio, o cuando el patrón es muy específico.
    # En la mayoría de auditorías HTB/BB, con A y B es suficiente.
    print()
    rx_in = input(
        "  \033[96m[?]\033[0m [C] Advanced scope regex (optional)\n"
        "      Evaluated against the FULL URL (domain + path).\n"
        "      Useful when you need to filter by path, not just domain.\n"
        "      If A and B already cover your scope, leave this empty.\n"
        "\n"
        "      Examples of when to use it:\n"
        "        API endpoints only  →  .*/api/.*\n"
        "        Any .htb         →  .*\\.htb.*\n"
        "        HTTPS only             →  ^https://.*\n"
        "        A specific path     →  .*/v2/users.*\n"
        "\n"
        "      [Enter to skip — recommended if you already used A or B] > "
    ).strip()

    config["scope_regex"] = None
    if rx_in:
        try:
            config["scope_regex"] = re.compile(rx_in, re.IGNORECASE)
            log("OK", f"Regex custom compilada: {rx_in}")
        except re.error as e:
            log("WARN", f"Regex inválida ({e}), se ignora.")

    total_rules = (
        len(config["scope_domains"]) +
        len(config["scope_wildcards"]) +
        (1 if config["scope_regex"] else 0)
    )
    log("OK", f"Scope: {total_rules} reglas activas  "
              f"({len(config['scope_domains'])} exact | "
              f"{len(config['scope_wildcards'])} wildcards | "
              f"{'1 regex' if config['scope_regex'] else '0 regex'})")

    # ══════════════════════════════════════════════════════════════════════════
    # BLOQUE 4 — GRAFO
    # Controla cuántos niveles de path se muestran como nodos individuales.
    # Paths más profundos se colapsan en su directorio padre con contador ×N.
    # Los nodos de ffuf nunca se colapsan (son findings críticos individuales).
    # El límite de nodos garantiza que el HTML sea navegable en el browser.
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;71m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;71m  ║  BLOCK 4 — GRAPH  (SVG visualization)                         ║\033[0m")
    print("\033[38;5;71m  ║  Depth 2 → shows /dir/subdir, collapses the rest.          ║\033[0m")
    print("\033[38;5;71m  ║  ffuf findings are NEVER collapsed.                        ║\033[0m")
    print("\033[38;5;71m  ║  Node limit: ensures browser performance.           ║\033[0m")
    print("\033[38;5;71m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    depth_in = input("  \033[96m[?]\033[0m Max depth of Katana nodes in graph [2]: ").strip()
    try:
        config["graph_depth"] = max(1, int(depth_in)) if depth_in else 2
    except ValueError:
        config["graph_depth"] = 2
        log("WARN", "Invalid value, using default depth: 2")
    log("OK", f"Graph depth: {config['graph_depth']} niveles")

    # ── Límite máximo de nodos ───────────────────────────────────────────────
    # El browser empieza a sufrir con más de ~500 nodos en el layout jerárquico.
    # Por encima de 1000 nodos el HTML puede tardar minutes en cargar o trabarse.
    # Prioridad de recorte: se eliminan nodos de Katana con menos URLs agrupadas,
    # preservando siempre: seed, VHOSTs, subfinder y todos los nodos de ffuf.
    #
    # Guía de referencia:
    #   HTB (box simple)         →  50-150 nodos  → límite 200
    #   HTB (box complejo/CMS)   →  150-400 nodos → límite 500
    #   Bug Bounty (1 subdominio) → 200-800 nodos → límite 500
    #   Bug Bounty (multi-scope) → 500-5000 nodos → límite 300
    print()
    limit_in = input(
        "  \033[96m[?]\033[0m Maximum nodes in graph [300]\n"
        "      Simple HTB: 200  |  Complex HTB: 500  |  Bug Bounty multi-scope: 300\n"
        "      [0 = no limit, not recommended with multiple subdomains] > "
    ).strip()
    try:
        config["graph_node_limit"] = int(limit_in) if limit_in else 300
    except ValueError:
        config["graph_node_limit"] = 300
        log("WARN", "Invalid value, using default limit: 300")
    lim_label = str(config["graph_node_limit"]) if config["graph_node_limit"] else "No limit"
    log("OK", f"Graph node limit: {lim_label}")

    # ── Directorio de output de la sesión ────────────────────────────────────
    ts_label   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host  = sanitize_filename(config["host"])
    output_dir = Path(f"recon_{safe_host}_{ts_label}")
    output_dir.mkdir(parents=True, exist_ok=True)
    config["output_dir"]    = output_dir
    config["session_label"] = f"{safe_host}_{ts_label}"
    log("OK", f"Directorio de sesión: {output_dir.resolve()}")

    # ── Resumen final antes de confirmar ─────────────────────────────────────
    print("\n\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━  RESUMEN DE SESIÓN  ━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print(f"  \033[38;5;240mTarget\033[0m          : \033[96m{config['target']}\033[0m  (puerto {config['port']})")
    _hdrs = " | ".join(config.get("custom_headers", [])) or "None"
    _rl   = f"{config.get('rate_limit')} req/s" if config.get('rate_limit') else "No limit"
    _nf   = "YES ⚠" if config.get('no_forms') else "No"
    print(f"  \033[38;5;220m[PROFILE]\033[0m  Headers: \033[96m{_hdrs}\033[0m")
    print(f"           Rate   : \033[96m{_rl}\033[0m  |  No-forms: \033[96m{_nf}\033[0m")
    _fw = len(config.get("scope_file_wildcards", []))
    _fe = len(config.get("scope_file_exact", []))
    if _fw or _fe:
        print(f"  \033[38;5;39m[SCOPE  ]\033[0m  File   : \033[96m{_fw} wildcards + {_fe} exact\033[0m")
    print()
    if config.get("use_subfinder"):
        print(f"  \033[38;5;208m[SUBFINDER]\033[0m Passive enumeration de subdomains")
        print(f"           Domain   : \033[96m{config.get('subfinder_domain', config['host'])}\033[0m")
        _kw  = ", ".join(config.get("subfinder_keywords", [])) or "Sin filtro"
        _lim = str(config.get("subfinder_limit", 20)) if config.get("subfinder_limit") else "No limit"
        print(f"           Keywords : \033[96m{_kw}\033[0m")
        print(f"           Limit    : \033[96m{_lim} subdomains\033[0m")
    print()
    print(f"  \033[38;5;51m[KATANA]\033[0m  Autonomous crawler, no wordlist")
    print(f"           VHOSTs  : \033[96m{config['katana_vhosts'] if config['katana_vhosts'] else 'Target base only'}\033[0m")
    print()
    print(f"  \033[38;5;214m[FFUF  ]\033[0m  Fuzzer de directories y archivos")
    print(f"           WL dirs    : \033[96m{config['wordlist']}\033[0m")
    _wlf = config.get('wordlist_files') or "(igual que dirs)"
    print(f"           WL files   : \033[96m{_wlf}\033[0m")
    print(f"           VHOSTs     : \033[96m{config['ffuf_vhosts'] if config['ffuf_vhosts'] else 'Target base only'}\033[0m")
    _ext = config.get('ffuf_extensions', [])
    _ext_str = ", ".join(_ext) if _ext else "Solo directories (pasada única)"
    _pass_str = f"1 dirs + {len(_ext)} archivos" if _ext else "1 pasada"
    print(f"           Extensions : \033[96m{_ext_str}\033[0m  \033[90m({_pass_str})\033[0m")
    _ac_str = "ENABLED" if config.get("ffuf_ac", True) else "DESENABLED (sin filtro)"
    print(f"           Auto-calib : \033[96m{_ac_str}\033[0m")
    print()
    print(f"  \033[38;5;99m[SCOPE ]\033[0m  URL filter for Katana")
    print(f"           Exactos : \033[96m{config['scope_domains']}\033[0m")
    wc_lbl = config['scope_wildcards'] if config['scope_wildcards'] else ['None']
    print(f"           Wildcard: \033[96m{wc_lbl}\033[0m")
    rx_lbl = config['scope_regex'].pattern if config.get('scope_regex') else 'Ninguna'
    print(f"           Regex   : \033[96m{rx_lbl}\033[0m")
    print()
    _lim_g = str(config['graph_node_limit']) if config.get('graph_node_limit') else 'No limit'
    print(f"  \033[38;5;71m[GRAPH ]\033[0m  Depth: \033[96m{config['graph_depth']} niveles\033[0m  |  Limit: \033[96m{_lim_g} nodos\033[0m")
    print(f"           Output  : \033[96m{output_dir.resolve()}\033[0m")
    print("\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")

    confirm = input("  \033[96m[?]\033[0m Confirm and launch pipeline? (Y/n): ").strip().lower()
    if confirm in ("n", "no"):
        log("WARN", "Pipeline cancelled by user.")
        sys.exit(0)

    return config


# =============================================================================
# SECCIÓN 3: FILTRO DE SCOPE + FASE 1 — MOTOR DE CRAWLING CON KATANA
# =============================================================================

def is_in_scope(url: str, config: dict) -> bool:
    """
    Determina si una URL está dentro del scope de auditoría.

    Evalúa en orden las 3 capas de reglas. La URL es in-scope si pasa
    CUALQUIERA de las siguientes condiciones (lógica OR entre capas):

      [A] Hostname exacto en scope_domains
          ej: "admin.htb" matchea "admin.htb" pero no "sub.admin.htb"

      [B] Hostname matchea algún patrón wildcard (scope_wildcard_patterns)
          ej: "*.mheducation.com" matchea "app.mheducation.com"
              y también "mheducation.com" sin subdominio

      [C] URL completa matchea la regex custom (scope_regex)
          ej: r".*[.]htb$" matchea cualquier .htb

    Si ninguna regla está configurada, acepta todo (comportamiento permisivo
    por defecto para no romper sesiones sin scope definido).

    Args:
        url    : URL completa a evaluar (ej: https://app.mheducation.com/login)
        config : Config global con scope_domains, scope_wildcard_patterns, scope_regex

    Returns:
        True si la URL está in-scope, False si debe filtrarse fuera.
    """
    scope_domains   = config.get("scope_domains", [])
    wildcard_pats   = config.get("scope_wildcard_patterns", [])
    scope_regex     = config.get("scope_regex")

    # Sin ninguna regla configurada → aceptar todo
    has_any_rule = bool(scope_domains or wildcard_pats or scope_regex)
    if not has_any_rule:
        return True

    try:
        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return False

    # ── [A] Match exacto de hostname ─────────────────────────────────────────
    if hostname in scope_domains:
        return True

    # ── [B] Match de wildcard *.dominio.com ──────────────────────────────────
    # Cada patrón ya fue compilado en collect_inputs desde el string *.dominio.com
    for pattern in wildcard_pats:
        if pattern.match(hostname):
            return True

    # ── [C] Regex custom sobre la URL completa ───────────────────────────────
    if scope_regex and scope_regex.search(url):
        return True

    return False


def _make_findings_table(tool: str, findings: list, scope: str):
    """
    Construye una tabla Rich con los últimos findings en tiempo real.
    Se renderiza dentro del panel Live durante la ejecución.
    """
    table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
        show_lines=False,
    )
    table.add_column("STATUS", width=7, justify="center")
    table.add_column("URL / PATH", no_wrap=False)
    table.add_column("EXTRA", width=18, justify="right", style="dim")

    # Mostrar solo los últimos 12 findings para no desbordar la pantalla
    for item in findings[-12:]:
        status = item.get("status", 0)
        url    = item.get("url", "")
        extra  = item.get("content_type", "") or item.get("fuzz_word", "")

        # Colorear el status según su categoría HTTP
        if status == 200:
            st_text = Text(str(status), style="bold green")
        elif status in (301, 302):
            st_text = Text(str(status), style="bold yellow")
        elif status == 403:
            st_text = Text(str(status), style="bold red")
        else:
            st_text = Text(str(status) if status else "---", style="dim")

        table.add_row(st_text, url[:90], str(extra)[:18])

    return table


def run_katana(target_url: str, vhost: "str | None", output_dir: Path, config: dict) -> list:
    """
    Ejecuta Katana con output en tiempo real usando Popen + lectura línea a línea.
    Muestra un panel Rich con spinner, contador en vivo y tabla de URLs encontradas.

    Args:
        target_url : URL base a crawlear (ej: http://10.10.11.20)
        vhost      : Nombre del virtual host si aplica (ej: admin.htb), None si no.
        output_dir : Directorio donde se guardan los archivos temporales.
        config     : Diccionario global de configuración de la sesión.

    Returns:
        Lista de dicts con las URLs descubiertas y sus metadatos.
    """
    label       = sanitize_filename(vhost if vhost else config["host"])
    output_file = output_dir / f"katana_{label}.jsonl"
    scope_label = vhost or config["host"]

    # ── Construcción del comando Katana ──────────────────────────────────────
    # NOTA: Eliminamos -silent para poder leer el stdout en tiempo real.
    # Katana con -jsonl escribe al archivo -o Y también al stdout.
    # Concurrencia: respetar rate limit si está configurado
    # Katana no tiene flag -rate directo, se controla con -c (workers)
    # Aproximación: rate_limit / 2 workers (cada worker hace ~2 req/s)
    rate_limit  = config.get("rate_limit", 0)
    concurrency = max(1, rate_limit // 2) if rate_limit > 0 else 20

    cmd = [
        "katana",
        "-u", target_url,
        "-d", "3",
        "-jc",                     # Parsear JavaScript
        "-jsonl",                  # Formato JSON Lines
        "-o", str(output_file),    # Archivo de salida
        "-timeout", "10",
        "-c", str(concurrency),    # Workers (controlado por rate_limit)
    ]
    if vhost:
        cmd.extend(["-H", f"Host: {vhost}"])

    # Agregar headers custom de identificación (ej: X-HackerOne-Research)
    for header in config.get("custom_headers", []):
        cmd.extend(["-H", header])
    if config.get("custom_headers"):
        log("INFO", f"Identification headers added to Katana: {config['custom_headers']}")

    log("INFO", f"Katana → scope: {scope_label}")
    log("INFO", f"Comando: {' '.join(cmd)}")

    discovered  = []
    seen_urls   = set()    # Deduplicación: evita procesar la misma URL múltiples veces
    start_time  = time.time()

    # ── Modo con Rich: panel Live en tiempo real ─────────────────────────────
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(spinner_name="dots2", style="cyan"),
            TextColumn("[bold cyan]KATANA[/] [{task.fields[scope]}]"),
            BarColumn(bar_width=None, style="cyan", complete_style="bright_cyan"),
            TextColumn("[cyan]{task.fields[found]}[/] URLs"),
            TimeElapsedColumn(),
            TextColumn("[dim]{task.fields[last_url]}[/]"),
            expand=True,
            transient=False,
        ) as progress:
            task = progress.add_task(
                "crawling",
                total=None,       # Total desconocido → barra indeterminada
                scope=scope_label,
                found="0",
                last_url="",
            )

            # Timeout global y detección de bloqueo WAF/CDN
            GLOBAL_TIMEOUT  = config.get("katana_timeout", 300)
            STALL_TIMEOUT   = 45    # seconds sin nueva URL → stall
            BLOCK_THRESHOLD = 20    # 403 consecutivos → bloqueo

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

                last_url_time   = time.time()
                consecutive_403 = 0
                blocked         = False

                for raw_line in proc.stdout:
                    line = raw_line.strip()
                    if not line:
                        continue

                    # Timeout global
                    if time.time() - start_time > GLOBAL_TIMEOUT:
                        log("WARN", f"Katana: global timeout of {GLOBAL_TIMEOUT}s para '{scope_label}'")
                        proc.kill(); break

                    # Stall: sin URLs nuevas por STALL_TIMEOUT seconds
                    if time.time() - last_url_time > STALL_TIMEOUT:
                        log("WARN", f"Katana: no new URLs for {STALL_TIMEOUT}s en '{scope_label}' — aborting scope")
                        proc.kill(); break

                    try:
                        entry = json.loads(line)
                        url   = entry.get("request", {}).get("endpoint", "") or entry.get("endpoint", "")
                        if not url:
                            continue

                        last_url_time = time.time()

                        method       = entry.get("request", {}).get("method", "GET")
                        status       = entry.get("response", {}).get("status_code", 0)
                        content_type = entry.get("response", {}).get("headers", {}).get("content-type", [""])[0]

                        # Detección de bloqueo WAF/CDN por 403 consecutivos
                        if status == 403:
                            consecutive_403 += 1
                            if consecutive_403 >= BLOCK_THRESHOLD:
                                log("WARN", f"Katana: {BLOCK_THRESHOLD} consecutive 403 responses en '{scope_label}' — WAF/CDN bloqueando")
                                log("INFO",  "  Wait a few minutes before running the framework again.")
                                proc.kill(); blocked = True; break
                        else:
                            consecutive_403 = 0

                        if not is_in_scope(url, config):
                            progress.update(task, advance=1); continue

                        if url in seen_urls:
                            progress.update(task, advance=1); continue
                        seen_urls.add(url)

                        resp_headers = entry.get("response", {}).get("headers", {})
                        tech = detect_tech(resp_headers, content_type, url)

                        forms = []
                        req_body = entry.get("request", {}).get("body", "")
                        if req_body:
                            pat = re.compile(
                                "name=([\x22\x27])([^\x22\x27>\\s]+)\\1",
                                re.IGNORECASE
                            )
                            matches = pat.findall(req_body)
                            if matches:
                                forms = list({m[1] for m in matches})

                        discovered.append({
                            "url": url, "method": method, "status": status,
                            "content_type": content_type,
                            "tech": tech, "forms": forms,
                            "headers": dict(resp_headers),
                            "source": scope_label, "type": "visible",
                        })

                        short_url = url[-65:] if len(url) > 65 else url
                        progress.update(task,
                            advance=1,
                            found=str(len(discovered)),
                            last_url=short_url,
                        )
                    except json.JSONDecodeError:
                        continue

                if not blocked:
                    proc.wait(timeout=30)

            except subprocess.TimeoutExpired:
                proc.kill()
                log("WARN", f"Katana: timeout de espera final para '{scope_label}', continuando.")
            except FileNotFoundError:
                log("ERROR", "'katana' no está instalado o no está en PATH.")
                log("INFO",  "Instalación: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            except Exception as e:
                log("ERROR", f"Error inesperado en Katana: {e}")

    # ── Modo fallback sin Rich: subprocess.run clásico ───────────────────────
    else:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode not in (0, 1):
                log("WARN", f"Katana finalizó con código {result.returncode}")
        except subprocess.TimeoutExpired:
            log("ERROR", f"Katana timeout para {scope_label}")
            return []
        except FileNotFoundError:
            log("ERROR", "'katana' no found in PATH.")
            return []

        # Parseo post-ejecución desde el archivo JSONL
        if output_file.exists():
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        url   = entry.get("request", {}).get("endpoint", "") or entry.get("endpoint", "")
                        if url and url not in seen_urls and is_in_scope(url, config):
                            seen_urls.add(url)
                            discovered.append({
                                "url": url,
                                "method": entry.get("request", {}).get("method", "GET"),
                                "status": entry.get("response", {}).get("status_code", 0),
                                "content_type": entry.get("response", {}).get("headers", {}).get("content-type", [""])[0],
                                "source": scope_label, "type": "visible",
                            })
                    except json.JSONDecodeError:
                        continue

    elapsed = time.time() - start_time
    scope_info = f" | scope: {config.get('scope_domains', [])}" if config.get("scope_domains") else ""
    log("OK", f"Katana → {len(discovered)} unique in-scope URLs in {elapsed:.1f}s para '{label}'{scope_info}")
    return discovered


# =============================================================================
# SECCIÓN 4: FASE 2 — MOTOR DE FUZZING CON FFUF (con Live Output)
# =============================================================================

def _count_wordlist_lines(wordlist_path: str) -> int:
    """
    Cuenta las líneas de la wordlist para calcular el progreso de ffuf.
    Lo hace eficientemente sin cargar todo el archivo en memoria.
    """
    try:
        with open(wordlist_path, "rb") as f:
            return sum(1 for _ in f)
    except IOError:
        return 0


def run_ffuf(target_url: str, vhost: "str | None", wordlist: str,
             output_dir: Path, config: dict,
             extension: "str | None" = None) -> list:
    """
    Ejecuta una pasada de ffuf con barra de progreso en tiempo real.

    Puede correr en dos modos según el parámetro 'extension':
      · extension=None  → Pass 1: fuzzea /FUZZ  (directories puros)
      · extension=".php" → Pass 2: fuzzea /FUZZ.php  (dirs + extensión)

    PROBLEMA RESUELTO: ffuf escribe su progreso al stderr usando \r (retorno de
    carro) en lugar de \n, por lo que 'for line in proc.stderr' bloquea
    indefinidamente esperando un salto de línea que nunca llega.

    SOLUCIÓN: Leer stderr carácter a carácter en un hilo dedicado, acumulando
    en un buffer hasta encontrar \r o \n, y parsear el progreso de ese fragmento.
    Los hits se capturan desde stdout con -v (verbose) que sí usa \n.

    Args:
        target_url : URL base para el fuzzing.
        vhost      : Nombre del virtual host, si aplica.
        wordlist   : Ruta al diccionario de palabras.
        output_dir : Directorio donde se guarda el JSON de resultados.
        config     : Diccionario global de configuración.
        extension  : Extensión a agregar al placeholder FUZZ (ej: ".php").
                     None = pasada de directories sin extensión.

    Returns:
        Lista de dicts con las rutas descubiertas y sus metadatos.
    """
    label       = sanitize_filename(vhost if vhost else config["host"])
    # Nombre de archivo único por pasada para no solapar los JSON
    ext_suffix  = extension.lstrip(".") if extension else "dirs"
    output_file = output_dir / f"ffuf_{label}_{ext_suffix}.json"
    scope_label = vhost or config["host"]

    # El placeholder FUZZ se extiende con la extensión si se especificó:
    #   Sin extensión: http://target/FUZZ
    #   Con extensión: http://target/FUZZ.php
    fuzz_suffix = extension if extension else ""
    fuzz_url    = target_url.rstrip("/") + "/FUZZ" + fuzz_suffix

    # Label de pasada para los logs y la barra de progreso
    pass_label  = f"dirs+{extension}" if extension else "dirs"

    # ── Construcción del comando ffuf ────────────────────────────────────────
    # Flags clave para el modo live:
    #   Sin -s  → ffuf escribe el progreso al stderr (con \r entre actualizaciones)
    #   -v      → ffuf escribe cada hit al stdout en formato "| STATUS | URL |"
    #             separado por \n, lo que sí permite leer línea a línea sin bloqueo
    # -ac (auto-calibración) filtra respuestas que parecen "base" del servidor.
    # Muy útil en targets simples, pero en sitios con WAF o respuestas uniformes
    # puede filtrar TODOS los resultados. Se puede desactivar desde config.
    # Rate limit y threads: respetar el límite configurado
    rate_limit = config.get("rate_limit", 0)
    threads    = max(1, min(rate_limit, 50)) if rate_limit > 0 else 50

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-o", str(output_file),
        "-of", "json",
        "-t", str(threads),        # Threads (controlado por rate_limit)
        "-timeout", "10",
        "-mc", "200,301,302,403",
        "-v",           # Verbose: hits al stdout línea a línea (formato parseable)
    ]
    if rate_limit > 0:
        cmd.extend(["-rate", str(rate_limit)])   # Rate limit estricto en req/s
    if config.get("ffuf_ac", True):
        cmd.append("-ac")

    # Agregar headers custom de identificación
    for header in config.get("custom_headers", []):
        cmd.extend(["-H", header])
    if config.get("custom_headers"):
        log("INFO", f"Identification headers added to ffuf: {config['custom_headers']}")
    if vhost:
        cmd.extend(["-H", f"Host: {vhost}"])

    log("INFO", f"ffuf [{pass_label}] → scope: {scope_label}")
    log("INFO", f"Comando: {' '.join(cmd)}")

    discovered = []
    start_time = time.time()

    total_words = _count_wordlist_lines(wordlist)
    log("INFO", f"Wordlist: {total_words:,} words to test")

    hits = {"200": 0, "301": 0, "302": 0, "403": 0}

    # ── Modo con Rich: barra de progreso real ────────────────────────────────
    if RICH_AVAILABLE:

        # Regex para el progreso de stderr de ffuf.
        # ffuf escribe algo así (separado por \r, no \n):
        # ":: Progress: [1234/4614] :: Job [1/1] :: 220 req/sec :: Duration: [0:00:05]"
        progress_re = re.compile(r"Progress: \[(\d+)/(\d+)\]")

        # Regex para hits en stdout con -v. Formato:
        # "| 200 | 4821 B | http://target/backup"  (puede variar levemente entre versiones)
        # También captura la línea de resultado estándar sin -v como fallback:
        # "backup  [Status: 200, Size: 4821, Words: 123, Lines: 45, Duration: 12ms]"
        hit_re_verbose  = re.compile(r"\|\s+(\d{3})\s+\|\s+[\d.]+\s+\w+\s+\|\s+(https?://\S+)")
        hit_re_standard = re.compile(
            r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)"
        )

        hits_buffer = []  # Compartido entre threads (append es thread-safe en CPython)

        def _read_stderr_chars(proc, prog, task_id, hbuf, stop_event):
            """
            Hilo dedicado a leer stderr de ffuf CARÁCTER A CARÁCTER.

            ffuf usa \r para sobreescribir la línea de progreso en la terminal.
            Leer por líneas (for line in proc.stderr) bloquea porque nunca llega \n.
            Leyendo char a char, acumulamos hasta \r o \n y parseamos el fragmento.
            """
            buf = ""
            try:
                while not stop_event.is_set():
                    ch = proc.stderr.read(1)   # Leer UN carácter
                    if not ch:                  # EOF: proceso terminó
                        break
                    if ch in ("\r", "\n"):     # Fin de "línea" (\r o \n)
                        fragment = buf.strip()
                        buf = ""
                        if not fragment:
                            continue
                        m = progress_re.search(fragment)
                        if m:
                            current = int(m.group(1))
                            # Actualizar la barra con el progreso real de ffuf
                            prog.update(task_id,
                                completed=current,
                                h200=str(hits["200"]),
                                h301=str(hits["301"] + hits["302"]),
                                h403=str(hits["403"]),
                                last_hit=hbuf[-1]["fuzz_word"][:35] if hbuf else "",
                            )
                    else:
                        buf += ch
            except (ValueError, OSError):
                pass  # Pipe cerrado normalmente al terminar ffuf

        def _read_stdout_lines(proc, buf, furl, slabel):
            """
            Hilo que lee stdout de ffuf línea a línea (con -v sí usa \n).
            Parsea los hits y los acumula en el buffer compartido.
            """
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                # Intentar formato verbose (-v): "| STATUS | SIZE | URL"
                m = hit_re_verbose.search(line)
                if m:
                    status   = int(m.group(1))
                    full_url = m.group(2)
                    word     = full_url.replace(furl.replace("FUZZ", ""), "").strip("/")
                    entry = {
                        "url": full_url, "status": status,
                        "length": 0, "words": 0, "lines": 0,
                        "redirect": "", "fuzz_word": word,
                        "source": slabel, "type": "hidden",
                    }
                    buf.append(entry)
                    s = str(status)
                    if s in hits:
                        hits[s] += 1
                    continue

                # Fallback: formato estándar sin -v
                m2 = hit_re_standard.match(line)
                if m2:
                    word   = m2.group(1)
                    status = int(m2.group(2))
                    size   = int(m2.group(3))
                    wds    = int(m2.group(4))
                    lns    = int(m2.group(5))
                    full_url = furl.replace("FUZZ", word)
                    entry = {
                        "url": full_url, "status": status,
                        "length": size, "words": wds, "lines": lns,
                        "redirect": "", "fuzz_word": word,
                        "source": slabel, "type": "hidden",
                    }
                    buf.append(entry)
                    s = str(status)
                    if s in hits:
                        hits[s] += 1

        with Progress(
            SpinnerColumn(spinner_name="dots12", style="bright_yellow"),
            TextColumn("[bold yellow]FFUF[/] [{task.fields[scope]}] [dim]{task.fields[pass_label]}[/]"),
            BarColumn(bar_width=None, style="yellow", complete_style="bright_yellow"),
            MofNCompleteColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TextColumn(
                " [green]{task.fields[h200]}✓[/]"
                " [yellow]{task.fields[h301]}→[/]"
                " [red]{task.fields[h403]}✗[/]"
                "  [dim]{task.fields[last_hit]}[/]"
            ),
            expand=True,
            transient=False,
        ) as progress:

            task = progress.add_task(
                "fuzzing",
                total=total_words,
                scope=scope_label,
                pass_label=pass_label,
                h200="0", h301="0", h403="0",
                last_hit="",
            )

            stop_event = threading.Event()

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=0,   # Sin buffer: esencial para recibir los \r de stderr al instante
                )

                t_err = threading.Thread(
                    target=_read_stderr_chars,
                    args=(proc, progress, task, hits_buffer, stop_event),
                    daemon=True,
                )
                t_out = threading.Thread(
                    target=_read_stdout_lines,
                    args=(proc, hits_buffer, fuzz_url, scope_label),
                    daemon=True,
                )
                t_err.start()
                t_out.start()

                proc.wait(timeout=600)
                stop_event.set()
                t_err.join(timeout=5)
                t_out.join(timeout=5)

                # Marcar la barra como 100% al terminar
                progress.update(task, completed=total_words)
                discovered.extend(hits_buffer)

            except subprocess.TimeoutExpired:
                proc.kill()
                stop_event.set()
                log("ERROR", f"ffuf superó el timeout de 600s para {scope_label}")
            except FileNotFoundError:
                log("ERROR", "'ffuf' no está instalado o no está en PATH.")
                log("INFO",  "Instalación: sudo apt install ffuf  |  go install github.com/ffuf/ffuf@latest")
            except Exception as e:
                log("ERROR", f"Error inesperado en ffuf: {e}")

    # ── Modo fallback sin Rich ───────────────────────────────────────────────
    else:
        try:
            result = subprocess.run(cmd + ["-s"], capture_output=True, text=True, timeout=600)
            if result.returncode not in (0, 1):
                log("WARN", f"ffuf finalizó con código {result.returncode}")
        except subprocess.TimeoutExpired:
            log("ERROR", f"ffuf timeout para {scope_label}")
            return []
        except FileNotFoundError:
            log("ERROR", "'ffuf' no found in PATH.")
            return []

    # ── Parseo del JSON final de ffuf (siempre como fuente de verdad) ────────
    # El JSON de salida de ffuf es la fuente canónica. Los hits capturados
    # en vivo son para el display, pero el JSON tiene todos los campos completos.
    if output_file.exists():
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            results = data.get("results", [])
            # Si el parseo en vivo no funcionó (modo fallback), cargar desde JSON
            if not discovered:
                for entry in results:
                    status = entry.get("status", 0)
                    if status in (200, 201, 301, 302, 403):
                        url    = entry.get("url", "")
                        input_raw = entry.get("input", {}).get("FUZZ", "")
                        input_w = input_raw.decode("utf-8", errors="ignore") if isinstance(input_raw, bytes) else input_raw
                        discovered.append({
                            "url": url, "status": status,
                            "length": entry.get("length", 0),
                            "words": entry.get("words", 0),
                            "lines": entry.get("lines", 0),
                            "redirect": entry.get("redirectlocation", ""),
                            "fuzz_word": input_w,
                            "source": scope_label, "type": "hidden",
                        })
        except (json.JSONDecodeError, IOError) as e:
            log("ERROR", f"Error al parsear JSON final de ffuf: {e}")

    elapsed = time.time() - start_time
    log("OK", f"ffuf → {len(discovered)} rutas en {elapsed:.1f}s | 200:{hits['200']} 3xx:{hits['301']+hits['302']} 403:{hits['403']}")
    return discovered

# =============================================================================
# SECCIÓN 4b: ORQUESTADOR DE PASADAS DE FFUF
# =============================================================================

def run_ffuf_all_passes(target_url: str, vhost: "str | None",
                        output_dir: Path, config: dict) -> list:
    """
    Orquesta todas las pasadas de ffuf para un scope dado:

      Pass 1 (siempre): /FUZZ  → directories puros
      Pass 2..N (opcional): /FUZZ.ext por cada extensión configurada

    Consolida y deduplica todos los findings en una sola lista,
    marcando cada entry con el campo 'extension' para que el grafo
    pueda distinguir visualmente entre directories y archivos.

    Args:
        target_url : URL base para el fuzzing.
        vhost      : Virtual host a usar en el header Host, o None.
        output_dir : Directorio donde guardar los JSON de resultados.
        config     : Config global con wordlist y ffuf_extensions.

    Returns:
        Lista consolidada de todos los findings de todas las pasadas.
    """
    wordlist   = config["wordlist"]
    extensions = config.get("ffuf_extensions", [])   # [] = solo dirs
    all_found  = []
    seen_urls  = set()   # Deduplicación por URL exacta entre pasadas

    scope_label = vhost or config["host"]
    total_passes = 1 + len(extensions)

    log("PHASE", f"ffuf → {total_passes} pasada(s) para '{scope_label}'  "
                 f"[dirs{' + ' + ', '.join(extensions) if extensions else ''}]")

    # ── Pass 1: directories puros (/FUZZ) ──────────────────────────────────
    log("INFO", f"  Pass 1/{total_passes}: /FUZZ  (directories)")
    results = run_ffuf(target_url, vhost, wordlist, output_dir, config, extension=None)
    for entry in results:
        entry["extension"] = ""          # Sin extensión
        entry["pass"]      = "dirs"
        url_key = entry.get("url", "")
        if url_key not in seen_urls:
            seen_urls.add(url_key)
            all_found.append(entry)

    # ── Passs adicionales: una por extensión (/FUZZ.ext) ───────────────────
    # Para las pasadas con extensión se usa wordlist_files si está configurada,
    # o la wordlist de directories como fallback si no se especificó ninguna.
    wordlist_files = config.get("wordlist_files") or wordlist

    for i, ext in enumerate(extensions, start=2):
        log("INFO", f"  Pass {i}/{total_passes}: /FUZZ{ext}  ({wordlist_files.split('/')[-1]})")
        results = run_ffuf(target_url, vhost, wordlist_files, output_dir, config, extension=ext)
        for entry in results:
            entry["extension"] = ext
            entry["pass"]      = f"ext:{ext}"
            url_key = entry.get("url", "")
            if url_key not in seen_urls:
                seen_urls.add(url_key)
                all_found.append(entry)

    dirs_count = sum(1 for e in all_found if not e["extension"])
    ext_count  = sum(1 for e in all_found if e["extension"])
    log("OK", f"ffuf total para '{scope_label}': "
              f"{len(all_found)} findings  "
              f"({dirs_count} directories | {ext_count} files with extension)")

    return all_found


# SECCIÓN 5: FASE 3 — CONSTRUCCIÓN DEL GRAFO CON PYVIS
# =============================================================================

def _build_path_tree(urls: list, max_depth: int) -> dict:
    """
    Construye un árbol jerárquico de paths a partir de una lista de URLs.

    Cada URL se descompone en segmentos de path y se inserta en el árbol.
    Los paths más profundos que max_depth se colapsan en su nodo padre.

    Retorna un dict con estructura:
      {
        node_path: {
          "entries": [lista de entries originales que caen en este nodo],
          "children": set(paths hijos directos),
          "parent": path padre o None si es raíz,
          "depth": profundidad del nodo,
        }
      }
    """
    tree = {}

    def ensure_node(path, depth, parent):
        """Crea un nodo en el árbol si no existe."""
        if path not in tree:
            tree[path] = {
                "entries":  [],
                "children": set(),
                "parent":   parent,
                "depth":    depth,
            }

    for entry in urls:
        url = entry.get("url", "").strip()
        if not url:
            continue

        parsed = urlparse(url)
        # Segmentos de path no vacíos
        parts = [p for p in parsed.path.split("/") if p]

        # Limitar profundidad: colapsar paths más profundos al nivel max_depth
        if len(parts) > max_depth:
            parts = parts[:max_depth]

        # Insertar cada nivel del path en el árbol
        for depth in range(len(parts) + 1):
            path_key  = "/" + "/".join(parts[:depth]) if depth > 0 else "/"
            parent_key = "/" + "/".join(parts[:depth-1]) if depth > 1 else ("/" if depth == 1 else None)

            ensure_node(path_key, depth, parent_key)

            if parent_key is not None and parent_key in tree:
                tree[parent_key]["children"].add(path_key)

        # Añadir el entry al nodo hoja (último nivel del path)
        leaf_key = "/" + "/".join(parts) if parts else "/"
        if leaf_key in tree:
            tree[leaf_key]["entries"].append(entry)

    return tree


def build_graph(config: dict, katana_results: dict, ffuf_results: dict) -> Network:
    """
    Construye el grafo con layout jerárquico de vis.js.

    Cambios respecto a la versión anterior:
      1. Layout JERÁRQUICO (top-down) en lugar de Barnes-Hut radial.
         Los paths se organizan como un árbol de directories: /a → /a/b → /a/b/c
      2. Árbol de paths real: cada nodo cuelga de su directorio padre,
         no todos del seed. Elimina la "explosión solar".
      3. Física SOLO durante estabilización inicial, luego se apaga.
         Los nodos quedan estáticos y arrastrables.

    Args:
        config         : Configuración global de la sesión.
        katana_results : Dict scope_label → list de URLs de Katana.
        ffuf_results   : Dict scope_label → list de rutas de ffuf.

    Returns:
        Objeto Network de PyVis configurado y listo para exportar.
    """
    log("PHASE", "Fase 3: Building hierarchical graph (PyVis)...")

    # ── Inicializar la red PyVis ─────────────────────────────────────────────
    net = Network(
        height="100vh",
        width="100%",
        bgcolor="#141414",
        font_color="#E8E8E8",
        directed=True,        # Dirigido para el layout jerárquico top-down
        notebook=False,
    )

    # ── Layout jerárquico de vis.js ──────────────────────────────────────────
    # "hierarchical" organiza los nodos en niveles visuales.
    # direction: "UD" = Up-Down (raíz arriba, hojas abajo).
    # sortMethod: "directed" respeta la dirección de los edges para el nivel.
    # levelSeparation: espacio vertical entre niveles.
    # nodeSpacing: espacio horizontal entre nodos del mismo nivel.
    # Physics desactivada desde el inicio: el layout jerárquico posiciona
    # los nodos matemáticamente, no necesita simulación física.
    options = """
    {
        "layout": {
            "hierarchical": {
                "enabled": true,
                "direction": "UD",
                "sortMethod": "directed",
                "levelSeparation": 120,
                "nodeSpacing": 160,
                "treeSpacing": 200,
                "blockShifting": true,
                "edgeMinimization": true,
                "parentCentralization": true
            }
        },
        "physics": {
            "enabled": false
        },
        "nodes": {
            "borderWidth": 2,
            "borderWidthSelected": 4,
            "shadow": {
                "enabled": true,
                "color": "rgba(0,0,0,0.8)",
                "size": 8,
                "x": 2,
                "y": 2
            },
            "font": {
                "size": 11,
                "color": "#E8E8E8",
                "face": "monospace",
                "multi": false
            }
        },
        "edges": {
            "arrows": {
                "to": {
                    "enabled": true,
                    "scaleFactor": 0.4
                }
            },
            "color": {
                "color": "#333333",
                "highlight": "#FFD700",
                "hover": "#666666"
            },
            "smooth": {
                "enabled": true,
                "type": "cubicBezier",
                "forceDirection": "vertical",
                "roundness": 0.4
            },
            "width": 1,
            "hoverWidth": 2
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": { "enabled": true },
            "dragNodes": true,
            "zoomView": true,
            "dragView": true
        }
    }
    """
    net.set_options(options)

    # ── Helpers internos ─────────────────────────────────────────────────────
    added_nodes = set()

    def add_node_safe(node_id, label, color, shape, size, title_html,
                      group="", level=0):
        if node_id not in added_nodes:
            net.add_node(
                node_id,
                label=label,
                color=color,
                shape=shape,
                size=size,
                title=title_html,
                group=group,
                level=level,                  # Nivel jerárquico explícito
                font={"color": "#E8E8E8", "size": 11},
            )
            added_nodes.add(node_id)

    def add_edge_safe(src, dst, color="#444444", width=1):
        if src in added_nodes and dst in added_nodes:
            net.add_edge(src, dst, color=color, width=width)

    # ─────────────────────────────────────────────────────────────────────────
    # NODO RAÍZ (nivel 0)
    # ─────────────────────────────────────────────────────────────────────────
    seed_id = config["target"]
    seed_tooltip = f"""
    <div style='background:#1a1a2e;color:#FFD700;padding:12px;border-radius:8px;
                border:1px solid #FFD700;font-family:monospace;min-width:250px;'>
        <b style='font-size:14px;'>🎯 ROOT TARGET</b>
        <hr style='border-color:#FFD700;margin:6px 0;'>
        <b>URL:</b> {config["target"]}<br>
        <b>Host:</b> {config["host"]}<br>
        <b>Puerto:</b> {config.get("port", 80)}<br>
        <b>Sesión:</b> {config["session_label"]}
    </div>
    """
    add_node_safe(
        node_id=seed_id, label=config["host"],
        color=COLOR_SEED, shape="star", size=35,
        title_html=seed_tooltip, group="seed", level=0,
    )

    # ─────────────────────────────────────────────────────────────────────────
    # NODOS DE VHOST (nivel 1)
    # ─────────────────────────────────────────────────────────────────────────
    for vhost in config.get("all_vhosts", []):
        vhost_id = f"vhost:{vhost}"
        tooltip  = f"""
        <div style='background:#1a1a2e;color:#9B59B6;padding:12px;border-radius:8px;
                    border:1px solid #9B59B6;font-family:monospace;min-width:220px;'>
            <b>🌐 VIRTUAL HOST</b>
            <hr style='border-color:#9B59B6;margin:6px 0;'>
            <b>VHOST:</b> {vhost}
        </div>
        """
        add_node_safe(
            node_id=vhost_id, label=vhost,
            color=COLOR_VHOST, shape="hexagon", size=22,
            title_html=tooltip, group="vhost", level=1,
        )
        add_edge_safe(seed_id, vhost_id, color=COLOR_VHOST, width=2)

    # ─────────────────────────────────────────────────────────────────────────
    # NODOS DE SUBFINDER — Subdominios descubiertos pasivamente
    # Se muestran como nodos intermedios entre el seed y sus ramas de Katana/ffuf
    # ─────────────────────────────────────────────────────────────────────────
    for subdomain in config.get("subfinder_results", []):
        sub_id = f"subfinder:{subdomain}"
        # Solo agregar si no es ya un VHOST configurado manualmente
        if f"vhost:{subdomain}" not in added_nodes:
            sub_tooltip = f"""
            <div style='background:#1a1a2e;color:#8E44AD;padding:12px;border-radius:8px;
                        border:1px solid #8E44AD;font-family:monospace;min-width:220px;'>
                <b>🔍 SUBDOMAIN (subfinder)</b>
                <hr style='border-color:#8E44AD;margin:6px 0;'>
                <b>Subdominio:</b> {subdomain}<br>
                <b>Origen:</b> Passive enumeration<br>
                <i style='color:#888;font-size:10px;'>Discovered without contacting the target</i>
            </div>
            """
            add_node_safe(
                node_id=sub_id, label=subdomain,
                color=COLOR_SUBDOMAIN, shape="hexagon", size=18,
                title_html=sub_tooltip, group="subfinder", level=1,
            )
            add_edge_safe(seed_id, sub_id, color=COLOR_SUBDOMAIN, width=1)

    # ─────────────────────────────────────────────────────────────────────────
    # NODOS DE KATANA — Árbol jerárquico de paths
    # ─────────────────────────────────────────────────────────────────────────
    log("INFO", "Building hierarchical path tree from Katana...")
    max_depth  = config.get("graph_depth", 2)
    node_limit = config.get("graph_node_limit", 300)

    # ── Presupuesto de nodos ────────────────────────────────────────────────
    # Nodos fijos (seed + VHOSTs + subfinder + ffuf) siempre se incluyen.
    # El resto del presupuesto se reparte entre los scopes de Katana.
    #
    # DISTRIBUCIÓN POR SCOPE (clave para multi-scope):
    # En lugar de un pool global (que www consumiría todo), cada scope
    # recibe una cuota igual del presupuesto disponible.
    # Excepción: el target base (www) recibe la mitad de la cuota de los
    # subdomains — los subdomains son más interesantes para un pentest.
    fixed_nodes   = 1 + len(config.get("all_vhosts", [])) + len(config.get("subfinder_results", []))
    ffuf_count    = sum(len(v) for v in ffuf_results.values())
    katana_budget = max(10, node_limit - fixed_nodes - ffuf_count) if node_limit else 999999

    # Calcular cuota por scope
    scopes_with_results = [sl for sl, urls in katana_results.items() if urls]
    n_scopes            = len(scopes_with_results) or 1
    base_host           = config["host"].lower()

    # El scope base (www) recibe la mitad que los subdomains
    # Fórmula: n_sub scopes * 1 + 1 base * 0.5 = total_parts
    n_sub_scopes  = sum(1 for sl in scopes_with_results if sl.lower() != base_host)
    n_base_scopes = n_scopes - n_sub_scopes
    total_parts   = n_sub_scopes * 2 + n_base_scopes * 1   # subdomains valen doble
    part_size     = max(5, katana_budget // total_parts) if total_parts else katana_budget

    quota_per_scope = {}
    for sl in scopes_with_results:
        if sl.lower() == base_host:
            quota_per_scope[sl] = part_size          # cuota base (menor)
        else:
            quota_per_scope[sl] = part_size * 2      # cuota subdominio (mayor)

    log("INFO", f"Katana budget: {katana_budget} nodos | "
                f"{n_scopes} scopes | cuota base={part_size} | cuota subdomains={part_size*2}")

    # ── Construir árbol por scope y aplicar cuota individual ─────────────────
    # Cada scope selecciona sus mejores nodos dentro de su cuota.
    # Ordenados por importancia: más entries primero, luego menos profundos.
    katana_nodes_by_scope: dict = {}
    total_katana_inserted = 0

    for scope_label, urls in katana_results.items():
        if not urls:
            continue

        tree  = _build_path_tree(urls, max_depth)
        quota = quota_per_scope.get(scope_label, part_size)

        # Recopilar nodos del scope ordenados por importancia
        scope_nodes = [
            (path_key, node)
            for path_key, node in tree.items()
            if node["depth"] > 0
        ]
        scope_nodes.sort(key=lambda x: (-len(x[1]["entries"]), x[1]["depth"]))

        # Aplicar scope quota
        if node_limit and len(scope_nodes) > quota:
            log("INFO", f"  {scope_label}: {len(scope_nodes)} nodos → {quota} (scope quota)")
            scope_nodes = scope_nodes[:quota]
        else:
            log("INFO", f"  {scope_label}: {len(scope_nodes)} nodos (within quota)")

        katana_nodes_by_scope[scope_label] = {pk: node for pk, node in scope_nodes}
        total_katana_inserted += len(scope_nodes)

    log("INFO", f"Katana nodes to insert: {total_katana_inserted} "
                f"(de {sum(len(u) for u in katana_results.values())} URLs totales)")

    for scope_label, urls in katana_results.items():
        # El padre de este scope es su VHOST o el seed si no hay VHOSTs
        scope_parent = f"vhost:{scope_label}" if scope_label in config.get("all_vhosts", []) else seed_id
        scope_level  = 2 if scope_label in config.get("all_vhosts", []) else 1

        # Usar el árbol pre-filtrado (con límite de nodos ya aplicado)
        tree = katana_nodes_by_scope.get(scope_label, {})

        # Ordenar los paths por profundidad para insertar padres antes que hijos
        sorted_paths = sorted(tree.keys(), key=lambda p: tree[p]["depth"])

        for path_key in sorted_paths:
            node     = tree[path_key]
            depth    = node["depth"]
            entries  = node["entries"]
            children = node["children"]
            count    = len(entries)

            # Nodo raíz del árbol de paths (/) → conectar al scope_parent
            if depth == 0:
                continue   # La raíz "/" no genera nodo propio, usa scope_parent

            # ID único por scope + path para evitar colisiones entre VHOSTs
            node_id = f"katana:{scope_label}:{path_key}"
            label   = path_key.split("/")[-1] or path_key   # Solo el último segmento

            # Mostrar contador si el nodo agrupa múltiples entries
            if count > 1:
                label = f"{label}  ×{count}"
            elif count == 0 and children:
                # Nodo de directorio intermedio sin entries propios
                label = f"{label}/"

            # Tamaño proporcional a la cantidad de entries agrupados
            node_size = min(8 + count // 2, 20)

            # Construir lista de URLs para el tooltip (máx 10)
            url_items = "".join(
                f"<li style='margin:2px 0;color:#79C0FF;'>{e.get('url','')[:80]}</li>"
                for e in entries[:10]
            )
            more = f"<li style='color:#888'>... y {count-10} más</li>" if count > 10 else ""

            # Detectar tecnología predominante en las entries del nodo
            techs = [e.get("tech", "") for e in entries if e.get("tech")]
            tech  = max(set(techs), key=techs.count) if techs else ""
            tech_color = TECH_COLORS.get(tech, COLOR_VISIBLE)
            tech_html  = (
                f"<b>Tech:</b> <span style='color:{tech_color};font-weight:bold'>"
                f"{tech.upper()}</span><br>"
            ) if tech else ""

            # Colorear el nodo según la tecnología detectada
            node_color = tech_color if tech else COLOR_VISIBLE

            # Recopilar formularios únicos de todas las entries del nodo
            all_forms = list({f for e in entries for f in e.get("forms", [])})
            forms_html = ""
            if all_forms:
                fields = ", ".join(all_forms[:8])
                forms_html = (
                    f"<b style='color:#E91E63'>📝 Inputs:</b> "
                    f"<span style='color:#F48FB1'>{fields}</span><br>"
                )

            tooltip = f"""
            <div style='background:#0d1117;color:#58A6FF;padding:12px;border-radius:8px;
                        border:1px solid #1f77b4;font-family:monospace;max-width:440px;'>
                <b>🔵 PATH (Katana)</b>
                <hr style='border-color:#1f77b4;margin:6px 0;'>
                <b>Path:</b> {path_key}<br>
                <b>Grouped URLs:</b> <span style='color:#FFD700'>{count}</span><br>
                <b>Children:</b> {len(children)}<br>
                <b>Scope:</b> {scope_label}<br>
                {tech_html}{forms_html}
                <hr style='border-color:#333;margin:6px 0;'>
                <ul style='margin:4px 0;padding-left:14px;font-size:10px;
                           max-height:120px;overflow-y:auto;'>
                    {url_items}{more}
                </ul>
            </div>
            """

            # Nodos con formularios detectados usan forma "diamond" para destacar
            node_shape = "diamond" if all_forms else "dot"
            add_node_safe(
                node_id=node_id, label=label,
                color=node_color, shape=node_shape,
                size=node_size, title_html=tooltip,
                group=f"katana_{scope_label}",
                level=scope_level + depth,
            )

            # Conectar al padre: si depth==1 el padre es scope_parent,
            # si depth>1 el padre es el nodo del path padre en este scope
            if depth == 1:
                add_edge_safe(scope_parent, node_id, color=COLOR_VISIBLE, width=1)
            else:
                parent_path = node["parent"]
                parent_id   = f"katana:{scope_label}:{parent_path}"
                # Si el padre no existe en el grafo (por colapso de profundidad),
                # conectar directamente al scope_parent
                if parent_id in added_nodes:
                    add_edge_safe(parent_id, node_id, color=COLOR_VISIBLE, width=1)
                else:
                    add_edge_safe(scope_parent, node_id, color=COLOR_VISIBLE, width=1)

    katana_node_count = len(added_nodes)
    log("INFO", f"Katana tree: {katana_node_count} nodos (profundidad {max_depth})")

    # ─────────────────────────────────────────────────────────────────────────
    # NODOS DE FFUF — Hallazgos individuales (nunca se colapsan)
    # Se conectan al scope_parent o al nodo de path más cercano si existe
    # ─────────────────────────────────────────────────────────────────────────
    log("INFO", "Añadiendo findings de ffuf...")

    for scope_label, paths in ffuf_results.items():
        scope_parent = f"vhost:{scope_label}" if scope_label in config.get("all_vhosts", []) else seed_id
        scope_level  = 2 if scope_label in config.get("all_vhosts", []) else 1

        for entry in paths:
            url    = entry.get("url", "").strip()
            status = entry.get("status", 0)
            length = entry.get("length", 0)
            words  = entry.get("words", 0)
            redir  = entry.get("redirect", "")
            ext    = entry.get("extension", "")

            if not url:
                continue

            if status == 403:
                node_color   = COLOR_HIDDEN_F
                border_color = "#E74C3C"
                icon         = "🔴"
                prefix       = "[403]"
            elif status in (301, 302):
                node_color   = COLOR_HIDDEN_OK
                border_color = "#FF8C00"
                icon         = "🟠"
                prefix       = f"[{status}]"
            else:
                node_color   = COLOR_HIDDEN_OK
                border_color = "#FF8C00"
                icon         = "🟠"
                prefix       = "[200]"

            parsed    = urlparse(url)
            path_segs = [p for p in parsed.path.split("/") if p]
            path_label = parsed.path[:50] or "/"
            node_label = f"{prefix} {path_label}"

            redir_html = f"<b>Redirect →</b> {redir}<br>" if redir else ""
            ext_html   = f"<b>Extensión:</b> {ext}<br>" if ext else ""
            tooltip = f"""
            <div style='background:#0d1117;color:#FF8C00;padding:12px;border-radius:8px;
                        border:1px solid {border_color};font-family:monospace;max-width:400px;'>
                <b>{icon} ffuf FINDING</b>
                <hr style='border-color:{border_color};margin:6px 0;'>
                <b>URL:</b> <a href='{url}' style='color:#FFA500;'>{url}</a><br>
                <b>HTTP Status:</b>
                    <span style='color:{"#E74C3C" if status==403 else "#2ECC71"}'>{status}</span><br>
                <b>Size:</b> {length} bytes | <b>Words:</b> {words}<br>
                {ext_html}{redir_html}
                <b>Scope:</b> {scope_label}
                <hr style='border-color:{border_color};margin:6px 0;'>
                <i style='color:#888;font-size:10px;'>💡 Investigate manually</i>
            </div>
            """

            node_id = f"ffuf:{url}:{status}"

            # Intentar conectar al nodo de path padre de Katana si existe,
            # para que los findings de ffuf aparezcan en la rama correcta
            # del árbol en lugar de colgar todos del scope_parent.
            parent_id    = scope_parent
            parent_level = scope_level

            if path_segs:
                # Buscar el nodo de path más profundo que exista en el grafo
                for depth in range(min(len(path_segs), max_depth), 0, -1):
                    candidate_path = "/" + "/".join(path_segs[:depth])
                    candidate_id   = f"katana:{scope_label}:{candidate_path}"
                    if candidate_id in added_nodes:
                        parent_id    = candidate_id
                        parent_level = scope_level + depth
                        break

            add_node_safe(
                node_id=node_id, label=node_label,
                color=node_color, shape="triangle",
                size=14, title_html=tooltip,
                group=f"ffuf_{scope_label}",
                level=parent_level + 1,
            )
            add_edge_safe(parent_id, node_id, color=node_color, width=1)

    total_nodes = len(net.nodes)
    total_edges = len(net.edges)
    log("OK", f"Graph built: \033[96m{total_nodes}\033[0m nodos, \033[96m{total_edges}\033[0m edges")

    return net


# =============================================================================
# SECCIÓN 6: EXPORTACIÓN DEL GRAFO HTML AUTOCONTENIDO
# =============================================================================

def _norm_color(c, group: str = "", node_id: str = "") -> str:
    """Normaliza el color de PyVis a string CSS.
    PyVis puede guardar el color como string, dict, o None.
    Si es None (PyVis lo descarta), se infiere del grupo del nodo.
    """
    # Intentar extraer el color directamente
    if isinstance(c, str) and c.startswith("#"):
        return c
    if isinstance(c, dict):
        v = c.get("color", c.get("background", c.get("border", "")))
        if isinstance(v, str) and v.startswith("#"):
            return v

    # Color es None o inválido → inferir del grupo del nodo
    if group == "seed":
        return "#FFD700"       # Dorado
    if group in ("vhost", "subfinder"):
        return "#9B59B6"       # Violeta
    if group.startswith("ffuf_"):
        # ffuf: inferir 403 (rojo) vs 200/301 (naranja) del node_id
        if node_id.endswith(":403"):
            return "#E74C3C"   # Rojo
        return "#FF8C00"       # Naranja
    if group.startswith("katana_"):
        return "#1f77b4"       # Azul
    return "#1f77b4"           # Default azul


def export_graph(net, config: dict) -> Path:
    """
    Genera un HTML autocontenido con SVG + JS embebido.
    Sin dependencias externas — funciona desde file:/// sin servidor.
    El layout jerárquico se calcula en Python y se pasa como datos JSON
    al JS embebido que maneja interactividad (click, hover, pan, zoom).
    """
    import json as _json
    import math as _math

    output_dir  = config["output_dir"]
    output_file = output_dir / f"recon_graph_{config['session_label']}.html"
    log("PHASE", f"Exporting SVG graph to: {output_file}")

    # ── Extraer nodos y edges del objeto PyVis ───────────────────────────────
    nodes_raw = []
    for node in net.nodes:
        nodes_raw.append({
            "id":    str(node["id"]),
            "label": node.get("label", str(node["id"]))[:40],
            "color": _norm_color(node.get("color"), node.get("group", ""), str(node.get("id", ""))),
            "shape": node.get("shape", "dot"),
            "size":  int(node.get("size", 10)),
            "title": node.get("title", ""),
            "group": node.get("group", ""),
            "level": int(node.get("level", 0)),
        })

    # Mapa de colores por nodo para heredar en edges sin color
    _ncmap = {n["id"]: n["color"] for n in nodes_raw}

    edges_raw = []
    for edge in net.edges:
        dst = str(edge["to"])
        ec  = edge.get("color")
        # Si PyVis perdió el color del edge, heredar del nodo destino
        if ec is None:
            ec = _ncmap.get(dst, "#444444")
        elif isinstance(ec, dict):
            ec = ec.get("color", "#444444")
        edges_raw.append({
            "from":  str(edge["from"]),
            "to":    dst,
            "color": ec if isinstance(ec, str) else "#444444",
        })

    # ── Calcular posiciones del layout jerárquico en Python ──────────────────
    # Agrupar nodos por nivel
    levels = {}
    for n in nodes_raw:
        lv = n["level"]
        levels.setdefault(lv, []).append(n)

    max_level   = max(levels.keys()) if levels else 0
    # Calcular ancho dinámico: mínimo 80px por nodo en el nivel más poblado
    max_nodes   = max((len(v) for v in levels.values()), default=1)
    NODE_SEP    = 90     # separación mínima horizontal entre nodos
    W           = max(1400, max_nodes * NODE_SEP + 200)
    LEVEL_H     = 150    # separación vertical entre niveles (más espacio)
    H           = max(600, (max_level + 1) * LEVEL_H + 120)

    for lv in sorted(levels.keys()):
        nodes_at_level = levels[lv]
        n = len(nodes_at_level)
        for i, node in enumerate(nodes_at_level):
            x = W * (i + 1) / (n + 1)
            y = 60 + lv * LEVEL_H
            # Escalonar labels: nodos pares suben el texto, impares bajan
            # Esto separa visualmente los labels de nodos contiguos
            node["label_offset"] = -18 if (i % 2 == 0) else 16
            node["x"] = x
            node["y"] = y

    nodes_json   = _json.dumps(nodes_raw,  ensure_ascii=False)
    edges_json   = _json.dumps(edges_raw,  ensure_ascii=False)
    session_json = _json.dumps({
        "target":   config["target"],
        "host":     config["host"],
        "session":  config["session_label"],
        "no_forms": config.get("no_forms", False),
        "nodes":    len(nodes_raw),
        "edges":    len(edges_raw),
        "W": W, "H": H,
    }, ensure_ascii=False)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Spider Noir — {config["host"]}</title>
<style>
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ background:#141414; font-family:'Courier New',monospace;
       color:#e8e8e8; overflow:hidden; height:100vh;
       display:flex; flex-direction:column; }}
#header {{
    background:linear-gradient(90deg,#0d0d0d,#1a1a2e);
    border-bottom:1px solid #FFD700;
    padding:6px 20px; height:38px; flex-shrink:0;
    display:flex; align-items:center; justify-content:space-between;
}}
#header .title {{ color:#FFD700; font-size:13px; font-weight:bold; letter-spacing:2px; }}
#header .meta  {{ color:#666; font-size:11px; }}
#main {{ display:flex; flex:1; overflow:hidden; }}
#canvas-wrap {{
    flex:1; overflow:hidden; position:relative; cursor:grab;
    background:#141414;
}}
#canvas-wrap:active {{ cursor:grabbing; }}
#graph-svg {{ display:block; }}
#panel {{
    width:300px; min-width:300px; background:#0d0d0d;
    border-left:1px solid #1e1e1e;
    display:flex; flex-direction:column; overflow:hidden;
}}
#ph {{
    background:#111; border-bottom:1px solid #1e1e1e;
    padding:10px 14px; color:#FFD700;
    font-size:12px; font-weight:bold; flex-shrink:0;
}}
#ni {{
    padding:12px 14px; border-bottom:1px solid #1a1a1a;
    font-size:11px; min-height:120px; flex-shrink:0; overflow-y:auto;
}}
.ni-empty {{ color:#333; font-style:italic; text-align:center;
             padding-top:28px; line-height:1.9; }}
#al {{ flex:1; overflow-y:auto; padding:8px 12px; }}
.ag {{ color:#444; font-size:10px; letter-spacing:2px;
       text-transform:uppercase; margin:10px 0 5px;
       border-bottom:1px solid #1a1a1a; padding-bottom:3px; }}
.ab {{
    display:block; width:100%; text-align:left;
    background:#141414; border:1px solid #222; color:#ccc;
    font-family:monospace; font-size:11px;
    padding:7px 10px; margin-bottom:4px;
    border-radius:4px; cursor:pointer; transition:all .15s;
}}
.ab:hover {{ background:#1e1e1e; border-color:#FFD700; color:#FFD700; }}
.ab.danger:hover {{ border-color:#E74C3C; color:#E74C3C; }}
.ab.info:hover   {{ border-color:#1f77b4; color:#79C0FF; }}
.ab .sc {{ display:block; color:#333; font-size:9px; margin-top:2px;
           white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.ab:hover .sc {{ color:#555; }}
#legend {{
    position:absolute; bottom:12px; left:12px;
    background:rgba(13,13,13,.92); border:1px solid #222;
    border-radius:6px; padding:10px 14px; font-size:11px; z-index:10;
    pointer-events:none;
}}
#legend h4 {{ color:#FFD700; margin-bottom:7px; font-size:11px;
              border-bottom:1px solid #222; padding-bottom:4px; }}
.li {{ display:flex; align-items:center; gap:7px; margin:3px 0; color:#999; }}
#tip {{
    position:fixed; z-index:9999; pointer-events:none;
    display:none; max-width:380px; word-wrap:break-word;
    filter:drop-shadow(0 4px 12px rgba(0,0,0,.85));
    font-family:monospace; font-size:11px;
}}
#modal {{
    display:none; position:fixed; top:0; left:0; right:0; bottom:0;
    background:rgba(0,0,0,.75); z-index:99999;
    align-items:center; justify-content:center;
}}
#modal.show {{ display:flex; }}
#mbox {{
    background:#0d0d0d; border:1px solid #FFD700;
    border-radius:8px; padding:20px; max-width:660px; width:90%;
}}
#mbox h3 {{ color:#FFD700; margin-bottom:10px; font-size:13px; }}
#mcmd {{
    background:#111; padding:12px; border-radius:4px; color:#2ECC71;
    font-size:11px; white-space:pre-wrap; word-break:break-all;
    max-height:180px; overflow-y:auto; margin-bottom:10px;
    font-family:monospace;
}}
#mhint {{ color:#555; font-size:10px; margin-bottom:10px; }}
#mclose {{
    background:#1a1a1a; border:1px solid #333; color:#aaa;
    padding:5px 16px; border-radius:4px; cursor:pointer;
    font-family:monospace; font-size:11px;
}}
#toast {{
    position:fixed; bottom:20px; right:310px;
    background:#2ECC71; color:#000; font-size:12px;
    padding:5px 14px; border-radius:4px; opacity:0;
    transition:opacity .3s; pointer-events:none; z-index:9999;
}}
</style>
</head>
<body>
<div id="header">
  <span class="title">🕷 SPIDER NOIR</span>
  <span class="meta">
    Target: <span style="color:#96CEB4">{config["target"]}</span>
    &nbsp;|&nbsp; {len(nodes_raw)} nodos · {len(edges_raw)} edges
  </span>
</div>
<div id="main">
  <div id="canvas-wrap">
    <svg id="graph-svg" xmlns="http://www.w3.org/2000/svg"></svg>
    <div id="legend">
      <h4>📊 LEGEND</h4>
      <div class="li"><span style="color:#FFD700;font-size:15px">★</span> Root</div>
      <div class="li"><span style="color:#9B59B6;font-size:14px">⬡</span> VHOST / Subfinder</div>
      <div class="li"><span style="color:#1f77b4;font-size:13px">●</span> Katana (visible)</div>
      <div class="li"><span style="color:#FF8C00;font-size:13px">▲</span> ffuf 200/301</div>
      <div class="li"><span style="color:#E74C3C;font-size:13px">▲</span> ffuf 403</div>
      <div style="margin-top:6px;border-top:1px solid #222;padding-top:5px;
                  color:#333;font-size:9px;">Color = detected technology</div>
    </div>
  </div>
  <div id="panel">
    <div id="ph">⚡ ACTION PANEL</div>
    <div id="ni">
      <div class="ni-empty">← Click on a node<br>to see its details<br>and available actions</div>
    </div>
    <div id="al"></div>
  </div>
</div>
<div id="tip"></div>
<div id="toast">✓ Copied</div>
<div id="modal"><div id="mbox">
  <h3>⚡ Command copied to clipboard</h3>
  <div id="mcmd"></div>
  <div id="mhint">Paste in your terminal with Ctrl+Shift+V</div>
  <button id="mclose">Close</button>
</div></div>

<script>
// ═══════════════════════════════════════════════════════════════════════
// SPIDER NOIR — SVG + JS autocontenido (sin dependencias externas)
// ═══════════════════════════════════════════════════════════════════════

var S    = {session_json};
var NODES = {nodes_json};
var EDGES = {edges_json};

// Índice de nodos por id
var NMAP = {{}};
NODES.forEach(function(n) {{ NMAP[n.id] = n; }});

// ── Canvas y viewport ────────────────────────────────────────────────
var wrap = document.getElementById('canvas-wrap');
var svg  = document.getElementById('graph-svg');
var W = S.W, H = S.H;

// Viewport: pan y zoom
var vx = 0, vy = 0, vscale = 1;
var MIN_SCALE = 0.15, MAX_SCALE = 4;

function setViewport() {{
    var cw = wrap.clientWidth, ch = wrap.clientHeight;
    svg.setAttribute('width',  cw);
    svg.setAttribute('height', ch);
    svg.setAttribute('viewBox', cw + ' ' + ch);
    // Centrar inicialmente
    vx = (cw - W * vscale) / 2;
    vy = 20;
    renderAll();
}}

// ── Renderizar el grafo ─────────────────────────────────────────────
var gEdges, gNodes, gLabels;

function buildSVG() {{
    svg.innerHTML = '';
    var defs = svgEl('defs');
    // Flecha para edges
    var marker = svgEl('marker');
    marker.setAttribute('id','arr');
    marker.setAttribute('markerWidth','6');
    marker.setAttribute('markerHeight','6');
    marker.setAttribute('refX','5');
    marker.setAttribute('refY','3');
    marker.setAttribute('orient','auto');
    var path = svgEl('path');
    path.setAttribute('d','M0,0 L6,3 L0,6 Z');
    path.setAttribute('fill','#555');
    marker.appendChild(path);
    defs.appendChild(marker);
    svg.appendChild(defs);

    // Grupo principal (transformado por pan/zoom)
    var g = svgEl('g'); g.id = 'g-main'; svg.appendChild(g);

    // Edges
    gEdges = svgEl('g'); g.appendChild(gEdges);
    EDGES.forEach(function(e) {{
        var a = NMAP[e.from], b = NMAP[e.to];
        if (!a || !b) return;
        var line = svgEl('line');
        line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
        line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
        line.setAttribute('stroke', e.color || '#444');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('marker-end','url(#arr)');
        line.setAttribute('data-from', e.from);
        line.setAttribute('data-to',   e.to);
        gEdges.appendChild(line);
    }});

    // Nodos
    gNodes = svgEl('g'); g.appendChild(gNodes);
    gLabels= svgEl('g'); g.appendChild(gLabels);

    NODES.forEach(function(n) {{
        var g2 = svgEl('g');
        g2.setAttribute('cursor','pointer');
        g2.setAttribute('data-id', n.id);
        g2.setAttribute('class','node-g');

        var shape = n.shape || 'dot';
        var sz    = n.size  || 10;
        // Asegurar que col sea string (por si acaso llega como objeto)
        var col = (typeof n.color === 'object' && n.color !== null)
                  ? (n.color.color || '#1f77b4')
                  : (n.color || '#1f77b4');

        if (shape === 'star') {{
            var star = makeStar(n.x, n.y, sz * 1.4, col);
            g2.appendChild(star);
        }} else if (shape === 'hexagon') {{
            var hex = makeHex(n.x, n.y, sz, col);
            g2.appendChild(hex);
        }} else if (shape === 'triangle') {{
            var tri = makeTri(n.x, n.y, sz, col);
            g2.appendChild(tri);
        }} else if (shape === 'diamond') {{
            var dia = makeDia(n.x, n.y, sz, col);
            g2.appendChild(dia);
        }} else {{
            var c = svgEl('circle');
            c.setAttribute('cx', n.x); c.setAttribute('cy', n.y);
            c.setAttribute('r', sz); c.setAttribute('fill', col);
            c.setAttribute('stroke', '#222'); c.setAttribute('stroke-width','1');
            g2.appendChild(c);
        }}

        // Eventos
        // Solo mostrar panel si no estamos arrastrando (evitar falso click al soltar)
        g2.addEventListener('click', function(e) {{
            e.stopPropagation();
            if (Math.abs(e.clientX - startX) < 5 && Math.abs(e.clientY - startY) < 5) {{
                showPanel(n.id);
            }}
        }});
        g2.addEventListener('mouseenter', function(e) {{ showTip(n, e); }});
        g2.addEventListener('mouseleave', function()  {{ hideTip(); }});
        gNodes.appendChild(g2);

        // Label — con data-nid para poder moverlo al arrastrar el nodo
        var txt = svgEl('text');
        txt.setAttribute('data-nid', n.id);
        txt.setAttribute('x', n.x);
        // Escalonar el label según el índice del nodo en su nivel
        // para evitar solapamiento entre nodos contiguos
        var loff = n.label_offset !== undefined ? n.label_offset : 13;
        var ly   = loff >= 0 ? n.y + sz + loff : n.y + loff;
        txt.setAttribute('y', ly);
        // Fondo semitransparente detrás del texto para mejor legibilidad
        var bg = svgEl('rect');
        bg.setAttribute('data-nid', n.id);
        var lw = Math.min(n.label.length * 6.5, 160);
        bg.setAttribute('x',      n.x - lw/2 - 2);
        bg.setAttribute('y',      ly - 10);
        bg.setAttribute('width',  lw + 4);
        bg.setAttribute('height', 12);
        bg.setAttribute('fill',   'rgba(20,20,20,0.7)');
        bg.setAttribute('rx',     '2');
        bg.setAttribute('pointer-events', 'none');
        gLabels.appendChild(bg);
        txt.setAttribute('text-anchor','middle');
        txt.setAttribute('fill','#ccc');
        txt.setAttribute('font-size','10');
        txt.setAttribute('font-family','monospace');
        txt.setAttribute('pointer-events','none');
        txt.textContent = n.label;
        gLabels.appendChild(txt);
    }});
}}

function renderAll() {{
    var gm = document.getElementById('g-main');
    if (gm) gm.setAttribute('transform',
        'translate(' + vx + ',' + vy + ') scale(' + vscale + ')');
}}

// ── Formas SVG ──────────────────────────────────────────────────────
function svgEl(tag) {{
    return document.createElementNS('http://www.w3.org/2000/svg', tag);
}}

function makeStar(cx, cy, r, col) {{
    var pts = [];
    for (var i = 0; i < 10; i++) {{
        var angle = (i * Math.PI / 5) - Math.PI / 2;
        var rad   = (i % 2 === 0) ? r : r * 0.45;
        pts.push((cx + rad * Math.cos(angle)).toFixed(1) + ',' +
                 (cy + rad * Math.sin(angle)).toFixed(1));
    }}
    var p = svgEl('polygon');
    p.setAttribute('points', pts.join(' '));
    p.setAttribute('fill', col);
    p.setAttribute('stroke','#222');
    p.setAttribute('stroke-width','1');
    return p;
}}

function makeHex(cx, cy, r, col) {{
    var pts = [];
    for (var i = 0; i < 6; i++) {{
        var a = (i * Math.PI / 3) - Math.PI / 6;
        pts.push((cx + r * Math.cos(a)).toFixed(1) + ',' +
                 (cy + r * Math.sin(a)).toFixed(1));
    }}
    var p = svgEl('polygon');
    p.setAttribute('points', pts.join(' '));
    p.setAttribute('fill', col);
    p.setAttribute('stroke','#222');
    p.setAttribute('stroke-width','1');
    return p;
}}

function makeTri(cx, cy, r, col) {{
    var pts = [
        cx + ',' + (cy - r * 1.2),
        (cx + r * 1.1) + ',' + (cy + r * 0.7),
        (cx - r * 1.1) + ',' + (cy + r * 0.7)
    ].join(' ');
    var p = svgEl('polygon');
    p.setAttribute('points', pts);
    p.setAttribute('fill', col);
    p.setAttribute('stroke','#222');
    p.setAttribute('stroke-width','1');
    return p;
}}

function makeDia(cx, cy, r, col) {{
    var pts = [cx+','+( cy-r), (cx+r)+','+cy, cx+','+(cy+r), (cx-r)+','+cy].join(' ');
    var p = svgEl('polygon');
    p.setAttribute('points', pts);
    p.setAttribute('fill', col);
    p.setAttribute('stroke','#222');
    p.setAttribute('stroke-width','1');
    return p;
}}

// ── Drag de nodos + Pan ───────────────────────────────────────────────
var panning     = false, startX, startY, startVX, startVY;
var dragNode    = null;   // nodo siendo arrastrado (objeto de NODES)
var dragStartNX = 0;      // posición original del nodo al empezar a arrastrar
var dragStartNY = 0;

// Mousedown en el canvas: si clickea un nodo → drag del nodo; si no → pan
wrap.addEventListener('mousedown', function(e) {{
    var nodeEl = e.target.closest('.node-g');
    if (nodeEl) {{
        // Drag de nodo
        var nid = nodeEl.getAttribute('data-id');
        dragNode = NMAP[nid] || null;
        if (dragNode) {{
            dragStartNX = dragNode.x;
            dragStartNY = dragNode.y;
            startX = e.clientX;
            startY = e.clientY;
            e.preventDefault();
            e.stopPropagation();
        }}
    }} else {{
        // Pan del canvas
        panning = true;
        startX = e.clientX; startY = e.clientY;
        startVX = vx; startVY = vy;
    }}
}});

window.addEventListener('mousemove', function(e) {{
    if (dragNode) {{
        // Arrastrar nodo: convertir delta de pantalla a coordenadas SVG
        var dx = (e.clientX - startX) / vscale;
        var dy = (e.clientY - startY) / vscale;
        var newX = dragStartNX + dx;
        var newY = dragStartNY + dy;

        // Actualizar posición en los datos
        dragNode.x = newX;
        dragNode.y = newY;

        // Mover el grupo SVG del nodo (forma + hit area)
        var nodeEls = document.querySelectorAll('.node-g[data-id="' + dragNode.id + '"]');
        nodeEls.forEach(function(el) {{
            // Reconstruir la forma en la nueva posición
            el.innerHTML = '';
            var shape = dragNode.shape || 'dot';
            var sz    = dragNode.size  || 10;
            var col   = (typeof dragNode.color === 'object' && dragNode.color !== null)
                        ? (dragNode.color.color || '#1f77b4')
                        : (dragNode.color || '#1f77b4');
            var child;
            if (shape === 'star')          child = makeStar(newX, newY, sz * 1.4, col);
            else if (shape === 'hexagon')  child = makeHex(newX, newY, sz, col);
            else if (shape === 'triangle') child = makeTri(newX, newY, sz, col);
            else if (shape === 'diamond')  child = makeDia(newX, newY, sz, col);
            else {{
                child = svgEl('circle');
                child.setAttribute('cx', newX); child.setAttribute('cy', newY);
                child.setAttribute('r', sz);    child.setAttribute('fill', col);
                child.setAttribute('stroke','#222'); child.setAttribute('stroke-width','1');
            }}
            el.appendChild(child);
        }});

        // Mover labels (text + bg rect)
        var labels = document.querySelectorAll('[data-nid="' + dragNode.id + '"]');
        var sz = dragNode.size || 10;
        var loff = dragNode.label_offset !== undefined ? dragNode.label_offset : 13;
        var ly   = loff >= 0 ? newY + sz + loff : newY + loff;
        labels.forEach(function(el) {{
            if (el.tagName === 'text') {{
                el.setAttribute('x', newX);
                el.setAttribute('y', ly);
            }} else if (el.tagName === 'rect') {{
                var lw = parseFloat(el.getAttribute('width'));
                el.setAttribute('x', newX - lw/2);
                el.setAttribute('y', ly - 10);
            }}
        }});

        // Mover edges conectados
        var lines = gEdges.querySelectorAll('line');
        lines.forEach(function(line) {{
            if (line.getAttribute('data-from') === dragNode.id) {{
                line.setAttribute('x1', newX);
                line.setAttribute('y1', newY);
            }}
            if (line.getAttribute('data-to') === dragNode.id) {{
                line.setAttribute('x2', newX);
                line.setAttribute('y2', newY);
            }}
        }});

        hideTip();
        return;
    }}

    if (panning) {{
        vx = startVX + (e.clientX - startX);
        vy = startVY + (e.clientY - startY);
        renderAll();
    }}
}});

window.addEventListener('mouseup', function() {{
    dragNode = null;
    panning  = false;
}});

wrap.addEventListener('wheel', function(e) {{
    e.preventDefault();
    var rect  = wrap.getBoundingClientRect();
    var mx    = e.clientX - rect.left;
    var my    = e.clientY - rect.top;
    var delta = e.deltaY > 0 ? 0.85 : 1.18;
    var ns    = Math.max(MIN_SCALE, Math.min(MAX_SCALE, vscale * delta));
    vx = mx - (mx - vx) * (ns / vscale);
    vy = my - (my - vy) * (ns / vscale);
    vscale = ns;
    renderAll();
}}, {{ passive: false }});

// Click en fondo → limpiar panel
wrap.addEventListener('click', function(e) {{
    if (!e.target.closest('.node-g')) {{
        document.getElementById('ni').innerHTML =
            '<div class="ni-empty">← Click on a node<br>to see its details<br>and available actions</div>';
        document.getElementById('al').innerHTML = '';
    }}
}});

// ── Tooltip ─────────────────────────────────────────────────────────
var tip = document.getElementById('tip');

function showTip(n, e) {{
    if (!n.title) return;
    // Decodificar entidades HTML del title
    var ta = document.createElement('textarea');
    ta.innerHTML = n.title;
    tip.innerHTML = ta.value;
    tip.style.display = 'block';
    moveTip(e);
}}
function hideTip()  {{ tip.style.display = 'none'; }}
function moveTip(e) {{
    var x = e.clientX + 16, y = e.clientY + 16;
    var tw = tip.offsetWidth || 380, th = tip.offsetHeight || 180;
    if (x + tw > window.innerWidth  - 310) x = e.clientX - tw - 10;
    if (y + th > window.innerHeight - 10)  y = e.clientY - th - 10;
    tip.style.left = x + 'px'; tip.style.top = y + 'px';
}}
document.addEventListener('mousemove', function(e) {{
    if (tip.style.display !== 'none') moveTip(e);
}});

// ── Comandos y modal ─────────────────────────────────────────────────
var TERM = 'xfce4-terminal';
var A = {{
    curl:    function(u) {{ return 'curl -sI --max-time 10 "' + u + '"'; }},
    browser: function(u) {{ return 'xdg-open "' + u + '"'; }},
    whatweb: function(u) {{ return 'whatweb -v "' + u + '"'; }},
    nmap:    function(u) {{ try {{ var h=new URL(u).hostname; }} catch(e) {{ var h=u; }} return 'nmap -sV -sC -p 80,443,8080,8443 ' + h; }},
    gobuster:function(u) {{ return 'gobuster dir -u "' + u + '" -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,bak'; }},
    ffuf:    function(u) {{ return 'ffuf -u "' + u.replace(/[/]+$/, '') + '/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,301,403'; }},
    nikto:   function(u) {{ return 'nikto -h "' + u + '"'; }},
    sqlmap:  function(u) {{ return 'sqlmap -u "' + u + '" --batch --level=2 --risk=1'; }},
    nuclei:  function(u) {{ return 'nuclei -u "' + u + '" -severity low,medium,high,critical'; }},
    bypass:  function(u) {{ return 'curl -sv -H "X-Forwarded-For: 127.0.0.1" "' + u + '"'; }},
    sslyze:  function(u) {{ try {{ var h=new URL(u).hostname; }} catch(e) {{ var h=u; }} return 'sslyze ' + h + ':443'; }},
}};

function runCmd(cmd) {{
    document.getElementById('mcmd').textContent = cmd;
    document.getElementById('modal').classList.add('show');
    if (navigator.clipboard) {{
        navigator.clipboard.writeText(cmd).catch(function() {{ fbCopy(cmd); }});
    }} else {{ fbCopy(cmd); }}
    var t = document.getElementById('toast');
    t.style.opacity = '1';
    setTimeout(function() {{ t.style.opacity = '0'; }}, 1800);
}}
function fbCopy(txt) {{
    var ta = document.createElement('textarea');
    ta.value = txt; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select();
    try {{ document.execCommand('copy'); }} catch(e) {{}}
    document.body.removeChild(ta);
}}
document.getElementById('mclose').onclick = function() {{
    document.getElementById('modal').classList.remove('show');
}};
document.getElementById('modal').addEventListener('click', function(e) {{
    if (e.target === this) this.classList.remove('show');
}});

function mkBtn(icon, label, cmd, cls) {{
    var b = document.createElement('button');
    b.className = 'ab ' + (cls || '');
    b.innerHTML = icon + ' ' + label +
        '<span class="sc">' + cmd.substring(0, 55) + (cmd.length > 55 ? '…' : '') + '</span>';
    b.onclick = function() {{ runCmd(cmd); }};
    return b;
}}
function mkGrp(txt) {{
    var d = document.createElement('div');
    d.className = 'ag'; d.textContent = txt; return d;
}}

// ── Panel de acciones ────────────────────────────────────────────────
function showPanel(nodeId) {{
    var n  = NMAP[nodeId];
    if (!n) return;
    var ni = document.getElementById('ni');
    var al = document.getElementById('al');

    // Reconstruir URL desde nodeId
    var url = S.target;
    var sid = String(nodeId);
    if (sid.startsWith('ffuf:')) {{
        var parts = sid.split(':'); url = parts.slice(1,-1).join(':');
    }} else if (sid.startsWith('katana:')) {{
        var parts = sid.split(':');
        url = S.target.replace(/[/]+$/, '') + parts.slice(2).join(':');
    }} else if (sid.startsWith('vhost:') || sid.startsWith('subfinder:')) {{
        var sub = sid.split(':')[1];
        url = (S.target.startsWith('https') ? 'https' : 'http') + '://' + sub;
    }}

    var status = 0;
    if (sid.startsWith('ffuf:')) status = parseInt(sid.split(':').pop()) || 0;

    var sc = status===200 ? '#2ECC71' : (status===403 ? '#E74C3C' : '#FF8C00');

    // Decodificar title para extraer tech y forms
    var ta2 = document.createElement('textarea');
    ta2.innerHTML = n.title || '';
    var titleDecoded = ta2.value;
    var techM = titleDecoded.match(/Tech:<.b>[^>]*>([^<]+)</);
    var tech  = techM ? techM[1].toLowerCase().trim() : '';
    var hasForms = titleDecoded.indexOf('Inputs:') !== -1 || titleDecoded.indexOf('📝') !== -1;

    ni.innerHTML =
        '<div style="color:#FFD700;font-size:12px;font-weight:bold;margin-bottom:8px;word-break:break-all">' + n.label + '</div>' +
        '<div style="margin:3px 0"><span style="color:#555">URL: </span><span style="font-size:10px;color:#ccc;word-break:break-all">' + url + '</span></div>' +
        (status ? '<div style="margin:3px 0"><span style="color:#555">Status: </span><span style="color:' + sc + '">' + status + '</span></div>' : '') +
        (tech   ? '<div style="margin:3px 0"><span style="color:#555">Tech: </span><span style="color:#8892BF;font-weight:bold">' + tech.toUpperCase() + '</span></div>' : '') +
        (hasForms ? '<div style="margin:3px 0;color:#E91E63">📝 Forms detected</div>' : '') +
        '<div style="margin-top:6px"><span style="color:#333;font-size:9px">' + (n.group||'') + '</span></div>';

    al.innerHTML = '';
    al.appendChild(mkGrp('RECONNAISSANCE'));
    al.appendChild(mkBtn('🌐', 'Open in browser',   A.browser(url), 'info'));
    al.appendChild(mkBtn('📡', 'curl -I (headers)',   A.curl(url),    'info'));
    al.appendChild(mkBtn('🔍', 'WhatWeb',              A.whatweb(url), 'info'));

    var g = n.group || '';
    if (g==='seed'||g==='vhost'||g==='subfinder') {{
        al.appendChild(mkGrp('HOST'));
        al.appendChild(mkBtn('🗺️','nmap -sV -sC',     A.nmap(url)));
        al.appendChild(mkBtn('🔒','SSLyze',            A.sslyze(url)));
        al.appendChild(mkGrp('VULNERABILITIES'));
        al.appendChild(mkBtn('☢️','Nuclei',            A.nuclei(url), 'danger'));
        al.appendChild(mkBtn('🕵️','Nikto',            A.nikto(url),  'danger'));
    }}
    if (g.startsWith('katana_')||g.startsWith('ffuf_')) {{
        al.appendChild(mkGrp('FUZZING'));
        al.appendChild(mkBtn('💥','ffuf dirs',         A.ffuf(url)));
        al.appendChild(mkBtn('🔫','Gobuster',          A.gobuster(url)));
    }}
    if (status===403) {{
        al.appendChild(mkGrp('BYPASS 403'));
        al.appendChild(mkBtn('🔓','Bypass headers',    A.bypass(url), 'danger'));
    }}
    if (hasForms && !S.no_forms) {{
        al.appendChild(mkGrp('FORMS'));
        al.appendChild(mkBtn('💉','SQLMap (forms)',    A.sqlmap(url), 'danger'));
    }} else if (g.startsWith('ffuf_') && status===200) {{
        al.appendChild(mkGrp('ANALYSIS'));
        al.appendChild(mkBtn('💉','SQLMap',            A.sqlmap(url), 'danger'));
    }}
    al.appendChild(mkGrp('GENERAL'));
    al.appendChild(mkBtn('☢️','Nuclei',               A.nuclei(url), 'danger'));
    al.appendChild(mkBtn('📋','Copy URL',            url,           'info'));
}}

// ── Inicialización ───────────────────────────────────────────────────
window.addEventListener('resize', setViewport);
setViewport();
buildSVG();
renderAll();
</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    log("OK", f"Graph exported: \033[96m{output_file.resolve()}\033[0m")
    log("INFO", f"Open graph with: xdg-open {output_file.resolve()}")
    return output_file

def run_subfinder(config: dict) -> list:
    """
    Ejecuta subfinder para enumerar subdomains del dominio raíz del target.

    subfinder consulta múltiples fuentes pasivas (crt.sh, VirusTotal, Shodan,
    etc.) para encontrar subdomains sin enviar tráfico al target directamente.
    Los subdomains descubiertos se añaden automáticamente como VHOSTs tanto
    para Katana como para ffuf, y aparecen como nodos en el grafo.

    Args:
        config : Config global con subfinder_domain y output_dir.

    Returns:
        Lista de subdomains descubiertos (strings).
    """
    domain     = config.get("subfinder_domain", config["host"])
    output_dir = config["output_dir"]
    out_file   = output_dir / "subfinder_results.txt"

    cmd = [
        "subfinder",
        "-d", domain,
        "-o", str(out_file),
        "-silent",          # Sin banner, solo resultados
        "-all",             # Usar todas las fuentes disponibles
        "-t", "10",         # Threads
    ]

    log("INFO", f"subfinder → enumerating subdomains for: {domain}")
    log("INFO", f"Comando: {' '.join(cmd)}")

    subdomains = []
    start_time = time.time()

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(spinner_name="dots", style="bright_magenta"),
            TextColumn("[bold magenta]SUBFINDER[/] buscando subdomains de "
                       f"[cyan]{domain}[/]..."),
            TimeElapsedColumn(),
            expand=True,
            transient=False,
        ) as progress:
            progress.add_task("subfinder", total=None)
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120
                )
                if result.returncode not in (0, 1):
                    log("WARN", f"subfinder finalizó con código {result.returncode}")
            except subprocess.TimeoutExpired:
                log("ERROR", "subfinder superó el timeout de 120s")
                return []
            except FileNotFoundError:
                log("ERROR", "'subfinder' no está instalado o no está en PATH.")
                log("INFO",  "Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
                return []
    else:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log("ERROR", f"subfinder: {e}")
            return []

    # Leer resultados del archivo de output
    if out_file.exists():
        with open(out_file, "r") as f:
            subdomains = [l.strip() for l in f if l.strip()]

    elapsed = time.time() - start_time
    total_raw = len(subdomains)
    log("OK", f"subfinder → {total_raw} subdomains found en {elapsed:.1f}s")

    # ── Aplicar filtro 1: palabras clave ─────────────────────────────────────
    keywords = config.get("subfinder_keywords", [])
    if keywords and subdomains:
        before = len(subdomains)
        subdomains = [
            sd for sd in subdomains
            if any(kw in sd.lower() for kw in keywords)
        ]
        log("INFO", f"Filtro keywords {keywords}: {before} → {len(subdomains)} subdomains")
    elif not keywords:
        log("INFO", "Sin filtro de keywords aplicado.")

    # ── Aplicar filtro 2: ordenar por longitud y aplicar límite ──────────────
    # Ordenar de más corto a más largo: los subdomains cortos son más relevantes
    # (admin.target.com es más interesante que qastg-eks-alv-integration.target.com)
    subdomains.sort(key=len)

    limit = config.get("subfinder_limit", 20)
    if limit and limit > 0 and len(subdomains) > limit:
        log("INFO", f"Applying limit: {len(subdomains)} → {limit} subdomains (shortest first)")
        subdomains = subdomains[:limit]

    # ── Mostrar lista final ───────────────────────────────────────────────────
    if subdomains:
        log("OK", f"Subdomains to process ({len(subdomains)} de {total_raw} encontrados):")
        for sd in subdomains:
            log("INFO", f"  → {sd}")
    else:
        log("WARN", "No subdomains left after applying filters.")
        log("INFO", f"  All results are in: {out_file}")

    return subdomains


# =============================================================================
# SECCIÓN 7: PIPELINE PRINCIPAL
# =============================================================================

def run_pipeline(config: dict):
    """
    Orquesta la ejecución secuencial de todas las fases del pipeline de reconocimiento:
    0. Subfinder (enumeración de subdomains, opcional)
    1. Katana Crawling (por target base y/o cada VHOST)
    2. ffuf Fuzzing   (por target base y/o cada VHOST)
    3. Construcción y exportación del grafo PyVis
    """

    # ── Verificar herramientas disponibles ────────────────────────────────────
    print("\n\033[93m━━━━━━━━━━━━━━━━━━━━━━  DEPENDENCY CHECK  ━━━━━━━━━━━━━━━━━━\033[0m")
    katana_ok    = check_tool("katana")
    ffuf_ok      = check_tool("ffuf")
    if config.get("use_subfinder"):
        subfinder_ok = check_tool("subfinder")
    else:
        subfinder_ok = False
    print()

    # ── FASE 0: Subfinder ────────────────────────────────────────────────────
    if config.get("use_subfinder") and subfinder_ok:
        print("\n\033[38;5;208m━━━━━━━━━━━━━━━━━━━━━━  PHASE 0: SUBFINDER  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
        discovered_subs = run_subfinder(config)
        config["subfinder_results"] = discovered_subs

        if discovered_subs:
            # Agregar subdomains descubiertos a los VHOSTs de Katana y ffuf
            # Solo si el usuario no los configuró manualmente (no solapar)
            existing_katana = set(config.get("katana_vhosts", []))
            existing_ffuf   = set(config.get("ffuf_vhosts", []))

            new_for_katana = [s for s in discovered_subs if s not in existing_katana]
            new_for_ffuf   = [s for s in discovered_subs if s not in existing_ffuf]

            if new_for_katana:
                config["katana_vhosts"].extend(new_for_katana)
                config["use_katana_vhosts"] = True
                log("OK", f"  {len(new_for_katana)} subdomains added to Katana")

            if new_for_ffuf:
                config["ffuf_vhosts"].extend(new_for_ffuf)
                config["use_ffuf_vhosts"] = True
                log("OK", f"  {len(new_for_ffuf)} subdomains added to ffuf")

            # Actualizar all_vhosts con los nuevos subdomains
            config["all_vhosts"] = list(dict.fromkeys(
                config["katana_vhosts"] + config["ffuf_vhosts"]
            ))
    else:
        config["subfinder_results"] = []

    output_dir = config["output_dir"]

    # ── Construcción de scopes ──────────────────────────────────────────────
    # Distingue dos modos de VHOST según el origen:
    #
    # Modo HTB (IP/dominio .htb): todos los VHOSTs comparten la misma IP.
    #   → Katana/ffuf apuntan al target base + header -H "Host: vhost.htb"
    #   → La IP resuelve a la misma máquina para todos los hosts
    #
    # Modo Bug Bounty (subdomains reales con DNS propio):
    #   → Katana/ffuf apuntan directamente a https://subdominio.target.com
    #   → Sin header Host extra (el DNS ya resuelve al servidor correcto)
    #
    # La heurística para distinguirlos: si el VHOST termina en el mismo
    # dominio raíz que el target, es un subdominio real (BB mode).
    # Si no (ej: admin.htb, dev.htb apuntando a 10.10.11.20), es HTB mode.

    parsed_target = urlparse(config["target"])
    base_scheme   = parsed_target.scheme   # http o https
    base_host     = parsed_target.hostname or ""

    # Extraer el dominio raíz del target (ej: mheducation.com de www.mheducation.com)
    host_parts  = base_host.split(".")
    root_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else base_host

    def build_scope(vhost: str) -> tuple:
        """
        Determina si un VHOST es un subdominio real (BB) o un virtual host HTB.

        BB mode  → retorna (https://vhost.target.com, None)
                   Katana/ffuf apuntan directo al subdominio, sin header Host.

        HTB mode → retorna (target_base, vhost)
                   Katana/ffuf apuntan al target base con header -H Host: vhost.
        """
        vhost_lower = vhost.lower()

        # Si el VHOST termina en el dominio raíz → subdominio real (BB mode)
        if vhost_lower.endswith("." + root_domain) or vhost_lower == root_domain:
            sub_url = f"{base_scheme}://{vhost}"
            return (sub_url, None)   # URL directa, sin header Host

        # Si no → VHOST ficticio estilo HTB (mismo servidor, distinto Host header)
        return (config["target"], vhost)

    # Construir los scopes aplicando la heurística
    katana_scopes = [(config["target"], None)]   # Target base siempre incluido
    if config["use_katana_vhosts"]:
        for vhost in config["katana_vhosts"]:
            scope = build_scope(vhost)
            if scope not in katana_scopes:
                katana_scopes.append(scope)

    ffuf_scopes = [(config["target"], None)]     # Target base siempre incluido
    if config["use_ffuf_vhosts"]:
        for vhost in config["ffuf_vhosts"]:
            scope = build_scope(vhost)
            if scope not in ffuf_scopes:
                ffuf_scopes.append(scope)

    # Log descriptivo del modo detectado para cada scope
    log("INFO", f"Root domain detected: {root_domain}")
    log("INFO", f"Katana scopes ({len(katana_scopes)}):")
    for url, vhost in katana_scopes:
        mode = "directo" if vhost is None else f"HTB header: {vhost}"
        log("INFO", f"  {url}  [{mode}]")
    log("INFO", f"ffuf scopes ({len(ffuf_scopes)}):")
    for url, vhost in ffuf_scopes:
        mode = "directo" if vhost is None else f"HTB header: {vhost}"
        log("INFO", f"  {url}  [{mode}]")

    # Almacenamiento de resultados por scope
    katana_results = {}  # { scope_label: [urls...] }
    ffuf_results   = {}  # { scope_label: [paths...] }

    # ─────────────────────────────────────────────────────────────────────────
    # FASE 1: Katana Crawling
    # ─────────────────────────────────────────────────────────────────────────
    print("\n\033[95m━━━━━━━━━━━━━━━━━━━━━━  PHASE 1: KATANA CRAWLING  ━━━━━━━━━━━━━━━━━━━━━━\033[0m")

    if not katana_ok:
        log("WARN", "Katana no disponible. Saltando Fase 1. El grafo solo tendrá resultados de ffuf.")
    else:
        for target_url, vhost in katana_scopes:
            scope_label = vhost if vhost else config["host"]
            log("PHASE", f"Crawling scope: {scope_label}")
            urls = run_katana(target_url, vhost, output_dir, config)
            katana_results[scope_label] = urls
            log("INFO", f"  → {len(urls)} URLs added for '{scope_label}'")

    total_katana = sum(len(v) for v in katana_results.values())
    log("OK", f"Phase 1 complete. Total Katana URLs: \033[96m{total_katana}\033[0m")

    # ─────────────────────────────────────────────────────────────────────────
    # FASE 2: ffuf Fuzzing — con estimación previa y grafo parcial en Ctrl+C
    # ─────────────────────────────────────────────────────────────────────────
    print("\n\033[95m━━━━━━━━━━━━━━━━━━━━━━  PHASE 2: FFUF FUZZING  ━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")

    ffuf_cancelled = False   # Flag: True si el usuario canceló con Ctrl+C

    if not ffuf_ok:
        log("WARN", "ffuf no disponible. Saltando Fase 2.")
    else:
        # ── Estimación de tiempo ANTES de empezar ────────────────────────────
        # Calcular cuántas palabras se van a probar en total
        wordlist_lines = _count_wordlist_lines(config["wordlist"])
        extensions     = config.get("ffuf_extensions", [])
        passes_per_scope = 1 + len(extensions)
        total_words    = wordlist_lines * passes_per_scope
        n_scopes       = len(ffuf_scopes)
        rate           = config.get("rate_limit", 0) or 50  # req/s efectivo

        total_requests = total_words * n_scopes
        eta_seconds    = total_requests / rate
        eta_minutes    = eta_seconds / 60
        eta_hours      = eta_minutes / 60

        # Formatear ETA de forma legible
        if eta_seconds < 60:
            eta_str = f"{eta_seconds:.0f} seconds"
        elif eta_minutes < 60:
            eta_str = f"{eta_minutes:.1f} minutes"
        else:
            eta_str = f"{eta_hours:.1f} hours"

        print()
        print(f"  \033[93m┌─ TIME ESTIMATION ────────────────────────────────────────────┐\033[0m")
        print(f"  \033[93m│\033[0m  Wordlist      : {wordlist_lines:,} palabras × {passes_per_scope} pasada(s)")
        print(f"  \033[93m│\033[0m  Scopes        : {n_scopes}")
        print(f"  \033[93m│\033[0m  Total requests: {total_requests:,}")
        print(f"  \033[93m│\033[0m  Rate limit    : {rate} req/s")
        print(f"  \033[93m│\033[0m  Estimated ETA : \033[96m{eta_str}\033[0m")
        print(f"  \033[93m└───────────────────────────────────────────────────────────────────┘\033[0m")
        print()

        # Advertir si va a tardar más de 30 minutes
        if eta_seconds > 1800:
            log("WARN", f"High estimate ({eta_str}). Consider a smaller wordlist.")
            log("INFO", "  common.txt (4,614)  →  seclists/common.txt")
            log("INFO", "  You can also cancel with Ctrl+C — the graph will be generated anyway.")
            print()

        confirm_ffuf = input(
            f"  \033[96m[?]\033[0m Start ffuf? (ETA: {eta_str}) (Y/n): "
        ).strip().lower()

        if confirm_ffuf in ("n", "no"):
            log("INFO", "ffuf skipped by user. Graph will be generated with Katana data only.")
            ffuf_cancelled = True
        else:
            log("INFO", "Ctrl+C anytime to cancel ffuf and generate partial graph.")
            print()
            try:
                for target_url, vhost in ffuf_scopes:
                    scope_label = vhost if vhost else config["host"]
                    log("PHASE", f"Fuzzing scope: {scope_label}")
                    paths = run_ffuf_all_passes(target_url, vhost, output_dir, config)
                    ffuf_results[scope_label] = paths
                    log("INFO", f"  → {len(paths)} routes added for '{scope_label}'")

            except KeyboardInterrupt:
                # Ctrl+C durante ffuf → grafo parcial con lo que se tiene
                ffuf_cancelled = True
                print()
                log("WARN", "ffuf interrupted by user (Ctrl+C).")
                log("INFO", f"  Scopes completed: {len(ffuf_results)}/{len(ffuf_scopes)}")
                log("INFO", "  Generating partial graph with available data...")

    total_ffuf = sum(len(v) for v in ffuf_results.values())
    status_ffuf = "PARTIAL (cancelled)" if ffuf_cancelled else "completo"
    log("OK", f"Fase 2 {status_ffuf}. Rutas de ffuf: \033[96m{total_ffuf}\033[0m")

    # ─────────────────────────────────────────────────────────────────────────
    # FASE 3: Construcción y exportación del grafo PyVis
    # Corre siempre — incluso si ffuf fue cancelado o no corrió.
    # El grafo se arma con lo que haya disponible en katana_results y ffuf_results.
    # ─────────────────────────────────────────────────────────────────────────
    print("\n\033[95m━━━━━━━━━━━━━━━━━━━━━  PHASE 3: GRAPH CONSOLIDATION  ━━━━━━━━━━━━━━\033[0m")
    if ffuf_cancelled:
        log("INFO", "Partial graph: includes complete Katana + ffuf up to where it got.")

    net = build_graph(config, katana_results, ffuf_results)
    output_html = export_graph(net, config)

    # ─────────────────────────────────────────────────────────────────────────
    # RESUMEN FINAL
    # ─────────────────────────────────────────────────────────────────────────
    parcial_label = " \033[93m(PARTIAL GRAPH — ffuf cancelled)\033[0m" if ffuf_cancelled else ""
    print(f"\n\033[92m━━━━━━━━━━━━━━━━━━━━━━━━━━  PIPELINE COMPLETE{parcial_label}  ━━━━━━━━━━━━━━━━━━━\033[0m")
    log("OK", f"Session directory : \033[96m{output_dir.resolve()}\033[0m")
    log("OK", f"HTML graph generated: \033[96m{output_html.resolve()}\033[0m")
    log("OK", f"Total nodes        : \033[96m{len(net.nodes)}\033[0m")
    log("OK", f"Total edges        : \033[96m{len(net.edges)}\033[0m")
    log("OK", f"Katana URLs        : \033[96m{total_katana}\033[0m")
    log("OK", f"ffuf routes        : \033[96m{total_ffuf}\033[0m")
    # Levantar servidor HTTP local para que Firefox pueda cargar vis.js desde CDN
    print(f"\n  \033[93m[>>]\033[0m Open the graph: \033[96mxdg-open {output_html.resolve()}\033[0m\n")
    print("\033[92m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")

    # ── Save session cache for drill-down ────────────────────────────────────
    _save_session_cache(config, katana_results, ffuf_results)

    return katana_results, ffuf_results, output_html


# =============================================================================
# SECTION 8: SESSION CACHE & DRILL-DOWN MODE
# =============================================================================

def _save_session_cache(config: dict, katana_results: dict, ffuf_results: dict):
    """Save pipeline results as JSON for drill-down reuse."""
    import json as _json
    cache_dir = config["output_dir"]

    cache = {
        "katana_results": katana_results,
        "ffuf_results":   ffuf_results,
        "target":         config["target"],
        "host":           config["host"],
        "session_label":  config["session_label"],
        "graph_depth":    config.get("graph_depth", 2),
        "drill_history":  config.get("drill_history", []),
    }

    cache_file = cache_dir / "session_cache.json"
    with open(cache_file, "w", encoding="utf-8") as f:
        _json.dump(cache, f, ensure_ascii=False, indent=2, default=str)

    log("INFO", f"Session cache saved: {cache_file}")


def _load_session_cache(session_dir: Path) -> dict:
    """Load cached results from a previous session."""
    import json as _json
    cache_file = session_dir / "session_cache.json"
    if not cache_file.exists():
        return {}
    with open(cache_file, "r", encoding="utf-8") as f:
        return _json.load(f)


def drill_down_menu(config: dict, katana_results: dict, ffuf_results: dict,
                     drill_depth: int = 0, base_url: str = "") -> "dict | None":
    """
    Display numbered list of interesting nodes and let user pick one to drill into.

    Shows:
      1. Subdomains (from subfinder)
      2. Top-level directories with most grouped URLs
      3. ffuf findings (200/301/403)

    Returns a dict with the selected node info, or None to exit.
    """
    print()
    indent = "  " * (drill_depth + 1)
    depth_label = f" (depth {drill_depth})" if drill_depth > 0 else ""
    print(f"\033[38;5;208m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print(f"\033[38;5;208m  ║  🔍 DRILL-DOWN MODE{depth_label:>46}║\033[0m")
    print(f"\033[38;5;208m  ║  Select a node to explore deeper.                                ║\033[0m")
    print(f"\033[38;5;208m  ║  The tool will re-crawl and re-fuzz only the selected target.    ║\033[0m")
    print(f"\033[38;5;208m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    options = []   # [(index, label, url, type, details)]

    # ── Subdomains ────────────────────────────────────────────────────────────
    subfinder_subs = config.get("subfinder_results", [])
    if subfinder_subs:
        print(f"  \033[38;5;208m── SUBDOMAINS ──────────────────────────────────────────────────────\033[0m")
        for sub in subfinder_subs:
            katana_count = len(katana_results.get(sub, []))
            ffuf_count   = len(ffuf_results.get(sub, []))
            scheme = "https" if config["target"].startswith("https") else "http"
            url    = f"{scheme}://{sub}"  # Subdomains always use their own hostname
            idx    = len(options) + 1
            options.append({
                "index": idx, "label": sub, "url": url,
                "type": "subdomain",
                "katana_count": katana_count, "ffuf_count": ffuf_count,
            })
            # Color: green if has data, yellow if empty
            color = "\033[92m" if katana_count > 0 else "\033[93m"
            print(f"  {color}  [{idx:2d}]\033[0m {sub:40s} "
                  f"\033[90m{katana_count} URLs, {ffuf_count} ffuf hits\033[0m")
        print()

    # ── Top directories from Katana ──────────────────────────────────────────
    # Extract first-level paths and count how many URLs each one groups
    path_counts = {}   # { scope:path → count }
    for scope_label, urls in katana_results.items():
        for entry in urls:
            url = entry.get("url", "") if isinstance(entry, dict) else str(entry)
            try:
                parsed_path = urlparse(url).path
                parts = [p for p in parsed_path.split("/") if p]
                if parts:
                    top_dir = "/" + parts[0] + "/"
                    key = (scope_label, top_dir)
                    path_counts[key] = path_counts.get(key, 0) + 1
            except Exception:
                continue

    # Sort by count descending, take top 10
    sorted_paths = sorted(path_counts.items(), key=lambda x: -x[1])[:10]

    if sorted_paths:
        print(f"  \033[38;5;51m── TOP DIRECTORIES (by URL count) ─────────────────────────────────\033[0m")
        for (scope_label, path), count in sorted_paths:
            scheme = "https" if config["target"].startswith("https") else "http"
            # Build absolute URL from target host + path
            # Paths in parent_katana are always absolute from the host root
            # (e.g. /vendor/select2/, /vendor/countdowntime/)
            scheme = "https" if config["target"].startswith("https") else "http"
            _host  = config["host"]
            _port  = config.get("port", 80)
            port_str = f":{_port}" if _port not in (80, 443) else ""
            url = f"{scheme}://{_host}{port_str}{path}"
            idx = len(options) + 1
            options.append({
                "index": idx, "label": f"{scope_label}{path}",
                "url": url, "type": "directory",
                "katana_count": count, "ffuf_count": 0,
                "scope": scope_label, "path": path,
            })
            print(f"  \033[96m  [{idx:2d}]\033[0m {scope_label}{path:30s} "
                  f"\033[90m{count} URLs grouped\033[0m")
        print()

    # ── ffuf findings ────────────────────────────────────────────────────────
    all_ffuf = []
    for scope_label, findings in ffuf_results.items():
        for f in findings:
            all_ffuf.append((scope_label, f))

    if all_ffuf:
        print(f"  \033[38;5;214m── FFUF FINDINGS ──────────────────────────────────────────────────\033[0m")
        for scope_label, finding in all_ffuf[:10]:
            url    = finding.get("url", "")
            status = finding.get("status", 0)
            idx    = len(options) + 1
            sc = "\033[92m" if status == 200 else ("\033[91m" if status == 403 else "\033[93m")
            options.append({
                "index": idx, "label": f"[{status}] {url}",
                "url": url, "type": "ffuf",
                "status": status, "scope": scope_label,
            })
            print(f"  {sc}  [{idx:2d}]\033[0m [{status}] {url[:60]}")
        print()

    if not options:
        log("INFO", "No nodes available for drill-down.")
        return None

    # ── User selection ────────────────────────────────────────────────────────
    print(f"  \033[38;5;240m  Cached results will be reused. Only the selected target will be\033[0m")
    print(f"  \033[38;5;240m  re-crawled with deeper depth and re-fuzzed.\033[0m\n")

    selection = input(
        f"  \033[96m[?]\033[0m Drill into node (1-{len(options)}, Enter to exit): "
    ).strip()

    if not selection:
        return None

    try:
        idx = int(selection)
        if 1 <= idx <= len(options):
            selected = options[idx - 1]
            log("OK", f"Selected: {selected['label']}")
            return selected
        else:
            log("WARN", f"Invalid selection: {idx}")
            return None
    except ValueError:
        return None


def run_drill_down(config: dict, parent_katana: dict, parent_ffuf: dict,
                   selected: dict, drill_depth: int) -> tuple:
    """
    Drill into a selected node using cached Katana data + optional new ffuf.

    Flow:
      1. FILTER cached Katana results to only URLs in the selected branch
         (no re-crawling — Katana already crawled everything in the initial scan)
      2. Run ffuf ONLY on the selected target if user wants
      3. Generate focused graph: selected node as root, filtered Katana + new ffuf
      4. Return updated parent results for the next drill-down menu

    Returns: (updated_parent_katana, updated_parent_ffuf, output_html)
    """
    import copy

    drill_label = selected["label"].replace("/", "_").replace(":", "_").strip("_")
    drill_dir   = config["output_dir"] / f"drill_{drill_depth}_{sanitize_filename(drill_label)}"
    drill_dir.mkdir(parents=True, exist_ok=True)

    target_url  = selected["url"]
    scope_label = selected.get("scope", urlparse(target_url).hostname or config["host"])

    # Determine the path prefix to filter cached results
    # e.g. if target_url is "http://10.10.10.1/vendor/", prefix is "/vendor"
    parsed_target = urlparse(target_url)
    drill_path    = parsed_target.path.rstrip("/") or ""

    print(f"\n\033[38;5;208m━━━━━━━━━━━━━━━━━━━━━━  DRILL-DOWN #{drill_depth}: {selected['label'][:40]}  ━━━━━━━━━━━━━━━\033[0m")
    log("PHASE", f"Target: {target_url}")
    log("INFO",  f"Branch filter: {drill_path or '/'}")
    log("INFO",  f"Output: {drill_dir}")

    # ── Ask drill settings ───────────────────────────────────────────────────
    print()
    depth_in = input(
        f"  \033[96m[?]\033[0m Graph depth for this drill [3]: "
    ).strip()
    try:
        drill_graph_depth = max(1, int(depth_in)) if depth_in else 3
    except ValueError:
        drill_graph_depth = 3

    node_limit_in = input(
        f"  \033[96m[?]\033[0m Max nodes [{config.get('graph_node_limit', 150)}]: "
    ).strip()
    try:
        drill_node_limit = int(node_limit_in) if node_limit_in else config.get("graph_node_limit", 150)
    except ValueError:
        drill_node_limit = config.get("graph_node_limit", 150)

    # ffuf settings
    print()
    run_ffuf_yn = input(
        f"  \033[96m[?]\033[0m Run ffuf on {selected['label'][:40]}? (Y/n): "
    ).strip().lower()
    skip_ffuf = run_ffuf_yn in ("n", "no")

    drill_wordlist  = config.get("wordlist", "")
    drill_extensions = config.get("ffuf_extensions", [])

    if not skip_ffuf:
        current_wl = config.get("wordlist", "")
        wl_in = input(
            f"  \033[96m[?]\033[0m Wordlist [Enter = {Path(current_wl).name if current_wl else 'none'}]: "
        ).strip()
        if wl_in and Path(wl_in).is_file():
            drill_wordlist = wl_in
        elif wl_in:
            log("WARN", f"File not found: {wl_in}. Using previous wordlist.")

        ext_in = input(
            f"  \033[96m[?]\033[0m File extensions to test (Enter = skip, e.g. .php,.bak,.txt): "
        ).strip()
        if ext_in:
            drill_extensions = [e.strip() if e.strip().startswith(".") else "." + e.strip()
                                for e in ext_in.split(",") if e.strip()]
            log("OK", f"Extensions: {drill_extensions}")
        else:
            drill_extensions = []

    # ── Create drill config ──────────────────────────────────────────────────
    drill_config = copy.deepcopy(config)
    drill_config["target"]           = target_url
    drill_config["host"]             = parsed_target.hostname or config["host"]
    drill_config["output_dir"]       = drill_dir
    drill_config["session_label"]    = f"{config['session_label']}_drill{drill_depth}_{drill_label}"
    drill_config["graph_depth"]      = drill_graph_depth
    drill_config["graph_node_limit"] = drill_node_limit
    drill_config["wordlist"]         = drill_wordlist
    drill_config["ffuf_extensions"]  = drill_extensions
    drill_config["use_katana_vhosts"] = False
    drill_config["use_ffuf_vhosts"]   = False
    drill_config["katana_vhosts"]     = []
    drill_config["ffuf_vhosts"]       = []
    drill_config["subfinder_results"] = []

    # Track drill history
    history = list(config.get("drill_history", []))
    history.append({"depth": drill_depth, "target": target_url,
                    "label": selected["label"], "type": selected["type"]})
    drill_config["drill_history"] = history

    log("OK", f"Settings: depth={drill_graph_depth} | limit={drill_node_limit} | "
              f"ffuf={'skip' if skip_ffuf else drill_wordlist.split('/')[-1] if drill_wordlist else 'none'} | "
              f"ext={drill_extensions or 'none'}")

    # ══════════════════════════════════════════════════════════════════════════
    # DRILL PHASE 1: FILTER cached Katana results (NO re-crawling)
    # Katana already crawled everything in the initial scan. We just filter
    # the cached URLs to only those that belong to the selected branch.
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n\033[95m━━━━━━━━━━━━  DRILL PHASE 1: FILTER CACHED DATA  ━━━━━━━━━━━━━━━━━━━━\033[0m")

    filtered_katana = {}
    total_parent = 0
    total_filtered = 0

    for scope, urls in parent_katana.items():
        total_parent += len(urls)
        filtered = []
        for entry in urls:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url", "")
            try:
                entry_path = urlparse(url).path
            except Exception:
                continue

            # Keep URLs whose path starts with the drill prefix
            # If drilling into a subdomain (no path prefix), keep all URLs from that scope
            if not drill_path:
                # Drilling into a subdomain → keep all URLs that match the hostname
                entry_host = urlparse(url).hostname or ""
                drill_host = parsed_target.hostname or ""
                if entry_host == drill_host:
                    filtered.append(entry)
            elif entry_path.startswith(drill_path + "/") or entry_path == drill_path:
                filtered.append(entry)

        if filtered:
            filtered_katana[scope] = filtered
            total_filtered += len(filtered)

    log("OK", f"Cached Katana: {total_parent} total → {total_filtered} in branch '{drill_path or '/'}'")

    # ── Strip drill prefix from URLs so the path tree is relative ────────────
    # Without this, drilling into /vendor produces: seed → /vendor → /vendor/select2
    # With this: seed → select2 (relative to the drill root)
    # The original URLs are preserved for the action panel commands.
    if drill_path:
        # IMPORTANT: Create NEW dicts instead of modifying originals in place.
        # Python passes dicts by reference — modifying entries here would corrupt
        # parent_katana for future drill-downs.
        for scope in list(filtered_katana.keys()):
            stripped = []
            for entry in filtered_katana[scope]:
                new_entry = dict(entry)   # shallow copy — new dict, same values
                original_url = new_entry.get("url", "")
                try:
                    p = urlparse(original_url)
                    rel_path = p.path
                    if rel_path.startswith(drill_path + "/"):
                        rel_path = rel_path[len(drill_path):]
                    elif rel_path == drill_path:
                        rel_path = "/"
                    port_str = f":{p.port}" if p.port and p.port not in (80, 443) else ""
                    new_entry["_original_url"] = original_url
                    new_entry["url"] = f"{p.scheme}://{p.hostname}{port_str}{rel_path}"
                except Exception:
                    pass
                stripped.append(new_entry)
            filtered_katana[scope] = stripped
        log("INFO", f"Paths stripped: '{drill_path}/' prefix removed for relative tree")

    if total_filtered == 0:
        log("WARN", "No cached URLs found for this branch. The drill graph will only have ffuf results.")

    # ══════════════════════════════════════════════════════════════════════════
    # DRILL PHASE 2: ffuf on the selected target ONLY
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n\033[95m━━━━━━━━━━━━  DRILL PHASE 2: FFUF  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")

    drill_ffuf = {}
    if not skip_ffuf and check_tool("ffuf") and drill_wordlist:
        wordlist_lines = _count_wordlist_lines(drill_wordlist)
        passes = 1 + len(drill_extensions)
        total_words = wordlist_lines * passes
        rate = drill_config.get("rate_limit", 0) or 50
        eta_sec = total_words / rate
        eta_str = f"{eta_sec:.0f}s" if eta_sec < 60 else f"{eta_sec/60:.1f}min"

        log("INFO", f"Fuzzing {target_url} — {passes} pass(es) — ETA: {eta_str}")

        try:
            paths = run_ffuf_all_passes(target_url, None, drill_dir, drill_config)
            drill_ffuf[scope_label] = paths
            log("OK", f"ffuf: {len(paths)} findings")
        except KeyboardInterrupt:
            log("WARN", "ffuf interrupted.")
    elif skip_ffuf:
        log("INFO", "ffuf skipped by user.")
    else:
        log("INFO", "ffuf not available or no wordlist.")

    # ── Separate original vs stripped ffuf for graph vs merge ─────────────────
    # drill_ffuf_original: non-stripped URLs, used for merging back to parent
    # drill_ffuf_stripped: prefix-stripped URLs, used only for the graph
    import copy as _copy2
    drill_ffuf_original = {}
    for scope in drill_ffuf:
        drill_ffuf_original[scope] = [dict(e) for e in drill_ffuf[scope]]

    drill_ffuf_stripped = {}
    if drill_path and drill_ffuf:
        for scope in drill_ffuf:
            stripped = []
            for entry in drill_ffuf[scope]:
                new_entry = dict(entry)
                original_url = new_entry.get("url", "")
                try:
                    p = urlparse(original_url)
                    rel_path = p.path
                    if rel_path.startswith(drill_path + "/"):
                        rel_path = rel_path[len(drill_path):]
                    elif rel_path == drill_path:
                        rel_path = "/"
                    port_str = f":{p.port}" if p.port and p.port not in (80, 443) else ""
                    new_entry["_original_url"] = original_url
                    new_entry["url"] = f"{p.scheme}://{p.hostname}{port_str}{rel_path}"
                except Exception:
                    pass
                stripped.append(new_entry)
            drill_ffuf_stripped[scope] = stripped
    else:
        drill_ffuf_stripped = drill_ffuf_original

    # ══════════════════════════════════════════════════════════════════════════
    # DRILL PHASE 3: Build FOCUSED graph
    # Uses ONLY: filtered Katana data + new ffuf data
    # The selected node becomes the root of the new graph
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n\033[95m━━━━━━━━━━━━  DRILL PHASE 3: FOCUSED GRAPH  ━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")

    net = build_graph(drill_config, filtered_katana, drill_ffuf_stripped)
    output_html = export_graph(net, drill_config)

    total_k = sum(len(v) for v in filtered_katana.values())
    total_f = sum(len(v) for v in drill_ffuf_stripped.values())
    print(f"\n\033[92m━━━━━━━━━━━━  DRILL #{drill_depth} COMPLETE  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    log("OK", f"Graph: {output_html.resolve()}")
    log("OK", f"Nodes: {len(net.nodes)} | Edges: {len(net.edges)}")
    log("OK", f"URLs: {total_k} (cached Katana) + {total_f} (new ffuf)")
    print(f"\n  \033[93m[>>]\033[0m Open: \033[96mxdg-open {output_html.resolve()}\033[0m\n")

    # ── Update parent results with new ffuf findings ─────────────────────────
    # Katana data doesn't change (no re-crawl). Only ffuf results are new.
    updated_katana = parent_katana   # unchanged
    updated_ffuf   = dict(parent_ffuf)

    for scope, findings in drill_ffuf_original.items():
        if scope in updated_ffuf:
            existing = {f.get("url", "") for f in updated_ffuf[scope]}
            for f in findings:
                if f.get("url", "") not in existing:
                    updated_ffuf[scope].append(f)
        else:
            updated_ffuf[scope] = findings

    _save_session_cache(drill_config, filtered_katana, drill_ffuf_stripped)

    return updated_katana, updated_ffuf, output_html


# =============================================================================
# SECTION 9: ENTRY POINT
# =============================================================================

def main():
    """Main entry point. Handles: disclaimer → banner → inputs → pipeline → drill-down loop."""

    # ── Ethical use disclaimer ────────────────────────────────────────────────
    print()
    print("\033[93m  ⚠  DISCLAIMER\033[0m")
    print("\033[38;5;240m  This tool is intended for authorized security testing and educational")
    print("  purposes only. Only use Spider Noir against targets you have explicit")
    print("  written permission to test. Unauthorized access to computer systems")
    print("  is illegal. The author assumes no liability for misuse of this tool.\033[0m")
    print()
    accept = input("  \033[96m[?]\033[0m Do you agree to use this tool ethically and responsibly? (Y/n): ").strip().lower()
    if accept in ("n", "no"):
        print("\n  Exiting. Use this tool responsibly.\n")
        sys.exit(0)

    banner()

    # ── Verify dependencies ──────────────────────────────────────────────────
    try:
        from pyvis.network import Network  # noqa
    except ImportError:
        log("ERROR", "pyvis required: pip install pyvis --break-system-packages")
        sys.exit(1)

    # ── Collect configuration ────────────────────────────────────────────────
    try:
        config = collect_inputs()
    except KeyboardInterrupt:
        print("\n\n  \033[93m[!] Cancelled by user.\033[0m\n")
        sys.exit(0)

    # ── Run initial pipeline ─────────────────────────────────────────────────
    try:
        result = run_pipeline(config)
        if result is None:
            sys.exit(0)
        katana_results, ffuf_results, output_html = result
    except KeyboardInterrupt:
        print("\n\n  \033[93m[!] Pipeline interrupted.\033[0m")
        print(f"  \033[93m[!] Partial results in: {config['output_dir'].resolve()}\033[0m\n")
        sys.exit(0)
    except Exception as e:
        log("ERROR", f"Unhandled critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # ── Drill-down loop ──────────────────────────────────────────────────────
    # After the initial pipeline, the user can select nodes to explore deeper.
    # Each drill-down re-crawls and re-fuzzes only the selected target with
    # increased depth. Results are merged with the parent cache.
    drill_depth = 0
    current_base = config["target"]   # Tracks the base URL for the drill-down menu

    while True:
        try:
            selected = drill_down_menu(config, katana_results, ffuf_results, drill_depth, current_base)
            if selected is None:
                log("INFO", "Exiting drill-down mode.")
                break

            drill_depth += 1

            katana_results, ffuf_results, output_html = run_drill_down(
                config, katana_results, ffuf_results, selected, drill_depth
            )

            # After drill completes, set current_base to the drill's target
            # so the NEXT menu builds URLs relative to this drill level.
            # BUT: the menu shows data from parent_katana (unchanged),
            # so we need to use the selected URL as base only if the user
            # will drill into a CHILD of this node.
            # For simplicity: always use the original target as base.
            # The menu paths are absolute from the host root.
            current_base = config["target"]
        except KeyboardInterrupt:
            print("\n\n  \033[93m[!] Drill-down interrupted.\033[0m\n")
            break
        except Exception as e:
            log("ERROR", f"Drill-down error: {e}")
            import traceback
            traceback.print_exc()
            break

    # ── Final summary ────────────────────────────────────────────────────────
    print()
    log("OK", f"Session directory: \033[96m{config['output_dir'].resolve()}\033[0m")
    if drill_depth > 0:
        log("OK", f"Drill-downs completed: {drill_depth}")
    print("\n  \033[38;5;240mThank you for using Spider Noir. Stay ethical. 🕷\033[0m\n")


if __name__ == "__main__":
    main()
