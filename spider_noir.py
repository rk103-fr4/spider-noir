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
# Spider Noir — Recon Pipeline v1.0
# Author: rk103
# Description: Web recon framework unifying subfinder, katana, and ffuf
#              into an interactive SVG knowledge graph with an action panel.
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
# MAIN DEPENDENCY: pyvis for the interactive graph
# Installation: pip install pyvis
# ─────────────────────────────────────────────────────────────────────────────
try:
    from pyvis.network import Network
except ImportError:
    print("\n[!] pyvis is not installed. Run: pip install pyvis")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# SECONDARY DEPENDENCY: rich for real-time visual progress
# Installation: pip install rich
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
    print("\n[!] rich is not installed (visual progress disabled). Run: pip install rich")


# =============================================================================
# GRAPH COLOR AND STYLE CONSTANTS
# =============================================================================
COLOR_SEED      = "#FFD700"   # Gold   → Root target / seed node
COLOR_VHOST     = "#9B59B6"   # Purple → VHOST / subdomain nodes
COLOR_SUBDOMAIN = "#8E44AD"   # Dark Purple → Subdomains discovered by subfinder
COLOR_VISIBLE   = "#1f77b4"   # Blue   → URLs discovered by Katana (crawling)
COLOR_HIDDEN_OK = "#FF8C00"   # Orange → ffuf: HTTP 200 / 301 (hidden paths)
COLOR_HIDDEN_F  = "#E74C3C"   # Red    → ffuf: HTTP 403 Forbidden
COLOR_INFO      = "#2ECC71"   # Green  → Metadata / info nodes
COLOR_FORM      = "#E91E63"   # Pink   → Nodes with detected forms/inputs

# Technology detection palette (to color nodes based on stack)
TECH_COLORS = {
    "php":    "#8892BF",   # PHP Blue
    "asp":    "#5C2D91",   # ASP.NET Purple
    "java":   "#F89820",   # Java/JSP Orange
    "python": "#3776AB",   # Python Blue
    "ruby":   "#CC342D",   # Ruby Red
    "node":   "#68A063",   # Node.js Green
    "nginx":  "#009900",   # Nginx Green
    "apache": "#D22128",   # Apache Red
}

def detect_tech(headers: dict, content_type: str, url: str) -> str:
    """
    Detects server technology from HTTP headers and the URL.
    Returns a string with the detected technology or "" if not identified.
    Prioritizes specific info (language over web server).
    """
    h = {k.lower(): v.lower() if isinstance(v, str) else v
         for k, v in (headers or {}).items()}

    powered = h.get("x-powered-by", "")
    server  = h.get("server", "")
    cookie  = h.get("set-cookie", "")

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

    if "php" in powered:
        return "php"
    if "asp.net" in powered or "aspnet" in powered:
        return "asp"
    if "express" in powered or "node" in powered:
        return "node"

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

    if "phpsessid" in cookie:
        return "php"
    if "jsessionid" in cookie:
        return "java"
    if "asp.net_sessionid" in cookie or "aspsessionid" in cookie:
        return "asp"

    return ""

# =============================================================================
# SECTION 1: CONSOLE UTILITIES
# =============================================================================

def banner():
    """
    Prints the complete ASCII banner with ANSI color gradient,
    title ASCII art, and author signature (rk103).
    """
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

    gradient = [
        245, 248, 251, 254, 251, 248,
        0,
        240, 243, 247, 250, 253, 255,
    ]

    print()

    for i, line in enumerate(title_lines):
        color_code = gradient[i] if i < len(gradient) else 99
        if line.strip():
            print(f"\033[38;5;{color_code}m{line}\033[0m")
        else:
            print()

    sep   = "─" * 72
    print(f"\033[38;5;240m  {sep}\033[0m")

    desc  = "  Subfinder  ►  Katana Crawler  ►  ffuf Fuzzer  ►  SVG Graph"
    tags  = "  HTB  ·  Bug Bounty  ·  Web Auditing  ·  Red Team Recon"
    print(f"\033[38;5;75m{desc}\033[0m")
    print(f"\033[38;5;240m{tags}\033[0m")

    print(f"\033[38;5;240m  {sep}\033[0m")

    version  = "v1.0"
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
    Logger with ANSI colors for the console.
    Levels: INFO, OK, WARN, ERROR, PHASE
    """
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO":  "\033[94m[*]\033[0m",   # Blue
        "OK":    "\033[92m[+]\033[0m",   # Green
        "WARN":  "\033[93m[!]\033[0m",   # Yellow
        "ERROR": "\033[91m[✗]\033[0m",   # Red
        "PHASE": "\033[95m[►]\033[0m",   # Magenta
    }
    prefix = colors.get(level, "[?]")
    print(f"  {prefix} \033[90m{ts}\033[0m  {msg}")


def check_tool(tool_name: str) -> bool:
    """
    Verifies if an external tool is available in the system PATH.
    Returns True if exists, False otherwise.
    """
    if shutil.which(tool_name) is None:
        log("WARN", f"'{tool_name}' not found in PATH. Please install it before continuing.")
        return False
    log("OK", f"'{tool_name}' found in PATH.")
    return True


def sanitize_filename(name: str) -> str:
    """
    Sanitizes a string to be used as a safe filename,
    replacing special characters with underscores.
    """
    return re.sub(r"[^\w\-_.]", "_", name)


# =============================================================================
# SECTION 2: INTERACTIVE PARAMETER COLLECTION
# =============================================================================

def parse_hackerone_csv(filepath: str) -> dict:
    import csv

    result = {
        "wildcards":    [],
        "exact_urls":   [],
        "out_of_scope": [],
        "skipped":      [],
        "raw_rows":     [],
    }

    WEB_TYPES = {"url", "wildcard", "domain"}

    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            sample  = f.read(2048)
            f.seek(0)
            dialect = csv.Sniffer().sniff(sample, delimiters=",;	")
            reader  = csv.DictReader(f, dialect=dialect)

            for row in reader:
                result["raw_rows"].append(row)

                norm = {k.strip().lower(): v.strip() for k, v in row.items()}

                identifier   = norm.get("identifier", "").strip()
                asset_type   = norm.get("asset_type", "").strip().lower()
                eligible     = norm.get("eligible_for_submission", "true").strip().lower()

                if not identifier:
                    continue

                if asset_type not in WEB_TYPES and asset_type != "":
                    result["skipped"].append(f"{identifier} ({asset_type})")
                    continue

                if eligible in ("false", "no", "0"):
                    result["out_of_scope"].append(identifier)
                    continue

                if identifier.startswith("*."):
                    result["wildcards"].append(identifier)
                elif "*" in identifier:
                    result["wildcards"].append(identifier)
                else:
                    clean = identifier.replace("https://", "").replace("http://", "").rstrip("/")
                    result["exact_urls"].append(clean)

    except FileNotFoundError:
        log("ERROR", f"CSV file not found: {filepath}")
    except Exception as e:
        log("ERROR", f"Error parsing HackerOne CSV: {e}")

    return result


def parse_burp_scope(filepath: str) -> dict:
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
                clean = host.replace(".*.", "*.").replace("\\.", ".")
                result["wildcards"].append(clean)
            else:
                result["exact_urls"].append(host)

        for entry in exclude:
            host = entry.get("host", "").strip()
            if host:
                result["out_of_scope"].append(host)

    except FileNotFoundError:
        log("ERROR", f"Burp file not found: {filepath}")
    except Exception as e:
        log("ERROR", f"Error parsing Burp scope: {e}")

    return result


def _load_vhosts_input(prompt_label: str) -> list:
    print(f"\n      You can input for {prompt_label}:")
    print("        · Comma-separated list: dev.htb,admin.htb,api.htb")
    print("        · Path to a .txt file with one VHOST per line\n")
    raw = input(f"  \033[96m[?]\033[0m [{prompt_label}] VHOSTs or file path: ").strip()
    if not raw:
        return []
    if Path(raw).is_file():
        with open(raw, "r") as fh:
            vhosts = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        log("OK", f"{prompt_label}: {len(vhosts)} VHOSTs loaded from file.")
        return vhosts
    vhosts = [v.strip() for v in raw.split(",") if v.strip()]
    log("OK", f"{prompt_label}: {len(vhosts)} VHOSTs loaded from manual input.")
    return vhosts


def collect_inputs() -> dict:
    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 0a — TESTER PROFILE
    # ══════════════════════════════════════════════════════════════════════════
    print("\n\033[38;5;220m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;220m  ║  BLOCK 0a — TESTER PROFILE                                       ║\033[0m")
    print("\033[38;5;220m  ║  Identification headers + rate limit for Bug Bounty.             ║\033[0m")
    print("\033[38;5;220m  ║  Applies to Katana, ffuf, and subfinder automatically.           ║\033[0m")
    print("\033[38;5;220m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    config = {}

    print("  \033[38;5;240m  Some BB programs require identifying your recon traffic with a custom\033[0m")
    print("  \033[38;5;240m  HTTP header. E.g.: HackerOne requires X-HackerOne-Research: your-user\033[0m\n")

    headers_input = input(
        "  \033[96m[?]\033[0m Identification headers (Enter to skip)\n"
        "      e.g.: X-HackerOne-Research: your-user\n"
        "      e.g.: X-HackerOne-Research: your-user, X-Custom: value > "
    ).strip()

    config["custom_headers"] = []
    if headers_input:
        raw_headers = []
        import re as _re
        parts = _re.split(r",\s*(?=[A-Za-z-]+:)", headers_input)
        for part in parts:
            part = part.strip()
            if ":" in part:
                raw_headers.append(part)

        config["custom_headers"] = raw_headers
        log("OK", f"Configured headers: {raw_headers}")
    else:
        log("INFO", "No identification headers. Continuing without custom headers.")

    print()
    print("  \033[38;5;240m  Rate limiting protects the target and prevents IP bans.\033[0m")
    print("  \033[38;5;240m  Some BB programs specify a maximum (e.g.: Gogo: 10 req/s)\033[0m\n")

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

    print()
    no_forms_input = input(
        "  \033[96m[?]\033[0m Does the program prohibit submitting forms? (y/N)\n"
        "      Disables Hydra and SQLMap-forms in the graph's action panel > "
    ).strip().lower()
    config["no_forms"] = no_forms_input in ("y", "yes")
    if config["no_forms"]:
        log("WARN", "Forms disabled — Hydra and SQLMap-forms will not be available in the graph.")

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 0 — GLOBAL TARGET
    # ══════════════════════════════════════════════════════════════════════════
    print("\n\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━  GLOBAL TARGET  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print("  URL or IP that acts as the entry point for the entire pipeline.\n")

    while True:
        target = input("  \033[96m[?]\033[0m Target URL or IP (e.g., http://10.10.11.20 or http://target.htb): ").strip()
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
    # BLOCK 0c — SCOPE FROM FILE
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;39m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;39m  ║  BLOCK 0c — SCOPE FROM FILE                                      ║\033[0m")
    print("\033[38;5;39m  ║  Load HackerOne CSV or Burp Suite JSON.                          ║\033[0m")
    print("\033[38;5;39m  ║  In-scope wildcards and exact URLs are extracted automatically.  ║\033[0m")
    print("\033[38;5;39m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    print("  \033[38;5;240m  Download the scope from:\033[0m")
    print("  \033[38;5;240m    HackerOne → Program → Policy → Download CSV\033[0m")
    print("  \033[38;5;240m    Burp Suite → Target → Scope → Save to file\033[0m\n")

    scope_file_input = input(
        "  \033[96m[?]\033[0m Path to scope file (Enter to skip)\n"
        "      e.g.: ~/Downloads/gogo_vdp_scope.csv  or  ~/burp_scope.json > "
    ).strip()

    config["scope_file_wildcards"] = []
    config["scope_file_exact"]     = []
    config["scope_file_excluded"]  = []

    if scope_file_input:
        scope_path = Path(scope_file_input).expanduser()

        if not scope_path.exists():
            log("WARN", f"File not found: {scope_path}")
        else:
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
                log("INFO", f"Unknown extension, attempting as CSV: {scope_path}")
                parsed = parse_hackerone_csv(str(scope_path))
                fmt    = "CSV (auto-detected)"

            config["scope_file_wildcards"] = parsed["wildcards"]
            config["scope_file_exact"]     = parsed["exact_urls"]
            config["scope_file_excluded"]  = parsed["out_of_scope"]

            log("OK", f"Scope loaded from {fmt}:")
            log("INFO", f"  In-scope wildcards  : {len(parsed['wildcards'])}")
            for wc in parsed["wildcards"][:10]:
                log("INFO", f"    ✓ {wc}")
            if len(parsed["wildcards"]) > 10:
                log("INFO", f"    ... and {len(parsed['wildcards'])-10} more")

            log("INFO", f"  In-scope exact URLs: {len(parsed['exact_urls'])}")
            for url in parsed["exact_urls"][:10]:
                log("INFO", f"    ✓ {url}")
            if len(parsed["exact_urls"]) > 10:
                log("INFO", f"    ... and {len(parsed['exact_urls'])-10} more")

            if parsed["out_of_scope"]:
                log("WARN", f"  Out of scope ({len(parsed['out_of_scope'])}): {parsed['out_of_scope'][:5]}")

            if parsed["skipped"]:
                log("INFO", f"  Ignored (non-web): {parsed['skipped'][:5]}")

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 0b — SUBFINDER
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;208m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;208m  ║  BLOCK 0b — SUBFINDER  (Subdomain Enumeration)                   ║\033[0m")
    print("\033[38;5;208m  ║  Discovers admin., api., dev., staging. before crawling.         ║\033[0m")
    print("\033[38;5;208m  ║  Highly recommended for Bug Bounty. Optional for HTB.            ║\033[0m")
    print("\033[38;5;208m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    subfinder_available = shutil.which("subfinder") is not None
    if not subfinder_available:
        print("  \033[93m[!]\033[0m subfinder not found in PATH — skipping this phase.")
        print("      Installation: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n")

    print("  \033[38;5;240m──────────────────────────────────────────────────────────────────────\033[0m")
    use_subfinder = input("  \033[96m[?]\033[0m Run subfinder? (y/N): ").strip().lower()
    config["use_subfinder"] = (use_subfinder in ("y", "yes")) and subfinder_available
    config["subfinder_results"] = []

    if use_subfinder in ("y", "yes") and not subfinder_available:
        log("WARN", "You chose 'y' but subfinder is not installed. Skipping Phase 0.")
    elif config["use_subfinder"]:
        parsed_target = urlparse(config["target"])
        host_parts    = (parsed_target.hostname or "").split(".")
        if len(host_parts) >= 2 and not host_parts[-1].isdigit():
            root_domain = ".".join(host_parts[-2:])
        else:
            root_domain = parsed_target.hostname or config["host"]
        config["subfinder_domain"] = root_domain
        log("OK", f"subfinder activated → root domain: {root_domain}")

        print()
        kw_input = input(
            "  \033[96m[?]\033[0m Filter subdomains by keywords (recommended)\n"
            "      Only subdomains containing any of these words will be processed.\n"
            "      [Enter = no keyword filter, process all]\n"
            "      e.g.: admin,api,dev,staging,test,portal,internal,vpn > "
        ).strip()

        config["subfinder_keywords"] = []
        if kw_input:
            keywords = [k.strip().lower() for k in kw_input.split(",") if k.strip()]
            config["subfinder_keywords"] = keywords
            log("OK", f"Filter keywords: {keywords}")
        else:
            log("INFO", "No keyword filter — all subdomains will be processed.")

        print()
        limit_input = input(
            "  \033[96m[?]\033[0m Maximum subdomain limit to process [20]\n"
            "      Shorter ones (more important) are prioritized automatically.\n"
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
    # BLOCK 1 — KATANA (Crawler)
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;51m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;51m  ║  BLOCK 1 — KATANA  (Crawler)                                     ║\033[0m")
    print("\033[38;5;51m  ║  Katana follows HTML/JS links automatically. Doesn't use wordlist.║\033[0m")
    print("\033[38;5;51m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    subfinder_vhosts = config.get("subfinder_results", [])
    if subfinder_vhosts:
        print(f"  \033[92m[+]\033[0m Subfinder already added {len(subfinder_vhosts)} subdomain(s) to crawling:")
        for sv in subfinder_vhosts:
            print(f"       \033[96m→ {sv}\033[0m")
        print()
        print("  \033[38;5;240m  You can add additional VHOSTs (HTB) or leave empty if subfinder was enough.\033[0m\n")
    
    print()
    timeout_in = input(
        "  \033[96m[?]\033[0m Katana global timeout per scope in seconds [300]\n"
        "      Targets with aggressive WAF: 60-120s  |  Permissive targets: 300s+\n"
        "      If no URLs arrive in 45s → scope is automatically abandoned > "
    ).strip()
    try:
        config["katana_timeout"] = int(timeout_in) if timeout_in else 300
    except ValueError:
        config["katana_timeout"] = 300
    log("OK", f"Katana timeout: {config['katana_timeout']}s per scope (stall: 45s, WAF: 20x403)")

    use_k = input("\n  \033[96m[?]\033[0m Add EXTRA VHOSTs/subdomains for Katana? (y/N): ").strip().lower()
    config["use_katana_vhosts"] = use_k in ("y", "yes")
    config["katana_vhosts"] = []

    if config["use_katana_vhosts"]:
        config["katana_vhosts"] = _load_vhosts_input("KATANA")
        if not config["katana_vhosts"]:
            log("WARN", "Empty list. No extra VHOSTs added.")
            config["use_katana_vhosts"] = False

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 2 — FFUF (Fuzzer)
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;214m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;214m  ║  BLOCK 2 — FFUF  (Directory and file fuzzer)                     ║\033[0m")
    print("\033[38;5;214m  ║  Pass 1: directory wordlist      →  /FUZZ                        ║\033[0m")
    print("\033[38;5;214m  ║  Pass 2+: file wordlist          →  /FUZZ.ext (optional)         ║\033[0m")
    print("\033[38;5;214m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    print("  \033[38;5;214m── Pass 1: Directories (/FUZZ) ───────────────────────────────────\033[0m\n")
    while True:
        wordlist = input(
            "  \033[96m[?]\033[0m DIRECTORY Wordlist (mandatory)\n"
            "      Words intended as paths: admin, backup, api, config\n"
            "      [Enter = search for default system wordlist]: "
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

    print()
    ac_input = input(
        "  \033[96m[?]\033[0m Enable ffuf auto-calibration? (-ac) [Y/n]\n"
        "      Y → filters false positives automatically (recommended for HTB)\n"
        "      n → no filter (recommended if ffuf returns 0 results with -ac) > "
    ).strip().lower()
    config["ffuf_ac"] = ac_input not in ("n", "no")
    log("OK", f"ffuf auto-calibration: {'ENABLED' if config['ffuf_ac'] else 'DISABLED'}")

    if subfinder_vhosts:
        print(f"\n  \033[92m[+]\033[0m Subfinder already added {len(subfinder_vhosts)} subdomain(s) to fuzzing.")
        print("  \033[38;5;240m  You can add additional VHOSTs (HTB) or leave empty if subfinder was enough.\033[0m\n")

    use_f = input("\n  \033[96m[?]\033[0m Add EXTRA VHOSTs/subdomains for ffuf? (y/N): ").strip().lower()
    config["use_ffuf_vhosts"] = use_f in ("y", "yes")
    config["ffuf_vhosts"] = []

    if config["use_ffuf_vhosts"]:
        config["ffuf_vhosts"] = _load_vhosts_input("FFUF")
        if not config["ffuf_vhosts"]:
            log("WARN", "Empty list. No extra VHOSTs added.")
            config["use_ffuf_vhosts"] = False

    print()
    print("  \033[38;5;214m── Additional passes: Files (/FUZZ.ext) ────────────────────────\033[0m\n")

    ext_input = input(
        "  \033[96m[?]\033[0m Extensions to test (Enter to skip file passes)\n"
        "      Unknown tech           : .php,.html,.bak,.zip,.txt,.xml\n"
        "      PHP                    : .php,.php5,.phtml,.bak,.old\n"
        "      Java / JSP             : .jsp,.jspa,.do,.action,.war\n"
        "      ASP.NET                : .asp,.aspx,.ashx,.config,.cs\n"
        "      Sensitive files        : .bak,.sql,.log,.zip,.tar.gz\n"
        "      > "
    ).strip()

    config["ffuf_extensions"] = []
    config["wordlist_files"]  = None

    if ext_input:
        exts = []
        for e in ext_input.split(","):
            e = e.strip().lower()
            if e and not e.startswith("."):
                e = "." + e
            if e:
                exts.append(e)
        config["ffuf_extensions"] = exts
        log("OK", f"Configured extensions: {exts}")

        print()
        wordlist_files = input(
            "  \033[96m[?]\033[0m FILE Wordlist for extension passes\n"
            "      Words intended as filenames: config, index, db\n"
            "      [Enter = reuse directory wordlist as fallback]: "
        ).strip()

        if wordlist_files:
            if not Path(wordlist_files).is_file():
                log("WARN", f"File not found: {wordlist_files}. Using directory wordlist.")
                config["wordlist_files"] = None
            else:
                config["wordlist_files"] = wordlist_files
                log("OK", f"Wordlist files: {wordlist_files} ({Path(wordlist_files).stat().st_size // 1024} KB)")
        else:
            log("INFO", "Wordlist files: reusing directory wordlist.")

        total_passes = 1 + len(exts)
        wl_files_label = config["wordlist_files"] or config["wordlist"]
        log("INFO", f"ffuf will run {total_passes} total pass(es):")
        log("INFO", f"  Pass 1        : {config['wordlist']}  →  /FUZZ")
        for ext in exts:
            log("INFO", f"  Pass ext      : {wl_files_label}  →  /FUZZ{ext}")
    else:
        log("INFO", "No extensions: ffuf will only run the directories pass.")

    all_vhosts = list(dict.fromkeys(config["katana_vhosts"] + config["ffuf_vhosts"]))
    config["all_vhosts"] = all_vhosts

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 3 — SCOPE
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;99m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;99m  ║  BLOCK 3 — SCOPE  (applies to Katana)                            ║\033[0m")
    print("\033[38;5;99m  ║  Without scope, Katana follows external links off-target.        ║\033[0m")
    print("\033[38;5;99m  ║  You can combine all 3 formats in the same session.              ║\033[0m")
    print("\033[38;5;99m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    file_wildcards = config.get("scope_file_wildcards", [])
    file_exact     = config.get("scope_file_exact", [])

    if file_wildcards or file_exact:
        print(f"  \033[92m[+]\033[0m Pre-loaded scope from file:")
        if file_wildcards:
            print(f"       Wildcards : {', '.join(file_wildcards[:5])}"
                  + (f" (+{len(file_wildcards)-5} more)" if len(file_wildcards) > 5 else ""))
        if file_exact:
            print(f"       Exact     : {', '.join(file_exact[:5])}"
                  + (f" (+{len(file_exact)-5} more)" if len(file_exact) > 5 else ""))
        print("  \033[38;5;240m  You can add more below or leave empty to use only the file's scope.\033[0m\n")

    scope_in = input(
        "  \033[96m[?]\033[0m [A] Additional exact domains (Enter = use file's or base target)\n"
        "      e.g.: target.htb,admin.htb,10.10.11.20 > "
    ).strip()

    if scope_in:
        manual_exact = [d.strip().lower() for d in scope_in.split(",") if d.strip()]
    else:
        manual_exact = []

    if file_exact or manual_exact:
        scope_domains = list(dict.fromkeys(
            [e.lower() for e in file_exact] +
            manual_exact
        ))
    else:
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

    print()
    wc_in = input(
        "  \033[96m[?]\033[0m [B] Additional wildcards (Enter = use file's)\n"
        "      e.g.: *.target.com,*.company.com > "
    ).strip()

    config["scope_wildcards"] = []
    config["scope_wildcard_patterns"] = []

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
            log("INFO", f"  ... and {len(config['scope_wildcards'])-5} more")

    print()
    rx_in = input(
        "  \033[96m[?]\033[0m [C] Advanced scope regex (optional)\n"
        "      Evaluated against the FULL URL (domain + path).\n"
        "      Useful when you need to filter by path, not just domain.\n"
        "      If A and B already cover your scope, leave this empty.\n"
        "\n"
        "      Examples:\n"
        "        Only API endpoints     →  .*/api/.*\n"
        "        Any .htb               →  .*\\.htb.*\n"
        "        Only HTTPS             →  ^https://.*\n"
        "        A specific path        →  .*/v2/users.*\n"
        "\n"
        "      [Enter to skip — recommended if you used A or B] > "
    ).strip()

    config["scope_regex"] = None
    if rx_in:
        try:
            config["scope_regex"] = re.compile(rx_in, re.IGNORECASE)
            log("OK", f"Custom regex compiled: {rx_in}")
        except re.error as e:
            log("WARN", f"Invalid regex ({e}), ignored.")

    total_rules = (
        len(config["scope_domains"]) +
        len(config["scope_wildcards"]) +
        (1 if config["scope_regex"] else 0)
    )
    log("OK", f"Scope: {total_rules} active rules  "
              f"({len(config['scope_domains'])} exact | "
              f"{len(config['scope_wildcards'])} wildcards | "
              f"{'1 regex' if config['scope_regex'] else '0 regex'})")

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCK 4 — GRAPH
    # ══════════════════════════════════════════════════════════════════════════
    print()
    print("\033[38;5;71m  ╔═══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[38;5;71m  ║  BLOCK 4 — GRAPH  (PyVis visualization)                          ║\033[0m")
    print("\033[38;5;71m  ║  Depth 2 → shows /dir/subdir, collapses the rest.                ║\033[0m")
    print("\033[38;5;71m  ║  ffuf findings NEVER collapse.                                   ║\033[0m")
    print("\033[38;5;71m  ║  Node limit: guarantees browser performance.                     ║\033[0m")
    print("\033[38;5;71m  ╚═══════════════════════════════════════════════════════════════════╝\033[0m\n")

    depth_in = input("  \033[96m[?]\033[0m Maximum Katana node depth in the graph [2]: ").strip()
    try:
        config["graph_depth"] = max(1, int(depth_in)) if depth_in else 2
    except ValueError:
        config["graph_depth"] = 2
        log("WARN", "Invalid value, using default depth: 2")
    log("OK", f"Graph depth: {config['graph_depth']} levels")

    print()
    limit_in = input(
        "  \033[96m[?]\033[0m Maximum node limit in the graph [300]\n"
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

    ts_label   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host  = sanitize_filename(config["host"])
    output_dir = Path(f"recon_{safe_host}_{ts_label}")
    output_dir.mkdir(parents=True, exist_ok=True)
    config["output_dir"]    = output_dir
    config["session_label"] = f"{safe_host}_{ts_label}"
    log("OK", f"Session directory: {output_dir.resolve()}")

    print("\n\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━  SESSION SUMMARY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print(f"  \033[38;5;240mTarget\033[0m          : \033[96m{config['target']}\033[0m  (port {config['port']})")
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
        print(f"  \033[38;5;208m[SUBFINDER]\033[0m Passive subdomain enumeration")
        print(f"           Domain   : \033[96m{config.get('subfinder_domain', config['host'])}\033[0m")
        _kw  = ", ".join(config.get("subfinder_keywords", [])) or "No filter"
        _lim = str(config.get("subfinder_limit", 20)) if config.get("subfinder_limit") else "No limit"
        print(f"           Keywords : \033[96m{_kw}\033[0m")
        print(f"           Limit    : \033[96m{_lim} subdomains\033[0m")
    print()
    print(f"  \033[38;5;51m[KATANA]\033[0m  Autonomous crawler, no wordlist")
    print(f"           VHOSTs  : \033[96m{config['katana_vhosts'] if config['katana_vhosts'] else 'Only base target'}\033[0m")
    print()
    print(f"  \033[38;5;214m[FFUF  ]\033[0m  Directory and file fuzzer")
    print(f"           WL dirs    : \033[96m{config['wordlist']}\033[0m")
    _wlf = config.get('wordlist_files') or "(same as dirs)"
    print(f"           WL files   : \033[96m{_wlf}\033[0m")
    print(f"           VHOSTs     : \033[96m{config['ffuf_vhosts'] if config['ffuf_vhosts'] else 'Only base target'}\033[0m")
    _ext = config.get('ffuf_extensions', [])
    _ext_str = ", ".join(_ext) if _ext else "Only directories (single pass)"
    _pass_str = f"1 dirs + {len(_ext)} files" if _ext else "1 pass"
    print(f"           Extensions : \033[96m{_ext_str}\033[0m  \033[90m({_pass_str})\033[0m")
    _ac_str = "ENABLED" if config.get("ffuf_ac", True) else "DISABLED (no filter)"
    print(f"           Auto-calib : \033[96m{_ac_str}\033[0m")
    print()
    print(f"  \033[38;5;99m[SCOPE ]\033[0m  URL filter for Katana")
    print(f"           Exact   : \033[96m{config['scope_domains']}\033[0m")
    wc_lbl = config['scope_wildcards'] if config['scope_wildcards'] else ['None']
    print(f"           Wildcard: \033[96m{wc_lbl}\033[0m")
    rx_lbl = config['scope_regex'].pattern if config.get('scope_regex') else 'None'
    print(f"           Regex   : \033[96m{rx_lbl}\033[0m")
    print()
    _lim_g = str(config['graph_node_limit']) if config.get('graph_node_limit') else 'No limit'
    print(f"  \033[38;5;71m[GRAPH ]\033[0m  Depth: \033[96m{config['graph_depth']} levels\033[0m  |  Limit: \033[96m{_lim_g} nodes\033[0m")
    print(f"           Output : \033[96m{output_dir.resolve()}\033[0m")
    print("\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")

    confirm = input("  \033[96m[?]\033[0m Confirm and launch pipeline? (Y/n): ").strip().lower()
    if confirm in ("n", "no"):
        log("WARN", "Pipeline cancelled by user.")
        sys.exit(0)

    return config


# =============================================================================
# SECTION 3: SCOPE FILTER + PHASE 1 — KATANA CRAWLING ENGINE
# =============================================================================

def is_in_scope(url: str, config: dict) -> bool:
    scope_domains   = config.get("scope_domains", [])
    wildcard_pats   = config.get("scope_wildcard_patterns", [])
    scope_regex     = config.get("scope_regex")

    has_any_rule = bool(scope_domains or wildcard_pats or scope_regex)
    if not has_any_rule:
        return True

    try:
        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return False

    if hostname in scope_domains:
        return True

    for pattern in wildcard_pats:
        if pattern.match(hostname):
            return True

    if scope_regex and scope_regex.search(url):
        return True

    return False


def _make_findings_table(tool: str, findings: list, scope: str):
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

    for item in findings[-12:]:
        status = item.get("status", 0)
        url    = item.get("url", "")
        extra  = item.get("content_type", "") or item.get("fuzz_word", "")

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
    label       = sanitize_filename(vhost if vhost else config["host"])
    output_file = output_dir / f"katana_{label}.jsonl"
    scope_label = vhost or config["host"]

    rate_limit  = config.get("rate_limit", 0)
    concurrency = max(1, rate_limit // 2) if rate_limit > 0 else 20

    cmd = [
        "katana",
        "-u", target_url,
        "-d", "3",
        "-jc",
        "-jsonl",
        "-o", str(output_file),
        "-timeout", "10",
        "-c", str(concurrency),
    ]
    if vhost:
        cmd.extend(["-H", f"Host: {vhost}"])

    for header in config.get("custom_headers", []):
        cmd.extend(["-H", header])
    if config.get("custom_headers"):
        log("INFO", f"Identification headers added to Katana: {config['custom_headers']}")

    log("INFO", f"Katana → scope: {scope_label}")
    log("INFO", f"Command: {' '.join(cmd)}")

    discovered  = []
    seen_urls   = set()
    start_time  = time.time()

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
                total=None,
                scope=scope_label,
                found="0",
                last_url="",
            )

            GLOBAL_TIMEOUT  = config.get("katana_timeout", 300)
            STALL_TIMEOUT   = 45
            BLOCK_THRESHOLD = 20

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

                    if time.time() - start_time > GLOBAL_TIMEOUT:
                        log("WARN", f"Katana: global timeout of {GLOBAL_TIMEOUT}s for '{scope_label}'")
                        proc.kill(); break

                    if time.time() - last_url_time > STALL_TIMEOUT:
                        log("WARN", f"Katana: no new URLs for {STALL_TIMEOUT}s in '{scope_label}' — aborting scope")
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

                        if status == 403:
                            consecutive_403 += 1
                            if consecutive_403 >= BLOCK_THRESHOLD:
                                log("WARN", f"Katana: {BLOCK_THRESHOLD} consecutive 403 responses in '{scope_label}' — WAF/CDN blocking")
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
                log("WARN", f"Katana: wait timeout for '{scope_label}', continuing.")
            except FileNotFoundError:
                log("ERROR", "'katana' is not installed or not in PATH.")
                log("INFO",  "Installation: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            except Exception as e:
                log("ERROR", f"Unexpected Katana error: {e}")

    else:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode not in (0, 1):
                log("WARN", f"Katana finished with code {result.returncode}")
        except subprocess.TimeoutExpired:
            log("ERROR", f"Katana timeout for {scope_label}")
            return []
        except FileNotFoundError:
            log("ERROR", "'katana' not found in PATH.")
            return []

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
    log("OK", f"Katana → {len(discovered)} unique in-scope URLs in {elapsed:.1f}s for '{label}'{scope_info}")
    return discovered


# =============================================================================
# SECTION 4: PHASE 2 — FFUF FUZZING ENGINE (with Live Output)
# =============================================================================

def _count_wordlist_lines(wordlist_path: str) -> int:
    try:
        with open(wordlist_path, "rb") as f:
            return sum(1 for _ in f)
    except IOError:
        return 0


def run_ffuf(target_url: str, vhost: "str | None", wordlist: str,
             output_dir: Path, config: dict,
             extension: "str | None" = None) -> list:
    label       = sanitize_filename(vhost if vhost else config["host"])
    ext_suffix  = extension.lstrip(".") if extension else "dirs"
    output_file = output_dir / f"ffuf_{label}_{ext_suffix}.json"
    scope_label = vhost or config["host"]

    fuzz_suffix = extension if extension else ""
    fuzz_url    = target_url.rstrip("/") + "/FUZZ" + fuzz_suffix

    pass_label  = f"dirs+{extension}" if extension else "dirs"

    rate_limit = config.get("rate_limit", 0)
    threads    = max(1, min(rate_limit, 50)) if rate_limit > 0 else 50

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-o", str(output_file),
        "-of", "json",
        "-t", str(threads),
        "-timeout", "10",
        "-mc", "200,301,302,403",
        "-v",
    ]
    if rate_limit > 0:
        cmd.extend(["-rate", str(rate_limit)])
    if config.get("ffuf_ac", True):
        cmd.append("-ac")

    for header in config.get("custom_headers", []):
        cmd.extend(["-H", header])
    if config.get("custom_headers"):
        log("INFO", f"Identification headers added to ffuf: {config['custom_headers']}")
    if vhost:
        cmd.extend(["-H", f"Host: {vhost}"])

    log("INFO", f"ffuf [{pass_label}] → scope: {scope_label}")
    log("INFO", f"Command: {' '.join(cmd)}")

    discovered = []
    start_time = time.time()

    total_words = _count_wordlist_lines(wordlist)
    log("INFO", f"Wordlist: {total_words:,} words to test")

    hits = {"200": 0, "301": 0, "302": 0, "403": 0}

    if RICH_AVAILABLE:
        progress_re = re.compile(r"Progress: \[(\d+)/(\d+)\]")
        hit_re_verbose  = re.compile(r"\|\s+(\d{3})\s+\|\s+[\d.]+\s+\w+\s+\|\s+(https?://\S+)")
        hit_re_standard = re.compile(
            r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)"
        )

        hits_buffer = []

        def _read_stderr_chars(proc, prog, task_id, hbuf, stop_event):
            buf = ""
            try:
                while not stop_event.is_set():
                    ch = proc.stderr.read(1)
                    if not ch:
                        break
                    if ch in ("\r", "\n"):
                        fragment = buf.strip()
                        buf = ""
                        if not fragment:
                            continue
                        m = progress_re.search(fragment)
                        if m:
                            current = int(m.group(1))
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
                pass

        def _read_stdout_lines(proc, buf, furl, slabel):
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

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
                    bufsize=0,
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

                progress.update(task, completed=total_words)
                discovered.extend(hits_buffer)

            except subprocess.TimeoutExpired:
                proc.kill()
                stop_event.set()
                log("ERROR", f"ffuf exceeded 600s timeout for {scope_label}")
            except FileNotFoundError:
                log("ERROR", "'ffuf' is not installed or not in PATH.")
                log("INFO",  "Installation: sudo apt install ffuf  |  go install github.com/ffuf/ffuf@latest")
            except Exception as e:
                log("ERROR", f"Unexpected ffuf error: {e}")

    else:
        try:
            result = subprocess.run(cmd + ["-s"], capture_output=True, text=True, timeout=600)
            if result.returncode not in (0, 1):
                log("WARN", f"ffuf finished with code {result.returncode}")
        except subprocess.TimeoutExpired:
            log("ERROR", f"ffuf timeout for {scope_label}")
            return []
        except FileNotFoundError:
            log("ERROR", "'ffuf' not found in PATH.")
            return []

    if output_file.exists():
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            results = data.get("results", [])
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
            log("ERROR", f"Error parsing final ffuf JSON: {e}")

    elapsed = time.time() - start_time
    log("OK", f"ffuf → {len(discovered)} paths in {elapsed:.1f}s | 200:{hits['200']} 3xx:{hits['301']+hits['302']} 403:{hits['403']}")
    return discovered

# =============================================================================
# SECTION 4b: FFUF PASSES ORCHESTRATOR
# =============================================================================

def run_ffuf_all_passes(target_url: str, vhost: "str | None",
                        output_dir: Path, config: dict) -> list:
    wordlist   = config["wordlist"]
    extensions = config.get("ffuf_extensions", [])
    all_found  = []
    seen_urls  = set()

    scope_label = vhost or config["host"]
    total_passes = 1 + len(extensions)

    log("PHASE", f"ffuf → {total_passes} pass(es) for '{scope_label}'  "
                 f"[dirs{' + ' + ', '.join(extensions) if extensions else ''}]")

    log("INFO", f"  Pass 1/{total_passes}: /FUZZ  (directories)")
    results = run_ffuf(target_url, vhost, wordlist, output_dir, config, extension=None)
    for entry in results:
        entry["extension"] = ""
        entry["pass"]      = "dirs"
        url_key = entry.get("url", "")
        if url_key not in seen_urls:
            seen_urls.add(url_key)
            all_found.append(entry)

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
    log("OK", f"Total ffuf for '{scope_label}': "
              f"{len(all_found)} findings  "
              f"({dirs_count} directories | {ext_count} files with extension)")

    return all_found


# SECTION 5: PHASE 3 — PYVIS GRAPH CONSTRUCTION
# =============================================================================

def _build_path_tree(urls: list, max_depth: int) -> dict:
    tree = {}

    def ensure_node(path, depth, parent):
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
        parts = [p for p in parsed.path.split("/") if p]

        if len(parts) > max_depth:
            parts = parts[:max_depth]

        for depth in range(len(parts) + 1):
            path_key  = "/" + "/".join(parts[:depth]) if depth > 0 else "/"
            parent_key = "/" + "/".join(parts[:depth-1]) if depth > 1 else ("/" if depth == 1 else None)

            ensure_node(path_key, depth, parent_key)

            if parent_key is not None and parent_key in tree:
                tree[parent_key]["children"].add(path_key)

        leaf_key = "/" + "/".join(parts) if parts else "/"
        if leaf_key in tree:
            tree[leaf_key]["entries"].append(entry)

    return tree


def build_graph(config: dict, katana_results: dict, ffuf_results: dict) -> Network:
    log("PHASE", "Phase 3: Building Hierarchical Graph (PyVis)...")

    net = Network(
        height="100vh",
        width="100%",
        bgcolor="#141414",
        font_color="#E8E8E8",
        directed=True,
        notebook=False,
    )

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
                level=level,
                font={"color": "#E8E8E8", "size": 11},
            )
            added_nodes.add(node_id)

    def add_edge_safe(src, dst, color="#444444", width=1):
        if src in added_nodes and dst in added_nodes:
            net.add_edge(src, dst, color=color, width=width)

    # ROOT TARGET (level 0)
    seed_id = config["target"]
    seed_tooltip = f"""
    <div style='background:#1a1a2e;color:#FFD700;padding:12px;border-radius:8px;
                border:1px solid #FFD700;font-family:monospace;min-width:250px;'>
        <b style='font-size:14px;'>🎯 ROOT TARGET</b>
        <hr style='border-color:#FFD700;margin:6px 0;'>
        <b>URL:</b> {config["target"]}<br>
        <b>Host:</b> {config["host"]}<br>
        <b>Port:</b> {config.get("port", 80)}<br>
        <b>Session:</b> {config["session_label"]}
    </div>
    """
    add_node_safe(
        node_id=seed_id, label=config["host"],
        color=COLOR_SEED, shape="star", size=35,
        title_html=seed_tooltip, group="seed", level=0,
    )

    # VHOST NODES (level 1)
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

    # SUBFINDER NODES
    for subdomain in config.get("subfinder_results", []):
        sub_id = f"subfinder:{subdomain}"
        if f"vhost:{subdomain}" not in added_nodes:
            sub_tooltip = f"""
            <div style='background:#1a1a2e;color:#8E44AD;padding:12px;border-radius:8px;
                        border:1px solid #8E44AD;font-family:monospace;min-width:220px;'>
                <b>🔍 SUBDOMAIN (subfinder)</b>
                <hr style='border-color:#8E44AD;margin:6px 0;'>
                <b>Subdomain:</b> {subdomain}<br>
                <b>Source:</b> Passive enumeration<br>
                <i style='color:#888;font-size:10px;'>Discovered without contacting the target</i>
            </div>
            """
            add_node_safe(
                node_id=sub_id, label=subdomain,
                color=COLOR_SUBDOMAIN, shape="hexagon", size=18,
                title_html=sub_tooltip, group="subfinder", level=1,
            )
            add_edge_safe(seed_id, sub_id, color=COLOR_SUBDOMAIN, width=1)

    # KATANA NODES
    log("INFO", "Building hierarchical Katana path tree...")
    max_depth  = config.get("graph_depth", 2)
    node_limit = config.get("graph_node_limit", 300)

    fixed_nodes   = 1 + len(config.get("all_vhosts", [])) + len(config.get("subfinder_results", []))
    ffuf_count    = sum(len(v) for v in ffuf_results.values())
    katana_budget = max(10, node_limit - fixed_nodes - ffuf_count) if node_limit else 999999

    scopes_with_results = [sl for sl, urls in katana_results.items() if urls]
    n_scopes            = len(scopes_with_results) or 1
    base_host           = config["host"].lower()

    n_sub_scopes  = sum(1 for sl in scopes_with_results if sl.lower() != base_host)
    n_base_scopes = n_scopes - n_sub_scopes
    total_parts   = n_sub_scopes * 2 + n_base_scopes * 1
    part_size     = max(5, katana_budget // total_parts) if total_parts else katana_budget

    quota_per_scope = {}
    for sl in scopes_with_results:
        if sl.lower() == base_host:
            quota_per_scope[sl] = part_size
        else:
            quota_per_scope[sl] = part_size * 2

    log("INFO", f"Katana budget: {katana_budget} nodes | "
                f"{n_scopes} scopes | base quota={part_size} | subdomain quota={part_size*2}")

    katana_nodes_by_scope: dict = {}
    total_katana_inserted = 0

    for scope_label, urls in katana_results.items():
        if not urls:
            continue

        tree  = _build_path_tree(urls, max_depth)
        quota = quota_per_scope.get(scope_label, part_size)

        scope_nodes = [
            (path_key, node)
            for path_key, node in tree.items()
            if node["depth"] > 0
        ]
        scope_nodes.sort(key=lambda x: (-len(x[1]["entries"]), x[1]["depth"]))

        if node_limit and len(scope_nodes) > quota:
            log("INFO", f"  {scope_label}: {len(scope_nodes)} nodes → {quota} (scope quota)")
            scope_nodes = scope_nodes[:quota]
        else:
            log("INFO", f"  {scope_label}: {len(scope_nodes)} nodes (within quota)")

        katana_nodes_by_scope[scope_label] = {pk: node for pk, node in scope_nodes}
        total_katana_inserted += len(scope_nodes)

    log("INFO", f"Katana nodes to insert: {total_katana_inserted} "
                f"(of {sum(len(u) for u in katana_results.values())} total URLs)")

    for scope_label, urls in katana_results.items():
        scope_parent = f"vhost:{scope_label}" if scope_label in config.get("all_vhosts", []) else seed_id
        scope_level  = 2 if scope_label in config.get("all_vhosts", []) else 1

        tree = katana_nodes_by_scope.get(scope_label, {})
        sorted_paths = sorted(tree.keys(), key=lambda p: tree[p]["depth"])

        for path_key in sorted_paths:
            node     = tree[path_key]
            depth    = node["depth"]
            entries  = node["entries"]
            children = node["children"]
            count    = len(entries)

            if depth == 0:
                continue

            node_id = f"katana:{scope_label}:{path_key}"
            label   = path_key.split("/")[-1] or path_key

            if count > 1:
                label = f"{label}  ×{count}"
            elif count == 0 and children:
                label = f"{label}/"

            node_size = min(8 + count // 2, 20)

            url_items = "".join(
                f"<li style='margin:2px 0;color:#79C0FF;'>{e.get('url','')[:80]}</li>"
                for e in entries[:10]
            )
            more = f"<li style='color:#888'>... and {count-10} more</li>" if count > 10 else ""

            techs = [e.get("tech", "") for e in entries if e.get("tech")]
            tech  = max(set(techs), key=techs.count) if techs else ""
            tech_color = TECH_COLORS.get(tech, COLOR_VISIBLE)
            tech_html  = (
                f"<b>Tech:</b> <span style='color:{tech_color};font-weight:bold'>"
                f"{tech.upper()}</span><br>"
            ) if tech else ""

            node_color = tech_color if tech else COLOR_VISIBLE

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

            node_shape = "diamond" if all_forms else "dot"
            add_node_safe(
                node_id=node_id, label=label,
                color=node_color, shape=node_shape,
                size=node_size, title_html=tooltip,
                group=f"katana_{scope_label}",
                level=scope_level + depth,
            )

            if depth == 1:
                add_edge_safe(scope_parent, node_id, color=COLOR_VISIBLE, width=1)
            else:
                parent_path = node["parent"]
                parent_id   = f"katana:{scope_label}:{parent_path}"
                if parent_id in added_nodes:
                    add_edge_safe(parent_id, node_id, color=COLOR_VISIBLE, width=1)
                else:
                    add_edge_safe(scope_parent, node_id, color=COLOR_VISIBLE, width=1)

    katana_node_count = len(added_nodes)
    log("INFO", f"Katana Tree: {katana_node_count} nodes (depth {max_depth})")

    # FFUF NODES
    log("INFO", "Adding ffuf findings...")

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
            ext_html   = f"<b>Extension:</b> {ext}<br>" if ext else ""
            tooltip = f"""
            <div style='background:#0d1117;color:#FF8C00;padding:12px;border-radius:8px;
                        border:1px solid {border_color};font-family:monospace;max-width:400px;'>
                <b>{icon} FFUF FINDING</b>
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

            parent_id    = scope_parent
            parent_level = scope_level

            if path_segs:
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
    log("OK", f"Graph built: \033[96m{total_nodes}\033[0m nodes, \033[96m{total_edges}\033[0m edges")

    return net


# =============================================================================
# SECTION 6: SELF-CONTAINED HTML GRAPH EXPORT
# =============================================================================

def _norm_color(c, group: str = "", node_id: str = "") -> str:
    if isinstance(c, str) and c.startswith("#"):
        return c
    if isinstance(c, dict):
        v = c.get("color", c.get("background", c.get("border", "")))
        if isinstance(v, str) and v.startswith("#"):
            return v

    if group == "seed":
        return "#FFD700"
    if group in ("vhost", "subfinder"):
        return "#9B59B6"
    if group.startswith("ffuf_"):
        if node_id.endswith(":403"):
            return "#E74C3C"
        return "#FF8C00"
    if group.startswith("katana_"):
        return "#1f77b4"
    return "#1f77b4"


def export_graph(net, config: dict) -> Path:
    import json as _json
    import math as _math

    output_dir  = config["output_dir"]
    output_file = output_dir / f"recon_graph_{config['session_label']}.html"
    log("PHASE", f"Exporting SVG graph to: {output_file}")

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

    _ncmap = {n["id"]: n["color"] for n in nodes_raw}

    edges_raw = []
    for edge in net.edges:
        dst = str(edge["to"])
        ec  = edge.get("color")
        if ec is None:
            ec = _ncmap.get(dst, "#444444")
        elif isinstance(ec, dict):
            ec = ec.get("color", "#444444")
        edges_raw.append({
            "from":  str(edge["from"]),
            "to":    dst,
            "color": ec if isinstance(ec, str) else "#444444",
        })

    levels = {}
    for n in nodes_raw:
        lv = n["level"]
        levels.setdefault(lv, []).append(n)

    max_level   = max(levels.keys()) if levels else 0
    max_nodes   = max((len(v) for v in levels.values()), default=1)
    NODE_SEP    = 90
    W           = max(1400, max_nodes * NODE_SEP + 200)
    LEVEL_H     = 150
    H           = max(600, (max_level + 1) * LEVEL_H + 120)

    for lv in sorted(levels.keys()):
        nodes_at_level = levels[lv]
        n = len(nodes_at_level)
        for i, node in enumerate(nodes_at_level):
            x = W * (i + 1) / (n + 1)
            y = 60 + lv * LEVEL_H
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
<html lang="en">
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
    &nbsp;|&nbsp; {len(nodes_raw)} nodes · {len(edges_raw)} edges
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
                  color:#333;font-size:9px;">Color = detected tech</div>
    </div>
  </div>
  <div id="panel">
    <div id="ph">⚡ ACTION PANEL</div>
    <div id="ni">
      <div class="ni-empty">← Click on a node<br>to view details<br>and available actions</div>
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
// SPIDER NOIR — SVG + JS Self-contained (no external dependencies)
// ═══════════════════════════════════════════════════════════════════════

var S    = {session_json};
var NODES = {nodes_json};
var EDGES = {edges_json};

var NMAP = {{}};
NODES.forEach(function(n) {{ NMAP[n.id] = n; }});

var wrap = document.getElementById('canvas-wrap');
var svg  = document.getElementById('graph-svg');
var W = S.W, H = S.H;

var vx = 0, vy = 0, vscale = 1;
var MIN_SCALE = 0.15, MAX_SCALE = 4;

function setViewport() {{
    var cw = wrap.clientWidth, ch = wrap.clientHeight;
    svg.setAttribute('width',  cw);
    svg.setAttribute('height', ch);
    svg.setAttribute('viewBox', cw + ' ' + ch);
    vx = (cw - W * vscale) / 2;
    vy = 20;
    renderAll();
}}

var gEdges, gNodes, gLabels;

function buildSVG() {{
    svg.innerHTML = '';
    var defs = svgEl('defs');
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

    var g = svgEl('g'); g.id = 'g-main'; svg.appendChild(g);

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

    gNodes = svgEl('g'); g.appendChild(gNodes);
    gLabels= svgEl('g'); g.appendChild(gLabels);

    NODES.forEach(function(n) {{
        var g2 = svgEl('g');
        g2.setAttribute('cursor','pointer');
        g2.setAttribute('data-id', n.id);
        g2.setAttribute('class','node-g');

        var shape = n.shape || 'dot';
        var sz    = n.size  || 10;
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

        g2.addEventListener('click', function(e) {{
            e.stopPropagation();
            if (Math.abs(e.clientX - startX) < 5 && Math.abs(e.clientY - startY) < 5) {{
                showPanel(n.id);
            }}
        }});
        g2.addEventListener('mouseenter', function(e) {{ showTip(n, e); }});
        g2.addEventListener('mouseleave', function()  {{ hideTip(); }});
        gNodes.appendChild(g2);

        var txt = svgEl('text');
        txt.setAttribute('data-nid', n.id);
        txt.setAttribute('x', n.x);
        var loff = n.label_offset !== undefined ? n.label_offset : 13;
        var ly   = loff >= 0 ? n.y + sz + loff : n.y + loff;
        txt.setAttribute('y', ly);
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

var panning     = false, startX, startY, startVX, startVY;
var dragNode    = null;
var dragStartNX = 0;
var dragStartNY = 0;

wrap.addEventListener('mousedown', function(e) {{
    var nodeEl = e.target.closest('.node-g');
    if (nodeEl) {{
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
        panning = true;
        startX = e.clientX; startY = e.clientY;
        startVX = vx; startVY = vy;
    }}
}});

window.addEventListener('mousemove', function(e) {{
    if (dragNode) {{
        var dx = (e.clientX - startX) / vscale;
        var dy = (e.clientY - startY) / vscale;
        var newX = dragStartNX + dx;
        var newY = dragStartNY + dy;

        dragNode.x = newX;
        dragNode.y = newY;

        var nodeEls = document.querySelectorAll('.node-g[data-id="' + dragNode.id + '"]');
        nodeEls.forEach(function(el) {{
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

wrap.addEventListener('click', function(e) {{
    if (!e.target.closest('.node-g')) {{
        document.getElementById('ni').innerHTML =
            '<div class="ni-empty">← Click on a node<br>to view details<br>and available actions</div>';
        document.getElementById('al').innerHTML = '';
    }}
}});

var tip = document.getElementById('tip');

function showTip(n, e) {{
    if (!n.title) return;
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

function showPanel(nodeId) {{
    var n  = NMAP[nodeId];
    if (!n) return;
    var ni = document.getElementById('ni');
    var al = document.getElementById('al');

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
    al.appendChild(mkBtn('🌐', 'Open in browser',    A.browser(url), 'info'));
    al.appendChild(mkBtn('📡', 'curl -I (headers)',  A.curl(url),    'info'));
    al.appendChild(mkBtn('🔍', 'WhatWeb',            A.whatweb(url), 'info'));

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
    log("INFO", f"Open the graph with: xdg-open {output_file.resolve()}")
    return output_file

def run_subfinder(config: dict) -> list:
    domain     = config.get("subfinder_domain", config["host"])
    output_dir = config["output_dir"]
    out_file   = output_dir / "subfinder_results.txt"

    cmd = [
        "subfinder",
        "-d", domain,
        "-o", str(out_file),
        "-silent",
        "-all",
        "-t", "10",
    ]

    log("INFO", f"subfinder → enumerating subdomains for: {domain}")
    log("INFO", f"Command: {' '.join(cmd)}")

    subdomains = []
    start_time = time.time()

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(spinner_name="dots", style="bright_magenta"),
            TextColumn("[bold magenta]SUBFINDER[/] searching subdomains for "
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
                    log("WARN", f"subfinder finished with code {result.returncode}")
            except subprocess.TimeoutExpired:
                log("ERROR", "subfinder exceeded 120s timeout")
                return []
            except FileNotFoundError:
                log("ERROR", "'subfinder' is not installed or not in PATH.")
                log("INFO",  "Installation: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
                return []
    else:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log("ERROR", f"subfinder: {e}")
            return []

    if out_file.exists():
        with open(out_file, "r") as f:
            subdomains = [l.strip() for l in f if l.strip()]

    elapsed = time.time() - start_time
    total_raw = len(subdomains)
    log("OK", f"subfinder → {total_raw} subdomains found in {elapsed:.1f}s")

    keywords = config.get("subfinder_keywords", [])
    if keywords and subdomains:
        before = len(subdomains)
        subdomains = [
            sd for sd in subdomains
            if any(kw in sd.lower() for kw in keywords)
        ]
        log("INFO", f"Keyword filter {keywords}: {before} → {len(subdomains)} subdomains")
    elif not keywords:
        log("INFO", "No keyword filter applied.")

    subdomains.sort(key=len)

    limit = config.get("subfinder_limit", 20)
    if limit and limit > 0 and len(subdomains) > limit:
        log("INFO", f"Applying limit: {len(subdomains)} → {limit} subdomains (shortest first)")
        subdomains = subdomains[:limit]

    if subdomains:
        log("OK", f"Subdomains to process ({len(subdomains)} of {total_raw} found):")
        for sd in subdomains:
            log("INFO", f"  → {sd}")
    else:
        log("WARN", "No subdomains left after applying filters.")
        log("INFO", f"  All results are in: {out_file}")

    return subdomains


# =============================================================================
# SECTION 7: MAIN PIPELINE
# =============================================================================

def run_pipeline(config: dict):

    print("\n\033[93m━━━━━━━━━━━━━━━━━━━━━━  DEPENDENCY VERIFICATION  ━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    katana_ok    = check_tool("katana")
    ffuf_ok      = check_tool("ffuf")
    if config.get("use_subfinder"):
        subfinder_ok = check_tool("subfinder")
    else:
        subfinder_ok = False
    print()

    if config.get("use_subfinder") and subfinder_ok:
        print("\n\033[38;5;208m━━━━━━━━━━━━━━━━━━━━━━  PHASE 0: SUBFINDER  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
        discovered_subs = run_subfinder(config)
        config["subfinder_results"] = discovered_subs

        if discovered_subs:
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

            config["all_vhosts"] = list(dict.fromkeys(
                config["katana_vhosts"] + config["ffuf_vhosts"]
            ))
    else:
        config["subfinder_results"] = []

    output_dir = config["output_dir"]

    parsed_target = urlparse(config["target"])
    base_scheme   = parsed_target.scheme
    base_host     = parsed_target.hostname or ""

    host_parts  = base_host.split(".")
    root_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else base_host

    def build_scope(vhost: str) -> tuple:
        vhost_lower = vhost.lower()

        if vhost_lower.endswith("." + root_domain) or vhost_lower == root_domain:
            sub_url = f"{base_scheme}://{vhost}"
            return (sub_url, None)

        return (config["target"], vhost)

    katana_scopes = [(config["target"], None)]
    if config["use_katana_vhosts"]:
        for vhost in config["katana_vhosts"]:
            scope = build_scope(vhost)
            if scope not in katana_scopes:
                katana_scopes.append(scope)

    ffuf_scopes = [(config["target"], None)]
    if config["use_ffuf_vhosts"]:
        for vhost in config["ffuf_vhosts"]:
            scope = build_scope(vhost)
            if scope not in ffuf_scopes:
                ffuf_scopes.append(scope)

    log("INFO", f"Detected root domain: {root_domain}")
    log("INFO", f"Katana scopes ({len(katana_scopes)}):")
    for url, vhost in katana_scopes:
        mode = "direct" if vhost is None else f"HTB header: {vhost}"
        log("INFO", f"  {url}  [{mode}]")
    log("INFO", f"ffuf scopes ({len(ffuf_scopes)}):")
    for url, vhost in ffuf_scopes:
        mode = "direct" if vhost is None else f"HTB header: {vhost}"
        log("INFO", f"  {url}  [{mode}]")

    katana_results = {}
    ffuf_results   = {}

    print("\n\033[95m━━━━━━━━━━━━━━━━━━━━━━  PHASE 1: KATANA CRAWLING  ━━━━━━━━━━━━━━━━━━━━━━\033[0m")

    if not katana_ok:
        log("WARN", "Katana not available. Skipping Phase 1. The graph will only have ffuf results.")
    else:
        for target_url, vhost in katana_scopes:
            scope_label = vhost if vhost else config["host"]
            log("PHASE", f"Crawling scope: {scope_label}")
            urls = run_katana(target_url, vhost, output_dir, config)
            katana_results[scope_label] = urls
            log("INFO", f"  → {len(urls)} URLs added for '{scope_label}'")

    total_katana = sum(len(v) for v in katana_results.values())
    log("OK", f"Phase 1 complete. Total Katana URLs: \033[96m{total_katana}\033[0m")

    print("\n\033[95m━━━━━━━━━━━━━━━━━━━━━━  PHASE 2: FFUF FUZZING  ━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")

    ffuf_cancelled = False

    if not ffuf_ok:
        log("WARN", "ffuf not available. Skipping Phase 2.")
    else:
        wordlist_lines = _count_wordlist_lines(config["wordlist"])
        extensions     = config.get("ffuf_extensions", [])
        passes_per_scope = 1 + len(extensions)
        total_words    = wordlist_lines * passes_per_scope
        n_scopes       = len(ffuf_scopes)
        rate           = config.get("rate_limit", 0) or 50

        total_requests = total_words * n_scopes
        eta_seconds    = total_requests / rate
        eta_minutes    = eta_seconds / 60
        eta_hours      = eta_minutes / 60

        if eta_seconds < 60:
            eta_str = f"{eta_seconds:.0f} seconds"
        elif eta_minutes < 60:
            eta_str = f"{eta_minutes:.1f} minutes"
        else:
            eta_str = f"{eta_hours:.1f} hours"

        print()
        print(f"  \033[93m┌─ TIME ESTIMATION ─────────────────────────────────────────────────┐\033[0m")
        print(f"  \033[93m│\033[0m  Wordlist      : {wordlist_lines:,} words × {passes_per_scope} pass(es)")
        print(f"  \033[93m│\033[0m  Scopes        : {n_scopes}")
        print(f"  \033[93m│\033[0m  Total requests: {total_requests:,}")
        print(f"  \033[93m│\033[0m  Rate limit    : {rate} req/s")
        print(f"  \033[93m│\033[0m  Estimated ETA : \033[96m{eta_str}\033[0m")
        print(f"  \033[93m└───────────────────────────────────────────────────────────────────┘\033[0m")
        print()

        if eta_seconds > 1800:
            log("WARN", f"High estimation ({eta_str}). Consider a smaller wordlist.")
            log("INFO", "  common.txt (4,614)  →  seclists/common.txt")
            log("INFO", "  You can also cancel with Ctrl+C — the graph will still be generated.")
            print()

        confirm_ffuf = input(
            f"  \033[96m[?]\033[0m Start ffuf? (ETA: {eta_str}) (Y/n): "
        ).strip().lower()

        if confirm_ffuf in ("n", "no"):
            log("INFO", "ffuf skipped by user. The graph will be generated with Katana data.")
            ffuf_cancelled = True
        else:
            log("INFO", "Ctrl+C at any time to cancel ffuf and generate the partial graph.")
            print()
            try:
                for target_url, vhost in ffuf_scopes:
                    scope_label = vhost if vhost else config["host"]
                    log("PHASE", f"Fuzzing scope: {scope_label}")
                    paths = run_ffuf_all_passes(target_url, vhost, output_dir, config)
                    ffuf_results[scope_label] = paths
                    log("INFO", f"  → {len(paths)} paths added for '{scope_label}'")

            except KeyboardInterrupt:
                ffuf_cancelled = True
                print()
                log("WARN", "ffuf interrupted by user (Ctrl+C).")
                log("INFO", f"  Completed scopes: {len(ffuf_results)}/{len(ffuf_scopes)}")
                log("INFO", "  Generating partial graph with available data...")

    total_ffuf = sum(len(v) for v in ffuf_results.values())
    status_ffuf = "PARTIAL (cancelled)" if ffuf_cancelled else "complete"
    log("OK", f"Phase 2 {status_ffuf}. ffuf paths: \033[96m{total_ffuf}\033[0m")

    print("\n\033[95m━━━━━━━━━━━━━━━━━━━━━  PHASE 3: GRAPH CONSOLIDATION  ━━━━━━━━━━━━━━━━━\033[0m")
    if ffuf_cancelled:
        log("INFO", "Partial graph: includes Katana complete + ffuf up to interruption.")

    net = build_graph(config, katana_results, ffuf_results)
    output_html = export_graph(net, config)

    parcial_label = " \033[93m(PARTIAL GRAPH — ffuf cancelled)\033[0m" if ffuf_cancelled else ""
    print(f"\n\033[92m━━━━━━━━━━━━━━━━━━━━━━━━━━  PIPELINE COMPLETE{parcial_label}  ━━━━━━━━━━━━━━━━━━━\033[0m")
    log("OK", f"Session directory    : \033[96m{output_dir.resolve()}\033[0m")
    log("OK", f"Generated HTML Graph : \033[96m{output_html.resolve()}\033[0m")
    log("OK", f"Total nodes          : \033[96m{len(net.nodes)}\033[0m")
    log("OK", f"Total edges          : \033[96m{len(net.edges)}\033[0m")
    log("OK", f"Katana URLs          : \033[96m{total_katana}\033[0m")
    log("OK", f"ffuf paths           : \033[96m{total_ffuf}\033[0m")
    print(f"\n  \033[93m[>>]\033[0m Open the graph: \033[96mxdg-open {output_html.resolve()}\033[0m\n")
    print("\033[92m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")


# SECTION 8: ENTRY POINT
# =============================================================================

def main():
    banner()

    try:
        from pyvis.network import Network  # noqa
    except ImportError:
        log("ERROR", "pyvis required: pip install pyvis")
        sys.exit(1)

    try:
        config = collect_inputs()
    except KeyboardInterrupt:
        print("\n\n  \033[93m[!] Pipeline cancelled by user (Ctrl+C).\033[0m\n")
        sys.exit(0)

    try:
        run_pipeline(config)
    except KeyboardInterrupt:
        print("\n\n  \033[93m[!] Pipeline interrupted by user (Ctrl+C).\033[0m")
        print(f"  \033[93m[!] Partial results are in: {config['output_dir'].resolve()}\033[0m\n")
        sys.exit(0)
    except Exception as e:
        log("ERROR", f"Unhandled critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
