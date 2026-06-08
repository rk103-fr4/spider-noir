# 🕷 Spider Noir


////////////// WORKING FOR AN ENGLISH VERSION, RIGHT NOW ITS JUST IN SPANISH //////////////



**Recon pipeline for web pentesting that unifies subdomain enumeration, crawling and fuzzing into an interactive SVG knowledge graph.**

Built for Parrot OS / Kali Linux. Designed for HTB and Bug Bounty workflows.

```
Subfinder  ►  Katana Crawler  ►  ffuf Fuzzer  ►  SVG Graph
```

---

## What it does

Spider Noir chains three recon tools into a single pipeline and visualizes the results as a hierarchical graph with an action panel:

- **Phase 0 — Subfinder**: passive subdomain enumeration with keyword filters and limits
- **Phase 1 — Katana**: autonomous crawling that follows HTML/JS links
- **Phase 2 — ffuf**: directory and file fuzzing with separate wordlists
- **Phase 3 — SVG Graph**: self-contained HTML with interactive nodes, tooltips and an action panel that generates ready-to-paste commands

The graph shows the target's structure at a glance: which paths exist, what technology each endpoint runs, where forms are exposed, and what ffuf found hidden. Click any node to get contextual attack commands (nmap, nuclei, sqlmap, gobuster, etc.) copied to your clipboard.

---

## Features

- **HackerOne CSV / Burp JSON import** — load scope directly from exported files
- **Tester profile** — custom HTTP headers (X-HackerOne-Research), rate limiting, no-forms mode
- **Smart BB vs HTB detection** — subfinder results use direct URLs (Bug Bounty) or Host headers (HTB) automatically
- **WAF/CDN detection** — aborts crawling after 20 consecutive 403s or 45s stall
- **Time estimation** — shows ETA before starting ffuf, lets you skip or Ctrl+C for a partial graph
- **Node budget** — configurable limit with per-scope distribution (subdomains get 2x quota vs main site)
- **URL deduplication** — Katana results are deduplicated before processing
- **Technology detection** — identifies PHP, ASP.NET, Java, Python, Node.js, nginx, Apache from headers and URLs
- **Form detection** — highlights nodes with input fields (login forms, search boxes, upload forms)
- **Draggable nodes** — rearrange the graph layout by dragging any node
- **Zero dependencies for the graph** — the SVG+JS output works from `file:///` without internet or a local server

---

## Installation

### Requirements

| Tool | Purpose | Install |
|------|---------|---------|
| Python 3.10+ | Runtime | Pre-installed on Parrot/Kali |
| katana | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| ffuf | Web fuzzer | `apt install ffuf` or `go install github.com/ffuf/ffuf/v2@latest` |
| subfinder | Subdomain enum (optional) | [Download binary](https://github.com/projectdiscovery/subfinder/releases) |
| pyvis | Graph data structure | `pip install pyvis` |
| rich | Terminal UI | `pip install rich` |

### Quick start

```bash
git clone https://github.com/rk103-fr4/spider-noir.git
cd spider-noir

# Install Python deps
pip install pyvis rich --break-system-packages

# Install subfinder (optional, for Bug Bounty)
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_amd64.zip
unzip subfinder_2.14.0_linux_amd64.zip && sudo mv subfinder /usr/local/bin/

# Run
python3 spider_noir.py
```

Or use the install script:
```bash
chmod +x install.sh && ./install.sh
```

---

## Usage

### HTB (simple box)

```
Target      : http://10.129.40.184
Subfinder   : No
Rate limit  : 0 (no limit)
Wordlist    : /usr/share/wordlists/dirb/common.txt
Auto-calib  : Yes
Extensions  : .php
Node limit  : 150
```

### Bug Bounty (corporate target)

```
Headers     : X-HackerOne-Research: your-username
Rate limit  : 10 req/s
Scope file  : ~/Downloads/program_scope.csv
Subfinder   : Yes (keywords: admin,api,dev,test)
Wordlist    : /usr/share/wordlists/dirb/common.txt
Auto-calib  : No (WAF interference)
No forms    : Yes (if program prohibits)
Node limit  : 300
```

---

## Graph legend

| Symbol | Color | Meaning |
|--------|-------|---------|
| ★ | Gold | Root target (seed) |
| ⬡ | Purple | VHOST / Subfinder subdomain |
| ● | Blue | Katana visible URL |
| ▲ | Orange | ffuf finding (200/301) |
| ▲ | Red | ffuf finding (403 Forbidden) |
| ◆ | Variable | Path with detected forms |

Node color reflects detected technology (PHP = purple-blue, Java = orange, Node.js = green, etc.)

---

## Action panel

Click any node to see contextual commands:

| Node type | Available actions |
|-----------|-------------------|
| Root / VHOST / Subfinder | nmap, SSLyze, Nuclei, Nikto, WhatWeb |
| Katana path | ffuf, Gobuster, curl, WhatWeb |
| ffuf 200/301 | SQLMap, ffuf, Gobuster, Nuclei |
| ffuf 403 | Bypass headers (X-Forwarded-For, path tricks) |
| Node with forms | SQLMap --forms, Hydra (disabled if program prohibits) |

Commands are copied to clipboard. Paste in your terminal with `Ctrl+Shift+V`.

---

## Architecture

```
┌─────────────┐      ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Subfinder   │────►│    Katana    │────►│     ffuf     │────►│  SVG Graph   │
│  (passive)   │     │  (crawling)  │     │  (fuzzing)   │     │ (interactive)│
│              │     │              │     │              │     │              │
│ Subdomains   │     │ Visible URLs │     │ Hidden paths │     │ All combined │
│ from public  │     │ from HTML/JS │     │ by wordlist  │     │ + actions    │
│ sources      │     │ links        │     │ brute force  │     │ panel        │
└─────────────┘      └──────────────┘     └──────────────┘     └──────────────┘
```

---

## Legal & Ethical Disclaimer

**IMPORTANT NOTICE:** This tool is developed and published strictly for educational purposes, authorized security auditing, and research within controlled laboratory environments. 

By downloading, cloning, running, or utilizing **Spider Noir**, you agree to the following terms:

1. **Authorized Testing Only:** You shall only execute this tool against targets where you have explicit, written, and prior authorization from the system owner (e.g., within an active Bug Bounty program scope, a formal penetration testing engagement, or self-owned infrastructure).
2. **Prohibited Actions:** Unauthorized scanning, crawling, or fuzzing against third-party networks without explicit consent is illegal and can be considered a violation of computer crime laws (such as the CFAA in the US or equivalent international cyberlegislation).
3. **No Liability:** The author (**rk103**) assumes absolutely no liability and is not responsible for any misuse, damage, service disruption, or legal consequences caused by this program. 
4. **Compliance:** It is the sole responsibility of the end-user to ensure that their usage of this tool complies with all applicable local, national, and international laws.

**Use responsibly. Test only what you own or have explicit permission to hack.**

## Author

**rk103** — [github.com/rk103-fr4](https://github.com/rk103-fr4)

## License

MIT
