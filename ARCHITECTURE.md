# Shadow-Flow — Automated Penetration Testing Toolkit
## Architecture & Design Document

---

## Step 1 — High-Level Architecture

```
╔══════════════════════════════════════════════════════════════════════╗
║                        SHADOW-FLOW FRAMEWORK                        ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║   ┌─────────────┐   ┌────────────────────────────────────────────┐  ║
║   │  CLI / REPL │──▶│           Entry Point (main.py)            │  ║
║   └─────────────┘   └────────────────┬───────────────────────────┘  ║
║                                      │                              ║
║                         ┌────────────▼────────────┐                ║
║                         │   Config Loader (YAML)  │                ║
║                         └────────────┬────────────┘                ║
║                                      │                              ║
║                    ┌─────────────────▼──────────────────┐          ║
║                    │     Orchestration Engine (core/)    │          ║
║                    │  ┌──────────────────────────────┐   │          ║
║                    │  │   Rule-Based Decision Engine  │   │          ║
║                    │  │   (decides attack path)       │   │          ║
║                    │  └──────────────┬───────────────┘   │          ║
║                    │                 │                    │          ║
║                    │  ┌──────────────▼───────────────┐   │          ║
║                    │  │   Session Manager             │   │          ║
║                    │  │   (tracks state & results)    │   │          ║
║                    │  └──────────────────────────────┘   │          ║
║                    └──────────────┬─────────────────────┘          ║
║                                   │                                 ║
║           ┌───────────────────────┼──────────────────────┐         ║
║           │                       │                      │          ║
║  ┌────────▼──────┐   ┌────────────▼──────┐   ┌──────────▼───────┐  ║
║  │   modules/    │   │   modules/        │   │   modules/       │  ║
║  │   recon/      │   │   scanning/       │   │   exploitation/  │  ║
║  │               │   │                   │   │                  │  ║
║  │ - nmap        │   │ - nse_scripts     │   │ - msf_rpc        │  ║
║  │ - dns_enum    │   │ - nikto           │   │ - exploit_select │  ║
║  │ - subdomain   │   │ - svc_detection   │   │ - payload_cfg    │  ║
║  └───────────────┘   └───────────────────┘   └──────────────────┘  ║
║                                                                      ║
║  ┌───────────────────┐                                               ║
║  │  persistence/     │                                               ║
║  │  - cron           │                                               ║
║  │  - startup        │                                               ║
║  │  - mechanism_log  │                                               ║
║  └───────────────────┘                                               ║
║                                                                      ║
║  ┌──────────────────────────┐    ┌───────────────────────────────┐  ║
║  │ network_monitor/         │    │ reporting/                    │  ║
║  │ - tcpdump_capture        │    │ - json_reporter               │  ║
║  │ - bettercap_mitm         │    │ - html_reporter (Jinja2)      │  ║
║  └──────────────────────────┘    └───────────────────────────────┘  ║
║                                                                      ║
║  ┌──────────────────────────────────────────────────────────────┐   ║
║  │            Plugins (plugin_loader / custom tools)            │   ║
║  └──────────────────────────────────────────────────────────────┘   ║
║                                                                      ║
║  ┌───────────────┐   ┌─────────────────┐   ┌───────────────────┐   ║
║  │  core/logger  │   │ core/config     │   │ core/exceptions   │   ║
║  └───────────────┘   └─────────────────┘   └───────────────────┘   ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Attack Flow Pipeline

```
TARGET INPUT
    │
    ▼
[Config Loader]  ←── config/config.yaml
    │
    ▼
[Decision Engine] — identifies: Web / Network / Linux / Windows
    │
    ├──── Phase 1: RECON
    │         └── nmap host discovery → dns enum → subdomain enum
    │
    ├──── Phase 2: SCAN & ENUMERATE
    │         └── nmap NSE → nikto (if web) → service fingerprint
    │
    ├──── Phase 3: EXPLOIT
    │         └── match CVEs to open ports → MSF RPC → payload launch
    │
    ├──── Phase 4: PERSISTENCE (lab only)
    │         └── mechanism simulation → full audit log
    │
    └──── REPORTING
              └── JSON dump → Jinja2 HTML report → severity + remediation
```

---

## Role of Each Component

| Component | Role |
|---|---|
| `core/orchestrator.py` | Master controller — sequences phases, calls modules |
| `core/decision_engine.py` | Rule-based logic — selects tools based on detected services/OS |
| `core/session.py` | Tracks scan state, accumulated results, active sessions |
| `core/config.py` | Loads and validates YAML/JSON config |
| `core/logger.py` | Unified logging to console + file |
| `core/exceptions.py` | Custom exception hierarchy |
| `modules/recon/` | All passive and active recon tools |
| `modules/scanning/` | NSE scripts, Nikto, service detection |
| `modules/exploitation/` | Metasploit RPC bridge, exploit/payload selection |
| `modules/persistence/` | Simulated persistence mechanism tracking |
| `modules/network_monitor/` | tcpdump / Bettercap wrappers |
| `reporting/` | JSON + HTML report generators |
| `plugins/` | Drop-in plugin loader for third-party or custom tools |
| `cli/` | Metasploit-style interactive console |

---

## Step 2 — Folder Structure

```
Shadow-Flow/
├── pentest_tool.py          ← Legacy entry (keep for backward compat)
├── main.py                  ← New primary entry point (CLI + REPL)
├── config/
│   ├── config.yaml          ← Tool paths, timing, API keys, options
│   └── rules.yaml           ← Decision engine rules
│
├── core/
│   ├── __init__.py
│   ├── logger.py            ← Unified logger (existing, upgraded)
│   ├── config.py            ← Config loader (YAML/JSON)
│   ├── orchestrator.py      ← Phase sequencer / master controller
│   ├── decision_engine.py   ← Rule-based attack path builder
│   ├── session.py           ← Session state management
│   └── exceptions.py        ← Custom exceptions
│
├── modules/
│   ├── __init__.py
│   ├── base_module.py       ← Abstract base class for all modules
│   │
│   ├── recon/
│   │   ├── __init__.py
│   │   ├── nmap_scanner.py  ← (existing, upgraded)
│   │   ├── dns_enum.py      ← DNS record enumeration
│   │   └── subdomain_enum.py← Subdomain brute-force / passive enum
│   │
│   ├── scanning/
│   │   ├── __init__.py
│   │   ├── nse_scanner.py   ← Nmap NSE script runner
│   │   ├── nikto_scanner.py ← Nikto web vuln scanner wrapper
│   │   └── service_detector.py ← Service/version fingerprinting
│   │
│   ├── exploitation/
│   │   ├── __init__.py
│   │   ├── msf_rpc.py       ← Metasploit RPC bridge (pymetasploit3)
│   │   ├── exploit_selector.py ← CVE/service → exploit mapper
│   │   └── payload_builder.py  ← Payload configuration helper
│   │
│   ├── persistence/
│   │   ├── __init__.py
│   │   └── persistence_sim.py ← Simulated persistence + audit log
│   │
│   └── network_monitor/
│       ├── __init__.py
│       ├── tcpdump_capture.py  ← Packet capture wrapper
│       └── bettercap_mitm.py   ← Bettercap MITM simulation
│
├── reporting/
│   ├── __init__.py
│   ├── json_reporter.py     ← Structured JSON output
│   ├── html_reporter.py     ← Jinja2 HTML reports
│   └── templates/
│       └── report.html.j2   ← HTML report template
│
├── plugins/
│   ├── __init__.py
│   ├── plugin_loader.py     ← Dynamic plugin discovery & loading
│   └── example_plugin/
│       ├── plugin.json       ← Plugin manifest
│       └── tool.py           ← Plugin implementation
│
├── cli/
│   ├── __init__.py
│   └── console.py           ← Interactive REPL console
│
├── logs/
│   └── pentest_toolkit.log  ← Auto-generated
│
├── reports/
│   └── session_report.json  ← Auto-generated
│
├── tests/
│   ├── test_recon.py
│   ├── test_scanning.py
│   └── test_reporting.py
│
├── requirements.txt
└── README.md
```
