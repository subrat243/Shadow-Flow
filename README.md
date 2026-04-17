# ⚡ Shadow-Flow
> **An industry-grade, modular, and automated penetration testing framework designed for intelligent attack orchestration and professional reporting.**

**Shadow-Flow** is an industry-grade, modular, and automated penetration testing framework built in Python. Designed for offensive security professionals and red team operators, it automates the full penetration testing lifecycle—from reconnaissance to reporting—using an intelligent, rule-based attack orchestration engine.

---

## 🎯 Objective

Shadow-Flow aims to bridge the gap between fragmented security tools and a unified attack workflow. It chains industry-standard tools like Nmap, Metasploit, Nikto, and Bettercap into a coordinated, multi-stage pipeline, making complex engagements more efficient and reproducible.

---

## 🚀 Key Features

- **Intelligent Attack Orchestration**: A rule-based decision engine that dynamically builds attack paths based on detected services, OS versions, and vulnerabilities.
- **Modular Plugin Architecture**: Easily extend the toolkit by adding new modules or third-party tool wrappers.
- **Full Lifecycle Automation**:
  - **Reconnaissance**: Nmap, DNS enumeration, and subdomain discovery.
  - **Scanning**: Deep NSE script analysis and web vulnerability scanning (Nikto).
  - **Exploitation**: Seamless integration with Metasploit via RPC for automated exploit delivery.
  - **Persistence & Monitoring**: Simulated persistence mechanisms and network traffic capture (tcpdump).
- **Professional Reporting**: Generates both machine-readable JSON and beautiful, executive-ready HTML reports with remediation advice.
- **Interactive REPL**: A Metasploit-style console (`cli/console.py`) for a premium user experience.

---

## 🛠️ Tech Stack

- **Language**: Python 3.x
- **Core Libraries**: `subprocess`, `argparse`, `json`, `requests`, `jinja2`, `pyyaml`, `dnspython`
- **Integrations**: Nmap, Metasploit (msfrpcd), Nikto, tcpdump, Bettercap
- **Design Patterns**: Factory, Strategy, Plugin, Template Method

---

## 📂 Project Structure

```text
Shadow-Flow/
├── main.py                  # Primary entry point (CLI + REPL)
├── core/                    # Framework logic (Orchestrator, Decision Engine)
├── modules/                 # Attack modules (Recon, Scanning, Exploitation, etc.)
├── plugins/                 # Extensible plugin system
├── reporting/               # JSON & HTML report generation
├── config/                  # YAML configurations and rules
├── cli/                     # Interactive console interface
└── tests/                   # Unit and integration tests
```

---

## 🏁 Getting Started

### 1. Prerequisites
Ensure you have the following tools installed:
- Nmap
- Metasploit Framework
- Nikto
- Python 3.8+

### 2. Installation
```bash
git clone https://github.com/subrat243/Shadow-Flow.git
cd Shadow-Flow
pip install -r requirements.txt
```

### 3. Usage

Shadow-Flow supports two primary modes: a Metasploit-style **Interactive REPL** and a **Non-Interactive CLI** for automation.

#### **A. Interactive Console (Recommended)**
Perfect for manual testing and granular control.
```bash
python main.py
```
**Common Console Commands:**
```text
shadow-flow > set target 192.168.1.100    # Set session target
shadow-flow > show modules                 # View all attack modules
shadow-flow > set module exploitation      # Toggle a specific module
shadow-flow > run                          # Execute full intelligent attack chain
shadow-flow > run recon                    # Run ONLY the reconnaissance phase
shadow-flow > show config                  # View current engine settings
shadow-flow > clear                        # Clear the terminal
```

#### **B. CLI Mode (Automation & CI/CD)**
Ideal for scheduled scans or integration into larger pipelines.

**1. Full Automated Scan:**
```bash
python main.py --target scanme.nmap.org
```

**2. Specific Modules Only:**
```bash
python main.py --target 10.0.0.5 --modules recon,scanning
```

**3. Custom Configuration & Rules:**
```bash
python main.py --target 10.0.0.5 --config my_custom_config.yaml --rules custom_rules.yaml
```

**4. Stealth / Speed (Disable heavy reports):**
```bash
python main.py --target 10.0.2.15 --no-html --no-json
```

**5. Debug Mode (Full Verbosity):**
```bash
python main.py --target 10.0.2.15 --verbose
```

---

## 🛠️ Plugin Development

Shadow-Flow is designed to be extensible. You can add your own tools by dropping them into the `plugins/` directory.

1.  **Create a Directory**: `plugins/my_scanner/`
2.  **Add Manifest**: Create `plugin.json` with your tool's metadata (Name, Class, Phase).
3.  **Implement Logic**: Create `tool.py` inheriting from `BaseModule`.
4.  **Auto-Load**: Shadow-Flow will automatically detect and load your plugin on next launch.

Refer to `plugins/example_plugin/` for a boilerplate implementation.

---

## ⚠️ Ethical Hacking Disclaimer

This toolkit is for **authorized penetration testing and educational purposes only**. Using this tool against targets without prior written consent is illegal and unethical. The developers assume no liability for misuse. Always follow the [Computer Fraud and Abuse Act (CFAA)](https://en.wikipedia.org/wiki/Computer_Fraud_and_abuse_act) and equivalent local laws.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

**Developed with ❤️ by Subrat**
