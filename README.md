# <p align="center">Shadow-Flow</p>

<p align="center">
  <img src="https://img.shields.io/github/license/subrat243/Shadow-Flow?style=for-the-badge&color=blue" alt="License">
  <img src="https://img.shields.io/github/v/release/subrat243/Shadow-Flow?style=for-the-badge&color=green" alt="Version">
  <img src="https://img.shields.io/github/issues/subrat243/Shadow-Flow?style=for-the-badge&color=orange" alt="Issues">
  <img src="https://img.shields.io/github/stars/subrat243/Shadow-Flow?style=for-the-badge&color=yellow" alt="Stars">
</p>

<p align="center">
  <strong>Advanced Automated Penetration Testing & Vulnerability Research Toolkit</strong>
</p>

---

## ⚡ Overview

**Shadow-Flow** is a comprehensive, state-of-the-art cybersecurity suite designed for automated security assessments and deep-vulnerability research. From intelligent reconnaissance to advanced exploitation, Shadow-Flow streamlines the security testing workflow for professionals and researchers.

> [!IMPORTANT]
> This tool is designed for educational purposes and authorized security testing only. Always obtain proper permission before testing any system or network.

---

## 🚀 Key Features

<details>
<summary><b>🔍 1. Information Gathering</b></summary>

*   **DNS Enumeration**: Subdomains, DNS records, and zone transfers.
*   **Port Scanning**: Protocol-level service discovery.
*   **Technology Detection**: Framework, CMS, and web-server fingerprinting.
*   **Directory Enumeration**: Intelligent discovery of hidden paths and sensitive files.
*   **SSL/TLS Analysis**: Configuration and certificate validation.
*   **Metadata Extraction**: Deep file analysis for sensitive data leaks.
</details>

<details>
<summary><b>🛡️ 2. Vulnerability Scanning</b></summary>

*   **SQL Injection**: Union-based, Error-based, Time-based, and Boolean testing.
*   **XSS**: Reflected, Stored, DOM-based, and Template injection checks.
*   **Security Misconfigurations**: Default credentials, exposed `.env`, and insecure headers.
*   **Modern Vuls**: SSRF, XXE, and Template Injection detection.
</details>

<details>
<summary><b>💥 3. Exploitation & Post-Exploitation</b></summary>

*   **Automated Exploits**: SQLi data extraction, XSS cookie theft, and command execution.
*   **File Inclusion**: LFI/RFI and PHP wrapper exploitation.
*   **Persistence**: Backdoor placement and credential harvesting logic.
*   **Privilege Escalation**: Kernel exploit detection and misconfiguration checks.
</details>

<details>
<summary><b>📊 4. Reporting</b></summary>

*   **Professional HTML Reports**: Interactive, executive-style findings.
*   **JSON Data Export**: Integration-ready formats for dev teams.
*   **Historical Tracking**: Track scan progress and resolution over time.
</details>

---

## 🛠️ Installation

### Quick Start (System-wide)

```bash
# Clone the repository
git clone https://github.com/subrat243/Shadow-Flow.git
cd Shadow-Flow

# Install dependencies
pip install -r requirements.txt

# Install globally
sudo chmod +x install.sh
sudo ./install.sh
```

---

## 💻 Usage

Shadow-Flow can be used via the **Interactive Shell** or **Command Line Interface**.

### Interactive Mode
```bash
pentest
```

### CLI Mode
```bash
# Full vulnerability scan
pentest -t https://example.com -m scan

# Silent information gathering
pentest -t 192.168.1.1 -m info -v

# List demo targets
pentest -d
```

### Options:
| Flag | Description |
| --- | --- |
| `-t, --target` | Target URL or IP address |
| `-m, --mode` | Mode: `info`, `scan`, `manual`, `exploit`, `post`, `report` |
| `-v, --verbose` | Enable verbose debugging output |
| `-d, --demo` | List available safe demo targets |

---

## 🛡️ Security Notice

> [!CAUTION]
> **Your Identity Matters**: This tool makes direct HTTP requests. To stay anonymous and secure:
> *   Use a **VPN** or **Proxy**.
> *   Route traffic through **Tor**.
> *   Use a dedicated testing environment.

---

## 🤝 Contributing

Contributions are what make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/subrat243">subrat243</a>
</p>
