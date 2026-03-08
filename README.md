<img width="1278" height="722" alt="CredAudit Banner Image" src="https://github.com/user-attachments/assets/58e5e460-4077-4c98-a888-a3e587d6f2a5" />

# 🔐 CredAudit — Automated Windows Credential Audit Tool

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Kali%20%7C%20macOS-lightgrey?style=flat-square)]()
[![Security](https://img.shields.io/badge/Purpose-Defensive%20Security-red?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-2.0.0-brightgreen?style=flat-square)]()
[![Hashcat](https://img.shields.io/badge/Engine-Hashcat%20%7C%20Python-orange?style=flat-square)]()

> **CredAudit** is a fully automated Python CLI tool for auditing Windows local account password strength through NTLM hash extraction and dictionary attack analysis. Built for penetration testers, security auditors, and system administrators.

**No manual commands. No complex setup. Just drop your SAM + SYSTEM files and run one script.**

---

## 📋 Table of Contents

- [What is CredAudit?](#-what-is-credaudit)
- [How It Works](#-how-it-works)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Exporting SAM + SYSTEM from Windows](#-exporting-sam--system-from-windows)
- [Transferring Files to Kali / Linux](#-transferring-files-to-kali--linux)
- [Running the Tool](#-running-the-tool)
- [CLI Options Reference](#-cli-options-reference)
- [Output Reports](#-output-reports)
- [Cross-Platform Support](#-cross-platform-support)
- [Important Notes](#-important-notes)
- [Ethical Use Disclaimer](#-ethical-use-disclaimer)
- [License](#-license)

---

## 🔍 What is CredAudit?

**CredAudit** automates the Windows credential auditing process that security professionals perform manually during penetration tests and security assessments.

In a real pentest scenario, auditors need to:
1. Export SAM and SYSTEM registry hives from a Windows machine
2. Extract NTLM password hashes
3. Run dictionary attacks to identify weak passwords
4. Document findings in a security report

**CredAudit automates all of these steps in one command.**

### Use Cases

- **Penetration Testing** — Audit Windows local account password strength during authorized engagements
- **Security Assessments** — Identify weak passwords on corporate workstations and servers
- **Lab Practice** — Learn NTLM hash extraction and password cracking in a controlled environment
- **Security Awareness** — Demonstrate password weakness risks to clients and stakeholders

### What CredAudit Can Audit

| Account Type | Supported | Notes |
|-------------|-----------|-------|
| Local accounts | ✅ Yes | Full hash extraction and cracking |
| Built-in accounts (Administrator, Guest) | ✅ Yes | Detects empty/default passwords |
| Service accounts | ✅ Yes | Classified and risk-flagged |
| Domain accounts (on domain-joined machines) | ✅ Yes | Cached credentials in SAM |
| Microsoft accounts (personal laptops) | ⚠️ Partial | Hash extracted but may not be crackable |

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER WORKFLOW                              │
│                                                                 │
│  STEP 1 — On the Windows target machine (as Administrator):     │
│     reg save HKLM\SAM    C:\Users\Public\SAM                    │
│     reg save HKLM\SYSTEM C:\Users\Public\SYSTEM                 │
│                                                                 │
│  STEP 2 — Transfer SAM + SYSTEM to your audit machine           │
│           and drop them into the  input/  folder                │
│                                                                 │
│  STEP 3 — Run the launcher:                                     │
│     ./run_audit.sh          (Linux / Kali / macOS)              │
│     run_audit.bat           (Windows CMD)                       │
│     .\run_audit.ps1         (Windows PowerShell)                │
│                                                                 │
│  STEP 4 — Follow the guided prompts                             │
│           (wordlist selection, report format)                   │
│                                                                 │
│  STEP 5 — Reports saved to  reports/  folder  ✅                │
└─────────────────────────────────────────────────────────────────┘
```

### Internal Pipeline

```
input/SAM + input/SYSTEM
         │
         ▼
  [1/4] Extract NTLM hashes
        └─ Boot key from SYSTEM hive
        └─ Decrypt SAM with Impacket LocalOperations
        └─ Output: username, RID, LM hash, NTLM hash
         │
         ▼
  [2/4] Parse account records
        └─ Classify account types (Admin, Guest, Standard, Service)
        └─ Detect empty passwords, LM hash storage, disabled accounts
        └─ Apply risk flags (default RIDs, high-privilege accounts)
         │
         ▼
  [3/4] Dictionary attack
        └─ Primary: Hashcat mode 1000 (NTLM) — GPU/CPU accelerated
        └─ Fallback: Python MD4 engine — no dependencies needed
        └─ Uses any wordlist (recommended: rockyou.txt)
         │
         ▼
  [4/4] Generate audit report
        └─ TXT  — Plain text, suitable for documentation
        └─ JSON — Machine-readable, SIEM-ready
        └─ HTML — Visual report with charts and severity colors
```

---

## ✨ Features

- 🎬 **Animated startup** — Letter-by-letter banner animation on launch
- 🤖 **Fully guided** — Interactive setup shows exact commands to run
- 🔑 **Automatic hash extraction** — No manual secretsdump or mimikatz needed
- ⚡ **Hashcat integration** — GPU-accelerated cracking using mode 1000 (NTLM)
- 🐍 **Python fallback engine** — Works even without Hashcat installed
- 📊 **Three report formats** — TXT, JSON, and HTML in one run
- 🌍 **Cross-platform** — Works on Kali Linux, Ubuntu, macOS, and Windows
- 🎨 **Color-coded terminal output** — Clear visual feedback throughout
- 🚩 **Risk flagging** — Detects high-value targets, empty passwords, LM hash storage
- 📁 **Rotating log files** — Full audit trail saved to `logs/`
- 🔒 **Safe by default** — `.gitignore` blocks SAM/SYSTEM files from being committed

---

## 📁 Project Structure

```
credential-audit-tool/
│
├── main.py                    ← CLI entry point — auto + guided + manual modes
├── run_audit.sh               ← One-click launcher for Linux / Kali / macOS
├── run_audit.bat              ← One-click launcher for Windows CMD
├── run_audit.ps1              ← One-click launcher for Windows PowerShell
├── requirements.txt           ← Python dependencies
├── README.md
├── LICENSE                    ← MIT License
├── .gitignore                 ← Blocks SAM/SYSTEM/hive files from git
│
├── modules/
│   ├── hash_extractor.py      ← SAM + SYSTEM hive parsing, NTLM extraction
│   ├── hash_parser.py         ← Account enrichment, risk flags, LM detection
│   ├── password_cracker.py    ← Hashcat (mode 1000) + Python MD4 fallback
│   ├── report_generator.py    ← TXT / JSON / HTML report generation
│   └── logger.py              ← Colored console + rotating file logger
│
├── input/                     ← ⬅ DROP YOUR SAM + SYSTEM FILES HERE
│   └── README.md
│
├── wordlists/
│   └── example_wordlist.txt   ← Bundled demo wordlist (limited)
│
├── reports/                   ← Generated audit reports saved here
└── logs/                      ← Audit session logs saved here
```

---

## 📦 Requirements

| Component | Requirement |
|-----------|-------------|
| Python | 3.8 or higher |
| OS | Kali Linux, Ubuntu, Debian, macOS, Windows |
| Hashcat | Optional — falls back to Python engine |
| RAM | 512 MB minimum |
| Disk | 200 MB (plus wordlist size) |

### Python Dependencies

```
impacket>=0.11.0       # SAM/SYSTEM hive parsing and NTLM extraction
pycryptodome>=3.18.0   # Cryptographic operations for hash decryption
python-registry>=1.4   # Windows registry hive file reading
```

---

## 🚀 Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/yourusername/CredAudit.git
cd CredAudit
```

### Step 2 — Install Python Dependencies

```bash
# Standard install
pip install -r requirements.txt

# On Kali Linux (if you get externally-managed error)
pip install -r requirements.txt --break-system-packages

# Or using virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3 — Install Hashcat (Optional but Recommended)

```bash
# Kali Linux / Ubuntu / Debian
sudo apt update && sudo apt install hashcat

# macOS
brew install hashcat

# Windows — Download from https://hashcat.net/hashcat/
```

### Step 4 — Make Launcher Executable (Linux/macOS)

```bash
chmod +x run_audit.sh
```

---

## 🪟 Exporting SAM + SYSTEM from Windows

Open **Command Prompt as Administrator** and run:

```cmd
reg save HKLM\SAM    C:\Users\Public\SAM    /y
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM /y
```

You should see:
```
The operation completed successfully.
The operation completed successfully.
```

> ⚠️ **Note:** Must be run as Administrator. Right-click CMD → **Run as Administrator**.

---

## 📤 Transferring Files to Kali / Linux

### Method 1 — Python HTTP Server (Recommended)

**On the Windows machine:**
```cmd
cd C:\Users\Public
python -m http.server 8888
```

**On Kali / Linux:**
```bash
wget http://<windows-ip>:8888/SAM    -O input/SAM
wget http://<windows-ip>:8888/SYSTEM -O input/SYSTEM
```

### Method 2 — SCP

```bash
scp user@<windows-ip>:"C:/Users/Public/SAM"    ./input/SAM
scp user@<windows-ip>:"C:/Users/Public/SYSTEM" ./input/SYSTEM
```

### Verify

```bash
ls input/
# Should show: README.md  SAM  SYSTEM
```

---

## ▶️ Running the Tool

### Auto Mode — Recommended

```bash
./run_audit.sh          # Linux / Kali / macOS
run_audit.bat           # Windows CMD
.\run_audit.ps1         # Windows PowerShell
```

### Manual Mode

```bash
# Basic
python3 main.py --sam input/SAM --system input/SYSTEM

# With rockyou.txt wordlist and all report formats
python3 main.py --sam input/SAM --system input/SYSTEM \
                --wordlist /usr/share/wordlists/rockyou.txt \
                --format all

# Force Python engine (no Hashcat needed)
python3 main.py --sam input/SAM --system input/SYSTEM --cracker python

# Verbose debug output
python3 main.py --auto --verbose
```

---

## 🎛️ CLI Options Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--auto` | — | Launch guided interactive mode (recommended) |
| `--sam FILE` | — | Path to SAM hive file |
| `--system FILE` | — | Path to SYSTEM hive file |
| `--wordlist FILE` | `wordlists/example_wordlist.txt` | Wordlist for dictionary attack |
| `--format` | `all` | Report format: `txt` / `json` / `html` / `all` |
| `--output DIR` | `reports/` | Directory to save reports |
| `--cracker` | `auto` | Engine: `hashcat` / `python` / `auto` |
| `--hashcat-path` | `hashcat` | Custom path to Hashcat binary |
| `--skip-disabled` | off | Skip disabled accounts |
| `--no-color` | off | Disable ANSI color output |
| `--verbose` / `-v` | off | Enable debug logging |
| `--log-file FILE` | `logs/audit.log` | Custom log file path |

---

## 📄 Output Reports

### 📊 HTML Report
Visual browser-based report with severity-colored table, donut chart, bar chart, risk flags, and remediation recommendations.

```bash
xdg-open reports/audit_report_<timestamp>.html     # Linux / Kali
open reports/audit_report_<timestamp>.html          # macOS
start reports\audit_report_<timestamp>.html         # Windows
```

### 🗂️ JSON Report
Machine-readable output for SIEM integration or custom scripting.

### 📝 TXT Report
Plain text report for email, documentation, or terminal review.

---

## 🌍 Cross-Platform Support

| Platform | Launcher | Hashcat Install | Status |
|----------|----------|-----------------|--------|
| Kali Linux | `./run_audit.sh` | `sudo apt install hashcat` | ✅ Fully tested |
| Ubuntu / Debian | `./run_audit.sh` | `sudo apt install hashcat` | ✅ Supported |
| macOS | `./run_audit.sh` | `brew install hashcat` | ✅ Supported |
| Windows CMD | `run_audit.bat` | hashcat.net | ✅ Supported |
| Windows PowerShell | `.\run_audit.ps1` | hashcat.net | ✅ Supported |

---

## ⚠️ Important Notes

### Use your own wordlists or rockyou.txt for Real Auditing

The bundled example wordlist is for demo only. For real auditing use your own wordlists or rockyou.txt:

```bash
# Unzip on Kali if needed
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Then use in tool
/usr/share/wordlists/rockyou.txt
```

### Microsoft Accounts

If the target uses a Microsoft account (Gmail, Outlook etc.), 
the SAM file contains cached credentials that cannot be cracked 
with a wordlist. This tool is designed for **local accounts** 
— standard in corporate environments.

### File Safety

The `.gitignore` automatically blocks SAM, SYSTEM, and hive files from Git. **Never commit real SAM/SYSTEM files to any repository.**

---

## 🛡️ Ethical Use Disclaimer

> **This tool is provided strictly for authorized security auditing, penetration testing, and cybersecurity education.**
>
> ✅ **Permitted:** Systems you own, systems with explicit written authorization, controlled lab environments.
>
> ❌ **Prohibited:** Any unauthorized access to systems you do not own or have permission to test.
>
> Unauthorized use is illegal under the **CFAA**, **UK Computer Misuse Act**, **IT Act (India)**, and equivalent laws worldwide. The authors accept no responsibility for unauthorized or illegal use.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for full terms.

---

## 👤 Author

CredAudit is a practical open-source security tool developed for penetration testers, security auditors, and system administrators to extract, crack, and analyze Windows local account password strength in authorized environments.

---

*⭐ If you found this useful, consider giving it a star on GitHub!*
