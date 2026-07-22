# SCANFY
SCANFY — A pure-Python terminal tool that scans your local Wi-Fi/LAN and reveals every connected device: IP, MAC address, vendor and hostname. Zero dependencies, green Minecraft-grass ASCII banner, and an interactive menu — you launch it, then trigger the scan yourself.

<div align="center">

```
 ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗   ██╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚██╗ ██╔╝
 ███████╗██║     ███████║██╔██╗ ██║█████╗   ╚████╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝    ╚██╔╝
 ███████║╚██████╗██║  ██║██║ ╚████║██║        ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝        ╚═╝
```

### 🌿 Advanced Network Scanner · Service Fingerprinter · Security Dossier

**SCANFY** discovers every device on your Wi-Fi/LAN, fingerprints its services,
classifies it, analyzes its security posture and generates a **complete,
beautiful reconnaissance dossier** — all from a single Python file.

![Python](https://img.shields.io/badge/Python-3.8%2B-6abe30?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/OS-Windows%20%7C%20Linux-4e9120?style=for-the-badge)
![Single File](https://img.shields.io/badge/Single%20File-8.4k%20lines-3fa7a0?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-96dc5a?style=for-the-badge)
![Made in](https://img.shields.io/badge/Made%20in-Brazil%20%F0%9F%87%A7%F0%9F%87%B7-e6c85a?style=for-the-badge)

</div>

---

## ⚡ Get started in 30 seconds

```bash
# 1) Clone the repository
git clone https://github.com/Uyrnihck/SCANFY.git

# 2) Enter the folder
cd SCANFY

# 3) Install the dependencies
pip install -r requirements_scanfy.txt

# 4) Run it
python scanfy.py
```

> 💡 On some systems use `python3` instead of `python`.
> Only `rich` is strictly required — everything else unlocks more power and
> degrades gracefully when missing.

---

## 📑 Table of contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Scan profiles](#-scan-profiles)
- [The dossier](#-the-dossier)
- [Dependencies](#-dependencies)
- [How it works](#-how-it-works)
- [FAQ](#-faq)
- [Legal & ethical use](#-legal--ethical-use)
- [License](#-license)

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Multi-method discovery
- ICMP ping sweep (TTL + latency)
- TCP "ping" (finds ICMP-blocking hosts)
- ARP table **+ optional layer-2 ARP** (scapy)
- **mDNS / Bonjour** (zeroconf)
- **SSDP / UPnP** device descriptions
- **WS-Discovery** (printers / ONVIF cameras)
- NetBIOS names & UDP service probes

</td>
<td width="50%" valign="top">

### 🧬 Deep per-device research
- Port scan (top-100 → full range)
- Banner grabbing + product/version parsing
- Active probes: **FTP, SMTP, MySQL, Redis,
  Memcached, RTSP, RDP, VNC, MQTT**
- Dedicated **HTTP/HTTPS, TLS cert, SSH,
  SNMP, SMB, DNS** fingerprinters
- OS fingerprint (TTL + banners + nmap)

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🏷️ Identity & classification
- Full **IEEE OUI** vendor database
- Reverse DNS · NetBIOS · mDNS · UPnP names
- Scoring-based device classifier:
  router, camera, printer, NAS, phone,
  IoT/ESP, smart speaker, PC, VM, BMC…
- MAC-randomization aware

</td>
<td width="50%" valign="top">

### 🛡️ Security analysis
- Exposed-service & legacy-protocol rules
- TLS weakness & missing-header checks
- **No-auth / default-credential** detection
  (Redis, Memcached, anon FTP, open MQTT…)
- **CVE hint** correlation
- Per-device **risk score** + network
  **scorecard** & remediation plan

</td>
</tr>
</table>

### 📊 Complete dossier & history
- Self-contained **HTML** dossier: risk gauge, SVG charts, security scorecard,
  findings register, topology overview, inventory and a **per-device card**.
- Also exports **PDF · Markdown · JSON · CSV · XML · TXT**.
- **SQLite history** + diff (new/gone/changed devices) and a **monitor mode**
  that alerts when devices join or leave the network.

---

## 📦 Installation

```bash
git clone https://github.com/Uyrnihck/SCANFY.git
cd SCANFY
pip install -r requirements_scanfy.txt
```

**Requirements:** Python **3.8+**. Works on **Windows** and **Linux**.
SCANFY is a single self-contained file (`scanfy.py`) — nothing else to build.

<details>
<summary><b>🔧 Optional power-ups (click to expand)</b></summary>

<br>

| Extra                     | Unlocks                                       | Notes |
|---------------------------|-----------------------------------------------|-------|
| `scapy` + **Npcap**       | Layer-2 ARP scan discovery                    | Npcap is a driver, install separately on Windows |
| `python-nmap` + **nmap**  | nmap service/OS detection (single host)       | needs the `nmap` binary on PATH |

Everything in `requirements_scanfy.txt` is pip-installable. The startup screen
shows an **Engine** line listing which capabilities are active.

</details>

---

## 🚀 Usage

### Interactive menu
```bash
python scanfy.py
```
```
  [1] Quick scan       discovery + identity (fast)
  [2] Deep scan        ports · OS · HTTP/TLS · findings   (recommended)
  [3] Thorough scan    all ports · UDP · nmap (if present) · traceroute
  [4] Single host      deep-scan one IP
  [5] ARP table        instant snapshot
  [6] Export dossier   HTML · MD · JSON · CSV · XML · TXT · PDF
  [7] Scan history     compare with previous scans
  [8] Monitor mode     watch for new/leaving devices
  [9] Settings         profile · timeouts · output dir
  [0] Exit
```

### Headless CLI (automation / scheduled scans)
```bash
python scanfy.py -p deep -f all                      # deep scan → every format
python scanfy.py -t 192.168.0.1 -f html              # one host → HTML dossier
python scanfy.py -n 10.0.0.0/24 -p thorough -f pdf -o ./reports
python scanfy.py --update-oui                        # refresh vendor database
python scanfy.py --help
```

Dossiers are saved as `scanfy_dossier_YYYYMMDD_HHMMSS.<ext>`.

---

## 🎚️ Scan profiles

| Profile     | Ports        | UDP | HTTP/TLS | SNMP/SMB | mDNS/SSDP | Traceroute | nmap |
|-------------|--------------|:---:|:--------:|:--------:|:---------:|:----------:|:----:|
| `fast`      | top 100      | ❌  | ✅       | partial  | ✅        | ❌         | ❌   |
| `default`   | ~250 curated | ❌  | ✅       | ✅       | ✅        | ❌         | ❌   |
| `deep`      | ~250 curated | ✅  | ✅       | ✅       | ✅        | ✅         | ❌   |
| `thorough`  | full range   | ✅  | ✅       | ✅       | ✅        | ✅         | ✅   |

---

## 📄 The dossier

The HTML report is a full, offline, self-contained document:

- **Cover** — network, operator, gateway, DNS, methods, engine.
- **Executive summary** — risk gauge, severity bar, device-type donut, top-services bars.
- **Security scorecard** — posture grade, issues by category, prioritised remediation plan.
- **Findings register** — every issue with severity, host, service, CVEs and a fix.
- **Topology overview** — gateway/operator centre, hosts grouped by type.
- **Inventory** — every device with MAC, vendor, name, type, OS, risk and ports.
- **Per-device dossier cards** — identity, classification, open-port table, HTTP/TLS
  details, mDNS/UPnP data, tags and per-device findings.

---

## 🧩 Dependencies

| Library             | Purpose                                   | Fallback if missing |
|---------------------|-------------------------------------------|---------------------|
| `rich` *(required)* | terminal interface                        | won't start |
| `mac-vendor-lookup` | full offline IEEE OUI vendor DB           | small built-in table |
| `requests`          | HTTP/TLS-UI fingerprint, UPnP, public IP  | skipped |
| `psutil` / `ifaddr` | real subnet-mask / interface detection    | assumes /24 |
| `zeroconf`          | mDNS / Bonjour discovery                  | skipped |
| `dnspython`         | PTR / version.bind fingerprint            | stdlib reverse DNS |
| `cryptography`      | X.509 / TLS certificate parsing           | limited TLS info |
| `getmac`            | remote / local MAC resolution             | ARP-table only |
| `reportlab`         | **PDF** dossier                           | PDF skipped |
| `python-nmap`+`nmap`| service/OS detection (single host)        | built-in fingerprinting |
| `scapy` + `Npcap`   | layer-2 ARP scan                          | ICMP+TCP+ARP-table |

---

## ⚙️ How it works

```
environment ─▶ discovery ─▶ port scan ─▶ service fingerprint ─▶
classification ─▶ security analysis ─▶ topology ─▶ dossier
```

SCANFY ships as one file, but internally it is a full modular engine (67 modules,
~8,000 lines) bundled together. The readable modular source is preserved in
`scanfyx_source_backup.zip` — unzip it, edit the modules and run
`python build_bundle.py` to regenerate `scanfy.py`.

---

## ❓ FAQ

<details>
<summary><b>Can it show the usernames of other people's devices?</b></summary>

<br>

No. A login/username lives inside each device and never crosses the network.
SCANFY reveals the **IP, MAC, vendor, hostname/NetBIOS/mDNS name, OS, open
services, web/TLS banners and device type** — usually enough to identify exactly
what each device is (e.g. `Galaxy-S23`, `Joao-iPhone`, `esp32-sensor`).
</details>

<details>
<summary><b>Why do some devices show vendor "unknown" or "Private"?</b></summary>

<br>

Modern phones use **MAC address randomization** for privacy, so their MAC does
not map to a real manufacturer. SCANFY tags these devices accordingly — it's
expected behaviour, not a bug.
</details>

<details>
<summary><b>Does it need administrator/root privileges?</b></summary>

<br>

No. Core discovery and scanning use standard sockets and system tools. Only the
optional scapy layer-2 ARP scan needs Npcap (Windows) or root (Linux); without
it SCANFY automatically falls back to ICMP + TCP + ARP-table discovery.
</details>

---

## ⚠️ Legal & ethical use

> Use SCANFY **only on your own network** or one you are **explicitly authorized**
> to test. Port scanning and probing networks you do not own may be **illegal**
> in your country. This tool is intended for learning, home-network auditing and
> authorized security testing only. The author is not responsible for misuse.

---

## 📜 License

Released under the **MIT License** — free to use, modify and share.
Provided "as is", without warranty of any kind.

---

<div align="center">

### 🇧🇷 Long live the Hackers of Brazil
#### *Viva os Hackers do Brasil*

⭐ If SCANFY was useful, consider starring the repo!

[**github.com/Uyrnihck/SCANFY**](https://github.com/Uyrnihck/SCANFY)

</div>

