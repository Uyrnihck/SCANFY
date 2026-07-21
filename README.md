# SCANFY
SCANFY — A pure-Python terminal tool that scans your local Wi-Fi/LAN and reveals every connected device: IP, MAC address, vendor and hostname. Zero dependencies, green Minecraft-grass ASCII banner, and an interactive menu — you launch it, then trigger the scan yourself.

# SCANFY

```
 ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗   ██╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚██╗ ██╔╝
 ███████╗██║     ███████║██╔██╗ ██║█████╗   ╚████╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝    ╚██╔╝
 ███████║╚██████╗██║  ██║██║ ╚████║██║        ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝        ╚═╝
     advanced local network scanner  ::  v2.0
```

**SCANFY** is a terminal-based **advanced** local network scanner written in
pure Python. It discovers every device on your Wi-Fi / LAN and enriches each one
with a full profile: **IP, MAC, vendor, hostname, NetBIOS name, latency, OS
fingerprint, open ports/services and an inferred device type** — then exports a
polished report in **HTML, JSON, CSV or TXT**.

Runs with **zero external dependencies** (Python standard library only) and an
**interactive menu**: you open the tool first, then trigger the scan yourself —
it never starts scanning automatically. Green "Minecraft grass" ASCII banner
included. 🌱

---

## Features

### Discovery
- 📶 **Automatic network detection** — local IP, subnet (`/24`), gateway and DNS servers.
- 🔎 **Parallel ping sweep** (up to 128 threads) with a live progress bar.
- 🧾 **ARP table reading** to map IP → MAC (catches hosts that block ping).
- 🧹 **Noise filtering** — hides broadcast and multicast automatically.

### Deep scan (per device)
- 🔌 **Port scanning** across ~50 common ports with **service names** (HTTP, SSH, RDP, SMB, MQTT, RTSP, JetDirect/printer, iPhone-sync, Plex…).
- 🖥️ **OS fingerprint** from the TTL (Windows / Linux-Unix-macOS-Android / network device).
- ⏱️ **Latency** measurement per host (ms).
- 🏷️ **Vendor lookup** from the MAC prefix (OUI) — 100+ built-in prefixes, plus optional full IEEE `oui.txt` support.
- 🪟 **NetBIOS name** resolution (Windows, via `nbtstat`).
- 🧠 **Device-type inference** — Router, Printer, iPhone/iPad, Raspberry Pi, IoT/ESP, Smart-home, Windows PC/Server, Linux server, IP camera, and more.

### Reporting
- 📊 **On-screen advanced report** — detailed per-device cards + a statistics summary (counts by device type and by service).
- 💾 **Export** the last scan to **HTML** (styled, dark green theme), **JSON**, **CSV** or **TXT** — timestamped files saved next to the script.
- 🚩 Highlights which entry is **you** and which is the **router**.
- 🪟🐧 Works on **Windows and Linux**.

---

## Requirements

- **Python 3.7+**
- No pip packages required — everything uses the standard library.
- A terminal that supports ANSI truecolor (Windows Terminal, most modern
  terminals). On Windows, ANSI support is enabled automatically.

*(Optional)* Drop an IEEE-format `oui.txt` next to `scanfy.py` and SCANFY will
load the **full vendor database** at startup for far more accurate manufacturer
identification.

---

## Installation

Just download `scanfy.py`. There is nothing to install.

```bash
cd path/to/scanfy
python scanfy.py     # or: python3 scanfy.py
```

---

## Usage

You will see the banner, your network information, and a menu:

```
  [1] Quick scan    ping + ARP + vendor + hostname
  [2] Deep scan     + ports + OS + NetBIOS + device type   (recommended)
  [3] Single host   deep scan one IP
  [4] ARP table     instant, no sweep
  [5] Export report HTML / JSON / CSV / TXT
  [0] Exit
```

- **[1] Quick scan** — fast overview: live hosts with MAC, vendor and hostname.
- **[2] Deep scan** — full profile of every device (ports, OS, NetBIOS, type, latency) + statistics summary.
- **[3] Single host** — run the full deep profile against one IP you type in.
- **[4] ARP table** — instant snapshot of devices already known to your system.
- **[5] Export report** — save the most recent scan as HTML / JSON / CSV / TXT.
- **[0] Exit**.

### Example (deep scan card)

```
  ● 192.168.3.1 (router)
    MAC       : f0:fa:c7:3f:dc:20  (TP-Link)
    Hostname  : router.local
    NetBIOS   : -
    Type      : Router / Gateway
    OS guess  : Linux/Unix/macOS/Android (TTL 64)
    Latency   : 2 ms
    Open ports: 53/DNS, 80/HTTP, 443/HTTPS

  Summary
    Devices found: 5
    By type      : Apple device x2, Router / Gateway x1, IoT device (ESP) x1, ...
    Open services: HTTP x3, HTTPS x2, SSH x1, ...
```

---

## How it works

1. Opens a UDP socket to a public IP to learn the **local IP**, then assumes a **/24** subnet.
2. Reads the **gateway** and **DNS servers** from `ipconfig` (Windows) / `ip route` + `resolv.conf` (Linux).
3. Runs a **parallel ping sweep** to find live devices, capturing **TTL** and **latency** from each reply.
4. Reads the system **ARP table** (`arp -a`) to attach **MAC addresses**.
5. **Deep scan only:** connects to common **ports** to map open services, guesses the **OS** from the TTL, queries **NetBIOS**, matches the **MAC prefix** to a vendor, and **infers the device type**.
6. Renders an on-screen report and can **export** it to HTML/JSON/CSV/TXT.

---

## A note about "users"

On a normal Wi-Fi network you **cannot see the login/username** of other
people's devices — that information stays inside each device and never travels
across the network. What SCANFY *can* reveal is the **IP, MAC address, vendor,
hostname, NetBIOS name, open services and device type**, which is usually enough
to tell exactly what a device is (e.g. `Galaxy-S23`, `Joao-iPhone`, `esp32-sensor`).

---

## Legal & ethical use

> ⚠️ Use SCANFY **only on your own network** or on networks you are explicitly
> authorized to test. Port scanning and probing networks you do not own or have
> permission to assess may be **illegal** in your country. The author is not
> responsible for misuse. This tool is intended for learning, home network
> auditing, and authorized security testing only.

---

## License

Free to use, modify and share. Provided "as is", without warranty of any kind.

---

<p align="center"><b>Long live the Hackers of Brazil</b><br><i>Viva os Hacker do Brasil</i> 🇧🇷</p>

