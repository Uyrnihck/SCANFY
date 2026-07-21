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
        local network scanner  ::  v1.0
```

**SCANFY** is a terminal-based local network scanner written in pure Python.
It discovers the devices connected to the same Wi-Fi / LAN as your computer and
shows their **IP address**, **MAC address**, **vendor** and **hostname** in a
clean, colored table — all with a green "Minecraft grass" ASCII banner.

It runs **without any external dependencies** (Python standard library only) and
uses an **interactive menu**: you open the tool first, then trigger the scan
yourself — it does not start scanning automatically.

---

## Features

- 🌱 **Green ASCII banner** with a grass-like gradient.
- 📶 **Automatic network detection** — finds your local IP, subnet (`/24`) and gateway.
- 🔎 **Parallel ping sweep** across the whole subnet with a live progress bar.
- 🧾 **ARP table reading** to map IP → MAC address.
- 🏷️ **Offline vendor lookup** from the MAC prefix (OUI) — identifies Apple,
  Samsung, TP-Link, Espressif/ESP, Raspberry Pi, Intel, and more.
- 🖥️ **Hostname resolution** via reverse DNS.
- 🧹 **Noise filtering** — automatically hides broadcast and multicast addresses.
- 🚩 Highlights which entry is **you** and which one is the **router**.
- ⚡ **Fast ARP-only mode** for an instant view without a full sweep.
- 🪟🐧 Works on **Windows and Linux**.

---

## Requirements

- **Python 3.7+**
- No pip packages required — everything uses the standard library.
- A terminal that supports ANSI truecolor (Windows Terminal, most modern
  terminals). On Windows, ANSI support is enabled automatically.

---

## Installation

Just download `scanfy.py`. There is nothing to install.

```bash
# clone or copy the file, then:
cd path/to/scanfy
```

---

## Usage

Run it from your terminal:

```bash
python scanfy.py
```

On some systems you may need `python3`:

```bash
python3 scanfy.py
```

You will see the banner, your network information, and a menu:

```
  [1] Start network scan
  [2] Show current ARP table (fast)
  [0] Exit
```

- **[1] Start network scan** — runs the full ping sweep, then reads the ARP
  table, resolves hostnames, and prints the results table.
- **[2] Show current ARP table (fast)** — instant snapshot of devices already
  known to your system, no sweep.
- **[0] Exit** — quit.

### Example output

```
  IP              MAC                VENDOR            HOSTNAME
  ──────────────────────────────────────────────────────────────────────────
  192.168.3.1     f0:fa:c7:3f:dc:20  TP-Link           router.local        (router)
  192.168.3.15    ac:de:48:11:22:33  Apple             Joao-iPhone
  192.168.3.42    18:fe:34:aa:bb:cc  Espressif (ESP)    esp32-sensor
  192.168.3.129   e0:b9:4d:44:55:66  Intel             my-notebook         (you)
```

---

## How it works

1. Opens a UDP socket to a public IP to learn which **local IP** your machine
   uses, then assumes a **/24** subnet.
2. Reads the **gateway** from `ipconfig` (Windows) or `ip route` (Linux).
3. Runs a **parallel ping sweep** (up to 100 threads) across every host in the
   subnet to find live devices.
4. Reads the system **ARP table** (`arp -a`) to attach MAC addresses.
5. Resolves **hostnames** via reverse DNS and matches the **MAC prefix** against
   a built-in vendor table.
6. Filters out broadcast/multicast noise and prints a sorted, colored table.

---

## A note about "users"

On a normal Wi-Fi network you **cannot see the login/username** of other
people's devices — that information stays inside each device and never travels
across the network. What SCANFY *can* reveal is the **IP, MAC address, vendor
and hostname** of each connected device, which is usually enough to tell what a
device is (e.g. `Galaxy-S23`, `Joao-iPhone`, `esp32-sensor`).

---

## Legal & ethical use

> ⚠️ Use SCANFY **only on your own network** or on networks you are explicitly
> authorized to test. Scanning networks you do not own or have permission to
> assess may be **illegal** in your country. The author is not responsible for
> misuse. This tool is intended for learning, home network auditing, and
> authorized security testing only.

---

## License

Free to use, modify and share. Provided "as is", without warranty of any kind.

---

<p align="center"><b>Long live the Hackers of Brazil</b><br><i>Viva os Hacker do Brasil</i> 🇧🇷</p>
