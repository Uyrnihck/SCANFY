#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCANFY - Advanced local network scanner (Wi-Fi/LAN)

Discovers devices on your network and enriches each one with:
IP, MAC, vendor (OUI), hostname, NetBIOS name, latency, OS fingerprint (TTL),
open ports/services and an inferred device type. Produces advanced reports
(HTML / JSON / CSV / TXT).

Legitimate use only: analyze YOUR OWN network, or one you are explicitly
authorized to test. No external dependencies - Python 3 standard library only.
"""

import concurrent.futures
import ctypes
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Colors (truecolor ANSI). "Minecraft grass" green ~ (106, 190, 48).
# ---------------------------------------------------------------------------
IS_WIN = platform.system().lower().startswith("win")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _enable_ansi_windows():
    """Enables ANSI escape-sequence processing in the Windows console."""
    if not IS_WIN:
        return
    try:
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GRASS = rgb(106, 190, 48)        # Minecraft grass green
GRASS_DARK = rgb(78, 145, 32)    # dark green (shadow)
GRASS_LIGHT = rgb(150, 220, 90)  # light green (highlight)
DIRT = rgb(150, 108, 74)         # brown dirt (accent)
WHITE = rgb(235, 235, 235)
GREY = rgb(140, 140, 140)
RED = rgb(220, 80, 80)
YELLOW = rgb(230, 200, 90)
CYAN = rgb(90, 200, 210)

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text):
    return ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------
BANNER = r"""
 ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗   ██╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚██╗ ██╔╝
 ███████╗██║     ███████║██╔██╗ ██║█████╗   ╚████╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝    ╚██╔╝
 ███████║╚██████╗██║  ██║██║ ╚████║██║        ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝        ╚═╝
"""

SUBTITLE = "     advanced local network scanner  ::  v2.0"


def clear():
    os.system("cls" if IS_WIN else "clear")


def print_banner():
    clear()
    lines = BANNER.strip("\n").split("\n")
    # green gradient per line to give it that grassy look
    shades = [GRASS_LIGHT, GRASS_LIGHT, GRASS, GRASS, GRASS_DARK, GRASS_DARK]
    for i, line in enumerate(lines):
        shade = shades[i] if i < len(shades) else GRASS
        print(shade + BOLD + line + RESET)
    print(DIRT + SUBTITLE + RESET)
    print(GREY + "  " + "─" * 52 + RESET)


# ---------------------------------------------------------------------------
# Network discovery
# ---------------------------------------------------------------------------
def get_local_ip():
    """Finds the local IP used to reach the network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_network(local_ip):
    """Assumes a /24 (255.255.255.0), the most common home-network mask."""
    return ipaddress.ip_network(local_ip + "/24", strict=False)


def get_gateway():
    """Tries to discover the gateway (router) from the routing table."""
    try:
        if IS_WIN:
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True,
                encoding="cp850", errors="ignore"
            ).stdout
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if "Gateway" not in line:
                    continue
                # The IPv4 address may be on the label line itself or on the
                # continuation line just below it (the one above is usually IPv6).
                for cand in [line] + lines[i + 1:i + 3]:
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", cand)
                    if m and m.group(1) != "0.0.0.0":
                        return m.group(1)
        else:
            out = subprocess.run(
                ["ip", "route"], capture_output=True, text=True
            ).stdout
            m = re.search(r"default via ([\d.]+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def get_dns_servers():
    """Best-effort list of configured DNS servers."""
    servers = []
    try:
        if IS_WIN:
            out = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True,
                encoding="cp850", errors="ignore"
            ).stdout
            capture = False
            for line in out.splitlines():
                if re.search(r"DNS", line) and ":" in line:
                    capture = True
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                    if m:
                        servers.append(m.group(1))
                    continue
                if capture:
                    m = re.match(r"\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$", line)
                    if m:
                        servers.append(m.group(1))
                    else:
                        capture = False
        else:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    m = re.match(r"nameserver\s+([\d.]+)", line)
                    if m:
                        servers.append(m.group(1))
    except Exception:
        pass
    # de-duplicate, keep order
    seen = set()
    return [s for s in servers if not (s in seen or seen.add(s))]


# ---------------------------------------------------------------------------
# Ping sweep (rich: TTL + latency)
# ---------------------------------------------------------------------------
def ping_host(ip):
    """Pings a host once. Returns {ip, ttl, latency} if alive, else None."""
    ip = str(ip)
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "600", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="cp850" if IS_WIN else "utf-8", errors="ignore"
        )
        out = r.stdout
        if r.returncode != 0:
            return None
        # On Windows an unreachable destination may still return 0, so we
        # confirm there was an actual reply (TTL present in the output).
        ttl_m = re.search(r"ttl[=\s]*(\d+)", out, re.IGNORECASE)
        if IS_WIN and not ttl_m:
            return None
        # Latency handles both English ("time") and Portuguese ("tempo").
        lat_m = re.search(r"(?:time|tempo)[=<]\s*([\d.]+)\s*ms", out, re.IGNORECASE)
        return {
            "ip": ip,
            "ttl": int(ttl_m.group(1)) if ttl_m else None,
            "latency": float(lat_m.group(1)) if lat_m else None,
        }
    except Exception:
        return None


def ping_sweep(network, progress_cb=None):
    """Pings every host in the network in parallel. Returns list of dicts."""
    hosts = list(network.hosts())
    alive = []
    total = len(hosts)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
        futures = {ex.submit(ping_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            res = fut.result()
            if res:
                alive.append(res)
    return alive


def guess_os(ttl):
    """Heuristic OS family from the observed TTL (LAN => few hops)."""
    if ttl is None:
        return "-"
    if ttl <= 64:
        return f"Linux/Unix/macOS/Android (TTL {ttl})"
    if ttl <= 128:
        return f"Windows (TTL {ttl})"
    return f"Network device (TTL {ttl})"


# ---------------------------------------------------------------------------
# ARP (MAC address), hostname, NetBIOS
# ---------------------------------------------------------------------------
def get_arp_table():
    """Reads the system ARP table -> {ip: mac}."""
    table = {}
    try:
        if IS_WIN:
            out = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True,
                encoding="cp850", errors="ignore"
            ).stdout
            for line in out.splitlines():
                m = re.search(
                    r"([\d.]+)\s+([\da-fA-F]{2}(?:[-:][\da-fA-F]{2}){5})", line)
                if m:
                    table[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            out = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True
            ).stdout
            for line in out.splitlines():
                m = re.search(r"\(([\d.]+)\)\s+at\s+([\da-fA-F:]{17})", line)
                if m:
                    table[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return table


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


def netbios_name(ip):
    """Windows NetBIOS name via nbtstat (the <00> UNIQUE workstation entry)."""
    if not IS_WIN:
        return "-"
    try:
        r = subprocess.run(
            ["nbtstat", "-A", ip], capture_output=True, text=True,
            encoding="cp850", errors="ignore", timeout=3
        )
        for line in r.stdout.splitlines():
            m = re.match(r"\s*([^\s<]+)\s+<00>\s+UNIQUE", line)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return "-"


# ---------------------------------------------------------------------------
# Vendor lookup (OUI). Built-in table + optional external oui.txt.
# ---------------------------------------------------------------------------
OUI = {
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f4:f5:e8": "Google",
    "94:eb:2c": "Google", "d8:eb:97": "TP-Link", "50:c7:bf": "TP-Link",
    "a4:2b:b0": "TP-Link", "00:1d:0f": "TP-Link", "b0:be:76": "TP-Link",
    "60:32:b1": "TP-Link", "cc:32:e5": "TP-Link",
    "fc:ec:da": "Ubiquiti", "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "e0:63:da": "Ubiquiti", "00:0c:29": "VMware", "00:50:56": "VMware",
    "00:05:69": "VMware", "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "ac:de:48": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "3c:07:54": "Apple", "d0:e1:40": "Apple", "bc:92:6b": "Apple",
    "f0:99:bf": "Apple", "90:72:40": "Apple", "a8:66:7f": "Apple",
    "68:96:7b": "Apple", "88:66:5a": "Apple", "dc:2b:2a": "Apple",
    "fc:fb:fb": "Cisco", "00:1b:54": "Cisco", "00:1a:a1": "Cisco",
    "00:24:14": "Cisco", "18:fe:34": "Espressif (ESP)", "24:0a:c4": "Espressif (ESP)",
    "a0:20:a6": "Espressif (ESP)", "50:02:91": "Espressif (ESP)",
    "24:6f:28": "Espressif (ESP)", "7c:9e:bd": "Espressif (ESP)",
    "c4:4f:33": "Espressif (ESP)", "84:cc:a8": "Espressif (ESP)",
    "00:12:fb": "Samsung", "5c:0a:5b": "Samsung", "78:1f:db": "Samsung",
    "8c:77:12": "Samsung", "34:23:87": "Samsung", "e8:50:8b": "Samsung",
    "00:24:e4": "Withings", "44:65:0d": "Amazon", "fc:65:de": "Amazon",
    "68:37:e9": "Amazon", "f0:81:73": "Amazon", "50:dc:e7": "Amazon",
    "f0:27:2d": "Xiaomi", "64:09:80": "Xiaomi", "28:6c:07": "Xiaomi",
    "c4:6a:b7": "Xiaomi", "78:11:dc": "Xiaomi", "50:8f:4c": "Xiaomi",
    "d4:6a:6a": "Netgear", "a0:40:a0": "Netgear", "9c:d3:6d": "Netgear",
    "e0:b9:4d": "Intel", "94:65:9c": "Intel", "34:41:5d": "Intel",
    "60:45:cb": "Intel", "a4:c3:f0": "Intel", "8c:16:45": "Intel",
    "00:15:5d": "Microsoft (Hyper-V)", "00:03:ff": "Microsoft",
    "7c:1e:52": "Microsoft", "b4:2e:99": "Giga-Byte", "d8:5e:d3": "ASUS",
    "2c:56:dc": "ASUS", "04:d4:c4": "ASUS", "1c:87:2c": "ASUS",
    "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    "d0:03:4b": "Apple", "70:ee:50": "Netatmo", "18:b4:30": "Nest",
    "64:16:66": "Nest", "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "b0:a7:37": "Roku", "cc:6d:a0": "Roku", "00:04:4b": "NVIDIA",
    "48:b0:2d": "NVIDIA", "e4:5f:01": "Raspberry Pi", "dc:44:6d": "Sonos",
    "94:9f:3e": "Sonos", "5c:aa:fd": "Sonos", "00:04:20": "Slim Devices",
    "00:1e:c0": "Microchip", "b8:d7:af": "Murata (WiFi module)",
}


def load_extra_oui():
    """Loads a full IEEE-style oui.txt (if present next to the script)."""
    path = os.path.join(SCRIPT_DIR, "oui.txt")
    if not os.path.isfile(path):
        return 0
    added = 0
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.match(
                    r"\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})"
                    r"\s+\(hex\)\s+(.+)", line)
                if m:
                    prefix = f"{m.group(1)}:{m.group(2)}:{m.group(3)}".lower()
                    OUI.setdefault(prefix, m.group(4).strip())
                    added += 1
    except Exception:
        pass
    return added


def lookup_vendor(mac):
    if not mac or mac == "-":
        return "-"
    return OUI.get(mac[:8].lower(), "unknown")


def is_real_device(ip, mac=""):
    """Filters out broadcast and multicast, which are not real devices."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or ip.endswith(".255"):
        return False
    mac = (mac or "").lower()
    if mac.startswith(("01:00:5e", "ff:ff:ff", "33:33")):
        return False
    return True


# ---------------------------------------------------------------------------
# Port scanning + service/device-type inference
# ---------------------------------------------------------------------------
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    515: "LPD-Printer", 548: "AFP", 554: "RTSP", 587: "SMTP", 631: "IPP-Printer",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1723: "PPTP", 1883: "MQTT",
    2323: "Telnet-alt", 3128: "Proxy", 3306: "MySQL", 3389: "RDP",
    5000: "UPnP/HTTP", 5060: "SIP", 5353: "mDNS", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 7000: "AirPlay", 8000: "HTTP-alt",
    8008: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8883: "MQTT-TLS",
    9000: "HTTP-alt", 9100: "JetDirect-Printer", 27017: "MongoDB",
    32400: "Plex", 49152: "UPnP", 62078: "iPhone-sync",
}


def check_port(ip, port, timeout=0.7):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def scan_ports_bulk(ips, ports, progress_cb=None):
    """Scans given ports on given IPs in parallel -> {ip: {port: service}}."""
    found = {ip: {} for ip in ips}
    tasks = [(ip, port) for ip in ips for port in ports]
    total = len(tasks)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=256) as ex:
        futs = {ex.submit(check_port, ip, port): (ip, port)
                for ip, port in tasks}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            ip, port = futs[fut]
            if fut.result():
                found[ip][port] = COMMON_PORTS.get(port, str(port))
    return found


def infer_device_type(dev, gateway):
    """Best-effort device category from ports + vendor + OS."""
    ports = set(dev.get("ports", {}).keys())
    vendor = (dev.get("vendor") or "").lower()
    os_guess = (dev.get("os") or "").lower()

    if gateway and dev["ip"] == gateway:
        return "Router / Gateway"
    if 62078 in ports:
        return "iPhone / iPad"
    if ports & {9100, 631, 515}:
        return "Printer"
    if 32400 in ports:
        return "Media server (Plex)"
    if "espressif" in vendor:
        return "IoT device (ESP)"
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if "philips hue" in vendor or "nest" in vendor or "sonos" in vendor \
            or "roku" in vendor or ports & {1883, 8883}:
        return "IoT / Smart-home"
    if 3389 in ports:
        return "Windows PC / Server"
    if ports & {445, 139}:
        return "Windows device"
    if 22 in ports and ports & {80, 443}:
        return "Linux server"
    if 22 in ports:
        return "Linux / Unix host"
    if 554 in ports:
        return "IP camera"
    if "apple" in vendor:
        return "Apple device"
    if any(v in vendor for v in ("samsung", "xiaomi", "google")):
        return "Phone / IoT"
    if any(v in vendor for v in ("tp-link", "netgear", "ubiquiti", "cisco", "asus")):
        return "Network device"
    if "windows" in os_guess:
        return "Windows device"
    if "linux" in os_guess:
        return "Linux / Unix host"
    return "Unknown"


# ---------------------------------------------------------------------------
# Scan result container
# ---------------------------------------------------------------------------
class ScanResult:
    def __init__(self, devices, meta):
        self.devices = devices          # list of device dicts
        self.meta = meta                # dict with scan metadata


LAST_RESULT = None  # most recent ScanResult, used by the export menu


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def progress_bar(done, total, width=40, label=""):
    frac = done / total if total else 1
    filled = int(width * frac)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(frac * 100)
    sys.stdout.write(
        f"\r  {label}{GRASS}{bar}{RESET} {WHITE}{pct:3d}%{RESET} "
        f"{GREY}({done}/{total}){RESET}   "
    )
    sys.stdout.flush()


def trunc(text, n):
    text = str(text)
    return text if len(text) <= n else text[:n - 1] + "…"


def show_network_info(local_ip, network, gateway, dns):
    print(f"  {GRASS_LIGHT}Your machine{RESET}  : {WHITE}{local_ip}{RESET}")
    print(f"  {GRASS_LIGHT}Network{RESET}       : {WHITE}{network}{RESET}")
    print(f"  {GRASS_LIGHT}Gateway{RESET}       : {WHITE}{gateway or 'not detected'}{RESET}")
    print(f"  {GRASS_LIGHT}DNS servers{RESET}   : {WHITE}{', '.join(dns) if dns else 'not detected'}{RESET}")
    print(f"  {GRASS_LIGHT}Hosts to check{RESET}: {WHITE}{network.num_addresses - 2}{RESET}")
    print(f"  {GRASS_LIGHT}OUI database{RESET}  : {WHITE}{len(OUI)} vendor prefixes{RESET}")
    print(GREY + "  " + "─" * 52 + RESET)


def show_menu():
    print()
    print(f"  {GRASS}[1]{RESET} {WHITE}Quick scan{RESET}    {GREY}ping + ARP + vendor + hostname{RESET}")
    print(f"  {GRASS}[2]{RESET} {WHITE}Deep scan{RESET}     {GREY}+ ports + OS + NetBIOS + device type{RESET}  {GRASS_LIGHT}(recommended){RESET}")
    print(f"  {GRASS}[3]{RESET} {WHITE}Single host{RESET}   {GREY}deep scan one IP{RESET}")
    print(f"  {GRASS}[4]{RESET} {WHITE}ARP table{RESET}     {GREY}instant, no sweep{RESET}")
    print(f"  {GRASS}[5]{RESET} {WHITE}Export report{RESET} {GREY}HTML / JSON / CSV / TXT{RESET}")
    print(f"  {GRASS}[0]{RESET} {WHITE}Exit{RESET}")
    print()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
def _build_alive_set(alive_pings, arp, gateway):
    ping_map = {p["ip"]: p for p in alive_pings}
    ips = set(ping_map) | set(arp)
    if gateway:
        ips.add(gateway)
    ips.discard("127.0.0.1")
    ips = {ip for ip in ips if is_real_device(ip, arp.get(ip, ""))}
    return ips, ping_map


def _enrich(ips, arp, ping_map, gateway, deep, progress=True):
    """Resolves names, vendors, (deep: ports/os/netbios) and builds devices."""
    port_map = {}
    if deep:
        print(f"  {GRASS_LIGHT}> Scanning ports on {len(ips)} host(s)...{RESET}")
        port_map = scan_ports_bulk(
            ips, list(COMMON_PORTS),
            progress_cb=(lambda d, t: progress_bar(d, t)) if progress else None)
        if progress:
            print()

    print(f"  {GRASS_LIGHT}> Resolving hostnames{' / NetBIOS' if deep else ''}...{RESET}")
    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        host_f = {ip: ex.submit(resolve_hostname, ip) for ip in ips}
        nb_f = {ip: ex.submit(netbios_name, ip) for ip in ips} if deep else {}
        for ip in ips:
            mac = arp.get(ip, "-")
            p = ping_map.get(ip, {})
            dev = {
                "ip": ip,
                "mac": mac,
                "vendor": lookup_vendor(mac),
                "hostname": host_f[ip].result(),
                "netbios": nb_f[ip].result() if deep else "-",
                "latency": p.get("latency"),
                "ttl": p.get("ttl"),
                "os": guess_os(p.get("ttl")) if deep else "-",
                "ports": port_map.get(ip, {}),
            }
            dev["type"] = infer_device_type(dev, gateway) if deep else "-"
            devices.append(dev)
    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return devices


def run_scan(local_ip, network, gateway, dns, deep):
    print()
    kind = "DEEP" if deep else "QUICK"
    print(f"  {GRASS_LIGHT}> [{kind}] Ping sweep across {network}...{RESET}")
    start = time.time()
    alive_pings = ping_sweep(network, progress_cb=progress_bar)
    print()
    print(f"  {GRASS_LIGHT}> Reading ARP table...{RESET}")
    arp = get_arp_table()
    ips, ping_map = _build_alive_set(alive_pings, arp, gateway)
    devices = _enrich(ips, arp, ping_map, gateway, deep)
    elapsed = time.time() - start

    meta = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": kind.title(),
        "network": str(network),
        "local_ip": local_ip,
        "gateway": gateway,
        "dns": dns,
        "duration": round(elapsed, 1),
        "count": len(devices),
    }
    global LAST_RESULT
    LAST_RESULT = ScanResult(devices, meta)
    render_report(LAST_RESULT, deep)


def deep_scan_single(local_ip, gateway, dns):
    ip = input(f"  {GRASS}Target IP{RESET} {WHITE}>{RESET} ").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"  {RED}Invalid IP.{RESET}")
        return
    print(f"  {GRASS_LIGHT}> Deep scanning {ip}...{RESET}")
    start = time.time()
    p = ping_host(ip) or {}
    arp = get_arp_table()
    ips = {ip}
    devices = _enrich(ips, arp, {ip: p} if p else {}, gateway, True)
    elapsed = time.time() - start

    meta = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": "Single-host (Deep)",
        "network": ip,
        "local_ip": local_ip,
        "gateway": gateway,
        "dns": dns,
        "duration": round(elapsed, 1),
        "count": len(devices),
    }
    global LAST_RESULT
    LAST_RESULT = ScanResult(devices, meta)
    render_report(LAST_RESULT, True)


def show_arp_only():
    arp = {ip: mac for ip, mac in get_arp_table().items() if is_real_device(ip, mac)}
    print()
    print(GREY + "  " + "═" * 45 + RESET)
    print(f"  {GRASS}{BOLD}{'IP':<16}{'MAC':<19}{'VENDOR'}{RESET}")
    print(GREY + "  " + "─" * 45 + RESET)
    for ip in sorted(arp, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp[ip]
        print(f"  {WHITE}{ip:<16}{RESET}{GRASS}{mac:<19}{RESET}{GRASS_LIGHT}{lookup_vendor(mac)}{RESET}")
    print(GREY + "  " + "═" * 45 + RESET)
    print(f"  {GRASS_LIGHT}{len(arp)} device(s) in the ARP table{RESET}")


# ---------------------------------------------------------------------------
# On-screen report
# ---------------------------------------------------------------------------
def render_report(result, deep):
    devices = result.devices
    meta = result.meta
    if deep:
        _render_cards(devices, meta)
    else:
        _render_table(devices, meta)
    _render_summary(devices, meta, deep)


def _tag(dev, meta):
    if dev["ip"] == meta["local_ip"]:
        return f" {GRASS_LIGHT}(you){RESET}"
    if dev["ip"] == meta["gateway"]:
        return f" {YELLOW}(router){RESET}"
    return ""


def _render_table(devices, meta):
    print()
    print(GREY + "  " + "═" * 74 + RESET)
    print(f"  {GRASS}{BOLD}{'IP':<16}{'MAC':<19}{'VENDOR':<18}{'HOSTNAME'}{RESET}")
    print(GREY + "  " + "─" * 74 + RESET)
    for d in devices:
        host = d["hostname"] if d["hostname"] != "-" else GREY + "-" + RESET
        print(
            f"  {WHITE}{d['ip']:<16}{RESET}"
            f"{GRASS}{d['mac']:<19}{RESET}"
            f"{GRASS_LIGHT}{trunc(d['vendor'], 17):<18}{RESET}"
            f"{WHITE}{trunc(host, 24)}{RESET}{_tag(d, meta)}"
        )
    print(GREY + "  " + "═" * 74 + RESET)


def _render_cards(devices, meta):
    print()
    print(GREY + "  " + "═" * 74 + RESET)
    for d in devices:
        ports = ", ".join(f"{p}/{s}" for p, s in sorted(d["ports"].items())) or "none detected"
        lat = f"{d['latency']:.0f} ms" if d.get("latency") is not None else "-"
        print(f"  {GRASS}{BOLD}● {d['ip']}{RESET}{_tag(d, meta)}")
        print(f"    {GREY}MAC       {RESET}: {GRASS}{d['mac']}{RESET}  {GREY}({d['vendor']}){RESET}")
        print(f"    {GREY}Hostname  {RESET}: {WHITE}{d['hostname']}{RESET}")
        print(f"    {GREY}NetBIOS   {RESET}: {WHITE}{d['netbios']}{RESET}")
        print(f"    {GREY}Type      {RESET}: {CYAN}{d['type']}{RESET}")
        print(f"    {GREY}OS guess  {RESET}: {WHITE}{d['os']}{RESET}")
        print(f"    {GREY}Latency   {RESET}: {WHITE}{lat}{RESET}")
        print(f"    {GREY}Open ports{RESET}: {GRASS_LIGHT}{ports}{RESET}")
        print(GREY + "  " + "─" * 74 + RESET)


def _render_summary(devices, meta, deep):
    print(f"  {GRASS}{BOLD}Summary{RESET}")
    print(f"    {GREY}Devices found{RESET}: {GRASS_LIGHT}{len(devices)}{RESET}")
    print(f"    {GREY}Scan type    {RESET}: {WHITE}{meta['scan_type']}{RESET}")
    print(f"    {GREY}Duration     {RESET}: {WHITE}{meta['duration']}s{RESET}")
    if deep:
        types = {}
        services = {}
        for d in devices:
            types[d["type"]] = types.get(d["type"], 0) + 1
            for s in d["ports"].values():
                services[s] = services.get(s, 0) + 1
        if types:
            tsum = ", ".join(f"{k} x{v}" for k, v in sorted(types.items(), key=lambda i: -i[1]))
            print(f"    {GREY}By type      {RESET}: {WHITE}{tsum}{RESET}")
        if services:
            ssum = ", ".join(f"{k} x{v}" for k, v in sorted(services.items(), key=lambda i: -i[1]))
            print(f"    {GREY}Open services{RESET}: {WHITE}{ssum}{RESET}")
    print(GREY + "  " + "═" * 74 + RESET)
    print(f"  {GRASS_LIGHT}Tip:{RESET} {GREY}use menu option [5] to export this scan as HTML/JSON/CSV/TXT.{RESET}")


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------
def _report_path(ext):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(SCRIPT_DIR, f"scanfy_report_{stamp}.{ext}")


def export_json(result):
    path = _report_path("json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": result.meta, "devices": result.devices},
                  f, indent=2, ensure_ascii=False)
    return path


def export_csv(result):
    path = _report_path("csv")
    fields = ["ip", "mac", "vendor", "hostname", "netbios", "type",
              "os", "latency", "ports"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for d in result.devices:
            ports = "; ".join(f"{p}/{s}" for p, s in sorted(d["ports"].items()))
            w.writerow([d["ip"], d["mac"], d["vendor"], d["hostname"],
                        d["netbios"], d["type"], d["os"],
                        "" if d["latency"] is None else d["latency"], ports])
    return path


def export_txt(result):
    path = _report_path("txt")
    m = result.meta
    lines = []
    lines.append("=" * 70)
    lines.append("SCANFY - network scan report")
    lines.append("=" * 70)
    lines.append(f"Generated : {m['generated']}")
    lines.append(f"Scan type : {m['scan_type']}")
    lines.append(f"Network   : {m['network']}")
    lines.append(f"Your IP   : {m['local_ip']}")
    lines.append(f"Gateway   : {m['gateway']}")
    lines.append(f"DNS       : {', '.join(m['dns']) if m['dns'] else '-'}")
    lines.append(f"Duration  : {m['duration']}s")
    lines.append(f"Devices   : {m['count']}")
    lines.append("=" * 70)
    for d in result.devices:
        ports = ", ".join(f"{p}/{s}" for p, s in sorted(d["ports"].items())) or "none detected"
        lat = f"{d['latency']:.0f} ms" if d["latency"] is not None else "-"
        lines.append(f"\n[{d['ip']}]")
        lines.append(f"  MAC        : {d['mac']} ({d['vendor']})")
        lines.append(f"  Hostname   : {d['hostname']}")
        lines.append(f"  NetBIOS    : {d['netbios']}")
        lines.append(f"  Type       : {d['type']}")
        lines.append(f"  OS guess   : {d['os']}")
        lines.append(f"  Latency    : {lat}")
        lines.append(f"  Open ports : {ports}")
    lines.append("\n" + "=" * 70)
    lines.append("Long live the Hackers of Brazil / Viva os Hacker do Brasil")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def export_html(result):
    path = _report_path("html")
    m = result.meta
    rows = []
    for d in result.devices:
        ports = ", ".join(f"{p}/{s}" for p, s in sorted(d["ports"].items())) or "<span class=dim>none</span>"
        lat = f"{d['latency']:.0f} ms" if d["latency"] is not None else "-"
        tag = ""
        if d["ip"] == m["local_ip"]:
            tag = " <span class='tag you'>you</span>"
        elif d["ip"] == m["gateway"]:
            tag = " <span class='tag router'>router</span>"
        rows.append(f"""      <tr>
        <td class=ip>{d['ip']}{tag}</td>
        <td class=mono>{d['mac']}</td>
        <td>{d['vendor']}</td>
        <td>{d['hostname']}</td>
        <td>{d['netbios']}</td>
        <td>{d['type']}</td>
        <td>{d['os']}</td>
        <td>{lat}</td>
        <td class=ports>{ports}</td>
      </tr>""")
    rows_html = "\n".join(rows)
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SCANFY report - {m['generated']}</title>
<style>
  :root {{ --grass:#6abe30; --grass-l:#96dc5a; --grass-d:#4e9120;
           --bg:#0e1510; --panel:#16211544; --line:#24331c; --text:#e7f0e0; --dim:#7d8c74; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
          font-family:'Segoe UI',system-ui,sans-serif; padding:32px; }}
  h1 {{ color:var(--grass-l); font-family:monospace; letter-spacing:3px; margin:0 0 4px; }}
  .sub {{ color:var(--dim); margin-bottom:24px; }}
  .cards {{ display:flex; flex-wrap:wrap; gap:12px; margin-bottom:24px; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
           padding:14px 18px; min-width:150px; }}
  .card .k {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
  .card .v {{ color:var(--grass-l); font-size:22px; font-weight:700; margin-top:4px; }}
  .wrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:10px; }}
  table {{ border-collapse:collapse; width:100%; font-size:14px; }}
  th {{ background:#16211533; color:var(--grass); text-align:left; padding:10px 12px;
        border-bottom:2px solid var(--grass-d); position:sticky; top:0; white-space:nowrap; }}
  td {{ padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
  tr:hover td {{ background:#16211533; }}
  .mono, .ip, .ports {{ font-family:monospace; }}
  .ip {{ color:var(--grass-l); font-weight:600; white-space:nowrap; }}
  .ports {{ color:var(--grass); }}
  .dim {{ color:var(--dim); }}
  .tag {{ font-size:11px; padding:1px 7px; border-radius:20px; margin-left:6px; font-family:sans-serif; }}
  .tag.you {{ background:var(--grass-d); color:#fff; }}
  .tag.router {{ background:#8a6d2a; color:#fff; }}
  footer {{ margin-top:28px; color:var(--dim); text-align:center; font-style:italic; }}
  footer b {{ color:var(--grass-l); font-style:normal; }}
</style></head><body>
  <h1>SCANFY</h1>
  <div class="sub">network scan report &middot; generated {m['generated']}</div>
  <div class="cards">
    <div class="card"><div class="k">Devices</div><div class="v">{m['count']}</div></div>
    <div class="card"><div class="k">Scan type</div><div class="v">{m['scan_type']}</div></div>
    <div class="card"><div class="k">Duration</div><div class="v">{m['duration']}s</div></div>
    <div class="card"><div class="k">Network</div><div class="v" style="font-size:16px">{m['network']}</div></div>
    <div class="card"><div class="k">Gateway</div><div class="v" style="font-size:16px">{m['gateway'] or '-'}</div></div>
  </div>
  <div class="wrap"><table>
    <thead><tr>
      <th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>NetBIOS</th>
      <th>Type</th><th>OS guess</th><th>Latency</th><th>Open ports</th>
    </tr></thead>
    <tbody>
{rows_html}
    </tbody>
  </table></div>
  <footer><b>Long live the Hackers of Brazil</b><br>Viva os Hacker do Brasil 🇧🇷</footer>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def export_menu():
    if LAST_RESULT is None:
        print(f"  {RED}No scan results yet. Run a scan first (option 1, 2 or 3).{RESET}")
        return
    print()
    print(f"  {GRASS}[1]{RESET} {WHITE}HTML{RESET}  {GRASS}[2]{RESET} {WHITE}JSON{RESET}  "
          f"{GRASS}[3]{RESET} {WHITE}CSV{RESET}  {GRASS}[4]{RESET} {WHITE}TXT{RESET}  "
          f"{GRASS}[5]{RESET} {WHITE}All{RESET}")
    choice = input(f"  {GRASS}format{RESET} {WHITE}>{RESET} ").strip()
    jobs = {
        "1": [export_html], "2": [export_json], "3": [export_csv],
        "4": [export_txt],
        "5": [export_html, export_json, export_csv, export_txt],
    }.get(choice)
    if not jobs:
        print(f"  {RED}Invalid option.{RESET}")
        return
    print()
    for fn in jobs:
        try:
            path = fn(LAST_RESULT)
            print(f"  {GRASS_LIGHT}saved{RESET} {WHITE}{path}{RESET}")
        except Exception as e:
            print(f"  {RED}failed ({fn.__name__}): {e}{RESET}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _enable_ansi_windows()
    added = load_extra_oui()
    local_ip = get_local_ip()
    network = get_network(local_ip)
    gateway = get_gateway()
    dns = get_dns_servers()

    while True:
        print_banner()
        if added:
            print(f"  {GREY}(loaded {added} extra OUI entries from oui.txt){RESET}")
        show_network_info(local_ip, network, gateway, dns)
        show_menu()
        try:
            choice = input(f"  {GRASS}scanfy{RESET} {WHITE}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {GREY}Exiting...{RESET}")
            break

        try:
            if choice == "1":
                run_scan(local_ip, network, gateway, dns, deep=False)
            elif choice == "2":
                run_scan(local_ip, network, gateway, dns, deep=True)
            elif choice == "3":
                deep_scan_single(local_ip, gateway, dns)
            elif choice == "4":
                show_arp_only()
            elif choice == "5":
                export_menu()
            elif choice == "0":
                print(f"  {GRASS_LIGHT}See you!{RESET}")
                break
            else:
                print(f"  {RED}Invalid option.{RESET}")
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}Scan aborted.{RESET}")

        input(f"\n  {GREY}[Enter] to go back to the menu...{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{GREY}Interrupted.{RESET}")
