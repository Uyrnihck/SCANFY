#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCANFY - Local network scanner (Wi-Fi/LAN)
Discovers devices connected to the same network: IP, MAC, hostname and vendor.
Legitimate use: analyzing YOUR OWN network. Do not use on networks without
authorization.

No external dependencies - runs on the Python 3 standard library only.
"""

import concurrent.futures
import ctypes
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Colors (truecolor ANSI). "Minecraft grass" green ~ (106, 190, 48).
# ---------------------------------------------------------------------------
IS_WIN = platform.system().lower().startswith("win")


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

SUBTITLE = "        local network scanner  ::  v1.0"


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


# ---------------------------------------------------------------------------
# Ping sweep
# ---------------------------------------------------------------------------
def ping(ip):
    """Returns the IP if the host replied to the ping, otherwise None."""
    ip = str(ip)
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="cp850" if IS_WIN else "utf-8", errors="ignore"
        )
        if r.returncode != 0:
            return None
        # On Windows an unreachable destination may still return 0, so we
        # confirm there was an actual reply (TTL present in the output).
        if IS_WIN and "TTL=" not in r.stdout.upper():
            return None
        return ip
    except Exception:
        return None


def ping_sweep(network, progress_cb=None):
    """Pings every host in the network in parallel."""
    hosts = list(network.hosts())
    alive = []
    total = len(hosts)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(ping, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            res = fut.result()
            if res:
                alive.append(res)
    return alive


# ---------------------------------------------------------------------------
# ARP (MAC address) and hostname
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
                m = re.search(r"([\d.]+)\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})", line)
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


# MAC prefixes (OUI) of common vendors - approximate offline identification.
OUI = {
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f4:f5:e8": "Google",
    "d8:eb:97": "TP-Link", "50:c7:bf": "TP-Link", "a4:2b:b0": "TP-Link",
    "00:1d:0f": "TP-Link", "b0:be:76": "TP-Link",
    "fc:ec:da": "Ubiquiti", "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "00:0c:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "ac:de:48": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "3c:07:54": "Apple", "d0:e1:40": "Apple", "bc:92:6b": "Apple",
    "fc:fb:fb": "Cisco", "00:1b:54": "Cisco",
    "18:fe:34": "Espressif (ESP)", "24:0a:c4": "Espressif (ESP)", "a0:20:a6": "Espressif (ESP)",
    "50:02:91": "Espressif (ESP)", "24:6f:28": "Espressif (ESP)",
    "00:12:fb": "Samsung", "5c:0a:5b": "Samsung", "78:1f:db": "Samsung",
    "00:24:e4": "Withings", "44:65:0d": "Amazon", "fc:65:de": "Amazon",
    "68:37:e9": "Amazon", "f0:27:2d": "Xiaomi", "64:09:80": "Xiaomi",
    "28:6c:07": "Xiaomi", "c4:6a:b7": "Xiaomi",
    "d4:6a:6a": "Netgear", "a0:40:a0": "Netgear",
    "e0:b9:4d": "Intel", "94:65:9c": "Intel", "34:41:5d": "Intel",
    "60:45:cb": "Intel", "00:15:5d": "Microsoft (Hyper-V)",
}


def lookup_vendor(mac):
    if not mac or mac == "-":
        return "-"
    prefix = mac[:8].lower()
    return OUI.get(prefix, "unknown")


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
# UI helpers
# ---------------------------------------------------------------------------
def progress_bar(done, total, width=40):
    frac = done / total if total else 1
    filled = int(width * frac)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(frac * 100)
    sys.stdout.write(
        f"\r  {GRASS}{bar}{RESET} {WHITE}{pct:3d}%{RESET} "
        f"{GREY}({done}/{total}){RESET}"
    )
    sys.stdout.flush()


def show_network_info(local_ip, network, gateway):
    print(f"  {GRASS_LIGHT}Your machine{RESET}  : {WHITE}{local_ip}{RESET}")
    print(f"  {GRASS_LIGHT}Network{RESET}       : {WHITE}{network}{RESET}")
    print(f"  {GRASS_LIGHT}Gateway{RESET}       : {WHITE}{gateway or 'not detected'}{RESET}")
    print(f"  {GRASS_LIGHT}Hosts to check{RESET}: {WHITE}{network.num_addresses - 2}{RESET}")
    print(GREY + "  " + "─" * 52 + RESET)


def show_menu():
    print()
    print(f"  {GRASS}[1]{RESET} {WHITE}Start network scan{RESET}")
    print(f"  {GRASS}[2]{RESET} {WHITE}Show current ARP table (fast){RESET}")
    print(f"  {GRASS}[0]{RESET} {WHITE}Exit{RESET}")
    print()


def run_scan(local_ip, network, gateway):
    print()
    print(f"  {GRASS_LIGHT}> Running ping sweep on the network...{RESET}")
    start = time.time()
    alive = ping_sweep(network, progress_cb=progress_bar)
    print()  # break the progress-bar line
    print(f"  {GRASS_LIGHT}> Reading ARP table and resolving names...{RESET}")

    arp = get_arp_table()
    # include the gateway and ARP IPs that may not have replied to the ping
    ips = set(alive) | set(arp.keys())
    if gateway:
        ips.add(gateway)
    ips.discard("127.0.0.1")
    ips = {ip for ip in ips if is_real_device(ip, arp.get(ip, ""))}

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        names = {ip: ex.submit(resolve_hostname, ip) for ip in ips}
        for ip in ips:
            mac = arp.get(ip, "-")
            devices.append({
                "ip": ip,
                "mac": mac,
                "host": names[ip].result(),
                "vendor": lookup_vendor(mac),
            })

    devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))
    elapsed = time.time() - start
    show_results(devices, local_ip, gateway, elapsed)


def show_results(devices, local_ip, gateway, elapsed):
    print()
    print(GREY + "  " + "═" * 74 + RESET)
    print(f"  {GRASS}{BOLD}{'IP':<16}{'MAC':<19}{'VENDOR':<18}{'HOSTNAME'}{RESET}")
    print(GREY + "  " + "─" * 74 + RESET)

    for d in devices:
        tag = ""
        if d["ip"] == local_ip:
            tag = f" {GRASS_LIGHT}(you){RESET}"
        elif d["ip"] == gateway:
            tag = f" {YELLOW}(router){RESET}"
        host = d["host"] if d["host"] != "-" else GREY + "-" + RESET
        print(
            f"  {WHITE}{d['ip']:<16}{RESET}"
            f"{GRASS}{d['mac']:<19}{RESET}"
            f"{GRASS_LIGHT}{d['vendor']:<18}{RESET}"
            f"{WHITE}{host}{RESET}{tag}"
        )

    print(GREY + "  " + "═" * 74 + RESET)
    print(
        f"  {GRASS_LIGHT}{len(devices)} device(s){RESET} "
        f"{GREY}found in {elapsed:.1f}s{RESET}"
    )


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
# Main
# ---------------------------------------------------------------------------
def main():
    _enable_ansi_windows()
    local_ip = get_local_ip()
    network = get_network(local_ip)
    gateway = get_gateway()

    while True:
        print_banner()
        show_network_info(local_ip, network, gateway)
        show_menu()
        try:
            choice = input(f"  {GRASS}scanfy{RESET} {WHITE}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {GREY}Exiting...{RESET}")
            break

        if choice == "1":
            run_scan(local_ip, network, gateway)
        elif choice == "2":
            show_arp_only()
        elif choice == "0":
            print(f"  {GRASS_LIGHT}See you!{RESET}")
            break
        else:
            print(f"  {RED}Invalid option.{RESET}")

        input(f"\n  {GREY}[Enter] to go back to the menu...{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{GREY}Interrupted.{RESET}")
