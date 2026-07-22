#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCANFY - Advanced network scanner, service fingerprinter and security
reconnaissance dossier generator  ---  SINGLE-FILE EDITION.

This one file contains the entire SCANFY suite. It was assembled from the
modular `scanfyx` package by build_bundle.py: every module's source is embedded
below in the SCANFY_MODULES table, and a small in-file import loader executes
them on demand, so this single file behaves exactly like the full package.

Run it:
    python scanfy.py                 # interactive menu
    python scanfy.py -p deep -f all  # headless deep scan, all dossier formats
    python scanfy.py -t 192.168.0.1 -f html   # deep-scan one host -> HTML
    python scanfy.py --help

Install the optional power-up libraries for full capability:
    pip install -r requirements_scanfy.txt

Legitimate use only: scan networks you own or are explicitly authorized to test.
Long live the Hackers of Brazil / Viva os Hacker do Brasil.
"""

import importlib.abc
import importlib.util
import sys


def _install_loader(sources, packages):
    """Install a meta-path finder that serves the embedded module sources."""

    class _Loader(importlib.abc.Loader):
        def create_module(self, spec):
            return None

        def exec_module(self, module):
            code = compile(sources[module.__name__], module.__name__, "exec")
            exec(code, module.__dict__)

    class _Finder(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name not in sources:
                return None
            is_pkg = name in packages
            return importlib.util.spec_from_loader(
                name, _Loader(), is_package=is_pkg)

    sys.meta_path.insert(0, _Finder())


def main():
    _install_loader(SCANFY_MODULES, SCANFY_PACKAGES)
    from scanfyx.app import main as app_main
    return app_main()

SCANFY_PACKAGES = {
    'scanfyx',
    'scanfyx.data',
    'scanfyx.discovery',
    'scanfyx.fingerprint',
    'scanfyx.portscan',
    'scanfyx.report',
    'scanfyx.security',
    'scanfyx.ui',
    'scanfyx.utils',
}

SCANFY_MODULES = {}

# ---------------------------------------------------------------------------
# module: scanfyx
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx'] = r'''"""
SCANFY - Advanced local network scanner, service fingerprinter and security
reconnaissance dossier generator.

This package is organized into cohesive subsystems:

    scanfyx.utils        low-level helpers (net, text, concurrency)
    scanfyx.data         static knowledge bases (services, OUI, vulns, signatures)
    scanfyx.models       typed data model (Device, Port, Service, Finding, ...)
    scanfyx.discovery    host discovery engines (icmp/tcp/udp/arp/mdns/ssdp/netbios)
    scanfyx.portscan     port scanning and banner grabbing
    scanfyx.fingerprint  per-service deep fingerprinting (http/tls/ssh/snmp/smb/...)
    scanfyx.classify     device classification engine
    scanfyx.security     vulnerability analysis, risk scoring, CVE correlation
    scanfyx.topology     traceroute and network graph
    scanfyx.storage      SQLite scan history and diffing
    scanfyx.monitor      continuous monitoring mode
    scanfyx.report       dossier generation (html/pdf/markdown/json/csv/xml/txt)
    scanfyx.ui           rich terminal interface
    scanfyx.engine       the end-to-end scan pipeline
    scanfyx.app          interactive application loop
    scanfyx.cli          command-line interface

The package uses *progressive enhancement*: optional third-party libraries are
used when available and gracefully degraded when not, so SCANFY always runs.
"""

from .version import __version__, VERSION, BUILD, CODENAME

__all__ = ["__version__", "VERSION", "BUILD", "CODENAME"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.app
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.app'] = r'''"""
Application entry point.

Verifies the Python version, configures logging, checks that the required UI
dependency (rich) is present and hands control to the CLI (which either shows
the interactive menu or performs a headless scan).
"""

import sys

from .version import MIN_PYTHON, __version__


def _check_python():
    if sys.version_info[:2] < MIN_PYTHON:
        sys.stderr.write(
            f"SCANFY requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ "
            f"(you have {sys.version.split()[0]}).\n")
        return False
    return True


def _check_rich():
    try:
        import rich  # noqa
        return True
    except ImportError:
        sys.stderr.write(
            "SCANFY needs the 'rich' library for its interface.\n"
            "Install dependencies:  pip install -r requirements_scanfy.txt\n"
            "(minimally:  pip install rich)\n")
        return False


def main(argv=None):
    if not _check_python():
        return 1
    if not _check_rich():
        return 1

    # force UTF-8 output so block/box characters survive piping/redirection
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # enable ANSI on legacy Windows consoles
    try:
        import ctypes
        if sys.platform.startswith("win"):
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        pass

    from .cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
'''

# ---------------------------------------------------------------------------
# module: scanfyx.classify
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.classify'] = r'''"""
Device classification engine.

Fuses every available signal - HTTP device kind, mDNS/SSDP service types,
open-port patterns, vendor hints, banners and OS guess - into a single
human-readable device type and a coarse ``device_kind`` slug. A small scoring
scheme lets strong signals (an mDNS ``_googlecast`` record, an HTTP camera UI)
outweigh weak ones (a lone open port).
"""

from . import vendors
from .logging_setup import get_logger

log = get_logger("classify")


# device_kind -> friendly label
LABELS = {
    "router": "Router / Gateway",
    "firewall": "Firewall / UTM",
    "switch": "Managed switch",
    "ap": "Wireless access point",
    "camera": "IP camera / NVR",
    "printer": "Printer / scanner",
    "nas": "NAS / storage",
    "media-server": "Media server",
    "media-device": "Streaming device",
    "smart-speaker": "Smart speaker",
    "smart-tv": "Smart TV",
    "iot-hub": "Smart-home hub",
    "iot-device": "IoT device",
    "voip": "VoIP phone / PBX",
    "phone": "Phone / tablet",
    "laptop": "Laptop / desktop",
    "windows-pc": "Windows PC / server",
    "linux-host": "Linux / Unix host",
    "mac": "Apple Mac",
    "server": "Server",
    "hypervisor": "Hypervisor / VM host",
    "vm": "Virtual machine",
    "bmc": "Out-of-band mgmt (BMC)",
    "sbc": "Single-board computer",
    "game-console": "Game console",
    "industrial": "Industrial / OT device",
    "unknown": "Unknown",
}

MDNS_KIND = {
    "googlecast": "media-device", "airplay": "media-device", "raop": "smart-speaker",
    "spotify-connect": "smart-speaker", "sonos": "smart-speaker",
    "printer": "printer", "ipp": "printer", "ipps": "printer",
    "pdl-datastream": "printer", "scanner": "printer", "ippusb": "printer",
    "hap": "iot-device", "homekit": "iot-device", "matter": "iot-device",
    "esphomelib": "iot-device", "home-assistant": "iot-hub",
    "smb": "server", "afpovertcp": "nas", "adisk": "nas", "time-machine": "nas",
    "nvstream": "game-console", "workstation": "laptop", "ssh": "linux-host",
    "companion-link": "phone", "touch-able": "media-device",
    "amzn-wplay": "media-device", "daap": "media-server",
}


def _score_from_http(dev):
    scores = {}
    for h in dev.http:
        if h.device_kind:
            scores[h.device_kind] = scores.get(h.device_kind, 0) + 6
        for tech in h.technologies:
            k = tech.get("kind")
            if k in ("camera", "router", "firewall", "nas", "printer",
                     "media-server", "iot-hub", "iot-device", "hypervisor", "bmc"):
                scores[k] = scores.get(k, 0) + 4
    return scores


def _score_from_mdns(dev):
    scores = {}
    for svc in dev.services_detail.get("mdns_services", []) or []:
        kind = MDNS_KIND.get(svc)
        if kind:
            scores[kind] = scores.get(kind, 0) + 5
    return scores


def _score_from_ssdp(dev):
    scores = {}
    server = (dev.services_detail.get("ssdp_server") or "").lower()
    upnp = dev.services_detail.get("upnp") or {}
    model = " ".join(str(v) for v in upnp.values()).lower()
    blob = server + " " + model
    table = [
        ("dlna", "media-server"), ("mediarenderer", "media-device"),
        ("mediaserver", "media-server"), ("internetgatewaydevice", "router"),
        ("wandevice", "router"), ("printer", "printer"), ("camera", "camera"),
        ("roku", "media-device"), ("sonos", "smart-speaker"),
        ("samsung", "smart-tv"), ("lg", "smart-tv"), ("xbox", "game-console"),
        ("playstation", "game-console"), ("nas", "nas"),
    ]
    for token, kind in table:
        if token in blob:
            scores[kind] = scores.get(kind, 0) + 4
    return scores


def _score_from_wsd(dev):
    scores = {}
    kind = dev.services_detail.get("wsd_kind") or ""
    if kind == "printer":
        scores["printer"] = 5
    elif kind == "camera":
        scores["camera"] = 5
    elif kind == "computer":
        scores["windows-pc"] = 2
    return scores


def _score_from_ports(dev):
    ports = dev.port_set()
    scores = {}

    def add(kind, pts):
        scores[kind] = scores.get(kind, 0) + pts

    if ports & {9100, 515, 631}:
        add("printer", 5)
    if 62078 in ports:
        add("phone", 6)
    if ports & {554, 8554, 37777}:
        add("camera", 4)
    if 32400 in ports:
        add("media-server", 5)
    if ports & {1883, 8883}:
        add("iot-hub", 3)
    if ports & {2, 5, 623, 16992}:
        add("bmc", 3)
    if 3389 in ports:
        add("windows-pc", 4)
    if ports & {445, 139, 135}:
        add("windows-pc", 3)
    if 22 in ports and ports & {80, 443}:
        add("linux-host", 3)
    elif 22 in ports:
        add("linux-host", 2)
    if ports & {2375, 2376, 6443, 10250}:
        add("server", 3)
    # unambiguous OT/industrial protocols
    if ports & {502, 47808, 102, 4840}:
        add("industrial", 6)
    # DNP3(20000) also clashes with Usermin; only a weak hint on its own
    if 20000 in ports:
        add("industrial", 1)
    if ports & {5060, 5061, 2000}:
        add("voip", 4)
    if ports & {548, 5009, 2049, 873}:
        add("nas", 2)
    return scores


def _score_from_vendor(dev):
    scores = {}
    v = (dev.vendor or "").lower()
    hint = vendors.device_hint(dev.vendor) or ""
    mapping = [
        ("raspberry", "sbc"), ("espressif", "iot-device"),
        ("philips hue", "iot-hub"), ("sonos", "smart-speaker"),
        ("roku", "media-device"), ("nest", "iot-device"),
        ("hikvision", "camera"), ("dahua", "camera"), ("axis", "camera"),
        ("hewlett", "printer"), ("ricoh", "printer"), ("kyocera", "printer"),
        ("brother", "printer"), ("epson", "printer"), ("canon", "printer"),
        ("synology", "nas"), ("qnap", "nas"), ("western digital", "nas"),
        ("apple", "mac"), ("mikrotik", "router"), ("ubiquiti", "ap"),
        ("tp-link", "router"), ("netgear", "router"), ("hyper-v", "vm"),
        ("vmware", "vm"), ("virtualbox", "vm"), ("qemu", "vm"),
    ]
    for token, kind in mapping:
        if token in v:
            scores[kind] = scores.get(kind, 0) + 3
    if "printer" in hint.lower():
        scores["printer"] = scores.get("printer", 0) + 2
    return scores


def _score_from_os(dev):
    scores = {}
    os = (dev.os_guess or "").lower()
    if "windows" in os:
        scores["windows-pc"] = scores.get("windows-pc", 0) + 1
    elif "android" in os:
        scores["phone"] = scores.get("phone", 0) + 1
    elif "macos" in os or "darwin" in os:
        scores["mac"] = scores.get("mac", 0) + 1
    elif "linux" in os or "unix" in os:
        scores["linux-host"] = scores.get("linux-host", 0) + 1
    elif "network device" in os:
        scores["router"] = scores.get("router", 0) + 1
    return scores


def classify(dev):
    """Assign dev.device_kind and dev.device_type. Returns the kind."""
    if dev.is_gateway:
        dev.device_kind = "router"
        dev.device_type = LABELS["router"]
        dev.add_tag("gateway")
        return dev.device_kind

    scores = {}
    for fn in (_score_from_http, _score_from_mdns, _score_from_ssdp,
               _score_from_wsd, _score_from_ports, _score_from_vendor,
               _score_from_os):
        for kind, pts in fn(dev).items():
            scores[kind] = scores.get(kind, 0) + pts

    if dev.randomized_mac and not scores:
        # phones with MAC randomization and no other signal
        dev.device_kind = "phone"
        dev.device_type = LABELS["phone"]
        dev.add_tag("randomized-mac")
        return dev.device_kind

    if not scores:
        dev.device_kind = "unknown"
        dev.device_type = LABELS["unknown"]
        return dev.device_kind

    best_kind = max(scores.items(), key=lambda kv: kv[1])[0]
    dev.device_kind = best_kind
    dev.device_type = LABELS.get(best_kind, best_kind.title())

    # secondary tags from other strong signals
    for kind, pts in sorted(scores.items(), key=lambda kv: -kv[1])[1:3]:
        if pts >= 4:
            dev.add_tag(LABELS.get(kind, kind))
    if dev.randomized_mac:
        dev.add_tag("randomized-mac")
    return dev.device_kind


def classify_all(devices):
    for d in devices:
        classify(d)
    return devices
'''

# ---------------------------------------------------------------------------
# module: scanfyx.cli
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.cli'] = r'''"""
Command-line interface.

With no arguments SCANFY launches its interactive menu. Flags allow fully
headless operation: choose a profile, target a network or single host and emit
one or more dossier formats to a directory - ideal for scheduled scans.
"""

import argparse
import ipaddress
import sys

from . import engine, report
from .config import ScanConfig, PROFILES
from .version import __version__, MOTTO_EN
from .logging_setup import setup_logging


def build_parser():
    p = argparse.ArgumentParser(
        prog="scanfy",
        description="SCANFY - advanced network scanner & security recon dossier",
        epilog=MOTTO_EN)
    p.add_argument("--version", action="version",
                   version=f"SCANFY v{__version__}")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="force the interactive menu (default when no scan args)")
    p.add_argument("-p", "--profile", choices=list(PROFILES.keys()),
                   default="default", help="scan profile (default: default)")
    p.add_argument("-n", "--network", metavar="CIDR",
                   help="network to scan, e.g. 192.168.1.0/24 (default: auto)")
    p.add_argument("-t", "--target", metavar="IP",
                   help="deep-scan a single host instead of the whole network")
    p.add_argument("-o", "--output-dir", metavar="DIR",
                   help="directory for exported dossiers")
    p.add_argument("-f", "--format", metavar="FMT", action="append",
                   choices=list(report.FORMATS.keys()) + ["all"],
                   help="report format(s) to write (repeatable); e.g. -f html -f json")
    p.add_argument("--ports", metavar="LIST",
                   help="custom comma-separated port list (implies --profile custom set)")
    p.add_argument("--no-public-ip", action="store_true",
                   help="skip the online public-IP / ISP lookup")
    p.add_argument("--no-security", action="store_true",
                   help="skip the security analysis stage")
    p.add_argument("--nmap", action="store_true",
                   help="use nmap for service/OS detection (single-host, if installed)")
    p.add_argument("--update-oui", action="store_true",
                   help="refresh the MAC vendor database and exit")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="minimal output (headless)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="verbose logging to the console")
    return p


def _headless(args):
    from .ui.console import console
    from .ui import render
    from .ui.progress import RichProgress

    cfg = ScanConfig().apply_profile(args.profile)
    if args.output_dir:
        cfg.report_dir = args.output_dir
    if args.no_public_ip:
        cfg.geoip_public = False
    if args.no_security:
        cfg.security = False
    if args.ports:
        try:
            cfg.custom_ports = [int(x) for x in args.ports.split(",") if x.strip()]
            cfg.port_set = "custom"
        except ValueError:
            print("Invalid --ports list", file=sys.stderr)
            return 2

    env = engine.detect_environment(with_public_ip=cfg.geoip_public)

    network = None
    if args.network:
        try:
            network = ipaddress.ip_network(args.network, strict=False)
        except ValueError:
            print(f"Invalid network: {args.network}", file=sys.stderr)
            return 2

    progress = None if args.quiet else RichProgress()
    if args.target:
        try:
            ipaddress.ip_address(args.target)
        except ValueError:
            print(f"Invalid target IP: {args.target}", file=sys.stderr)
            return 2
        if progress:
            with progress as pr:
                result = engine.run_single_host(args.target, cfg, env=env,
                                                progress=pr, use_nmap=args.nmap)
        else:
            result = engine.run_single_host(args.target, cfg, env=env,
                                            use_nmap=args.nmap)
        if not args.quiet:
            render.render_device_card(result.devices[0])
    else:
        if progress:
            with progress as pr:
                result = engine.run_scan(cfg, env=env, network=network,
                                         progress=pr,
                                         scan_type=cfg.profile_label())
        else:
            result = engine.run_scan(cfg, env=env, network=network,
                                     scan_type=cfg.profile_label())
        if not args.quiet:
            render.render_result(result, deep=True)

    fmts = args.format or []
    if "all" in fmts:
        fmts = list(report.FORMATS.keys())
    written = []
    for fmt in fmts:
        label, fn = report.FORMATS[fmt]
        try:
            path = fn(result, cfg)
            if path:
                written.append(path)
                print(f"[saved] {label}: {path}")
        except Exception as exc:
            print(f"[error] {label}: {exc}", file=sys.stderr)
    if not fmts and not args.quiet:
        console.print("  [stone]Tip: add -f html (or -f all) to write a dossier.[/]")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    setup_logging(verbose=args.verbose)

    if args.update_oui:
        from . import vendors
        print("Updating MAC vendor database…")
        ok = vendors.update_database()
        print("Done." if ok else "Update failed (needs internet / mac-vendor-lookup).")
        return 0 if ok else 1

    headless = bool(args.network or args.target or args.format) and not args.interactive
    if headless:
        return _headless(args)

    # interactive
    from .ui.menu import InteractiveApp
    cfg = ScanConfig().apply_profile(args.profile)
    if args.output_dir:
        cfg.report_dir = args.output_dir
    if args.no_public_ip:
        cfg.geoip_public = False
    app = InteractiveApp(config=cfg)
    try:
        app.start()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    return 0
'''

# ---------------------------------------------------------------------------
# module: scanfyx.config
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.config'] = r'''"""
Runtime configuration for SCANFY.

``ScanConfig`` holds every tunable (timeouts, worker counts, which subsystems to
run, output directory, scan profile). It can be loaded from and saved to
``~/.scanfy/config.json`` and overridden by CLI flags.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List

from . import constants


# Named scan profiles select which port set / features to run.
PROFILES = {
    "fast": dict(
        label="Fast", port_set="top100", udp=False, banners=True,
        http=True, tls=False, snmp=False, smb=True, ssh=True,
        mdns=True, ssdp=False, arp=True, traceroute=False, nmap=False,
    ),
    "default": dict(
        label="Standard", port_set="default", udp=False, banners=True,
        http=True, tls=True, snmp=True, smb=True, ssh=True,
        mdns=True, ssdp=True, arp=True, traceroute=False, nmap=False,
    ),
    "deep": dict(
        label="Deep", port_set="default", udp=True, banners=True,
        http=True, tls=True, snmp=True, smb=True, ssh=True,
        mdns=True, ssdp=True, arp=True, traceroute=True, nmap=False,
    ),
    "thorough": dict(
        label="Thorough", port_set="all", udp=True, banners=True,
        http=True, tls=True, snmp=True, smb=True, ssh=True,
        mdns=True, ssdp=True, arp=True, traceroute=True, nmap=True,
    ),
}


@dataclass
class ScanConfig:
    # profile
    profile: str = "default"

    # discovery
    icmp: bool = True
    tcp_ping: bool = True
    arp: bool = True
    mdns: bool = True
    ssdp: bool = True
    netbios: bool = True

    # port scan
    port_set: str = "default"      # top100 | default | all | custom
    custom_ports: List[int] = field(default_factory=list)
    udp: bool = False
    banners: bool = True

    # fingerprint
    http: bool = True
    tls: bool = True
    ssh: bool = True
    snmp: bool = True
    smb: bool = True
    os_detect: bool = True
    nmap: bool = False

    # analysis / extras
    security: bool = True
    traceroute: bool = False
    geoip_public: bool = True

    # timeouts / workers
    ping_timeout_ms: int = constants.DEFAULT_PING_TIMEOUT_MS
    tcp_timeout: float = constants.DEFAULT_TCP_TIMEOUT
    banner_timeout: float = constants.DEFAULT_BANNER_TIMEOUT
    http_timeout: float = constants.DEFAULT_HTTP_TIMEOUT
    max_ping_workers: int = constants.DEFAULT_MAX_PING_WORKERS
    max_port_workers: int = constants.DEFAULT_MAX_PORT_WORKERS
    max_fp_workers: int = constants.DEFAULT_MAX_FP_WORKERS

    # output
    report_dir: str = constants.REPORT_DIR_DEFAULT

    # ---------------------------------------------------------------------
    def apply_profile(self, name):
        prof = PROFILES.get(name)
        if not prof:
            return self
        self.profile = name
        self.port_set = prof["port_set"]
        self.udp = prof["udp"]
        self.banners = prof["banners"]
        self.http = prof["http"]
        self.tls = prof["tls"]
        self.snmp = prof["snmp"]
        self.smb = prof["smb"]
        self.ssh = prof["ssh"]
        self.mdns = prof["mdns"]
        self.ssdp = prof["ssdp"]
        self.arp = prof["arp"]
        self.traceroute = prof["traceroute"]
        self.nmap = prof["nmap"] and constants.HAS_NMAP_BINARY
        return self

    def profile_label(self):
        return PROFILES.get(self.profile, {}).get("label", self.profile.title())

    def to_dict(self):
        return asdict(self)

    def save(self, path=None):
        path = path or constants.CONFIG_PATH
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
            return True
        except Exception:
            return False

    @classmethod
    def load(cls, path=None):
        path = path or constants.CONFIG_PATH
        cfg = cls()
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
            except Exception:
                pass
        return cfg


def build_config(profile="default", **overrides):
    cfg = ScanConfig().apply_profile(profile)
    for k, v in overrides.items():
        if hasattr(cfg, k) and v is not None:
            setattr(cfg, k, v)
    return cfg
'''

# ---------------------------------------------------------------------------
# module: scanfyx.constants
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.constants'] = r'''"""
Global constants, filesystem paths and optional-dependency capability flags.

Importing this module performs a one-time probe of every optional third-party
library SCANFY can take advantage of, exposing simple boolean flags plus a
``CAPABILITIES`` dict used by the UI to show what is active.
"""

import os
import platform
import socket
import sys

# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------
IS_WINDOWS = platform.system().lower().startswith("win")
IS_LINUX = platform.system().lower().startswith("linux")
IS_MAC = platform.system().lower() == "darwin"
PLATFORM = platform.system()
HOSTNAME = socket.gethostname()

# Console encoding used to decode Windows CLI tools (ipconfig/arp/nbtstat).
WIN_ENCODING = "cp850"

# ---------------------------------------------------------------------------
# Filesystem paths
# ---------------------------------------------------------------------------
HOME = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME, ".scanfy")
CACHE_DIR = os.path.join(CONFIG_DIR, "cache")
REPORT_DIR_DEFAULT = os.getcwd()
DB_PATH = os.path.join(CONFIG_DIR, "scanfy_history.sqlite3")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LOG_PATH = os.path.join(CONFIG_DIR, "scanfy.log")

for _d in (CONFIG_DIR, CACHE_DIR):
    try:
        os.makedirs(_d, exist_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Optional dependency probing
# ---------------------------------------------------------------------------
def _probe(module_name):
    try:
        __import__(module_name)
        return True
    except Exception:
        return False


HAS_RICH = _probe("rich")
HAS_REQUESTS = _probe("requests")
HAS_MAC_VENDOR = _probe("mac_vendor_lookup")
HAS_PSUTIL = _probe("psutil")
HAS_SCAPY = _probe("scapy")
HAS_ZEROCONF = _probe("zeroconf")
HAS_DNSPYTHON = _probe("dns")
HAS_CRYPTOGRAPHY = _probe("cryptography")
HAS_GETMAC = _probe("getmac")
HAS_NMAP = _probe("nmap")
HAS_REPORTLAB = _probe("reportlab")
HAS_IFADDR = _probe("ifaddr")


def _nmap_binary_present():
    """python-nmap is only useful if the nmap executable exists on PATH."""
    from shutil import which
    return which("nmap") is not None


HAS_NMAP_BINARY = HAS_NMAP and _nmap_binary_present()


CAPABILITIES = {
    "rich": HAS_RICH,
    "requests": HAS_REQUESTS,
    "mac_vendor_lookup": HAS_MAC_VENDOR,
    "psutil": HAS_PSUTIL,
    "scapy": HAS_SCAPY,
    "zeroconf": HAS_ZEROCONF,
    "dnspython": HAS_DNSPYTHON,
    "cryptography": HAS_CRYPTOGRAPHY,
    "getmac": HAS_GETMAC,
    "nmap": HAS_NMAP_BINARY,
    "reportlab": HAS_REPORTLAB,
    "ifaddr": HAS_IFADDR,
}


def active_capabilities():
    """Return the list of active capability names, in a stable order."""
    order = ["rich", "requests", "mac_vendor_lookup", "psutil", "scapy",
             "zeroconf", "dnspython", "cryptography", "getmac", "nmap",
             "reportlab", "ifaddr"]
    return [name for name in order if CAPABILITIES.get(name)]


def capability_summary():
    """Short human string, e.g. 'rich+requests+scapy+zeroconf'."""
    labels = {
        "rich": "rich", "requests": "http", "mac_vendor_lookup": "oui-db",
        "psutil": "psutil", "scapy": "scapy", "zeroconf": "mdns",
        "dnspython": "dns", "cryptography": "tls", "getmac": "getmac",
        "nmap": "nmap", "reportlab": "pdf", "ifaddr": "ifaddr",
    }
    return "+".join(labels[c] for c in active_capabilities())


# ---------------------------------------------------------------------------
# Theme (Minecraft grass green family) - hex, used by rich and HTML
# ---------------------------------------------------------------------------
class Palette:
    GRASS = "#6abe30"
    GRASS_LIGHT = "#96dc5a"
    GRASS_DARK = "#4e9120"
    LEAF = "#3fa7a0"
    DIRT = "#966c4a"
    STONE = "#7d8c74"
    WATER = "#4f8fc7"
    GOLD = "#e6c85a"
    REDSTONE = "#dc5050"
    LAPIS = "#3b5dc9"
    WHITE = "#e7f0e0"
    BLACK = "#0d130c"
    PANEL = "#161f13"


CHART_COLORS = [
    "#6abe30", "#4e9120", "#96dc5a", "#3fa7a0", "#c7b53f", "#c77f3f",
    "#7f6ad0", "#c74f6a", "#4f8fc7", "#9ec16a", "#d08a3f", "#5ac8a0",
    "#b56ad0", "#d0b76a", "#6ad0a3", "#c76a9e",
]


# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0,
                   "low": 1.5, "info": 0.2}
SEVERITY_COLOR = {
    "critical": "#ff5c5c", "high": "#ff8a5c", "medium": "#ffd97a",
    "low": "#a9c98f", "info": "#7d8c74",
}


def severity_rank(sev):
    return SEVERITY_ORDER.get(str(sev).lower(), len(SEVERITIES))


# ---------------------------------------------------------------------------
# Scan tuning defaults (overridable via config)
# ---------------------------------------------------------------------------
DEFAULT_PING_TIMEOUT_MS = 600
DEFAULT_TCP_TIMEOUT = 0.7
DEFAULT_BANNER_TIMEOUT = 3.0
DEFAULT_HTTP_TIMEOUT = 3.0
DEFAULT_MAX_PING_WORKERS = 128
DEFAULT_MAX_PORT_WORKERS = 400
DEFAULT_MAX_FP_WORKERS = 48
MAX_SWEEPABLE_HOSTS = 4096

PYTHON_OK = sys.version_info[:2] >= (3, 8)
'''

# ---------------------------------------------------------------------------
# module: scanfyx.data
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.data'] = r'''"""Static knowledge bases used by SCANFY (ports, OUI, vulns, HTTP signatures)."""

from . import services, oui_fallback, vuln_db, http_signatures

__all__ = ["services", "oui_fallback", "vuln_db", "http_signatures"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.data.http_signatures
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.data.http_signatures'] = r'''"""
HTTP fingerprinting signatures.

Given a web response (Server header, other headers, page title and a snippet
of the body), these signatures identify the web server, framework, CMS, and -
importantly for LAN recon - the *kind of device* (router, camera, NAS, printer,
IoT hub, etc.) hosting the interface.
"""

import re

# Each signature: name, kind, and any of {server, header, title, body} regexes.
# 'kind' is used as a device-type hint by the classifier.
SIGNATURES = [
    # --- Web servers / frameworks ---
    dict(name="nginx", kind="web-server", server=re.compile(r"nginx", re.I)),
    dict(name="Apache httpd", kind="web-server", server=re.compile(r"Apache", re.I)),
    dict(name="Microsoft IIS", kind="web-server", server=re.compile(r"Microsoft-IIS", re.I)),
    dict(name="lighttpd", kind="web-server", server=re.compile(r"lighttpd", re.I)),
    dict(name="Caddy", kind="web-server", server=re.compile(r"Caddy", re.I)),
    dict(name="Tomcat", kind="app-server", server=re.compile(r"Coyote|Tomcat", re.I)),
    dict(name="Jetty", kind="app-server", server=re.compile(r"Jetty", re.I)),
    dict(name="Express", kind="app-server", header=re.compile(r"x-powered-by:\s*express", re.I)),
    dict(name="PHP", kind="app-server", header=re.compile(r"x-powered-by:\s*php", re.I)),
    dict(name="ASP.NET", kind="app-server", header=re.compile(r"x-aspnet-version|x-powered-by:\s*asp\.net", re.I)),
    dict(name="Werkzeug/Flask", kind="app-server", server=re.compile(r"Werkzeug", re.I)),
    dict(name="Gunicorn", kind="app-server", server=re.compile(r"gunicorn", re.I)),
    dict(name="Kestrel", kind="app-server", server=re.compile(r"Kestrel", re.I)),
    dict(name="GoAhead", kind="embedded-web", server=re.compile(r"GoAhead", re.I)),
    dict(name="Boa", kind="embedded-web", server=re.compile(r"Boa/", re.I)),
    dict(name="mini_httpd", kind="embedded-web", server=re.compile(r"mini_httpd", re.I)),
    dict(name="thttpd", kind="embedded-web", server=re.compile(r"thttpd", re.I)),
    dict(name="RomPager", kind="embedded-web", server=re.compile(r"RomPager", re.I)),
    dict(name="uhttpd", kind="embedded-web", server=re.compile(r"uhttpd", re.I)),
    dict(name="lwIP/httpd", kind="embedded-web", server=re.compile(r"lwIP", re.I)),

    # --- CMS / apps ---
    dict(name="WordPress", kind="cms", body=re.compile(r"wp-content|wp-includes", re.I)),
    dict(name="Joomla", kind="cms", body=re.compile(r"Joomla", re.I)),
    dict(name="Drupal", kind="cms", header=re.compile(r"x-generator:\s*drupal", re.I)),
    dict(name="phpMyAdmin", kind="db-admin", title=re.compile(r"phpMyAdmin", re.I)),
    dict(name="Grafana", kind="dashboard", title=re.compile(r"Grafana", re.I)),
    dict(name="Kibana", kind="dashboard", title=re.compile(r"Kibana", re.I)),
    dict(name="Jenkins", kind="ci", header=re.compile(r"x-jenkins", re.I)),
    dict(name="GitLab", kind="devtools", header=re.compile(r"gitlab", re.I)),
    dict(name="Portainer", kind="dashboard", title=re.compile(r"Portainer", re.I)),
    dict(name="Home Assistant", kind="iot-hub", title=re.compile(r"Home Assistant", re.I)),
    dict(name="Webmin", kind="admin-panel", title=re.compile(r"Webmin", re.I)),
    dict(name="cPanel", kind="admin-panel", header=re.compile(r"cpanel", re.I)),
    dict(name="pfSense", kind="firewall", title=re.compile(r"pfSense", re.I)),
    dict(name="OPNsense", kind="firewall", title=re.compile(r"OPNsense", re.I)),

    # --- Routers / network gear ---
    dict(name="MikroTik RouterOS", kind="router", server=re.compile(r"MikroTik", re.I)),
    dict(name="MikroTik RouterOS", kind="router", title=re.compile(r"RouterOS|MikroTik", re.I)),
    dict(name="OpenWrt/LuCI", kind="router", title=re.compile(r"OpenWrt|LuCI", re.I)),
    dict(name="DD-WRT", kind="router", title=re.compile(r"DD-WRT", re.I)),
    dict(name="TP-Link router", kind="router", title=re.compile(r"TP-LINK|TL-|Archer", re.I)),
    dict(name="Netgear router", kind="router", title=re.compile(r"NETGEAR", re.I)),
    dict(name="ASUS router", kind="router", title=re.compile(r"ASUS.*Router|RT-AC|RT-AX", re.I)),
    dict(name="D-Link", kind="router", title=re.compile(r"D-LINK|DIR-", re.I)),
    dict(name="Tenda", kind="router", title=re.compile(r"Tenda", re.I)),
    dict(name="Huawei HG", kind="router", title=re.compile(r"Huawei|HG8|EchoLife", re.I)),
    dict(name="UniFi", kind="router", title=re.compile(r"UniFi", re.I)),
    dict(name="Fortinet", kind="firewall", title=re.compile(r"FortiGate|Fortinet", re.I)),
    dict(name="Cisco", kind="router", title=re.compile(r"Cisco", re.I)),

    # --- Cameras / DVRs ---
    dict(name="Hikvision", kind="camera", body=re.compile(r"Hikvision|/doc/page/login", re.I)),
    dict(name="Hikvision", kind="camera", server=re.compile(r"DVRDVS|Hikvision|App-webs", re.I)),
    dict(name="Dahua", kind="camera", body=re.compile(r"Dahua|/RPC2_Login", re.I)),
    dict(name="Axis camera", kind="camera", server=re.compile(r"Axis", re.I)),
    dict(name="Foscam", kind="camera", title=re.compile(r"Foscam|IPCam", re.I)),
    dict(name="Reolink", kind="camera", title=re.compile(r"Reolink", re.I)),
    dict(name="Ubiquiti UniFi Protect", kind="camera", title=re.compile(r"UniFi Protect", re.I)),
    dict(name="Generic IP camera", kind="camera", title=re.compile(r"IP Camera|NetCam|Webcam", re.I)),

    # --- NAS / storage ---
    dict(name="Synology DSM", kind="nas", title=re.compile(r"Synology|DiskStation", re.I)),
    dict(name="QNAP", kind="nas", title=re.compile(r"QNAP|QTS", re.I)),
    dict(name="TrueNAS/FreeNAS", kind="nas", title=re.compile(r"TrueNAS|FreeNAS", re.I)),
    dict(name="WD MyCloud", kind="nas", title=re.compile(r"My Cloud|WD ", re.I)),
    dict(name="OpenMediaVault", kind="nas", title=re.compile(r"openmediavault", re.I)),

    # --- Printers ---
    dict(name="HP printer", kind="printer", server=re.compile(r"HP HTTP Server|Virata-EmWeb", re.I)),
    dict(name="HP printer", kind="printer", title=re.compile(r"HP LaserJet|HP OfficeJet|HP Color", re.I)),
    dict(name="Brother printer", kind="printer", server=re.compile(r"KS_HTTP|Brother", re.I)),
    dict(name="Epson printer", kind="printer", title=re.compile(r"EPSON|SEIKO EPSON", re.I)),
    dict(name="Canon printer", kind="printer", title=re.compile(r"Canon", re.I)),
    dict(name="Xerox printer", kind="printer", title=re.compile(r"Xerox", re.I)),
    dict(name="CUPS", kind="printer", server=re.compile(r"CUPS", re.I)),

    # --- Media / IoT ---
    dict(name="Plex", kind="media-server", header=re.compile(r"x-plex", re.I)),
    dict(name="Jellyfin/Emby", kind="media-server", header=re.compile(r"emby|jellyfin", re.I)),
    dict(name="Chromecast", kind="media-device", header=re.compile(r"Chromecast|Fuchsia", re.I)),
    dict(name="Roku", kind="media-device", server=re.compile(r"Roku", re.I)),
    dict(name="Sonos", kind="smart-speaker", server=re.compile(r"Sonos", re.I)),
    dict(name="Philips Hue", kind="iot-hub", body=re.compile(r"hue personal wireless", re.I)),
    dict(name="Tasmota", kind="iot-device", body=re.compile(r"Tasmota", re.I)),
    dict(name="ESPHome", kind="iot-device", body=re.compile(r"ESPHome|esphome", re.I)),
    dict(name="Shelly", kind="iot-device", title=re.compile(r"Shelly", re.I)),
    dict(name="Tuya/SmartLife", kind="iot-device", body=re.compile(r"tuya", re.I)),

    # --- Virtualisation / management ---
    dict(name="VMware ESXi", kind="hypervisor", title=re.compile(r"VMware ESXi|vSphere", re.I)),
    dict(name="Proxmox VE", kind="hypervisor", title=re.compile(r"Proxmox", re.I)),
    dict(name="iDRAC", kind="bmc", title=re.compile(r"iDRAC", re.I)),
    dict(name="iLO", kind="bmc", server=re.compile(r"HPE iLO|HP-iLO", re.I)),
    dict(name="Supermicro IPMI", kind="bmc", title=re.compile(r"ATEN|Supermicro", re.I)),
]


def identify(server="", headers_text="", title="", body=""):
    """
    Return a list of matched signatures as dicts {name, kind}. ``headers_text``
    should be the raw 'key: value\\n' header block (lowercased is fine).
    """
    matches = []
    seen = set()
    for sig in SIGNATURES:
        ok = False
        if "server" in sig and server and sig["server"].search(server):
            ok = True
        elif "header" in sig and headers_text and sig["header"].search(headers_text):
            ok = True
        elif "title" in sig and title and sig["title"].search(title):
            ok = True
        elif "body" in sig and body and sig["body"].search(body):
            ok = True
        if ok and sig["name"] not in seen:
            seen.add(sig["name"])
            matches.append({"name": sig["name"], "kind": sig["kind"]})
    return matches


def primary_kind(matches):
    """Pick the most specific device 'kind' from a set of matches."""
    priority = ["camera", "router", "firewall", "nas", "printer", "media-server",
                "media-device", "smart-speaker", "iot-hub", "iot-device",
                "hypervisor", "bmc", "db-admin", "admin-panel", "dashboard",
                "ci", "devtools", "cms", "app-server", "embedded-web", "web-server"]
    kinds = {m["kind"] for m in matches}
    for k in priority:
        if k in kinds:
            return k
    return None
'''

# ---------------------------------------------------------------------------
# module: scanfyx.data.oui_fallback
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.data.oui_fallback'] = r'''"""
Embedded OUI (MAC vendor) fallback table plus vendor->device-type hints.

When ``mac-vendor-lookup`` is installed SCANFY uses the full IEEE database;
this table is the offline fallback and also feeds device classification with
vendor-based hints.
"""

# 24-bit OUI prefix (aa:bb:cc) -> vendor name
OUI_PREFIXES = {
    "d8:eb:97": "TP-Link", "50:c7:bf": "TP-Link", "a4:2b:b0": "TP-Link",
    "00:1d:0f": "TP-Link", "b0:be:76": "TP-Link", "60:32:b1": "TP-Link",
    "cc:32:e5": "TP-Link", "f4:f2:6d": "TP-Link", "50:d4:f7": "TP-Link",
    "fc:ec:da": "Ubiquiti", "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "e0:63:da": "Ubiquiti", "68:d7:9a": "Ubiquiti", "b4:fb:e4": "Ubiquiti",
    "b8:27:eb": "Raspberry Pi Foundation", "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading", "28:cd:c1": "Raspberry Pi Trading",
    "ac:de:48": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "3c:07:54": "Apple", "d0:e1:40": "Apple", "bc:92:6b": "Apple",
    "f0:99:bf": "Apple", "90:72:40": "Apple", "a8:66:7f": "Apple",
    "68:96:7b": "Apple", "88:66:5a": "Apple", "dc:2b:2a": "Apple",
    "b8:e6:0c": "Apple", "f4:0f:24": "Apple", "70:ef:00": "Apple",
    "fc:fb:fb": "Cisco", "00:1b:54": "Cisco", "00:1a:a1": "Cisco",
    "00:24:14": "Cisco", "00:0c:85": "Cisco", "00:26:0b": "Cisco",
    "18:fe:34": "Espressif", "24:0a:c4": "Espressif", "a0:20:a6": "Espressif",
    "50:02:91": "Espressif", "24:6f:28": "Espressif", "7c:9e:bd": "Espressif",
    "c4:4f:33": "Espressif", "84:cc:a8": "Espressif", "3c:71:bf": "Espressif",
    "b4:e6:2d": "Espressif", "cc:50:e3": "Espressif", "d8:a0:1d": "Espressif",
    "00:12:fb": "Samsung", "5c:0a:5b": "Samsung", "78:1f:db": "Samsung",
    "8c:77:12": "Samsung", "34:23:87": "Samsung", "e8:50:8b": "Samsung",
    "50:32:75": "Samsung", "a0:21:95": "Samsung", "f0:5a:09": "Samsung",
    "00:24:e4": "Withings", "44:65:0d": "Amazon", "fc:65:de": "Amazon",
    "68:37:e9": "Amazon", "f0:81:73": "Amazon", "50:dc:e7": "Amazon",
    "74:c2:46": "Amazon", "b4:7c:9c": "Amazon", "ac:63:be": "Amazon",
    "f0:27:2d": "Xiaomi", "64:09:80": "Xiaomi", "28:6c:07": "Xiaomi",
    "c4:6a:b7": "Xiaomi", "78:11:dc": "Xiaomi", "50:8f:4c": "Xiaomi",
    "34:ce:00": "Xiaomi", "68:df:dd": "Xiaomi", "98:fa:e3": "Xiaomi",
    "d4:6a:6a": "Netgear", "a0:40:a0": "Netgear", "9c:d3:6d": "Netgear",
    "2c:30:33": "Netgear", "b0:7f:b9": "Netgear",
    "e0:b9:4d": "Intel", "94:65:9c": "Intel", "34:41:5d": "Intel",
    "60:45:cb": "Intel", "a4:c3:f0": "Intel", "8c:16:45": "Intel",
    "00:15:5d": "Microsoft (Hyper-V)", "00:03:ff": "Microsoft",
    "7c:1e:52": "Microsoft", "b4:2e:99": "Giga-Byte", "d8:5e:d3": "ASUS",
    "2c:56:dc": "ASUS", "04:d4:c4": "ASUS", "1c:87:2c": "ASUS",
    "ac:22:0b": "ASUS", "70:8b:cd": "ASUS",
    "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    "70:ee:50": "Netatmo", "18:b4:30": "Nest Labs", "64:16:66": "Nest Labs",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "b0:a7:37": "Roku", "cc:6d:a0": "Roku", "d0:4d:2c": "Roku",
    "00:04:4b": "NVIDIA", "48:b0:2d": "NVIDIA",
    "dc:44:6d": "Sonos", "94:9f:3e": "Sonos", "5c:aa:fd": "Sonos",
    "00:1e:c0": "Microchip", "b8:d7:af": "Murata", "f0:fa:c7": "Huawei",
    "4c:0f:c7": "Earda Technologies", "00:9d:6b": "TP-Link",
    "e8:9f:80": "Belkin", "94:10:3e": "Belkin", "08:86:3b": "Belkin",
    "d8:07:b6": "TP-Link", "d4:6e:0e": "TP-Link", "00:22:6b": "Cisco-Linksys",
    "00:1c:df": "Belkin", "00:0e:8f": "Sercomm", "40:16:7e": "ASUS",
    "b8:27:eb": "Raspberry Pi Foundation", "00:90:a9": "Western Digital",
    "00:14:ee": "Western Digital", "9c:8e:99": "Hewlett Packard",
    "3c:d9:2b": "Hewlett Packard", "70:5a:0f": "Hewlett Packard",
    "00:1b:78": "Hewlett Packard", "2c:41:38": "Hewlett Packard",
    "00:21:5a": "Hewlett Packard", "38:63:bb": "Hewlett Packard",
    "d0:bf:9c": "Hewlett Packard", "00:17:a4": "Hewlett Packard",
    "00:26:73": "Ricoh", "00:00:74": "Ricoh", "00:80:92": "Kyocera",
    "00:23:32": "Apple", "00:cd:fe": "Apple", "40:cb:c0": "Apple",
    "6c:40:08": "Apple", "84:38:35": "Apple", "9c:20:7b": "Apple",
    "b8:53:ac": "Apple", "d8:96:95": "Apple",
    "00:80:77": "Brother", "30:05:5c": "Brother", "00:1b:a9": "Brother",
    "00:26:ab": "Seiko Epson", "00:00:48": "Seiko Epson", "38:1a:52": "Seiko Epson",
    "00:1e:8f": "Canon", "88:87:17": "Canon", "2c:9e:fc": "Canon",
    "00:60:e9": "Hitachi", "00:0f:b0": "Compal", "00:c0:ee": "Kyocera",
}


# Substring in vendor name -> hinted device type (used by the classifier).
VENDOR_DEVICE_HINTS = {
    "raspberry pi": "Single-board computer",
    "espressif": "IoT microcontroller (ESP)",
    "philips hue": "Smart lighting",
    "nest": "Smart-home device",
    "sonos": "Smart speaker",
    "roku": "Streaming media player",
    "amazon": "Amazon device / Echo",
    "withings": "Health / wearable",
    "netatmo": "Smart-home sensor",
    "apple": "Apple device",
    "samsung": "Samsung device",
    "xiaomi": "Xiaomi device",
    "huawei": "Huawei device",
    "tp-link": "Network equipment",
    "ubiquiti": "Network equipment",
    "netgear": "Network equipment",
    "cisco": "Network equipment",
    "asus": "Router / PC",
    "mikrotik": "Router",
    "hewlett packard": "HP printer / PC",
    "ricoh": "Printer",
    "kyocera": "Printer",
    "brother": "Printer",
    "seiko epson": "Printer",
    "canon": "Printer / camera",
    "western digital": "NAS / storage",
    "synology": "NAS",
    "qnap": "NAS",
    "hyper-v": "Virtual machine",
    "vmware": "Virtual machine",
    "virtualbox": "Virtual machine",
    "qemu": "Virtual machine",
    "xen": "Virtual machine",
    "realtek": "PC / generic NIC",
    "intel": "PC / laptop",
    "microsoft": "Windows device / Xbox",
    "nvidia": "PC / Shield",
    "belkin": "Network equipment",
    "sercomm": "ISP router / camera",
    "dahua": "IP camera / DVR",
    "hikvision": "IP camera / NVR",
    "earda": "Smart-home device",
}


def lookup(mac):
    prefix = (mac or "").lower()[:8]
    return OUI_PREFIXES.get(prefix, "unknown")


def device_hint_for_vendor(vendor):
    if not vendor:
        return None
    v = vendor.lower()
    for needle, hint in VENDOR_DEVICE_HINTS.items():
        if needle in v:
            return hint
    return None
'''

# ---------------------------------------------------------------------------
# module: scanfyx.data.services
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.data.services'] = r'''"""
Port / service reference data.

``PORT_SERVICES`` maps a TCP/UDP port number to ``(name, category, description)``.
The categories drive parts of the classification and security engines.

This is curated reference data (IANA + common real-world usage), not an
exhaustive dump - it focuses on ports that matter for LAN reconnaissance.
"""

# category constants
CAT_WEB = "web"
CAT_REMOTE = "remote"
CAT_FILE = "file"
CAT_MAIL = "mail"
CAT_DB = "database"
CAT_DIR = "directory"
CAT_NAME = "naming"
CAT_MEDIA = "media"
CAT_PRINT = "printing"
CAT_IOT = "iot"
CAT_VOIP = "voip"
CAT_MGMT = "management"
CAT_PROXY = "proxy"
CAT_MSG = "messaging"
CAT_INDUSTRIAL = "industrial"
CAT_MISC = "misc"


PORT_SERVICES = {
    7: ("echo", CAT_MISC, "Echo protocol"),
    9: ("discard", CAT_MISC, "Discard / Wake-on-LAN"),
    13: ("daytime", CAT_MISC, "Daytime protocol"),
    19: ("chargen", CAT_MISC, "Character generator (DDoS amplifier)"),
    20: ("ftp-data", CAT_FILE, "FTP data channel"),
    21: ("ftp", CAT_FILE, "File Transfer Protocol control"),
    22: ("ssh", CAT_REMOTE, "Secure Shell / SFTP"),
    23: ("telnet", CAT_REMOTE, "Telnet (cleartext remote shell)"),
    25: ("smtp", CAT_MAIL, "Simple Mail Transfer Protocol"),
    37: ("time", CAT_MISC, "Time protocol"),
    42: ("wins", CAT_NAME, "WINS name service"),
    43: ("whois", CAT_MISC, "WHOIS directory"),
    49: ("tacacs", CAT_MGMT, "TACACS+ AAA"),
    53: ("dns", CAT_NAME, "Domain Name System"),
    67: ("dhcp-server", CAT_NAME, "DHCP server"),
    68: ("dhcp-client", CAT_NAME, "DHCP client"),
    69: ("tftp", CAT_FILE, "Trivial FTP"),
    70: ("gopher", CAT_WEB, "Gopher protocol"),
    79: ("finger", CAT_MISC, "Finger user information"),
    80: ("http", CAT_WEB, "HyperText Transfer Protocol"),
    81: ("http-alt", CAT_WEB, "Alternate HTTP (often cameras/routers)"),
    88: ("kerberos", CAT_DIR, "Kerberos authentication"),
    102: ("iso-tsap", CAT_INDUSTRIAL, "Siemens S7 / ISO-TSAP"),
    110: ("pop3", CAT_MAIL, "Post Office Protocol v3"),
    111: ("rpcbind", CAT_MGMT, "ONC RPC portmapper"),
    113: ("ident", CAT_MISC, "Ident authentication"),
    119: ("nntp", CAT_MSG, "Network News Transfer Protocol"),
    123: ("ntp", CAT_MISC, "Network Time Protocol"),
    135: ("msrpc", CAT_MGMT, "Microsoft RPC endpoint mapper"),
    137: ("netbios-ns", CAT_NAME, "NetBIOS name service"),
    138: ("netbios-dgm", CAT_FILE, "NetBIOS datagram service"),
    139: ("netbios-ssn", CAT_FILE, "NetBIOS session (SMB over NetBIOS)"),
    143: ("imap", CAT_MAIL, "Internet Message Access Protocol"),
    161: ("snmp", CAT_MGMT, "Simple Network Management Protocol"),
    162: ("snmp-trap", CAT_MGMT, "SNMP trap"),
    179: ("bgp", CAT_MGMT, "Border Gateway Protocol"),
    194: ("irc", CAT_MSG, "Internet Relay Chat"),
    389: ("ldap", CAT_DIR, "Lightweight Directory Access Protocol"),
    443: ("https", CAT_WEB, "HTTP over TLS"),
    445: ("microsoft-ds", CAT_FILE, "SMB over TCP (Windows file sharing)"),
    465: ("smtps", CAT_MAIL, "SMTP over TLS"),
    500: ("isakmp", CAT_REMOTE, "IKE / IPsec VPN"),
    502: ("modbus", CAT_INDUSTRIAL, "Modbus TCP (industrial control)"),
    512: ("exec", CAT_REMOTE, "Remote process execution"),
    513: ("login", CAT_REMOTE, "rlogin"),
    514: ("syslog", CAT_MGMT, "Syslog / remote shell"),
    515: ("printer", CAT_PRINT, "LPD / LPR line printer daemon"),
    520: ("rip", CAT_MGMT, "Routing Information Protocol"),
    523: ("db2", CAT_DB, "IBM Db2"),
    540: ("uucp", CAT_FILE, "Unix-to-Unix Copy"),
    543: ("klogin", CAT_REMOTE, "Kerberos login"),
    544: ("kshell", CAT_REMOTE, "Kerberos remote shell"),
    546: ("dhcpv6-client", CAT_NAME, "DHCPv6 client"),
    547: ("dhcpv6-server", CAT_NAME, "DHCPv6 server"),
    548: ("afp", CAT_FILE, "Apple Filing Protocol"),
    554: ("rtsp", CAT_MEDIA, "Real Time Streaming Protocol (cameras)"),
    587: ("submission", CAT_MAIL, "SMTP mail submission"),
    591: ("http-alt", CAT_WEB, "FileMaker HTTP"),
    593: ("http-rpc-epmap", CAT_MGMT, "RPC over HTTP endpoint mapper"),
    623: ("ipmi", CAT_MGMT, "IPMI / BMC out-of-band management"),
    631: ("ipp", CAT_PRINT, "Internet Printing Protocol / CUPS"),
    636: ("ldaps", CAT_DIR, "LDAP over TLS"),
    646: ("ldp", CAT_MGMT, "Label Distribution Protocol"),
    873: ("rsync", CAT_FILE, "rsync file synchronisation"),
    902: ("vmware", CAT_MGMT, "VMware ESXi/authd"),
    989: ("ftps-data", CAT_FILE, "FTP data over TLS"),
    990: ("ftps", CAT_FILE, "FTP over TLS"),
    993: ("imaps", CAT_MAIL, "IMAP over TLS"),
    995: ("pop3s", CAT_MAIL, "POP3 over TLS"),
    1080: ("socks", CAT_PROXY, "SOCKS proxy"),
    1099: ("java-rmi", CAT_MGMT, "Java RMI registry"),
    1194: ("openvpn", CAT_REMOTE, "OpenVPN"),
    1234: ("vlc", CAT_MEDIA, "VLC / stream"),
    1433: ("ms-sql", CAT_DB, "Microsoft SQL Server"),
    1434: ("ms-sql-m", CAT_DB, "MSSQL monitor"),
    1521: ("oracle", CAT_DB, "Oracle database listener"),
    1604: ("citrix-ica", CAT_REMOTE, "Citrix ICA"),
    1701: ("l2tp", CAT_REMOTE, "L2TP VPN"),
    1723: ("pptp", CAT_REMOTE, "PPTP VPN (legacy)"),
    1812: ("radius", CAT_MGMT, "RADIUS authentication"),
    1883: ("mqtt", CAT_IOT, "MQTT message broker"),
    1900: ("ssdp", CAT_IOT, "SSDP / UPnP discovery"),
    2000: ("cisco-sccp", CAT_VOIP, "Cisco SCCP / callmanager"),
    2049: ("nfs", CAT_FILE, "Network File System"),
    2082: ("cpanel", CAT_WEB, "cPanel"),
    2083: ("cpanel-ssl", CAT_WEB, "cPanel over TLS"),
    2087: ("whm-ssl", CAT_WEB, "WHM over TLS"),
    2095: ("webmail", CAT_WEB, "cPanel webmail"),
    2181: ("zookeeper", CAT_MGMT, "Apache ZooKeeper"),
    2222: ("ssh-alt", CAT_REMOTE, "Alternate SSH / DirectAdmin"),
    2323: ("telnet-alt", CAT_REMOTE, "Alternate Telnet (IoT botnets)"),
    2375: ("docker", CAT_MGMT, "Docker API (unencrypted)"),
    2376: ("docker-tls", CAT_MGMT, "Docker API over TLS"),
    2455: ("wago", CAT_INDUSTRIAL, "WAGO PLC"),
    2483: ("oracle-db", CAT_DB, "Oracle DB (no TLS)"),
    2484: ("oracle-db-ssl", CAT_DB, "Oracle DB over TLS"),
    2601: ("zebra", CAT_MGMT, "Quagga/Zebra routing shell"),
    2604: ("ospfd", CAT_MGMT, "Quagga OSPF shell"),
    2701: ("sms-remctrl", CAT_MGMT, "SCCM remote control"),
    3000: ("http-dev", CAT_WEB, "Dev server / Grafana"),
    3128: ("squid", CAT_PROXY, "Squid HTTP proxy"),
    3260: ("iscsi", CAT_FILE, "iSCSI target"),
    3268: ("globalcat", CAT_DIR, "AD Global Catalog"),
    3283: ("apple-remote", CAT_REMOTE, "Apple Remote Desktop"),
    3306: ("mysql", CAT_DB, "MySQL / MariaDB"),
    3333: ("http-alt", CAT_WEB, "Alternate HTTP / mining"),
    3389: ("rdp", CAT_REMOTE, "Microsoft Remote Desktop"),
    3478: ("stun", CAT_VOIP, "STUN/TURN (WebRTC)"),
    3632: ("distcc", CAT_MGMT, "distcc distributed compiler"),
    3689: ("daap", CAT_MEDIA, "Apple DAAP (iTunes)"),
    3690: ("svn", CAT_FILE, "Subversion"),
    3702: ("ws-discovery", CAT_IOT, "WS-Discovery (printers/cameras)"),
    4000: ("http-alt", CAT_WEB, "Alt HTTP"),
    4022: ("dnox", CAT_MISC, "dnox"),
    4040: ("spark-ui", CAT_WEB, "Spark / ngrok dashboard"),
    4444: ("metasploit", CAT_MISC, "Common backdoor/Metasploit handler"),
    4500: ("ipsec-nat", CAT_REMOTE, "IPsec NAT traversal"),
    4567: ("http-alt", CAT_WEB, "Sinatra / dev"),
    4711: ("mcafee", CAT_MGMT, "McAfee ePO"),
    4786: ("smart-install", CAT_MGMT, "Cisco Smart Install"),
    4840: ("opc-ua", CAT_INDUSTRIAL, "OPC-UA industrial"),
    4899: ("radmin", CAT_REMOTE, "Radmin remote control"),
    5000: ("upnp-http", CAT_IOT, "UPnP / Flask / Synology"),
    5001: ("http-alt", CAT_WEB, "Synology / iperf"),
    5006: ("mxit", CAT_INDUSTRIAL, "Beckhoff ADS"),
    5009: ("airport-admin", CAT_MGMT, "Apple AirPort admin"),
    5060: ("sip", CAT_VOIP, "Session Initiation Protocol"),
    5061: ("sips", CAT_VOIP, "SIP over TLS"),
    5222: ("xmpp", CAT_MSG, "XMPP client (Jabber)"),
    5269: ("xmpp-server", CAT_MSG, "XMPP server-to-server"),
    5353: ("mdns", CAT_NAME, "Multicast DNS / Bonjour"),
    5357: ("wsdapi", CAT_IOT, "Microsoft WSDAPI"),
    5432: ("postgresql", CAT_DB, "PostgreSQL"),
    5555: ("adb", CAT_REMOTE, "Android Debug Bridge / HP data"),
    5601: ("kibana", CAT_WEB, "Kibana dashboard"),
    5672: ("amqp", CAT_MSG, "AMQP / RabbitMQ"),
    5683: ("coap", CAT_IOT, "Constrained Application Protocol"),
    5800: ("vnc-http", CAT_REMOTE, "VNC over HTTP"),
    5900: ("vnc", CAT_REMOTE, "Virtual Network Computing"),
    5901: ("vnc-1", CAT_REMOTE, "VNC display :1"),
    5938: ("teamviewer", CAT_REMOTE, "TeamViewer"),
    5984: ("couchdb", CAT_DB, "Apache CouchDB"),
    5985: ("winrm-http", CAT_REMOTE, "WinRM / PowerShell remoting"),
    5986: ("winrm-https", CAT_REMOTE, "WinRM over TLS"),
    6000: ("x11", CAT_REMOTE, "X11 display server"),
    6379: ("redis", CAT_DB, "Redis key-value store"),
    6443: ("kubernetes", CAT_MGMT, "Kubernetes API server"),
    6514: ("syslog-tls", CAT_MGMT, "Syslog over TLS"),
    6566: ("sane", CAT_PRINT, "SANE scanner daemon"),
    6600: ("mpd", CAT_MEDIA, "Music Player Daemon"),
    6667: ("irc", CAT_MSG, "IRC"),
    6697: ("ircs", CAT_MSG, "IRC over TLS"),
    7000: ("afs-airplay", CAT_MEDIA, "AFS / AirPlay"),
    7001: ("weblogic", CAT_WEB, "Oracle WebLogic"),
    7070: ("realserver", CAT_MEDIA, "RealServer / AnyConnect"),
    7443: ("https-alt", CAT_WEB, "Alt HTTPS"),
    7547: ("cwmp", CAT_MGMT, "TR-069 CPE WAN management"),
    7657: ("http-alt", CAT_WEB, "i2p / alt HTTP"),
    8000: ("http-alt", CAT_WEB, "Alternate HTTP / IoT"),
    8008: ("http-alt", CAT_WEB, "Chromecast / alt HTTP"),
    8009: ("ajp13", CAT_WEB, "Apache JServ Protocol / Chromecast"),
    8060: ("roku", CAT_MEDIA, "Roku ECP"),
    8080: ("http-proxy", CAT_WEB, "HTTP proxy / alt web"),
    8081: ("http-alt", CAT_WEB, "Alt HTTP"),
    8085: ("http-alt", CAT_WEB, "Alt HTTP"),
    8086: ("influxdb", CAT_DB, "InfluxDB"),
    8088: ("http-alt", CAT_WEB, "Hadoop / Radarr"),
    8096: ("jellyfin", CAT_MEDIA, "Jellyfin / Emby"),
    8123: ("home-assistant", CAT_IOT, "Home Assistant"),
    8181: ("http-alt", CAT_WEB, "Alt HTTP / GitLab"),
    8291: ("winbox", CAT_MGMT, "MikroTik Winbox"),
    8333: ("bitcoin", CAT_MISC, "Bitcoin P2P"),
    8388: ("shadowsocks", CAT_PROXY, "Shadowsocks proxy"),
    8443: ("https-alt", CAT_WEB, "Alternate HTTPS / admin panels"),
    8500: ("consul", CAT_MGMT, "HashiCorp Consul"),
    8554: ("rtsp-alt", CAT_MEDIA, "Alternate RTSP"),
    8728: ("mikrotik-api", CAT_MGMT, "MikroTik RouterOS API"),
    8729: ("mikrotik-api-ssl", CAT_MGMT, "MikroTik API over TLS"),
    8760: ("http-alt", CAT_WEB, "Alt HTTP"),
    8765: ("http-alt", CAT_WEB, "Alt HTTP"),
    8834: ("nessus", CAT_MGMT, "Nessus scanner UI"),
    8880: ("http-alt", CAT_WEB, "Alt HTTP / UniFi"),
    8883: ("mqtt-tls", CAT_IOT, "MQTT over TLS"),
    8888: ("http-alt", CAT_WEB, "Jupyter / alt HTTP"),
    8983: ("solr", CAT_DB, "Apache Solr"),
    9000: ("http-alt", CAT_WEB, "PHP-FPM / Portainer / SonarQube"),
    9001: ("tor", CAT_PROXY, "Tor OR / Supervisor"),
    9042: ("cassandra", CAT_DB, "Apache Cassandra CQL"),
    9090: ("prometheus", CAT_MGMT, "Prometheus / Cockpit"),
    9100: ("jetdirect", CAT_PRINT, "HP JetDirect raw printing"),
    9200: ("elasticsearch", CAT_DB, "Elasticsearch"),
    9300: ("elastic-node", CAT_DB, "Elasticsearch node transport"),
    9418: ("git", CAT_FILE, "Git protocol"),
    9443: ("https-alt", CAT_WEB, "Alt HTTPS / VMware"),
    9595: ("landesk", CAT_MGMT, "LANDesk ping"),
    9999: ("http-alt", CAT_WEB, "Alt HTTP / Telnet backdoor"),
    10000: ("webmin", CAT_MGMT, "Webmin admin panel"),
    10250: ("kubelet", CAT_MGMT, "Kubernetes kubelet"),
    11211: ("memcached", CAT_DB, "Memcached (amplifier)"),
    15672: ("rabbitmq-mgmt", CAT_MSG, "RabbitMQ management UI"),
    16992: ("intel-amt", CAT_MGMT, "Intel AMT management"),
    16993: ("intel-amt-tls", CAT_MGMT, "Intel AMT over TLS"),
    17500: ("dropbox", CAT_MISC, "Dropbox LAN sync"),
    18080: ("monero", CAT_MISC, "Monero / alt HTTP"),
    19999: ("netdata", CAT_MGMT, "Netdata dashboard"),
    20000: ("dnp3", CAT_INDUSTRIAL, "DNP3 / Usermin"),
    23023: ("telnet-alt", CAT_REMOTE, "Alt Telnet"),
    25565: ("minecraft", CAT_MISC, "Minecraft server"),
    27017: ("mongodb", CAT_DB, "MongoDB"),
    27018: ("mongodb-shard", CAT_DB, "MongoDB shard"),
    28017: ("mongodb-http", CAT_DB, "MongoDB HTTP status"),
    32400: ("plex", CAT_MEDIA, "Plex Media Server"),
    32764: ("router-backdoor", CAT_MGMT, "Known router backdoor"),
    33060: ("mysqlx", CAT_DB, "MySQL X protocol"),
    37777: ("dahua", CAT_MEDIA, "Dahua DVR/camera"),
    44158: ("helium", CAT_IOT, "Helium miner"),
    47808: ("bacnet", CAT_INDUSTRIAL, "BACnet building automation"),
    49152: ("upnp", CAT_IOT, "UPnP dynamic / Supermicro"),
    49153: ("upnp", CAT_IOT, "UPnP dynamic"),
    50000: ("sap", CAT_MGMT, "SAP / DB2"),
    51820: ("wireguard", CAT_REMOTE, "WireGuard VPN"),
    54321: ("http-alt", CAT_WEB, "Alt HTTP"),
    55443: ("http-alt", CAT_WEB, "Alt HTTP"),
    62078: ("apple-iphone-sync", CAT_MGMT, "iPhone lockdown/usbmux"),
    64738: ("mumble", CAT_VOIP, "Mumble voice server"),
}


# Ports that speak HTTP(S) - drives the web fingerprinter.
HTTP_PORTS = {80, 81, 591, 2082, 2095, 3000, 3333, 4040, 4567, 5000, 5001,
              5601, 7001, 8000, 8008, 8080, 8081, 8085, 8086, 8088, 8096,
              8123, 8181, 8443, 8880, 8888, 9000, 9090, 9200, 10000, 15672,
              19999, 32400}
HTTPS_PORTS = {443, 2083, 2087, 2096, 4433, 5986, 7443, 8443, 9443, 7071}
TLS_PORTS = {443, 465, 636, 989, 990, 993, 995, 5061, 5986, 6514, 8443, 9443}

WEB_PROBE_ORDER = [
    (443, "https"), (80, "http"), (8443, "https"), (8080, "http"),
    (8000, "http"), (8888, "http"), (5000, "http"), (9000, "http"),
    (81, "http"), (8081, "http"), (8008, "http"), (3000, "http"),
    (8123, "http"), (9090, "http"), (10000, "https"),
]


# nmap-style "top" TCP ports for the fast scan profile.
TOP_100_TCP = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

# A pragmatic default scan set - the union of top ports and juicy targets.
DEFAULT_SCAN_PORTS = sorted(set(TOP_100_TCP) | set(PORT_SERVICES.keys()))

# UDP ports worth a probe.
UDP_PROBE_PORTS = [53, 67, 123, 137, 161, 500, 1900, 5353, 5060, 47808, 623,
                   69, 111, 520, 4500, 27015]


def service_name(port):
    entry = PORT_SERVICES.get(int(port)) if str(port).isdigit() else None
    return entry[0] if entry else str(port)


def service_category(port):
    entry = PORT_SERVICES.get(int(port)) if str(port).isdigit() else None
    return entry[1] if entry else CAT_MISC


def service_description(port):
    entry = PORT_SERVICES.get(int(port)) if str(port).isdigit() else None
    return entry[2] if entry else "Unknown service"


def is_http_port(port):
    return int(port) in HTTP_PORTS or int(port) in HTTPS_PORTS


def is_tls_port(port):
    return int(port) in TLS_PORTS or int(port) in HTTPS_PORTS


def describe(port):
    """Return a dict describing a port for reports."""
    name, cat, desc = PORT_SERVICES.get(
        int(port), (str(port), CAT_MISC, "Unknown service"))
    return {"port": int(port), "name": name, "category": cat, "description": desc}
'''

# ---------------------------------------------------------------------------
# module: scanfyx.data.vuln_db
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.data.vuln_db'] = r'''"""
Security knowledge base: exposed-service risk rules, TLS weakness catalogue,
missing-HTTP-header checks, default-credential hints and a curated
service/version -> CVE correlation table.

This is heuristic reconnaissance guidance, not an authoritative vulnerability
scanner. Findings are meant to prioritise manual review.
"""

import re

# ---------------------------------------------------------------------------
# Exposed-service risk rules keyed by port.
# Each rule: severity, title, description, recommendation.
# ---------------------------------------------------------------------------
SERVICE_RISKS = {
    23: dict(severity="high", title="Telnet exposed",
             description="Telnet transmits credentials and data in cleartext and "
                         "is a primary target of IoT botnets (Mirai).",
             recommendation="Disable Telnet and use SSH instead."),
    2323: dict(severity="high", title="Alternate Telnet exposed",
               description="Non-standard Telnet port, commonly abused by IoT malware.",
               recommendation="Disable Telnet; restrict management interfaces."),
    2049: dict(severity="high", title="NFS export exposed",
               description="Network File System may expose file shares without "
                           "strong authentication.",
               recommendation="Restrict NFS to trusted hosts; require auth."),
    6379: dict(severity="high", title="Redis exposed",
               description="Redis is frequently deployed without authentication, "
                           "allowing full data access and sometimes RCE.",
               recommendation="Enable requirepass/ACL and bind to localhost."),
    27017: dict(severity="high", title="MongoDB exposed",
                description="MongoDB has historically shipped unauthenticated, "
                            "leading to mass data breaches.",
                recommendation="Enable authentication and bind to trusted nets."),
    11211: dict(severity="high", title="Memcached exposed",
                description="Memcached has no auth and is a UDP DDoS amplifier.",
                recommendation="Bind to localhost; disable UDP."),
    9200: dict(severity="high", title="Elasticsearch exposed",
               description="Open Elasticsearch instances have caused major leaks.",
               recommendation="Enable security features; restrict access."),
    5984: dict(severity="high", title="CouchDB exposed",
               description="CouchDB admin party / RCE risk when unauthenticated.",
               recommendation="Set admin credentials; restrict network."),
    32764: dict(severity="critical", title="Router backdoor port",
                description="TCP/32764 is a known consumer-router backdoor.",
                recommendation="Patch firmware; the device may be compromised."),
    4444: dict(severity="high", title="Common backdoor/Metasploit port",
               description="Port 4444 is a default Metasploit/handler port.",
               recommendation="Investigate the listening process immediately."),
    445: dict(severity="medium", title="SMB exposed",
              description="SMB file sharing is a frequent lateral-movement and "
                          "ransomware vector (EternalBlue, SMBGhost).",
              recommendation="Patch, disable SMBv1, restrict to trusted hosts."),
    139: dict(severity="medium", title="NetBIOS session exposed",
              description="Legacy NetBIOS/SMB sharing surface.",
              recommendation="Disable NetBIOS over TCP/IP where possible."),
    137: dict(severity="low", title="NetBIOS name service exposed",
              description="Leaks hostnames and can be used for spoofing.",
              recommendation="Disable NetBIOS over TCP/IP."),
    3389: dict(severity="medium", title="RDP exposed",
               description="Remote Desktop is a top brute-force/ransomware entry "
                           "point (BlueKeep).",
               recommendation="Require NLA + MFA; restrict via VPN/firewall."),
    5900: dict(severity="medium", title="VNC exposed",
               description="VNC is often unauthenticated or weakly authenticated.",
               recommendation="Require strong auth; tunnel over SSH/VPN."),
    5800: dict(severity="low", title="VNC over HTTP exposed",
               description="Web-based VNC access surface.",
               recommendation="Restrict and authenticate."),
    21: dict(severity="medium", title="FTP exposed",
             description="FTP is cleartext and frequently allows anonymous access.",
             recommendation="Use SFTP/FTPS; disable anonymous login."),
    3306: dict(severity="medium", title="MySQL/MariaDB exposed",
               description="Database directly reachable on the network.",
               recommendation="Bind to localhost; use least-privilege accounts."),
    5432: dict(severity="medium", title="PostgreSQL exposed",
               description="Database directly reachable on the network.",
               recommendation="Restrict pg_hba.conf; bind to trusted nets."),
    1433: dict(severity="medium", title="Microsoft SQL Server exposed",
               description="MSSQL reachable; brute-force and RCE surface.",
               recommendation="Restrict access; strong sa password/disable sa."),
    1521: dict(severity="medium", title="Oracle DB listener exposed",
               description="Oracle listener reachable on the network.",
               recommendation="Restrict access; patch; strong credentials."),
    9042: dict(severity="medium", title="Cassandra exposed",
               description="Cassandra CQL reachable; often unauthenticated.",
               recommendation="Enable authentication; restrict access."),
    8086: dict(severity="medium", title="InfluxDB exposed",
               description="Time-series DB reachable; may be unauthenticated.",
               recommendation="Enable auth; restrict access."),
    161: dict(severity="medium", title="SNMP exposed",
              description="SNMP with default community strings (public/private) "
                          "leaks device internals and can allow writes.",
              recommendation="Use SNMPv3; change community strings; restrict."),
    623: dict(severity="high", title="IPMI/BMC exposed",
              description="Out-of-band BMC management has severe historical CVEs "
                          "(cipher-zero auth bypass, hash leak).",
              recommendation="Isolate BMC on a management VLAN; patch firmware."),
    16992: dict(severity="high", title="Intel AMT exposed",
                description="Intel AMT has had auth-bypass CVEs (CVE-2017-5689).",
                recommendation="Patch/disable AMT; restrict to management net."),
    2375: dict(severity="critical", title="Docker API exposed (no TLS)",
               description="Unauthenticated Docker API allows host takeover.",
               recommendation="Never expose 2375; use TLS + auth on 2376."),
    6443: dict(severity="high", title="Kubernetes API exposed",
               description="K8s API server reachable; verify anonymous auth off.",
               recommendation="Enforce RBAC; restrict API access."),
    10250: dict(severity="high", title="Kubelet exposed",
                description="Kubelet API can allow command execution in pods.",
                recommendation="Enable authn/authz; restrict access."),
    7547: dict(severity="medium", title="TR-069 (CWMP) exposed",
               description="CPE WAN management has been exploited at ISP scale.",
               recommendation="Restrict to ISP ACS; patch (CVE-2017-17215 etc.)."),
    8291: dict(severity="medium", title="MikroTik Winbox exposed",
               description="Winbox has had auth-bypass CVEs (CVE-2018-14847).",
               recommendation="Update RouterOS; restrict management access."),
    502: dict(severity="high", title="Modbus exposed",
              description="Industrial Modbus has no authentication.",
              recommendation="Air-gap/segment OT; use firewalls & gateways."),
    47808: dict(severity="high", title="BACnet exposed",
                description="Building-automation protocol without authentication.",
                recommendation="Segment OT network; restrict access."),
    20000: dict(severity="high", title="DNP3 exposed",
                description="SCADA protocol commonly unauthenticated.",
                recommendation="Segment OT; deploy DNP3 secure authentication."),
    5555: dict(severity="high", title="Android Debug Bridge exposed",
               description="Open ADB allows full device control / malware.",
               recommendation="Disable network ADB immediately."),
    9100: dict(severity="low", title="Raw printing (JetDirect) exposed",
               description="Raw print port can be abused to exfil/print spam.",
               recommendation="Restrict printer access; disable if unused."),
    515: dict(severity="low", title="LPD printing exposed",
              description="Legacy line-printer daemon reachable.",
              recommendation="Restrict printer access."),
    111: dict(severity="low", title="RPC portmapper exposed",
              description="Portmapper enumerates RPC services (NFS, etc.).",
              recommendation="Restrict RPC; disable if unused."),
    69: dict(severity="medium", title="TFTP exposed",
             description="TFTP has no authentication and enables file theft.",
             recommendation="Disable TFTP or restrict to provisioning nets."),
    1900: dict(severity="low", title="UPnP/SSDP exposed",
               description="UPnP can auto-open firewall holes and is a DDoS "
                           "amplifier.",
               recommendation="Disable UPnP on the router if not required."),
    19: dict(severity="medium", title="CHARGEN exposed",
             description="Character generator is a DDoS amplification vector.",
             recommendation="Disable the service."),
    512: dict(severity="high", title="rexec exposed",
              description="Berkeley r-services send credentials in cleartext.",
              recommendation="Disable r-services; use SSH."),
    513: dict(severity="high", title="rlogin exposed",
              description="rlogin trusts host-based auth and is cleartext.",
              recommendation="Disable r-services; use SSH."),
    514: dict(severity="medium", title="rsh/syslog exposed",
              description="rsh is insecure; open syslog may accept remote logs.",
              recommendation="Disable rsh; restrict syslog sources."),
    873: dict(severity="low", title="rsync exposed",
              description="Open rsync modules may allow file read/write.",
              recommendation="Require auth; restrict modules."),
    2601: dict(severity="medium", title="Zebra/Quagga routing shell exposed",
               description="Routing daemon shell reachable (default password).",
               recommendation="Change passwords; restrict access."),
}


# ---------------------------------------------------------------------------
# TLS weaknesses (protocol versions and cert issues).
# ---------------------------------------------------------------------------
TLS_WEAKNESSES = {
    "SSLv2": dict(severity="critical", note="SSLv2 is fundamentally broken."),
    "SSLv3": dict(severity="high", note="SSLv3 is vulnerable to POODLE."),
    "TLSv1": dict(severity="medium", note="TLS 1.0 is deprecated (PCI-DSS ban)."),
    "TLSv1.1": dict(severity="medium", note="TLS 1.1 is deprecated."),
    "self-signed": dict(severity="low", note="Self-signed certificate (no trust chain)."),
    "expired": dict(severity="medium", note="Certificate is expired."),
    "not-yet-valid": dict(severity="low", note="Certificate not yet valid."),
    "weak-key": dict(severity="medium", note="RSA key smaller than 2048 bits."),
    "weak-sig": dict(severity="medium", note="Certificate signed with MD5/SHA-1."),
    "wildcard": dict(severity="info", note="Wildcard certificate in use."),
}


# ---------------------------------------------------------------------------
# HTTP security headers that should be present on web apps.
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "strict-transport-security": ("low", "HSTS not set (allows TLS downgrade)."),
    "content-security-policy": ("low", "CSP not set (weaker XSS defence)."),
    "x-frame-options": ("info", "X-Frame-Options not set (clickjacking)."),
    "x-content-type-options": ("info", "X-Content-Type-Options not set (MIME sniff)."),
    "referrer-policy": ("info", "Referrer-Policy not set."),
}

# Server headers that leak version details worth flagging.
VERSION_LEAK_HINT = ("info", "Server banner leaks software/version details.")


# ---------------------------------------------------------------------------
# Services commonly shipped with default / weak credentials.
# ---------------------------------------------------------------------------
DEFAULT_CRED_HINTS = {
    "snmp": "public/private community strings",
    "telnet": "admin/admin, root/root, admin/(blank)",
    "ftp": "anonymous / ftp",
    "rtsp": "admin/admin, admin/12345 (cameras)",
    "vnc": "no password / weak password",
    "mongodb": "no authentication",
    "redis": "no authentication",
    "jetdirect": "no authentication",
    "webmin": "admin/admin",
    "ipmi": "ADMIN/ADMIN, admin/admin",
    "grafana": "admin/admin",
    "tomcat": "tomcat/tomcat, admin/admin",
    "jenkins": "admin/admin",
    "elasticsearch": "no authentication (default)",
}


# ---------------------------------------------------------------------------
# Curated service+version -> CVE hints. Patterns match against a banner or a
# 'product/version' string. These are indicative pointers, not confirmations.
# ---------------------------------------------------------------------------
CVE_HINTS = [
    dict(match=re.compile(r"OpenSSH[_/ ]?([0-6]\.|7\.[0-6])", re.I),
         cves=["CVE-2016-6210", "CVE-2016-0777"],
         note="Old OpenSSH: user enumeration / roaming info leak."),
    dict(match=re.compile(r"OpenSSH[_/ ]?([0-8]\.[0-9])", re.I),
         cves=["CVE-2023-38408"],
         note="OpenSSH < 9.3p2 ssh-agent RCE (if agent forwarding)."),
    dict(match=re.compile(r"vsftpd 2\.3\.4", re.I),
         cves=["CVE-2011-2523"], note="vsftpd 2.3.4 backdoor (smiley)."),
    dict(match=re.compile(r"ProFTPD 1\.3\.[0-3]", re.I),
         cves=["CVE-2010-4221", "CVE-2015-3306"],
         note="ProFTPD mod_copy / response overflow."),
    dict(match=re.compile(r"Apache/2\.4\.(4[0-9]|[0-4][0-9])\b", re.I),
         cves=["CVE-2021-41773", "CVE-2021-42013"],
         note="Apache 2.4.49/2.4.50 path traversal / RCE."),
    dict(match=re.compile(r"Apache/2\.2\.", re.I),
         cves=["CVE-2017-15715"], note="Apache 2.2.x end-of-life; multiple CVEs."),
    dict(match=re.compile(r"nginx/1\.(1[0-9]|[0-9])\.", re.I),
         cves=[], note="Older nginx; verify against latest security advisories."),
    dict(match=re.compile(r"Microsoft-IIS/[567]\.", re.I),
         cves=[], note="Legacy IIS version; likely end-of-life OS."),
    dict(match=re.compile(r"lighttpd/1\.4\.(1[0-9]|[0-9])\b", re.I),
         cves=["CVE-2019-11072"], note="Old lighttpd; upgrade recommended."),
    dict(match=re.compile(r"Boa/0\.9", re.I),
         cves=["CVE-2017-9833"], note="Boa httpd (IoT) end-of-life, RCE-prone."),
    dict(match=re.compile(r"GoAhead", re.I),
         cves=["CVE-2017-17562"], note="GoAhead (IoT/cameras) LD_PRELOAD RCE."),
    dict(match=re.compile(r"RomPager/4\.07", re.I),
         cves=["CVE-2014-9222"], note="RomPager 'Misfortune Cookie' router flaw."),
    dict(match=re.compile(r"Hikvision|DVRDVS|DNVRS", re.I),
         cves=["CVE-2021-36260", "CVE-2017-7921"],
         note="Hikvision camera command injection / auth bypass."),
    dict(match=re.compile(r"Dahua|DVR|IPC-", re.I),
         cves=["CVE-2021-33044", "CVE-2017-7927"],
         note="Dahua camera auth bypass / credential disclosure."),
    dict(match=re.compile(r"MikroTik|RouterOS", re.I),
         cves=["CVE-2018-14847"], note="RouterOS Winbox path-traversal cred leak."),
    dict(match=re.compile(r"Samba 3\.|Samba 4\.[0-4]\.", re.I),
         cves=["CVE-2017-7494"], note="Samba 'SambaCry' remote code execution."),
    dict(match=re.compile(r"ProFTPD", re.I), cves=[],
         note="Verify ProFTPD version against mod_copy CVEs."),
    dict(match=re.compile(r"Exim 4\.(8[0-9]|9[0-2])", re.I),
         cves=["CVE-2019-10149"], note="Exim 'Return of the Wizard' RCE."),
    dict(match=re.compile(r"Dropbear[_ ]?(0\.|201[0-6])", re.I),
         cves=["CVE-2016-7406", "CVE-2016-7407"],
         note="Old Dropbear SSH format-string / parsing bugs."),
    dict(match=re.compile(r"WebLogic", re.I),
         cves=["CVE-2020-14882", "CVE-2019-2725"],
         note="Oracle WebLogic console RCE."),
    dict(match=re.compile(r"phpMyAdmin", re.I), cves=[],
         note="Exposed phpMyAdmin; verify version & auth."),
    dict(match=re.compile(r"Jenkins", re.I),
         cves=["CVE-2018-1000861"], note="Jenkins script-console RCE risk."),
    dict(match=re.compile(r"Grafana", re.I),
         cves=["CVE-2021-43798"], note="Grafana path traversal (8.x)."),
]


def match_cves(text):
    """Return a list of {cves, note} for hints matching the given text."""
    if not text:
        return []
    out = []
    for hint in CVE_HINTS:
        if hint["match"].search(text):
            out.append({"cves": hint["cves"], "note": hint["note"]})
    return out


def service_risk(port):
    return SERVICE_RISKS.get(int(port))


def default_cred_hint(service_name):
    return DEFAULT_CRED_HINTS.get(str(service_name).lower())
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery'] = r'''"""
Host discovery engines.

Each engine returns a mapping ``{ip: info_dict}`` where ``info_dict`` may carry
keys such as ``mac``, ``method``, ``mdns_name``, ``ttl``, ``latency`` etc. The
:mod:`orchestrator` merges the outputs of every enabled engine into a single
deduplicated host set.
"""

from . import (environment, icmp, tcp, udp, arp, mdns, ssdp, wsd, netbios,
               orchestrator)

__all__ = ["environment", "icmp", "tcp", "udp", "arp", "mdns", "ssdp", "wsd",
           "netbios", "orchestrator"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.arp
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.arp'] = r'''"""
ARP-based discovery.

Two sources are combined:

1. The system ARP cache (``arp -a``) - passively populated by prior traffic and
   the ICMP/TCP sweeps, giving IP->MAC pairs for free.
2. An active layer-2 ARP scan via scapy (only when a pcap provider such as
   Npcap is present) - this reliably reaches every host on the wire, even ones
   that block ICMP and expose no TCP ports.
"""

import re
import subprocess

from .. import constants
from ..logging_setup import get_logger
from ..utils import netutils

log = get_logger("discovery.arp")

_WIN_ARP_RE = re.compile(
    r"([\d.]+)\s+([\da-fA-F]{2}(?:[-:][\da-fA-F]{2}){5})")
_NIX_ARP_RE = re.compile(r"\(([\d.]+)\)\s+at\s+([\da-fA-F:]{17})")


def read_arp_table():
    """Return {ip: mac} from the OS ARP cache."""
    table = {}
    try:
        if constants.IS_WINDOWS:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                 encoding=constants.WIN_ENCODING, errors="ignore").stdout
            for line in out.splitlines():
                m = _WIN_ARP_RE.search(line)
                if m:
                    table[m.group(1)] = netutils.normalize_mac(m.group(2))
        else:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                m = _NIX_ARP_RE.search(line)
                if m:
                    table[m.group(1)] = netutils.normalize_mac(m.group(2))
    except Exception as exc:
        log.debug("arp table read failed: %s", exc)
    return table


def scapy_l2_ready():
    """True only if scapy can actually send layer-2 frames on this host."""
    if not constants.HAS_SCAPY:
        return False
    try:
        from scapy.all import conf
        if "NotAvailable" in repr(conf.L2socket):
            return False
        if constants.IS_WINDOWS and not getattr(conf, "use_pcap", False):
            return False
        return True
    except Exception:
        return False


def scapy_arp_scan(network, timeout=3):
    """Active L2 ARP sweep. Returns {ip: mac}. Empty if unavailable."""
    if not scapy_l2_ready():
        return {}
    try:
        from scapy.all import ARP, Ether, srp
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            timeout=timeout, verbose=0)
        out = {}
        for _, r in answered:
            out[r.psrc] = netutils.normalize_mac(r.hwsrc)
        log.info("scapy ARP scan: %d hosts", len(out))
        return out
    except Exception as exc:
        log.debug("scapy arp scan failed: %s", exc)
        return {}


def local_mac(ip=None):
    """Best-effort own MAC via getmac (optional)."""
    if not constants.HAS_GETMAC:
        return "-"
    try:
        from getmac import get_mac_address
        mac = get_mac_address(ip=ip) if ip else get_mac_address()
        return netutils.normalize_mac(mac) if mac else "-"
    except Exception:
        return "-"


def remote_mac(ip):
    """Try to resolve a remote host's MAC via getmac (uses OS ARP)."""
    if not constants.HAS_GETMAC:
        return "-"
    try:
        from getmac import get_mac_address
        mac = get_mac_address(ip=str(ip))
        return netutils.normalize_mac(mac) if mac else "-"
    except Exception:
        return "-"


def discover(network, use_scapy=True):
    """Merge OS ARP cache with an optional active scapy scan -> {ip: info}."""
    macs = read_arp_table()
    if use_scapy:
        for ip, mac in scapy_arp_scan(network).items():
            macs.setdefault(ip, mac)
    out = {}
    for ip, mac in macs.items():
        out[ip] = {"method": "arp", "mac": mac}
    return out
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.environment
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.environment'] = r'''"""
Network environment detection.

Discovers the operator's own vantage point: network interfaces, the active
local IP, the true subnet (from the interface netmask), default gateway, DNS
servers and (optionally) the public IP + ISP via an online lookup.
"""

import ipaddress
import re
import socket
import subprocess

from .. import constants
from ..logging_setup import get_logger
from ..utils import netutils

log = get_logger("discovery.env")


class NetworkEnvironment:
    def __init__(self):
        self.local_ip = "127.0.0.1"
        self.network = ipaddress.ip_network("127.0.0.0/24")
        self.netmask = "255.255.255.0"
        self.gateway = "-"
        self.dns_servers = []
        self.interfaces = []
        self.primary_iface = ""
        self.mac = "-"
        self.public_ip = ""
        self.isp = ""
        self.geo = ""

    def to_dict(self):
        return {
            "local_ip": self.local_ip, "network": str(self.network),
            "netmask": self.netmask, "gateway": self.gateway,
            "dns_servers": self.dns_servers, "primary_iface": self.primary_iface,
            "mac": self.mac, "public_ip": self.public_ip, "isp": self.isp,
            "geo": self.geo,
            "interfaces": self.interfaces,
        }


def _enumerate_interfaces():
    """Return a list of interface dicts using psutil or ifaddr if available."""
    ifaces = []
    if constants.HAS_PSUTIL:
        try:
            import psutil
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                ipv4 = mask = mac = ""
                for a in addrs:
                    if a.family == socket.AF_INET:
                        ipv4, mask = a.address, a.netmask
                    elif getattr(a, "family", None) == getattr(psutil, "AF_LINK", -1):
                        mac = a.address
                    elif str(a.family).endswith("AF_PACKET"):
                        mac = a.address
                up = stats.get(name).isup if name in stats else True
                if ipv4:
                    ifaces.append({"name": name, "ip": ipv4, "netmask": mask,
                                   "mac": netutils.normalize_mac(mac), "up": up})
            return ifaces
        except Exception as exc:
            log.debug("psutil iface enum failed: %s", exc)
    if constants.HAS_IFADDR:
        try:
            import ifaddr
            for ad in ifaddr.get_adapters():
                for ip in ad.ips:
                    if isinstance(ip.ip, str) and "." in ip.ip:
                        mask = str(ipaddress.ip_network(
                            f"0.0.0.0/{ip.network_prefix}").netmask)
                        ifaces.append({"name": ad.nice_name, "ip": ip.ip,
                                       "netmask": mask, "mac": "-", "up": True})
            return ifaces
        except Exception as exc:
            log.debug("ifaddr iface enum failed: %s", exc)
    return ifaces


def _network_for(local_ip, ifaces):
    for i in ifaces:
        if i["ip"] == local_ip and i.get("netmask"):
            try:
                net = ipaddress.ip_network(f"{local_ip}/{i['netmask']}", strict=False)
                if net.num_addresses <= constants.MAX_SWEEPABLE_HOSTS:
                    return net, i["netmask"], i["name"], i.get("mac", "-")
                # too large: clamp to /24 around the host
                return (ipaddress.ip_network(f"{local_ip}/24", strict=False),
                        "255.255.255.0", i["name"], i.get("mac", "-"))
            except Exception:
                pass
    return ipaddress.ip_network(f"{local_ip}/24", strict=False), "255.255.255.0", "", "-"


def get_gateway():
    try:
        if constants.IS_WINDOWS:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 encoding=constants.WIN_ENCODING, errors="ignore").stdout
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if "Gateway" not in line:
                    continue
                for cand in [line] + lines[i + 1:i + 3]:
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", cand)
                    if m and m.group(1) != "0.0.0.0":
                        return m.group(1)
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
            m = re.search(r"default via ([\d.]+)", out)
            if m:
                return m.group(1)
    except Exception as exc:
        log.debug("gateway detection failed: %s", exc)
    return "-"


def get_dns_servers():
    servers = []
    try:
        if constants.IS_WINDOWS:
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                                 encoding=constants.WIN_ENCODING, errors="ignore").stdout
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
    except Exception as exc:
        log.debug("dns detection failed: %s", exc)
    seen = set()
    return [s for s in servers if not (s in seen or seen.add(s))]


def get_public_ip():
    """Best-effort public IP + ISP via a couple of free JSON endpoints."""
    if not constants.HAS_REQUESTS:
        return "", "", ""
    import requests
    endpoints = [
        ("https://ipinfo.io/json", ("ip", "org", "city", "region", "country")),
        ("https://ifconfig.co/json", ("ip", "asn_org", "city", "region_name", "country")),
    ]
    for url, keys in endpoints:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                data = r.json()
                ip = data.get(keys[0], "")
                isp = data.get(keys[1], "")
                city = data.get(keys[2], "")
                region = data.get(keys[3], "")
                country = data.get(keys[4], "")
                geo = ", ".join(x for x in (city, region, country) if x)
                if ip:
                    return ip, isp, geo
        except Exception:
            continue
    return "", "", ""


def detect(with_public_ip=True):
    env = NetworkEnvironment()
    env.local_ip = netutils.local_outbound_ip()
    env.interfaces = _enumerate_interfaces()
    env.network, env.netmask, env.primary_iface, env.mac = _network_for(
        env.local_ip, env.interfaces)
    env.gateway = get_gateway()
    env.dns_servers = get_dns_servers()
    if with_public_ip:
        env.public_ip, env.isp, env.geo = get_public_ip()
    log.info("environment: ip=%s net=%s gw=%s", env.local_ip, env.network, env.gateway)
    return env
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.icmp
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.icmp'] = r'''"""
ICMP host discovery via the system ``ping`` command (no raw-socket privileges
required). Captures TTL and round-trip latency for each responsive host, which
later feed OS fingerprinting and quality metrics.
"""

import re
import subprocess

from .. import constants
from ..logging_setup import get_logger
from ..utils import concurrency

log = get_logger("discovery.icmp")

_TTL_RE = re.compile(r"ttl[=\s]*(\d+)", re.IGNORECASE)
_LAT_RE = re.compile(r"(?:time|tempo)[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def ping_once(ip, timeout_ms=600):
    """Ping a host once. Returns {ip, ttl, latency, method} or None."""
    ip = str(ip)
    if constants.IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        secs = max(1, int(round(timeout_ms / 1000.0)))
        cmd = ["ping", "-c", "1", "-W", str(secs), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding=constants.WIN_ENCODING if constants.IS_WINDOWS else "utf-8",
                           errors="ignore")
    except Exception as exc:
        log.debug("ping error %s: %s", ip, exc)
        return None
    if r.returncode != 0:
        return None
    out = r.stdout
    ttl_m = _TTL_RE.search(out)
    # On Windows an unreachable host can still exit 0; require a real TTL reply.
    if constants.IS_WINDOWS and not ttl_m:
        return None
    lat_m = _LAT_RE.search(out)
    return {
        "ip": ip,
        "ttl": int(ttl_m.group(1)) if ttl_m else None,
        "latency": float(lat_m.group(1)) if lat_m else None,
        "method": "icmp",
    }


def sweep(network, timeout_ms=600, max_workers=128, on_step=None, stop_event=None):
    """Ping every host in ``network`` in parallel -> {ip: info}."""
    hosts = [str(h) for h in network.hosts()]
    result = {}
    replies = concurrency.parallel_map(
        lambda ip: ping_once(ip, timeout_ms), hosts,
        max_workers=max_workers, on_step=on_step, stop_event=stop_event)
    for rep in replies:
        if rep:
            result[rep["ip"]] = rep
    log.info("icmp sweep: %d/%d responded", len(result), len(hosts))
    return result
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.mdns
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.mdns'] = r'''"""
mDNS / Bonjour / DNS-SD discovery via the ``zeroconf`` library.

Browses the local link for a broad set of common service types and collects
device names, service types and advertised IP addresses. This is one of the
richest passive sources of *device identity* on a LAN (Apple devices,
Chromecasts, printers, NAS, smart-home hubs all announce themselves here).
"""

import time

from .. import constants
from ..logging_setup import get_logger

log = get_logger("discovery.mdns")

# A pragmatic set of DNS-SD service types worth browsing.
SERVICE_TYPES = [
    "_http._tcp.local.", "_https._tcp.local.", "_workstation._tcp.local.",
    "_ssh._tcp.local.", "_sftp-ssh._tcp.local.", "_smb._tcp.local.",
    "_afpovertcp._tcp.local.", "_device-info._tcp.local.",
    "_printer._tcp.local.", "_ipp._tcp.local.", "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.", "_scanner._tcp.local.",
    "_airplay._tcp.local.", "_raop._tcp.local.", "_airport._tcp.local.",
    "_googlecast._tcp.local.", "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.", "_hap._tcp.local.", "_homekit._tcp.local.",
    "_matter._tcp.local.", "_esphomelib._tcp.local.", "_home-assistant._tcp.local.",
    "_nvstream._tcp.local.", "_daap._tcp.local.", "_touch-able._tcp.local.",
    "_companion-link._tcp.local.", "_rfb._tcp.local.", "_nfs._tcp.local.",
    "_webdav._tcp.local.", "_adisk._tcp.local.", "_time-machine._tcp.local.",
    "_ptp._tcp.local.", "_googlezone._tcp.local.", "_amzn-wplay._tcp.local.",
    "_dosvc._tcp.local.", "_ippusb._tcp.local.", "_ewelink._tcp.local.",
]


def discover(duration=4.0):
    """
    Browse mDNS for ``duration`` seconds. Returns {ip: info} where info holds
    ``mdns_name`` and a list of advertised ``services``.
    """
    if not constants.HAS_ZEROCONF:
        return {}
    try:
        from zeroconf import Zeroconf, ServiceBrowser
    except Exception as exc:
        log.debug("zeroconf import failed: %s", exc)
        return {}

    found = {}

    class _Listener:
        def _record(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:
                info = None
            if not info:
                return
            try:
                addrs = info.parsed_addresses()
            except Exception:
                addrs = []
            friendly = name.split("." + type_.split(".", 1)[0])[0] if type_ in name else name
            friendly = friendly.rstrip(".")
            svc = type_.replace("._tcp.local.", "").replace("._udp.local.", "").lstrip("_")
            props = {}
            try:
                for k, v in (info.properties or {}).items():
                    try:
                        props[k.decode("utf-8", "ignore")] = v.decode("utf-8", "ignore") if isinstance(v, bytes) else v
                    except Exception:
                        pass
            except Exception:
                pass
            for ip in addrs:
                if ":" in ip:   # skip IPv6 for now
                    continue
                entry = found.setdefault(ip, {"method": "mdns", "mdns_name": friendly,
                                              "services": [], "props": {}})
                if svc not in entry["services"]:
                    entry["services"].append(svc)
                if friendly and (entry["mdns_name"] in ("", "-")):
                    entry["mdns_name"] = friendly
                entry["props"].update(props)

        def add_service(self, zc, type_, name):
            self._record(zc, type_, name)

        def update_service(self, zc, type_, name):
            self._record(zc, type_, name)

        def remove_service(self, zc, type_, name):
            pass

    zc = None
    try:
        zc = Zeroconf()
        listener = _Listener()
        browsers = [ServiceBrowser(zc, st, listener) for st in SERVICE_TYPES]
        time.sleep(duration)
    except Exception as exc:
        log.debug("mdns browse failed: %s", exc)
    finally:
        try:
            if zc:
                zc.close()
        except Exception:
            pass
    log.info("mdns discovery: %d hosts", len(found))
    return found
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.netbios
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.netbios'] = r'''"""
NetBIOS name resolution.

On Windows this shells out to ``nbtstat -A <ip>``; on Linux it uses
``nmblookup -A <ip>`` if available. Returns the workstation name, the workgroup
/ domain and the MAC address that nbtstat conveniently reports.
"""

import re
import subprocess

from .. import constants
from ..logging_setup import get_logger
from ..utils import concurrency, netutils

log = get_logger("discovery.netbios")


def query(ip):
    """Return {"netbios", "workgroup", "mac"} for a single host."""
    result = {"netbios": "-", "workgroup": "-", "mac": "-"}
    try:
        if constants.IS_WINDOWS:
            r = subprocess.run(["nbtstat", "-A", str(ip)], capture_output=True,
                               text=True, encoding=constants.WIN_ENCODING,
                               errors="ignore", timeout=4)
            text = r.stdout
            for line in text.splitlines():
                m = re.match(r"\s*([^\s<]+)\s+<00>\s+UNIQUE", line)
                if m and result["netbios"] == "-":
                    result["netbios"] = m.group(1).strip()
                mg = re.match(r"\s*([^\s<]+)\s+<00>\s+GROUP", line)
                if mg and result["workgroup"] == "-":
                    result["workgroup"] = mg.group(1).strip()
            mac_m = re.search(r"MAC Address\s*=\s*([\dA-Fa-f-]{17})", text)
            if mac_m:
                result["mac"] = netutils.normalize_mac(mac_m.group(1))
        else:
            r = subprocess.run(["nmblookup", "-A", str(ip)], capture_output=True,
                               text=True, timeout=4)
            for line in r.stdout.splitlines():
                m = re.match(r"\s*([^\s<]+)\s+<00>\s+-\s+([BMH<]?)", line)
                if m and result["netbios"] == "-" and "GROUP" not in line:
                    result["netbios"] = m.group(1).strip()
                if "<00>" in line and "GROUP" in line and result["workgroup"] == "-":
                    gm = re.match(r"\s*([^\s<]+)\s+<00>", line)
                    if gm:
                        result["workgroup"] = gm.group(1).strip()
    except Exception as exc:
        log.debug("netbios query %s failed: %s", ip, exc)
    return result


def query_many(ips, max_workers=32, on_step=None):
    """Query NetBIOS for a list of IPs in parallel -> {ip: info}."""
    if not (constants.IS_WINDOWS or _have_nmblookup()):
        return {}
    return concurrency.parallel_map_dict(query, list(ips),
                                         max_workers=max_workers, on_step=on_step)


def _have_nmblookup():
    from shutil import which
    return which("nmblookup") is not None
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.orchestrator
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.orchestrator'] = r'''"""
Discovery orchestrator.

Runs every enabled discovery engine, merges their results into one host set,
filters out broadcast/multicast noise and produces a list of seed
:class:`~scanfyx.models.Device` objects carrying whatever identity information
each engine contributed (MAC, TTL, latency, mDNS/SSDP names, discovery methods).
"""

from .. import constants
from ..logging_setup import get_logger
from ..models import Device
from ..utils import netutils
from . import icmp, tcp, udp, arp, mdns, ssdp, wsd

log = get_logger("discovery.orch")


class DiscoveryReport:
    def __init__(self):
        self.hosts = {}          # ip -> merged info dict
        self.methods_used = []
        self.mdns_raw = {}
        self.ssdp_raw = {}

    def merge(self, engine_result, method_name):
        if not engine_result:
            return
        if method_name not in self.methods_used:
            self.methods_used.append(method_name)
        for ip, info in engine_result.items():
            entry = self.hosts.setdefault(ip, {"methods": set()})
            entry["methods"].add(info.get("method", method_name))
            for k, v in info.items():
                if k == "method":
                    continue
                if k in ("services", "ssdp_st", "locations", "udp_ports",
                         "open_hint") and isinstance(v, list):
                    cur = entry.setdefault(k, [])
                    for item in v:
                        if item not in cur:
                            cur.append(item)
                elif k in ("props", "upnp") and isinstance(v, dict):
                    entry.setdefault(k, {}).update(v)
                else:
                    # do not overwrite a good value with a placeholder
                    if v not in (None, "", "-") or k not in entry:
                        entry[k] = v


def run(network, config, env, progress=None, stop_event=None):
    """
    Execute discovery according to ``config``. ``progress`` is an optional
    object exposing ``phase(name, total)`` and ``step()`` for UI feedback.
    Returns (list[Device], DiscoveryReport).
    """
    report = DiscoveryReport()
    nhosts = max(1, network.num_addresses - 2)

    # -- ICMP --------------------------------------------------------------
    if config.icmp:
        if progress:
            progress.phase("ICMP ping sweep", nhosts)
        res = icmp.sweep(network, timeout_ms=config.ping_timeout_ms,
                         max_workers=config.max_ping_workers,
                         on_step=progress.step if progress else None,
                         stop_event=stop_event)
        report.merge(res, "icmp")

    # -- TCP ---------------------------------------------------------------
    if config.tcp_ping:
        ports = tcp.DEFAULT_PING_PORTS
        if progress:
            progress.phase("TCP discovery", nhosts * len(ports))
        res = tcp.sweep(network, timeout=config.tcp_timeout,
                        max_workers=config.max_port_workers,
                        on_step=progress.step if progress else None,
                        stop_event=stop_event)
        report.merge(res, "tcp")

    # -- ARP ---------------------------------------------------------------
    if config.arp:
        if progress:
            progress.phase("ARP table / L2 scan", 1)
        res = arp.discover(network, use_scapy=True)
        report.merge(res, "arp")
        if progress:
            progress.step()

    # -- mDNS --------------------------------------------------------------
    if config.mdns and constants.HAS_ZEROCONF:
        if progress:
            progress.phase("mDNS / Bonjour", 1)
        res = mdns.discover(duration=4.0)
        report.mdns_raw = res
        report.merge(res, "mdns")
        if progress:
            progress.step()

    # -- SSDP --------------------------------------------------------------
    if config.ssdp:
        if progress:
            progress.phase("SSDP / UPnP", 1)
        res = ssdp.discover(timeout=3.0)
        report.ssdp_raw = res
        report.merge(res, "ssdp")
        if progress:
            progress.step()

        # WS-Discovery (printers / ONVIF cameras) rides with SSDP
        wsd_res = wsd.discover(timeout=3.0)
        report.merge(wsd_res, "wsd")

    # -- UDP (deep/thorough only) -----------------------------------------
    if config.udp:
        if progress:
            progress.phase("UDP service probes", nhosts)
        res = udp.sweep(network, max_workers=config.max_ping_workers,
                        on_step=progress.step if progress else None,
                        stop_event=stop_event)
        report.merge(res, "udp")

    # -- Always include gateway & drop noise ------------------------------
    if env.gateway and env.gateway != "-":
        report.hosts.setdefault(env.gateway, {"methods": {"gateway"}})
    report.hosts.pop("127.0.0.1", None)

    devices = _build_devices(report, env, network)
    log.info("discovery complete: %d devices via %s",
             len(devices), ",".join(report.methods_used))
    return devices, report


def _build_devices(report, env, network=None):
    devices = []
    for ip, info in report.hosts.items():
        mac = info.get("mac", "-")
        if not netutils.is_valid_ip(ip):
            continue
        if netutils.is_multicast_ip(ip) or netutils.is_broadcast(ip):
            continue
        if netutils.is_multicast_mac(mac) or (mac or "").startswith("ff:ff:ff"):
            continue
        # keep only hosts inside the scanned network (plus the gateway),
        # so stray ARP entries from other interfaces/subnets are dropped
        if network is not None and ip != env.gateway \
                and not netutils.in_network(ip, network):
            continue

        dev = Device(ip=ip, mac=mac if mac else "-")
        dev.discovery_methods = sorted(info.get("methods", []))
        dev.ttl = info.get("ttl")
        dev.latency_ms = info.get("latency")
        dev.mdns_name = info.get("mdns_name", "-") or "-"
        dev.randomized_mac = netutils.looks_randomized(mac)
        dev.is_gateway = (ip == env.gateway)
        dev.is_self = (ip == env.local_ip)

        # stash raw discovery extras for fingerprint/classify stages
        dev.services_detail["mdns_services"] = info.get("services", [])
        dev.services_detail["mdns_props"] = info.get("props", {})
        dev.services_detail["ssdp_server"] = info.get("ssdp_server", "")
        dev.services_detail["ssdp_st"] = info.get("ssdp_st", [])
        dev.services_detail["upnp"] = info.get("upnp", {})
        dev.services_detail["udp_ports"] = info.get("udp_ports", [])
        dev.services_detail["tcp_hint"] = info.get("open_hint", [])
        dev.services_detail["wsd_kind"] = info.get("wsd_kind", "")
        dev.services_detail["wsd_types"] = info.get("wsd_types", "")
        devices.append(dev)

    devices.sort(key=lambda d: netutils.ip_sort_key(d.ip))
    return devices
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.ssdp
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.ssdp'] = r'''"""
SSDP / UPnP discovery.

Sends a multicast M-SEARCH to 239.255.255.250:1900 and collects the responders'
``LOCATION`` URLs, then (optionally) fetches each device-description XML to pull
the friendly name, manufacturer and model. Routers, smart TVs, media servers,
game consoles and many IoT devices answer SSDP.
"""

import re
import socket

from .. import constants
from ..logging_setup import get_logger

log = get_logger("discovery.ssdp")

MCAST_ADDR = "239.255.255.250"
MCAST_PORT = 1900

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()

_LOCATION_RE = re.compile(r"location:\s*(\S+)", re.IGNORECASE)
_SERVER_RE = re.compile(r"server:\s*(.+)", re.IGNORECASE)
_ST_RE = re.compile(r"st:\s*(.+)", re.IGNORECASE)


def _fetch_description(url):
    """Fetch and parse a UPnP device description XML."""
    info = {}
    if not constants.HAS_REQUESTS:
        return info
    try:
        import requests
        r = requests.get(url, timeout=2.5)
        text = r.text
        for tag in ("friendlyName", "manufacturer", "modelName",
                    "modelNumber", "modelDescription", "serialNumber"):
            m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.I | re.S)
            if m:
                info[tag] = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
    except Exception:
        pass
    return info


def discover(timeout=3.0, fetch_description=True):
    """Return {ip: info} with ssdp server strings and UPnP descriptions."""
    found = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(_MSEARCH, (MCAST_ADDR, MCAST_PORT))
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except Exception:
                break
            ip = addr[0]
            text = data.decode("utf-8", "ignore")
            loc = _LOCATION_RE.search(text)
            server = _SERVER_RE.search(text)
            st = _ST_RE.search(text)
            entry = found.setdefault(ip, {"method": "ssdp", "ssdp_server": "",
                                          "ssdp_st": [], "locations": [],
                                          "upnp": {}})
            if server and not entry["ssdp_server"]:
                entry["ssdp_server"] = server.group(1).strip()
            if st:
                stv = st.group(1).strip()
                if stv not in entry["ssdp_st"]:
                    entry["ssdp_st"].append(stv)
            if loc:
                url = loc.group(1).strip()
                if url not in entry["locations"]:
                    entry["locations"].append(url)
    except Exception as exc:
        log.debug("ssdp discovery failed: %s", exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if fetch_description:
        for ip, entry in found.items():
            if entry["locations"]:
                desc = _fetch_description(entry["locations"][0])
                if desc:
                    entry["upnp"] = desc

    log.info("ssdp discovery: %d hosts", len(found))
    return found
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.tcp
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.tcp'] = r'''"""
TCP host discovery ("TCP ping").

Attempts a TCP connect to a handful of very common ports across the subnet.
This finds hosts that silently drop ICMP echo (a common firewall setting) but
still expose at least one service, and it also warms the system ARP cache so
MAC addresses become resolvable afterwards.
"""

from .. import constants
from ..logging_setup import get_logger
from ..utils import concurrency, netutils

log = get_logger("discovery.tcp")

# Ports most likely to be open on *something* on a home/office LAN.
DEFAULT_PING_PORTS = (80, 443, 22, 445, 139, 8080, 53, 3389, 62078, 5000)


def sweep(network, ports=DEFAULT_PING_PORTS, timeout=0.5, max_workers=400,
          on_step=None, stop_event=None):
    """Return {ip: {"method": "tcp", "open_hint": [ports...]}}."""
    hosts = [str(h) for h in network.hosts()]
    tasks = [(ip, port) for ip in hosts for port in ports]

    def probe(args):
        ip, port = args
        return (ip, port) if netutils.tcp_connect(ip, port, timeout) else None

    results = concurrency.parallel_map(
        probe, tasks, max_workers=max_workers, on_step=on_step,
        stop_event=stop_event)

    found = {}
    for res in results:
        if res:
            ip, port = res
            found.setdefault(ip, {"method": "tcp", "open_hint": []})
            found[ip]["open_hint"].append(port)
    log.info("tcp sweep: %d hosts responded on %d ports", len(found), len(ports))
    return found
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.udp
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.udp'] = r'''"""
UDP host discovery / probing.

UDP is connectionless, so "open" cannot be proven by a connect() the way TCP
allows. Instead SCANFY sends small protocol-specific probes to well-known UDP
services (DNS, NTP, SNMP, mDNS, SSDP, NetBIOS, IKE) and treats any application
reply as evidence the host and service exist. Absence of a reply is
inconclusive, so this engine only *adds* hosts, never removes them.
"""

import socket
import struct

from ..logging_setup import get_logger
from ..utils import concurrency

log = get_logger("discovery.udp")


def _dns_query_probe():
    # A minimal DNS query for "." NS - most resolvers answer.
    tid = b"\x13\x37"
    header = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = b"\x00" + struct.pack("!HH", 2, 1)  # root, type NS, class IN
    return header + question


def _ntp_probe():
    # NTP client request (mode 3, version 3).
    return b"\x1b" + 47 * b"\0"


def _snmp_probe():
    # SNMPv1 get-request for sysDescr with community 'public'.
    return bytes.fromhex(
        "302602010004067075626c6963a01902040000000002"
        "0100020100300b300906052b060102010500")


def _netbios_probe():
    # NBSTAT query (node status).
    return bytes.fromhex(
        "a2480000000100000000000020434b41414141414141414141"
        "41414141414141414141414141414141410000210001")


_PROBES = {
    53: _dns_query_probe(),
    123: _ntp_probe(),
    161: _snmp_probe(),
    137: _netbios_probe(),
    5353: bytes.fromhex("0000000000010000000000000000010001"),
    1900: (b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
           b'MAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n'),
}


def probe_host(ip, ports=(53, 123, 161, 137), timeout=1.0):
    """Send UDP probes; return list of ports that produced a reply."""
    open_ports = []
    for port in ports:
        payload = _PROBES.get(port)
        if payload is None:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(payload, (str(ip), port))
            data, _ = s.recvfrom(2048)
            if data:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports


def sweep(network, ports=(53, 123, 161, 137), timeout=1.0, max_workers=128,
          on_step=None, stop_event=None, limit=None):
    hosts = [str(h) for h in network.hosts()]
    if limit:
        hosts = hosts[:limit]

    def work(ip):
        found = probe_host(ip, ports, timeout)
        return (ip, found) if found else None

    results = concurrency.parallel_map(
        work, hosts, max_workers=max_workers, on_step=on_step,
        stop_event=stop_event)
    out = {}
    for res in results:
        if res:
            ip, found = res
            out[ip] = {"method": "udp", "udp_ports": found}
    log.info("udp sweep: %d hosts replied", len(out))
    return out
'''

# ---------------------------------------------------------------------------
# module: scanfyx.discovery.wsd
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.discovery.wsd'] = r'''"""
WS-Discovery (WSD) probing.

Sends a SOAP-over-UDP multicast ``Probe`` to 239.255.255.250:3702, the discovery
protocol used by Windows network devices, most network printers and many IP
cameras (ONVIF). Responders return service addresses (XAddrs) and device types
that identify the hardware. Implemented with raw sockets - no dependencies.
"""

import re
import socket
import uuid

from ..logging_setup import get_logger

log = get_logger("discovery.wsd")

WSD_ADDR = "239.255.255.250"
WSD_PORT = 3702


def _probe_message():
    msg_id = f"urn:uuid:{uuid.uuid4()}"
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope '
        'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<soap:Header>'
        '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
        '<wsa:Action>'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe'
        '</wsa:Action>'
        f'<wsa:MessageID>{msg_id}</wsa:MessageID>'
        '</soap:Header>'
        '<soap:Body><wsd:Probe/></soap:Body>'
        '</soap:Envelope>'
    ).encode("utf-8")


_TYPES_RE = re.compile(r"<[\w:]*Types>(.*?)</[\w:]*Types>", re.I | re.S)
_XADDRS_RE = re.compile(r"<[\w:]*XAddrs>(.*?)</[\w:]*XAddrs>", re.I | re.S)


def _classify_types(types_text):
    low = types_text.lower()
    if "printer" in low or "print" in low:
        return "printer"
    if "networkvideo" in low or "onvif" in low or "camera" in low:
        return "camera"
    if "computer" in low or "device" in low:
        return "computer"
    return ""


def discover(timeout=3.0):
    """Return {ip: info} for WS-Discovery responders."""
    found = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(_probe_message(), (WSD_ADDR, WSD_PORT))

        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            except Exception:
                break
            ip = addr[0]
            text = data.decode("utf-8", "ignore")
            types_m = _TYPES_RE.search(text)
            xaddrs_m = _XADDRS_RE.search(text)
            types = types_m.group(1).strip() if types_m else ""
            xaddrs = xaddrs_m.group(1).strip() if xaddrs_m else ""
            kind = _classify_types(types)
            entry = found.setdefault(ip, {"method": "wsd", "wsd_types": types[:120],
                                          "wsd_xaddrs": xaddrs[:200], "wsd_kind": kind})
            if kind and not entry.get("wsd_kind"):
                entry["wsd_kind"] = kind
    except Exception as exc:
        log.debug("wsd discovery failed: %s", exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    log.info("wsd discovery: %d responders", len(found))
    return found
'''

# ---------------------------------------------------------------------------
# module: scanfyx.engine
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.engine'] = r'''"""
The SCANFY scan pipeline.

Ties every subsystem together into one flow:

    environment -> discovery -> port scan -> service fingerprint ->
    classification -> security analysis -> topology -> ScanResult

A ``progress`` object (duck-typed with ``phase(name, total)`` and ``step()``)
receives feedback for the UI; :class:`NullProgress` is used for headless runs.
"""

import platform
import time

from . import constants, classify, topology
from .config import ScanConfig
from .discovery import environment, orchestrator as discovery_orch
from .fingerprint import orchestrator as fp_orch
from .fingerprint import os_detect
from .logging_setup import get_logger
from .models import ScanResult, ScanMeta, now_str
from .portscan import scanner, nmap_integration
from .security import analyzer
from .discovery import arp as arp_disc

log = get_logger("engine")


class NullProgress:
    def phase(self, name, total):
        pass

    def step(self, n=1):
        pass

    def done(self):
        pass


def engine_tag():
    return constants.capability_summary()


def detect_environment(with_public_ip=True):
    return environment.detect(with_public_ip=with_public_ip)


def run_scan(config, env=None, network=None, progress=None, stop_event=None,
             scan_type="Deep"):
    """Full network scan. Returns a populated :class:`ScanResult`."""
    progress = progress or NullProgress()
    start = time.monotonic()

    if env is None:
        env = detect_environment(with_public_ip=config.geoip_public)
    net = network or env.network

    # 1. discovery
    devices, disc_report = discovery_orch.run(
        net, config, env, progress=progress, stop_event=stop_event)

    # 2. port scan
    ports = scanner.select_ports(config)
    scanner.scan_hosts(devices, ports, config, progress=progress,
                       stop_event=stop_event)

    # 3. service fingerprinting
    fp_orch.enrich(devices, config, env, progress=progress)

    # 4. classification
    classify.classify_all(devices)

    # 5. security analysis
    if config.security:
        if progress:
            progress.phase("Security analysis", len(devices))
        for d in devices:
            analyzer.analyze_device(d)
            if progress:
                progress.step()

    # 6. build result
    elapsed = round(time.monotonic() - start, 1)
    meta = _build_meta(config, env, net, devices, disc_report, elapsed, scan_type)
    result = ScanResult(devices, meta)
    topology.annotate_hop_counts(result)
    if progress:
        progress.done()
    log.info("scan complete: %d devices, grade %s in %ss",
             len(devices), result.risk_grade(), elapsed)
    return result


def run_quick_scan(config, env=None, network=None, progress=None, stop_event=None):
    """A fast pass: discovery + light identification, no deep fingerprinting."""
    quick_cfg = ScanConfig().apply_profile("fast")
    quick_cfg.http = False
    quick_cfg.tls = False
    quick_cfg.snmp = False
    quick_cfg.udp = False
    quick_cfg.report_dir = config.report_dir
    return run_scan(quick_cfg, env=env, network=network, progress=progress,
                    stop_event=stop_event, scan_type="Quick")


def run_single_host(ip, config, env=None, progress=None, use_nmap=None):
    """Deep-scan a single host and return a one-device ScanResult."""
    from .models import Device
    from .discovery import icmp
    progress = progress or NullProgress()
    if env is None:
        env = detect_environment(with_public_ip=False)

    p = icmp.ping_once(ip, config.ping_timeout_ms)
    macs = arp_disc.read_arp_table()
    dev = Device(ip=str(ip), mac=macs.get(str(ip), "-"))
    if p:
        dev.ttl = p.get("ttl")
        dev.latency_ms = p.get("latency")
        dev.discovery_methods = ["icmp"]
    else:
        dev.discovery_methods = ["manual"]
    dev.is_gateway = (str(ip) == env.gateway)
    dev.is_self = (str(ip) == env.local_ip)
    devices = [dev]

    ports = scanner.select_ports(config)
    scanner.scan_hosts(devices, ports, config, progress=progress)

    # optional nmap enrichment
    if (use_nmap or config.nmap) and nmap_integration.available():
        if progress:
            progress.phase("nmap service/OS detection", 1)
        nres = nmap_integration.scan_host(
            str(ip), ports=dev.open_ports() or None,
            service_version=True, os_detect=True)
        if nres:
            _apply_nmap(dev, nres)
        if progress:
            progress.step()

    fp_orch.enrich(devices, config, env, progress=progress)
    classify.classify_all(devices)
    if config.security:
        analyzer.analyze_device(dev)

    meta = ScanMeta(
        generated=now_str(), scan_type="Single-host (Deep)",
        profile=config.profile, network=str(ip), local_ip=env.local_ip,
        gateway=env.gateway, dns=env.dns_servers, methods=dev.discovery_methods,
        engine=engine_tag(), duration=0.0, count=1,
        hostname=constants.HOSTNAME, platform=platform.platform())
    return ScanResult(devices, meta)


def _apply_nmap(dev, nres):
    for np in nres.get("ports", []):
        for pr in dev.ports:
            if pr.port == np["port"]:
                if np.get("product"):
                    pr.product = np["product"]
                if np.get("version"):
                    pr.version = np["version"]
                if np.get("service"):
                    pr.service = np["service"] or pr.service
                if np.get("extra"):
                    pr.extra["nmap"] = np["extra"]
                break
    if nres.get("os"):
        dev.services_detail["nmap_os"] = nres["os"][0]["name"]


def _build_meta(config, env, net, devices, disc_report, elapsed, scan_type):
    return ScanMeta(
        generated=now_str(),
        scan_type=scan_type,
        profile=config.profile,
        network=str(net),
        local_ip=env.local_ip,
        gateway=env.gateway,
        dns=env.dns_servers,
        public_ip=env.public_ip,
        isp=env.isp,
        geo=env.geo,
        methods=disc_report.methods_used,
        engine=engine_tag(),
        duration=elapsed,
        count=len(devices),
        hostname=constants.HOSTNAME,
        platform=platform.platform(),
    )
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint'] = r'''"""
Per-service deep fingerprinting.

Each module probes one protocol family and enriches a :class:`Device`:

    http       HTTP/HTTPS headers, title, technologies, security headers
    tls        X.509 certificate details and TLS version/weaknesses
    ssh        SSH protocol banner and host-key/algorithm hints
    snmp       SNMP sysDescr / sysName via community strings
    smb        SMB dialect / OS / shares (best effort)
    dns_fp     reverse DNS and extra name records
    os_detect  OS family from TTL, banners and (optional) nmap

The :mod:`orchestrator` dispatches the right fingerprinters per open port.
"""

from . import http, tls, ssh, snmp, smb, dns_fp, os_detect, probes, orchestrator

__all__ = ["http", "tls", "ssh", "snmp", "smb", "dns_fp", "os_detect",
           "probes", "orchestrator"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.dns_fp
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.dns_fp'] = r'''"""
DNS-based host fingerprinting.

Beyond the standard reverse lookup, when ``dnspython`` is available this queries
the local resolver for PTR records and (for hosts that are DNS servers) probes
version.bind. Reverse names frequently encode the device role or owner
(e.g. ``printer-hr.lan``, ``johns-macbook.lan``).
"""

import socket

from .. import constants
from ..logging_setup import get_logger
from ..utils import netutils

log = get_logger("fingerprint.dns")


def reverse(ip):
    """Reverse DNS via the stdlib (uses the OS resolver)."""
    return netutils.reverse_dns(ip)


def ptr_via_dnspython(ip, nameservers=None, timeout=2.0):
    if not constants.HAS_DNSPYTHON:
        return "-"
    try:
        import dns.resolver
        import dns.reversename
        resolver = dns.resolver.Resolver(configure=True)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        rev = dns.reversename.from_address(str(ip))
        answers = resolver.resolve(rev, "PTR")
        return str(answers[0]).rstrip(".")
    except Exception:
        return "-"


def bind_version(ip, timeout=2.0):
    """Query version.bind CH TXT of a DNS server (often reveals software)."""
    if not constants.HAS_DNSPYTHON:
        return ""
    try:
        import dns.message
        import dns.query
        q = dns.message.make_query("version.bind", "TXT", "CH")
        r = dns.query.udp(q, str(ip), timeout=timeout)
        for ans in r.answer:
            for item in ans.items:
                return str(item).strip('"')[:80]
    except Exception:
        pass
    return ""


def fingerprint(ip, is_dns_server=False, nameservers=None):
    """Return {"reverse", "ptr", "bind_version"}."""
    result = {"reverse": reverse(ip), "ptr": "-", "bind_version": ""}
    if constants.HAS_DNSPYTHON:
        result["ptr"] = ptr_via_dnspython(ip, nameservers)
        if is_dns_server:
            result["bind_version"] = bind_version(ip)
    return result
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.http
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.http'] = r'''"""
HTTP / HTTPS fingerprinting.

For each web port it performs a real GET (following redirects, ignoring TLS
verification since LAN devices use self-signed certs) and extracts the Server
header, page title, X-Powered-By, content type, an authentication hint and the
set of matched technologies/device kinds (via the signature database). It also
records which recommended security headers are missing for the security stage.
"""

import hashlib
import re

from .. import constants
from ..data import http_signatures
from ..data.vuln_db import SECURITY_HEADERS
from ..logging_setup import get_logger
from ..models import HttpInfo

log = get_logger("fingerprint.http")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


def _auth_hint(status, headers):
    if status == 401 or "www-authenticate" in headers:
        return headers.get("www-authenticate", "HTTP auth required")[:60]
    if status in (403,):
        return "forbidden"
    return ""


def fingerprint(ip, port, scheme, timeout=3.0, user_agent="SCANFY/4.0"):
    """Probe one web endpoint. Returns HttpInfo or None."""
    if not constants.HAS_REQUESTS:
        return None
    import requests
    url = f"{scheme}://{ip}:{port}/"
    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                            allow_redirects=True,
                            headers={"User-Agent": user_agent,
                                     "Accept": "*/*"})
    except Exception as exc:
        log.debug("http fp %s failed: %s", url, exc)
        return None

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text if len(resp.text) < 200000 else resp.text[:200000]

    info = HttpInfo(port=port, scheme=scheme, url=url, status=resp.status_code)
    info.server = headers.get("server", "").strip()[:100]
    info.powered_by = headers.get("x-powered-by", "").strip()[:100]
    info.content_type = headers.get("content-type", "").strip()[:80]
    info.location = headers.get("location", "").strip()[:120]
    info.headers = {k: v[:200] for k, v in headers.items()}

    m = _TITLE_RE.search(body)
    if m:
        info.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

    # technology / device identification
    header_block = "\n".join(f"{k}: {v}" for k, v in headers.items())
    techs = http_signatures.identify(server=info.server,
                                     headers_text=header_block,
                                     title=info.title, body=body)
    gen = _GENERATOR_RE.search(body)
    if gen:
        techs.append({"name": gen.group(1).strip()[:40], "kind": "cms"})
    info.technologies = techs
    kind = http_signatures.primary_kind(techs)
    if kind:
        info.device_kind = kind

    info.auth = _auth_hint(resp.status_code, headers)

    # missing security headers (stored for the analyzer)
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    info.headers["_missing_security"] = ",".join(missing)

    # favicon hash (best-effort identity signal)
    try:
        fav = requests.get(f"{scheme}://{ip}:{port}/favicon.ico",
                          timeout=timeout, verify=False)
        if fav.status_code == 200 and fav.content:
            info.favicon_hash = hashlib.md5(fav.content).hexdigest()[:16]
    except Exception:
        pass

    return info


def fingerprint_device(device, config):
    """Fingerprint every HTTP(S)-capable open port on a device."""
    from ..data import services
    results = []
    for pr in device.ports:
        if pr.protocol != "tcp" or pr.state != "open":
            continue
        port = pr.port
        if port in services.HTTPS_PORTS or port == 443:
            scheme = "https"
        elif port in services.HTTP_PORTS:
            scheme = "http"
        else:
            continue
        info = fingerprint(device.ip, port, scheme, timeout=config.http_timeout)
        if info is None and scheme == "http":
            info = fingerprint(device.ip, port, "https", timeout=config.http_timeout)
        if info:
            results.append(info)
            if info.device_kind and not device.device_kind:
                device.device_kind = info.device_kind
    device.http = results
    return results
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.orchestrator
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.orchestrator'] = r'''"""
Fingerprint orchestrator.

Given the discovered + port-scanned devices, this enriches every host: it
resolves vendors (serially, for thread-safety), reverse-DNS + NetBIOS names,
then dispatches per-service fingerprinters (HTTP, TLS, SSH, SNMP, SMB, DNS)
against the appropriate open ports in parallel, and finally infers the OS.
"""

from .. import constants, vendors
from ..data import services
from ..logging_setup import get_logger
from ..utils import concurrency
from ..discovery import netbios as netbios_disc
from . import http, tls, ssh, snmp, smb, dns_fp, os_detect, probes

log = get_logger("fingerprint.orch")


def enrich(devices, config, env, progress=None):
    if not devices:
        return devices

    # ---- vendors (serial: mac_vendor_lookup is not thread-safe) ---------
    vendor_map = vendors.resolve_many([d.mac for d in devices])
    for d in devices:
        d.vendor = vendor_map.get(d.mac, "-")

    # ---- own MAC/vendor for the local host ------------------------------
    for d in devices:
        if d.is_self and d.mac == "-" and env.mac not in ("-", ""):
            d.mac = env.mac
            d.vendor = vendors.resolve(env.mac)

    # ---- NetBIOS (batch, Windows/nmblookup) -----------------------------
    if config.netbios:
        if progress:
            progress.phase("NetBIOS names", len(devices))
        nb = netbios_disc.query_many(
            [d.ip for d in devices], max_workers=32,
            on_step=progress.step if progress else None)
        for d in devices:
            info = nb.get(d.ip) or {}
            if info.get("netbios", "-") != "-":
                d.netbios = info["netbios"]
            if info.get("workgroup", "-") != "-":
                d.workgroup = info["workgroup"]
            if d.mac == "-" and info.get("mac", "-") != "-":
                d.mac = info["mac"]
                d.vendor = vendors.resolve(d.mac)

    # ---- per-device service fingerprinting (parallel) -------------------
    if progress:
        progress.phase("Service fingerprinting", len(devices))

    def work(dev):
        _fingerprint_device(dev, config, env)
        if progress:
            progress.step()
        return dev

    concurrency.parallel_map(work, devices, max_workers=config.max_fp_workers)

    # ---- OS inference (cheap, after signals gathered) -------------------
    for d in devices:
        os_detect.infer(d)

    return devices


def _fingerprint_device(dev, config, env):
    ports = dev.port_set()

    # reverse DNS / PTR
    dns_info = dns_fp.fingerprint(
        dev.ip, is_dns_server=(53 in ports), nameservers=env.dns_servers or None)
    if dns_info.get("reverse", "-") != "-":
        dev.hostname = dns_info["reverse"]
    elif dns_info.get("ptr", "-") != "-":
        dev.hostname = dns_info["ptr"]
    dev.services_detail["dns"] = dns_info

    # HTTP / HTTPS
    if config.http:
        try:
            http.fingerprint_device(dev, config)
        except Exception as exc:
            log.debug("http fp %s failed: %s", dev.ip, exc)

    # TLS on TLS-capable open ports
    if config.tls:
        tls_ports = [p for p in ports if services.is_tls_port(p)]
        for p in tls_ports[:6]:
            try:
                ti = tls.fingerprint(dev.ip, p, timeout=config.banner_timeout)
                if ti:
                    ti_weak = tls.weaknesses(ti)
                    dev.tls.append(ti)
                    dev.services_detail.setdefault("tls_weak", {})[p] = ti_weak
            except Exception as exc:
                log.debug("tls fp %s:%s failed: %s", dev.ip, p, exc)

    # SSH
    if config.ssh and 22 in ports:
        try:
            info = ssh.fingerprint(dev.ip, 22, timeout=config.banner_timeout)
            if info:
                dev.services_detail["ssh"] = info
                _apply_banner_to_port(dev, 22, info.get("software", ""),
                                      "", info.get("banner", ""))
        except Exception:
            pass

    # SNMP
    if config.snmp and (161 in ports or 161 in (dev.services_detail.get("udp_ports") or [])):
        try:
            info = snmp.fingerprint(dev.ip, timeout=1.5)
            if info:
                dev.services_detail["snmp"] = info
        except Exception:
            pass

    # SMB
    if config.smb and 445 in ports:
        try:
            info = smb.fingerprint(dev.ip, 445, timeout=config.banner_timeout)
            if info:
                dev.services_detail["smb"] = info
        except Exception:
            pass

    # active protocol probes (FTP/SMTP/MySQL/Redis/RTSP/RDP/VNC/MQTT/...)
    try:
        probes.probe_device(dev, timeout=config.banner_timeout)
    except Exception as exc:
        log.debug("probes %s failed: %s", dev.ip, exc)

    # fold mDNS / SSDP identity into a friendly name if we still lack one
    _apply_discovery_names(dev)


def _apply_banner_to_port(dev, port, product, version, banner):
    for pr in dev.ports:
        if pr.port == port:
            if product and not pr.product:
                pr.product = product
            if version and not pr.version:
                pr.version = version
            if banner and not pr.banner:
                pr.banner = banner
            break


def _apply_discovery_names(dev):
    if dev.mdns_name in ("-", "") :
        pass
    # promote upnp friendlyName into hostname if nothing better exists
    upnp = dev.services_detail.get("upnp") or {}
    if dev.hostname in ("-", "") and upnp.get("friendlyName"):
        dev.hostname = upnp["friendlyName"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.os_detect
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.os_detect'] = r'''"""
Operating-system inference.

Combines multiple weak signals into a best-guess OS family with a confidence
level:

  * TTL bucket from the ICMP reply (64 -> *nix/macOS/Android, 128 -> Windows,
    255 -> network gear).
  * Banner hints (SSH comment strings, HTTP Server headers, SNMP sysDescr).
  * SMB presence (implies Windows or Samba).
  * Optional authoritative nmap OS match.
"""

from ..logging_setup import get_logger

log = get_logger("fingerprint.os")


def from_ttl(ttl):
    if ttl is None:
        return "", ""
    if ttl <= 64:
        return "Linux/Unix/macOS/Android", f"TTL {ttl}"
    if ttl <= 128:
        return "Windows", f"TTL {ttl}"
    return "Network device", f"TTL {ttl}"


def _from_banner(text):
    if not text:
        return ""
    low = text.lower()
    table = [
        ("windows", "Windows"), ("ubuntu", "Ubuntu Linux"),
        ("debian", "Debian Linux"), ("raspbian", "Raspberry Pi OS"),
        ("centos", "CentOS Linux"), ("red hat", "RHEL"),
        ("freebsd", "FreeBSD"), ("openwrt", "OpenWrt"),
        ("mikrotik", "MikroTik RouterOS"), ("routeros", "MikroTik RouterOS"),
        ("darwin", "macOS"), ("mac os", "macOS"), ("android", "Android"),
        ("dd-wrt", "DD-WRT"), ("dropbear", "Embedded Linux"),
        ("vxworks", "VxWorks"), ("cisco", "Cisco IOS"),
    ]
    for token, name in table:
        if token in low:
            return name
    return ""


def infer(device):
    """
    Populate device.os_guess / device.os_confidence from all available signals.
    """
    signals = []

    # strongest: explicit banner hints
    for pr in device.ports:
        hint = _from_banner(f"{pr.product} {pr.version} {pr.banner}")
        if hint:
            signals.append((hint, "banner", 3))
    ssh = device.services_detail.get("ssh") or {}
    if ssh.get("os_hint"):
        signals.append((ssh["os_hint"], "ssh", 3))
    snmp = device.services_detail.get("snmp") or {}
    if snmp.get("sysdescr"):
        hint = _from_banner(snmp["sysdescr"])
        if hint:
            signals.append((hint, "snmp", 3))
    for h in device.http:
        hint = _from_banner(f"{h.server} {h.powered_by}")
        if hint:
            signals.append((hint, "http", 2))

    # medium: SMB implies Windows/Samba
    if device.has_port(445) or device.has_port(139):
        signals.append(("Windows / SMB host", "smb", 2))

    # nmap authoritative if present
    nmap_os = device.services_detail.get("nmap_os")
    if nmap_os:
        signals.append((nmap_os, "nmap", 5))

    # weakest: TTL bucket
    ttl_os, ttl_conf = from_ttl(device.ttl)
    if ttl_os:
        signals.append((ttl_os, "ttl", 1))

    if not signals:
        device.os_guess = "-"
        device.os_confidence = ""
        return device

    # pick the highest-weight signal
    signals.sort(key=lambda s: -s[2])
    best_os, source, weight = signals[0]
    conf = {5: "high", 3: "medium", 2: "medium", 1: "low"}.get(weight, "low")
    detail = f"{source}"
    if source == "ttl" and device.ttl is not None:
        detail = f"TTL {device.ttl}"
    device.os_guess = best_os
    device.os_confidence = f"{conf} ({detail})"
    return device
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.probes
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.probes'] = r'''"""
Active protocol probes for deep per-service research.

Each probe speaks just enough of a protocol to extract identifying details and,
where relevant, a security-relevant fact (anonymous FTP allowed, Redis without
authentication, RTSP camera methods, exposed database version, etc.). All are
short, timeout-bounded and dependency-free. Results are stored under
``device.services_detail[<service>]`` and consumed by the security checks.
"""

import re
import socket
import struct

from ..logging_setup import get_logger

log = get_logger("fingerprint.probes")


def _recv(sock, n=2048, timeout=3.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except Exception:
        return b""


def _connect(ip, port, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if s.connect_ex((str(ip), int(port))) == 0:
            return s
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
def ftp(ip, port=21, timeout=3.0):
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        greeting = _recv(s, timeout=timeout).decode("latin-1", "ignore").strip()
        info = {"banner": greeting[:160], "anonymous": False}
        try:
            s.sendall(b"USER anonymous\r\n")
            r1 = _recv(s, timeout=timeout).decode("latin-1", "ignore")
            if r1.startswith("331"):
                s.sendall(b"PASS scanfy@example.com\r\n")
                r2 = _recv(s, timeout=timeout).decode("latin-1", "ignore")
                info["anonymous"] = r2.startswith("230")
        except Exception:
            pass
        return info
    finally:
        s.close()


def smtp(ip, port=25, timeout=3.0):
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        greeting = _recv(s, timeout=timeout).decode("latin-1", "ignore").strip()
        info = {"banner": greeting[:160], "capabilities": [], "starttls": False}
        try:
            s.sendall(b"EHLO scanfy\r\n")
            resp = _recv(s, 4096, timeout).decode("latin-1", "ignore")
            caps = re.findall(r"25[015][ -](\S+)", resp)
            info["capabilities"] = caps[:20]
            info["starttls"] = "STARTTLS" in resp.upper()
        except Exception:
            pass
        return info
    finally:
        s.close()


def mysql(ip, port=3306, timeout=3.0):
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        data = _recv(s, 256, timeout)
        if len(data) < 6:
            return None
        # skip 4-byte packet header; byte 4 = protocol version; then NUL-term version
        proto = data[4]
        rest = data[5:]
        end = rest.find(b"\x00")
        version = rest[:end].decode("latin-1", "ignore") if end > 0 else ""
        return {"protocol": proto, "version": version[:40],
                "banner": version[:40]}
    except Exception:
        return None
    finally:
        s.close()


def redis(ip, port=6379, timeout=3.0):
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        s.sendall(b"*1\r\n$4\r\nINFO\r\n")
        data = _recv(s, 4096, timeout).decode("latin-1", "ignore")
        info = {"no_auth": False, "version": ""}
        if "redis_version" in data:
            info["no_auth"] = True   # INFO answered without AUTH
            m = re.search(r"redis_version:([\d.]+)", data)
            if m:
                info["version"] = m.group(1)
        elif "NOAUTH" in data:
            info["no_auth"] = False
        return info
    except Exception:
        return None
    finally:
        s.close()


def memcached(ip, port=11211, timeout=3.0):
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        s.sendall(b"version\r\n")
        data = _recv(s, 256, timeout).decode("latin-1", "ignore").strip()
        if data.upper().startswith("VERSION"):
            return {"no_auth": True, "version": data.split(" ", 1)[-1][:24]}
        return {"no_auth": False, "version": ""}
    except Exception:
        return None
    finally:
        s.close()


def rtsp(ip, port=554, timeout=3.0):
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        req = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
               "CSeq: 1\r\nUser-Agent: SCANFY\r\n\r\n").encode()
        s.sendall(req)
        data = _recv(s, 2048, timeout).decode("latin-1", "ignore")
        server = re.search(r"Server:\s*(.+)", data, re.I)
        public = re.search(r"Public:\s*(.+)", data, re.I)
        return {"server": server.group(1).strip()[:80] if server else "",
                "methods": public.group(1).strip()[:120] if public else "",
                "banner": data.splitlines()[0][:60] if data else ""}
    except Exception:
        return None
    finally:
        s.close()


def vnc(ip, port=5900, timeout=3.0):
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        data = _recv(s, 32, timeout)
        text = data.decode("latin-1", "ignore").strip()
        if text.startswith("RFB"):
            return {"version": text[:12]}
        return None
    except Exception:
        return None
    finally:
        s.close()


def rdp(ip, port=3389, timeout=3.0):
    """Send an X.224 connection request; a valid response confirms RDP."""
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        # TPKT + X.224 Connection Request with RDP negotiation
        cr = bytes.fromhex(
            "0300002a25e00000000000436f6f6b69653a206d737473686173683d0d0a"
            "0100080000000000")
        s.sendall(cr)
        data = _recv(s, 64, timeout)
        if data and data[0] == 0x03:
            # byte offset 11 (if present) carries the negotiation type
            nla = False
            if len(data) >= 19 and data[11] == 0x02:
                flags = data[15] if len(data) > 15 else 0
                nla = bool(flags & 0x02)
            return {"present": True, "nla": nla}
        return None
    except Exception:
        return None
    finally:
        s.close()


def mqtt(ip, port=1883, timeout=3.0):
    """Send an MQTT CONNECT and read the CONNACK return code."""
    s = _connect(ip, port, timeout)
    if not s:
        return None
    try:
        # CONNECT, protocol level 4 (MQTT 3.1.1), client id "scanfy"
        payload = b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x06scanfy"
        packet = b"\x10" + bytes([len(payload)]) + payload
        s.sendall(packet)
        data = _recv(s, 8, timeout)
        if len(data) >= 4 and data[0] == 0x20:
            rc = data[3]
            accepted = (rc == 0)
            return {"present": True, "accepted": accepted, "return_code": rc}
        return {"present": True, "accepted": False, "return_code": None}
    except Exception:
        return None
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Dispatch table: port -> (service_key, probe_fn)
# ---------------------------------------------------------------------------
PROBE_MAP = {
    21: ("ftp", ftp),
    25: ("smtp", smtp),
    587: ("smtp", smtp),
    3306: ("mysql", mysql),
    6379: ("redis", redis),
    11211: ("memcached", memcached),
    554: ("rtsp", rtsp),
    8554: ("rtsp", rtsp),
    5900: ("vnc", vnc),
    5901: ("vnc", vnc),
    3389: ("rdp", rdp),
    1883: ("mqtt", mqtt),
}


def probe_device(device, timeout=3.0):
    """Run every applicable probe for a device's open ports."""
    ports = device.port_set()
    for port, (key, fn) in PROBE_MAP.items():
        if port not in ports:
            continue
        try:
            result = fn(device.ip, port, timeout)
            if result:
                device.services_detail.setdefault("probes", {})[key] = result
                # fold a version/banner back onto the port
                for pr in device.ports:
                    if pr.port == port and not pr.product:
                        if result.get("version"):
                            pr.version = result["version"]
                        if result.get("banner") and not pr.banner:
                            pr.banner = result["banner"]
                        break
        except Exception as exc:
            log.debug("probe %s:%s failed: %s", device.ip, port, exc)
    return device.services_detail.get("probes", {})
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.smb
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.smb'] = r'''"""
SMB fingerprinting (best effort, no external dependencies).

Sends an SMB1/SMB2 negotiate request to port 445 and inspects the response to
determine the highest supported dialect and whether signing is required. This
is a lightweight probe - it does not authenticate or enumerate shares (that
would require a full SMB stack such as impacket) - but the negotiated dialect
already tells us a lot (e.g. SMBv1 still enabled is a real finding).
"""

import socket
import struct

from ..logging_setup import get_logger

log = get_logger("fingerprint.smb")

# An SMB1 "negotiate protocol" request listing common dialects, including the
# SMB2 wildcard so an SMB2-only server still answers.
_NEGOTIATE_SMB1 = bytes.fromhex(
    "000000d4ff534d4272000000001843c80000000000000000000000000000"
    "feff0000000000d100025043204e4554574f524b2050524f4752414d20312e"
    "3000024d4943524f534f4654204e4554574f524b5320312e303300024d4943"
    "524f534f4654204e4554574f524b5320332e3000024c414e4d414e312e3000"
    "024c4d312e325830303200024453414e2d5354304350313030300002444544"
    "5541454c202020202020310002444544554c202020202031000253414d4241"
    "0002504320294e4554574f524b2050524f4752414d20312e30000247412e30"
    "3000024e54204c4d20302e313200025357302e3132000200")

_DIALECTS = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0xFFFF: "SMB 2+ (wildcard)",
}


def _negotiate_smb2(sock):
    """Send an SMB2 negotiate and parse the dialect from the response."""
    # SMB2 header + negotiate request (dialects 0202,0210,0300,0302,0311)
    header = b"\xfeSMB" + b"\x00" * 60
    # This is a simplified static SMB2 NEGOTIATE; many servers still reply.
    body = struct.pack("<H", 36)          # StructureSize
    body += struct.pack("<H", 5)          # DialectCount
    body += struct.pack("<H", 1)          # SecurityMode = signing enabled
    body += struct.pack("<H", 0)          # Reserved
    body += struct.pack("<I", 0)          # Capabilities
    body += b"\x00" * 16                   # ClientGuid
    body += struct.pack("<I", 0)          # NegotiateContextOffset
    body += struct.pack("<H", 0)          # NegotiateContextCount
    body += struct.pack("<H", 0)          # Reserved2
    body += struct.pack("<HHHHH", 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    msg = header + body
    netbios = struct.pack(">I", len(msg))
    try:
        sock.sendall(netbios + msg)
        data = sock.recv(1024)
    except Exception:
        return None
    if len(data) > 0x48 and data[4:8] == b"\xfeSMB":
        dialect = struct.unpack_from("<H", data, 0x48)[0]
        return _DIALECTS.get(dialect, f"SMB2 dialect 0x{dialect:04x}")
    return None


def fingerprint(ip, port=445, timeout=4.0):
    """Return {"dialect", "smbv1"} or None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        if sock.connect_ex((str(ip), int(port))) != 0:
            return None
        dialect = _negotiate_smb2(sock)
        result = {"dialect": dialect or "unknown", "smbv1": False}
        # try an SMB1 negotiate to detect legacy SMBv1
        try:
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((str(ip), int(port))) == 0:
                sock.sendall(_NEGOTIATE_SMB1)
                data = sock.recv(1024)
                if data and data[4:8] == b"\xffSMB":
                    result["smbv1"] = True
                    if not dialect:
                        result["dialect"] = "SMB 1.0"
        except Exception:
            pass
        return result
    except Exception as exc:
        log.debug("smb fp %s failed: %s", ip, exc)
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.snmp
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.snmp'] = r'''"""
SNMP fingerprinting.

Sends an SNMPv1 GET for sysDescr (1.3.6.1.2.1.1.1.0) and sysName
(1.3.6.1.2.1.1.5.0) using common community strings. A successful read exposes
the device's own description (OS, model, firmware) and confirms a weak/default
community string - a notable finding on its own. Implemented with hand-built
BER packets so it needs no external SNMP library.
"""

import socket
import struct

from ..logging_setup import get_logger

log = get_logger("fingerprint.snmp")

COMMON_COMMUNITIES = ["public", "private", "community", "admin", "cisco"]

# OIDs (as byte sequences after the 1.3 prefix, encoded below)
OID_SYSDESCR = [1, 3, 6, 1, 2, 1, 1, 1, 0]
OID_SYSNAME = [1, 3, 6, 1, 2, 1, 1, 5, 0]
OID_SYSOBJECTID = [1, 3, 6, 1, 2, 1, 1, 2, 0]


def _encode_length(length):
    if length < 0x80:
        return bytes([length])
    out = b""
    while length:
        out = bytes([length & 0xFF]) + out
        length >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, value):
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_oid(oid):
    first = 40 * oid[0] + oid[1]
    body = bytes([first])
    for n in oid[2:]:
        if n < 0x80:
            body += bytes([n])
        else:
            chunk = []
            while n:
                chunk.insert(0, n & 0x7F)
                n >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            body += bytes(chunk)
    return _tlv(0x06, body)


def _encode_int(value):
    if value == 0:
        return _tlv(0x02, b"\x00")
    out = b""
    v = value
    while v:
        out = bytes([v & 0xFF]) + out
        v >>= 8
    return _tlv(0x02, out)


def _build_get(community, oid, request_id=0x1234):
    varbind = _tlv(0x30, _encode_oid(oid) + _tlv(0x05, b""))
    varbind_list = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _encode_int(request_id) + _encode_int(0) +
              _encode_int(0) + varbind_list)
    message = _tlv(0x30, _encode_int(0) +            # version 1 (0)
                   _tlv(0x04, community.encode()) + pdu)
    return message


def _extract_string(response):
    """Very small BER walk to pull the first OCTET STRING value from the PDU."""
    try:
        i = 0
        n = len(response)
        # find last OCTET STRING (0x04) which is usually the varbind value
        best = ""
        while i < n:
            tag = response[i]
            i += 1
            if i >= n:
                break
            length = response[i]
            i += 1
            if length & 0x80:
                num = length & 0x7F
                length = int.from_bytes(response[i:i + num], "big")
                i += num
            if tag == 0x04:
                val = response[i:i + length]
                text = val.decode("latin-1", "ignore").strip()
                if text and len(text) > 1:
                    best = text
            if tag in (0x30, 0xA2, 0xA0):
                continue  # descend into constructed
            else:
                i += length
        return best
    except Exception:
        return ""


def _query(ip, oid, community, timeout=1.5):
    packet = _build_get(community, oid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(packet, (str(ip), 161))
        data, _ = s.recvfrom(4096)
        return _extract_string(data)
    except Exception:
        return ""
    finally:
        s.close()


def fingerprint(ip, timeout=1.5):
    """Return {"community", "sysdescr", "sysname"} or None."""
    for community in COMMON_COMMUNITIES:
        descr = _query(ip, OID_SYSDESCR, community, timeout)
        if descr:
            name = _query(ip, OID_SYSNAME, community, timeout)
            log.info("snmp %s community=%s", ip, community)
            return {"community": community, "sysdescr": descr[:200],
                    "sysname": name[:80]}
    return None
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.ssh
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.ssh'] = r'''"""
SSH fingerprinting.

Reads the SSH identification string (e.g. ``SSH-2.0-OpenSSH_8.9p1 Ubuntu``)
which reveals the implementation, version and frequently the host OS/distro.
Optionally performs the very first step of the key exchange to learn the
server's offered host-key and encryption algorithms.
"""

import socket

from ..logging_setup import get_logger

log = get_logger("fingerprint.ssh")


def fingerprint(ip, port=22, timeout=4.0):
    """Return {"banner", "protocol", "software", "comments", "os_hint"}."""
    result = {"banner": "", "protocol": "", "software": "", "comments": "",
              "os_hint": ""}
    try:
        with socket.create_connection((str(ip), int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
    except Exception as exc:
        log.debug("ssh fp %s failed: %s", ip, exc)
        return None
    if not data:
        return None
    line = data.decode("latin-1", "ignore").splitlines()[0].strip()
    result["banner"] = line
    # SSH-<proto>-<software> <comments>
    if line.startswith("SSH-"):
        try:
            _, proto, rest = line.split("-", 2)
            result["protocol"] = proto
            if " " in rest:
                result["software"], result["comments"] = rest.split(" ", 1)
            else:
                result["software"] = rest
        except Exception:
            result["software"] = line
    low = line.lower()
    for token, os_name in (("ubuntu", "Ubuntu Linux"), ("debian", "Debian Linux"),
                           ("raspbian", "Raspberry Pi OS"), ("freebsd", "FreeBSD"),
                           ("centos", "CentOS"), ("windows", "Windows"),
                           ("dropbear", "Embedded Linux (Dropbear)"),
                           ("mikrotik", "MikroTik RouterOS")):
        if token in low:
            result["os_hint"] = os_name
            break
    return result
'''

# ---------------------------------------------------------------------------
# module: scanfyx.fingerprint.tls
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.fingerprint.tls'] = r'''"""
TLS / X.509 certificate fingerprinting.

Opens a TLS connection (no verification), captures the negotiated protocol and
cipher, then parses the peer certificate with ``cryptography`` (falling back to
the stdlib ``ssl`` dict). Extracts subject/issuer, validity window, SANs, key
size and signature algorithm, and derives weakness flags (self-signed, expired,
weak key/sig) consumed by the security analyzer.
"""

import datetime
import socket
import ssl

from .. import constants
from ..logging_setup import get_logger
from ..models import TlsInfo

log = get_logger("fingerprint.tls")


def _name_to_str(name):
    try:
        return ", ".join(f"{a.oid._name}={a.value}" for a in name)
    except Exception:
        return str(name)


def _common_name(name):
    try:
        from cryptography.x509.oid import NameOID
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def fingerprint(ip, port=443, timeout=4.0):
    """Return a TlsInfo for ip:port, or None on failure."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception:
        pass

    info = TlsInfo(port=port)
    raw_der = None
    try:
        with socket.create_connection((str(ip), int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=str(ip)) as ss:
                info.tls_version = ss.version() or ""
                cipher = ss.cipher()
                if cipher:
                    info.cipher = cipher[0]
                try:
                    raw_der = ss.getpeercert(binary_form=True)
                except Exception:
                    raw_der = None
    except Exception as exc:
        log.debug("tls connect %s:%s failed: %s", ip, port, exc)
        return None

    if raw_der and constants.HAS_CRYPTOGRAPHY:
        _parse_with_cryptography(info, raw_der)
    elif raw_der:
        _parse_minimal(info, raw_der)

    _derive_flags(info)
    return info


def _parse_with_cryptography(info, der):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        cert = x509.load_der_x509_certificate(der)
        info.subject = _name_to_str(cert.subject)
        info.issuer = _name_to_str(cert.issuer)
        info.subject_cn = _common_name(cert.subject)
        info.issuer_cn = _common_name(cert.issuer)
        info.serial = format(cert.serial_number, "x")[:32]
        try:
            info.not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d")
            info.not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d")
            now = datetime.datetime.now(datetime.timezone.utc)
            info.expired = cert.not_valid_after_utc < now
            info.not_yet_valid = cert.not_valid_before_utc > now
            info.days_to_expiry = (cert.not_valid_after_utc - now).days
        except Exception:
            # older cryptography without *_utc
            info.not_before = cert.not_valid_before.strftime("%Y-%m-%d")
            info.not_after = cert.not_valid_after.strftime("%Y-%m-%d")
            now = datetime.datetime.utcnow()
            info.expired = cert.not_valid_after < now
            info.days_to_expiry = (cert.not_valid_after - now).days
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info.san = [str(n.value) for n in ext.value][:20]
        except Exception:
            info.san = []
        try:
            info.sig_algorithm = cert.signature_algorithm_oid._name
        except Exception:
            info.sig_algorithm = ""
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info.key_type = "RSA"
            info.key_bits = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info.key_type = "EC"
            info.key_bits = pub.key_size
        else:
            info.key_type = type(pub).__name__
        info.self_signed = (info.subject == info.issuer)
    except Exception as exc:
        log.debug("cert parse failed: %s", exc)


def _parse_minimal(info, der):
    """Fallback parse using the stdlib ssl dict from a fresh handshake."""
    try:
        cert = ssl.DER_cert_to_PEM_cert(der)
        info.subject = "(parsed without cryptography)"
        info.san = []
        _ = cert
    except Exception:
        pass


def _derive_flags(info):
    weak = []
    if info.self_signed:
        weak.append("self-signed")
    if info.expired:
        weak.append("expired")
    if info.not_yet_valid:
        weak.append("not-yet-valid")
    if info.key_type == "RSA" and info.key_bits and info.key_bits < 2048:
        weak.append("weak-key")
    if info.sig_algorithm and ("md5" in info.sig_algorithm.lower()
                               or "sha1" in info.sig_algorithm.lower()):
        weak.append("weak-sig")
    if info.tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        weak.append(info.tls_version)
    # stash weaknesses on the object via a plain attribute the analyzer reads
    setattr(info, "_weaknesses", weak)
    return weak


def weaknesses(info):
    return getattr(info, "_weaknesses", [])
'''

# ---------------------------------------------------------------------------
# module: scanfyx.logging_setup
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.logging_setup'] = r'''"""
Logging configuration. Logs go to ``~/.scanfy/scanfy.log`` at DEBUG level and,
optionally, a concise stream to the console. Noisy third-party loggers
(scapy, urllib3, zeroconf) are silenced.
"""

import logging
import logging.handlers

from . import constants

_CONFIGURED = False


def setup_logging(verbose=False):
    global _CONFIGURED
    if _CONFIGURED:
        return logging.getLogger("scanfy")

    logger = logging.getLogger("scanfy")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # rotating file handler
    try:
        fh = logging.handlers.RotatingFileHandler(
            constants.LOG_PATH, maxBytes=1_000_000, backupCount=2,
            encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        logger.addHandler(fh)
    except Exception:
        pass

    if verbose:
        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(sh)

    # silence noisy libraries
    for noisy in ("scapy", "scapy.runtime", "scapy.loading", "urllib3",
                  "requests", "zeroconf", "asyncio", "chardet"):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)

    _CONFIGURED = True
    return logger


def get_logger(name="scanfy"):
    if not _CONFIGURED:
        setup_logging()
    return logging.getLogger(name if name.startswith("scanfy") else f"scanfy.{name}")
'''

# ---------------------------------------------------------------------------
# module: scanfyx.models
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.models'] = r'''"""
Typed data model for SCANFY.

These dataclasses are the single source of truth passed between the discovery,
scanning, fingerprinting, security and reporting layers. Every class provides
``to_dict`` for JSON/report serialisation and, where useful, ``from_dict``.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .constants import SEVERITY_WEIGHT, severity_rank


# ---------------------------------------------------------------------------
# Ports & services
# ---------------------------------------------------------------------------
@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    category: str = "misc"
    description: str = ""
    banner: str = ""
    product: str = ""
    version: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def label(self):
        return f"{self.port}/{self.service or self.protocol}"

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# TLS certificate info
# ---------------------------------------------------------------------------
@dataclass
class TlsInfo:
    port: int = 443
    tls_version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    subject_cn: str = ""
    issuer_cn: str = ""
    not_before: str = ""
    not_after: str = ""
    san: List[str] = field(default_factory=list)
    key_type: str = ""
    key_bits: int = 0
    sig_algorithm: str = ""
    serial: str = ""
    self_signed: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    days_to_expiry: Optional[int] = None

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# HTTP info
# ---------------------------------------------------------------------------
@dataclass
class HttpInfo:
    port: int = 80
    scheme: str = "http"
    url: str = ""
    status: Optional[int] = None
    server: str = ""
    title: str = ""
    powered_by: str = ""
    content_type: str = ""
    location: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[Dict[str, str]] = field(default_factory=list)
    device_kind: str = ""
    auth: str = ""
    favicon_hash: str = ""

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# Security finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str = "info"
    category: str = "general"
    title: str = ""
    description: str = ""
    recommendation: str = ""
    port: Optional[int] = None
    service: str = ""
    cves: List[str] = field(default_factory=list)
    evidence: str = ""

    def weight(self):
        return SEVERITY_WEIGHT.get(self.severity, 0.2)

    def rank(self):
        return severity_rank(self.severity)

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------
@dataclass
class Device:
    ip: str
    mac: str = "-"
    vendor: str = "-"
    hostname: str = "-"
    netbios: str = "-"
    mdns_name: str = "-"
    workgroup: str = "-"
    dns_names: List[str] = field(default_factory=list)
    ttl: Optional[int] = None
    os_guess: str = "-"
    os_confidence: str = ""
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    discovery_methods: List[str] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    http: List[HttpInfo] = field(default_factory=list)
    tls: List[TlsInfo] = field(default_factory=list)
    services_detail: Dict[str, Any] = field(default_factory=dict)
    device_type: str = "Unknown"
    device_kind: str = ""
    tags: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    risk_label: str = "info"
    randomized_mac: bool = False
    is_gateway: bool = False
    is_self: bool = False
    first_seen: str = ""
    last_seen: str = ""

    # -- helpers -----------------------------------------------------------
    def open_ports(self):
        return sorted(p.port for p in self.ports if p.state == "open")

    def has_port(self, port):
        return any(p.port == port and p.state == "open" for p in self.ports)

    def port_set(self):
        return {p.port for p in self.ports if p.state == "open"}

    def service_names(self):
        return [p.service for p in self.ports if p.service]

    def add_port(self, port_result):
        if not any(p.port == port_result.port and p.protocol == port_result.protocol
                   for p in self.ports):
            self.ports.append(port_result)

    def add_finding(self, finding):
        self.findings.append(finding)

    def add_tag(self, tag):
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def best_name(self):
        for candidate in (self.hostname, self.mdns_name, self.netbios):
            if candidate and candidate not in ("-", ""):
                return candidate
        return self.ip

    def ports_str(self, limit=None):
        items = [f"{p.port}/{p.service or p.protocol}" for p in
                 sorted(self.ports, key=lambda x: x.port)]
        if limit and len(items) > limit:
            return ", ".join(items[:limit]) + f" (+{len(items) - limit})"
        return ", ".join(items) if items else "-"

    def max_severity(self):
        if not self.findings:
            return "info"
        return min((f.severity for f in self.findings), key=severity_rank)

    def count_findings(self):
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self):
        d = asdict(self)
        # asdict already recursed into nested dataclasses (ports/http/tls/findings)
        return d


# ---------------------------------------------------------------------------
# Scan metadata & result
# ---------------------------------------------------------------------------
@dataclass
class ScanMeta:
    generated: str = ""
    scan_type: str = "Quick"
    profile: str = "default"
    network: str = ""
    local_ip: str = ""
    gateway: str = "-"
    dns: List[str] = field(default_factory=list)
    public_ip: str = ""
    isp: str = ""
    geo: str = ""
    methods: List[str] = field(default_factory=list)
    engine: str = ""
    duration: float = 0.0
    count: int = 0
    hostname: str = ""
    platform: str = ""

    def to_dict(self):
        return asdict(self)


class ScanResult:
    """A completed scan: the device list plus metadata and aggregates."""

    def __init__(self, devices, meta):
        self.devices: List[Device] = devices
        self.meta: ScanMeta = meta

    # -- aggregations ------------------------------------------------------
    def all_findings(self):
        out = []
        for d in self.devices:
            for f in d.findings:
                out.append((d, f))
        out.sort(key=lambda pair: severity_rank(pair[1].severity))
        return out

    def severity_counts(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for d in self.devices:
            for f in d.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def type_distribution(self):
        dist = {}
        for d in self.devices:
            dist[d.device_type] = dist.get(d.device_type, 0) + 1
        return sorted(dist.items(), key=lambda kv: -kv[1])

    def vendor_distribution(self):
        dist = {}
        for d in self.devices:
            v = d.vendor if d.vendor not in ("-", "", "unknown") else "unknown"
            dist[v] = dist.get(v, 0) + 1
        return sorted(dist.items(), key=lambda kv: -kv[1])

    def service_distribution(self):
        dist = {}
        for d in self.devices:
            for p in d.ports:
                if p.state == "open":
                    key = p.service or str(p.port)
                    dist[key] = dist.get(key, 0) + 1
        return sorted(dist.items(), key=lambda kv: -kv[1])

    def category_distribution(self):
        dist = {}
        for d in self.devices:
            for p in d.ports:
                if p.state == "open":
                    dist[p.category] = dist.get(p.category, 0) + 1
        return sorted(dist.items(), key=lambda kv: -kv[1])

    def total_open_ports(self):
        return sum(len(d.open_ports()) for d in self.devices)

    def riskiest(self, n=5):
        return sorted(self.devices, key=lambda d: -d.risk_score)[:n]

    def overall_risk_score(self):
        if not self.devices:
            return 0.0
        return round(sum(d.risk_score for d in self.devices), 1)

    def risk_grade(self):
        counts = self.severity_counts()
        if counts["critical"]:
            return "F"
        if counts["high"] >= 3:
            return "E"
        if counts["high"]:
            return "D"
        if counts["medium"] >= 3:
            return "C"
        if counts["medium"]:
            return "B"
        return "A"

    def to_dict(self):
        return {
            "meta": self.meta.to_dict(),
            "aggregates": {
                "severity": self.severity_counts(),
                "types": self.type_distribution(),
                "services": self.service_distribution(),
                "risk_score": self.overall_risk_score(),
                "risk_grade": self.risk_grade(),
            },
            "devices": [d.to_dict() for d in self.devices],
        }


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
'''

# ---------------------------------------------------------------------------
# module: scanfyx.monitor
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.monitor'] = r'''"""
Continuous network monitor.

Repeatedly runs a lightweight discovery pass on an interval, compares each pass
to a baseline and emits events when a device joins or leaves the network. Useful
for spotting rogue/unexpected devices. The heavy scanning subsystems are not
used here - just fast multi-method discovery - so it stays cheap enough to run
for long periods.
"""

import time

from .logging_setup import get_logger
from .utils import netutils

log = get_logger("monitor")


class NetworkMonitor:
    def __init__(self, network, config, env, discovery_fn, on_event=None):
        """
        ``discovery_fn(network, config, env)`` -> list[Device].
        ``on_event(event_type, device)`` is called for 'join'/'leave'.
        """
        self.network = network
        self.config = config
        self.env = env
        self.discovery_fn = discovery_fn
        self.on_event = on_event
        self.baseline = {}     # key -> device
        self.running = False

    @staticmethod
    def _key(dev):
        return dev.mac if dev.mac and dev.mac != "-" else dev.ip

    def _snapshot(self):
        devices = self.discovery_fn(self.network, self.config, self.env)
        return {self._key(d): d for d in devices}

    def establish_baseline(self):
        self.baseline = self._snapshot()
        log.info("baseline established: %d devices", len(self.baseline))
        return self.baseline

    def poll_once(self):
        """Run one comparison pass. Returns (joined, left) device lists."""
        current = self._snapshot()
        joined = [d for k, d in current.items() if k not in self.baseline]
        left = [d for k, d in self.baseline.items() if k not in current]
        for d in joined:
            if self.on_event:
                self.on_event("join", d)
        for d in left:
            if self.on_event:
                self.on_event("leave", d)
        # merge: keep known + add new; drop long-gone
        self.baseline = current
        return joined, left

    def run(self, interval=30, iterations=None, stop_event=None):
        """Blocking monitor loop. ``iterations=None`` runs until interrupted."""
        self.running = True
        if not self.baseline:
            self.establish_baseline()
        count = 0
        try:
            while self.running:
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(interval)
                self.poll_once()
                count += 1
                if iterations is not None and count >= iterations:
                    break
        finally:
            self.running = False
        return count

    def stop(self):
        self.running = False
'''

# ---------------------------------------------------------------------------
# module: scanfyx.portscan
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.portscan'] = r'''"""Port scanning, banner grabbing and optional nmap integration."""

from . import scanner, banner, nmap_integration

__all__ = ["scanner", "banner", "nmap_integration"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.portscan.banner
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.portscan.banner'] = r'''"""
TCP banner grabbing.

For each open port SCANFY tries to read a service banner. Some services speak
first (SSH, FTP, SMTP, POP3, IMAP, MySQL, Redis, VNC); others need a nudge, so
protocol-appropriate probes are sent (an HTTP HEAD for web ports, ``\\r\\n`` for
line protocols). Product/version strings are parsed out where the format is
well known.
"""

import re
import socket

from ..logging_setup import get_logger

log = get_logger("portscan.banner")

# Probes sent for ports that stay silent until spoken to.
_PROBES = {
    "http": b"HEAD / HTTP/1.0\r\nHost: scanfy\r\nUser-Agent: SCANFY\r\n\r\n",
    "generic_line": b"\r\n",
    "help": b"HELP\r\n",
}

HTTP_LIKE = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888,
             9000, 9090, 10000}

# Regexes to lift product/version from common banners.
_PRODUCT_RES = [
    ("OpenSSH", re.compile(r"SSH-2\.0-OpenSSH[_/ ]?([\w.\-p]+)", re.I)),
    ("SSH", re.compile(r"SSH-([\d.]+)-(\S+)", re.I)),
    ("vsftpd", re.compile(r"\(vsFTPd ([\d.]+)\)", re.I)),
    ("ProFTPD", re.compile(r"ProFTPD ([\d.]+)", re.I)),
    ("Pure-FTPd", re.compile(r"Pure-FTPd", re.I)),
    ("FileZilla", re.compile(r"FileZilla Server ([\d.]+)", re.I)),
    ("Postfix", re.compile(r"ESMTP Postfix", re.I)),
    ("Exim", re.compile(r"Exim ([\d.]+)", re.I)),
    ("Sendmail", re.compile(r"Sendmail ([\d.\-/]+)", re.I)),
    ("Dovecot", re.compile(r"Dovecot", re.I)),
    ("MySQL", re.compile(r"([\d]+\.[\d]+\.[\d]+)[\w\-]*[\x00]?.*mysql", re.I)),
    ("MariaDB", re.compile(r"([\d.]+)-MariaDB", re.I)),
    ("Redis", re.compile(r"redis_version:([\d.]+)", re.I)),
    ("RFB/VNC", re.compile(r"RFB ([\d.]+)", re.I)),
    ("Microsoft FTP", re.compile(r"Microsoft FTP Service", re.I)),
]


def _parse_product(banner):
    for product, rx in _PRODUCT_RES:
        m = rx.search(banner)
        if m:
            version = ""
            if m.groups():
                version = next((g for g in m.groups() if g), "")
            return product, version
    return "", ""


def grab(ip, port, timeout=3.0):
    """
    Connect to ip:port, obtain a banner. Returns dict with keys
    ``banner``, ``product``, ``version`` (any may be empty).
    """
    result = {"banner": "", "product": "", "version": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        if sock.connect_ex((str(ip), int(port))) != 0:
            return result
        # try passive read first (many services greet you)
        data = b""
        try:
            data = sock.recv(1024)
        except socket.timeout:
            data = b""
        except Exception:
            data = b""
        # if silent, nudge with an appropriate probe
        if not data:
            probe = _PROBES["http"] if int(port) in HTTP_LIKE else _PROBES["generic_line"]
            try:
                sock.sendall(probe)
                sock.settimeout(timeout)
                data = sock.recv(2048)
            except Exception:
                data = b""
        if data:
            text = data.decode("latin-1", "ignore")
            banner = re.sub(r"[\r\n]+", " ", text).strip()
            banner = re.sub(r"[^\x20-\x7e]", ".", banner)[:300]
            result["banner"] = banner
            product, version = _parse_product(text)
            result["product"] = product
            result["version"] = version
    except Exception as exc:
        log.debug("banner %s:%s failed: %s", ip, port, exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result
'''

# ---------------------------------------------------------------------------
# module: scanfyx.portscan.nmap_integration
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.portscan.nmap_integration'] = r'''"""
Optional nmap integration.

When the ``nmap`` binary is installed and python-nmap is importable, SCANFY can
delegate service/version detection and OS fingerprinting to nmap for a single
host (used by the deep single-host dossier). Everything degrades gracefully if
nmap is not present.
"""

from .. import constants
from ..logging_setup import get_logger

log = get_logger("portscan.nmap")


def available():
    return constants.HAS_NMAP_BINARY


def scan_host(ip, ports=None, service_version=True, os_detect=False,
              timeout=120):
    """
    Run nmap against a single host. Returns a normalised dict:
        {ports: [{port, proto, state, service, product, version, extra}],
         os: [{name, accuracy}], raw: <nmap dict>}
    Returns None if nmap is unavailable or the scan fails.
    """
    if not available():
        return None
    try:
        import nmap
    except Exception as exc:
        log.debug("python-nmap import failed: %s", exc)
        return None

    args = ["-Pn"]
    if service_version:
        args.append("-sV")
    if os_detect:
        args.append("-O")
    port_arg = ",".join(str(p) for p in ports) if ports else None

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=str(ip), ports=port_arg,
                     arguments=" ".join(args), timeout=timeout)
    except Exception as exc:
        log.debug("nmap scan failed for %s: %s", ip, exc)
        return None

    if str(ip) not in scanner.all_hosts():
        return None

    host = scanner[str(ip)]
    out = {"ports": [], "os": [], "raw": {}}
    for proto in host.all_protocols():
        for port in sorted(host[proto].keys()):
            p = host[proto][port]
            out["ports"].append({
                "port": int(port), "proto": proto, "state": p.get("state", ""),
                "service": p.get("name", ""), "product": p.get("product", ""),
                "version": p.get("version", ""),
                "extra": p.get("extrainfo", ""), "cpe": p.get("cpe", ""),
            })
    try:
        for match in host.get("osmatch", []):
            out["os"].append({"name": match.get("name", ""),
                              "accuracy": match.get("accuracy", "")})
    except Exception:
        pass
    return out
'''

# ---------------------------------------------------------------------------
# module: scanfyx.portscan.scanner
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.portscan.scanner'] = r'''"""
TCP connect port scanner.

Runs a bounded, highly parallel connect() scan across the alive host set, then
optionally grabs banners on the ports that turn out open. Port sets are chosen
by profile: ``top100``, ``default`` (curated ~250), ``all`` (1-1024 + juicy
high ports) or a caller-supplied custom list.
"""

from .. import constants
from ..data import services
from ..logging_setup import get_logger
from ..models import PortResult
from ..utils import concurrency, netutils
from . import banner as banner_mod

log = get_logger("portscan.scanner")


def select_ports(config):
    """Resolve the configured port set into an explicit list of ports."""
    which = config.port_set
    if which == "top100":
        return list(services.TOP_100_TCP)
    if which == "all":
        base = set(range(1, 1025))
        base |= set(services.PORT_SERVICES.keys())
        base |= {1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5984, 6379,
                 8080, 8443, 8888, 9000, 9100, 9200, 11211, 27017, 32400,
                 49152, 49153, 62078}
        return sorted(base)
    if which == "custom" and config.custom_ports:
        return sorted(set(int(p) for p in config.custom_ports))
    return list(services.DEFAULT_SCAN_PORTS)


def scan_hosts(devices, ports, config, progress=None, stop_event=None):
    """
    Connect-scan ``ports`` on every device. Populates ``device.ports`` with
    :class:`PortResult` for each open port. Returns the total open-port count.
    """
    ip_list = [d.ip for d in devices]
    by_ip = {d.ip: d for d in devices}
    if not ip_list or not ports:
        return 0

    tasks = [(ip, port) for ip in ip_list for port in ports]
    if progress:
        progress.phase("Port scan", len(tasks))

    timeout = config.tcp_timeout

    def probe(args):
        ip, port = args
        if netutils.tcp_connect(ip, port, timeout):
            return (ip, port)
        return None

    results = concurrency.parallel_map(
        probe, tasks, max_workers=config.max_port_workers,
        on_step=progress.step if progress else None, stop_event=stop_event)

    open_pairs = [r for r in results if r]
    for ip, port in open_pairs:
        info = services.describe(port)
        pr = PortResult(port=port, protocol="tcp", state="open",
                        service=info["name"], category=info["category"],
                        description=info["description"])
        by_ip[ip].add_port(pr)

    total_open = len(open_pairs)
    log.info("port scan: %d open ports across %d hosts", total_open, len(devices))

    # ---- banners -------------------------------------------------------
    if config.banners and open_pairs:
        _grab_banners(by_ip, open_pairs, config, progress)

    # attach UDP hints discovered earlier as (closed|open) informational ports
    for dev in devices:
        for uport in dev.services_detail.get("udp_ports", []) or []:
            if not any(p.port == uport and p.protocol == "udp" for p in dev.ports):
                info = services.describe(uport)
                dev.add_port(PortResult(port=uport, protocol="udp",
                                        state="open|filtered", service=info["name"],
                                        category=info["category"],
                                        description=info["description"]))
    return total_open


def _grab_banners(by_ip, open_pairs, config, progress):
    if progress:
        progress.phase("Banner grabbing", len(open_pairs))

    def work(args):
        ip, port = args
        return (ip, port, banner_mod.grab(ip, port, config.banner_timeout))

    results = concurrency.parallel_map(
        work, open_pairs, max_workers=min(config.max_fp_workers * 2, 128),
        on_step=progress.step if progress else None)

    for res in results:
        if not res:
            continue
        ip, port, info = res
        dev = by_ip.get(ip)
        if not dev:
            continue
        for pr in dev.ports:
            if pr.port == port and pr.protocol == "tcp":
                pr.banner = info.get("banner", "")
                if info.get("product"):
                    pr.product = info["product"]
                if info.get("version"):
                    pr.version = info["version"]
                break


def quick_scan_single(ip, ports, timeout=0.7):
    """Convenience: return the list of open ports for one host."""
    open_ports = []
    for port in ports:
        if netutils.tcp_connect(ip, port, timeout):
            open_ports.append(port)
    return open_ports
'''

# ---------------------------------------------------------------------------
# module: scanfyx.report
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.report'] = r'''"""
Dossier reporting.

Turns a :class:`~scanfyx.models.ScanResult` into shareable artefacts:

    charts      self-contained inline SVG charts (no JS/CDN)
    html        the full styled HTML reconnaissance dossier
    markdown    a Markdown dossier
    exporters   JSON / CSV / XML / TXT
    pdf         a PDF dossier (requires reportlab)

All formats are written to the configured report directory with a timestamped
filename.
"""

from . import charts, html, markdown, exporters, pdf

__all__ = ["charts", "html", "markdown", "exporters", "pdf"]


FORMATS = {
    "html": ("HTML dossier", html.export),
    "markdown": ("Markdown dossier", markdown.export),
    "json": ("JSON", exporters.export_json),
    "csv": ("CSV", exporters.export_csv),
    "xml": ("XML", exporters.export_xml),
    "txt": ("Text dossier", exporters.export_txt),
    "pdf": ("PDF dossier", pdf.export),
}
'''

# ---------------------------------------------------------------------------
# module: scanfyx.report.charts
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.report.charts'] = r'''"""
Inline SVG chart generation.

Hand-drawn, self-contained SVG (no JavaScript, no external libraries) so the
HTML dossier renders identically offline. Provides a donut, horizontal bars, a
risk gauge and a stacked severity bar, all themed to SCANFY's grass palette.
"""

import math

from ..constants import CHART_COLORS, SEVERITY_COLOR
from ..utils.textutils import esc_html


def donut(pairs, size=190, thickness=32):
    """Donut chart from [(label, value), ...]. Returns an <svg> string."""
    pairs = [(l, v) for l, v in pairs if v > 0]
    if not pairs:
        return "<div class='chart-empty'>no data</div>"
    total = sum(v for _, v in pairs) or 1
    r = (size - thickness) / 2
    circ = 2 * math.pi * r
    cx = cy = size / 2
    segments, acc = [], 0.0
    for i, (_, val) in enumerate(pairs):
        seg = (val / total) * circ
        color = CHART_COLORS[i % len(CHART_COLORS)]
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" '
            f'stroke="{color}" stroke-width="{thickness}" '
            f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
            f'stroke-dashoffset="{-acc:.2f}" transform="rotate(-90 {cx} {cy})">'
            f'</circle>')
        acc += seg
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
            f'class="donut" role="img" aria-label="distribution">'
            f'{"".join(segments)}'
            f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" class="donut-num">{total}</text>'
            f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" class="donut-lbl">total</text>'
            f'</svg>')


def legend(pairs, max_items=12):
    pairs = [(l, v) for l, v in pairs if v > 0][:max_items]
    items = []
    for i, (label, val) in enumerate(pairs):
        color = CHART_COLORS[i % len(CHART_COLORS)]
        items.append(
            f'<li><span class="dot" style="background:{color}"></span>'
            f'<span class="lg-label">{esc_html(label)}</span>'
            f'<b>{val}</b></li>')
    return "<ul class='legend'>" + "".join(items) + "</ul>"


def hbars(pairs, width=440, bar_h=22, gap=8, label_w=140, max_items=12):
    pairs = [(l, v) for l, v in pairs if v > 0][:max_items]
    if not pairs:
        return "<div class='chart-empty'>no data</div>"
    maxv = max(v for _, v in pairs) or 1
    chart_w = width - label_w - 46
    rows, y = [], 4
    for i, (label, val) in enumerate(pairs):
        w = max(3, chart_w * val / maxv)
        color = CHART_COLORS[i % len(CHART_COLORS)]
        rows.append(
            f'<text x="{label_w - 8}" y="{y + bar_h * 0.68:.0f}" '
            f'text-anchor="end" class="bar-lbl">{esc_html(label)}</text>'
            f'<rect x="{label_w}" y="{y}" width="{w:.1f}" height="{bar_h}" '
            f'rx="4" fill="{color}"></rect>'
            f'<text x="{label_w + w + 7:.1f}" y="{y + bar_h * 0.68:.0f}" '
            f'class="bar-val">{val}</text>')
        y += bar_h + gap
    return (f'<svg viewBox="0 0 {width} {y}" width="100%" height="{y}" '
            f'class="bars">{"".join(rows)}</svg>')


def risk_gauge(score, size=180):
    """A 180-degree gauge for a 0-100 risk score."""
    score = max(0.0, min(100.0, float(score)))
    cx = cy = size / 2
    r = size / 2 - 16
    start_a = math.pi              # 180deg (left)
    end_a = 0.0                    # 0deg (right)
    frac = score / 100.0
    cur_a = start_a + (end_a - start_a) * frac

    def point(angle):
        return cx + r * math.cos(angle), cy - r * math.sin(angle)

    x0, y0 = point(start_a)
    x1, y1 = point(cur_a)
    xe, ye = point(end_a)
    # colour ramps green -> amber -> red
    if score < 30:
        color = "#6abe30"
    elif score < 55:
        color = "#e6c85a"
    elif score < 75:
        color = "#e69a3f"
    else:
        color = "#dc5050"
    large = 1 if frac > 0.5 else 0
    track = (f'<path d="M {x0:.1f} {y0:.1f} A {r} {r} 0 1 1 {xe:.1f} {ye:.1f}" '
             f'fill="none" stroke="#26331d" stroke-width="14" stroke-linecap="round"/>')
    arc = (f'<path d="M {x0:.1f} {y0:.1f} A {r} {r} 0 {large} 1 {x1:.1f} {y1:.1f}" '
           f'fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"/>')
    return (f'<svg viewBox="0 0 {size} {size*0.62:.0f}" width="{size}" '
            f'class="gauge">{track}{arc}'
            f'<text x="{cx}" y="{cy}" text-anchor="middle" class="gauge-num" '
            f'style="fill:{color}">{score:.0f}</text>'
            f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" class="gauge-lbl">risk</text>'
            f'</svg>')


def severity_bar(counts, width=440, height=26):
    order = ["critical", "high", "medium", "low", "info"]
    total = sum(counts.get(s, 0) for s in order) or 1
    x = 0
    segs = []
    for s in order:
        v = counts.get(s, 0)
        if not v:
            continue
        w = width * v / total
        segs.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="{height}" '
                    f'fill="{SEVERITY_COLOR[s]}"><title>{s}: {v}</title></rect>')
        x += w
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'class="sevbar" preserveAspectRatio="none">{"".join(segs)}</svg>')
'''

# ---------------------------------------------------------------------------
# module: scanfyx.report.common
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.report.common'] = r'''"""Shared reporting helpers (output paths, small formatting utilities)."""

import os
from datetime import datetime

from .. import constants


def report_path(config, ext, prefix="scanfy_dossier"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = getattr(config, "report_dir", None) or constants.REPORT_DIR_DEFAULT
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        out_dir = constants.REPORT_DIR_DEFAULT
    return os.path.join(out_dir, f"{prefix}_{stamp}.{ext}")


def ports_inline(device, limit=None):
    items = [f"{p.port}/{p.service or p.protocol}"
             for p in sorted(device.ports, key=lambda x: x.port)]
    if limit and len(items) > limit:
        return ", ".join(items[:limit]) + f" (+{len(items) - limit})"
    return ", ".join(items) if items else "-"


def latency_str(ms):
    if ms is None:
        return "-"
    try:
        return "<1 ms" if float(ms) < 1 else f"{float(ms):.0f} ms"
    except (TypeError, ValueError):
        return "-"
'''

# ---------------------------------------------------------------------------
# module: scanfyx.report.exporters
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.report.exporters'] = r'''"""
Structured exporters: JSON, CSV, XML and a plain-text dossier.
"""

import csv
import json

from ..version import MOTTO_EN, MOTTO_PT
from ..security import scorecard as sc_mod
from ..utils.textutils import esc_xml
from .common import report_path, ports_inline, latency_str


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def export_json(result, config):
    path = report_path(config, "json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    return path


# ---------------------------------------------------------------------------
# CSV (device inventory)
# ---------------------------------------------------------------------------
def export_csv(result, config):
    path = report_path(config, "csv")
    fields = ["ip", "mac", "vendor", "hostname", "netbios", "device_type",
              "os_guess", "os_confidence", "latency_ms", "risk_score",
              "risk_label", "open_ports", "findings", "discovery"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for d in result.devices:
            w.writerow([
                d.ip, d.mac, d.vendor, d.best_name(), d.netbios, d.device_type,
                d.os_guess, d.os_confidence,
                "" if d.latency_ms is None else d.latency_ms,
                d.risk_score, d.risk_label, ports_inline(d), len(d.findings),
                "+".join(d.discovery_methods),
            ])
    return path


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------
def export_xml(result, config):
    path = report_path(config, "xml")
    m = result.meta
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<scanfy>"]
    lines.append("  <meta>")
    for k, v in m.to_dict().items():
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        lines.append(f"    <{k}>{esc_xml(v)}</{k}>")
    lines.append("  </meta>")
    counts = result.severity_counts()
    lines.append("  <summary "
                 f'devices="{len(result.devices)}" '
                 f'risk_grade="{result.risk_grade()}" '
                 f'risk_score="{result.overall_risk_score()}" '
                 f'critical="{counts["critical"]}" high="{counts["high"]}" '
                 f'medium="{counts["medium"]}" low="{counts["low"]}"/>')
    lines.append("  <devices>")
    for d in result.devices:
        lines.append(f'    <device ip="{esc_xml(d.ip)}" mac="{esc_xml(d.mac)}" '
                     f'type="{esc_xml(d.device_type)}" '
                     f'risk="{d.risk_score}">')
        lines.append(f"      <vendor>{esc_xml(d.vendor)}</vendor>")
        lines.append(f"      <hostname>{esc_xml(d.best_name())}</hostname>")
        lines.append(f"      <os>{esc_xml(d.os_guess)}</os>")
        lines.append("      <ports>")
        for p in sorted(d.ports, key=lambda x: x.port):
            lines.append(f'        <port number="{p.port}" proto="{p.protocol}" '
                         f'service="{esc_xml(p.service)}" '
                         f'product="{esc_xml(p.product)}" '
                         f'version="{esc_xml(p.version)}"/>')
        lines.append("      </ports>")
        lines.append("      <findings>")
        for fnd in d.findings:
            lines.append(f'        <finding severity="{fnd.severity}" '
                         f'category="{esc_xml(fnd.category)}" '
                         f'port="{fnd.port if fnd.port else ""}">'
                         f"{esc_xml(fnd.title)}</finding>")
        lines.append("      </findings>")
        lines.append("    </device>")
    lines.append("  </devices>")
    lines.append("</scanfy>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


# ---------------------------------------------------------------------------
# Plain-text dossier
# ---------------------------------------------------------------------------
def export_txt(result, config):
    path = report_path(config, "txt")
    m = result.meta
    counts = result.severity_counts()
    L = []
    bar = "=" * 74
    L.append(bar)
    L.append("SCANFY - NETWORK RECONNAISSANCE DOSSIER")
    L.append(bar)
    L.append(f"Generated : {m.generated}")
    L.append(f"Scan type : {m.scan_type} ({m.profile})")
    L.append(f"Network   : {m.network}")
    L.append(f"Operator  : {m.local_ip}  ({m.hostname})")
    L.append(f"Gateway   : {m.gateway}")
    L.append(f"DNS       : {', '.join(m.dns) if m.dns else '-'}")
    if m.public_ip:
        L.append(f"Public IP : {m.public_ip}  {m.isp}  {m.geo}")
    L.append(f"Methods   : {', '.join(m.methods)}")
    L.append(f"Engine    : {m.engine}")
    L.append(f"Duration  : {m.duration}s")
    L.append("")
    L.append(f"Devices   : {len(result.devices)}")
    L.append(f"Risk grade: {result.risk_grade()}   (score {result.overall_risk_score()})")
    L.append(f"Findings  : critical={counts['critical']} high={counts['high']} "
             f"medium={counts['medium']} low={counts['low']} info={counts['info']}")
    L.append(bar)

    # inventory
    L.append("\n== INVENTORY ==")
    for d in result.devices:
        tag = " (you)" if d.is_self else (" (router)" if d.is_gateway else "")
        L.append(f"\n[{d.ip}]{tag}  {d.device_type}   risk={d.risk_score} ({d.risk_label})")
        L.append(f"  MAC/Vendor : {d.mac}  {d.vendor}")
        L.append(f"  Hostname   : {d.best_name()}   NetBIOS: {d.netbios}")
        if d.mdns_name not in ("-", ""):
            L.append(f"  mDNS name  : {d.mdns_name}")
        L.append(f"  OS guess   : {d.os_guess}  {d.os_confidence}")
        L.append(f"  Latency    : {latency_str(d.latency_ms)}   "
                 f"Discovery: {'+'.join(d.discovery_methods)}")
        L.append(f"  Open ports : {ports_inline(d)}")
        for p in sorted(d.ports, key=lambda x: x.port):
            extra = " ".join(filter(None, [p.product, p.version]))
            if p.banner or extra:
                L.append(f"     {p.port}/{p.service}: {extra} {p.banner}".rstrip())
        for h in d.http:
            L.append(f"  Web {h.url} [{h.status}] {h.server} {h.title}".rstrip())
        for t in d.tls:
            L.append(f"  TLS :{t.port} {t.tls_version} CN={t.subject_cn} "
                     f"issuer={t.issuer_cn} key={t.key_type}{t.key_bits}")
        if d.findings:
            L.append("  Findings:")
            for fnd in d.findings:
                cve = (" " + ",".join(fnd.cves)) if fnd.cves else ""
                L.append(f"    ! [{fnd.severity.upper():8}] {fnd.title}{cve}")
                if fnd.recommendation:
                    L.append(f"        -> {fnd.recommendation}")

    # security scorecard
    L.append("\n" + bar)
    L.append("== SECURITY SCORECARD ==")
    L.append(sc_mod.text_summary(sc_mod.build(result)))

    # findings summary
    all_f = result.all_findings()
    if all_f:
        L.append("\n" + bar)
        L.append("== SECURITY FINDINGS (by severity) ==")
        for dev, fnd in all_f:
            L.append(f"  [{fnd.severity.upper():8}] {dev.ip:<15} "
                     f"{(str(fnd.port) + '/' + fnd.service) if fnd.port else '':<16} {fnd.title}")

    L.append("\n" + bar)
    L.append(f"{MOTTO_EN} / {MOTTO_PT}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path
'''

# ---------------------------------------------------------------------------
# module: scanfyx.report.html
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.report.html'] = r'''"""
The SCANFY HTML reconnaissance dossier.

A single, self-contained, offline HTML document: cover page, executive summary
with a risk gauge and inline SVG charts, a security-findings register, a logical
topology overview, the full device inventory and a detailed per-device dossier
card for every host. No external resources are referenced.
"""

from ..version import __version__, MOTTO_EN, MOTTO_PT
from ..utils.textutils import esc_html, esc_attr
from .. import topology as topo
from ..security import scorecard as sc_mod
from . import charts
from .common import report_path, latency_str


CSS = """
:root{
  --grass:#6abe30;--grass-l:#96dc5a;--grass-d:#4e9120;--leaf:#3fa7a0;
  --bg:#0c110b;--panel:#141d10;--panel2:#18220f;--line:#26331d;
  --text:#e7f0e0;--dim:#7d8c74;--gold:#e6c85a;--red:#dc5050;--amber:#e69a3f;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font-family:'Segoe UI',system-ui,Roboto,sans-serif;line-height:1.5;font-size:14px}
.page{max-width:1160px;margin:0 auto;padding:34px 26px 70px}
a{color:var(--grass-l);text-decoration:none}
a:hover{text-decoration:underline}
header.cover{border:1px solid var(--line);border-radius:18px;
  background:radial-gradient(1200px 300px at 10% -20%,#20301a,transparent),
             linear-gradient(150deg,#111a0e,#1b2612);padding:30px 32px;margin-bottom:26px}
.brand{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
h1{font-family:ui-monospace,Consolas,monospace;letter-spacing:6px;color:var(--grass-l);
  margin:0;font-size:40px;text-shadow:0 2px 12px rgba(106,190,48,.25)}
.brand .ver{color:var(--dim);font-family:ui-monospace,monospace}
.cover .tag{color:var(--dim);margin-top:4px;letter-spacing:.5px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
  gap:6px 26px;margin-top:20px;font-size:13.5px}
.meta b{color:var(--grass-l);font-weight:600;margin-right:6px}
h2{color:var(--grass);border-bottom:2px solid var(--grass-d);padding-bottom:8px;
  margin:38px 0 16px;font-size:21px;letter-spacing:.5px}
h2 .cnt{color:var(--dim);font-size:14px;font-weight:400}
.grid{display:grid;gap:16px}
.summary{display:grid;grid-template-columns:220px 1fr;gap:18px;align-items:stretch}
@media(max-width:760px){.summary{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.gauge-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center}
.grade{font-size:46px;font-weight:800;font-family:ui-monospace,monospace;margin-top:2px}
.grade small{display:block;font-size:12px;color:var(--dim);letter-spacing:2px;font-weight:400}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}
.card{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:13px 16px}
.card .k{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:1px}
.card .v{font-size:26px;font-weight:700;margin-top:3px;color:var(--grass-l)}
.card.crit .v{color:#ff6b6b}.card.high .v{color:var(--amber)}.card.med .v{color:var(--gold)}
.sevbar{border-radius:6px;overflow:hidden;margin-top:6px}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
@media(max-width:760px){.charts{grid-template-columns:1fr}}
.chart-box h3{margin:0 0 10px;font-size:13px;color:var(--dim);text-transform:uppercase;letter-spacing:1px}
.donut-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.donut-num{fill:var(--grass-l);font:700 30px ui-monospace,monospace}
.donut-lbl{fill:var(--dim);font:11px sans-serif;text-transform:uppercase;letter-spacing:1px}
.gauge-num{font:800 30px ui-monospace,monospace}
.gauge-lbl{fill:var(--dim);font:11px sans-serif;letter-spacing:2px;text-transform:uppercase}
.legend{list-style:none;margin:0;padding:0;font-size:13px}
.legend li{margin:3px 0;display:flex;align-items:center;gap:7px}
.legend .dot{width:11px;height:11px;border-radius:3px;flex:none}
.legend .lg-label{flex:1}.legend b{color:var(--grass-l)}
.bar-lbl{fill:var(--text);font:12px sans-serif}.bar-val{fill:var(--dim);font:12px sans-serif}
.chart-empty{color:var(--dim);font-style:italic;padding:12px}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{background:#111a0e;color:var(--grass);text-align:left;padding:11px 12px;
  border-bottom:2px solid var(--grass-d);white-space:nowrap;position:sticky;top:0}
td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:hover td{background:#111a0e}
.mono,.ip,.ports{font-family:ui-monospace,Consolas,monospace}
.ip{color:var(--grass-l);font-weight:600;white-space:nowrap}
.ports{color:var(--grass)}.dim{color:var(--dim)}
.tag{font-size:10.5px;padding:1px 7px;border-radius:20px;margin-left:6px;white-space:nowrap}
.tag.you{background:var(--grass-d);color:#fff}.tag.router{background:#8a6d2a;color:#fff}
.sev{font-weight:700;padding:2px 9px;border-radius:20px;font-size:10.5px;letter-spacing:.5px;white-space:nowrap}
.sev.critical{background:#3a1010;color:#ff8080}.sev.high{background:#3a2410;color:#ffb27a}
.sev.medium{background:#3a3510;color:#ffe07a}.sev.low{background:#22301b;color:#a9c98f}
.sev.info{background:#1c2618;color:#9fb495}
.risk-pill{font-weight:700;padding:1px 8px;border-radius:20px;font-size:11px}
.risk-critical{background:#3a1010;color:#ff8080}.risk-high{background:#3a2410;color:#ffb27a}
.risk-medium{background:#3a3510;color:#ffe07a}.risk-low{background:#22301b;color:#a9c98f}
.risk-info{background:#1c2618;color:#9fb495}
.topo{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.topo .grp{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.topo .grp h4{margin:0 0 8px;color:var(--grass-l);font-size:13px}
.topo .node{font-size:12.5px;padding:2px 0;border-bottom:1px dashed #21301a}
.topo .node:last-child{border-bottom:none}
.dev{background:var(--panel);border:1px solid var(--line);border-radius:14px;
  padding:18px 20px;margin-bottom:14px;scroll-margin-top:12px}
.dev.r-critical{border-left:4px solid var(--red)}.dev.r-high{border-left:4px solid var(--amber)}
.dev.r-medium{border-left:4px solid var(--gold)}.dev.r-low{border-left:4px solid var(--grass-d)}
.dev h3{margin:0;font-size:18px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.dev h3 .ip{font-size:18px}.dev .devtype{color:var(--leaf);font-size:13px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:2px 12px;margin-top:12px;font-size:13px}
.kv .k{color:var(--dim)}.kv .v{color:var(--text);word-break:break-word}
.pill{display:inline-block;background:#111a0e;border:1px solid var(--line);border-radius:6px;
  padding:2px 8px;margin:2px 4px 2px 0;font-family:ui-monospace,monospace;font-size:12px;color:var(--grass)}
.subtable{width:100%;margin-top:8px;font-size:12.5px}
.subtable th{position:static;background:#0f170c;font-size:11px}
.chips{margin-top:6px}
.chip{display:inline-block;background:#17220f;border:1px solid var(--line);color:var(--grass-l);
  border-radius:20px;padding:1px 9px;margin:2px 4px 2px 0;font-size:11.5px}
.find{margin:6px 0;padding-left:2px}
footer{margin-top:44px;text-align:center;color:var(--dim);font-style:italic;
  border-top:1px solid var(--line);padding-top:24px}
footer b{color:var(--grass-l);font-style:normal;font-size:18px;letter-spacing:1px}
.note{color:var(--dim);font-size:12px;margin-top:8px;font-style:normal}
@media print{
  body{background:#fff;color:#111}.page{max-width:100%}
  .panel,.card,.dev,.wrap,.topo .grp,header.cover{background:#fff;border-color:#ccc}
  h1,.ip,.card .v,.legend b,footer b{color:#2e6b12}
  th{background:#eee;color:#2e6b12}tr:hover td{background:transparent}
  .dev{break-inside:avoid}
}
"""


def _cover(meta):
    rows = [
        ("Generated", esc_html(meta.generated)),
        ("Scan", f"{esc_html(meta.scan_type)} ({esc_html(meta.profile)})"),
        ("Network", esc_html(meta.network)),
        ("Operator", f"{esc_html(meta.local_ip)} ({esc_html(meta.hostname)})"),
        ("Gateway", esc_html(meta.gateway)),
        ("DNS", esc_html(", ".join(meta.dns) if meta.dns else "-")),
        ("Methods", esc_html(", ".join(meta.methods))),
        ("Duration", f"{esc_html(meta.duration)}s"),
    ]
    if meta.public_ip:
        rows.append(("Public IP", f"{esc_html(meta.public_ip)} · {esc_html(meta.isp)}"))
        if meta.geo:
            rows.append(("Location", esc_html(meta.geo)))
    meta_html = "".join(f"<span><b>{k}</b>{v}</span>" for k, v in rows)
    return f"""<header class="cover">
  <div class="brand"><h1>SCANFY</h1><span class="ver">v{__version__}</span></div>
  <div class="tag">network reconnaissance dossier</div>
  <div class="meta">{meta_html}</div>
</header>"""


def _summary(result):
    counts = result.severity_counts()
    grade = result.risk_grade()
    score = result.overall_risk_score()
    grade_color = {"A": "#6abe30", "B": "#9ec16a", "C": "#e6c85a",
                   "D": "#e69a3f", "E": "#dc5050", "F": "#ff5c5c"}.get(grade, "#6abe30")
    cards = f"""<div class="cards">
      <div class="card"><div class="k">Devices</div><div class="v">{len(result.devices)}</div></div>
      <div class="card crit"><div class="k">Critical</div><div class="v">{counts['critical']}</div></div>
      <div class="card high"><div class="k">High</div><div class="v">{counts['high']}</div></div>
      <div class="card med"><div class="k">Medium</div><div class="v">{counts['medium']}</div></div>
      <div class="card"><div class="k">Open ports</div><div class="v">{result.total_open_ports()}</div></div>
    </div>
    <div style="margin-top:14px">{charts.severity_bar(counts)}</div>"""

    charts_html = f"""<div class="charts">
      <div class="chart-box panel"><h3>Device types</h3>
        <div class="donut-row">{charts.donut(result.type_distribution())}
        {charts.legend(result.type_distribution())}</div></div>
      <div class="chart-box panel"><h3>Top services</h3>
        {charts.hbars(result.service_distribution())}</div>
    </div>"""

    return f"""<h2>Executive summary</h2>
<div class="summary">
  <div class="panel gauge-wrap">
    {charts.risk_gauge(score)}
    <div class="grade" style="color:{grade_color}">{grade}<small>risk grade</small></div>
  </div>
  <div class="panel">{cards}</div>
</div>
{charts_html}"""


def _findings_section(result):
    all_f = result.all_findings()
    if not all_f:
        return ('<h2>Security findings</h2><div class="panel">'
                '<div class="v" style="color:var(--grass-l);font-size:16px">'
                'No risky exposed services detected ✓</div></div>')
    rows = []
    for dev, f in all_f:
        svc = f"{f.port}/{esc_html(f.service)}" if f.port else "-"
        cves = ", ".join(f.cves) if f.cves else ""
        rows.append(
            f'<tr><td><span class="sev {f.severity}">{f.severity.upper()}</span></td>'
            f'<td class="ip"><a href="#dev-{esc_attr(dev.ip)}">{esc_html(dev.ip)}</a></td>'
            f'<td class="dim">{esc_html(dev.device_type)}</td>'
            f'<td class="mono">{svc}</td>'
            f'<td>{esc_html(f.title)}<div class="dim" style="font-size:12px">{esc_html(f.recommendation)}</div></td>'
            f'<td class="mono">{esc_html(cves)}</td></tr>')
    return (f'<h2>Security findings <span class="cnt">({len(all_f)})</span></h2>'
            '<div class="wrap"><table><thead><tr><th>Severity</th><th>Host</th>'
            '<th>Type</th><th>Service</th><th>Finding</th><th>CVEs</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _scorecard_section(result):
    sc = sc_mod.build(result)
    ind = sc["indicators"]
    cats = "".join(
        f'<tr><td>{esc_html(c["category"])}</td>'
        f'<td><span class="sev {c["max_severity"]}">{c["max_severity"].upper()}</span></td>'
        f'<td>{c["count"]}</td><td>{c["hosts"]}</td></tr>'
        for c in sc["categories"])
    cats_table = (('<div class="wrap"><table><thead><tr><th>Category</th>'
                   '<th>Max severity</th><th>Findings</th><th>Hosts</th></tr></thead>'
                   f'<tbody>{cats}</tbody></table></div>') if cats
                  else '<div class="dim">No issues by category.</div>')

    rem = "".join(
        f'<tr><td><span class="sev {r["severity"]}">{r["severity"].upper()}</span></td>'
        f'<td>{esc_html(r["recommendation"])}<div class="dim" style="font-size:12px">'
        f'e.g. {esc_html(r["example"])}</div></td>'
        f'<td class="mono">{r["host_count"]}</td>'
        f'<td class="mono dim">{esc_html(", ".join(r["hosts"][:6]))}'
        f'{"…" if len(r["hosts"]) > 6 else ""}</td></tr>'
        for r in sc["remediation"][:14])
    rem_table = (('<div class="wrap"><table><thead><tr><th>Priority</th>'
                  '<th>Recommended action</th><th>Hosts</th><th>Affected</th>'
                  '</tr></thead>'
                  f'<tbody>{rem}</tbody></table></div>') if rem
                 else '<div class="panel"><div class="v" style="color:var(--grass-l)">'
                      'No remediation actions required ✓</div></div>')

    return (f'<h2>Security scorecard</h2>'
            f'<div class="cards">'
            f'<div class="card"><div class="k">Posture grade</div>'
            f'<div class="v">{sc["grade"]}</div></div>'
            f'<div class="card"><div class="k">Posture score</div>'
            f'<div class="v">{sc["score"]:.0f}</div></div>'
            f'<div class="card"><div class="k">Hosts w/ findings</div>'
            f'<div class="v">{ind["hosts_with_findings"]}/{ind["total"]}</div></div>'
            f'<div class="card"><div class="k">IoT / cameras</div>'
            f'<div class="v">{ind["iot_devices"]}</div></div>'
            f'<div class="card"><div class="k">TLS hosts</div>'
            f'<div class="v">{ind["encrypted_web"]}</div></div></div>'
            f'<div class="charts"><div class="chart-box"><h3>Issues by category</h3>'
            f'{cats_table}</div>'
            f'<div class="chart-box"><h3>Prioritised remediation plan</h3>'
            f'{rem_table}</div></div>')


def _topology_section(result):
    graph = topo.build_graph(result)
    grps = []
    for g in graph["groups"]:
        nodes = "".join(
            f'<div class="node"><span class="ip">{esc_html(n["ip"])}</span> '
            f'{esc_html(n["name"]) if n["name"] != n["ip"] else ""} '
            f'<span class="risk-pill risk-{n["risk"]}">{n["risk"]}</span></div>'
            for n in g["devices"])
        grps.append(f'<div class="grp"><h4>{esc_html(g["type"])} ({len(g["devices"])})</h4>{nodes}</div>')
    center = (f'<div class="grp" style="border-color:var(--grass-d)">'
              f'<h4>Gateway / Operator</h4>'
              f'<div class="node"><span class="ip">{esc_html(graph["gateway"])}</span> '
              f'<span class="tag router">router</span></div>'
              f'<div class="node"><span class="ip">{esc_html(graph["operator"])}</span> '
              f'<span class="tag you">you</span></div></div>')
    return (f'<h2>Topology overview</h2>'
            f'<div class="topo">{center}{"".join(grps)}</div>')


def _inventory_section(result):
    rows = []
    for d in result.devices:
        tag = ""
        if d.is_self:
            tag = ' <span class="tag you">you</span>'
        elif d.is_gateway:
            tag = ' <span class="tag router">router</span>'
        ports = ", ".join(f"{p.port}/{esc_html(p.service or p.protocol)}"
                          for p in sorted(d.ports, key=lambda x: x.port)) or '<span class=dim>none</span>'
        rows.append(
            f'<tr><td class="ip"><a href="#dev-{esc_attr(d.ip)}">{esc_html(d.ip)}</a>{tag}</td>'
            f'<td class="mono">{esc_html(d.mac)}</td><td>{esc_html(d.vendor)}</td>'
            f'<td>{esc_html(d.best_name())}</td><td>{esc_html(d.device_type)}</td>'
            f'<td class="dim">{esc_html(d.os_guess)}</td>'
            f'<td>{latency_str(d.latency_ms)}</td>'
            f'<td><span class="risk-pill risk-{d.risk_label}">{d.risk_score}</span></td>'
            f'<td class="ports">{ports}</td></tr>')
    return (f'<h2>Inventory <span class="cnt">({len(result.devices)} devices)</span></h2>'
            '<div class="wrap"><table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th>'
            '<th>Name</th><th>Type</th><th>OS guess</th><th>Latency</th><th>Risk</th>'
            '<th>Open ports</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _ports_subtable(device):
    if not device.ports:
        return '<div class="dim">no open ports detected</div>'
    rows = []
    for p in sorted(device.ports, key=lambda x: x.port):
        detail = " ".join(filter(None, [p.product, p.version]))
        banner = esc_html(p.banner[:120]) if p.banner else ""
        rows.append(
            f'<tr><td class="mono">{p.port}/{p.protocol}</td>'
            f'<td>{esc_html(p.service)}</td><td class="dim">{esc_html(p.category)}</td>'
            f'<td>{esc_html(detail)}</td><td class="dim mono">{banner}</td></tr>')
    return ('<table class="subtable"><thead><tr><th>Port</th><th>Service</th>'
            '<th>Category</th><th>Product/Version</th><th>Banner</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')


def _device_card(device):
    rlabel = device.risk_label
    kv = []
    kv.append(("MAC / Vendor", f'{esc_html(device.mac)} — {esc_html(device.vendor)}'
               + (' <span class="chip">randomized</span>' if device.randomized_mac else "")))
    kv.append(("Hostname", esc_html(device.hostname)))
    if device.netbios not in ("-", ""):
        kv.append(("NetBIOS", esc_html(device.netbios)
                   + (f' / {esc_html(device.workgroup)}' if device.workgroup not in ("-", "") else "")))
    if device.mdns_name not in ("-", ""):
        kv.append(("mDNS name", esc_html(device.mdns_name)))
    kv.append(("OS guess", f'{esc_html(device.os_guess)} <span class="dim">{esc_html(device.os_confidence)}</span>'))
    kv.append(("Latency", latency_str(device.latency_ms)))
    kv.append(("Discovery", esc_html("+".join(device.discovery_methods))))
    kv.append(("Risk", f'<span class="risk-pill risk-{rlabel}">{device.risk_score} ({rlabel})</span>'))

    # mDNS services chips
    mdns_svcs = device.services_detail.get("mdns_services") or []
    if mdns_svcs:
        chips = "".join(f'<span class="chip">{esc_html(s)}</span>' for s in mdns_svcs)
        kv.append(("mDNS services", f'<div class="chips">{chips}</div>'))
    upnp = device.services_detail.get("upnp") or {}
    if upnp.get("friendlyName") or upnp.get("modelName"):
        kv.append(("UPnP", esc_html(" · ".join(filter(None, [
            upnp.get("friendlyName", ""), upnp.get("manufacturer", ""),
            upnp.get("modelName", "")])))))
    ssh = device.services_detail.get("ssh") or {}
    if ssh.get("banner"):
        kv.append(("SSH", esc_html(ssh["banner"])))
    snmp = device.services_detail.get("snmp") or {}
    if snmp.get("sysdescr"):
        kv.append(("SNMP", esc_html(snmp["sysdescr"])
                   + f' <span class="dim">(community: {esc_html(snmp.get("community",""))})</span>'))
    smb = device.services_detail.get("smb") or {}
    if smb.get("dialect"):
        kv.append(("SMB", esc_html(smb["dialect"])
                   + (' <span class="chip">SMBv1</span>' if smb.get("smbv1") else "")))

    kv_html = "".join(f'<div class="k">{k}</div><div class="v">{v}</div>' for k, v in kv)

    # HTTP
    http_html = ""
    for h in device.http:
        techs = "".join(f'<span class="chip">{esc_html(t["name"])}</span>'
                        for t in h.technologies)
        http_html += (f'<div class="find"><b>Web</b> '
                      f'<a href="{esc_attr(h.url)}">{esc_html(h.url)}</a> '
                      f'[{esc_html(h.status)}] {esc_html(h.server)} '
                      f'<span class="dim">{esc_html(h.title)}</span> '
                      f'<div class="chips">{techs}</div></div>')

    # TLS
    tls_html = ""
    for t in device.tls:
        tls_html += (f'<div class="find"><b>TLS :{t.port}</b> {esc_html(t.tls_version)} '
                     f'· CN={esc_html(t.subject_cn)} · issuer={esc_html(t.issuer_cn)} '
                     f'· {esc_html(t.key_type)}{t.key_bits} · exp {esc_html(t.not_after)}</div>')

    # findings
    find_html = ""
    if device.findings:
        items = []
        for f in device.findings:
            cve = (" <span class='mono dim'>" + ", ".join(f.cves) + "</span>") if f.cves else ""
            items.append(
                f'<div class="find"><span class="sev {f.severity}">{f.severity.upper()}</span> '
                f'{esc_html(f.title)}{cve}<div class="dim" style="font-size:12px">'
                f'{esc_html(f.description)} <i>{esc_html(f.recommendation)}</i></div></div>')
        find_html = f'<div style="margin-top:12px"><b class="dim">Findings</b>{"".join(items)}</div>'

    tags = "".join(f'<span class="chip">{esc_html(t)}</span>' for t in device.tags)
    tagline = f'<div class="chips">{tags}</div>' if tags else ""

    return f"""<div class="dev r-{rlabel}" id="dev-{esc_attr(device.ip)}">
  <h3><span class="ip">● {esc_html(device.ip)}</span>
      <span class="devtype">{esc_html(device.device_type)}</span></h3>
  {tagline}
  <div class="kv">{kv_html}</div>
  <div style="margin-top:12px"><b class="dim">Open ports</b>{_ports_subtable(device)}</div>
  {('<div style="margin-top:10px">' + http_html + tls_html + '</div>') if (http_html or tls_html) else ''}
  {find_html}
</div>"""


def _devices_section(result):
    cards = "".join(_device_card(d) for d in result.devices)
    return f'<h2>Device dossiers <span class="cnt">({len(result.devices)})</span></h2>{cards}'


def render(result):
    m = result.meta
    body = "".join([
        _cover(m),
        _summary(result),
        _scorecard_section(result),
        _findings_section(result),
        _topology_section(result),
        _inventory_section(result),
        _devices_section(result),
    ])
    footer = (f'<footer><b>{MOTTO_EN}</b><br>{MOTTO_PT} \U0001f1e7\U0001f1f7'
              f'<div class="note">Engine: {esc_html(m.engine)} · Generated by '
              f'SCANFY v{__version__} · For authorized use on your own network only.</div>'
              f'</footer>')
    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SCANFY dossier — {esc_html(m.network)} — {esc_html(m.generated)}</title>
<style>{CSS}</style></head><body><div class="page">{body}{footer}</div></body></html>"""


def export(result, config):
    path = report_path(config, "html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render(result))
    return path
'''

# ---------------------------------------------------------------------------
# module: scanfyx.report.markdown
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.report.markdown'] = r'''"""Markdown dossier exporter."""

from ..version import MOTTO_EN, MOTTO_PT
from ..security import scorecard as sc_mod
from .common import report_path, ports_inline, latency_str


def export(result, config):
    path = report_path(config, "md")
    m = result.meta
    counts = result.severity_counts()
    L = []
    L.append("# SCANFY — Network Reconnaissance Dossier")
    L.append("")
    L.append(f"**Generated:** {m.generated}  ")
    L.append(f"**Scan type:** {m.scan_type} ({m.profile}) &nbsp; "
             f"**Network:** `{m.network}` &nbsp; **Duration:** {m.duration}s  ")
    L.append(f"**Operator:** `{m.local_ip}` ({m.hostname}) &nbsp; "
             f"**Gateway:** `{m.gateway}` &nbsp; **Methods:** {', '.join(m.methods)}  ")
    if m.public_ip:
        L.append(f"**Public IP:** `{m.public_ip}` &nbsp; {m.isp} &nbsp; {m.geo}  ")
    L.append(f"**Engine:** {m.engine}")
    L.append("")

    # summary
    L.append("## Executive summary")
    L.append("")
    L.append(f"- **Devices found:** {len(result.devices)}")
    L.append(f"- **Risk grade:** {result.risk_grade()} (score {result.overall_risk_score()})")
    L.append(f"- **Findings:** {counts['critical']} critical, {counts['high']} high, "
             f"{counts['medium']} medium, {counts['low']} low")
    L.append(f"- **Device types:** " +
             ", ".join(f"{t} ({n})" for t, n in result.type_distribution()))
    L.append(f"- **Top services:** " +
             ", ".join(f"{s} ({n})" for s, n in result.service_distribution()[:10]))
    L.append("")

    # top risky
    top = [d for d in result.riskiest(5) if d.risk_score > 0]
    if top:
        L.append("### Highest-risk devices")
        L.append("")
        L.append("| Device | Type | Risk | Findings |")
        L.append("|--------|------|------|----------|")
        for d in top:
            L.append(f"| `{d.ip}` {d.best_name()} | {d.device_type} | "
                     f"{d.risk_score} ({d.risk_label}) | {len(d.findings)} |")
        L.append("")

    # inventory
    L.append("## Inventory")
    L.append("")
    L.append("| IP | MAC | Vendor | Name | Type | OS | Risk | Open ports |")
    L.append("|----|-----|--------|------|------|----|------|-----------|")
    for d in result.devices:
        L.append(f"| {d.ip} | {d.mac} | {d.vendor} | {d.best_name()} | "
                 f"{d.device_type} | {d.os_guess} | {d.risk_score} | "
                 f"{ports_inline(d, limit=8)} |")
    L.append("")

    # findings
    all_f = result.all_findings()
    if all_f:
        L.append("## Security findings")
        L.append("")
        L.append("| Severity | Host | Service | Finding | CVEs |")
        L.append("|----------|------|---------|---------|------|")
        for dev, f in all_f:
            svc = f"{f.port}/{f.service}" if f.port else ""
            cves = ", ".join(f.cves) if f.cves else ""
            L.append(f"| {f.severity.upper()} | {dev.ip} | {svc} | "
                     f"{f.title} | {cves} |")
        L.append("")

    # security scorecard + remediation
    sc = sc_mod.build(result)
    L.append("## Security scorecard")
    L.append("")
    L.append(f"**Posture grade:** {sc['grade']} (score {sc['score']}/100) &nbsp; "
             f"**Hosts with findings:** {sc['indicators']['hosts_with_findings']}"
             f"/{sc['indicators']['total']}")
    L.append("")
    if sc["remediation"]:
        L.append("### Prioritised remediation plan")
        L.append("")
        L.append("| Priority | Recommended action | Hosts |")
        L.append("|----------|--------------------|-------|")
        for r in sc["remediation"][:14]:
            L.append(f"| {r['severity'].upper()} | {r['recommendation']} | "
                     f"{r['host_count']} |")
        L.append("")

    # per-device detail
    L.append("## Device dossiers")
    L.append("")
    for d in result.devices:
        L.append(f"### {d.ip} — {d.device_type}")
        L.append("")
        L.append(f"- **MAC / Vendor:** {d.mac} — {d.vendor}")
        L.append(f"- **Hostname:** {d.best_name()} &nbsp; **NetBIOS:** {d.netbios}")
        if d.mdns_name not in ("-", ""):
            L.append(f"- **mDNS:** {d.mdns_name}")
        L.append(f"- **OS guess:** {d.os_guess} {d.os_confidence}")
        L.append(f"- **Latency:** {latency_str(d.latency_ms)} &nbsp; "
                 f"**Discovery:** {'+'.join(d.discovery_methods)}")
        L.append(f"- **Risk:** {d.risk_score} ({d.risk_label})")
        if d.ports:
            L.append(f"- **Open ports:** {ports_inline(d)}")
        for h in d.http:
            techs = ", ".join(t["name"] for t in h.technologies)
            L.append(f"- **Web {h.url}** [{h.status}] {h.server} — {h.title} "
                     f"{'(' + techs + ')' if techs else ''}")
        for t in d.tls:
            L.append(f"- **TLS :{t.port}** {t.tls_version}, CN={t.subject_cn}, "
                     f"issuer={t.issuer_cn}, key={t.key_type}{t.key_bits}")
        if d.findings:
            L.append("- **Findings:**")
            for f in d.findings:
                cve = (" (" + ", ".join(f.cves) + ")") if f.cves else ""
                L.append(f"    - `{f.severity}` {f.title}{cve} — {f.recommendation}")
        L.append("")

    L.append("---")
    L.append("")
    L.append(f"**{MOTTO_EN}** — *{MOTTO_PT}* 🇧🇷")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path
'''

# ---------------------------------------------------------------------------
# module: scanfyx.report.pdf
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.report.pdf'] = r'''"""
PDF dossier exporter (requires reportlab).

Produces a paginated PDF with a cover block, an executive summary table, the
security-findings register and a per-device inventory. Degrades to ``None`` if
reportlab is not installed.
"""

from .. import constants
from ..version import __version__, MOTTO_EN, MOTTO_PT
from .common import report_path, ports_inline


def available():
    return constants.HAS_REPORTLAB


def export(result, config):
    if not available():
        return None
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle)
    except Exception:
        return None

    path = report_path(config, "pdf")
    m = result.meta
    counts = result.severity_counts()

    grass = colors.HexColor("#4e9120")
    grass_l = colors.HexColor("#6abe30")
    dark = colors.HexColor("#1b2612")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("H1x", parent=styles["Title"], textColor=grass,
                              fontSize=26, spaceAfter=2))
    styles.add(ParagraphStyle("Sub", parent=styles["Normal"],
                              textColor=colors.grey, fontSize=9))
    styles.add(ParagraphStyle("H2x", parent=styles["Heading2"], textColor=grass,
                              spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8))

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm,
                            rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm,
                            title="SCANFY dossier")
    story = []
    story.append(Paragraph("SCANFY", styles["H1x"]))
    story.append(Paragraph(f"network reconnaissance dossier · v{__version__}",
                           styles["Sub"]))
    story.append(Spacer(1, 8))

    meta_rows = [
        ["Generated", m.generated, "Scan", f"{m.scan_type} ({m.profile})"],
        ["Network", m.network, "Operator", f"{m.local_ip}"],
        ["Gateway", m.gateway, "Duration", f"{m.duration}s"],
        ["Methods", ", ".join(m.methods), "Engine", m.engine],
    ]
    mt = Table(meta_rows, colWidths=[26 * mm, 60 * mm, 26 * mm, 50 * mm])
    mt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), grass_l),
        ("TEXTCOLOR", (2, 0), (2, -1), grass_l),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(mt)
    story.append(Spacer(1, 10))

    # summary
    story.append(Paragraph("Executive summary", styles["H2x"]))
    summ = [["Devices", str(len(result.devices)), "Risk grade",
             f"{result.risk_grade()} ({result.overall_risk_score()})"],
            ["Critical", str(counts["critical"]), "High", str(counts["high"])],
            ["Medium", str(counts["medium"]), "Low", str(counts["low"])],
            ["Open ports", str(result.total_open_ports()), "Info",
             str(counts["info"])]]
    st = Table(summ, colWidths=[30 * mm, 40 * mm, 30 * mm, 40 * mm])
    st.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, -1), dark),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#26331d")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(st)

    # findings
    all_f = result.all_findings()
    if all_f:
        story.append(Paragraph(f"Security findings ({len(all_f)})", styles["H2x"]))
        data = [["Sev", "Host", "Service", "Finding"]]
        sev_bg = {"critical": "#3a1010", "high": "#3a2410", "medium": "#3a3510",
                  "low": "#22301b", "info": "#1c2618"}
        for dev, f in all_f[:60]:
            svc = f"{f.port}/{f.service}" if f.port else "-"
            data.append([f.severity.upper(), dev.ip, svc,
                         Paragraph(f.title, styles["Small"])])
        ft = Table(data, colWidths=[16 * mm, 26 * mm, 26 * mm, 94 * mm], repeatRows=1)
        style = [("FONTSIZE", (0, 0), (-1, -1), 7.5),
                 ("BACKGROUND", (0, 0), (-1, 0), grass),
                 ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                 ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
                 ("VALIGN", (0, 0), (-1, -1), "TOP")]
        for i, (dev, f) in enumerate(all_f[:60], start=1):
            style.append(("TEXTCOLOR", (0, i), (0, i),
                          colors.HexColor({"critical": "#cc0000", "high": "#cc6600",
                                           "medium": "#999900", "low": "#4e9120",
                                           "info": "#777777"}.get(f.severity, "#333"))))
        ft.setStyle(TableStyle(style))
        story.append(ft)

    # inventory
    story.append(Paragraph("Inventory", styles["H2x"]))
    inv = [["IP", "Vendor", "Type", "OS", "Risk", "Ports"]]
    for d in result.devices:
        inv.append([d.ip, (d.vendor or "-")[:22], d.device_type[:20],
                    (d.os_guess or "-")[:18], str(d.risk_score),
                    Paragraph(ports_inline(d, limit=8), styles["Small"])])
    it = Table(inv, colWidths=[26 * mm, 32 * mm, 30 * mm, 28 * mm, 12 * mm, 34 * mm],
               repeatRows=1)
    it.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("BACKGROUND", (0, 0), (-1, 0), grass),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f6ee")]),
    ]))
    story.append(it)

    story.append(Spacer(1, 16))
    story.append(Paragraph(f"<b>{MOTTO_EN}</b> — {MOTTO_PT}", styles["Sub"]))

    try:
        doc.build(story)
        return path
    except Exception:
        return None
'''

# ---------------------------------------------------------------------------
# module: scanfyx.security
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.security'] = r'''"""Security analysis: findings, CVE correlation and risk scoring."""

from . import checks, cve, analyzer, scorecard

__all__ = ["checks", "cve", "analyzer", "scorecard"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.security.analyzer
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.security.analyzer'] = r'''"""
Security analyzer.

Runs every check plus CVE correlation against each device, de-duplicates the
resulting findings, sorts them by severity and computes a per-device risk score
(0-100) and label. Also produces a compact network-wide security summary.
"""

from ..constants import SEVERITY_WEIGHT, severity_rank
from ..logging_setup import get_logger
from . import checks, cve

log = get_logger("security")


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.severity, f.title, f.port, f.category)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _risk_score(findings):
    """Blend finding weights into a 0-100 device risk score."""
    if not findings:
        return 0.0
    score = 0.0
    for f in findings:
        score += SEVERITY_WEIGHT.get(f.severity, 0.2)
    # diminishing returns so one host can't exceed 100
    score = 100.0 * (1 - (0.86 ** score))
    return round(score, 1)


def _risk_label(score, findings):
    sev = {f.severity for f in findings}
    if "critical" in sev or score >= 70:
        return "critical"
    if "high" in sev or score >= 45:
        return "high"
    if "medium" in sev or score >= 20:
        return "medium"
    if findings:
        return "low"
    return "info"


def analyze_device(device):
    findings = []
    for check in checks.ALL_CHECKS:
        try:
            findings.extend(check(device) or [])
        except Exception as exc:
            log.debug("check %s failed on %s: %s", check.__name__, device.ip, exc)
    try:
        findings.extend(cve.correlate(device))
    except Exception as exc:
        log.debug("cve correlate failed on %s: %s", device.ip, exc)

    findings = _dedupe(findings)
    findings.sort(key=lambda f: severity_rank(f.severity))
    device.findings = findings
    device.risk_score = _risk_score(findings)
    device.risk_label = _risk_label(device.risk_score, findings)
    return device


def analyze(devices):
    for d in devices:
        analyze_device(d)
    return devices


def network_summary(result):
    """Return a dict summarising the security posture of the whole scan."""
    counts = result.severity_counts()
    top = result.riskiest(5)
    return {
        "severity": counts,
        "total_findings": sum(counts.values()),
        "risk_grade": result.risk_grade(),
        "overall_score": result.overall_risk_score(),
        "top_risky": [
            {"ip": d.ip, "name": d.best_name(), "type": d.device_type,
             "score": d.risk_score, "label": d.risk_label,
             "findings": len(d.findings)}
            for d in top if d.risk_score > 0
        ],
    }
'''

# ---------------------------------------------------------------------------
# module: scanfyx.security.checks
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.security.checks'] = r'''"""
Individual security checks.

Each function inspects one aspect of a device and yields zero or more
:class:`Finding` objects. The analyzer runs them all. Checks are deliberately
conservative and explain *why* something matters plus *how* to remediate.
"""

from ..data import vuln_db
from ..data.services import service_name
from ..models import Finding


def check_exposed_services(device):
    """Flag risky services that are open on the network."""
    out = []
    for pr in device.ports:
        if pr.state not in ("open", "open|filtered"):
            continue
        rule = vuln_db.service_risk(pr.port)
        if not rule:
            continue
        out.append(Finding(
            severity=rule["severity"], category="exposed-service",
            title=rule["title"], description=rule["description"],
            recommendation=rule["recommendation"], port=pr.port,
            service=pr.service or service_name(pr.port),
            evidence=pr.banner[:120] if pr.banner else ""))
    return out


def check_default_credentials(device):
    """Hint at services commonly shipped with default/weak credentials."""
    out = []
    ports = device.port_set()
    seen_services = set()
    for pr in device.ports:
        svc = (pr.service or "").lower()
        hint = vuln_db.default_cred_hint(svc)
        if hint and svc not in seen_services:
            seen_services.add(svc)
            out.append(Finding(
                severity="low", category="default-credentials",
                title=f"{pr.service} may use default credentials",
                description=f"{pr.service} is frequently deployed with weak or "
                            f"default credentials ({hint}).",
                recommendation="Change default credentials; enforce strong auth.",
                port=pr.port, service=pr.service))
    # SNMP with a working common community string is concrete evidence
    snmp = device.services_detail.get("snmp") or {}
    if snmp.get("community"):
        out.append(Finding(
            severity="medium", category="default-credentials",
            title=f"SNMP community '{snmp['community']}' accepted",
            description="A common SNMP community string was accepted, exposing "
                        "device details and potentially allowing writes.",
            recommendation="Use SNMPv3; replace community strings; restrict access.",
            port=161, service="snmp",
            evidence=snmp.get("sysdescr", "")[:120]))
    return out


def check_tls(device):
    """Flag TLS weaknesses discovered during fingerprinting."""
    out = []
    weak_map = device.services_detail.get("tls_weak", {}) or {}
    for ti in device.tls:
        weaknesses = weak_map.get(ti.port, [])
        for w in weaknesses:
            meta = vuln_db.TLS_WEAKNESSES.get(w)
            if not meta:
                continue
            out.append(Finding(
                severity=meta["severity"], category="tls",
                title=f"TLS: {w}", description=meta["note"],
                recommendation="Update the certificate / disable weak protocols.",
                port=ti.port, service="tls",
                evidence=f"{ti.subject_cn or ti.subject} (issuer {ti.issuer_cn})"))
        if ti.days_to_expiry is not None and 0 <= ti.days_to_expiry <= 21:
            out.append(Finding(
                severity="low", category="tls",
                title="TLS certificate expiring soon",
                description=f"Certificate expires in {ti.days_to_expiry} days.",
                recommendation="Renew the certificate.", port=ti.port,
                service="tls"))
    return out


def check_http_headers(device):
    """Flag missing HTTP security headers and version leakage."""
    out = []
    for h in device.http:
        missing = h.headers.get("_missing_security", "")
        if missing:
            miss_list = [m for m in missing.split(",") if m]
            # only surface the two most important as a single finding
            important = [m for m in miss_list
                         if m in ("strict-transport-security", "content-security-policy")]
            if important:
                out.append(Finding(
                    severity="low", category="http-hardening",
                    title="Missing HTTP security headers",
                    description="Web interface is missing: " + ", ".join(miss_list) + ".",
                    recommendation="Add HSTS, CSP and related headers.",
                    port=h.port, service="http"))
        if h.server and any(ch.isdigit() for ch in h.server):
            out.append(Finding(
                severity="info", category="info-leak",
                title="Server banner leaks version",
                description=f"Server header reveals software/version: {h.server}",
                recommendation="Suppress detailed version banners.",
                port=h.port, service="http", evidence=h.server))
        if h.auth and "auth required" not in h.auth.lower() and h.status == 200 \
                and h.device_kind in ("router", "camera", "nas", "bmc"):
            out.append(Finding(
                severity="medium", category="access-control",
                title=f"{h.device_kind} admin UI reachable without auth prompt",
                description=f"The {h.device_kind} management interface at {h.url} "
                            "returned 200 without an authentication challenge.",
                recommendation="Verify access controls; require authentication.",
                port=h.port, service="http", evidence=h.title))
    return out


def check_smb(device):
    """Flag SMBv1 and unsigned SMB."""
    out = []
    smb = device.services_detail.get("smb") or {}
    if smb.get("smbv1"):
        out.append(Finding(
            severity="high", category="protocol",
            title="SMBv1 enabled",
            description="SMBv1 is obsolete and vulnerable (EternalBlue/WannaCry).",
            recommendation="Disable SMBv1; require SMBv2/3 with signing.",
            port=445, service="smb", evidence=smb.get("dialect", "")))
    return out


def check_upnp(device):
    """Flag exposed UPnP that can auto-open firewall pinholes."""
    out = []
    if device.services_detail.get("ssdp_server") or device.has_port(1900) \
            or device.has_port(5000):
        st = device.services_detail.get("ssdp_st", [])
        if any("InternetGatewayDevice" in s or "WANIPConnection" in s for s in st):
            out.append(Finding(
                severity="medium", category="exposed-service",
                title="UPnP IGD control exposed",
                description="The router exposes UPnP IGD, which lets LAN devices "
                            "open inbound firewall ports automatically.",
                recommendation="Disable UPnP on the router unless required.",
                port=1900, service="ssdp"))
    return out


def check_randomized_mac(device):
    if device.randomized_mac:
        return [Finding(
            severity="info", category="privacy",
            title="Randomized (locally-administered) MAC",
            description="This host uses a randomized MAC address (a privacy "
                        "feature of modern phones/laptops); vendor is not "
                        "determinable from the MAC.",
            recommendation="No action needed - expected behaviour.")]
    return []


def check_plaintext_protocols(device):
    """Emphasise cleartext protocols carrying credentials."""
    out = []
    ports = device.port_set()
    cleartext = {21: "FTP", 23: "Telnet", 80: "HTTP (if used for auth)",
                 110: "POP3", 143: "IMAP", 143: "IMAP"}
    present = [p for p in (21, 23, 110, 143) if p in ports]
    if 23 in present:
        pass  # already covered by exposed-service (high)
    if 21 in present:
        pass  # covered by exposed-service
    # POP3/IMAP without TLS counterparts
    if 110 in ports and 995 not in ports:
        out.append(Finding(severity="low", category="protocol",
                            title="POP3 without POP3S",
                            description="Cleartext POP3 offered without the TLS variant.",
                            recommendation="Offer POP3S (995) and disable cleartext.",
                            port=110, service="pop3"))
    if 143 in ports and 993 not in ports:
        out.append(Finding(severity="low", category="protocol",
                            title="IMAP without IMAPS",
                            description="Cleartext IMAP offered without the TLS variant.",
                            recommendation="Offer IMAPS (993) and disable cleartext.",
                            port=143, service="imap"))
    return out


def check_service_probes(device):
    """Turn active-probe results into concrete findings."""
    out = []
    probes = device.services_detail.get("probes") or {}

    ftp = probes.get("ftp")
    if ftp and ftp.get("anonymous"):
        out.append(Finding(
            severity="high", category="access-control",
            title="Anonymous FTP login allowed",
            description="The FTP server accepted an anonymous login, exposing "
                        "its contents without credentials.",
            recommendation="Disable anonymous FTP; require authentication.",
            port=21, service="ftp", evidence=ftp.get("banner", "")))

    redis = probes.get("redis")
    if redis and redis.get("no_auth"):
        out.append(Finding(
            severity="critical", category="access-control",
            title="Redis reachable without authentication",
            description="Redis answered INFO with no AUTH, allowing full read/write "
                        "access and potentially remote code execution.",
            recommendation="Set requirepass/ACLs and bind to localhost.",
            port=6379, service="redis",
            evidence=f"redis_version {redis.get('version', '?')}"))

    memc = probes.get("memcached")
    if memc and memc.get("no_auth"):
        out.append(Finding(
            severity="high", category="access-control",
            title="Memcached reachable without authentication",
            description="Memcached responded to VERSION with no auth; it can leak "
                        "cached data and be abused for UDP amplification.",
            recommendation="Bind to localhost; disable UDP; add SASL.",
            port=11211, service="memcached",
            evidence=memc.get("version", "")))

    mqtt = probes.get("mqtt")
    if mqtt and mqtt.get("accepted"):
        out.append(Finding(
            severity="medium", category="access-control",
            title="MQTT broker accepts anonymous connections",
            description="The MQTT broker accepted a CONNECT with no credentials, "
                        "letting anyone subscribe/publish to topics.",
            recommendation="Require username/password or TLS client certs.",
            port=1883, service="mqtt"))

    smtp = probes.get("smtp")
    if smtp and smtp.get("capabilities") and not smtp.get("starttls"):
        out.append(Finding(
            severity="low", category="protocol",
            title="SMTP without STARTTLS",
            description="The SMTP server did not advertise STARTTLS; mail may be "
                        "transmitted in cleartext.",
            recommendation="Enable STARTTLS.", port=25, service="smtp"))

    rdp = probes.get("rdp")
    if rdp and rdp.get("present") and not rdp.get("nla"):
        out.append(Finding(
            severity="medium", category="access-control",
            title="RDP without Network Level Authentication",
            description="RDP appears to accept connections without NLA, increasing "
                        "exposure to pre-auth attacks (e.g. BlueKeep).",
            recommendation="Require NLA; restrict RDP via VPN/firewall.",
            port=3389, service="rdp"))

    vnc = probes.get("vnc")
    if vnc:
        out.append(Finding(
            severity="low", category="access-control",
            title="VNC service reachable",
            description=f"A VNC server ({vnc.get('version', 'RFB')}) is reachable; "
                        "verify it enforces a strong password.",
            recommendation="Require strong auth; tunnel over SSH/VPN.",
            port=5900, service="vnc"))

    rtsp = probes.get("rtsp")
    if rtsp and rtsp.get("methods"):
        out.append(Finding(
            severity="info", category="info-leak",
            title="RTSP camera stream endpoint",
            description=f"RTSP OPTIONS exposed methods: {rtsp.get('methods', '')}",
            recommendation="Ensure the stream requires authentication.",
            port=554, service="rtsp", evidence=rtsp.get("server", "")))

    return out


ALL_CHECKS = [
    check_exposed_services,
    check_service_probes,
    check_smb,
    check_tls,
    check_default_credentials,
    check_http_headers,
    check_upnp,
    check_plaintext_protocols,
    check_randomized_mac,
]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.security.cve
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.security.cve'] = r'''"""
CVE correlation.

Runs the curated version/banner -> CVE hint table over every text signal a
device exposes (port banners, HTTP Server headers, SNMP sysDescr, SSH software
strings) and returns de-duplicated hints. These are *indicators for manual
verification*, not confirmed vulnerabilities.
"""

from ..data import vuln_db
from ..models import Finding


def _texts_for(device):
    texts = []
    for pr in device.ports:
        blob = " ".join(filter(None, [pr.product, pr.version, pr.banner]))
        if blob.strip():
            texts.append((pr.port, pr.service, blob))
    for h in device.http:
        blob = " ".join(filter(None, [h.server, h.powered_by, h.title]))
        if blob.strip():
            texts.append((h.port, "http", blob))
    snmp = device.services_detail.get("snmp") or {}
    if snmp.get("sysdescr"):
        texts.append((161, "snmp", snmp["sysdescr"]))
    ssh = device.services_detail.get("ssh") or {}
    if ssh.get("banner"):
        texts.append((22, "ssh", ssh["banner"]))
    return texts


def correlate(device):
    """Return a list of Finding objects for matched CVE hints."""
    findings = []
    seen = set()
    for port, service, text in _texts_for(device):
        for hint in vuln_db.match_cves(text):
            key = (tuple(hint["cves"]), hint["note"])
            if key in seen:
                continue
            seen.add(key)
            cve_list = hint["cves"]
            severity = "high" if cve_list else "info"
            title = hint["note"]
            findings.append(Finding(
                severity=severity, category="cve",
                title=("Possible " + (", ".join(cve_list) if cve_list else "known issue")),
                description=hint["note"],
                recommendation="Verify the exact version and patch if affected.",
                port=port, service=service, cves=cve_list,
                evidence=text[:160]))
    return findings
'''

# ---------------------------------------------------------------------------
# module: scanfyx.security.scorecard
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.security.scorecard'] = r'''"""
Network security scorecard and remediation planning.

Aggregates every device finding into a posture summary: a letter grade, category
metrics (exposure, encryption, authentication, legacy protocols, IoT/OT), a
prioritised remediation plan (recommendations grouped and counted by how many
hosts they affect) and a short list of the most urgent issues. Consumed by the
HTML/Markdown/text dossiers.
"""

from ..constants import severity_rank, SEVERITY_WEIGHT


CATEGORY_LABELS = {
    "exposed-service": "Service exposure",
    "access-control": "Authentication / access control",
    "tls": "Transport encryption (TLS)",
    "protocol": "Legacy / insecure protocols",
    "http-hardening": "Web hardening",
    "default-credentials": "Default credentials",
    "cve": "Known vulnerabilities (CVE)",
    "info-leak": "Information disclosure",
    "privacy": "Privacy",
    "general": "General",
}


def _grade_from_score(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    if score >= 35:
        return "E"
    return "F"


def build(result):
    devices = result.devices
    counts = result.severity_counts()

    # posture score: start at 100 and subtract weighted penalties, normalised
    penalty = 0.0
    for sev, n in counts.items():
        penalty += SEVERITY_WEIGHT.get(sev, 0) * n
    # normalise by device count so a bigger network isn't unfairly punished
    denom = max(1, len(devices))
    norm = penalty / denom
    score = max(0.0, 100.0 - min(100.0, norm * 9.0))
    grade = _grade_from_score(score)

    # category metrics
    category = {}
    for d in devices:
        for f in d.findings:
            cat = CATEGORY_LABELS.get(f.category, f.category)
            entry = category.setdefault(cat, {"count": 0, "hosts": set(),
                                              "max_sev": "info"})
            entry["count"] += 1
            entry["hosts"].add(d.ip)
            if severity_rank(f.severity) < severity_rank(entry["max_sev"]):
                entry["max_sev"] = f.severity
    category_list = sorted(
        ({"category": k, "count": v["count"], "hosts": len(v["hosts"]),
          "max_severity": v["max_sev"]} for k, v in category.items()),
        key=lambda x: (severity_rank(x["max_severity"]), -x["count"]))

    # remediation plan: group by (recommendation) and count affected hosts
    rem = {}
    for d in devices:
        for f in d.findings:
            if not f.recommendation:
                continue
            key = f.recommendation
            entry = rem.setdefault(key, {"recommendation": key,
                                         "hosts": set(), "max_sev": "info",
                                         "example": f.title})
            entry["hosts"].add(d.ip)
            if severity_rank(f.severity) < severity_rank(entry["max_sev"]):
                entry["max_sev"] = f.severity
                entry["example"] = f.title
    remediation = sorted(
        ({"recommendation": v["recommendation"], "hosts": sorted(v["hosts"]),
          "host_count": len(v["hosts"]), "severity": v["max_sev"],
          "example": v["example"]} for v in rem.values()),
        key=lambda x: (severity_rank(x["severity"]), -x["host_count"]))

    # urgent highlights: critical/high findings, most severe first
    highlights = []
    for d, f in result.all_findings():
        if f.severity in ("critical", "high"):
            highlights.append({
                "ip": d.ip, "name": d.best_name(), "type": d.device_type,
                "severity": f.severity, "title": f.title,
                "service": f"{f.port}/{f.service}" if f.port else "",
                "recommendation": f.recommendation,
            })
    highlights = highlights[:12]

    # simple posture indicators
    total = len(devices)
    indicators = {
        "hosts_with_findings": sum(1 for d in devices if d.findings),
        "hosts_clean": sum(1 for d in devices if not d.findings),
        "encrypted_web": sum(1 for d in devices if any(t.tls_version for t in d.tls)),
        "legacy_protocol_hosts": sum(
            1 for d in devices
            if any(f.category == "protocol" for f in d.findings)),
        "iot_devices": sum(1 for d in devices
                           if d.device_kind in ("iot-device", "iot-hub",
                                                "camera", "smart-speaker")),
        "total": total,
    }

    return {
        "score": round(score, 1),
        "grade": grade,
        "severity_counts": counts,
        "categories": category_list,
        "remediation": remediation,
        "highlights": highlights,
        "indicators": indicators,
    }


def text_summary(scorecard):
    """A compact multi-line text version for the TXT dossier."""
    lines = [f"Security posture: grade {scorecard['grade']} "
             f"(score {scorecard['score']}/100)"]
    ind = scorecard["indicators"]
    lines.append(f"  {ind['hosts_with_findings']}/{ind['total']} hosts have findings; "
                 f"{ind['iot_devices']} IoT/camera device(s).")
    if scorecard["remediation"]:
        lines.append("  Top remediation actions:")
        for r in scorecard["remediation"][:6]:
            lines.append(f"   - [{r['severity'].upper()}] {r['recommendation']} "
                         f"({r['host_count']} host(s))")
    return "\n".join(lines)
'''

# ---------------------------------------------------------------------------
# module: scanfyx.storage
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.storage'] = r'''"""
Scan history storage and diffing (SQLite).

Every completed scan can be persisted to ``~/.scanfy/scanfy_history.sqlite3``.
Two scans of the same network can then be diffed to reveal *new* devices,
*disappeared* devices and hosts whose open-port set or risk changed - the basis
for the monitor mode and for tracking a network over time.
"""

import json
import sqlite3
import time

from . import constants
from .logging_setup import get_logger
from .models import now_str

log = get_logger("storage")


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    network TEXT,
    scan_type TEXT,
    device_count INTEGER,
    risk_grade TEXT,
    meta_json TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip TEXT, mac TEXT, vendor TEXT, hostname TEXT,
    device_type TEXT, os_guess TEXT, risk_score REAL,
    open_ports TEXT, findings INTEGER,
    device_json TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_dev_scan ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_dev_mac ON devices(mac);
"""


class HistoryStore:
    def __init__(self, path=None):
        self.path = path or constants.DB_PATH
        self._conn = None

    def connect(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.path)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(SCHEMA)
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    # -- write -------------------------------------------------------------
    def save(self, result):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scans (ts, network, scan_type, device_count, risk_grade, meta_json)"
            " VALUES (?,?,?,?,?,?)",
            (result.meta.generated or now_str(), result.meta.network,
             result.meta.scan_type, len(result.devices), result.risk_grade(),
             json.dumps(result.meta.to_dict())))
        scan_id = cur.lastrowid
        for d in result.devices:
            cur.execute(
                "INSERT INTO devices (scan_id, ip, mac, vendor, hostname, "
                "device_type, os_guess, risk_score, open_ports, findings, device_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, d.ip, d.mac, d.vendor, d.best_name(), d.device_type,
                 d.os_guess, d.risk_score,
                 ",".join(str(p) for p in d.open_ports()), len(d.findings),
                 json.dumps(d.to_dict())))
        conn.commit()
        log.info("saved scan %d (%d devices)", scan_id, len(result.devices))
        return scan_id

    # -- read --------------------------------------------------------------
    def list_scans(self, limit=25):
        conn = self.connect()
        rows = conn.execute(
            "SELECT id, ts, network, scan_type, device_count, risk_grade "
            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_scan_devices(self, scan_id):
        conn = self.connect()
        rows = conn.execute(
            "SELECT ip, mac, vendor, hostname, device_type, os_guess, "
            "risk_score, open_ports, findings FROM devices WHERE scan_id=?",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def latest_scan_for_network(self, network, exclude_id=None):
        conn = self.connect()
        q = "SELECT id FROM scans WHERE network=?"
        params = [network]
        if exclude_id:
            q += " AND id<>?"
            params.append(exclude_id)
        q += " ORDER BY id DESC LIMIT 1"
        row = conn.execute(q, params).fetchone()
        return row["id"] if row else None


def diff_device_lists(old_devices, new_devices):
    """
    Compare two lists of device dicts (as stored). Returns a dict with
    ``new``, ``gone`` and ``changed`` lists. Identity is by MAC when available,
    else by IP.
    """
    def key(d):
        mac = d.get("mac", "-")
        return mac if mac and mac != "-" else d.get("ip")

    old_map = {key(d): d for d in old_devices}
    new_map = {key(d): d for d in new_devices}

    new_keys = [k for k in new_map if k not in old_map]
    gone_keys = [k for k in old_map if k not in new_map]

    changed = []
    for k in new_map:
        if k in old_map:
            o, n = old_map[k], new_map[k]
            op_o = set((o.get("open_ports") or "").split(",")) - {""}
            op_n = set((n.get("open_ports") or "").split(",")) - {""}
            if op_o != op_n or o.get("device_type") != n.get("device_type"):
                changed.append({
                    "ip": n.get("ip"), "name": n.get("hostname"),
                    "added_ports": sorted(op_n - op_o, key=lambda x: int(x) if x.isdigit() else 0),
                    "removed_ports": sorted(op_o - op_n, key=lambda x: int(x) if x.isdigit() else 0),
                    "type_before": o.get("device_type"),
                    "type_after": n.get("device_type"),
                })

    return {
        "new": [new_map[k] for k in new_keys],
        "gone": [old_map[k] for k in gone_keys],
        "changed": changed,
    }
'''

# ---------------------------------------------------------------------------
# module: scanfyx.topology
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.topology'] = r'''"""
Network topology & path tracing.

Builds a logical topology graph for the dossier (the operator's machine and the
gateway at the centre, every discovered host as a leaf, grouped by device type)
and can run a traceroute to an external target to document the upstream path.
"""

import re
import subprocess

from . import constants
from .logging_setup import get_logger
from .utils import netutils

log = get_logger("topology")


def traceroute(target="8.8.8.8", max_hops=15, timeout=2):
    """Return a list of {hop, ip, rtt_ms} using the system tracer."""
    hops = []
    try:
        if constants.IS_WINDOWS:
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w",
                   str(int(timeout * 1000)), target]
            enc = constants.WIN_ENCODING
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w",
                   str(timeout), target]
            enc = "utf-8"
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding=enc, errors="ignore",
                             timeout=max_hops * timeout + 15).stdout
    except Exception as exc:
        log.debug("traceroute failed: %s", exc)
        return hops

    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        rtt_m = re.search(r"([\d.]+)\s*ms", rest)
        if "*" in rest and not ip_m:
            hops.append({"hop": hop_num, "ip": "*", "rtt_ms": None})
        elif ip_m:
            hops.append({"hop": hop_num, "ip": ip_m.group(1),
                         "rtt_ms": float(rtt_m.group(1)) if rtt_m else None})
    log.info("traceroute to %s: %d hops", target, len(hops))
    return hops


def build_graph(result):
    """
    Produce a simple topology description consumed by the HTML renderer:
        {center: {gateway, operator}, groups: [{type, devices:[...]}], edges}
    """
    meta = result.meta
    gateway = meta.gateway
    operator = meta.local_ip

    groups = {}
    for d in result.devices:
        if d.is_gateway:
            continue
        groups.setdefault(d.device_type, []).append({
            "ip": d.ip, "name": d.best_name(), "risk": d.risk_label,
            "is_self": d.is_self, "type": d.device_type,
        })

    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return {
        "gateway": gateway,
        "operator": operator,
        "network": meta.network,
        "total": len(result.devices),
        "groups": [{"type": t, "devices": ds} for t, ds in ordered],
    }


def annotate_hop_counts(result):
    """On a flat LAN every host is one hop; mark gateway as hop 0."""
    for d in result.devices:
        d.services_detail["hop"] = 0 if d.is_gateway or d.is_self else 1
    return result
'''

# ---------------------------------------------------------------------------
# module: scanfyx.ui
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.ui'] = r'''"""Rich terminal user interface for SCANFY."""

from . import theme, banner, console, progress, render, menu

__all__ = ["theme", "banner", "console", "progress", "render", "menu"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.ui.banner
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.ui.banner'] = r'''"""ASCII banner rendering."""

from ..version import __version__, TAGLINE
from . import theme

BANNER = r"""
 ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗   ██╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚██╗ ██╔╝
 ███████╗██║     ███████║██╔██╗ ██║█████╗   ╚████╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝    ╚██╔╝
 ███████║╚██████╗██║  ██║██║ ╚████║██║        ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝        ╚═╝
"""

_SHADES = [theme.GRASS_L, theme.GRASS_L, theme.GRASS, theme.GRASS,
           theme.GRASS_D, theme.GRASS_D]


def render(console):
    console.clear()
    lines = BANNER.strip("\n").split("\n")
    for i, line in enumerate(lines):
        shade = _SHADES[i] if i < len(_SHADES) else theme.GRASS
        console.print(line, style=f"bold {shade}")
    console.print(f"  {TAGLINE}  ::  v{__version__}", style=theme.DIRT)
'''

# ---------------------------------------------------------------------------
# module: scanfyx.ui.console
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.ui.console'] = r'''"""Shared rich Console instance and small helpers."""

from rich.console import Console

from .theme import RICH_THEME

console = Console(theme=RICH_THEME, highlight=False)


def rule(title="", style="grass.dark"):
    console.rule(title, style=style)


def info(msg):
    console.print(f"  {msg}", style="stone")


def ok(msg):
    console.print(f"  {msg}", style="grass.light")


def warn(msg):
    console.print(f"  {msg}", style="gold")


def error(msg):
    console.print(f"  {msg}", style="danger")


def ask(prompt):
    try:
        return console.input(f"  [bold #6abe30]{prompt}[/] [grass.light]›[/] ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def pause():
    try:
        console.input("\n  [stone][Enter] to continue…[/]")
    except (EOFError, KeyboardInterrupt):
        pass
'''

# ---------------------------------------------------------------------------
# module: scanfyx.ui.menu
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.ui.menu'] = r'''"""
Interactive menu controller.

Drives the whole terminal experience: shows the banner and environment, offers
scan profiles, runs the engine with a live progress display, renders results and
handles dossier export, single-host deep scans, the ARP snapshot, scan history
and the continuous monitor.
"""

import ipaddress
import threading

from rich import box
from rich.panel import Panel
from rich.table import Table

from .. import engine, report, storage, vendors
from ..config import ScanConfig, PROFILES
from ..constants import capability_summary
from ..discovery import arp as arp_disc
from ..logging_setup import get_logger
from . import banner, render, theme
from .console import console, ask, pause, ok, warn, error, info
from .progress import RichProgress

log = get_logger("ui.menu")


class InteractiveApp:
    def __init__(self, config=None):
        self.config = config or ScanConfig().apply_profile("default")
        self.env = None
        self.last_result = None
        self.store = storage.HistoryStore()

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        console.print("  [stone]Detecting network environment…[/]")
        self.env = engine.detect_environment(with_public_ip=self.config.geoip_public)
        self.loop()

    def loop(self):
        while True:
            banner.render(console)
            render.environment_panel(self.env)
            self._menu()
            choice = ask("scanfy")
            try:
                if choice in ("1", "q"):
                    self._run(profile="fast", label="Quick", deep=False)
                elif choice in ("2", "d", ""):
                    self._run(profile="default", label="Deep", deep=True)
                elif choice == "3":
                    self._run(profile="thorough", label="Thorough", deep=True)
                elif choice == "4":
                    self._single_host()
                elif choice == "5":
                    self._arp_table()
                elif choice == "6":
                    self._export()
                elif choice == "7":
                    self._history()
                elif choice == "8":
                    self._monitor()
                elif choice == "9":
                    self._settings()
                elif choice in ("0", "x", "exit", "quit"):
                    ok("See you! · Viva os Hacker do Brasil 🇧🇷")
                    break
                else:
                    error("Invalid option.")
            except KeyboardInterrupt:
                warn("Aborted.")
            pause()

    def _menu(self):
        m = Table.grid(padding=(0, 2))
        m.add_column(style="bold #6abe30", justify="right")
        m.add_column(style="white")
        m.add_column(style="stone")
        m.add_row("[1]", "Quick scan", "discovery + identity (fast)")
        m.add_row("[2]", "Deep scan", "ports · OS · HTTP/TLS · findings   (recommended)")
        m.add_row("[3]", "Thorough scan", "all ports · UDP · nmap (if present) · traceroute")
        m.add_row("[4]", "Single host", "deep-scan one IP")
        m.add_row("[5]", "ARP table", "instant snapshot")
        m.add_row("[6]", "Export dossier", "HTML · MD · JSON · CSV · XML · TXT · PDF")
        m.add_row("[7]", "Scan history", "compare with previous scans")
        m.add_row("[8]", "Monitor mode", "watch for new/leaving devices")
        m.add_row("[9]", "Settings", "profile · timeouts · output dir")
        m.add_row("[0]", "Exit", "")
        console.print(m)

    # -- actions -----------------------------------------------------------
    def _run(self, profile, label, deep):
        self.config.apply_profile(profile)
        console.print(f"\n  [grass.light]Starting {label} scan of "
                      f"{self.env.network}…[/]\n")
        try:
            with RichProgress() as prog:
                if deep:
                    result = engine.run_scan(self.config, env=self.env,
                                             progress=prog, scan_type=label)
                else:
                    result = engine.run_quick_scan(self.config, env=self.env,
                                                   progress=prog)
        except KeyboardInterrupt:
            warn("Scan aborted.")
            return
        self.last_result = result
        render.render_result(result, deep=deep)
        try:
            self.store.save(result)
        except Exception as exc:
            log.debug("history save failed: %s", exc)

    def _single_host(self):
        ip = ask("Target IP")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            error("Invalid IP.")
            return
        self.config.apply_profile("deep")
        console.print(f"\n  [grass.light]Deep-scanning {ip}…[/]\n")
        with RichProgress() as prog:
            result = engine.run_single_host(ip, self.config, env=self.env,
                                            progress=prog)
        self.last_result = result
        render.render_device_card(result.devices[0])

    def _arp_table(self):
        table = arp_disc.read_arp_table()
        from ..utils import netutils
        real = {ip: mac for ip, mac in table.items()
                if netutils.is_real_device(ip, mac)}
        vendor_map = vendors.resolve_many(real.values())
        t = Table(box=box.SIMPLE_HEAVY, header_style="bold #6abe30")
        t.add_column("IP", style="grass.light")
        t.add_column("MAC", style="grass")
        t.add_column("Vendor", style="white")
        for ip in sorted(real, key=lambda x: [int(p) for p in x.split(".")]):
            t.add_row(ip, real[ip], vendor_map.get(real[ip], "-"))
        console.print(t)
        ok(f"{len(real)} devices in the ARP table")

    def _export(self):
        if not self.last_result:
            error("No scan results yet. Run a scan first.")
            return
        console.print("\n  [bold #6abe30][1][/] HTML   [bold #6abe30][2][/] Markdown   "
                      "[bold #6abe30][3][/] JSON   [bold #6abe30][4][/] CSV   "
                      "[bold #6abe30][5][/] XML   [bold #6abe30][6][/] TXT   "
                      "[bold #6abe30][7][/] PDF   [bold #6abe30][8][/] All")
        choice = ask("format")
        mapping = {"1": ["html"], "2": ["markdown"], "3": ["json"], "4": ["csv"],
                   "5": ["xml"], "6": ["txt"], "7": ["pdf"],
                   "8": ["html", "markdown", "json", "csv", "xml", "txt", "pdf"]}
        fmts = mapping.get(choice)
        if not fmts:
            error("Invalid option.")
            return
        console.print()
        for fmt in fmts:
            label, fn = report.FORMATS[fmt]
            try:
                path = fn(self.last_result, self.config)
                if path:
                    ok(f"saved {label}: [white]{path}[/]")
                else:
                    warn(f"{label} skipped (dependency missing)")
            except Exception as exc:
                error(f"{label} failed: {exc}")

    def _history(self):
        scans = self.store.list_scans(limit=15)
        if not scans:
            info("No scan history yet.")
            return
        t = Table(box=box.SIMPLE, header_style="bold #6abe30")
        t.add_column("ID", style="grass")
        t.add_column("When", style="stone")
        t.add_column("Network")
        t.add_column("Type")
        t.add_column("Devices", justify="right")
        t.add_column("Grade")
        for s in scans:
            t.add_row(str(s["id"]), s["ts"], s["network"], s["scan_type"],
                      str(s["device_count"]), s["risk_grade"] or "-")
        console.print(t)
        if self.last_result:
            prev_id = self.store.latest_scan_for_network(self.last_result.meta.network)
            if prev_id:
                self._show_diff(prev_id)

    def _show_diff(self, prev_id):
        old = self.store.get_scan_devices(prev_id)
        new = [{"mac": d.mac, "ip": d.ip, "open_ports": ",".join(str(p) for p in d.open_ports()),
                "device_type": d.device_type, "hostname": d.best_name()}
               for d in self.last_result.devices]
        diff = storage.diff_device_lists(old, new)
        if diff["new"]:
            ok("New devices since last scan: " +
               ", ".join(d["ip"] for d in diff["new"]))
        if diff["gone"]:
            warn("Devices no longer present: " +
                 ", ".join(d.get("ip", "?") for d in diff["gone"]))
        if diff["changed"]:
            for c in diff["changed"]:
                info(f"{c['ip']} changed ports: +{c['added_ports']} -{c['removed_ports']}")

    def _monitor(self):
        from ..monitor import NetworkMonitor
        from ..discovery import orchestrator as disc
        interval = ask("Poll interval seconds [30]") or "30"
        try:
            interval = max(10, int(interval))
        except ValueError:
            interval = 30
        warn(f"Monitoring {self.env.network} every {interval}s. Press Ctrl+C to stop.")

        mon_cfg = ScanConfig().apply_profile("fast")
        mon_cfg.http = mon_cfg.tls = mon_cfg.snmp = mon_cfg.smb = False
        mon_cfg.mdns = mon_cfg.ssdp = mon_cfg.udp = False

        def discovery_fn(network, config, env):
            devices, _ = disc.run(network, config, env)
            return devices

        def on_event(kind, dev):
            name = dev.best_name()
            if kind == "join":
                ok(f"[+] JOINED  {dev.ip}  {dev.mac}  {name}")
            else:
                warn(f"[-] LEFT    {dev.ip}  {dev.mac}  {name}")

        monitor = NetworkMonitor(self.env.network, mon_cfg, self.env,
                                 discovery_fn, on_event=on_event)
        info("Establishing baseline…")
        monitor.establish_baseline()
        ok(f"Baseline: {len(monitor.baseline)} devices. Watching…")
        try:
            monitor.run(interval=interval)
        except KeyboardInterrupt:
            warn("Monitor stopped.")

    def _settings(self):
        c = self.config
        t = Table.grid(padding=(0, 2))
        t.add_column(style="grass.light", justify="right")
        t.add_column(style="white")
        t.add_row("Profile", f"{c.profile} ({c.profile_label()})")
        t.add_row("Port set", c.port_set)
        t.add_row("TCP timeout", f"{c.tcp_timeout}s")
        t.add_row("Port workers", str(c.max_port_workers))
        t.add_row("HTTP fp", str(c.http))
        t.add_row("TLS fp", str(c.tls))
        t.add_row("UDP probes", str(c.udp))
        t.add_row("Public IP lookup", str(c.geoip_public))
        t.add_row("Report dir", c.report_dir)
        t.add_row("Engine", capability_summary())
        console.print(Panel(t, title="[grass]Settings[/]", border_style="grass.dark",
                            title_align="left"))
        console.print("  [bold #6abe30][1][/] Change profile   "
                      "[bold #6abe30][2][/] Set report dir   "
                      "[bold #6abe30][3][/] Toggle public-IP lookup   "
                      "[bold #6abe30][0][/] Back")
        choice = ask("settings")
        if choice == "1":
            names = list(PROFILES.keys())
            console.print("  Profiles: " + ", ".join(
                f"[grass]{n}[/]" for n in names))
            p = ask("profile name")
            if p in PROFILES:
                self.config.apply_profile(p)
                ok(f"Profile set to {p}.")
            else:
                error("Unknown profile.")
        elif choice == "2":
            d = ask("report directory")
            if d:
                self.config.report_dir = d
                ok(f"Report dir set to {d}.")
        elif choice == "3":
            self.config.geoip_public = not self.config.geoip_public
            ok(f"Public-IP lookup: {self.config.geoip_public}")
'''

# ---------------------------------------------------------------------------
# module: scanfyx.ui.progress
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.ui.progress'] = r'''"""
Rich-backed progress adapter.

Implements the ``phase(name, total)`` / ``step()`` interface the engine expects,
rendering a live multi-phase progress display. Each ``phase`` starts a new task;
``step`` advances the current one.
"""

from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                          MofNCompleteColumn, TimeElapsedColumn)

from .console import console
from . import theme


class RichProgress:
    def __init__(self):
        self._progress = Progress(
            SpinnerColumn(style=theme.GRASS),
            TextColumn("[bold #96dc5a]{task.description}"),
            BarColumn(complete_style=theme.GRASS, finished_style=theme.GRASS_D,
                      pulse_style=theme.GRASS_D),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        self._task = None
        self._started = False

    def __enter__(self):
        self._progress.start()
        self._started = True
        return self

    def __exit__(self, *exc):
        self._progress.stop()
        self._started = False
        return False

    def phase(self, name, total):
        if not self._started:
            self._progress.start()
            self._started = True
        # complete the previous task so it stays visible
        self._task = self._progress.add_task(name, total=max(1, total))

    def step(self, n=1):
        if self._task is not None:
            try:
                self._progress.advance(self._task, n)
            except Exception:
                pass

    def done(self):
        pass


class SimpleProgress:
    """Fallback used when a live display is undesirable (e.g. piped output)."""

    def __init__(self):
        self._name = ""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def phase(self, name, total):
        self._name = name
        console.print(f"  [grass.light]›[/] {name}…", style="stone")

    def step(self, n=1):
        pass

    def done(self):
        pass
'''

# ---------------------------------------------------------------------------
# module: scanfyx.ui.render
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.ui.render'] = r'''"""
Render a :class:`ScanResult` to the terminal using rich: an environment panel,
the device inventory table, a security-findings panel, per-service highlights
and a summary. Also renders a detailed single-device card.
"""

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

from ..constants import severity_rank
from .console import console
from . import theme
from .theme import SEV_STYLE, RISK_STYLE


def _tag(dev):
    if dev.is_self:
        return " [bold #96dc5a](you)[/]"
    if dev.is_gateway:
        return " [bold #e6c85a](router)[/]"
    return ""


def environment_panel(env):
    t = Table.grid(padding=(0, 2))
    t.add_column(style="grass.light", justify="right")
    t.add_column(style="white")
    t.add_row("Machine", f"{env.local_ip}  ({env.primary_iface})")
    t.add_row("Own MAC", env.mac)
    t.add_row("Network", str(env.network))
    t.add_row("Gateway", env.gateway)
    t.add_row("DNS", ", ".join(env.dns_servers) if env.dns_servers else "-")
    if env.public_ip:
        t.add_row("Public IP", f"{env.public_ip}  {env.isp}".strip())
        if env.geo:
            t.add_row("Location", env.geo)
    from ..constants import capability_summary
    t.add_row("Engine", capability_summary())
    console.print(Panel(t, title="[grass]Network environment[/]",
                        border_style="grass.dark", title_align="left"))


def inventory_table(result, deep=True):
    table = Table(box=box.ROUNDED, header_style="bold #6abe30",
                  border_style="grass.dark",
                  title=f"[bold #96dc5a]SCANFY — {result.meta.scan_type} scan · "
                        f"{len(result.devices)} devices[/]", title_justify="left")
    table.add_column("IP", style="grass.light", no_wrap=True)
    table.add_column("MAC", style="grass", no_wrap=True)
    table.add_column("Vendor", style="white", max_width=22)
    table.add_column("Name", style="white", max_width=22)
    table.add_column("Type", style="leaf")
    if deep:
        table.add_column("OS", style="stone", max_width=16)
        table.add_column("Risk", justify="right")
        table.add_column("Ports", style="grass", max_width=34)

    for d in sorted(result.devices, key=lambda x: [int(p) for p in x.ip.split(".")] if x.ip.count(".") == 3 else [999]):
        name = d.best_name()
        name = name if name != d.ip else "[stone]-[/]"
        row = [Text.from_markup(d.ip + _tag(d)), d.mac,
               d.vendor if d.vendor != "-" else "[stone]-[/]", name, d.device_type]
        if deep:
            risk = Text(f"{d.risk_score:g}", style=RISK_STYLE.get(d.risk_label, "stone"))
            os_short = d.os_guess.split(" (")[0] if d.os_guess != "-" else "-"
            row += [os_short, risk, d.ports_str(limit=5)]
        table.add_row(*row)
    console.print(table)


def findings_panel(result):
    all_f = result.all_findings()
    if not all_f:
        console.print(Panel("No risky exposed services detected ✓",
                            title="[grass]Security findings[/]",
                            border_style="grass.dark", title_align="left",
                            style="grass.light"))
        return
    t = Table(box=box.SIMPLE, header_style="bold #e6c85a", expand=False)
    t.add_column("Sev")
    t.add_column("Host", style="grass.light")
    t.add_column("Service", style="grass")
    t.add_column("Finding", style="white")
    for dev, f in all_f[:40]:
        svc = f"{f.port}/{f.service}" if f.port else "-"
        t.add_row(Text(f.severity.upper(), style=SEV_STYLE.get(f.severity, "white")),
                  dev.ip, svc, f.title)
    extra = f"  (+{len(all_f) - 40} more)" if len(all_f) > 40 else ""
    console.print(Panel(t, title=f"[gold]Security findings ({len(all_f)}){extra}[/]",
                        border_style="gold", title_align="left"))


def summary_panel(result):
    counts = result.severity_counts()
    m = result.meta
    grade = result.risk_grade()
    lines = [
        f"[stone]Devices[/] [grass.light]{len(result.devices)}[/]   "
        f"[stone]Open ports[/] {result.total_open_ports()}   "
        f"[stone]Duration[/] {m.duration}s   "
        f"[stone]Methods[/] {', '.join(m.methods)}",
        f"[stone]Risk grade[/] [bold]{grade}[/] (score {result.overall_risk_score()})   "
        f"[sev.critical]{counts['critical']} crit[/] · [sev.high]{counts['high']} high[/] · "
        f"[sev.medium]{counts['medium']} med[/] · [sev.low]{counts['low']} low[/]",
    ]
    types = result.type_distribution()
    if types:
        lines.append("[stone]Types[/]   " + ", ".join(
            f"{t} [grass]x{n}[/]" for t, n in types[:8]))
    services = result.service_distribution()
    if services:
        lines.append("[stone]Services[/] " + ", ".join(
            f"{s} [grass]x{n}[/]" for s, n in services[:10]))
    top = [d for d in result.riskiest(3) if d.risk_score > 0]
    if top:
        lines.append("[stone]Riskiest[/] " + " · ".join(
            f"[risk.{d.risk_label}]{d.ip}[/] ({d.risk_score:g})" for d in top))
    console.print(Panel("\n".join(lines), title="[grass]Summary[/]",
                        border_style="grass", title_align="left"))


def render_result(result, deep=True):
    console.print()
    inventory_table(result, deep=deep)
    if deep:
        findings_panel(result)
    summary_panel(result)
    console.print("  [stone]Tip: export a full dossier from the menu "
                  "(HTML · Markdown · JSON · CSV · XML · TXT · PDF).[/]")


def render_device_card(device):
    """Detailed single-device view (used by single-host scan)."""
    t = Table.grid(padding=(0, 2))
    t.add_column(style="stone", justify="right")
    t.add_column(style="white")
    t.add_row("MAC / Vendor", f"{device.mac}  {device.vendor}")
    t.add_row("Hostname", device.best_name())
    if device.netbios not in ("-", ""):
        t.add_row("NetBIOS", f"{device.netbios} / {device.workgroup}")
    if device.mdns_name not in ("-", ""):
        t.add_row("mDNS", device.mdns_name)
    t.add_row("Type", f"[leaf]{device.device_type}[/]")
    t.add_row("OS guess", f"{device.os_guess}  [stone]{device.os_confidence}[/]")
    t.add_row("Discovery", "+".join(device.discovery_methods))
    t.add_row("Risk", Text(f"{device.risk_score:g} ({device.risk_label})",
                           style=RISK_STYLE.get(device.risk_label, "stone")))

    ports_t = Table(box=box.SIMPLE, header_style="bold #6abe30", show_edge=False)
    ports_t.add_column("Port", style="grass")
    ports_t.add_column("Service")
    ports_t.add_column("Product / Version", style="stone")
    ports_t.add_column("Banner", style="stone", max_width=40)
    for p in sorted(device.ports, key=lambda x: x.port):
        ports_t.add_row(f"{p.port}/{p.protocol}", p.service,
                        " ".join(filter(None, [p.product, p.version])),
                        (p.banner or "")[:40])

    console.print(Panel(t, title=f"[bold #96dc5a]● {device.ip}[/]",
                        border_style="grass", title_align="left"))
    if device.ports:
        console.print(ports_t)
    for h in device.http:
        techs = ", ".join(x["name"] for x in h.technologies)
        console.print(f"  [grass]Web[/] {h.url} [{h.status}] {h.server} "
                      f"[stone]{h.title}[/] {('· ' + techs) if techs else ''}")
    for tinfo in device.tls:
        console.print(f"  [grass]TLS[/] :{tinfo.port} {tinfo.tls_version} "
                      f"CN={tinfo.subject_cn} issuer={tinfo.issuer_cn} "
                      f"{tinfo.key_type}{tinfo.key_bits}")
    if device.findings:
        ft = Table(box=box.SIMPLE, header_style="bold #e6c85a")
        ft.add_column("Sev")
        ft.add_column("Finding")
        ft.add_column("Recommendation", style="stone")
        for f in device.findings:
            ft.add_row(Text(f.severity.upper(), style=SEV_STYLE.get(f.severity, "white")),
                       f.title, f.recommendation)
        console.print(Panel(ft, title="[gold]Findings[/]", border_style="gold",
                            title_align="left"))
'''

# ---------------------------------------------------------------------------
# module: scanfyx.ui.theme
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.ui.theme'] = r'''"""Rich theme and shared style tokens (Minecraft grass palette)."""

from rich.theme import Theme

from ..constants import Palette

GRASS = Palette.GRASS
GRASS_L = Palette.GRASS_LIGHT
GRASS_D = Palette.GRASS_DARK
LEAF = Palette.LEAF
DIRT = Palette.DIRT
STONE = Palette.STONE
GOLD = Palette.GOLD
RED = Palette.REDSTONE
WATER = Palette.WATER
WHITE = Palette.WHITE

RICH_THEME = Theme({
    "grass": GRASS,
    "grass.light": GRASS_L,
    "grass.dark": GRASS_D,
    "leaf": LEAF,
    "dirt": DIRT,
    "stone": STONE,
    "gold": GOLD,
    "danger": RED,
    "water": WATER,
    "sev.critical": "bold #ff5c5c",
    "sev.high": "bold #ff8a5c",
    "sev.medium": GOLD,
    "sev.low": "#a9c98f",
    "sev.info": STONE,
    "risk.critical": "bold #ff5c5c",
    "risk.high": "bold #ff8a5c",
    "risk.medium": GOLD,
    "risk.low": "#a9c98f",
    "risk.info": STONE,
})

SEV_STYLE = {
    "critical": "sev.critical", "high": "sev.high", "medium": "sev.medium",
    "low": "sev.low", "info": "sev.info",
}
RISK_STYLE = {
    "critical": "risk.critical", "high": "risk.high", "medium": "risk.medium",
    "low": "risk.low", "info": "risk.info",
}
'''

# ---------------------------------------------------------------------------
# module: scanfyx.utils
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.utils'] = r'''"""Low-level utility helpers used across SCANFY."""

from . import netutils, textutils, concurrency

__all__ = ["netutils", "textutils", "concurrency"]
'''

# ---------------------------------------------------------------------------
# module: scanfyx.utils.concurrency
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.utils.concurrency'] = r'''"""
Concurrency helpers: bounded parallel maps with progress callbacks, a simple
token-bucket rate limiter and a retry decorator. Used by every scan engine so
they share consistent threading behaviour.
"""

import concurrent.futures
import functools
import threading
import time


def parallel_map(func, items, max_workers=64, on_step=None, stop_event=None):
    """
    Run ``func`` over ``items`` in a thread pool, returning a list of results
    in completion order. ``on_step`` (if given) is called once per completed
    item. A ``threading.Event`` passed as ``stop_event`` aborts early.
    """
    items = list(items)
    results = []
    if not items:
        return results
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(func, item) for item in items]
        for fut in concurrent.futures.as_completed(futures):
            if stop_event is not None and stop_event.is_set():
                break
            if on_step:
                try:
                    on_step()
                except Exception:
                    pass
            try:
                results.append(fut.result())
            except Exception:
                results.append(None)
    return results


def parallel_map_dict(func, keys, max_workers=64, on_step=None):
    """Like parallel_map but returns {key: func(key)} preserving association."""
    keys = list(keys)
    out = {}
    if not keys:
        return out
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_key = {ex.submit(func, k): k for k in keys}
        for fut in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[fut]
            if on_step:
                try:
                    on_step()
                except Exception:
                    pass
            try:
                out[key] = fut.result()
            except Exception:
                out[key] = None
    return out


def parallel_star(func, arg_tuples, max_workers=128, on_step=None):
    """Run func(*args) for each tuple in arg_tuples, yielding (args, result)."""
    arg_tuples = list(arg_tuples)
    out = []
    if not arg_tuples:
        return out
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_to_args = {ex.submit(func, *a): a for a in arg_tuples}
        for fut in concurrent.futures.as_completed(fut_to_args):
            if on_step:
                try:
                    on_step()
                except Exception:
                    pass
            try:
                out.append((fut_to_args[fut], fut.result()))
            except Exception:
                out.append((fut_to_args[fut], None))
    return out


class RateLimiter:
    """A minimal thread-safe token bucket rate limiter (ops per second)."""

    def __init__(self, rate_per_sec):
        self.rate = float(rate_per_sec)
        self.capacity = max(1.0, float(rate_per_sec))
        self.tokens = self.capacity
        self.timestamp = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens=1):
        if self.rate <= 0:
            return
        with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.timestamp
                self.timestamp = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                sleep_for = (tokens - self.tokens) / self.rate
                time.sleep(min(sleep_for, 0.25))


def retry(times=2, delay=0.2, exceptions=(Exception,)):
    """Decorator that retries a callable on failure."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last = None
            for attempt in range(times + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:  # noqa
                    last = exc
                    if attempt < times:
                        time.sleep(delay)
            if last is not None:
                raise last
        return wrapper

    return decorator


class Timer:
    """Context manager measuring wall-clock elapsed seconds."""

    def __init__(self):
        self.start = 0.0
        self.elapsed = 0.0

    def __enter__(self):
        self.start = time.monotonic()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.monotonic() - self.start
        return False
'''

# ---------------------------------------------------------------------------
# module: scanfyx.utils.netutils
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.utils.netutils'] = r'''"""
Networking helper utilities: IP/MAC parsing and validation, subnet math,
address classification and small socket helpers.

Everything here is pure standard library so it always works.
"""

import ipaddress
import re
import socket
import struct

MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------
def is_valid_ipv4(ip):
    m = IPV4_RE.match(str(ip or ""))
    if not m:
        return False
    return all(0 <= int(o) <= 255 for o in m.groups())


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(str(ip)))[0]


def int_to_ip(value):
    return socket.inet_ntoa(struct.pack("!I", value & 0xFFFFFFFF))


def ip_sort_key(ip):
    """Sort key that orders dotted-quads numerically."""
    try:
        return tuple(int(p) for p in str(ip).split("."))
    except Exception:
        return (999, 999, 999, 999)


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def is_multicast_ip(ip):
    try:
        return ipaddress.ip_address(str(ip)).is_multicast
    except ValueError:
        return False


def is_broadcast(ip, network=None):
    if str(ip).endswith(".255"):
        return True
    if network is not None:
        try:
            return ipaddress.ip_address(str(ip)) == network.broadcast_address
        except Exception:
            return False
    return False


def in_network(ip, network):
    try:
        return ipaddress.ip_address(str(ip)) in network
    except Exception:
        return False


def network_from(ip, prefix_or_mask):
    """Build an ip_network from an IP and either a mask or a prefix length."""
    return ipaddress.ip_network(f"{ip}/{prefix_or_mask}", strict=False)


def hosts_of(network, limit=None):
    hosts = network.hosts()
    out = []
    for i, h in enumerate(hosts):
        if limit is not None and i >= limit:
            break
        out.append(str(h))
    return out


def same_subnet(ip_a, ip_b, network):
    return in_network(ip_a, network) and in_network(ip_b, network)


# ---------------------------------------------------------------------------
# MAC helpers
# ---------------------------------------------------------------------------
def is_valid_mac(mac):
    return bool(MAC_RE.match(str(mac or "")))


def normalize_mac(mac):
    """Return a lowercase colon-separated MAC, or '-' if invalid."""
    if not mac:
        return "-"
    mac = str(mac).strip().lower().replace("-", ":")
    if MAC_RE.match(mac):
        return mac
    # try to normalise dotted cisco style aabb.ccdd.eeff
    hexonly = re.sub(r"[^0-9a-f]", "", mac)
    if len(hexonly) == 12:
        return ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))
    return "-"


def mac_oui(mac):
    """Return the 24-bit OUI prefix 'aa:bb:cc' of a MAC, or '' if invalid."""
    mac = normalize_mac(mac)
    if mac == "-":
        return ""
    return mac[:8]


def is_locally_administered_mac(mac):
    """The 2nd-least-significant bit of the first octet marks LAA (random)."""
    mac = normalize_mac(mac)
    if mac == "-":
        return False
    try:
        first = int(mac[:2], 16)
        return bool(first & 0b10)
    except ValueError:
        return False


def is_multicast_mac(mac):
    mac = normalize_mac(mac)
    if mac == "-":
        return False
    try:
        return bool(int(mac[:2], 16) & 0b1)
    except ValueError:
        return False


def looks_randomized(mac):
    """Heuristic: modern phones use locally-administered random MACs."""
    return is_locally_administered_mac(mac) and not is_multicast_mac(mac)


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------
def tcp_connect(ip, port, timeout=0.7):
    """Return True if a TCP connection can be established."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        return s.connect_ex((str(ip), int(port))) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def tcp_open_socket(ip, port, timeout=3.0):
    """Open and return a connected socket, or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((str(ip), int(port)))
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return "-"


def forward_dns(host):
    try:
        return socket.gethostbyname(str(host))
    except Exception:
        return None


def local_outbound_ip():
    """Discover the local IP used to reach the internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def prefix_from_netmask(netmask):
    try:
        return ipaddress.ip_network(f"0.0.0.0/{netmask}", strict=False).prefixlen
    except Exception:
        return 24


def cidr_size(network):
    return network.num_addresses
'''

# ---------------------------------------------------------------------------
# module: scanfyx.utils.textutils
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.utils.textutils'] = r'''"""
Text formatting helpers: truncation, humanising numbers/durations/bytes,
ANSI stripping, HTML/attr escaping and small string utilities used by the
reporting and UI layers.
"""

import html as _html
import re
import unicodedata

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text):
    return ANSI_RE.sub("", str(text))


def truncate(text, length, ellipsis="…"):
    text = str(text if text is not None else "")
    if len(text) <= length:
        return text
    if length <= 1:
        return text[:length]
    return text[: length - 1] + ellipsis


def pad(text, width, align="left"):
    text = str(text if text is not None else "")
    if len(text) >= width:
        return text
    space = width - len(text)
    if align == "right":
        return " " * space + text
    if align == "center":
        left = space // 2
        return " " * left + text + " " * (space - left)
    return text + " " * space


def esc_html(value):
    return _html.escape(str(value if value is not None else "-"), quote=True)


def esc_attr(value):
    return _html.escape(str(value if value is not None else ""), quote=True)


def esc_xml(value):
    s = str(value if value is not None else "")
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def slugify(text, maxlen=48):
    text = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return (text or "item")[:maxlen]


def humanize_bytes(num):
    try:
        num = float(num)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def humanize_duration(seconds):
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s"


def humanize_count(n, singular, plural=None):
    plural = plural or singular + "s"
    return f"{n} {singular if n == 1 else plural}"


def latency_str(ms):
    if ms is None:
        return "-"
    try:
        ms = float(ms)
    except (TypeError, ValueError):
        return "-"
    if ms < 1:
        return "<1 ms"
    return f"{ms:.0f} ms"


def join_nonempty(parts, sep=" "):
    return sep.join(str(p) for p in parts if p not in (None, "", "-"))


def clamp_line(text, width=120):
    text = re.sub(r"\s+", " ", str(text)).strip()
    return truncate(text, width)


def title_case(text):
    return " ".join(w.capitalize() for w in str(text).replace("_", " ").split())


def indent(text, prefix="  "):
    return "\n".join(prefix + line for line in str(text).splitlines())


def wrap_pill(items, sep=" "):
    return sep.join(items)


def bar_text(fraction, width=20, fill="█", empty="░"):
    fraction = max(0.0, min(1.0, float(fraction)))
    filled = int(round(width * fraction))
    return fill * filled + empty * (width - filled)


def kv_line(key, value, key_width=14):
    return f"{pad(key, key_width)}: {value}"


def safe_filename(name):
    return re.sub(r'[<>:"/\\|?*]', "_", str(name))
'''

# ---------------------------------------------------------------------------
# module: scanfyx.vendors
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.vendors'] = r'''"""
MAC vendor resolution.

Prefers the full IEEE database via ``mac-vendor-lookup`` and falls back to the
embedded prefix table. IMPORTANT: ``mac-vendor-lookup`` drives an asyncio loop
internally and is *not* thread-safe, so callers must resolve vendors serially
(this module offers ``resolve_many`` which does exactly that) rather than from a
thread pool.
"""

from . import constants
from .data import oui_fallback
from .logging_setup import get_logger
from .utils import netutils

log = get_logger("vendors")

_mac_lookup = None
if constants.HAS_MAC_VENDOR:
    try:
        from mac_vendor_lookup import MacLookup
        _mac_lookup = MacLookup()
    except Exception as exc:  # pragma: no cover
        log.debug("MacLookup init failed: %s", exc)
        _mac_lookup = None


def resolve(mac):
    """Return a vendor name for a MAC, or 'unknown'/'-' as appropriate."""
    mac = netutils.normalize_mac(mac)
    if mac == "-":
        return "-"
    if _mac_lookup is not None:
        try:
            return _mac_lookup.lookup(mac)
        except Exception:
            pass
    return oui_fallback.lookup(mac)


def resolve_many(macs):
    """Resolve a collection of MACs serially. Returns {mac: vendor}."""
    out = {}
    for mac in set(macs):
        out[mac] = resolve(mac)
    return out


def update_database():
    """Refresh the local OUI database (requires internet)."""
    if _mac_lookup is None:
        return False
    try:
        _mac_lookup.update_vendors()
        return True
    except Exception as exc:
        log.debug("OUI update failed: %s", exc)
        return False


def device_hint(vendor):
    return oui_fallback.device_hint_for_vendor(vendor)
'''

# ---------------------------------------------------------------------------
# module: scanfyx.version
# ---------------------------------------------------------------------------
SCANFY_MODULES['scanfyx.version'] = r'''"""Version and build metadata for SCANFY."""

__version__ = "4.0.0"

VERSION = __version__
BUILD = "grass-forge"
CODENAME = "Minecraft Grass"

# Semantic components, useful for comparisons / reports.
VERSION_INFO = (4, 0, 0)

# Human friendly banner subtitle.
TAGLINE = "advanced network scanner · service fingerprinter · security dossier"

# Project motto printed at the bottom of every dossier.
MOTTO_EN = "Long live the Hackers of Brazil"
MOTTO_PT = "Viva os Hacker do Brasil"

# Minimum supported Python.
MIN_PYTHON = (3, 8)
'''



if __name__ == "__main__":
    raise SystemExit(main())
