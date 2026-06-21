#!/usr/bin/env python3
"""
LAN Multi-Tool GUI
- Active discovery via ARP sweep (Scapy if available)
- Passive discovery via ARP sniffing (Scapy if available)
- Optional ping sweep fallback
- Auto-rescan to keep the list fresh
- CSV export with semicolon separator

Install:
    pip install scapy psutil
Run:
    python lan_multitool_gui.py
"""

import csv
import ipaddress
import json
import os
import platform
import queue
import socket
import subprocess
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Set, Tuple

try:
    from oui_lookup import annotate as oui_annotate
except Exception:
    def oui_annotate(_mac: str) -> str:  # graceful fallback if module missing
        return ""

try:
    import psutil
except Exception:
    psutil = None

def _import_scapy():
    """Import Scapy while silencing its noisy import-time pcap-service probe.

    Scapy logs a WARNING and shells out to the OS to probe/start the pcap
    service on import, leaking text to stderr when pcap is unavailable. The
    active/passive scapy paths degrade gracefully without pcap, so we mute the
    logger and redirect stderr only for the duration of the import.
    """
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    saved_fd = devnull_fd = None
    try:
        saved_fd = os.dup(2)
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull_fd, 2)
    except Exception:
        saved_fd = None
    try:
        from scapy.all import ARP, Ether, IP, conf, get_if_hwaddr, sniff, srp  # noqa: F401
        return ARP, Ether, IP, conf, get_if_hwaddr, sniff, srp
    finally:
        if saved_fd is not None:
            try:
                os.dup2(saved_fd, 2)
            finally:
                os.close(saved_fd)
        if devnull_fd is not None:
            os.close(devnull_fd)


try:
    ARP, Ether, IP, conf, get_if_hwaddr, sniff, srp = _import_scapy()
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# ----------------------------
# Data models
# ----------------------------

@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    sources: str = ""
    open_ports: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    alive: bool = True


@dataclass(frozen=True)
class NetSource:
    network: ipaddress.IPv4Network
    source: str
    iface: str = ""


# ----------------------------
# Helpers
# ----------------------------

def normalize_mac(mac: str) -> str:
    return (mac or "").strip().lower().replace("-", ":")


def is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except Exception:
        return False


def sort_ip(ip: str):
    try:
        return ipaddress.IPv4Address(ip)
    except Exception:
        return ip


def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str]:
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=creationflags,
        )
        return p.returncode, (p.stdout or "") + "\n" + (p.stderr or "")
    except Exception as e:
        return 1, str(e)


def which(cmd: str) -> bool:
    from shutil import which as _which
    return _which(cmd) is not None


def reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(0.7)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


# Common service ports probed by the optional TCP port-scan feature.
COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554,
    1723, 3306, 3389, 5900, 8080, 8443, 8888,
]


def tcp_probe(ip: str, port: int, timeout: float = 0.6) -> bool:
    """Return True if a TCP connect to ip:port succeeds. Pure stdlib."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_ports(ip: str, ports: List[int], timeout: float = 0.6, workers: int = 32) -> List[int]:
    """Probe a list of ports on one host concurrently; return sorted open ports."""
    open_ports: List[int] = []
    if not ports:
        return open_ports
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        futs = {ex.submit(tcp_probe, ip, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)


def parse_ports(spec: str) -> List[int]:
    """Parse a port spec like '22,80,443,8000-8010' into a sorted unique list."""
    out: Set[int] = set()
    for chunk in (spec or "").replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            try:
                lo, hi = chunk.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
                if lo_i > hi_i:
                    lo_i, hi_i = hi_i, lo_i
                for p in range(lo_i, hi_i + 1):
                    if 0 < p < 65536:
                        out.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(chunk)
                if 0 < p < 65536:
                    out.add(p)
            except ValueError:
                continue
    return sorted(out)


def ping_one(ip: str) -> bool:
    sys = platform.system().lower()
    if sys == "windows":
        cmd = ["ping", "-n", "1", "-w", "350", ip]
        timeout = 2
    elif sys == "darwin":
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
        timeout = 3
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        timeout = 3
    code, _ = run_cmd(cmd, timeout=timeout)
    return code == 0


def get_local_interfaces() -> List[NetSource]:
    out: List[NetSource] = []
    seen: Set[str] = set()

    if psutil is not None:
        for if_name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family != socket.AF_INET:
                    continue
                ip = a.address
                if not ip or ip.startswith("127."):
                    continue
                netmask = a.netmask or "255.255.255.0"
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                except Exception:
                    net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                key = str(net)
                if key not in seen:
                    seen.add(key)
                    out.append(NetSource(net, "nic", if_name))

    # Fallback: use scapy interface addresses when psutil is not available
    if not out and SCAPY_AVAILABLE:
        try:
            for iface in conf.ifaces.data.values():
                name = getattr(iface, "name", "") or ""
                ip = getattr(iface, "ip", "") or ""
                netmask = getattr(iface, "netmask", "") or "255.255.255.0"
                if not ip or ip.startswith("127."):
                    continue
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                except Exception:
                    net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                key = str(net)
                if key not in seen:
                    seen.add(key)
                    out.append(NetSource(net, "nic", name))
        except Exception:
            pass

    return out


def get_system_routes() -> List[NetSource]:
    sys = platform.system().lower()
    nets: List[NetSource] = []
    seen: Set[str] = set()

    if sys == "windows":
        code, text = run_cmd(["route", "print", "-4"], timeout=15)
        if code == 0:
            in_table = False
            for line in text.splitlines():
                if "IPv4 Route Table" in line:
                    in_table = True
                    continue
                if not in_table:
                    continue
                line = line.strip()
                if not line or line.startswith("Active Routes:") or line.startswith("Persistent Routes:"):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                dest, mask = parts[0], parts[1]
                if not (is_ipv4(dest) and is_ipv4(mask)):
                    continue
                try:
                    net = ipaddress.IPv4Network(f"{dest}/{mask}", strict=False)
                except Exception:
                    continue
                if net.prefixlen == 0:
                    continue
                key = str(net)
                if key not in seen:
                    seen.add(key)
                    nets.append(NetSource(net, "route"))
    elif sys == "linux":
        code, text = run_cmd(["ip", "-4", "route", "show"], timeout=15)
        if code == 0:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("default"):
                    continue
                first = line.split()[0]
                if "/" not in first:
                    continue
                try:
                    net = ipaddress.IPv4Network(first, strict=False)
                except Exception:
                    continue
                if net.prefixlen == 0:
                    continue
                key = str(net)
                if key not in seen:
                    seen.add(key)
                    nets.append(NetSource(net, "route"))
    elif sys == "darwin":
        code, text = run_cmd(["netstat", "-rn", "-f", "inet"], timeout=15)
        if code == 0:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("Destination") or line.startswith("Routing tables"):
                    continue
                first = line.split()[0]
                if "/" not in first:
                    continue
                try:
                    net = ipaddress.IPv4Network(first, strict=False)
                except Exception:
                    continue
                if net.prefixlen == 0:
                    continue
                key = str(net)
                if key not in seen:
                    seen.add(key)
                    nets.append(NetSource(net, "route"))

    return nets


def candidate_networks(include_private: bool, max_networks: int) -> List[NetSource]:
    nets: List[NetSource] = []
    seen: Set[str] = set()

    def add(net: ipaddress.IPv4Network, source: str, iface: str = ""):
        key = str(net)
        if key not in seen and net.prefixlen != 0:
            seen.add(key)
            nets.append(NetSource(net, source, iface))

    for ns in get_local_interfaces():
        add(ns.network, ns.source, ns.iface)

    for ns in get_system_routes():
        add(ns.network, ns.source, ns.iface)

    if include_private:
        # bounded probing for common home/office subnets
        for a in range(0, 256):
            add(ipaddress.IPv4Network(f"192.168.{a}.0/24"), "probe:192.168")
        for a in range(16, 32):
            for b in range(0, 16):
                add(ipaddress.IPv4Network(f"172.{a}.{b}.0/24"), "probe:172")
        for a in range(0, 16):
            for b in range(0, 16):
                add(ipaddress.IPv4Network(f"10.{a}.{b}.0/24"), "probe:10")

    return nets[:max_networks]


# ----------------------------
# Discovery engines
# ----------------------------

def arp_cache() -> Dict[str, str]:
    out: Dict[str, str] = {}
    sys = platform.system().lower()

    if sys == "windows":
        code, text = run_cmd(["arp", "-a"], timeout=8)
        if code == 0:
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 2 and is_ipv4(parts[0]):
                    out[parts[0]] = normalize_mac(parts[1])

        code, text = run_cmd(["netsh", "interface", "ipv4", "show", "neighbors"], timeout=12)
        if code == 0:
            import re
            for line in text.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})", line, re.I)
                if m:
                    out[m.group(1)] = normalize_mac(m.group(2))

    else:
        code, text = run_cmd(["ip", "neigh", "show"], timeout=8)
        if code == 0:
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 5 and is_ipv4(parts[0]) and "lladdr" in parts:
                    try:
                        mac = normalize_mac(parts[parts.index("lladdr") + 1])
                        out[parts[0]] = mac
                    except Exception:
                        pass

        code, text = run_cmd(["arp", "-a"], timeout=8)
        if code == 0:
            import re
            for line in text.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line, re.I)
                if m:
                    out[m.group(1)] = normalize_mac(m.group(2))

    return out


def scapy_arp_scan(net: ipaddress.IPv4Network, iface: Optional[str] = None) -> Dict[str, str]:
    if not SCAPY_AVAILABLE:
        return {}
    try:
        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        ans, _ = srp(pkt, timeout=2.0, retry=1, iface=iface, verbose=False)
        out: Dict[str, str] = {}
        for _, reply in ans:
            out[reply.psrc] = normalize_mac(reply.hwsrc)
        return out
    except Exception:
        return {}


def ping_scan(net: ipaddress.IPv4Network, limit: int = 4096) -> List[str]:
    hosts = list(net.hosts())
    if len(hosts) > limit:
        hosts = hosts[:limit]
    live: List[str] = []

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=min(128, max(16, len(hosts)))) as ex:
        futs = {ex.submit(ping_one, str(ip)): str(ip) for ip in hosts}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    live.append(ip)
            except Exception:
                pass

    return sorted(set(live), key=sort_ip)


def passive_sniff_loop(stop_event: threading.Event, emit, iface: Optional[str] = None):
    if not SCAPY_AVAILABLE:
        return

    def _handle(pkt):
        if stop_event.is_set():
            return
        try:
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                mac = normalize_mac(getattr(arp, "hwsrc", "") or pkt[Ether].src)
                ip = getattr(arp, "psrc", "") or ""
                if ip and mac:
                    emit(ip=ip, mac=mac, source="passive:arp")
            elif pkt.haslayer(IP):
                ip = pkt[IP].src
                mac = normalize_mac(pkt[Ether].src) if pkt.haslayer(Ether) else ""
                if ip:
                    emit(ip=ip, mac=mac, source="passive:ip")
        except Exception:
            pass

    try:
        conf.sniff_promisc = True
        sniff(
            iface=iface,
            prn=_handle,
            store=False,
            filter="arp or ip",
            stop_filter=lambda _: stop_event.is_set(),
        )
    except Exception:
        return


# ----------------------------
# Thread-safe device store
# ----------------------------

class DeviceStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.devices: Dict[str, Device] = {}

    def upsert(self, ip: str, mac: str = "", hostname: str = "", source: str = "",
               open_ports: str = "") -> Tuple[bool, bool]:
        """
        Returns (created, changed)
        """
        if not is_ipv4(ip):
            return False, False

        now = time.time()
        mac = normalize_mac(mac)
        with self.lock:
            existing = self.devices.get(ip)
            if existing is None:
                self.devices[ip] = Device(
                    ip=ip,
                    mac=mac,
                    hostname=hostname,
                    vendor=oui_annotate(mac),
                    sources=source,
                    open_ports=open_ports,
                    first_seen=now,
                    last_seen=now,
                    alive=True,
                )
                return True, True

            changed = False
            sources = set(filter(None, [existing.sources, source]))
            new_mac = mac or existing.mac
            new_host = hostname or existing.hostname
            new_vendor = oui_annotate(new_mac) or existing.vendor
            new_ports = open_ports or existing.open_ports

            if (new_mac != existing.mac or new_host != existing.hostname
                    or ";".join(sorted(sources)) != existing.sources
                    or new_ports != existing.open_ports
                    or new_vendor != existing.vendor):
                changed = True

            self.devices[ip] = Device(
                ip=ip,
                mac=new_mac,
                hostname=new_host,
                vendor=new_vendor,
                sources=";".join(sorted(sources)),
                open_ports=new_ports,
                first_seen=existing.first_seen or now,
                last_seen=now,
                alive=True,
            )
            return False, changed

    def mark_all_stale(self):
        with self.lock:
            for ip, dev in list(self.devices.items()):
                self.devices[ip] = Device(
                    ip=dev.ip,
                    mac=dev.mac,
                    hostname=dev.hostname,
                    vendor=dev.vendor,
                    sources=dev.sources,
                    open_ports=dev.open_ports,
                    first_seen=dev.first_seen,
                    last_seen=dev.last_seen,
                    alive=False,
                )

    def snapshot(self) -> List[Device]:
        with self.lock:
            return sorted(self.devices.values(), key=lambda d: sort_ip(d.ip))

    def get(self, ip: str) -> Optional[Device]:
        with self.lock:
            return self.devices.get(ip)

    def delete(self, ip: str):
        with self.lock:
            self.devices.pop(ip, None)


# ----------------------------
# GUI
# ----------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN Multi-Tool")
        self.geometry("1100x700")
        self.minsize(980, 620)

        self.queue: "queue.Queue[Tuple[str, object]]" = queue.Queue()
        self.store = DeviceStore()
        self.stop_event = threading.Event()
        self.sniff_thread: Optional[threading.Thread] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.auto_scan_job = None
        self.hostname_cache: Dict[str, str] = {}
        self.local_nets: List[NetSource] = []
        self.last_scan_text = tk.StringVar(value="Idle")
        self.status_text = tk.StringVar(value="Ready")
        self.auto_scan_on = tk.BooleanVar(value=True)
        self.passive_on = tk.BooleanVar(value=False)
        self.include_private = tk.BooleanVar(value=False)
        self.use_scapy = tk.BooleanVar(value=SCAPY_AVAILABLE)
        self.use_ping = tk.BooleanVar(value=True)
        self.use_reverse_dns = tk.BooleanVar(value=True)
        self.use_port_scan = tk.BooleanVar(value=False)
        self.monitor_on = tk.BooleanVar(value=False)
        self.port_spec = tk.StringVar(value=",".join(str(p) for p in COMMON_PORTS))
        self.scan_interval = tk.IntVar(value=20)
        self.max_networks = tk.IntVar(value=256)
        self.max_ping_hosts = tk.IntVar(value=1024)

        # Continuous-monitor change tracking: IPs known to be live as of the
        # previous completed scan, used to flag NEW / GONE / BACK hosts.
        self.known_alive: Set[str] = set()
        self.first_monitor_pass = True

        self._build_ui()
        self._load_targets()
        self.after(120, self._process_queue)
        self.after(1000, self._expire_loop)
        # Kick off the auto-scan loop once; it re-schedules itself thereafter.
        self._schedule_auto_scan()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        controls = ttk.Frame(top)
        controls.pack(fill="x")

        ttk.Button(controls, text="Load Targets", command=self._load_targets).pack(side="left", padx=4)
        ttk.Button(controls, text="Scan Now", command=self.scan_now).pack(side="left", padx=4)
        ttk.Button(controls, text="Start Passive", command=self.start_passive).pack(side="left", padx=4)
        ttk.Button(controls, text="Stop", command=self.stop_all).pack(side="left", padx=4)
        ttk.Button(controls, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(controls, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(controls, text="Clear", command=self.clear_devices).pack(side="left", padx=4)

        opts = ttk.Frame(top)
        opts.pack(fill="x", pady=(10, 0))

        ttk.Checkbutton(opts, text="Auto scan", variable=self.auto_scan_on, command=self._schedule_auto_scan).grid(row=0, column=0, sticky="w", padx=6)
        ttk.Label(opts, text="Interval (sec)").grid(row=0, column=1, sticky="e")
        ttk.Entry(opts, textvariable=self.scan_interval, width=8).grid(row=0, column=2, sticky="w", padx=6)

        ttk.Checkbutton(opts, text="Passive ARP/IP monitor", variable=self.passive_on).grid(row=0, column=3, sticky="w", padx=12)
        ttk.Checkbutton(opts, text="Use Scapy", variable=self.use_scapy).grid(row=0, column=4, sticky="w", padx=12)
        ttk.Checkbutton(opts, text="Ping fallback", variable=self.use_ping).grid(row=0, column=5, sticky="w", padx=12)
        ttk.Checkbutton(opts, text="Reverse DNS", variable=self.use_reverse_dns).grid(row=0, column=6, sticky="w", padx=12)

        ttk.Checkbutton(opts, text="Include bounded private probes", variable=self.include_private).grid(row=1, column=0, sticky="w", padx=6, pady=(6, 0))
        ttk.Label(opts, text="Max nets").grid(row=1, column=1, sticky="e", pady=(6, 0))
        ttk.Entry(opts, textvariable=self.max_networks, width=8).grid(row=1, column=2, sticky="w", padx=6, pady=(6, 0))
        ttk.Label(opts, text="Max ping hosts/net").grid(row=1, column=3, sticky="e", pady=(6, 0))
        ttk.Entry(opts, textvariable=self.max_ping_hosts, width=8).grid(row=1, column=4, sticky="w", padx=6, pady=(6, 0))

        ttk.Checkbutton(opts, text="TCP port probe", variable=self.use_port_scan).grid(row=2, column=0, sticky="w", padx=6, pady=(6, 0))
        ttk.Label(opts, text="Ports").grid(row=2, column=1, sticky="e", pady=(6, 0))
        ttk.Entry(opts, textvariable=self.port_spec, width=40).grid(row=2, column=2, columnspan=3, sticky="w", padx=6, pady=(6, 0))
        ttk.Checkbutton(opts, text="Monitor mode (flag new/gone hosts)", variable=self.monitor_on, command=self._on_monitor_toggle).grid(row=2, column=5, columnspan=2, sticky="w", padx=12, pady=(6, 0))

        info = ttk.Frame(self, padding=(10, 0, 10, 8))
        info.pack(fill="x")
        ttk.Label(info, textvariable=self.status_text).pack(side="left")
        ttk.Label(info, textvariable=self.last_scan_text).pack(side="right")

        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)

        columns = ("ip", "mac", "vendor", "hostname", "ports", "sources", "last_seen", "alive")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=18)
        self.tree.heading("ip", text="IP")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("vendor", text="Vendor")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("ports", text="Open Ports")
        self.tree.heading("sources", text="Sources")
        self.tree.heading("last_seen", text="Last seen")
        self.tree.heading("alive", text="Alive")

        self.tree.column("ip", width=120, anchor="w")
        self.tree.column("mac", width=150, anchor="w")
        self.tree.column("vendor", width=130, anchor="w")
        self.tree.column("hostname", width=210, anchor="w")
        self.tree.column("ports", width=130, anchor="w")
        self.tree.column("sources", width=200, anchor="w")
        self.tree.column("last_seen", width=100, anchor="w")
        self.tree.column("alive", width=60, anchor="center")

        yscroll = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        # Event log for continuous-monitor mode (NEW / GONE host notifications).
        logframe = ttk.LabelFrame(self, text="Monitor events", padding=(8, 4, 8, 4))
        logframe.pack(fill="x", padx=10, pady=(0, 4))
        self.event_log = tk.Text(logframe, height=6, wrap="none", state="disabled")
        log_scroll = ttk.Scrollbar(logframe, orient="vertical", command=self.event_log.yview)
        self.event_log.configure(yscrollcommand=log_scroll.set)
        self.event_log.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        bottom = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Re-resolve DNS for visible", command=self.resolve_dns_for_all).pack(side="left")
        ttk.Button(bottom, text="Clear events", command=self._clear_events).pack(side="left", padx=8)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _on_monitor_toggle(self):
        # Reset the baseline so the next scan establishes a fresh reference set.
        self.first_monitor_pass = True
        self.known_alive = set()
        if self.monitor_on.get():
            self._append_event("monitor enabled -- next scan sets the baseline")

    def _append_event(self, text: str):
        stamp = time.strftime("%H:%M:%S")
        self.event_log.configure(state="normal")
        self.event_log.insert("end", f"[{stamp}] {text}\n")
        self.event_log.see("end")
        self.event_log.configure(state="disabled")

    def _clear_events(self):
        self.event_log.configure(state="normal")
        self.event_log.delete("1.0", "end")
        self.event_log.configure(state="disabled")

    def _load_targets(self):
        self.local_nets = candidate_networks(
            include_private=self.include_private.get(),
            max_networks=self.max_networks.get(),
        )
        self.status_text.set(f"Loaded {len(self.local_nets)} target networks")
        self._refresh_tree()

    def _set_status(self, text: str):
        self.status_text.set(text)

    def log(self, text: str):
        self.queue.put(("log", text))

    def _process_queue(self):
        # Coalesce tree rebuilds: a single scan can enqueue dozens of device
        # updates per tick, and rebuilding the whole Treeview on each one is
        # O(n^2). Track a dirty flag and refresh at most once per drain.
        needs_refresh = False
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "device":
                    ip, mac, hostname, source, open_ports = payload
                    created, changed = self.store.upsert(
                        ip, mac=mac, hostname=hostname, source=source, open_ports=open_ports
                    )
                    if created or changed:
                        needs_refresh = True
                elif kind == "log":
                    self.last_scan_text.set(str(payload))
                elif kind == "event":
                    self._append_event(str(payload))
                elif kind == "refresh":
                    needs_refresh = True
                elif kind == "status":
                    self._set_status(str(payload))
                elif kind == "nets":
                    self.local_nets = payload
                    needs_refresh = True
        except queue.Empty:
            pass
        if needs_refresh:
            self._refresh_tree()
        self.after(120, self._process_queue)

    def _expire_loop(self):
        # Mark devices as stale if not seen recently; keeps the list honest during back-to-back scans.
        now = time.time()
        updated = False
        with self.store.lock:
            for ip, dev in list(self.store.devices.items()):
                alive = (now - dev.last_seen) <= 90
                if dev.alive != alive:
                    self.store.devices[ip] = Device(
                        ip=dev.ip,
                        mac=dev.mac,
                        hostname=dev.hostname,
                        vendor=dev.vendor,
                        sources=dev.sources,
                        open_ports=dev.open_ports,
                        first_seen=dev.first_seen,
                        last_seen=dev.last_seen,
                        alive=alive,
                    )
                    updated = True
        if updated:
            self._refresh_tree()

        # NOTE: auto-scan is driven by the self-perpetuating _schedule_auto_scan
        # chain (kicked off once in __init__), not from here. Re-scheduling it on
        # every 1s tick would continuously cancel and reset the timer so it would
        # never actually fire.
        self.after(1000, self._expire_loop)

    def _refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        snapshot = self.store.snapshot()
        now = time.time()
        for d in snapshot:
            age = int(now - d.last_seen) if d.last_seen else 0
            last_seen = f"{age}s ago" if age < 60 else f"{age // 60}m ago"
            self.tree.insert(
                "",
                "end",
                values=(d.ip, d.mac, d.vendor, d.hostname, d.open_ports, d.sources,
                        last_seen, "yes" if d.alive else "stale"),
            )

    def clear_devices(self):
        self.store = DeviceStore()
        self._refresh_tree()
        self._set_status("Cleared")

    def _discover_hostname(self, ip: str) -> str:
        if not self.use_reverse_dns.get():
            return ""
        if ip in self.hostname_cache:
            return self.hostname_cache[ip]
        host = reverse_dns(ip)
        self.hostname_cache[ip] = host
        return host

    def scan_now(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.log("scan already running")
            return

        self._load_targets()
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()

    def _scan_worker(self):
        self.queue.put(("status", "Scanning..."))
        try:
            # IPs discovered live during this scan pass (for monitor diffing).
            seen_this_pass: Set[str] = set()

            # Always seed from ARP cache first.
            for ip, mac in arp_cache().items():
                host = self._discover_hostname(ip)
                seen_this_pass.add(ip)
                self.queue.put(("device", (ip, mac, host, "arp-cache", "")))

            nets = self.local_nets[:]
            if not nets:
                self.queue.put(("status", "No target networks found"))
                return

            for ns in nets:
                self.queue.put(("log", f"Scanning {ns.network} [{ns.source}{'/' + ns.iface if ns.iface else ''}]"))
                # Active ARP scan is the best way to find connected LAN devices.
                if self.use_scapy.get() and SCAPY_AVAILABLE and ns.source == "nic":
                    found = scapy_arp_scan(ns.network, iface=ns.iface or None)
                    for ip, mac in found.items():
                        host = self._discover_hostname(ip)
                        seen_this_pass.add(ip)
                        self.queue.put(("device", (ip, mac, host, f"scapy:{ns.source}", "")))

                if self.use_ping.get():
                    live = ping_scan(ns.network, limit=self.max_ping_hosts.get())
                    for ip in live:
                        host = self._discover_hostname(ip)
                        seen_this_pass.add(ip)
                        self.queue.put(("device", (ip, "", host, f"ping:{ns.source}", "")))

            # Optional TCP port probe across all hosts found this pass.
            if self.use_port_scan.get() and seen_this_pass:
                ports = parse_ports(self.port_spec.get())
                if ports:
                    self.queue.put(("status", f"Port-scanning {len(seen_this_pass)} hosts..."))
                    for ip in sorted(seen_this_pass, key=sort_ip):
                        opened = scan_ports(ip, ports)
                        if opened:
                            ports_str = ",".join(str(p) for p in opened)
                            d = self.store.get(ip)
                            self.queue.put((
                                "device",
                                (ip, d.mac if d else "", d.hostname if d else "",
                                 d.sources if d else "ports", ports_str),
                            ))

            # Fill in hostnames for everything we have.
            if self.use_reverse_dns.get():
                ips = [d.ip for d in self.store.snapshot()]
                for ip in ips:
                    host = self._discover_hostname(ip)
                    if host:
                        d = self.store.get(ip)
                        if d:
                            self.queue.put(("device", (ip, d.mac, host, d.sources, d.open_ports)))

            # Continuous-monitor diff: flag hosts that appeared or vanished
            # relative to the previous completed pass.
            if self.monitor_on.get():
                self._emit_monitor_changes(seen_this_pass)
            self.known_alive = set(seen_this_pass)

            self.queue.put(("refresh", None))
            self.queue.put(("status", f"Scan done: {len(self.store.snapshot())} devices"))
            self.queue.put(("log", f"last scan {time.strftime('%H:%M:%S')}"))
        except Exception as e:
            self.queue.put(("status", f"Scan error: {e}"))

    def _emit_monitor_changes(self, seen_this_pass: Set[str]):
        """Compare this pass against the last and log NEW / GONE hosts."""
        if self.first_monitor_pass:
            # First pass establishes a baseline; everything is "known".
            self.first_monitor_pass = False
            self.queue.put(("event", f"monitor baseline: {len(seen_this_pass)} hosts"))
            return

        new_hosts = seen_this_pass - self.known_alive
        gone_hosts = self.known_alive - seen_this_pass

        for ip in sorted(new_hosts, key=sort_ip):
            d = self.store.get(ip)
            label = (d.hostname or d.vendor or d.mac) if d else ""
            extra = f" ({label})" if label else ""
            self.queue.put(("event", f"NEW   {ip}{extra}"))

        for ip in sorted(gone_hosts, key=sort_ip):
            d = self.store.get(ip)
            label = (d.hostname or d.vendor or d.mac) if d else ""
            extra = f" ({label})" if label else ""
            self.queue.put(("event", f"GONE  {ip}{extra}"))

    def _schedule_auto_scan(self):
        if self.auto_scan_job is not None:
            self.after_cancel(self.auto_scan_job)
            self.auto_scan_job = None

        if not self.auto_scan_on.get():
            return

        delay_ms = max(5, int(self.scan_interval.get())) * 1000

        def _go():
            self.auto_scan_job = None
            if self.auto_scan_on.get():
                self.scan_now()
                self._schedule_auto_scan()

        self.auto_scan_job = self.after(delay_ms, _go)

    def start_passive(self):
        if not SCAPY_AVAILABLE:
            messagebox.showwarning("Scapy not available", "Install scapy to use passive monitoring.")
            return
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.log("passive monitor already running")
            return
        self.stop_event.clear()
        iface = None  # sniff on default interface; you can change this if needed
        self.sniff_thread = threading.Thread(
            target=passive_sniff_loop,
            args=(self.stop_event, self._passive_emit, iface),
            daemon=True,
        )
        self.sniff_thread.start()
        self.passive_on.set(True)
        self._set_status("Passive monitor running")

    def _passive_emit(self, ip: str, mac: str, source: str):
        host = self._discover_hostname(ip)
        self.queue.put(("device", (ip, mac, host, source, "")))

    def stop_all(self):
        self.auto_scan_on.set(False)
        if self.auto_scan_job is not None:
            try:
                self.after_cancel(self.auto_scan_job)
            except Exception:
                pass
            self.auto_scan_job = None
        self.stop_event.set()
        self._set_status("Stopped")

    def resolve_dns_for_all(self):
        def worker():
            self.queue.put(("status", "Resolving hostnames..."))
            for dev in self.store.snapshot():
                host = self._discover_hostname(dev.ip)
                if host:
                    self.queue.put(("device", (dev.ip, dev.mac, host, dev.sources, dev.open_ports)))
            self.queue.put(("refresh", None))
            self.queue.put(("status", "Hostname refresh done"))

        threading.Thread(target=worker, daemon=True).start()

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="devices.csv",
        )
        if not path:
            return

        try:
            devices = self.store.snapshot()
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["IP Address", "MAC Address", "Vendor", "Hostname", "Open Ports",
                            "Sources", "First Seen", "Last Seen", "Alive"])
                for d in devices:
                    w.writerow([
                        d.ip,
                        d.mac,
                        d.vendor,
                        d.hostname,
                        d.open_ports,
                        d.sources,
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.first_seen)) if d.first_seen else "",
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.last_seen)) if d.last_seen else "",
                        "yes" if d.alive else "stale",
                    ])
            messagebox.showinfo("Export complete", f"Saved {len(devices)} devices to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def export_json(self):
        path = filedialog.asksaveasfilename(
            title="Save JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="devices.json",
        )
        if not path:
            return

        try:
            devices = self.store.snapshot()
            records = []
            for d in devices:
                records.append({
                    "ip": d.ip,
                    "mac": d.mac,
                    "vendor": d.vendor,
                    "hostname": d.hostname,
                    "open_ports": [int(p) for p in d.open_ports.split(",") if p.strip().isdigit()],
                    "sources": d.sources,
                    "first_seen": (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(d.first_seen))
                                   if d.first_seen else None),
                    "last_seen": (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(d.last_seen))
                                  if d.last_seen else None),
                    "alive": bool(d.alive),
                })
            payload = {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "count": len(records),
                "devices": records,
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            messagebox.showinfo("Export complete", f"Saved {len(records)} devices to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def on_close(self):
        self.stop_all()
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
