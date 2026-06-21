#!/usr/bin/env python3
"""
finder.py -- aggressive cross-platform LAN/WAN device discovery aggregator.

Combines every locally available discovery method and merges the results into a
single per-IP device table (IP, MAC, vendor, hostname, sources), then exports
CSV. Methods used when available:

  * the OS ARP / neighbor cache (seeded first)
  * a Scapy ARP scan on directly attached interfaces (optional, needs pcap)
  * external tools auto-detected on PATH: nmap (-sn), fping, arp-scan, nbtscan
  * a threaded ICMP ping sweep (fallback that always works)
  * reverse-DNS resolution of everything found

Targets are the local NIC subnets and OS routes; ``--private`` adds a bounded
set of common RFC-1918 /24s. MAC addresses are mapped to vendors offline via
oui_lookup. Scapy/arp-scan need Administrator (Windows) or root (Linux/macOS).

Note: the Scapy ARP path uses pcap (Npcap/libpcap). On a host with a broken
pcap driver, run with ``--no-scapy`` (the ping/nmap paths do not need pcap).

Usage:
    python finder.py --out devices.csv
    python finder.py --private --no-scapy --max-ping-hosts 1024
"""
import argparse
import csv
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import psutil

def _import_scapy():
    """Import Scapy while silencing its noisy pcap-service probe.

    On import Scapy logs a WARNING and even shells out to the OS to probe/start
    the pcap service, leaking text to stderr when pcap is unavailable. Neither
    affects this tool (the ARP path degrades to the ping sweep), so we suppress
    that one-time noise by muting the logger and redirecting stderr just for the
    duration of the import.
    """
    import logging
    import os as _os
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    saved_fd = devnull_fd = None
    try:
        saved_fd = _os.dup(2)
        devnull_fd = _os.open(_os.devnull, _os.O_WRONLY)
        _os.dup2(devnull_fd, 2)
    except Exception:
        saved_fd = None
    try:
        from scapy.all import ARP, Ether, srp, conf  # noqa: F401
        return ARP, Ether, srp, conf
    finally:
        if saved_fd is not None:
            try:
                _os.dup2(saved_fd, 2)
            finally:
                _os.close(saved_fd)
        if devnull_fd is not None:
            _os.close(devnull_fd)


try:
    ARP, Ether, srp, conf = _import_scapy()
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    from oui_lookup import annotate as oui_annotate
except Exception:
    def oui_annotate(_mac: str) -> str:
        return ""


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    sources: str = ""

    @property
    def vendor(self) -> str:
        return oui_annotate(self.mac)


@dataclass(frozen=True)
class NetSource:
    network: ipaddress.IPv4Network
    source: str
    iface: str = ""


def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


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


def is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def sort_ip(ip: str):
    try:
        return ipaddress.IPv4Address(ip)
    except Exception:
        return ip


def local_interfaces() -> List[NetSource]:
    out: List[NetSource] = []
    seen: Set[str] = set()

    for if_name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family != socket.AF_INET:
                continue
            ip = a.address
            if ip.startswith("127."):
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
    return out


def routes_windows() -> List[NetSource]:
    code, text = run_cmd(["route", "print", "-4"], timeout=15)
    if code != 0:
        return []

    nets: List[NetSource] = []
    seen: Set[str] = set()
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
    return nets


def routes_linux() -> List[NetSource]:
    code, text = run_cmd(["ip", "-4", "route", "show"], timeout=15)
    if code != 0:
        return []

    nets: List[NetSource] = []
    seen: Set[str] = set()

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
    return nets


def routes_macos() -> List[NetSource]:
    code, text = run_cmd(["netstat", "-rn", "-f", "inet"], timeout=15)
    if code != 0:
        return []

    nets: List[NetSource] = []
    seen: Set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Destination") or line.startswith("Routing tables"):
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


def system_routes() -> List[NetSource]:
    sys = platform.system().lower()
    if sys == "windows":
        return routes_windows()
    if sys == "linux":
        return routes_linux()
    if sys == "darwin":
        return routes_macos()
    return []


def arp_cache_windows() -> Dict[str, str]:
    out: Dict[str, str] = {}

    code, text = run_cmd(["arp", "-a"], timeout=8)
    if code == 0:
        for line in text.splitlines():
            line = line.strip()
            parts = line.split()
            if len(parts) >= 2 and is_ipv4(parts[0]):
                out[parts[0]] = parts[1].replace("-", ":").lower()

    code, text = run_cmd(["netsh", "interface", "ipv4", "show", "neighbors"], timeout=12)
    if code == 0:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("interface"):
                continue
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})", line, re.I)
            if m:
                out[m.group(1)] = m.group(2).replace("-", ":").lower()

    return out


def arp_cache_unix() -> Dict[str, str]:
    out: Dict[str, str] = {}

    code, text = run_cmd(["ip", "neigh", "show"], timeout=8)
    if code == 0:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 5 and is_ipv4(parts[0]) and "lladdr" in parts:
                try:
                    mac = parts[parts.index("lladdr") + 1].lower()
                    out[parts[0]] = mac
                except Exception:
                    pass

    code, text = run_cmd(["arp", "-a"], timeout=8)
    if code == 0:
        for line in text.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line, re.I)
            if m:
                out[m.group(1)] = m.group(2).lower()

    return out


def arp_cache() -> Dict[str, str]:
    return arp_cache_windows() if platform.system().lower() == "windows" else arp_cache_unix()


def reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(0.6)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


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


def ping_scan(net: ipaddress.IPv4Network, limit: int = 4096) -> List[str]:
    hosts = list(net.hosts())
    if len(hosts) > limit:
        hosts = hosts[:limit]

    live: List[str] = []
    with ThreadPoolExecutor(max_workers=128) as ex:
        futs = {ex.submit(ping_one, str(ip)): str(ip) for ip in hosts}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    live.append(ip)
            except Exception:
                pass
    return sorted(live, key=sort_ip)


def scapy_arp_scan(net: ipaddress.IPv4Network, iface: Optional[str] = None) -> Dict[str, str]:
    if not SCAPY_AVAILABLE:
        return {}
    try:
        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        ans, _ = srp(pkt, timeout=2, retry=1, iface=iface, verbose=False)
        out: Dict[str, str] = {}
        for _, reply in ans:
            out[reply.psrc] = reply.hwsrc.lower()
        return out
    except Exception:
        return {}


def nmap_scan(net: ipaddress.IPv4Network) -> Dict[str, str]:
    if not which("nmap"):
        return {}
    code, text = run_cmd(["nmap", "-sn", str(net)], timeout=180)
    if code != 0:
        return {}

    out: Dict[str, str] = {}
    current_ip = ""

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for "):
            tail = line[len("Nmap scan report for "):].strip()
            if tail.endswith(")") and "(" in tail:
                current_ip = tail.split("(")[-1].rstrip(")")
            else:
                current_ip = tail if is_ipv4(tail) else ""
        elif line.lower().startswith("mac address:") and current_ip:
            mac = line.split(":", 1)[1].split()[0].lower()
            out[current_ip] = mac
    return out


def fping_scan(net: ipaddress.IPv4Network) -> List[str]:
    if not which("fping"):
        return []
    code, text = run_cmd(["fping", "-a", "-g", str(net)], timeout=180)
    if code not in (0, 1):
        return []

    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if is_ipv4(line):
            out.append(line)
        elif "is alive" in line:
            ip = line.split()[0]
            if is_ipv4(ip):
                out.append(ip)
    return sorted(set(out), key=sort_ip)


def arp_scan_tool(net: ipaddress.IPv4Network) -> Dict[str, str]:
    if not which("arp-scan"):
        return {}
    code, text = run_cmd(["arp-scan", "--retry=1", "--timeout=500", str(net)], timeout=180)
    if code not in (0, 1):
        return {}

    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+", line, re.I)
        if m:
            out[m.group(1)] = m.group(2).lower()
    return out


def nbtscan_tool(net: ipaddress.IPv4Network) -> Dict[str, str]:
    if not which("nbtscan"):
        return {}
    code, text = run_cmd(["nbtscan", "-r", str(net)], timeout=180)
    if code not in (0, 1):
        return {}

    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+", line)
        if m:
            ip = m.group(1)
            out.setdefault(ip, "")
    return out


def merge_device(devices: Dict[str, Device], ip: str, mac: str = "", hostname: str = "", source: str = "") -> None:
    if not is_ipv4(ip):
        return
    existing = devices.get(ip)
    if existing is None:
        devices[ip] = Device(ip=ip, mac=mac, hostname=hostname, sources=source)
        return

    sources = set(filter(None, [existing.sources, source]))
    devices[ip] = Device(
        ip=ip,
        mac=mac or existing.mac,
        hostname=hostname or existing.hostname,
        sources=";".join(sorted(sources)),
    )


def add_sources_from_dict(devices: Dict[str, Device], mapping: Dict[str, str], source: str) -> None:
    for ip, mac in mapping.items():
        merge_device(devices, ip, mac=mac, source=source)


def candidate_networks(include_private: bool, max_networks: int) -> List[NetSource]:
    nets: List[NetSource] = []
    seen: Set[str] = set()

    def add(net: ipaddress.IPv4Network, source: str, iface: str = ""):
        key = str(net)
        if key not in seen and net.prefixlen != 0:
            seen.add(key)
            nets.append(NetSource(net, source, iface))

    for ns in local_interfaces():
        add(ns.network, ns.source, ns.iface)

    for ns in system_routes():
        add(ns.network, ns.source, ns.iface)

    if include_private:
        # Bounded private probing. This is intentionally not an entire RFC1918 brute force.
        # It scans common /24s in 192.168.x.0/24 and a small set of likely 172.16-31 /24s.
        for a in range(0, 256):
            add(ipaddress.IPv4Network(f"192.168.{a}.0/24"), "probe:192.168")
        for a in range(16, 32):
            for b in range(0, 8):
                add(ipaddress.IPv4Network(f"172.{a}.{b}.0/24"), "probe:172")
        for a in range(0, 8):
            for b in range(0, 8):
                add(ipaddress.IPv4Network(f"10.{a}.{b}.0/24"), "probe:10")

    return nets[:max_networks]


def scan_networks(
    nets: List[NetSource],
    use_scapy: bool,
    use_nmap: bool,
    use_fping: bool,
    use_arpscan: bool,
    use_nbtscan: bool,
    use_ping: bool,
    max_ping_hosts: int,
) -> List[Device]:
    devices: Dict[str, Device] = {}

    for ip, mac in arp_cache().items():
        merge_device(devices, ip, mac=mac, source="arp-cache")

    for ns in nets:
        net = ns.network
        print(f"Scanning {net} [{ns.source}{'/' + ns.iface if ns.iface else ''}]")

        if use_scapy and ns.source == "nic":
            try:
                found = scapy_arp_scan(net, iface=ns.iface or None)
                add_sources_from_dict(devices, found, f"scapy:{ns.source}")
            except Exception:
                pass

        if use_nmap and which("nmap"):
            try:
                found = nmap_scan(net)
                add_sources_from_dict(devices, found, f"nmap:{ns.source}")
            except Exception:
                pass

        if use_arpscan and which("arp-scan"):
            try:
                found = arp_scan_tool(net)
                add_sources_from_dict(devices, found, f"arp-scan:{ns.source}")
            except Exception:
                pass

        if use_fping and which("fping"):
            try:
                live = fping_scan(net)
                for ip in live:
                    merge_device(devices, ip, source=f"fping:{ns.source}")
            except Exception:
                pass

        if use_nbtscan and which("nbtscan"):
            try:
                found = nbtscan_tool(net)
                for ip in found:
                    merge_device(devices, ip, source=f"nbtscan:{ns.source}")
            except Exception:
                pass

        if use_ping:
            try:
                live = ping_scan(net, limit=max_ping_hosts)
                for ip in live:
                    merge_device(devices, ip, source=f"ping:{ns.source}")
            except Exception:
                pass

    # Fill reverse DNS in parallel.
    ips = list(devices.keys())
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(reverse_dns, ip): ip for ip in ips}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                host = fut.result()
                if host:
                    d = devices[ip]
                    devices[ip] = Device(ip=d.ip, mac=d.mac, hostname=host, sources=d.sources)
            except Exception:
                pass

    return sorted(devices.values(), key=lambda d: sort_ip(d.ip))


def save_csv(devices: List[Device], filename: str) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["IP Address", "MAC Address", "Vendor", "Hostname", "Sources"])
        for d in devices:
            w.writerow([d.ip, d.mac, d.vendor, d.hostname, d.sources])


def main():
    p = argparse.ArgumentParser(description="Aggressive local network device discovery.")
    p.add_argument("--private", action="store_true", help="Also probe bounded private-range subnets.")
    p.add_argument("--no-scapy", action="store_true", help="Disable Scapy ARP scan.")
    p.add_argument("--no-nmap", action="store_true", help="Disable nmap.")
    p.add_argument("--no-fping", action="store_true", help="Disable fping.")
    p.add_argument("--no-arpscan", action="store_true", help="Disable arp-scan.")
    p.add_argument("--no-nbtscan", action="store_true", help="Disable nbtscan.")
    p.add_argument("--no-ping", action="store_true", help="Disable ping sweep.")
    p.add_argument("--max-networks", type=int, default=256, help="Maximum number of subnets to scan.")
    p.add_argument("--max-ping-hosts", type=int, default=4096, help="Max hosts per subnet for ping sweep.")
    p.add_argument("--out", default="devices.csv", help="CSV output file.")
    args = p.parse_args()

    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Scapy: {'yes' if SCAPY_AVAILABLE else 'no'}")
    print(f"nmap: {'yes' if which('nmap') else 'no'}")
    print(f"fping: {'yes' if which('fping') else 'no'}")
    print(f"arp-scan: {'yes' if which('arp-scan') else 'no'}")
    print(f"nbtscan: {'yes' if which('nbtscan') else 'no'}")

    nets = candidate_networks(args.private, args.max_networks)

    if not nets:
        print("No networks found.")
        return

    print("\nTarget networks:")
    for ns in nets:
        print(f"  {ns.network}   [{ns.source}{'/' + ns.iface if ns.iface else ''}]")

    devices = scan_networks(
        nets=nets,
        use_scapy=SCAPY_AVAILABLE and not args.no_scapy,
        use_nmap=not args.no_nmap,
        use_fping=not args.no_fping,
        use_arpscan=not args.no_arpscan,
        use_nbtscan=not args.no_nbtscan,
        use_ping=not args.no_ping,
        max_ping_hosts=args.max_ping_hosts,
    )

    if not devices:
        print("\nNo devices found.")
        return

    print("\nDevices found:")
    for d in devices:
        print(f"  {d.ip:<15} {d.mac:<18} {d.vendor:<16} {d.hostname}")

    save_csv(devices, args.out)
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()