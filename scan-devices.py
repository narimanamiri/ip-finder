import argparse
import csv
import ipaddress
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

import psutil

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    source: str = ""


@dataclass(frozen=True)
class NetworkSource:
    network: ipaddress.IPv4Network
    source: str


def run_cmd(cmd: List[str], timeout: int = 15) -> Tuple[int, str]:
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


def is_ipv4(addr: str) -> bool:
    try:
        ipaddress.IPv4Address(addr)
        return True
    except Exception:
        return False


def get_local_interface_networks() -> List[NetworkSource]:
    out: List[NetworkSource] = []
    seen: Set[str] = set()

    for if_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if ip.startswith("127."):
                continue

            netmask = addr.netmask or "255.255.255.0"
            try:
                net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            except Exception:
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)

            key = str(net)
            if key not in seen:
                seen.add(key)
                out.append(NetworkSource(net, f"nic:{if_name}"))

    return out


def get_windows_routes() -> List[NetworkSource]:
    code, text = run_cmd(["route", "print", "-4"], timeout=10)
    if code != 0:
        return []

    nets: List[NetworkSource] = []
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

        # Example row:
        # Network Destination        Netmask          Gateway       Interface  Metric
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

        # Skip default route /0 because it is too broad.
        if net.prefixlen == 0:
            continue

        key = str(net)
        if key not in seen:
            seen.add(key)
            nets.append(NetworkSource(net, "route:windows"))

    return nets


def get_linux_routes() -> List[NetworkSource]:
    code, text = run_cmd(["ip", "-4", "route", "show"], timeout=10)
    if code != 0:
        return []

    nets: List[NetworkSource] = []
    seen: Set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("default"):
            continue

        # Examples:
        # 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10
        # 10.10.0.0/16 via 10.10.0.1 dev eth0
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
            nets.append(NetworkSource(net, "route:linux"))

    return nets


def get_macos_routes() -> List[NetworkSource]:
    code, text = run_cmd(["netstat", "-rn", "-f", "inet"], timeout=10)
    if code != 0:
        return []

    nets: List[NetworkSource] = []
    seen: Set[str] = set()

    # Best-effort parser for rows like:
    # 192.168.1/24       link#4             UCS         en0
    # 10.0.0.0/8         10.0.0.1           UGSc        en0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Destination") or line.startswith("Routing tables"):
            continue

        first = line.split()[0]
        if "/" not in first:
            continue

        # Convert shorthand like 192.168.1/24
        try:
            if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", first):
                net = ipaddress.IPv4Network(first, strict=False)
            else:
                # Sometimes macOS shows weird values; skip if not parseable.
                continue
        except Exception:
            continue

        if net.prefixlen == 0:
            continue

        key = str(net)
        if key not in seen:
            seen.add(key)
            nets.append(NetworkSource(net, "route:macos"))

    return nets


def get_system_route_networks() -> List[NetworkSource]:
    system = platform.system().lower()
    if system == "windows":
        return get_windows_routes()
    if system == "linux":
        return get_linux_routes()
    if system == "darwin":
        return get_macos_routes()
    return []


def has_nmap() -> bool:
    code, _ = run_cmd(["nmap", "--version"], timeout=5)
    return code == 0


def nmap_discover(network: ipaddress.IPv4Network, timeout: int = 120) -> Dict[str, str]:
    code, text = run_cmd(["nmap", "-sn", str(network)], timeout=timeout)
    if code != 0:
        return {}

    results: Dict[str, str] = {}
    current_ip = ""

    for line in text.splitlines():
        line = line.strip()

        if line.startswith("Nmap scan report for "):
            tail = line[len("Nmap scan report for "):].strip()
            # Handles:
            # Nmap scan report for 192.168.1.1
            # Nmap scan report for hostname (192.168.1.1)
            if tail.endswith(")") and "(" in tail:
                current_ip = tail.split("(")[-1].rstrip(")")
            else:
                current_ip = tail if is_ipv4(tail) else ""
        elif line.lower().startswith("mac address:") and current_ip:
            mac = line.split(":", 1)[1].split()[0].lower()
            results[current_ip] = mac

    return results


def arp_scan(network: ipaddress.IPv4Network, iface_name: Optional[str] = None, timeout: int = 2) -> Dict[str, str]:
    if not SCAPY_AVAILABLE:
        return {}

    try:
        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(pkt, timeout=timeout, retry=1, iface=iface_name, verbose=False)

        results: Dict[str, str] = {}
        for _, reply in answered:
            results[reply.psrc] = reply.hwsrc.lower()
        return results
    except Exception:
        return {}


def ping_one(ip: str, timeout_ms: int = 500) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        timeout = max(2, int(timeout_ms / 1000) + 2)
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
        timeout = 3
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        timeout = 3

    code, _ = run_cmd(cmd, timeout=timeout)
    return code == 0


def ping_sweep(network: ipaddress.IPv4Network, workers: int = 128, max_hosts: int = 4096) -> List[str]:
    hosts = list(network.hosts())
    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]

    live: List[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(ping_one, str(ip)): str(ip) for ip in hosts}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    live.append(ip)
            except Exception:
                pass

    return sorted(live, key=lambda x: ipaddress.IPv4Address(x))


def parse_arp_cache() -> Dict[str, str]:
    out: Dict[str, str] = {}
    system = platform.system().lower()

    if system == "windows":
        code, text = run_cmd(["arp", "-a"], timeout=5)
        if code == 0:
            for line in text.splitlines():
                line = line.strip()
                # Typical:
                # 192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic
                parts = line.split()
                if len(parts) >= 2 and is_ipv4(parts[0]):
                    out[parts[0]] = parts[1].replace("-", ":").lower()

    else:
        code, text = run_cmd(["ip", "neigh"], timeout=5)
        if code == 0:
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 5 and is_ipv4(parts[0]) and "lladdr" in parts:
                    try:
                        mac = parts[parts.index("lladdr") + 1].lower()
                        out[parts[0]] = mac
                    except Exception:
                        pass

        code, text = run_cmd(["arp", "-a"], timeout=5)
        if code == 0:
            for line in text.splitlines():
                # (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on en0
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line, re.I)
                if m:
                    out[m.group(1)] = m.group(2).lower()

    return out


def reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(0.5)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


def merge_device(devices: Dict[str, Device], ip: str, mac: str = "", hostname: str = "", source: str = "") -> None:
    existing = devices.get(ip)
    if existing is None:
        devices[ip] = Device(ip=ip, mac=mac, hostname=hostname, source=source)
        return

    sources = set(filter(None, [existing.source, source]))
    devices[ip] = Device(
        ip=ip,
        mac=mac or existing.mac,
        hostname=hostname or existing.hostname,
        source=";".join(sorted(sources)),
    )


def build_target_networks(
    include_private: bool,
    include_defaults: bool,
    max_total_hosts: int,
) -> List[NetworkSource]:
    nets: List[NetworkSource] = []
    seen: Set[str] = set()

    def add(net: ipaddress.IPv4Network, source: str):
        key = str(net)
        if key not in seen:
            seen.add(key)
            nets.append(NetworkSource(net, source))

    # 1) local NIC networks
    for ns in get_local_interface_networks():
        add(ns.network, ns.source)

    # 2) routes from OS
    for ns in get_system_route_networks():
        add(ns.network, ns.source)

    # 3) optional private-range probing
    # This is intentionally limited to /24s to avoid trying to brute-force an entire /8.
    if include_private:
        for a in range(0, 256):
            add(ipaddress.IPv4Network(f"192.168.{a}.0/24"), "private:192.168")
        for a in range(0, 256):
            add(ipaddress.IPv4Network(f"10.{a}.0.0/16"), "private:10")
        for a in range(16, 32):
            add(ipaddress.IPv4Network(f"172.{a}.0.0/16"), "private:172")

    # 4) optionally add default route-derived guesses from gateway-adjacent /24s
    # Not perfect, but useful when the target is on another nearby subnet.
    # We use the local interface networks already; this just keeps the behavior predictable.

    # Limit by total hosts so the script does not explode into enormous scans.
    chosen: List[NetworkSource] = []
    total_hosts = 0
    for ns in nets:
        hosts = max(0, ns.network.num_addresses - 2)
        if hosts == 0:
            continue
        if total_hosts + hosts > max_total_hosts and not include_defaults:
            continue
        chosen.append(ns)
        total_hosts += hosts

    return chosen


def discover_devices(
    include_private: bool,
    include_ping: bool,
    include_arp: bool,
    include_nmap: bool,
    max_total_hosts: int,
) -> List[Device]:
    devices: Dict[str, Device] = {}

    # Seed from ARP/neighbor cache
    for ip, mac in parse_arp_cache().items():
        merge_device(devices, ip, mac=mac, source="arp_cache")

    target_networks = build_target_networks(
        include_private=include_private,
        include_defaults=False,
        max_total_hosts=max_total_hosts,
    )

    if not target_networks:
        return []

    print("\nTarget networks:")
    for ns in target_networks:
        print(f"  {ns.network}  [{ns.source}]")

    # Also discover names and MACs from routes and scans
    for ns in target_networks:
        net = ns.network
        print(f"\nScanning {net} ({ns.source})")

        # ARP is best for directly attached L2 networks
        if include_arp and SCAPY_AVAILABLE:
            try:
                ifname = None
                if ns.source.startswith("nic:"):
                    ifname = ns.source.split("nic:", 1)[1]
                found = arp_scan(net, iface_name=ifname)
                for ip, mac in found.items():
                    merge_device(devices, ip, mac=mac, source=f"arp:{ns.source}")
            except Exception as e:
                print(f"  ARP failed: {e}")

        # Nmap is best for routed discovery and mixed environments
        if include_nmap and has_nmap():
            try:
                found = nmap_discover(net)
                for ip, mac in found.items():
                    merge_device(devices, ip, mac=mac, source=f"nmap:{ns.source}")
            except Exception as e:
                print(f"  nmap failed: {e}")

        # Ping sweep is the fallback when nothing else is available
        if include_ping:
            try:
                live = ping_sweep(net, workers=128, max_hosts=4096)
                for ip in live:
                    merge_device(devices, ip, source=f"ping:{ns.source}")
            except Exception as e:
                print(f"  ping sweep failed: {e}")

    # Reverse DNS last, in parallel
    ips = list(devices.keys())
    with ThreadPoolExecutor(max_workers=64) as pool:
        futs = {pool.submit(reverse_dns, ip): ip for ip in ips}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                host = fut.result()
                if host:
                    d = devices[ip]
                    devices[ip] = Device(ip=d.ip, mac=d.mac, hostname=host, source=d.source)
            except Exception:
                pass

    return sorted(devices.values(), key=lambda d: ipaddress.IPv4Address(d.ip))


def save_csv(devices: List[Device], filename: str = "devices.csv") -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["IP Address", "MAC Address", "Hostname", "Source"])
        for d in devices:
            w.writerow([d.ip, d.mac, d.hostname, d.source])


def main():
    parser = argparse.ArgumentParser(description="Find devices on your reachable networks.")
    parser.add_argument("--private", action="store_true", help="Also probe common private subnets. Can be slow.")
    parser.add_argument("--no-ping", action="store_true", help="Disable ping sweep.")
    parser.add_argument("--no-arp", action="store_true", help="Disable ARP scan.")
    parser.add_argument("--no-nmap", action="store_true", help="Disable nmap even if installed.")
    parser.add_argument("--max-hosts", type=int, default=8192, help="Rough cap for total hosts to scan.")
    parser.add_argument("--out", default="devices.csv", help="CSV output file.")
    args = parser.parse_args()

    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Scapy: {'yes' if SCAPY_AVAILABLE else 'no'}")
    print(f"Nmap: {'yes' if has_nmap() else 'no'}")

    devices = discover_devices(
        include_private=args.private,
        include_ping=not args.no_ping,
        include_arp=not args.no_arp,
        include_nmap=not args.no_nmap,
        max_total_hosts=args.max_hosts,
    )

    if not devices:
        print("\nNo devices found.")
        return

    print("\nDevices found:")
    for d in devices:
        host = f"  {d.hostname}" if d.hostname else ""
        print(f"  {d.ip:<15} {d.mac:<18} {host}")

    save_csv(devices, args.out)
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()