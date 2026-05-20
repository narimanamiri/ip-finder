import argparse
import atexit
import csv
import ctypes
import ipaddress
import platform
import re
import shutil
import socket
import struct
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

import psutil
from ctypes import wintypes


# =========================
# Windows ICMP API (fast ping)
# =========================

icmp = ctypes.WinDLL("icmp.dll")
kernel32 = ctypes.WinDLL("kernel32.dll")

icmp.IcmpCreateFile.restype = wintypes.HANDLE
icmp.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
icmp.IcmpCloseHandle.restype = wintypes.BOOL

icmp.IcmpSendEcho.argtypes = [
    wintypes.HANDLE,      # IcmpHandle
    wintypes.DWORD,       # DestinationAddress
    wintypes.LPVOID,      # RequestData
    wintypes.WORD,        # RequestSize
    wintypes.LPVOID,      # RequestOptions
    wintypes.LPVOID,      # ReplyBuffer
    wintypes.DWORD,       # ReplySize
    wintypes.DWORD,       # Timeout
]
icmp.IcmpSendEcho.restype = wintypes.DWORD

_thread_local = threading.local()


def _get_icmp_handle() -> wintypes.HANDLE:
    h = getattr(_thread_local, "icmp_handle", None)
    if h:
        return h
    h = icmp.IcmpCreateFile()
    _thread_local.icmp_handle = h
    return h


def _close_thread_handle():
    h = getattr(_thread_local, "icmp_handle", None)
    if h:
        try:
            icmp.IcmpCloseHandle(h)
        except Exception:
            pass


atexit.register(_close_thread_handle)


def ip_to_dword(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def ping_icmp(ip: str, timeout_ms: int = 50) -> bool:
    """
    Fast Windows ping using IcmpSendEcho.
    """
    try:
        handle = _get_icmp_handle()
        if not handle:
            return False

        payload = b"py"
        send_buf = ctypes.create_string_buffer(payload)
        reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + 32
        reply_buf = ctypes.create_string_buffer(reply_size)

        result = icmp.IcmpSendEcho(
            handle,
            ip_to_dword(ip),
            send_buf,
            len(payload),
            None,
            reply_buf,
            reply_size,
            timeout_ms,
        )
        return result > 0
    except Exception:
        return False


# =========================
# Data models
# =========================

@dataclass(frozen=True)
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    sources: str = ""


@dataclass(frozen=True)
class NetSource:
    network: ipaddress.IPv4Network
    source: str
    iface: str = ""


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.DWORD),
        ("Status", wintypes.DWORD),
        ("RoundTripTime", wintypes.DWORD),
        ("DataSize", wintypes.WORD),
        ("Reserved", wintypes.WORD),
        ("Data", wintypes.LPVOID),
        ("Options", wintypes.DWORD * 4),  # padding for practical use
    ]


# =========================
# Utility
# =========================

def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


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


# =========================
# Windows network discovery
# =========================

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
    code, text = run_cmd(["route", "print", "-4"], timeout=10)
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


def arp_cache_windows() -> Dict[str, str]:
    out: Dict[str, str] = {}

    code, text = run_cmd(["arp", "-a"], timeout=6)
    if code == 0:
        for line in text.splitlines():
            line = line.strip()
            parts = line.split()
            if len(parts) >= 2 and is_ipv4(parts[0]):
                out[parts[0]] = parts[1].replace("-", ":").lower()

    code, text = run_cmd(["netsh", "interface", "ipv4", "show", "neighbors"], timeout=10)
    if code == 0:
        for line in text.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})", line, re.I)
            if m:
                out[m.group(1)] = m.group(2).replace("-", ":").lower()

    return out


def reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(0.5)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


# =========================
# Optional tools
# =========================

def nmap_scan(cidr: str) -> Dict[str, str]:
    if not which("nmap"):
        return {}

    # Fast host discovery only.
    code, text = run_cmd(["nmap", "-sn", "-n", "-T5", "--max-retries", "1", cidr], timeout=300)
    if code not in (0, 1):
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


# =========================
# Scanner
# =========================

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


def iter_hosts(cidr: ipaddress.IPv4Network):
    for ip in cidr.hosts():
        yield str(ip)


def scan_cidr_icmp(
    cidr: ipaddress.IPv4Network,
    workers: int,
    timeout_ms: int,
    max_in_flight: int,
) -> List[str]:
    live: List[str] = []

    host_iter = iter_hosts(cidr)
    pending = set()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        # Prime the queue.
        for _ in range(max_in_flight):
            try:
                ip = next(host_iter)
            except StopIteration:
                break
            pending.add(ex.submit(ping_icmp, ip, timeout_ms))

        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done:
                try:
                    if fut.result():
                        # We do not know which IP from the future directly;
                        # so use a closure-free approach below in scan_cidr().
                        pass
                except Exception:
                    pass

            # Refill
            for _ in range(len(done)):
                try:
                    ip = next(host_iter)
                except StopIteration:
                    break
                pending.add(ex.submit(ping_icmp, ip, timeout_ms))

    return live


def scan_cidr(
    cidr: ipaddress.IPv4Network,
    workers: int = 1024,
    timeout_ms: int = 30,
    max_in_flight: int = 4096,
    use_nmap: bool = True,
    hostname_resolution: bool = True,
) -> List[Device]:
    devices: Dict[str, Device] = {}

    # Seed with current Windows caches.
    for ip, mac in arp_cache_windows().items():
        merge_device(devices, ip, mac=mac, source="arp-cache")

    # Nmap first if installed, because it may find MACs on local segments quickly.
    if use_nmap and which("nmap"):
        try:
            found = nmap_scan(str(cidr))
            for ip, mac in found.items():
                merge_device(devices, ip, mac=mac, source="nmap")
        except Exception:
            pass

    # High-speed ICMP sweep.
    host_iter = iter_hosts(cidr)
    pending = {}
    live_ips: List[str] = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        def submit_next():
            try:
                ip = next(host_iter)
            except StopIteration:
                return False
            fut = ex.submit(ping_icmp, ip, timeout_ms)
            pending[fut] = ip
            return True

        for _ in range(max_in_flight):
            if not submit_next():
                break

        while pending:
            done, _ = wait(list(pending.keys()), return_when=FIRST_COMPLETED)
            for fut in done:
                ip = pending.pop(fut, None)
                if ip is None:
                    continue
                try:
                    if fut.result():
                        live_ips.append(ip)
                        merge_device(devices, ip, source="icmp")
                except Exception:
                    pass
            while len(pending) < max_in_flight:
                if not submit_next():
                    break

    # Refresh Windows neighbor cache after pinging; often this fills in MACs.
    cache = arp_cache_windows()
    for ip, mac in cache.items():
        if ip in devices:
            d = devices[ip]
            devices[ip] = Device(ip=d.ip, mac=mac or d.mac, hostname=d.hostname, sources=d.sources)

    # DNS in parallel
    if hostname_resolution and devices:
        ips = list(devices.keys())
        with ThreadPoolExecutor(max_workers=min(256, workers)) as ex:
            futs = {ex.submit(reverse_dns, ip): ip for ip in ips}
            for fut in futs:
                ip = futs[fut]
                try:
                    host = fut.result()
                    if host:
                        d = devices[ip]
                        devices[ip] = Device(ip=d.ip, mac=d.mac, hostname=host, sources=d.sources)
                except Exception:
                    pass

    return sorted(devices.values(), key=lambda d: sort_ip(d.ip))


def scan_auto(
    workers: int,
    timeout_ms: int,
    max_in_flight: int,
    use_nmap: bool,
    hostname_resolution: bool,
) -> List[Device]:
    devices: Dict[str, Device] = {}

    for ns in local_interfaces():
        merge_device(devices, ns.network.network_address.exploded, source=f"nic:{ns.iface}")

    # Scan local NIC routes automatically.
    targets = []
    seen: Set[str] = set()
    for ns in local_interfaces() + routes_windows():
        key = str(ns.network)
        if key not in seen and ns.network.prefixlen != 0:
            seen.add(key)
            targets.append(ns.network)

    for net in targets:
        print(f"Scanning {net}")
        found = scan_cidr(
            net,
            workers=workers,
            timeout_ms=timeout_ms,
            max_in_flight=max_in_flight,
            use_nmap=use_nmap,
            hostname_resolution=hostname_resolution,
        )
        for d in found:
            merge_device(devices, d.ip, mac=d.mac, hostname=d.hostname, source=d.sources)

    return sorted(devices.values(), key=lambda d: sort_ip(d.ip))


def save_csv(devices: List[Device], filename: str) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["IP Address", "MAC Address", "Hostname", "Sources"])
        for d in devices:
            w.writerow([d.ip, d.mac, d.hostname, d.sources])


def main():
    if platform.system().lower() != "windows":
        raise SystemExit("This version is Windows-only.")

    p = argparse.ArgumentParser(description="Fast Windows IP scanner using ICMP API.")
    p.add_argument("--cidr", default="", help="CIDR to scan, e.g. 8.0.0.0/8")
    p.add_argument("--workers", type=int, default=1024, help="Thread count")
    p.add_argument("--timeout-ms", type=int, default=25, help="ICMP timeout per host")
    p.add_argument("--max-in-flight", type=int, default=4096, help="Maximum queued tasks")
    p.add_argument("--no-nmap", action="store_true", help="Disable nmap if installed")
    p.add_argument("--no-dns", action="store_true", help="Disable reverse DNS lookups")
    p.add_argument("--out", default="devices.csv", help="CSV output file")
    args = p.parse_args()

    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"nmap: {'yes' if which('nmap') else 'no'}")
    print(f"Workers: {args.workers}")
    print(f"Timeout: {args.timeout_ms} ms")

    if args.cidr:
        cidr = ipaddress.IPv4Network(args.cidr, strict=False)
        devices = scan_cidr(
            cidr,
            workers=args.workers,
            timeout_ms=args.timeout_ms,
            max_in_flight=args.max_in_flight,
            use_nmap=not args.no_nmap,
            hostname_resolution=not args.no_dns,
        )
    else:
        devices = scan_auto(
            workers=args.workers,
            timeout_ms=args.timeout_ms,
            max_in_flight=args.max_in_flight,
            use_nmap=not args.no_nmap,
            hostname_resolution=not args.no_dns,
        )

    print("\nDevices found:")
    for d in devices:
        print(f"{d.ip:<15} {d.mac:<18} {d.hostname}")

    save_csv(devices, args.out)
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()