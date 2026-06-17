import argparse
import csv
import ipaddress
import os
import platform
import queue
import re
import socket
import struct
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import psutil
import ctypes
from ctypes import wintypes

try:
    from oui_lookup import annotate as oui_annotate
except Exception:
    def oui_annotate(_mac: str) -> str:
        return ""


# =========================
# Windows ICMP API
# =========================
icmp = ctypes.WinDLL("icmp.dll")

icmp.IcmpCreateFile.restype = wintypes.HANDLE
icmp.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
icmp.IcmpCloseHandle.restype = wintypes.BOOL

icmp.IcmpSendEcho.argtypes = [
    wintypes.HANDLE,   # IcmpHandle
    wintypes.DWORD,    # DestinationAddress
    wintypes.LPVOID,   # RequestData
    wintypes.WORD,     # RequestSize
    wintypes.LPVOID,   # RequestOptions
    wintypes.LPVOID,   # ReplyBuffer
    wintypes.DWORD,    # ReplySize
    wintypes.DWORD,    # Timeout
]
icmp.IcmpSendEcho.restype = wintypes.DWORD

_thread_local = threading.local()


def _get_icmp_handle():
    h = getattr(_thread_local, "icmp_handle", None)
    if h:
        return h
    h = icmp.IcmpCreateFile()
    _thread_local.icmp_handle = h
    return h


def _close_icmp_handle():
    h = getattr(_thread_local, "icmp_handle", None)
    if h:
        try:
            icmp.IcmpCloseHandle(h)
        except Exception:
            pass
        _thread_local.icmp_handle = None


def ip_to_dword(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def ping_icmp(ip: str, timeout_ms: int) -> bool:
    """
    Fast Windows ping using IcmpSendEcho.
    """
    try:
        handle = _get_icmp_handle()
        if not handle:
            return False

        payload = b"py"
        request = ctypes.create_string_buffer(payload)
        reply = ctypes.create_string_buffer(1024)

        ret = icmp.IcmpSendEcho(
            handle,
            ip_to_dword(ip),
            request,
            len(payload),
            None,
            reply,
            len(reply),
            timeout_ms,
        )
        if ret <= 0:
            return False
        # IcmpSendEcho also returns a reply for error responses (e.g. a router's
        # "destination unreachable"), which would be a false positive. The
        # ICMP_ECHO_REPLY struct stores its Status DWORD at offset 4; only
        # IP_SUCCESS (0) means the target host itself answered.
        status = struct.unpack_from("<I", reply.raw, 4)[0]
        return status == 0
    except Exception:
        return False


# =========================
# Models
# =========================
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


# =========================
# Helpers
# =========================
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


def which(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None


# =========================
# Windows discovery
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


def windows_routes() -> List[NetSource]:
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


def windows_arp_cache() -> Dict[str, str]:
    out: Dict[str, str] = {}

    code, text = run_cmd(["arp", "-a"], timeout=6)
    if code == 0:
        for line in text.splitlines():
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
# Threaded scanner
# =========================
def ping_worker(ip_q: "queue.Queue[Optional[str]]", result_q: "queue.Queue[str]", timeout_ms: int):
    try:
        while True:
            ip = ip_q.get()
            try:
                if ip is None:
                    return
                if ping_icmp(ip, timeout_ms):
                    result_q.put(ip)
            finally:
                ip_q.task_done()
    finally:
        _close_icmp_handle()


def merge_device(devices: Dict[str, Device], ip: str, mac: str = "", hostname: str = "", source: str = ""):
    if not is_ipv4(ip):
        return

    old = devices.get(ip)
    if old is None:
        devices[ip] = Device(ip=ip, mac=mac, hostname=hostname, sources=source)
        return

    sources = set(filter(None, [old.sources, source]))
    devices[ip] = Device(
        ip=ip,
        mac=mac or old.mac,
        hostname=hostname or old.hostname,
        sources=";".join(sorted(sources)),
    )


def scan_cidr_threaded(
    cidr: ipaddress.IPv4Network,
    workers: int,
    timeout_ms: int,
    queue_size: int,
    use_dns: bool,
) -> List[Device]:
    devices: Dict[str, Device] = {}

    # Seed from Windows cache before and after scan
    for ip, mac in windows_arp_cache().items():
        merge_device(devices, ip, mac=mac, source="arp-cache")

    ip_q: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=queue_size)
    result_q: "queue.Queue[str]" = queue.Queue()

    threads = []
    for _ in range(workers):
        t = threading.Thread(target=ping_worker, args=(ip_q, result_q, timeout_ms), daemon=True)
        t.start()
        threads.append(t)

    # Producer: stream IPs into the queue without loading the whole subnet into memory.
    def producer():
        for ip in cidr.hosts():
            ip_q.put(str(ip))
        for _ in range(workers):
            ip_q.put(None)

    prod = threading.Thread(target=producer, daemon=True)
    prod.start()

    # Wait for all tasks to finish.
    ip_q.join()
    prod.join()

    # Drain results.
    live_ips = []
    while True:
        try:
            live_ips.append(result_q.get_nowait())
        except queue.Empty:
            break

    for ip in live_ips:
        merge_device(devices, ip, source="icmp")

    # Refresh cache after the sweep to pick up MACs for active neighbors.
    cache = windows_arp_cache()
    for ip, mac in cache.items():
        if ip in devices:
            d = devices[ip]
            devices[ip] = Device(ip=d.ip, mac=mac or d.mac, hostname=d.hostname, sources=d.sources)

    # Reverse DNS in parallel
    if use_dns and devices:
        with ThreadPoolExecutor(max_workers=min(256, workers)) as ex:
            futs = {ex.submit(reverse_dns, ip): ip for ip in devices.keys()}
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


def save_csv(devices: List[Device], filename: str):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["IP Address", "MAC Address", "Vendor", "Hostname", "Sources"])
        for d in devices:
            w.writerow([d.ip, d.mac, d.vendor, d.hostname, d.sources])


def auto_targets() -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    seen: Set[str] = set()

    for ns in local_interfaces() + windows_routes():
        key = str(ns.network)
        if key not in seen and ns.network.prefixlen != 0:
            seen.add(key)
            nets.append(ns.network)

    return nets


def main():
    if platform.system().lower() != "windows":
        raise SystemExit("Windows only.")

    p = argparse.ArgumentParser(description="High-performance Windows threaded IP scanner.")
    p.add_argument("--cidr", default="", help="CIDR to scan, e.g. 8.0.0.0/8")
    p.add_argument("--workers", type=int, default=1024, help="Number of worker threads")
    p.add_argument("--timeout-ms", type=int, default=20, help="ICMP timeout per host")
    p.add_argument("--queue-size", type=int, default=65536, help="Bounded queue size")
    p.add_argument("--no-dns", action="store_true", help="Disable reverse DNS")
    p.add_argument("--out", default="devices.csv", help="CSV output file")
    args = p.parse_args()

    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Workers: {args.workers}")
    print(f"Timeout: {args.timeout_ms} ms")
    print(f"Queue size: {args.queue_size}")
    print(f"nmap installed: {'yes' if which('nmap') else 'no'}")

    if args.cidr:
        cidr = ipaddress.IPv4Network(args.cidr, strict=False)
        targets = [cidr]
    else:
        targets = auto_targets()

    if not targets:
        print("No targets found.")
        return

    print("\nTargets:")
    for t in targets:
        print(f"  {t}")

    all_devices: Dict[str, Device] = {}

    for target in targets:
        print(f"\nScanning {target} ...")
        found = scan_cidr_threaded(
            target,
            workers=args.workers,
            timeout_ms=args.timeout_ms,
            queue_size=args.queue_size,
            use_dns=not args.no_dns,
        )
        for d in found:
            merge_device(all_devices, d.ip, mac=d.mac, hostname=d.hostname, source=d.sources)

    devices = sorted(all_devices.values(), key=lambda d: sort_ip(d.ip))

    print("\nDevices found:")
    for d in devices:
        print(f"{d.ip:<15} {d.mac:<18} {d.vendor:<16} {d.hostname}")

    save_csv(devices, args.out)
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()