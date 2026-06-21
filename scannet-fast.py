#!/usr/bin/env python3
"""
scannet-fast.py -- high-performance Windows ICMP sweeper (pcap-free).

Pings very large IPv4 ranges -- millions of hosts, e.g. an air-gapped Class-A
``10.0.0.0/8`` (16.7M addresses) -- using the native Windows ICMP helper API
(``IcmpSendEcho`` from ``icmp.dll``). It does **not** use Npcap / WinPcap or
Scapy, so it is safe on systems where the pcap driver is missing or unstable.

Why this design scales to a million+ hosts:
  * The target range is streamed lazily through a bounded queue, so memory stays
    flat no matter how large the range is (a ``/8`` is fine).
  * A worker-thread pool (default 1024) keeps a per-thread ICMP handle and reply
    buffer, so the hot path allocates nothing.
  * Live progress is printed (scanned / alive / rate / ETA).
  * Crash-safe: every live host is appended to a sidecar ``.live`` file the
    instant it is found, so an interrupted multi-million-host sweep keeps its
    results. Ctrl-C stops cleanly and still writes the final report.
  * Optional retries (for lossy links), reverse-DNS and MAC/vendor enrichment.

Output: CSV (default), JSON (``--json``) or plain text (``--text``).

Windows only. On Linux/macOS use ``scannet-fastV2.py``.

Examples
--------
    # Sweep an entire Class-A range, 2048 workers, write devices.csv + .live log
    python scannet-fast.py --cidr 10.0.0.0/8 --workers 2048 --out devices.csv

    # A few subnets, one extra retry for reliability, JSON output
    python scannet-fast.py --cidr 10.1.0.0/16,10.2.0.0/16 --retries 1 \
        --out hosts.json --json

    # Auto-detect local subnets (default when --cidr is omitted)
    python scannet-fast.py
"""
import argparse
import csv
import ctypes
import ipaddress
import json
import platform
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import psutil

try:
    from oui_lookup import annotate as oui_annotate
except Exception:
    def oui_annotate(_mac: str) -> str:
        return ""


# =========================
# Windows ICMP API
# =========================
# icmp.dll / IcmpSendEcho is Windows-only. Fail fast with a clear message on
# other platforms instead of crashing with an AttributeError at import time
# (ctypes.WinDLL/wintypes only exist on Windows). Use scannet-fastV2.py there.
if platform.system().lower() != "windows":
    raise SystemExit(
        "scannet-fast.py is Windows-only (uses icmp.dll). "
        "Use scannet-fastV2.py for cross-platform scanning."
    )

from ctypes import wintypes

try:
    icmp = ctypes.WinDLL("icmp.dll")
except OSError as exc:  # pragma: no cover - icmp.dll is always present on Windows
    raise SystemExit(f"Could not load icmp.dll: {exc}")

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
_REQUEST_PAYLOAD = b"scannet-fast"
_REPLY_SIZE = 1024


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
    """Fast Windows ping using IcmpSendEcho. Reuses per-thread buffers."""
    try:
        handle = _get_icmp_handle()
        if not handle:
            return False

        # Reuse one reply buffer per worker thread to avoid per-ping allocation
        # on the hot path (matters across millions of calls).
        reply = getattr(_thread_local, "reply_buf", None)
        if reply is None:
            reply = ctypes.create_string_buffer(_REPLY_SIZE)
            _thread_local.reply_buf = reply

        ret = icmp.IcmpSendEcho(
            handle,
            ip_to_dword(ip),
            _REQUEST_PAYLOAD,
            len(_REQUEST_PAYLOAD),
            None,
            reply,
            _REPLY_SIZE,
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


def fmt_int(n: int) -> str:
    return f"{n:,}"


def host_count(net: ipaddress.IPv4Network) -> int:
    """Number of addresses ``net.hosts()`` yields (handles /31 and /32)."""
    if net.num_addresses <= 2:
        return net.num_addresses
    return net.num_addresses - 2


def total_hosts(targets: List[ipaddress.IPv4Network]) -> int:
    return sum(host_count(net) for net in targets)


def fmt_duration(seconds: float) -> str:
    """Human-friendly H:MM:SS / M:SS / Ns string for progress + ETA."""
    if seconds < 0 or seconds != seconds:  # negative or NaN
        return "?"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m{seconds % 60:02d}s"


# =========================
# Windows discovery (auto targets + ARP enrichment)
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
# Threaded sweep core
# =========================
def _ping_worker(idx: int, ip_q: "queue.Queue", found_q: "queue.Queue",
                 counts: List[int], timeout_ms: int, retries: int,
                 stop: threading.Event):
    """Pull IPs off ip_q, ICMP-ping (with retries), push live ones to found_q."""
    try:
        local = 0
        while True:
            ip = ip_q.get()
            try:
                if ip is None:
                    return
                if not stop.is_set():
                    alive = False
                    for _ in range(retries + 1):
                        if ping_icmp(ip, timeout_ms):
                            alive = True
                            break
                    if alive:
                        found_q.put(ip)
                    local += 1
                    counts[idx] = local
            finally:
                ip_q.task_done()
    finally:
        _close_icmp_handle()


def _producer(targets: List[ipaddress.IPv4Network], ip_q: "queue.Queue",
              workers: int, stop: threading.Event):
    """Stream every host address of every target into the bounded queue."""
    try:
        for net in targets:
            # net.hosts() already handles /31 and /32 correctly (returns both /
            # the single address) and excludes network/broadcast otherwise.
            for ip in net.hosts():
                if stop.is_set():
                    return
                ip_q.put(str(ip))
    finally:
        # Always release the workers, even if interrupted.
        for _ in range(workers):
            try:
                ip_q.put(None)
            except Exception:
                pass


def _collector(found_q: "queue.Queue", live: List[str], stream_fp, stream_lock):
    """Drain live hosts, append to the in-memory list and the crash-safe log."""
    while True:
        ip = found_q.get()
        if ip is None:
            return
        live.append(ip)
        if stream_fp is not None:
            with stream_lock:
                stream_fp.write(ip + "\n")
                stream_fp.flush()


def _progress(total: int, counts: List[int], live: List[str],
              start: float, stop: threading.Event, interval: float):
    """Print a single refreshing status line until stop is set."""
    while not stop.wait(interval):
        scanned = sum(counts)
        elapsed = time.time() - start
        rate = scanned / elapsed if elapsed > 0 else 0
        eta = (total - scanned) / rate if rate > 0 else -1
        pct = (scanned / total * 100) if total else 0
        sys.stdout.write(
            f"\r  {pct:5.1f}%  scanned {fmt_int(scanned)}/{fmt_int(total)}"
            f"  alive {fmt_int(len(live))}  {fmt_int(int(rate))}/s"
            f"  ETA {fmt_duration(eta)}        "
        )
        sys.stdout.flush()


def sweep(
    targets: List[ipaddress.IPv4Network],
    workers: int,
    timeout_ms: int,
    queue_size: int,
    retries: int,
    stream_path: Optional[str],
    progress_interval: float,
) -> List[str]:
    """Run the full multi-threaded ICMP sweep; return sorted live IP strings.

    Streams results to ``stream_path`` (one IP per line) as they are found, and
    keeps partial results if interrupted with Ctrl-C.
    """
    total = total_hosts(targets)

    ip_q: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=queue_size)
    found_q: "queue.Queue[Optional[str]]" = queue.Queue()
    counts = [0] * workers
    live: List[str] = []
    stop = threading.Event()

    stream_fp = None
    stream_lock = threading.Lock()
    if stream_path:
        try:
            stream_fp = open(stream_path, "w", encoding="utf-8", buffering=1)
        except Exception as e:
            print(f"  (could not open stream file {stream_path}: {e})")
            stream_fp = None

    workers_t = [
        threading.Thread(target=_ping_worker,
                         args=(i, ip_q, found_q, counts, timeout_ms, retries, stop),
                         daemon=True)
        for i in range(workers)
    ]
    for t in workers_t:
        t.start()

    collector_t = threading.Thread(
        target=_collector, args=(found_q, live, stream_fp, stream_lock), daemon=True)
    collector_t.start()

    start = time.time()
    progress_t = threading.Thread(
        target=_progress, args=(total, counts, live, start, stop, progress_interval),
        daemon=True)
    progress_t.start()

    producer_t = threading.Thread(
        target=_producer, args=(targets, ip_q, workers, stop), daemon=True)
    producer_t.start()

    interrupted = False
    try:
        # Wait for all queued IPs to be processed.
        ip_q.join()
    except KeyboardInterrupt:
        interrupted = True
        print("\n  Interrupted -- stopping and saving partial results...")
        stop.set()
        # Drain quickly so workers reach their None sentinels.
        try:
            ip_q.join()
        except KeyboardInterrupt:
            pass

    # Stop progress and let the line settle.
    stop.set()
    progress_t.join(timeout=2)

    producer_t.join(timeout=2)
    for t in workers_t:
        t.join(timeout=2)

    # Close the collector once workers are done producing.
    found_q.put(None)
    collector_t.join(timeout=5)

    if stream_fp is not None:
        try:
            stream_fp.close()
        except Exception:
            pass

    elapsed = time.time() - start
    scanned = sum(counts)
    print(f"\n  Swept {fmt_int(scanned)} addresses in {fmt_duration(elapsed)} "
          f"({fmt_int(int(scanned / elapsed)) if elapsed else 0}/s), "
          f"{fmt_int(len(live))} alive" + ("  [partial -- interrupted]" if interrupted else ""))

    return sorted(set(live), key=sort_ip)


def enrich(live_ips: List[str], use_dns: bool, dns_workers: int) -> List[Device]:
    """Attach MAC (from ARP cache) + vendor + optional reverse-DNS to live IPs."""
    arp = windows_arp_cache()
    devices: Dict[str, Device] = {
        ip: Device(ip=ip, mac=arp.get(ip, ""), sources="icmp") for ip in live_ips
    }

    if use_dns and devices:
        with ThreadPoolExecutor(max_workers=min(dns_workers, max(1, len(devices)))) as ex:
            futs = {ex.submit(reverse_dns, ip): ip for ip in devices}
            for fut in as_completed(futs):
                ip = futs[fut]
                try:
                    host = fut.result()
                except Exception:
                    host = ""
                if host:
                    d = devices[ip]
                    devices[ip] = Device(ip=d.ip, mac=d.mac, hostname=host, sources=d.sources)

    return sorted(devices.values(), key=lambda d: sort_ip(d.ip))


# =========================
# Output
# =========================
def save_csv(devices: List[Device], filename: str):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["IP Address", "MAC Address", "Vendor", "Hostname", "Sources"])
        for d in devices:
            w.writerow([d.ip, d.mac, d.vendor, d.hostname, d.sources])


def save_json(devices: List[Device], filename: str):
    records = [
        {"ip": d.ip, "mac": d.mac, "vendor": d.vendor,
         "hostname": d.hostname, "sources": d.sources}
        for d in devices
    ]
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({"count": len(records), "devices": records}, f, indent=2)


def save_text(devices: List[Device], filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        for d in devices:
            f.write(d.ip + "\n")


# =========================
# Targets
# =========================
def parse_cidrs(specs: List[str]) -> List[ipaddress.IPv4Network]:
    """Parse one or more --cidr values (each may be comma-separated)."""
    nets: List[ipaddress.IPv4Network] = []
    seen: Set[str] = set()
    for spec in specs:
        for chunk in spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                net = ipaddress.IPv4Network(chunk, strict=False)
            except ValueError as e:
                raise SystemExit(f"Invalid CIDR '{chunk}': {e}")
            key = str(net)
            if key not in seen:
                seen.add(key)
                nets.append(net)
    return nets


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
    p = argparse.ArgumentParser(
        description="High-performance Windows ICMP sweeper (pcap-free). "
                    "Scans millions of hosts; safe without Npcap.")
    p.add_argument("--cidr", action="append", default=[],
                   help="Target CIDR(s). Repeatable and/or comma-separated, "
                        "e.g. --cidr 10.0.0.0/8 or --cidr 10.1.0.0/16,10.2.0.0/16. "
                        "Omit to auto-detect local subnets.")
    p.add_argument("--workers", type=int, default=1024, help="Worker threads (default 1024).")
    p.add_argument("--timeout-ms", type=int, default=400, help="ICMP timeout per host in ms (default 400).")
    p.add_argument("--retries", type=int, default=0,
                   help="Extra ICMP attempts before a host is declared dead "
                        "(default 0; use 1-2 on busy/lossy networks).")
    p.add_argument("--queue-size", type=int, default=65536, help="Bounded in-flight queue size.")
    p.add_argument("--no-dns", action="store_true", help="Disable reverse DNS on live hosts.")
    p.add_argument("--dns-workers", type=int, default=256, help="Reverse-DNS worker threads.")
    p.add_argument("--progress-interval", type=float, default=2.0,
                   help="Seconds between progress updates (0 disables).")
    p.add_argument("--out", default="devices.csv", help="Output file (CSV by default).")
    p.add_argument("--json", action="store_true", help="Write --out as JSON.")
    p.add_argument("--text", action="store_true", help="Write --out as a plain IP list.")
    p.add_argument("--no-stream", action="store_true",
                   help="Disable the crash-safe '<out>.live' streaming log.")
    args = p.parse_args()

    if args.json and args.text:
        raise SystemExit("Choose only one of --json / --text.")
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")

    targets = parse_cidrs(args.cidr) if args.cidr else auto_targets()
    if not targets:
        print("No targets found.")
        return

    total = total_hosts(targets)

    print(f"Platform     : {platform.system()} {platform.release()}")
    print(f"Workers      : {args.workers}")
    print(f"Timeout      : {args.timeout_ms} ms  (retries: {args.retries})")
    print(f"Targets      : {len(targets)} range(s), {fmt_int(total)} addresses")
    for t in targets[:10]:
        print(f"               {t}  ({fmt_int(host_count(t))} hosts)")
    if len(targets) > 10:
        print(f"               ... and {len(targets) - 10} more")

    stream_path = None if args.no_stream else f"{args.out}.live"
    if stream_path:
        print(f"Live log     : {stream_path}  (updated as hosts are found)")
    print()

    live_ips = sweep(
        targets=targets,
        workers=args.workers,
        timeout_ms=args.timeout_ms,
        queue_size=args.queue_size,
        retries=args.retries,
        stream_path=stream_path,
        progress_interval=args.progress_interval if args.progress_interval > 0 else 1e9,
    )

    if not live_ips:
        print("\nNo live hosts found.")
        return

    print("\nEnriching live hosts (ARP MAC / vendor" + ("" if args.no_dns else " / reverse DNS") + ")...")
    devices = enrich(live_ips, use_dns=not args.no_dns, dns_workers=args.dns_workers)

    print("\nLive hosts:")
    for d in devices[:50]:
        print(f"  {d.ip:<15} {d.mac:<18} {d.vendor:<16} {d.hostname}")
    if len(devices) > 50:
        print(f"  ... and {len(devices) - 50} more (see {args.out})")

    if args.json:
        save_json(devices, args.out)
    elif args.text:
        save_text(devices, args.out)
    else:
        save_csv(devices, args.out)
    print(f"\nSaved {fmt_int(len(devices))} live hosts to {args.out}")


if __name__ == "__main__":
    main()
