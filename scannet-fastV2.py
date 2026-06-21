#!/usr/bin/env python3
"""
scannet-fastV2.py -- portable high-concurrency IP sweeper (stdlib only).

A dependency-free, cross-platform host scanner for large CIDR ranges. It pings
(via the system ``ping`` binary) and/or TCP-connects to discover live hosts, and
bounds the number of in-flight tasks so even a Class-A ``10.0.0.0/8`` (16.7M
addresses) scans with flat memory use.

Use this on Linux/macOS, or on Windows when you cannot use ``scannet-fast.py``
(which is faster there via ``icmp.dll``). It needs **no third-party packages** --
only the Python standard library.

Highlights:
  * ping, TCP-connect, or both (TCP helps when ICMP is firewalled).
  * Live progress: percent / scanned / alive / rate / ETA.
  * Crash-safe streaming: live hosts are written to ``<out>.live`` as found, and
    Ctrl-C stops cleanly while keeping partial results.
  * Optional ping retries for lossy links, and reverse-DNS enrichment.
  * Multiple ranges (repeat or comma-separate the CIDR argument).

Examples
--------
    # Whole air-gapped Class-A, both methods, 1000 threads -> live.txt + .live log
    python scannet-fastV2.py 10.0.0.0/8 -t 1000 --method both -o live.txt

    # Several subnets, TCP only on a couple of ports, JSON output
    python scannet-fastV2.py 10.1.0.0/16,10.2.0.0/16 --method tcp \\
        --ports 80,443 -o live.json --json

    # Ping-only with one retry and reverse-DNS names
    python scannet-fastV2.py 192.168.0.0/16 --method ping --retries 1 --resolve
"""
import argparse
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from itertools import islice

# For maximum speed on large ranges, consider using masscan/zmap externally.
# This script maximizes Python resources with high concurrency + low timeouts.

_PLATFORM = platform.system().lower()
# Hide the console window each `ping` spawns on Windows (avoids flicker, and
# matters when this script is frozen into a windowed/onefile executable).
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _ping_command(ip, timeout):
    """Build a platform-correct single-shot ping command.

    The per-platform timeout flags are genuinely different and were previously
    wrong on Linux/macOS:
      * Windows  -w <milliseconds>
      * macOS    -W <milliseconds>
      * Linux    -W <seconds>     (-w there means a *total deadline*, not a
                                   per-reply timeout, so the old code asked for
                                   an 800-second deadline on every host)
    """
    if _PLATFORM == "windows":
        return ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), str(ip)]
    if _PLATFORM == "darwin":
        return ["ping", "-c", "1", "-W", str(max(1, int(timeout * 1000))), str(ip)]
    return ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), str(ip)]


def is_alive_ping(ip, timeout=1.0, retries=0):
    """ICMP ping via the system `ping` binary. Returns True on the first reply."""
    for _ in range(retries + 1):
        try:
            subprocess.run(
                _ping_command(ip, timeout),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1,
                creationflags=_NO_WINDOW,
                check=True,
            )
            return True
        except (subprocess.SubprocessError, OSError):
            continue
    return False


def is_alive_tcp(ip, port=80, timeout=0.8):
    """TCP connect check (SYN/ACK) - useful when ICMP is blocked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((str(ip), port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def scan_ip(ip, methods, ports, timeout=0.8, retries=0, full_ports=False):
    """Scan a single IP. Returns (ip_str, is_alive, [open_ports])."""
    alive = False
    open_ports = []

    if "ping" in methods and is_alive_ping(ip, timeout=timeout, retries=retries):
        alive = True

    if "tcp" in methods:
        for p in ports:
            if is_alive_tcp(ip, p, timeout=timeout):
                alive = True
                open_ports.append(p)
                # For discovery one open port is enough; --full-port-scan keeps
                # probing the rest of the list to report every open port.
                if not full_ports:
                    break

    return (str(ip), True, open_ports) if alive else (str(ip), False, [])


def parse_cidrs(specs):
    """Parse one or more CIDR specs (each may be comma-separated)."""
    nets = []
    seen = set()
    for spec in specs:
        for chunk in str(spec).split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                net = ipaddress.ip_network(chunk, strict=False)
            except ValueError as e:
                raise SystemExit(f"Invalid CIDR '{chunk}': {e}")
            key = str(net)
            if key not in seen:
                seen.add(key)
                nets.append(net)
    return nets


def total_hosts(nets):
    """Number of addresses ``hosts()`` will yield across all networks."""
    total = 0
    for net in nets:
        total += net.num_addresses if net.num_addresses <= 2 else net.num_addresses - 2
    return total


def generate_ips(nets):
    """Lazily yield every host address across all networks (memory-safe)."""
    for net in nets:
        for ip in net.hosts():  # handles /31, /32; skips network/broadcast otherwise
            yield ip


def reverse_dns(ip, timeout=0.5):
    """Best-effort reverse-DNS lookup for a discovered IP (stdlib, opt-in)."""
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(str(ip))
        return host
    except OSError:
        return ""


def resolve_hostnames(ips, workers=64):
    """Resolve reverse-DNS names for a list of IPs concurrently."""
    names = {}
    if not ips:
        return names
    with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as ex:
        futs = {ex.submit(reverse_dns, ip): ip for ip in ips}
        for fut in futs:
            ip = futs[fut]
            try:
                host = fut.result()
                if host:
                    names[ip] = host
            except Exception:
                pass
    return names


def fmt_duration(seconds):
    """Human-friendly H:MM:SS / M:SS / Ns string for progress + ETA."""
    if seconds is None or seconds < 0 or seconds != seconds:
        return "?"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m{seconds % 60:02d}s"


def main():
    parser = argparse.ArgumentParser(
        description="Portable high-concurrency IP scanner for large CIDRs (stdlib only).")
    parser.add_argument("cidr", nargs="+",
                        help="CIDR range(s), e.g. 192.168.1.0/24 or 10.0.0.0/8. "
                             "Repeatable and/or comma-separated.")
    parser.add_argument("-t", "--threads", type=int, default=500, help="Number of threads (default: 500)")
    parser.add_argument("-o", "--output", default=None, help="Output file for live hosts")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout per check in seconds (default: 0.8)")
    parser.add_argument("--retries", type=int, default=0,
                        help="Extra ping attempts before a host is declared dead (default 0)")
    parser.add_argument("--ports", type=str, default="80,443,22,445", help="Ports for TCP check (comma separated)")
    parser.add_argument("--method", choices=["ping", "tcp", "both"], default="both", help="Discovery method")
    parser.add_argument("--full-port-scan", action="store_true",
                        help="Report every open port from --ports on live hosts (not just the first)")
    parser.add_argument("--json", action="store_true", help="Write the output file as JSON")
    parser.add_argument("--resolve", action="store_true", help="Reverse-DNS resolve live hosts (stdlib, no extra deps)")
    parser.add_argument("--progress-interval", type=float, default=2.0,
                        help="Seconds between progress updates (0 disables)")
    parser.add_argument("--no-stream", action="store_true",
                        help="Disable the crash-safe '<output>.live' streaming log")
    args = parser.parse_args()

    if args.threads < 1:
        raise SystemExit("--threads must be >= 1")

    methods = ["ping", "tcp"] if args.method == "both" else [args.method]
    try:
        tcp_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        raise SystemExit(f"Invalid --ports value: {args.ports}")

    nets = parse_cidrs(args.cidr)
    if not nets:
        raise SystemExit("No valid CIDR ranges given.")
    total = total_hosts(nets)

    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Scanning {len(nets)} range(s) "
          f"({total:,} addresses) with {args.threads} threads")
    print(f"Methods: {methods} | TCP ports: {tcp_ports} | timeout {args.timeout}s | retries {args.retries}")

    # Crash-safe streaming log of live hosts as they are found.
    stream_fp = None
    stream_path = None
    if args.output and not args.no_stream:
        stream_path = f"{args.output}.live"
        try:
            stream_fp = open(stream_path, "w", encoding="utf-8", buffering=1)
            print(f"Live log: {stream_path} (updated as hosts are found)")
        except OSError as e:
            print(f"(could not open stream file {stream_path}: {e})")
            stream_fp = None
    print()

    live_hosts = []
    start_time = time.time()
    last_print = start_time
    scanned = 0
    interrupted = False
    interval = args.progress_interval

    # Bound the number of in-flight futures so scanning a huge range (e.g. /8)
    # does not buffer millions of pending tasks in memory at once.
    ip_gen = generate_ips(nets)
    window = max(args.threads * 2, args.threads + 1)
    executor = ThreadPoolExecutor(max_workers=args.threads)

    def submit(ip):
        return executor.submit(scan_ip, ip, methods, tcp_ports,
                               args.timeout, args.retries, args.full_port_scan)

    def show_progress(force=False):
        nonlocal last_print
        if interval <= 0 and not force:
            return
        now = time.time()
        if not force and (now - last_print) < interval:
            return
        last_print = now
        elapsed = now - start_time
        rate = scanned / elapsed if elapsed > 0 else 0
        eta = (total - scanned) / rate if rate > 0 else -1
        pct = (scanned / total * 100) if total else 0
        sys.stdout.write(
            f"\r  {pct:5.1f}%  scanned {scanned:,}/{total:,}  "
            f"alive {len(live_hosts):,}  {int(rate):,}/s  ETA {fmt_duration(eta)}        ")
        sys.stdout.flush()

    try:
        in_flight = {submit(ip): ip for ip in islice(ip_gen, window)}
        scanned += len(in_flight)

        while in_flight:
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for future in done:
                in_flight.pop(future)
                ip_str, is_live, open_p = future.result()
                if is_live:
                    live_hosts.append((ip_str, open_p))
                    if stream_fp is not None:
                        stream_fp.write(ip_str + "\n")

                next_ip = next(ip_gen, None)
                if next_ip is not None:
                    in_flight[submit(next_ip)] = next_ip
                    scanned += 1
            show_progress()
    except KeyboardInterrupt:
        interrupted = True
        sys.stdout.write("\n  Interrupted -- stopping and saving partial results...\n")
        executor.shutdown(wait=False, cancel_futures=True)
    finally:
        if not interrupted:
            executor.shutdown(wait=True)
        if stream_fp is not None:
            stream_fp.close()

    show_progress(force=True)
    elapsed = time.time() - start_time
    rate = int(scanned / elapsed) if elapsed else 0
    print(f"\n\nScan {'interrupted' if interrupted else 'completed'} in {fmt_duration(elapsed)} "
          f"({rate:,}/s).")
    print(f"Scanned: {scanned:,} | Live hosts: {len(live_hosts):,}")

    live_hosts.sort(key=lambda x: ipaddress.IPv4Address(x[0]))

    # Optional reverse-DNS enrichment of the live hosts.
    hostnames = {}
    if args.resolve and live_hosts:
        print("Resolving hostnames...")
        hostnames = resolve_hostnames([ip for ip, _ in live_hosts])

    # Show a sample of live hosts.
    for ip, ports in live_hosts[:50]:
        name = f" | host: {hostnames[ip]}" if ip in hostnames else ""
        ports_str = f" | ports: {ports}" if ports else ""
        print(f"  [+] {ip}{ports_str}{name}")
    if len(live_hosts) > 50:
        print(f"  ... and {len(live_hosts) - 50:,} more")

    if args.output and live_hosts:
        with open(args.output, "w", encoding="utf-8") as f:
            if args.json:
                json.dump(
                    [{"ip": ip, "hostname": hostnames.get(ip, ""), "open_ports": ports}
                     for ip, ports in live_hosts],
                    f, indent=2,
                )
            else:
                for ip, ports in live_hosts:
                    name = f" | host: {hostnames[ip]}" if ip in hostnames else ""
                    f.write(f"{ip} | ports: {ports}{name}\n")
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    # Increase open file limit on Linux for very high threads
    if os.name != "nt":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(10000, hard), hard))
        except Exception:
            pass
    main()
