import argparse
import ipaddress
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import os
from datetime import datetime

# For maximum speed on large ranges, consider using masscan/zmap externally.
# This script maximizes Python resources with high concurrency + low timeouts.

def is_alive_ping(ip, timeout=1):
    """Fast ICMP ping using subprocess (cross-platform)."""
    try:
        # -c 1 on Linux, -n 1 on Windows
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', '-w', str(int(timeout*1000)), str(ip)]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=timeout+1)
        return True
    except:
        return False


def is_alive_tcp(ip, port=80, timeout=0.8):
    """TCP connect check (SYN/ACK) - useful when ICMP is blocked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except:
        sock.close()
        return False


def scan_ip(ip, methods=['ping', 'tcp'], ports=[80, 443]):
    """Scan a single IP with multiple methods."""
    alive = False
    open_ports = []
    
    if 'ping' in methods:
        if is_alive_ping(ip):
            alive = True
    
    if not alive and 'tcp' in methods:
        for p in ports:
            if is_alive_tcp(ip, p):
                alive = True
                open_ports.append(p)
                break  # One success is enough for host discovery
    
    if alive:
        # Optional: deeper port scan on live hosts only
        return str(ip), True, open_ports
    return str(ip), False, []


def generate_ips(cidr):
    """Generator for large CIDRs to avoid memory explosion."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():  # skips network/broadcast
            yield ip
    except ValueError as e:
        print(f"Invalid CIDR: {e}")
        return


def main():
    parser = argparse.ArgumentParser(description="High-performance multi-threaded IP Scanner for large CIDRs")
    parser.add_argument("cidr", help="CIDR range to scan, e.g. 192.168.1.0/24 or 10.0.0.0/8")
    parser.add_argument("-t", "--threads", type=int, default=500, help="Number of threads (default: 500)")
    parser.add_argument("-o", "--output", default=None, help="Output file for live hosts")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout per check (seconds)")
    parser.add_argument("--ports", type=str, default="80,443,22,445", help="Ports for TCP check (comma separated)")
    parser.add_argument("--method", choices=['ping', 'tcp', 'both'], default='both', help="Discovery method")
    parser.add_argument("--full-port-scan", action="store_true", help="Do full port scan on live hosts (slower)")
    args = parser.parse_args()

    methods = ['ping', 'tcp'] if args.method == 'both' else [args.method]
    tcp_ports = [int(p.strip()) for p in args.ports.split(',')]

    print(f"[{datetime.now()}] Starting scan of {args.cidr} with {args.threads} threads...")
    print(f"Methods: {methods} | TCP Ports: {tcp_ports}")

    live_hosts = []
    start_time = time.time()
    scanned = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        
        for ip in generate_ips(args.cidr):
            future = executor.submit(scan_ip, ip, methods, tcp_ports)
            futures[future] = ip
            scanned += 1
            
            # Progress every 10k
            if scanned % 10000 == 0:
                print(f"Queued {scanned} IPs...")

        for future in as_completed(futures):
            ip_str, is_live, open_p = future.result()
            if is_live:
                live_hosts.append((ip_str, open_p))
                print(f"[+] LIVE: {ip_str} | Open ports: {open_p}")

    elapsed = time.time() - start_time
    print(f"\nScan completed in {elapsed:.2f} seconds.")
    print(f"Scanned: {scanned} | Live hosts: {len(live_hosts)}")

    if args.output and live_hosts:
        with open(args.output, 'w') as f:
            for ip, ports in live_hosts:
                f.write(f"{ip} | ports: {ports}\n")
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    # Increase open file limit on Linux for very high threads
    if os.name != 'nt':
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(10000, hard), hard))
        except:
            pass
    main()