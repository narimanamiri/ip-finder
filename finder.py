import csv
import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

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
class InterfaceNetwork:
    name: str
    ip: str
    netmask: str
    network: ipaddress.IPv4Network


def get_local_networks() -> List[InterfaceNetwork]:
    nets: List[InterfaceNetwork] = []
    seen: Set[Tuple[str, str]] = set()

    for if_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue

            ip = addr.address
            if ip.startswith("127."):
                continue

            netmask = addr.netmask or "255.255.255.0"
            try:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            except Exception:
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                netmask = "255.255.255.0"

            key = (if_name, str(network))
            if key in seen:
                continue
            seen.add(key)

            nets.append(InterfaceNetwork(
                name=if_name,
                ip=ip,
                netmask=netmask,
                network=network
            ))

    return nets


def run_cmd(cmd: List[str], timeout: int = 8) -> Tuple[int, str]:
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=creationflags
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return proc.returncode, out.strip()
    except Exception as e:
        return 1, str(e)


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


def ping_sweep(network: ipaddress.IPv4Network, workers: int = 128) -> List[str]:
    hosts = [str(ip) for ip in network.hosts()]
    live: List[str] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(ping_one, ip): ip for ip in hosts}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    live.append(ip)
            except Exception:
                pass

    return sorted(live, key=lambda x: ipaddress.IPv4Address(x))


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


def parse_arp_table() -> Dict[str, str]:
    system = platform.system().lower()
    out: Dict[str, str] = {}

    if system == "windows":
        code, text = run_cmd(["arp", "-a"], timeout=5)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0][0].isdigit():
                ip = parts[0]
                mac = parts[1].replace("-", ":").lower()
                out[ip] = mac
    else:
        code, text = run_cmd(["arp", "-a"], timeout=5)
        for line in text.splitlines():
            line = line.strip()
            if "(" in line and ")" in line and " at " in line:
                try:
                    ip = line.split("(")[1].split(")")[0]
                    mac = line.split(" at ")[1].split()[0].lower()
                    if ":" in mac:
                        out[ip] = mac
                except Exception:
                    pass

        code, text = run_cmd(["ip", "neigh"], timeout=5)
        if code == 0:
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    try:
                        ip = parts[0]
                        mac = parts[parts.index("lladdr") + 1].lower()
                        out[ip] = mac
                    except Exception:
                        pass

    return out


def optional_nmap_discovery(network: ipaddress.IPv4Network) -> Dict[str, str]:
    code, _ = run_cmd(["nmap", "-V"], timeout=3)
    if code != 0:
        return {}

    code, text = run_cmd(["nmap", "-sn", str(network)], timeout=120)
    if code != 0:
        return {}

    results: Dict[str, str] = {}
    current_ip = None

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for "):
            tail = line[len("Nmap scan report for "):].strip()
            if tail.endswith(")") and "(" in tail:
                current_ip = tail.split("(")[-1].rstrip(")")
            else:
                current_ip = tail
        elif line.lower().startswith("mac address:") and current_ip:
            mac = line.split(":", 1)[1].split()[0].lower()
            results[current_ip] = mac

    return results


def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


def merge_device(devices: Dict[str, Device], ip: str, mac: str = "", hostname: str = "", source: str = "") -> None:
    existing = devices.get(ip)
    if existing is None:
        devices[ip] = Device(ip=ip, mac=mac, hostname=hostname, source=source)
        return

    devices[ip] = Device(
        ip=ip,
        mac=mac or existing.mac,
        hostname=hostname or existing.hostname,
        source=";".join(sorted(set(filter(None, [existing.source, source]))))
    )


def discover_devices() -> List[Device]:
    interfaces = get_local_networks()
    devices: Dict[str, Device] = {}

    for ip, mac in parse_arp_table().items():
        merge_device(devices, ip, mac=mac, source="arp_cache")

    for iface in interfaces:
        print(f"Scanning {iface.name}: {iface.network}")

        arp_found = arp_scan(iface.network, iface_name=iface.name)
        for ip, mac in arp_found.items():
            merge_device(devices, ip, mac=mac, source=f"arp_scan:{iface.name}")

        nmap_found = optional_nmap_discovery(iface.network)
        for ip, mac in nmap_found.items():
            merge_device(devices, ip, mac=mac, source=f"nmap:{iface.name}")

        ping_found = ping_sweep(iface.network, workers=128)
        for ip in ping_found:
            merge_device(devices, ip, source=f"ping:{iface.name}")

    ips = list(devices.keys())
    with ThreadPoolExecutor(max_workers=64) as pool:
        futs = {pool.submit(resolve_hostname, ip): ip for ip in ips}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                hostname = fut.result()
                if hostname:
                    d = devices[ip]
                    devices[ip] = Device(ip=d.ip, mac=d.mac, hostname=hostname, source=d.source)
            except Exception:
                pass

    return sorted(devices.values(), key=lambda d: ipaddress.IPv4Address(d.ip))


def save_csv(devices: List[Device], filename: str = "devices.csv") -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["IP Address", "MAC Address", "Hostname", "Source"])
        for d in devices:
            writer.writerow([d.ip, d.mac, d.hostname, d.source])


def main():
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Scapy available: {SCAPY_AVAILABLE}")

    interfaces = get_local_networks()
    if not interfaces:
        print("No local IPv4 interfaces found.")
        return

    print("\nDetected interfaces:")
    for i in interfaces:
        print(f"  {i.name}: {i.ip}/{i.netmask} -> {i.network}")

    devices = discover_devices()

    if not devices:
        print("\nNo devices found.")
        return

    print("\nDevices found:")
    for d in devices:
        host = f"  {d.hostname}" if d.hostname else ""
        print(f"  {d.ip:<15}  {d.mac:<18} {host}")

    save_csv(devices, "devices.csv")
    print("\nSaved results to devices.csv")


if __name__ == "__main__":
    main()