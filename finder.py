import csv
import ipaddress
import platform
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple

import psutil

# Scapy is used for the LAN scan
from scapy.all import ARP, Ether, srp, conf


@dataclass
class InterfaceNetwork:
    name: str
    ip: str
    netmask: str
    network: ipaddress.IPv4Network


def get_local_networks() -> List[InterfaceNetwork]:
    """
    Detect all non-loopback IPv4 interfaces and derive their networks.
    If netmask is missing or invalid, fall back to /24.
    """
    nets: List[InterfaceNetwork] = []
    for if_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name != "AF_INET":
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

            nets.append(InterfaceNetwork(
                name=if_name,
                ip=ip,
                netmask=netmask,
                network=network
            ))
    return nets


def arp_scan(network: ipaddress.IPv4Network, iface_name: Optional[str] = None, timeout: int = 2):
    """
    Scan a subnet using ARP and return a list of (ip, mac).
    """
    print(f"\nScanning {network} on interface: {iface_name or 'default'}")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(
        pkt,
        timeout=timeout,
        verbose=False,
        iface=iface_name
    )

    results = []
    for _, reply in answered:
        results.append((reply.psrc, reply.hwsrc))
    return results


def save_csv(devices: List[Tuple[str, str]], filename: str = "devices.csv"):
    """
    Save results using semicolon separators.
    """
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["IP Address", "MAC Address"])
        for ip, mac in devices:
            writer.writerow([ip, mac])


def main():
    print(f"Running on: {platform.system()} {platform.release()}")

    networks = get_local_networks()
    if not networks:
        print("No local IPv4 network interfaces were found.")
        return

    print("\nDetected local networks:")
    for n in networks:
        print(f"  - {n.name}: {n.ip} / {n.netmask} -> {n.network}")

    all_devices: Set[Tuple[str, str]] = set()

    for n in networks:
        try:
            found = arp_scan(n.network, iface_name=n.name)
            for item in found:
                all_devices.add(item)
        except Exception as e:
            print(f"Scan failed on {n.name} ({n.network}): {e}")

    if not all_devices:
        print("\nNo devices found.")
        return

    print("\nDevices found:")
    for ip, mac in sorted(all_devices, key=lambda x: tuple(int(p) if p.isdigit() else p for p in x[0].replace(".", " ").split())):
        print(f"  {ip:<15}  {mac}")

    save_csv(sorted(all_devices), "devices.csv")
    print("\nSaved to devices.csv")


if __name__ == "__main__":
    main()