import argparse
import ipaddress
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    Ether,
    IP,
    sniff,
    conf,
    get_if_list,
)

# =========================================================
# Passive Direct-Link Device Discovery
#
# PURPOSE:
# - Find unknown device IPs on a direct Ethernet cable
# - NO subnet sweep
# - NO /8 scan
# - Passive listening only
#
# FEATURES:
# - Detects:
#     * Gratuitous ARP
#     * ARP probes
#     * DHCP discover/request
#     * Any IPv4 traffic
# - Thread-safe
# - Very low CPU
# - Works instantly when device speaks
#
# REQUIREMENTS:
# pip install scapy
#
# RUN AS ADMINISTRATOR
#
# EXAMPLE:
# python passive_listener.py --iface "Ethernet"
#
# =========================================================


@dataclass
class DeviceSeen:
    mac: str
    ip: str = ""
    hostname: str = ""
    protocol: str = ""
    last_seen: float = 0.0


devices: Dict[str, DeviceSeen] = {}
devices_lock = threading.Lock()

event_q: "queue.Queue[str]" = queue.Queue()


def now():
    return time.strftime("%H:%M:%S")


def normalize_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def save_device(mac: str, ip: str = "", proto: str = ""):
    mac = normalize_mac(mac)

    with devices_lock:
        existing = devices.get(mac)

        if existing:
            if ip:
                existing.ip = ip
            if proto:
                existing.protocol = proto
            existing.last_seen = time.time()
        else:
            devices[mac] = DeviceSeen(
                mac=mac,
                ip=ip,
                protocol=proto,
                last_seen=time.time(),
            )

    msg = f"[{now()}] MAC={mac:<17} IP={ip:<15} PROTO={proto}"
    event_q.put(msg)


# =========================================================
# Packet handlers
# =========================================================
def handle_arp(pkt):
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]

    mac = arp.hwsrc
    ip = arp.psrc

    if ip == "0.0.0.0":
        proto = "ARP Probe"
    else:
        proto = "ARP"

    save_device(mac, ip, proto)


def handle_dhcp(pkt):
    if not pkt.haslayer(DHCP):
        return

    mac = pkt[Ether].src

    requested_ip = ""

    options = pkt[DHCP].options

    for opt in options:
        if isinstance(opt, tuple):
            if opt[0] == "requested_addr":
                requested_ip = opt[1]

    proto = "DHCP"

    save_device(mac, requested_ip, proto)


def handle_ip(pkt):
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP].src

    if ip.startswith("127."):
        return

    mac = pkt[Ether].src

    save_device(mac, ip, "IPv4")


def packet_handler(pkt):
    try:
        if pkt.haslayer(ARP):
            handle_arp(pkt)

        elif pkt.haslayer(DHCP):
            handle_dhcp(pkt)

        elif pkt.haslayer(IP):
            handle_ip(pkt)

    except Exception:
        pass


# =========================================================
# Printer thread
# =========================================================
def printer():
    while True:
        msg = event_q.get()
        print(msg, flush=True)
        event_q.task_done()


# =========================================================
# Summary display
# =========================================================
def print_summary():
    print("\n================ DEVICES =================")

    with devices_lock:
        for d in devices.values():
            print(
                f"MAC={d.mac:<17} "
                f"IP={d.ip:<15} "
                f"PROTO={d.protocol}"
            )

    print("==========================================\n")


# =========================================================
# Main
# =========================================================
def main():
    parser = argparse.ArgumentParser(
        description="Passive direct-link IP discovery"
    )

    parser.add_argument(
        "--iface",
        required=True,
        help="Network interface name",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Stop after N seconds (0 = forever)",
    )

    args = parser.parse_args()

    print("\nAvailable interfaces:\n")

    for i in get_if_list():
        print(" ", i)

    print("\n=================================================")
    print(" PASSIVE DEVICE DISCOVERY")
    print("=================================================")
    print(f"Interface : {args.iface}")
    print("Mode      : PASSIVE")
    print("Scanning  : DISABLED")
    print("Waiting for device traffic...")
    print("Power-cycle the target device now.")
    print("=================================================\n")

    t = threading.Thread(target=printer, daemon=True)
    t.start()

    conf.sniff_promisc = True

    sniff(
        iface=args.iface,
        prn=packet_handler,
        store=False,
        filter="arp or udp port 67 or udp port 68 or ip",
        timeout=args.timeout if args.timeout > 0 else None,
    )

    print_summary()


if __name__ == "__main__":
    main()