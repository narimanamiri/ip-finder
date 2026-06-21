#!/usr/bin/env python3
"""
passive-finder.py -- passive (zero-probe) direct-link device discovery.

Sniffs the directly attached network with Scapy and reports hosts as they
reveal themselves through ARP, DHCP and IPv4 traffic -- without sending a single
packet. Useful when active scanning is undesirable (quiet/forensic discovery)
or when ICMP is firewalled. New or changed (MAC, IP, protocol) hosts are printed
as events; the local interface's own MAC/IP are filtered out.

Requires Scapy and a working pcap stack (Npcap on Windows, libpcap on
Linux/macOS) plus Administrator/root privileges. Pick the interface with
``--iface``.

Usage:
    sudo python passive-finder.py --iface eth0
    python passive-finder.py --iface Ethernet --timeout 60
"""
import argparse
import queue
import time
import threading
from dataclasses import dataclass
from typing import Dict, Set, Tuple

from scapy.all import ARP, DHCP, Ether, IP, conf, get_if_addr, get_if_hwaddr, sniff


@dataclass
class DeviceSeen:
    mac: str
    ip: str = ""
    proto: str = ""
    last_seen: float = 0.0


devices: Dict[str, DeviceSeen] = {}
devices_lock = threading.Lock()
event_q: "queue.Queue[str]" = queue.Queue()

LOCAL_MAC = ""
LOCAL_IP = ""


def now():
    return time.strftime("%H:%M:%S")


def normalize_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def is_local(mac: str = "", ip: str = "") -> bool:
    mac = normalize_mac(mac) if mac else ""
    return (mac and mac == LOCAL_MAC) or (ip and ip == LOCAL_IP)


def emit_change(mac: str, ip: str = "", proto: str = ""):
    mac = normalize_mac(mac)

    if is_local(mac, ip):
        return

    with devices_lock:
        old = devices.get(mac)
        changed = (
            old is None
            or (ip and ip != old.ip)
            or (proto and proto != old.proto)
        )

        if old is None:
            devices[mac] = DeviceSeen(mac=mac, ip=ip, proto=proto, last_seen=time.time())
        else:
            if ip:
                old.ip = ip
            if proto:
                old.proto = proto
            old.last_seen = time.time()

    if changed:
        event_q.put(f"[{now()}] NEW/CHANGED  MAC={mac:<17} IP={ip:<15} PROTO={proto}")


def handle_arp(pkt):
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    mac = normalize_mac(arp.hwsrc or pkt[Ether].src)
    ip = arp.psrc or ""
    if is_local(mac, ip):
        return
    proto = "ARP Probe" if ip == "0.0.0.0" else "ARP"
    emit_change(mac, ip, proto)


def handle_dhcp(pkt):
    if not pkt.haslayer(DHCP):
        return

    mac = normalize_mac(pkt[Ether].src)
    if is_local(mac):
        return

    requested_ip = ""
    msg_type = "DHCP"

    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple):
            if opt[0] == "requested_addr":
                requested_ip = opt[1]
            elif opt[0] == "message-type":
                msg_type = f"DHCP {opt[1]}"

    emit_change(mac, requested_ip, msg_type)


def handle_ip(pkt):
    if not pkt.haslayer(IP):
        return

    mac = normalize_mac(pkt[Ether].src)
    ip = pkt[IP].src

    if is_local(mac, ip):
        return

    emit_change(mac, ip, "IPv4")


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


def printer():
    while True:
        print(event_q.get(), flush=True)
        event_q.task_done()


def main():
    parser = argparse.ArgumentParser(description="Passive direct-link IP discovery")
    parser.add_argument("--iface", required=True, help="Network interface name")
    parser.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0 = forever)")
    args = parser.parse_args()

    global LOCAL_MAC, LOCAL_IP
    LOCAL_MAC = normalize_mac(get_if_hwaddr(args.iface))
    LOCAL_IP = get_if_addr(args.iface)

    print(f"Interface : {args.iface}")
    print(f"Local MAC : {LOCAL_MAC}")
    print(f"Local IP  : {LOCAL_IP}")
    print("Mode      : PASSIVE")
    print("Watching for remote changes...\n")

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


if __name__ == "__main__":
    main()