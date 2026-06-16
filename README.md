# ip-finder

A toolkit of network-device discovery scanners for LAN/WAN, ranging from
cross-platform aggregators to a high-performance Windows ICMP sweeper.

## Scripts
- **`finder.py`** — aggressive cross-platform discovery: combines ARP cache,
  Scapy ARP scan, nmap, fping, arp-scan, nbtscan and a ping sweep, then resolves
  reverse DNS. Exports `devices.csv`.
- **`scan-devices.py`** — similar multi-method discovery with bounded subnet
  selection.
- **`scannet-fast.py`** — Windows-only, very fast ICMP sweep via `icmp.dll`
  (`IcmpSendEcho`) with a worker-thread pool; validates reply status to avoid
  false positives.
- **`scannet-fastV2.py`** — portable high-concurrency ping/TCP scanner with a
  bounded in-flight window (safe even for `/8` ranges).
- **`passive-finder.py`** — passive discovery: sniffs ARP/DHCP/IPv4 with Scapy
  and reports newly seen hosts on the directly attached link.
- **`lan_multitool_gui.py`** — a GUI front-end tying the tools together.

## Requirements
- Python 3.x
- `psutil`, `scapy` (optional but recommended); some scripts use external tools
  (`nmap`, `fping`, `arp-scan`, `nbtscan`) when available.

## Usage
```bash
python finder.py --out devices.csv
python scannet-fastV2.py 192.168.1.0/24 --method both -o live.txt
python scannet-fast.py --cidr 10.0.0.0/16          # Windows only
sudo python passive-finder.py --iface eth0
```

> Use only on networks you are authorized to scan.
