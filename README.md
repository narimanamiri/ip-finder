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
- Python 3.8+
- `psutil` — used by `finder.py`, `scan-devices.py`, `scannet-fast.py` and the GUI
  to enumerate local interfaces.
- `scapy` — **required** by `passive-finder.py`; optional (but recommended) for the
  ARP-scan path in `finder.py`, `scan-devices.py` and `lan_multitool_gui.py`.
- `scannet-fastV2.py` uses only the standard library (no third-party deps).
- `lan_multitool_gui.py` needs Tkinter (bundled with most CPython installs).
- Optional external tools, used automatically when on `PATH`: `nmap`, `fping`,
  `arp-scan`, `nbtscan`.

Install the Python deps with:
```bash
pip install psutil scapy
```

Passive sniffing and raw ARP scanning require Administrator (Windows) or root
(Linux/macOS) privileges.

## Usage
```bash
# Aggressive multi-method discovery -> devices.csv
python finder.py --out devices.csv

# Multi-method discovery with a bounded total-host cap
python scan-devices.py --max-hosts 8192 --out devices.csv

# Portable high-concurrency ping/TCP sweep; --json for machine-readable output
python scannet-fastV2.py 192.168.1.0/24 --method both -o live.txt
python scannet-fastV2.py 10.0.0.0/8 --method tcp --ports 80,443 -o live.json --json

# Fast Windows-only ICMP sweep via icmp.dll
python scannet-fast.py --cidr 10.0.0.0/16          # Windows only

# Passive direct-link listener (run as admin/root)
sudo python passive-finder.py --iface eth0

# GUI front-end
python lan_multitool_gui.py
```

> Use only on networks you are authorized to scan.
