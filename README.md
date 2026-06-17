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
- **`oui_lookup.py`** — shared, offline MAC-vendor (OUI) lookup module. Maps a
  MAC's first 24 bits to a likely hardware vendor from a built-in table. No
  network access; importable by the other scripts and runnable on its own.

## Features
- **MAC-vendor (OUI) lookup** — every CSV-producing scanner and the GUI now show
  a **Vendor** column resolved offline from `oui_lookup.py`. Randomized
  (locally administered) MACs are flagged as `(random MAC)`.
- **Reverse-DNS hostname resolution** — already in the aggregators and the GUI;
  now also available in the portable `scannet-fastV2.py` via `--resolve`.
- **TCP port probe (GUI)** — optionally probe a configurable set of common
  service ports on every discovered host and show the open ones.
- **CSV & JSON export (GUI)** — export the live device table to either format.
- **Continuous-monitor mode (GUI)** — when enabled, each auto-scan is diffed
  against the previous one and **NEW** / **GONE** hosts are written to an
  on-screen event log.

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
# Aggressive multi-method discovery -> devices.csv (now includes a Vendor column)
python finder.py --out devices.csv

# Multi-method discovery with a bounded total-host cap
python scan-devices.py --max-hosts 8192 --out devices.csv

# Portable high-concurrency ping/TCP sweep; --json for machine-readable output
python scannet-fastV2.py 192.168.1.0/24 --method both -o live.txt
python scannet-fastV2.py 10.0.0.0/8 --method tcp --ports 80,443 -o live.json --json

# Same sweep, but also reverse-DNS resolve every live host (stdlib only)
python scannet-fastV2.py 192.168.1.0/24 --resolve -o live.txt

# Fast Windows-only ICMP sweep via icmp.dll
python scannet-fast.py --cidr 10.0.0.0/16          # Windows only

# Passive direct-link listener (run as admin/root)
sudo python passive-finder.py --iface eth0

# GUI front-end
python lan_multitool_gui.py

# Offline MAC -> vendor lookup on the command line
python oui_lookup.py 3c:5a:b4:11:22:33 b8:27:eb:aa:bb:cc 00:15:5d:01:02:03
#   3c:5a:b4:11:22:33    -> Google
#   b8:27:eb:aa:bb:cc    -> Raspberry Pi
#   00:15:5d:01:02:03    -> Microsoft (Hyper-V)
```

### Using the new GUI features
1. **Vendor column** — populated automatically from the MAC address (offline).
2. **TCP port probe** — tick **"TCP port probe"**, optionally edit the **Ports**
   box (comma list and `start-end` ranges are accepted, e.g. `22,80,443,8000-8010`),
   then **Scan Now**. Open ports appear in the **Open Ports** column.
3. **Export** — click **Export CSV** or **Export JSON** to save the current
   table. JSON includes per-host `open_ports`, `vendor`, `first_seen`/`last_seen`
   timestamps and an `alive` flag.
4. **Monitor mode** — tick **"Monitor mode"** and leave **Auto scan** on. The
   first scan sets a baseline; subsequent scans log `NEW` and `GONE` hosts to the
   **Monitor events** panel at the bottom.

> Use only on networks you are authorized to scan.
