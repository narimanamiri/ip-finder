# ip-finder

A toolkit of network-device discovery scanners for LAN/WAN — from cross-platform
aggregators to a **pcap-free** high-performance ICMP sweeper that can scan an
entire Class-A range (millions of hosts) on Windows without Npcap.

> ⚠️ **Authorized use only.** Scan only networks you own or are explicitly
> permitted to scan.

---

## Which tool should I use?

| I want to… | Use | Needs pcap/Npcap? | Platform |
|---|---|---|---|
| **Sweep a huge range fast** (e.g. `10.0.0.0/8`, 1M+ hosts) on Windows | **`scannet-fast.py`** | ❌ No (uses `icmp.dll`) | Windows |
| Sweep a huge range, portably / on Linux/macOS | **`scannet-fastV2.py`** | ❌ No (stdlib only) | All |
| Get MAC + vendor for everything on my LAN | `finder.py` / `scan-devices.py` | ⚠️ Optional (ARP path) | All |
| Discover quietly, sending **no** packets | `passive-finder.py` | ✅ Yes | All |
| A point-and-click app | `lan_multitool_gui.py` | ⚠️ Optional | All |
| Just map a MAC → vendor offline | `oui_lookup.py` | ❌ No | All |

> **pcap note:** the tools marked "needs pcap" use Scapy, which loads the
> Npcap/WinPcap (Windows) or libpcap (Linux/macOS) driver. **If your pcap driver
> is missing or unstable, stick to the pcap-free tools** (`scannet-fast`,
> `scannet-fastV2`, `oui_lookup`) — they never touch it. See
> [Troubleshooting](#troubleshooting).

---

## Quick start

```bash
pip install -r requirements.txt          # psutil + scapy (or skip for stdlib-only tools)

# Portable, no dependencies, scan a /24:
python scannet-fastV2.py 192.168.1.0/24 --method both -o live.txt

# Windows, pcap-free, scan a whole air-gapped Class-A with progress + ETA:
python scannet-fast.py --cidr 10.0.0.0/8 --workers 2048 --timeout-ms 200 --out devices.csv

# Aggressive LAN inventory with MAC/vendor/hostname:
python finder.py --out devices.csv
```

---

## Scanning very large networks (Class A / 1M+ hosts)

Designed for exactly this: a big, flat, **air-gapped** network that uses Class-A
addressing (e.g. someone assigned `10.x.x.x` to avoid IP conflicts). Both
fast scanners **stream** the address range through a bounded queue, so memory
stays flat whether you scan 254 or 16,777,214 addresses.

**On Windows → `scannet-fast.py`** (native `icmp.dll`, no Npcap, fastest):

```bash
# Whole 10.0.0.0/8, 2048 workers, 200 ms timeout, +1 retry for reliability
python scannet-fast.py --cidr 10.0.0.0/8 --workers 2048 --timeout-ms 200 --retries 1 --out devices.csv

# Just a few subnets
python scannet-fast.py --cidr 10.1.0.0/16,10.2.0.0/16 --out hosts.json --json
```

**On Linux/macOS → `scannet-fastV2.py`** (pure stdlib):

```bash
python scannet-fastV2.py 10.0.0.0/8 -t 1000 --method ping --timeout 0.3 -o live.txt
```

Both print a live progress line and keep a **crash-safe** `<out>.live` log that
is updated the instant each host is found — so a multi-hour sweep that is
interrupted (or `Ctrl-C`-ed) keeps everything discovered so far.

```
  34.7%  scanned 5,826,400/16,777,214  alive 1,204  41,300/s  ETA 4m26s
```

### Tuning throughput

For a mostly-empty range, **dead addresses dominate** the time (each costs one
timeout). Rough worst-case rate ≈ `workers ÷ timeout`:

| workers | timeout | ≈ rate | `/8` (16.7M) all-dead |
|--:|--:|--:|--:|
| 1024 | 400 ms | ~2,500/s | ~1.8 h |
| 2048 | 200 ms | ~10,000/s | ~28 min |
| 2048 | 100 ms | ~20,000/s | ~14 min |

Guidance for a quiet air-gapped LAN (hosts reply in <10 ms):

- **`--timeout-ms 100–300`** is plenty; lower = faster but may miss a sluggish host.
- **`--workers 1024–2048`** is the sweet spot on Windows. Going much higher costs
  RAM (≈1 MB of stack per thread) for little gain.
- **`--retries 1`** recovers hosts that dropped a single packet, at ~2× the
  dead-host cost. Use it for the authoritative inventory pass.

See [docs/LARGE-NETWORKS.md](docs/LARGE-NETWORKS.md) for a deeper guide.

---

## Tool reference

### `scannet-fast.py` — Windows ICMP sweeper (pcap-free, millions of hosts)
Native `IcmpSendEcho` via `icmp.dll`; per-thread handles/buffers; streaming;
progress/ETA; retries; ARP MAC + vendor + reverse-DNS enrichment of live hosts.

| flag | meaning |
|---|---|
| `--cidr` | target CIDR(s); repeatable and/or comma-separated; omit to auto-detect |
| `--workers` | worker threads (default 1024) |
| `--timeout-ms` | ICMP timeout per host (default 400) |
| `--retries` | extra attempts before "dead" (default 0) |
| `--no-dns` / `--dns-workers` | disable / size reverse DNS |
| `--out` `--json` `--text` | output file and format (CSV default) |
| `--no-stream` | disable the `<out>.live` crash-safe log |
| `--progress-interval` | seconds between progress updates (0 = off) |

### `scannet-fastV2.py` — portable sweeper (stdlib only)
Cross-platform ping/TCP discovery with a bounded in-flight window. Same
progress/streaming/retries; TCP helps when ICMP is firewalled.

| flag | meaning |
|---|---|
| `cidr` | one or more CIDRs (positional; comma-separated ok) |
| `-t/--threads` | threads (default 500) |
| `--method` | `ping`, `tcp`, or `both` |
| `--ports` | TCP ports to probe (e.g. `80,443,22,445`) |
| `--full-port-scan` | report *every* open port from `--ports`, not just the first |
| `--timeout` `--retries` | per-check timeout (s) and extra ping attempts |
| `-o/--output` `--json` | output file and JSON toggle |
| `--resolve` | reverse-DNS resolve live hosts |
| `--no-stream` `--progress-interval` | as above |

### `finder.py` — aggressive cross-platform aggregator
ARP cache + Scapy ARP + nmap + fping + arp-scan + nbtscan + ping sweep, merged
with reverse DNS → `devices.csv`. `--private` adds bounded RFC-1918 probing.
`--no-scapy` skips the pcap path.

### `scan-devices.py` — multi-method discovery with a host budget
Like `finder.py` but caps total hosts with `--max-hosts`. ARP / nmap / ping per
network. `--no-arp` skips the pcap path.

### `passive-finder.py` — passive direct-link listener
Sniffs ARP/DHCP/IPv4 and reports new/changed hosts **without sending packets**.
Needs Scapy + pcap + admin/root. `--iface` selects the interface.

### `lan_multitool_gui.py` — GUI front-end
Active ARP/ping scan, optional passive monitor, TCP port probe, vendor column,
CSV/JSON export, and a continuous-monitor mode that logs NEW/GONE hosts.

### `oui_lookup.py` — offline MAC → vendor
No network access. Importable module and a CLI:
```bash
python oui_lookup.py 3c:5a:b4:11:22:33 b8:27:eb:aa:bb:cc 00:15:5d:01:02:03
#   3c:5a:b4:11:22:33    -> Google
#   b8:27:eb:aa:bb:cc    -> Raspberry Pi
#   00:15:5d:01:02:03    -> Microsoft (Hyper-V)
```

---

## Output formats
- **CSV** — semicolon-separated: IP, MAC, Vendor, Hostname, Sources.
- **JSON** — machine-readable; the GUI/`scannet-fast` JSON includes per-host
  `open_ports`, `vendor`, timestamps and an `alive` flag where applicable.
- **`.live`** — a plain one-IP-per-line log written live during big sweeps
  (crash safety). Disable with `--no-stream`.

---

## Requirements
- Python 3.8+
- `psutil` — interface enumeration (`finder`, `scan-devices`, `scannet-fast`, GUI).
- `scapy` — required by `passive-finder`; optional ARP path elsewhere.
- `scannet-fastV2.py` and `oui_lookup.py` use **only the standard library**.
- The GUI needs Tkinter (bundled with most CPython installs).
- Optional external tools used automatically when on `PATH`: `nmap`, `fping`,
  `arp-scan`, `nbtscan`.

```bash
pip install -r requirements.txt   # psutil + scapy
```

Passive sniffing and raw ARP scanning need Administrator (Windows) or root.

---

## Building standalone executables
Single-file binaries (no Python needed on the target) via [PyInstaller]:

```bash
pip install -r requirements.txt pyinstaller

.\build.ps1        # Windows  -> dist\windows\*.exe
./build.sh         # Linux/macOS -> dist/linux|macos/*
```

`scannet-fast` is Windows-only (uses `icmp.dll`) and is produced only by
`build.ps1`. The GUI is built as a windowed (no-console) app on Windows. Push a
`v*` tag (or run the **Build executables** workflow) to build all three OSes in
CI — see [`.github/workflows/build.yml`](.github/workflows/build.yml).

[PyInstaller]: https://pyinstaller.org/

---

## Troubleshooting

**Scapy prints "pcap service not running" / ARP scan finds nothing.**
You need Npcap (Windows) or libpcap (Linux/macOS) plus admin/root. The tools
fall back to the ping sweep automatically; pass `--no-scapy` / `--no-arp` to
silence it.

**A broken/unstable pcap driver crashes the machine.**
Do **not** run the Scapy-based tools (`finder`, `scan-devices`,
`passive-finder`, the GUI's active/passive scapy paths). Use the **pcap-free**
tools instead — `scannet-fast` (Windows), `scannet-fastV2` (any OS) and
`oui_lookup` never load pcap.

**The scan finds nothing on an air-gapped network.**
ICMP may be filtered. Try `scannet-fastV2 --method tcp --ports 80,443,445`, or
add `--retries 1`. Confirm the range with `--cidr`/positional arg.

**It's slow on a `/8`.** See [Tuning throughput](#tuning-throughput): raise
`--workers`, lower `--timeout-ms`. For truly massive internet-scale scans,
external tools like `masscan`/`zmap` are faster.
