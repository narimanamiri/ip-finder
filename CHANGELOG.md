# Changelog

All notable changes to this toolkit.

## Unreleased

### Added
- **`scannet-fast.py` rewritten for million-host sweeps** (Windows, pcap-free):
  live progress with rate/ETA, crash-safe `<out>.live` streaming log, optional
  ICMP `--retries`, multiple/`,`-separated `--cidr` targets, graceful `Ctrl-C`
  (keeps partial results), CSV/JSON/text output, and per-thread ICMP handles +
  reply buffers on the hot path.
- **`scannet-fastV2.py` enhanced**: progress with percent/rate/ETA, crash-safe
  streaming, ping `--retries`, multiple/`,`-separated CIDRs, graceful `Ctrl-C`,
  and an implemented `--full-port-scan` (reports every open port, not just the
  first).
- `requirements.txt`, `build.ps1`, `build.sh`, and a GitHub Actions workflow
  (`.github/workflows/build.yml`) that builds Windows/Linux/macOS binaries.
- Module docstrings and an expanded README, plus
  [`docs/LARGE-NETWORKS.md`](docs/LARGE-NETWORKS.md).

### Fixed
- **Cross-platform ping was broken on Linux/macOS** in `scannet-fastV2.py`: it
  passed `-w` everywhere, but on Linux `-w` is a *total deadline* (it was asking
  for an 800-second deadline per host). Now uses the correct per-platform flag
  (`-w` ms on Windows, `-W` ms on macOS, `-W` s on Linux).
- **`scannet-fastV2.py --timeout` was ignored** — the value was parsed but never
  passed to the ping/TCP checks. It is now applied.
- `scannet-fast.py` no longer crashes with an `AttributeError` at import on
  non-Windows; it fails fast with a clear "Windows-only" message.
- `ping` no longer flashes a console window on Windows (uses `CREATE_NO_WINDOW`).
- Scapy's noisy import-time pcap-service warnings are suppressed in `finder.py`,
  `scan-devices.py` and the GUI (logger + scoped stderr redirect).
- GUI: the device table is rebuilt once per update batch instead of once per
  device message (was O(n²) per scan).
- Removed unused imports (`os`, `Iterable`, `BOOTP`).

### Notes
- The Scapy-based tools (`finder`, `scan-devices`, `passive-finder`, the GUI's
  scapy paths) load the pcap driver (Npcap/libpcap). The **pcap-free** tools
  (`scannet-fast`, `scannet-fastV2`, `oui_lookup`) never do — use them on hosts
  where the pcap driver is unavailable or unstable.
