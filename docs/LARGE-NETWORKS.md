# Scanning very large networks (Class A / millions of hosts)

This guide covers sweeping big, flat ranges — for example an **air-gapped**
network where Class-A addressing (`10.0.0.0/8`, 16,777,214 hosts) was used to
avoid IP conflicts. Everything here applies to any large range (`/12`, `/16`,
multiple subnets, etc.).

## TL;DR

- **Windows:** `scannet-fast.py` — native `icmp.dll`, no Npcap, fastest.
- **Linux/macOS:** `scannet-fastV2.py` — pure standard library.
- Memory is **flat** at any range size (addresses are streamed, not listed).
- A crash-safe `<out>.live` log captures hosts as they are found.
- `Ctrl-C` stops cleanly and still writes the final report.

```bash
# Windows: full Class-A, tuned for a quiet LAN, authoritative pass with 1 retry
python scannet-fast.py --cidr 10.0.0.0/8 --workers 2048 --timeout-ms 200 --retries 1 --out devices.csv

# Linux: same idea, stdlib only
python scannet-fastV2.py 10.0.0.0/8 -t 1000 --method ping --timeout 0.3 -o live.txt
```

## How it scales

Both scanners use a **producer → bounded queue → worker pool** design:

- A producer thread lazily walks `network.hosts()` and feeds a fixed-size queue.
- N worker threads pull addresses, ping them, and push live ones to a collector.
- The collector appends each live host to memory **and** to `<out>.live`.
- A progress thread prints `percent / scanned / alive / rate / ETA`.

Because addresses are generated on demand, scanning `10.0.0.0/8` uses the same
memory as scanning a `/24`. The only state that grows is the (small) list of
**live** hosts.

## Picking timeout and workers

On a mostly-empty range, the runtime is dominated by **dead** addresses — each
one costs exactly one timeout. Live hosts answer almost instantly and are cheap.

Worst-case throughput ≈ `workers ÷ timeout`:

| workers | timeout | ≈ rate | time for `/16` (65k) | time for `/8` (16.7M) |
|--:|--:|--:|--:|--:|
| 512  | 400 ms | ~1,300/s  | ~50 s   | ~3.5 h |
| 1024 | 300 ms | ~3,400/s  | ~19 s   | ~1.4 h |
| 2048 | 200 ms | ~10,000/s | ~6.5 s  | ~28 min |
| 2048 | 100 ms | ~20,000/s | ~3.3 s  | ~14 min |

(Real numbers are usually **better** — live hosts return early, and switch/OS
ICMP handling varies.)

### Recommendations for a quiet air-gapped LAN

- **`--timeout-ms 100–300`** (`--timeout 0.1–0.3` for V2). Local hosts reply in
  well under 10 ms, so a short timeout is safe; it only risks missing a host
  that is briefly busy — which `--retries` covers.
- **`--workers 1024–2048`** on Windows. Each thread reserves ~1 MB of stack, so
  4096+ threads mostly just costs RAM. 1024–2048 saturates a typical NIC/switch.
- **`--retries 1`** for the final, authoritative inventory. ICMP is lossy under
  load; one retry recovers single-packet drops at ~2× the dead-host cost. Use
  `--retries 0` for a fast first look.

## Reliability tips

- Run a fast pass first (`--retries 0`, short timeout) to find the bulk, then a
  slower verification pass (`--retries 1–2`, longer timeout) and merge.
- If ICMP is filtered, use TCP discovery: `scannet-fastV2 --method tcp --ports
  80,443,445,3389`.
- The `<out>.live` file is your safety net — if the box reboots mid-scan, you
  still have every host found up to that point.
- MAC addresses are only available for hosts on a **directly attached** L2
  segment (via the ARP cache). For routed Class-A segments most hosts will have
  an IP/hostname but no MAC — that is expected.

## When to reach for an external tool

For internet-scale or wire-speed scanning, purpose-built scanners such as
[`masscan`](https://github.com/robertdavidgraham/masscan) or
[`zmap`](https://github.com/zmap/zmap) send raw packets asynchronously and are
faster than any thread-pool approach. They require their own pcap/raw-socket
setup; on a host with a broken pcap driver, the pcap-free tools here remain the
safe choice.
