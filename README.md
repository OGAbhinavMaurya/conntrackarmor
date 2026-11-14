<div align="center">

# conntrackarmor

**Linux Netfilter connection tracking table exhaustion sentry and surgical pruner.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](go.mod)
[![Protocol](https://img.shields.io/badge/Netlink-NETLINK__NETFILTER%20%2F%20ctnetlink-orange)](#)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Go)-green)](#)

<p align="center">
  <a href="#the-problem">The problem</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#comparison">Comparison</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#how-it-works">How it works</a> •
  <a href="#license">License</a>
</p>

</div>

## The problem

Modern container and Kubernetes worker nodes use the Netfilter Connection Tracking (`nf_conntrack`) kernel subsystem to maintain state for Network Address Translation (DNAT and SNAT). Because UDP is stateless and lacks explicit connection termination, the kernel retains entries for an arbitrary duration (`nf_conntrack_udp_timeout`, default 30 seconds). DNS lookups to CoreDNS typically complete in under one millisecond, yet their corresponding entries linger in kernel memory for the full 30 second window.

Kubernetes default resolver configurations (`ndots:5`) multiply this overhead by splitting each outgoing domain lookup into up to five sequential search domain queries. Under high request volume, thousands of short-lived UDP records accumulate in the conntrack table. When `nf_conntrack_count` reaches `nf_conntrack_max`, the kernel silently drops incoming and outgoing packets (`table full, dropping packet`), causing DNS timeouts, failing kubelet health checks, and inducing node eviction cascades.

Common remedies introduce operational hazards:
- Increasing `nf_conntrack_max` allocates hundreds of megabytes of non-swappable kernel slab memory (`struct nf_conn`), risking kernel memory pressure.
- Running a global flush (`conntrack -F`) indiscriminately terminates every active TCP stream, database pool, and gRPC connection on the host.

`conntrackarmor` tracks table saturation, calculates fill velocity and projected time to exhaustion, and surgically purges stale UDP and terminal TCP connections via Netlink without dropping established sessions.

## Architecture

```text
Host / Kubernetes node
  │
  ├─► Outgoing DNS lookups (ndots:5)
  │     └─► 5x queries per domain (resolved in <1ms)
  │           └─► Held in conntrack table for 30s (nf_conntrack_udp_timeout)
  │
  ▼
[ Netfilter Conntrack Table: nf_conntrack_count / nf_conntrack_max ]
  │
  ├──► Critical threshold reached (>75%)
  │      ├─ Standard kernel: silent packet drops ("table full, dropping packet")
  │      ├─ Global flush (conntrack -F): terminates active TCP and database sessions
  │      │
  │      └─► ConntrackArmor sentry and reaper
  │            ├── 1. Read sysctl count and dump entries via Netlink CTNETLINK (pure Go)
  │            ├── 2. Calculate fill rate (Δcount / Δt) and time to exhaustion
  │            ├── 3. Identify expired flows (UDP port 53 older than 2s, TCP TIME_WAIT)
  │            └── 4. Surgical deletion via IPCTNL_MSG_CT_DELETE (CTA_TUPLE_ORIG)
  │                  └─► Safety invariant: ESTABLISHED TCP connections are never reaped
  ▼
Table capacity recovered without dropping active connections
```

## Comparison

| Dimension | Standard sysctl tuning | Global flush (`conntrack -F`) | Node reboot | ConntrackArmor |
| :--- | :--- | :--- | :--- | :--- |
| **Surgical precision** | None (passive limit raise) | None (clears all entries) | None (reboots host) | Granular 4-tuple targeting |
| **Active TCP safety** | Safe | Destructive (drops all active TCP/DB connections) | Destructive | Hard invariant: skips ESTABLISHED connections |
| **Memory overhead** | High (consumes pinned non-swappable kernel slab) | Zero (after flush) | N/A | Zero additional kernel slab allocated |
| **Velocity detection** | None (only checks static count) | None | None | Real-time rate of fill and time-to-full alerts |
| **External dependencies** | None | Requires `conntrack-tools` package | N/A | Zero dependencies (pure Go Netlink client) |
| **Automation suitability** | Static boot-time | Unsafe for automated cron/daemon | Disruptive | Safe for continuous sentry cron or daemon |

## Features

- Reads capacity and count directly from `/proc/sys/net/netfilter/`.
- Queries and decodes kernel conntrack records over pure Go Netlink sockets (`NETLINK_NETFILTER` / `ctnetlink`) with zero external C library dependencies.
- Calculates real-time fill velocity and projects time to exhaustion.
- Identifies stale UDP flows on port 53 older than configurable age thresholds.
- Surgically purges terminal TCP states (`TIME_WAIT`, `CLOSE`, `LAST_ACK`) and expired UDP entries.
- Hard safety invariant: established active TCP streams are never pruned.
- Includes a dry-run mode to preview candidate purges before committing changes.

## Installation

Building from source:

```bash
git clone https://github.com/OGAbhinavMaurya/conntrackarmor.git
cd conntrackarmor
go build -o conntrackarmor ./cmd/conntrackarmor
sudo install -m 0755 conntrackarmor /usr/local/bin/
```

## Usage

### Inspect conntrack table health

Scan table capacity, fill rate, and protocol breakdown:

```bash
conntrackarmor doctor
```

Example output:

```text
Conntrack Table Health: [CRITICAL]
  Capacity:          65536 max entries
  Active Entries:    54200 (82.7% utilized)
  Available Slots:   11336
  Fill Velocity:     +420.0 entries/sec (over 2s sample)
  Time to Full:      27.0s

Protocol Breakdown:
  - TCP Total:       18400 (established: 12200, terminal: 6200)
  - UDP Total:       35800 (DNS port 53: 31400, stale DNS >=2s: 28900)
  - ICMP / Other:    0

Detected Issues:
  ! Table capacity is at 82.7% (threshold: 75.0%).
  ! Time to table exhaustion is critically low: 27.0s.

Remediation:
  Run 'conntrackarmor reap --proto udp --older-than 2s' to relieve capacity pressure.
```

Sample table count over an interval to compute fill velocity:

```bash
conntrackarmor doctor --sample 2s
```

JSON output for metrics collection and automated alerts:

```bash
conntrackarmor doctor --json
```

### Surgically prune expired connections

Purge stale UDP entries older than 2 seconds:

```bash
sudo conntrackarmor reap --proto udp --older-than 2s
```

Preview matching entries without issuing kernel delete commands:

```bash
conntrackarmor reap --proto udp --older-than 2s --dry-run
```

Purge lingering TCP connections in terminal states:

```bash
sudo conntrackarmor reap --proto tcp --state timewait
```

Target specific network ports:

```bash
sudo conntrackarmor reap --proto udp --port 53 --older-than 2s
```

## How it works

### Kernel Netlink communication

`conntrackarmor` communicates with the kernel using raw Netlink sockets (`syscall.AF_NETLINK`, protocol 12 `NETLINK_NETFILTER`). It issues dump requests using message type `(NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET` (257) and decodes consecutive binary Type-Length-Value (TLV) attributes to reconstruct connection 4-tuples, protocol metadata, and remaining timeouts.

### Safe surgical pruning

Global table flushes (`conntrack -F`) sever active production traffic. `conntrackarmor reap` issues targeted delete requests (`IPCTNL_MSG_CT_DELETE`, 258) specifying the exact origin 4-tuple (`CTA_TUPLE_ORIG`). The execution engine enforces a safety invariant: any entry marked with protocol TCP and state `ESTABLISHED` is explicitly skipped, ensuring zero disruption to live database connections or in-flight service requests.

## License

MIT
