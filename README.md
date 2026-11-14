# conntrackarmor

Linux Netfilter connection tracking table exhaustion sentry and surgical pruner.

Modern container and Kubernetes worker nodes use the Netfilter Connection Tracking (`nf_conntrack`) kernel subsystem to maintain state for Network Address Translation (DNAT and SNAT). Because UDP is stateless and lacks explicit connection termination, the kernel retains entries for an arbitrary duration (`nf_conntrack_udp_timeout`, default 30 seconds). DNS lookups to CoreDNS typically complete in under one millisecond, yet their corresponding entries linger in kernel memory for the full 30 second window.

Kubernetes default resolver configurations (`ndots:5`) multiply this overhead by splitting each outgoing domain lookup into up to five sequential search domain queries. Under high request volume, thousands of short-lived UDP records accumulate in the conntrack table. When `nf_conntrack_count` reaches `nf_conntrack_max`, the kernel silently drops incoming and outgoing packets (`table full, dropping packet`), causing DNS timeouts, failing kubelet health checks, and inducing node eviction cascades.

Common remedies introduce operational hazards. Increasing `nf_conntrack_max` allocates hundreds of megabytes of non-swappable kernel slab memory (`struct nf_conn`), risking kernel memory pressure. Running a global flush (`conntrack -F`) indiscriminately terminates every active TCP stream, database pool, and gRPC connection on the host.

`conntrackarmor` tracks table saturation, calculates fill velocity and projected time to exhaustion, and surgically purges stale UDP and terminal TCP connections via Netlink without dropping established sessions.

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
