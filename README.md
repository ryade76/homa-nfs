# homa-nfs

A small local toolkit to measure existing NFS/RPC traffic before deciding whether a Homa experiment is worth pursuing. Python standard library only; existing `tcpdump` for capture and `tshark` for offline decoding. No Homa implementation, installation, or production benchmark is included.

**Current evidence:** synthetic verification only. No problem-host traffic, campus latency, server processing time, or Homa/NFS improvement has been measured.

## Quickstart (synthetic, no network traffic)

From a checkout, with Python 3.10+ and an already installed tshark:

```sh
python3 -m unittest discover -v
mkdir -m 700 captures
python3 -m tests.synthetic captures/synthetic-udp.pcap
python3 -m homa_nfs analyze captures/synthetic-udp.pcap --server 192.0.2.10
python3 -m tests.synthetic captures/synthetic-tcp.pcap --tcp
python3 -m homa_nfs analyze captures/synthetic-tcp.pcap --server 192.0.2.10
```

If `captures` already exists, reuse it only if it is owned by you, has mode 0700, and has no symlink components. Generated fixtures contain only documentation addresses and artificial data. No binaries or outputs are committed.

The UDP fixture should show four logical calls, three matches, one unmatched call, one duplicate call record, and one duplicate reply. The clean GETATTR sample is 1 ms; the clean COMPOUND sample is 2 ms. These are constructed values, not performance observations. The TCP fixture splits a call across segments and packs two RPC calls/replies into single frames; it should yield two matches with completion-frame spans of 2 ms.

Each analysis creates a unique private directory under `results/`, with `summary.json`, `operations.csv` and `report.txt`. JSON/CSV include exact nearest-rank p50/p95/p99 in milliseconds and sample counts. Zero samples use null/empty cells, never zero latency. Reports omit addresses, ports, XIDs, handles, names, identities and packet content. Keep aggregates local until explicitly cleared for sharing.

## Plan a capture

```sh
python3 -m homa_nfs capture --interface en0 --server 192.0.2.10 \
  --client 192.0.2.20 --duration 30 --size-mb 16 --rotations 4 --packets 200000
```

This is a **dry run**. It writes nothing and launches no capture. Replace documentation IPs/interface only for a separately authorized target. Required server IP, concrete interface, protocol/port, finite time, packet count, snap length and bounded size ring prevent accidental broad or unbounded capture. `--extra-filter` can only narrow the mandatory target filter. The wrapper never invokes sudo or grants privileges. Read the [capture runbook](docs/capture-runbook.md) before considering `--execute`; no live capture is authorized by this repository.

Analyze a single approved local file:

```sh
python3 -m homa_nfs analyze captures/approved-window.pcap --server 192.0.2.10 \
  --capture-metadata captures/approved-run/metadata.json
```

The metadata argument is optional; it copies only a validated whole-run kernel drop count. Match the metadata to the actual file yourself. Analysis defaults to 64 MiB, 200,000 input frames, 100,000 decoded RPC records and 120 seconds. A frame cap produces an explicit possibly-incomplete warning. Exceeding record/file bounds or decoding timeout fails without a report. Do not increase bounds to process a large production archive.

## Interpret the result

RPC wire spans include transit, host transport, server queues and service. TCP ACK RTT has different semantics. Neither isolates server execution, and their quantiles must not be subtracted to infer network contribution. Warm stat calls may issue no RPC; NFSv4 COMPOUND suboperations share one measured RPC span. See [measurement methods](docs/measurement.md) for cache controls and proposed decision gates.

The analyzer uses two-pass tshark TCP/RPC reassembly and protocol boundaries rather than zipped field arrays. Matching uses endpoint direction, TCP stream when present, XID and frame links. Retries, collisions, decode gaps and capture limitations stay visible. See [architecture and contracts](docs/architecture.md) for exact sample definitions and limitations.

## Handoff

Start with [AGENTS.md](AGENTS.md), then [verified status and next tasks](docs/handoff.md). The verified environment is Python 3.14.7, tshark 4.6.5 and Apple tcpdump 4.99.1/libpcap 1.10.1 on macOS. Other versions/platforms are not yet certified. No dependency install is required to run from the checkout. Git ignores captures, packet files and derived JSON/CSV/logs; never force-add real data.

The design follows the completed 5 October 2026 Homa/NFS assessment: baseline → isolated RPC transport trial → adapter only after measured benefit. Homa's official manual describes a different message socket API and a physically close, low-RTT target environment; a transport gain cannot be assumed to be an NFS gain. [Homa manual](https://github.com/PlatformLab/HomaModule/blob/main/man/homa.7)
