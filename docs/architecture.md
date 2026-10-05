# Architecture and data contracts

## Modules and flow

`capture.py` validates an immutable CapturePlan and builds a tcpdump argv list. The CLI only executes it with `--execute`. `storage.py` owns unique private output directories and exclusive 0600 writes. `decode.py` probes the decoder, runs bounded two-pass tshark offline, parses PDML one packet at a time and discards raw XML. `analyze.py` pairs RPCs and computes exact aggregates. `cli.py` validates bounds and writes JSON, CSV and text after successful decoding. No module sends data to a network service.

```text
explicit target + limits → dry-run plan → separately authorized tcpdump → private PCAP + metadata
single bounded local PCAP → tshark reassembly → transient Frame/Rpc objects → aggregates
synthetic generator → artificial PCAP → same decoder/analysis path → unit/CLI assertions
```

PDML can contain payload and identity; it stays on an in-memory pipe and is never exported. Internal Frame objects retain addresses/ports only to correlate endpoints. Rpc objects retain operation numbers, XIDs, links, timing and coverage flags. Neither raw objects nor identifiers are serialized to report output.

## Decoder contract

Required fields are checked with `tshark -G fields`. Offline options set `-n -2`, TCP stream desegmentation, RPC TCP desegmentation/record defragmentation, and TCP sequence analysis explicitly. The analyzer filters the literal server and configured TCP/UDP port after counting bounded input frames, so unrelated frames cannot hide a frame-cap stop. Unrelated packet objects are immediately discarded. Every RPC proto is associated with its subsequent NFS proto, preserving multiple records in one packet.

The verified tshark 4.6.5 RPC dissector emits `rpc.reqframe` **on a call pointing to its reply**, and `rpc.repframe` **on a reply pointing to its call**. `decode.py` normalizes these to `reply_frame` and `request_frame`. Naming alone is unsafe; the test checks both sides through real tshark. This mapping is corroborated by the [tagged Wireshark RPC source](https://github.com/wireshark/wireshark/blob/v4.6.5/epan/dissectors/packet-rpc.c). Duplicate markers come from `rpc.call.dup`/`rpc.reply.dup`; `rpc.time` stays a separate diagnostic. [Field reference](https://www.wireshark.org/docs/dfref/r/rpc.html)

Call identity is NFS program 100003 + program version + procedure; NFSv4 requested `nfs.opcode` values are kept in sequence. Unknown procedures/opcodes retain numeric labels. NFSv4 calls are grouped as COMPOUND, with requested suboperation occurrence counts independent of RPC counts. Replies may stop at an error; requested operations are not claims of execution. [NFS field reference](https://www.wireshark.org/docs/dfref/n/nfs.html)

## Pairing and sample contract

Key = transport, TCP stream (when present), oriented client address/port, server address/port, XID. Reply direction reverses endpoints. Prefer explicit frame links; a missing linked call stays unmatched. Without a link, use the outstanding key. Duplicate calls alias their original transaction; repeated same-key/same-operation calls while outstanding are conservatively treated as retries. A changed outstanding operation with the same XID marks both generations ambiguous. A new unflagged call after completion starts a new generation. Duplicate replies add no latency sample. Version/program/procedure mismatches are rejected. NFS server-initiated callbacks are outside current scope.

`all_matched_rpc_span` measures reply completion-frame timestamp minus the first observed call completion-frame timestamp, including retries and ambiguous matches; negative spans are excluded and counted. `clean_rpc_span` further excludes retried/ambiguous calls, endpoint truncation/malformed records, privacy/decode problems, any observed stream gap, and TCP retransmissions overlapping the RPC interval on that connection. Overlap can belong to another simultaneous RPC, so this exclusion is conservative. `tshark_rpc_time` uses the decoder's value for matched replies and may differ from our completion-frame span. Differences over 1 μs are counted, not silently reconciled.

“Clean” means those observed exclusion checks passed; it does **not** mean complete capture, successful NFS status, or pure server time. RPC/NFS error replies are currently included. TCP retransmissions and RPC retries are different events; a TCP retransmission may contain no newly decoded RPC. Reassembly completion time can hide initial-fragment duration. Cross-host clocks are not combined.

## Output schema 1

| Key | Meaning |
| --- | --- |
| `coverage` | Frame/record counts, logical/matched/unmatched calls, duplicates/collisions, truncation/decode/privacy/TCP diagnostics, input cap flag, kernel drops (null if unknown) |
| `operations` | Version/procedure group → call/match/retry/exclusion counts and three timing populations |
| `nfs4_requested_suboperations` | Requested opcode occurrence counts from logical calls; no independent latency |
| `tcp_ack_rtt` | ACK RTT nearest-rank distribution, separate from RPC spans |
| `wire_bytes`, `captured_bytes` | Sum for filtered target frames; frame bytes, not NFS payload throughput |
| `observed_window_seconds` | First-to-last filtered target frame interval; not workload duration |
| `decoder`, `input_bytes` | Actual tshark version and local input size |
| `warnings`, `observation` | Interpretation/coverage limits and evidence scope |

Each quantile object has `samples`, `p50_ms`, `p95_ms`, `p99_ms`. Exact nearest rank uses sorted sample `ceil(p*n)` (one-based); zero samples produce null. CSV has one row per operation/population with counts and those quantiles. No estimate of Homa improvement is emitted.

## Resource and coverage limits

Single-file input only; no ring merging, deduplication across captures or cross-host joins. Default file/frame/RPC/time caps are 64 MiB/200k/100k/120 s; hard configurable maxima are 256 MiB/500k/250k/300 s. Streaming XML bounds parser accumulation; tshark's two-pass state and exact quantile samples still consume memory. No hard OS memory quota is imposed. Failures produce no successful aggregate report. A frame-cap stop is labeled potentially incomplete; it is not an implicit full-file scan.

Target/port filters can omit noninitial IP fragments, nonstandard-port protocols, encapsulations and opaque IPsec traffic. Kernel capture drops, ring overwrites, offloads, absent initial handshakes and partial windows can skew matching without a truncation flag. A no-RPC report is a decode/coverage question, not proof that no NFS occurred. Installed tshark preferences/plugins beyond the explicitly set options remain environmental inputs.
