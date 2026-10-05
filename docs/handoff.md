# Verified handoff and next work

## Starting state

Private repository: https://github.com/ryade76/homa-nfs. This is the initial toolkit, not a transport port. Get current commit/status with `git rev-parse HEAD`, `git status --short` and `git log -3 --oneline`. A document inside a commit cannot contain its own final hash; commit identifiers accompany the delivery and Git history is authoritative.

Verified 5 October 2026 on macOS with Python 3.14.7, TShark/Wireshark 4.6.5 (v4.6.5-0-gb40c46f83867), Apple tcpdump 4.99.1 and libpcap 1.10.1. The package declares Python 3.10+ but only this runtime is currently verified. Runtime code uses only the Python standard library; tshark/tcpdump were already present. No install, Homa build, GUI, live capture or production traffic was used.

Read AGENTS.md before work, README for commands, architecture.md for data semantics, capture-runbook.md before any future capture, and measurement.md for the experiment design.

## Verification contract

Run `python3 -m unittest discover -v`. The initial suite has **29 tests**, including five real-tshark offline integration tests. They cover endpoint/stream/XID scope, XID reuse/collision, explicit-link mismatch, reply identity mismatch, retry/duplicate replies, clean/all distributions, NFSv3 READDIR/PLUS, NFSv4 COMPOUND suboperation counts, split TCP records and multiple RPCs per frame, sensitive-field omission, private modes, bounds (including unrelated frames at the input cap), corrupt input, optional drop metadata and mocked capture deadline/forced stop. Without tshark, five tests skip; report that as partial verification.

Also run both synthetic README examples, a capture dry run, no-target/broad-interface rejection and `git diff --check`. The fixture generator uses only reserved documentation addresses, fictitious names/handles and AUTH_NONE. Generated packets are not measurements and stay ignored.

Final local verification: **29 passed, 0 failed, 0 skipped**. Both synthetic CLI quickstarts produced the README counts/spans, the dry-run printed the finite argv plan, no-target/broad-interface commands returned exit code 2, and tcpdump compiled the target filter using only the synthetic PCAP (`-r ... -d`). Staged whitespace/ignored-data checks are part of the delivery verification.

Initial failures caught and fixed during development: opposite-side tshark RPC frame-link names, and a synthetic reply whose operation did not match its request. No unresolved test failure remains.

Not run: actual tcpdump capture, host access/privilege validation, real cache workloads, Linux/other Python or tshark versions, installed console-script packaging, encrypted/private captures, cross-host attribution, Homa benchmark/adapter, throughput/stress or large-file builds. The capture deadline is tested with a mock process, not a real interface.

## Known limits

- Single input PCAP only. Ring slots can overwrite; no multi-file chronology/deduplication or gap recovery.
- RPC completion-frame spans are not first-byte, application or server-only latency. TCP ACK RTT cannot isolate the transport share. NFS/RPC error status is currently mixed into matched populations.
- “Clean” is conservative observed filtering, not proof of a full capture. Stream gaps exclude all samples on that connection; a concurrent RPC's TCP retransmission may exclude another call.
- Request opcode counts do not prove which NFSv4 operations executed; only RPC spans have latency. Unknown opcodes/procedures retain numeric labels.
- TLS/IPsec/GSS privacy, IP fragments, offload, midstream captures, nonstandard ports and encapsulation can hide work. Version field presence is checked; other decoder versions still need behavioral fixtures.
- Exact samples plus tshark two-pass state use bounded-input memory, but there is no process memory quota. Input cap warns and may omit the tail; file/RPC/time excess fails.
- Drop metadata is operator-supplied whole-run information, not independently linked to a PCAP. Retention deletion and sharing approval remain operator responsibilities.

## Prioritized bounded next tasks

| Priority | Task | Acceptance criteria |
| --- | --- | --- |
| 1 | Bounded multi-ring input/provenance | Explicit file list, total-byte/frame/time caps; synthetic wraparound and duplicates; sort by timestamp; preserve transaction links across slots; report missing/overwritten intervals; never average per-file quantiles |
| 2 | Outcome and coverage refinement | Synthetic NFSv3/v4 error/partial COMPOUND fixtures; status-specific counts/populations; requested vs returned operations distinct; malformed/opaque and unrelated RPC coverage tests; no payload export |
| 3 | Decoder/platform compatibility | Small fixtures on approved existing Python 3.10+ and tshark/Linux versions; validate field links/reassembly/preferences; record skipped vs passed; unsupported decoders fail clearly; no automatic installs |
| 4 | Application baseline manifest/correlation | Local synthetic stat/RPC timing schema, ordinary warm/miss-heavy/parallel cases, observed vs proposed labels, bounded fixture; no real paths or cache-changing commands committed |
| 5 | Host/server attribution design | Document authorized instrumentation needed to distinguish client queue/network/server/storage; quantify clock error and missing coverage; implement offline joins only after a synthetic contract |
| 6 | Isolated transport trial design | Predeclared useful improvement/regression thresholds, measured path assumptions, equivalent workloads and revision pinning; separate authorization before Homa installs/network changes or adapter work |

Take one task at a time with meaningful small fixtures and updated schema/docs. Do not start a Homa implementation simply because traffic was observed. Avoid replacing the measurement goal with a large benchmarking framework.
