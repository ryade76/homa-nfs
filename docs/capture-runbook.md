# Capture runbook

This repository's initial verification used synthetic files and dry runs only. A future operator must have explicit authorization for the host, interface, client/server pair, port/protocol, window and workload. A proposed capture plan is not permission to run it. Stop if any of those inputs or retention ownership is unresolved.

## Preflight and minimum privilege

Record the observation point (client/server/tap), NFS version/security/mount options, workload start/end, interface, literal endpoint IPs and clock source in a private local note. Confirm existing capture access and installed Python/tcpdump/tshark versions through the host's ordinary procedures. The wrapper does not grant BPF access, capabilities, group membership or persistent access, and refuses root execution. If permission is missing, ask the host owner to choose an approved method; do not change permissions or invoke sudo.

Estimate capture volume from a short authorized window. Review disk space, memory load and other activity. Full snap length helps RPC reassembly but includes sensitive data; low snap lengths intentionally trade privacy/size for poorer visibility and must be labeled. Never assume a metadata workload prevents data payloads from entering a capture. Use a specific client as well as server where possible. `any`/`pktap`/wildcards/ranges/hostnames are refused; IP literals avoid DNS ambiguity. No capture of an entire campus/subnet is offered.

## Plan, then run only within separate authorization

Use the README dry-run to inspect the mandatory filter and all bounds. The wrapper adds `-p` (no promiscuous mode), `-n`, `-U`, snap length, packet limit and a size ring. The Python deadline stops tcpdump with SIGINT; after a 5-second grace it kills an unresponsive process and reports failure. tcpdump may stop earlier at its packet limit or an error. No shell, packet printing, rotation hook or remote transfer is used.

Defaults: 30 seconds, 200,000 packets, snaplen 65,535 bytes, four 16 MB ring slots. `-C` uses decimal MB; files can overshoot by a packet/header. Four slots nominally retain 64 MB, not all bytes observed over the run. Ring slots overwrite old packets and filenames are not chronological. Stay within the hard bounds shown by `--help`/CapturePlan.

Only an authorized operator adds `--execute` to the reviewed command. Do not run that flag during agent development or synthetic verification. No root, sysctl, mount/cache flushing, firewall/network change or production stress is needed by this toolkit.

## Local storage and analysis

Output root must be owned by the operator, private (0700), and free of symlink components. A new unique run directory prevents overwriting existing data; files use 0600 with a restrictive umask. Choose storage that is not shared, synced, backed up to an external service or under a public workspace. Modes cannot protect against root, endpoint compromise or backups; use local policy for stronger protection.

Each run keeps PCAP ring files, private tcpdump stderr/capture/drop counters and metadata (target/filter/argv, times, limits, exit reason, drop count). Metadata is sensitive too. A missing drop counter is unknown, not zero. Forced termination may leave incomplete files. Check logs locally and retain the exact decoder version beside analysis.

The MVP analyzes **one file**. With rotations, any single slot can omit calls/replies and early traffic; do not present it as the whole run. If an already approved offline workflow merges slots, use packet timestamps, retain provenance and keep the merged input within bounds. The toolkit currently performs no automatic merge or cross-file deduplication. Do not average per-slot p99 values. First-next-task acceptance criteria are in docs/handoff.md.

Aggregate reports omit packet content and identifiers but can still reveal workload/business characteristics. No upload happens by default. Clearing aggregates for sharing is a separate decision. Never attach PCAP, PDML, logs or real data to an issue/PR; never force-add ignored files.

## Retention and stopping criteria

Before capture, agree on retention expiry, authorized readers and deletion owner. Keep only the minimum useful interval; delete locally according to the agreed host policy. This tool neither implements secure erase nor a retention scheduler. Stop at the deadline, unexpected volume/host impact, permission error or scope mismatch. Do not extend duration or bounds to chase a tail event without reviewing the scope again.
