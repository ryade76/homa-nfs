# Agent handoff instructions

## Goal and boundaries

Build a defensible baseline for existing NFS traffic, then assess whether an isolated Homa/RPC experiment merits effort. Start with README and docs/handoff.md. Proposed gates are hypotheses, not observations. No measured campus/NFS/Homa benefit exists in this repo.

Keep implementation small, Python standard library only, and offline tests bounded. Run CLI from the checkout with `python3 -m homa_nfs`; do not install software simply to run tests. Do not launch live capture, run as root, invoke sudo, change sysctls/mount/cache/network/firewall settings, stress production, create credentials/persistent access, or upload packet content. Host/operator authorization and an explicit scope/window are separate prerequisites for future capture work.

Do not commit private employer data, real IPs/hostnames, traffic, credentials, reports containing real data, or the private design report. Capture data can expose payloads, filenames, file handles and identity. Default to no upload. Only synthetic fixture **source** belongs in tests; generated PCAP/PDML/JSON/CSV/logs stay ignored and local. Never `git add -f` ignored data. No third-party communications are implied by this repository.

## Development conventions

- Review existing changes/instructions before editing; preserve other agents' work. Use an isolated worktree for future PR work when appropriate; do not reset or overwrite a checkout.
- Capture must retain required literal target and concrete interface, time/packet/size bounds, default dry run, argv execution with no shell, no privilege escalation, 0700 directories and 0600 files.
- Preserve RPC record boundaries and Decimal timestamps. Never correlate on XID alone or zip flattened field arrays. Version-check the actual tshark field semantics with synthetic PCAPs.
- Keep clean and all-match populations distinct; expose exclusions, unmatched records, sample counts, decoder version, missing coverage and null quantiles. Do not silently fabricate service time or Homa speedup.
- Bump `schema_version` if output meaning changes. Update contracts and fixture expectations with the implementation.
- Check `git diff --check` and `python3 -m unittest discover -v`. Tests may skip tshark integration if unavailable: report skipped separately, never call that full verification.
- Only run the synthetic quickstart and capture dry-run here. Capture lifecycle tests must mock tcpdump; no live packets are required.

## Completion evidence

Provide repository/commit, changed behavior, exact passed/failed/skipped/not-run checks, known limits and next acceptance criteria. Use `git rev-parse HEAD`, `git status --short` and `git log -3 --oneline` to establish current state; don't guess a commit from a stale document. Keep real measurement provenance in private local storage.
