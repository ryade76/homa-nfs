"""Small stdlib CLI: capture plans, bounded capture, offline analysis."""

import argparse
import csv
import io
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

from .analyze import analyze
from .capture import CapturePlan, execute
from .decode import tshark_frames, tshark_info
from .storage import new_run, write_private


def report_text(result):
    c = result["coverage"]
    lines = ["NFS/RPC wire baseline", result["observation"], "",
             f"Decoded logical calls: {c['logical_nfs_calls']}; matched: {c['matched_nfs_calls']}; unmatched: {c['unmatched_nfs_calls']}",
             f"Unmatched reply records: {c['unmatched_reply_records']}; duplicate call records: {c['duplicate_or_retransmitted_call_records']}; duplicate reply records: {c['duplicate_reply_records']}",
             f"Truncated frames: {c['truncated_frames']}; TCP retransmission frames: {c['tcp_retransmission_frames']}; kernel drops: {c['kernel_drops'] if c['kernel_drops'] is not None else 'unknown'}", "",
             f"TLS frames: {c['tls_frames']}; RPC privacy records: {c['rpc_privacy_records']}; RPC decode problems: {c['rpc_decode_problem_records']}", "",
             "Operation | calls | clean samples | p50/p95/p99 ms"]
    for name, group in result["operations"].items():
        q = group["clean_rpc_span"]
        display = "/".join("n/a" if q[k] is None else f"{q[k]:.3f}" for k in ["p50_ms", "p95_ms", "p99_ms"])
        lines.append(f"{name} | {group['calls']} | {q['samples']} | {display}")
    lines.extend(["", "NFSv4 requested suboperation occurrences (no separate per-op latency): " + json.dumps(result["nfs4_requested_suboperations"]),
                  "TCP ACK RTT ms: " + json.dumps(result["tcp_ack_rtt"]), "", result["quantile_method"], ""])
    lines.extend("- " + warning for warning in result["warnings"])
    return "\n".join(lines) + "\n"


def report_csv(result):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["operation", "calls", "matched", "unmatched_calls", "retried_calls", "excluded_matches", "population", "samples", "p50_ms", "p95_ms", "p99_ms"])
    for name, group in result["operations"].items():
        for population in ["clean_rpc_span", "all_matched_rpc_span", "tshark_rpc_time"]:
            q = group[population]
            writer.writerow([name, *[group[k] for k in ["calls", "matched", "unmatched_calls", "retried_calls", "excluded_matches"]],
                             population, *[q[k] for k in ["samples", "p50_ms", "p95_ms", "p99_ms"]]])
    return out.getvalue()


def parser():
    root = argparse.ArgumentParser(description="Local NFS baselines; captures are sensitive and never uploaded.")
    commands = root.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture", help="dry-run by default; refuses broad/no-target captures")
    capture.add_argument("--interface", required=True)
    capture.add_argument("--server", required=True, help="one explicit unicast IP literal")
    capture.add_argument("--client")
    capture.add_argument("--port", type=int, default=2049)
    capture.add_argument("--transport", choices=["tcp", "udp"], default="tcp")
    capture.add_argument("--duration", type=int, default=30)
    capture.add_argument("--size-mb", type=int, default=16)
    capture.add_argument("--rotations", type=int, default=4)
    capture.add_argument("--snaplen", type=int, default=65535)
    capture.add_argument("--packets", type=int, default=200000)
    capture.add_argument("--extra-filter", default="")
    capture.add_argument("--tcpdump", default="tcpdump")
    capture.add_argument("--out-root", type=Path, default=Path("captures"))
    capture.add_argument("--execute", action="store_true", help="only for a separately authorized target/capture window")
    offline = commands.add_parser("analyze", help="offline local PCAP; no packet-content exports")
    offline.add_argument("pcap", type=Path)
    offline.add_argument("--server", required=True)
    offline.add_argument("--port", type=int, default=2049)
    offline.add_argument("--out-root", type=Path, default=Path("results"))
    offline.add_argument("--tshark", default="tshark")
    offline.add_argument("--max-mib", type=int, default=64)
    offline.add_argument("--max-frames", type=int, default=200000)
    offline.add_argument("--max-rpcs", type=int, default=100000)
    offline.add_argument("--timeout", type=int, default=120)
    offline.add_argument("--capture-metadata", type=Path, help="optional matching wrapper metadata; only drop count is copied")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "capture":
            plan = CapturePlan(args.interface, args.server, args.client, args.port, args.transport,
                               args.duration, args.size_mb, args.rotations, args.snaplen, args.packets, args.extra_filter, args.tcpdump)
            if args.execute:
                print(f"Private capture saved: {execute(plan, args.out_root)}")
            else:
                print(json.dumps(plan.describe(args.out_root), indent=2))
        else:
            address = ipaddress.ip_address(args.server)
            if address.is_unspecified or address.is_multicast:
                raise ValueError("server must be one unicast IP literal")
            if not 1 <= args.port <= 65535 or not 1 <= args.max_mib <= 256 or not 1 <= args.max_frames <= 500000 or not 1 <= args.max_rpcs <= 250000 or not 1 <= args.timeout <= 300:
                raise ValueError("invalid bounds: port 1..65535, MiB 1..256, frames 1..500000, RPCs 1..250000, timeout 1..300")
            if not args.pcap.is_file() or args.pcap.stat().st_size > args.max_mib * 1024 * 1024:
                raise ValueError("input must be a local file within --max-mib")
            version = tshark_info(args.tshark)
            stream = tshark_frames(args.pcap, str(address), args.port, args.tshark, args.timeout, args.max_frames)
            try:
                result = analyze(stream, str(address), args.max_frames, args.max_rpcs, args.port)
            finally:
                stream.close()
            result["decoder"] = version
            result["input_bytes"] = args.pcap.stat().st_size
            if args.capture_metadata:
                if args.capture_metadata.stat().st_size > 65536:
                    raise ValueError("capture metadata exceeds 64 KiB")
                metadata = json.loads(args.capture_metadata.read_text())
                if not isinstance(metadata, dict):
                    raise ValueError("capture metadata must be an object")
                settings = metadata.get("settings", {})
                if not isinstance(settings, dict):
                    raise ValueError("capture metadata settings must be an object")
                if settings.get("server") != str(address) or settings.get("port") != args.port:
                    raise ValueError("capture metadata target/port does not match analysis")
                drops = metadata.get("kernel_drops")
                if drops is not None and (type(drops) is not int or drops < 0):
                    raise ValueError("kernel_drops must be a nonnegative integer or null")
                result["coverage"]["kernel_drops"] = drops
                result["warnings"].append("Capture drop count is user-supplied whole-run metadata; it does not prove this file contains every ring slot.")
            run = new_run(args.out_root, "analysis-")
            write_private(run / "summary.json", json.dumps(result, indent=2) + "\n")
            write_private(run / "operations.csv", report_csv(result))
            write_private(run / "report.txt", report_text(result))
            print(report_text(result), end="")
            print(f"Private aggregate outputs: {run}")
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"homa-nfs: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
