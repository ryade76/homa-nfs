"""Conservative connection-scoped RPC pairing and aggregate measurement."""

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
import math

from .decode import Frame, Rpc


NFS_PROGRAM = 100003
V3 = {0: "NULL", 1: "GETATTR", 2: "SETATTR", 3: "LOOKUP", 4: "ACCESS", 5: "READLINK",
      6: "READ", 7: "WRITE", 8: "CREATE", 9: "MKDIR", 10: "SYMLINK", 11: "MKNOD",
      12: "REMOVE", 13: "RMDIR", 14: "RENAME", 15: "LINK", 16: "READDIR", 17: "READDIRPLUS",
      18: "FSSTAT", 19: "FSINFO", 20: "PATHCONF", 21: "COMMIT"}
V2 = {0: "NULL", 1: "GETATTR", 2: "SETATTR", 4: "LOOKUP", 5: "READLINK", 6: "READ",
      8: "WRITE", 9: "CREATE", 10: "REMOVE", 11: "RENAME", 12: "LINK", 13: "SYMLINK",
      14: "MKDIR", 15: "RMDIR", 16: "READDIR", 17: "STATFS"}
V4_OPS = {3: "ACCESS", 4: "CLOSE", 9: "GETATTR", 10: "GETFH", 15: "LOOKUP", 16: "LOOKUPP",
          18: "OPEN", 22: "PUTFH", 23: "PUTPUBFH", 24: "PUTROOTFH", 25: "READ", 26: "READDIR",
          27: "READLINK", 28: "REMOVE", 29: "RENAME", 31: "RESTOREFH", 32: "SAVEFH",
          34: "SETATTR", 38: "WRITE", 53: "SEQUENCE"}


def operation(rpc: Rpc):
    if rpc.version == 4:
        return "NFSv4.COMPOUND" if rpc.procedure == 1 else f"NFSv4.{rpc.procedure}"
    table = V3 if rpc.version == 3 else V2 if rpc.version == 2 else {}
    return f"NFSv{rpc.version}." + table.get(rpc.procedure, f"PROC_{rpc.procedure}")


def quantiles(values):
    """Exact nearest-rank quantiles, seconds in, milliseconds out; no interpolation."""
    ordered = sorted(values)
    return {"samples": len(ordered), "p50_ms": percentile(ordered, .50),
            "p95_ms": percentile(ordered, .95), "p99_ms": percentile(ordered, .99)}


def percentile(ordered, fraction):
    return float(ordered[max(0, math.ceil(len(ordered) * fraction) - 1)] * 1000) if ordered else None


@dataclass
class Transaction:
    frame: Frame
    rpc: Rpc
    attempts: list[int] = field(default_factory=list)
    reply: Frame | None = None
    reply_rpc: Rpc | None = None
    ambiguous: bool = False
    retried: bool = False

    @property
    def fingerprint(self):
        return (self.rpc.program, self.rpc.version, self.rpc.procedure, self.rpc.opcodes)


def flow_key(frame: Frame, reply=False):
    endpoints = ((frame.dst, frame.dport), (frame.src, frame.sport)) if reply else ((frame.src, frame.sport), (frame.dst, frame.dport))
    return (frame.transport, frame.stream, *endpoints)


def analyze(frames, server: str, max_frames=200000, max_rpcs=100000, port=2049):
    pending, by_frame = {}, {}
    transactions = []
    diagnostics = Counter()
    retransmissions = defaultdict(list)
    gaps = set()
    tcp_rtt = []
    observed_ops = Counter()
    first_time = last_time = previous_time = None
    last_number = 0
    bytes_wire = bytes_saved = 0
    for frame in frames:
        diagnostics["input_frames_decoded"] += 1
        if diagnostics["input_frames_decoded"] > max_frames:
            raise ValueError("frame limit exceeded; split the local input into bounded windows")
        last_number = max(last_number, frame.number)
        if server not in {frame.src, frame.dst} or port not in {frame.sport, frame.dport} or frame.transport not in {"tcp", "udp"}:
            continue
        diagnostics["target_frames"] += 1
        first_time = frame.timestamp if first_time is None else min(first_time, frame.timestamp)
        last_time = frame.timestamp if last_time is None else max(last_time, frame.timestamp)
        if previous_time is not None and frame.timestamp < previous_time:
            diagnostics["nonmonotonic_timestamps"] += 1
        previous_time = frame.timestamp
        bytes_wire += frame.wire_len
        bytes_saved += frame.captured_len
        diagnostics["truncated_frames"] += frame.captured_len < frame.wire_len
        diagnostics["malformed_frames"] += frame.malformed
        diagnostics["tls_frames"] += frame.tls
        diagnostics["tcp_retransmission_frames"] += frame.tcp_retransmission
        diagnostics["tcp_lost_segment_frames"] += frame.tcp_lost_segment
        diagnostics["tcp_out_of_order_frames"] += frame.tcp_out_of_order
        # Endpoints sort the same way for calls and replies, including connection stream.
        connection = (frame.transport, frame.stream, tuple(sorted(((frame.src, frame.sport), (frame.dst, frame.dport)))))
        if frame.tcp_retransmission:
            retransmissions[connection].append(frame.timestamp)
        if frame.tcp_lost_segment:
            gaps.add(connection)
        tcp_rtt.extend(r for r in frame.ack_rtt if r >= 0)
        for rpc in frame.rpcs:
            diagnostics["rpc_records"] += 1
            if diagnostics["rpc_records"] > max_rpcs:
                raise ValueError("RPC record limit exceeded; split the local input")
            diagnostics["rpc_privacy_records"] += rpc.privacy
            diagnostics["rpc_decode_problem_records"] += rpc.decode_problem
            if rpc.kind not in {0, 1}:
                diagnostics["invalid_rpc_message_types"] += 1
                continue
            reply = rpc.kind == 1
            if (frame.src if reply else frame.dst) != server:
                diagnostics["unexpected_direction_records"] += 1
                continue
            key = (*flow_key(frame, reply), rpc.xid)
            if not reply:
                if rpc.program != NFS_PROGRAM:
                    diagnostics["other_program_calls"] += 1
                    continue
                diagnostics["nfs_call_records"] += 1
                linked = by_frame.get((key, rpc.duplicate_frame)) if rpc.duplicate_frame else None
                current = linked or pending.get(key)
                if current and (rpc.duplicate_frame or current.fingerprint == (rpc.program, rpc.version, rpc.procedure, rpc.opcodes)):
                    current.retried = True
                    current.attempts.append(frame.number)
                    by_frame[key, frame.number] = current
                    diagnostics["duplicate_or_retransmitted_call_records"] += 1
                    continue
                if current:
                    # Same outstanding XID with a changed operation is unsafe to pair.
                    current.ambiguous = True
                    diagnostics["xid_collisions"] += 1
                transaction = Transaction(frame, rpc, [frame.number], ambiguous=bool(current), retried=bool(rpc.duplicate_frame))
                pending[key] = transaction
                by_frame[key, frame.number] = transaction
                transactions.append(transaction)
                if rpc.version == 4 and rpc.procedure == 1:
                    for opcode in rpc.opcodes:
                        observed_ops[V4_OPS.get(opcode, f"OP_{opcode}")] += 1
                    diagnostics["compound_calls_without_decoded_ops"] += not bool(rpc.opcodes)
            else:
                diagnostics["reply_records"] += 1
                current = by_frame.get((key, rpc.request_frame)) if rpc.request_frame else pending.get(key)
                if current is None:
                    diagnostics["unmatched_reply_records"] += 1
                    continue
                if current.reply is not None or rpc.duplicate_frame:
                    diagnostics["duplicate_reply_records"] += 1
                    continue
                if any(observed is not None and observed != expected for observed, expected in
                       [(rpc.program, current.rpc.program), (rpc.version, current.rpc.version), (rpc.procedure, current.rpc.procedure)]):
                    diagnostics["reply_identity_mismatches"] += 1
                    current.ambiguous = True
                    continue
                current.reply, current.reply_rpc = frame, rpc
                if pending.get(key) is current:
                    del pending[key]
    for times in retransmissions.values():
        times.sort()
    groups = defaultdict(lambda: {"calls": 0, "matched": 0, "unmatched_calls": 0, "retried_calls": 0,
                                  "excluded_matches": 0, "all": [], "clean": [], "tshark": []})
    for tx in transactions:
        group = groups[operation(tx.rpc)]
        group["calls"] += 1
        group["retried_calls"] += tx.retried
        if tx.reply is None:
            group["unmatched_calls"] += 1
            continue
        group["matched"] += 1
        duration = tx.reply.timestamp - tx.frame.timestamp
        connection = (tx.frame.transport, tx.frame.stream, tuple(sorted(((tx.frame.src, tx.frame.sport), (tx.frame.dst, tx.frame.dport)))))
        times = retransmissions[connection]
        overlap = bisect_right(times, tx.reply.timestamp) > bisect_left(times, tx.frame.timestamp)
        excluded = (tx.retried or tx.ambiguous or overlap or connection in gaps or tx.rpc.privacy or
                    tx.rpc.decode_problem or tx.reply_rpc.decode_problem or tx.frame.malformed or tx.reply.malformed or
                    tx.frame.captured_len < tx.frame.wire_len or tx.reply.captured_len < tx.reply.wire_len or duration < 0)
        if duration >= 0:
            group["all"].append(duration)
            if not excluded:
                group["clean"].append(duration)
        else:
            diagnostics["negative_rpc_spans"] += 1
        group["excluded_matches"] += excluded
        if tx.reply_rpc.rpc_time is not None and tx.reply_rpc.rpc_time >= 0:
            group["tshark"].append(tx.reply_rpc.rpc_time)
            if abs(duration - tx.reply_rpc.rpc_time) > Decimal("0.000001"):
                diagnostics["rpc_time_disagreements_over_1us"] += 1
    summaries = {}
    for name, group in sorted(groups.items()):
        summaries[name] = {k: v for k, v in group.items() if k not in {"all", "clean", "tshark"}}
        summaries[name].update(all_matched_rpc_span=quantiles(group["all"]),
                               clean_rpc_span=quantiles(group["clean"]), tshark_rpc_time=quantiles(group["tshark"]))
    counts = {name: int(diagnostics[name]) for name in ["input_frames_decoded", "target_frames", "rpc_records", "nfs_call_records", "reply_records",
        "unmatched_reply_records", "duplicate_reply_records", "duplicate_or_retransmitted_call_records", "xid_collisions",
        "reply_identity_mismatches", "truncated_frames", "malformed_frames", "tls_frames", "rpc_privacy_records",
        "rpc_decode_problem_records", "compound_calls_without_decoded_ops", "tcp_retransmission_frames",
        "tcp_lost_segment_frames", "tcp_out_of_order_frames", "nonmonotonic_timestamps", "negative_rpc_spans",
        "rpc_time_disagreements_over_1us", "other_program_calls", "unexpected_direction_records", "invalid_rpc_message_types"]}
    counts.update(logical_nfs_calls=len(transactions), matched_nfs_calls=sum(t.reply is not None for t in transactions),
                  unmatched_nfs_calls=sum(t.reply is None for t in transactions),
                  last_input_frame_seen=last_number, input_frame_limit_reached=last_number >= max_frames,
                  kernel_drops=None)
    warnings = ["Wire RPC spans contain transport, network, server queueing and service; they do not isolate server processing or predict Homa gains.",
                "TCP ACK RTT is a separate signal affected by delayed ACKs, offload and capture location; subtracting its quantiles from RPC quantiles is invalid.",
                "Latency timestamps are RPC dissection/reassembly completion frames, not application calls or first-byte arrival.",
                "Kernel drops and ring overwrites require capture metadata; absence of truncation does not prove capture completeness.",
                "TLS, IPsec, RPCSEC_GSS privacy, missing handshakes, capture boundaries and unsupported dissection can hide RPCs."]
    if not transactions:
        warnings.append("No decoded NFS calls: check target/port, protocol/security, bidirectional coverage and reassembly; this does not prove no NFS traffic.")
    if counts["input_frame_limit_reached"]:
        warnings.append("Input frame bound reached: tail of file may be omitted; split into smaller captures.")
    if any(counts[n] for n in ["truncated_frames", "rpc_decode_problem_records", "tls_frames", "rpc_privacy_records"]):
        warnings.append("Decode coverage is limited; operation mix and quantiles describe only visible records.")
    return {"schema_version": 1, "observation": "offline wire baseline; no Homa or campus performance observation",
            "quantile_method": "nearest-rank; milliseconds; null for zero samples; small-sample p99 is unstable",
            "coverage": counts, "wire_bytes": bytes_wire, "captured_bytes": bytes_saved,
            "observed_window_seconds": float(last_time - first_time) if first_time is not None else None,
            "operations": summaries, "nfs4_requested_suboperations": dict(sorted(observed_ops.items())),
            "tcp_ack_rtt": quantiles(tcp_rtt), "warnings": warnings}
