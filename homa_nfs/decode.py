"""Stream tshark PDML privately; retain only measurement fields in memory."""

from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET


REQUIRED_FIELDS = {"frame.number", "frame.time_epoch", "frame.cap_len", "frame.len", "rpc.xid",
                   "rpc.msgtyp", "rpc.program", "rpc.programversion", "rpc.procedure", "rpc.reqframe",
                   "rpc.repframe", "rpc.time", "rpc.call.dup", "rpc.reply.dup", "nfs.opcode",
                   "tcp.stream", "tcp.analysis.ack_rtt", "tcp.analysis.retransmission"}


@dataclass
class Rpc:
    xid: int
    kind: int
    program: int | None = None
    version: int | None = None
    procedure: int | None = None
    request_frame: int | None = None
    reply_frame: int | None = None
    duplicate_frame: int | None = None
    rpc_time: Decimal | None = None
    opcodes: tuple[int, ...] = ()
    minor_version: int | None = None
    privacy: bool = False
    decode_problem: bool = False


@dataclass
class Frame:
    number: int
    timestamp: Decimal
    src: str
    dst: str
    sport: int
    dport: int
    transport: str
    stream: int | None
    wire_len: int
    captured_len: int
    rpcs: list[Rpc] = field(default_factory=list)
    ack_rtt: tuple[Decimal, ...] = ()
    tcp_retransmission: bool = False
    tcp_lost_segment: bool = False
    tcp_out_of_order: bool = False
    malformed: bool = False
    tls: bool = False


def fields(element):
    found = {}
    for node in element.iter("field"):
        name = node.get("name", "")
        found.setdefault(name, []).append(node.get("show", ""))
    return found


def first(values, name, default=None):
    items = values.get(name)
    return items[0] if items else default


def integer(values, name, default=None):
    value = first(values, name)
    return int(value, 16 if value.lower().startswith("0x") else 10) if value else default


def packet_frame(packet):
    values = fields(packet)
    transport = "tcp" if "tcp.srcport" in values else "udp" if "udp.srcport" in values else "other"
    frame = Frame(integer(values, "frame.number"), Decimal(first(values, "frame.time_epoch")),
                  first(values, "ip.src", first(values, "ipv6.src", "")),
                  first(values, "ip.dst", first(values, "ipv6.dst", "")),
                  integer(values, f"{transport}.srcport", 0), integer(values, f"{transport}.dstport", 0),
                  transport, integer(values, "tcp.stream"), integer(values, "frame.len", 0),
                  integer(values, "frame.cap_len", 0),
                  ack_rtt=tuple(Decimal(v) for v in values.get("tcp.analysis.ack_rtt", [])),
                  tcp_retransmission=any(n in values for n in ["tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission"]),
                  tcp_lost_segment="tcp.analysis.lost_segment" in values,
                  tcp_out_of_order="tcp.analysis.out_of_order" in values,
                  malformed=any(p.get("name") == "_ws.malformed" for p in packet.iter("proto")),
                  tls=any(p.get("name") == "tls" for p in packet.iter("proto")))
    # PDML preserves RPC/NFS protocol boundaries, including several records per TCP frame.
    # Each NFS sibling belongs to the preceding RPC. Never zip aggregated -T fields arrays.
    current = None
    for proto in packet.iter("proto"):
        name = proto.get("name")
        if name == "rpc":
            v = fields(proto)
            if "rpc.xid" not in v or "rpc.msgtyp" not in v:
                current = None
                continue
            kind = integer(v, "rpc.msgtyp")
            # Wireshark 4.6.5 emits repframe on replies (pointing to the call),
            # and reqframe on calls (pointing to the reply). Normalize explicitly.
            current = Rpc(integer(v, "rpc.xid"), kind, integer(v, "rpc.program"),
                          integer(v, "rpc.programversion"), integer(v, "rpc.procedure"),
                          integer(v, "rpc.repframe") if kind == 1 else None,
                          integer(v, "rpc.reqframe") if kind == 0 else None,
                          integer(v, "rpc.call.dup", integer(v, "rpc.reply.dup")),
                          Decimal(first(v, "rpc.time")) if "rpc.time" in v else None,
                          privacy=integer(v, "rpc.authgss.service") == 3,
                          decode_problem=any(n in v for n in ["rpc.cannot_dissect", "rpc.segment_needed", "rpc.unknown_body", "rpc.fragment.error"]))
            frame.rpcs.append(current)
        elif name == "nfs" and current is not None:
            v = fields(proto)
            current.opcodes = tuple(int(o, 0) for o in v.get("nfs.opcode", []))
            current.minor_version = integer(v, "nfs.minorversion")
    return frame


def pdml_frames(handle):
    root = None
    for event, element in ET.iterparse(handle, events=("start", "end")):
        if root is None:
            root = element
        if event == "end" and element.tag == "packet":
            yield packet_frame(element)
            root.clear()


def tshark_info(executable="tshark"):
    version = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=15, check=True).stdout.splitlines()[0]
    available = subprocess.run([executable, "-G", "fields"], capture_output=True, text=True, timeout=30, check=True).stdout
    names = {parts[2] for line in available.splitlines() if len(parts := line.split("\t")) > 2 and parts[0] == "F"}
    missing = REQUIRED_FIELDS - names
    if missing:
        raise ValueError("tshark lacks required fields: " + ", ".join(sorted(missing)))
    return version


def tshark_frames(path: Path, server: str, port=2049, executable="tshark", timeout=120, max_frames=200000):
    # Decode all bounded input frames so the analyzer sees the true input cap,
    # even if the final frames carry unrelated traffic. Target filtering happens
    # in analyze(); unrelated packet objects are immediately discarded.
    command = [executable, "-n", "-2", "-r", str(path), "-c", str(max_frames),
               "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "rpc.desegment_rpc_over_tcp:TRUE",
               "-o", "rpc.defragment_rpc_over_tcp:TRUE", "-o", "tcp.analyze_sequence_numbers:TRUE",
               "-T", "pdml"]
    # No PDML file is written: it could contain filenames, authentication or payload.
    # stderr stays private and is not echoed into reports.
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors)
        timer = threading.Timer(timeout, process.kill)
        timer.start()
        try:
            yield from pdml_frames(process.stdout)
            status = process.wait(timeout=5)
            if status:
                raise RuntimeError("tshark failed or reached its time limit; no successful report produced")
        except ET.ParseError as error:
            raise RuntimeError("tshark output was incomplete; corrupt input or time limit; no successful report produced") from error
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
