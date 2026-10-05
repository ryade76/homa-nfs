"""Build tiny artificial PCAPs without dependencies or live traffic.

Reserved documentation IPs, fixed fictitious handle/name, AUTH_NONE. Source only.
"""

import argparse
from pathlib import Path
import socket
import struct

SERVER = "192.0.2.10"
CLIENT = "192.0.2.20"


def words(*values):
    return struct.pack("!" + "I" * len(values), *values)


def opaque(value):
    return words(len(value)) + value + b"\0" * (-len(value) % 4)


def call(xid=1, procedure=1, version=3, arguments=None):
    # xid, CALL, RPCv2, NFS, version, proc, AUTH_NONE credential and verifier.
    if arguments is None:
        arguments = opaque(b"TEST")
    return words(xid, 0, 2, 100003, version, procedure, 0, 0, 0, 0) + arguments


def reply(xid=1, body=None):
    # Accepted RPC, AUTH_NONE verifier, SUCCESS. NFSv3 GETATTR success fattr3.
    if body is None:
        body = words(0) + words(1, 0o644, 1, 0, 0) + b"\0" * 64
    return words(xid, 1, 0, 0, 0, 0) + body


def compound(xid=4):
    # v4.0 PUTFH + LOOKUP + GETATTR. Three suboperations, one RPC latency.
    args = opaque(b"") + words(0, 3, 22) + opaque(b"TEST") + words(15) + opaque(b"item") + words(9, 1, 0)
    return call(xid, 1, 4, args)


def compound_reply(xid=4):
    return reply(xid, words(0) + opaque(b"") + words(3, 22, 0, 15, 0, 9, 0, 1, 0, 0))


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(payload, reverse=False, transport="udp", seq=1, ack=1, flags=0x18, sport=40000):
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    ports = (2049, sport) if reverse else (sport, 2049)
    src_bytes, dst_bytes = socket.inet_aton(src), socket.inet_aton(dst)
    if transport == "udp":
        segment = struct.pack("!HHHH", *ports, 8 + len(payload), 0) + payload
        protocol = 17
    else:
        segment = struct.pack("!HHIIBBHHH", *ports, seq, ack, 0x50, flags, 65535, 0, 0) + payload
        pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, 6, len(segment))
        segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
        protocol = 6
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 1, 0, 64, protocol, 0, src_bytes, dst_bytes)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return b"\x02\0\0\0\0\x01\x02\0\0\0\0\x02\x08\x00" + header + segment


def record(payload):
    return words(0x80000000 | len(payload)) + payload


def write_pcap(path, packets):
    with Path(path).open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for micros, data in packets:
            seconds, fraction = divmod(micros, 1000000)
            handle.write(struct.pack("<IIII", seconds + 1700000000, fraction, len(data), len(data)))
            handle.write(data)


def udp_fixture(path):
    entries = [(0, packet(call(1))), (1000, packet(reply(1))),
               (2000, packet(call(2))), (3000, packet(call(2))), (5000, packet(reply(2))),
               (6000, packet(reply(2))), (7000, packet(compound())),
               (9000, packet(compound_reply(), reverse=True)), (10000, packet(call(5)))]
    # Reply packets point back to the client, except the initial list gets normalized here.
    entries = [(t, packet(reply(1), reverse=True) if t == 1000 else
                packet(reply(2), reverse=True) if t in {5000, 6000} else p) for t, p in entries]
    write_pcap(path, entries)


def tcp_fixture(path):
    first = record(call(11))
    second = record(call(12))
    entries = [(0, packet(b"", transport="tcp", seq=100, ack=0, flags=2)),
               (100, packet(b"", True, "tcp", seq=200, ack=101, flags=0x12)),
               (200, packet(b"", transport="tcp", seq=101, ack=201, flags=0x10)),
               (1000, packet(first[:20], transport="tcp", seq=101, ack=201)),
               (2000, packet(first[20:] + second, transport="tcp", seq=121, ack=201)),
               (4000, packet(record(reply(11)) + record(reply(12)), True, "tcp", seq=201, ack=101 + len(first) + len(second)))]
    write_pcap(path, entries)


if __name__ == "__main__":
    args = argparse.ArgumentParser(description="Generate synthetic data only; no network traffic")
    args.add_argument("path", type=Path)
    args.add_argument("--tcp", action="store_true")
    options = args.parse_args()
    (tcp_fixture if options.tcp else udp_fixture)(options.path)
