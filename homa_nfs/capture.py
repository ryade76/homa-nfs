"""Explicit-target, finite tcpdump plans. Execution requires --execute."""

from dataclasses import asdict, dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from .storage import new_run, write_private


@dataclass(frozen=True)
class CapturePlan:
    interface: str
    server: str
    client: str | None = None
    port: int = 2049
    transport: str = "tcp"
    duration: int = 30
    size_mb: int = 16
    rotations: int = 4
    snaplen: int = 65535
    packets: int = 200000
    extra_filter: str = ""
    tcpdump: str = "tcpdump"

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.interface) or self.interface.lower() in {"any", "all"} or self.interface.lower().startswith("pktap"):
            raise ValueError("name one concrete interface; broad interfaces are refused")
        for target in [self.server, self.client]:
            if target is not None:
                address = ipaddress.ip_address(target)
                if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
                    raise ValueError("target must be one unicast IP literal, not a range or wildcard")
        if self.client and ipaddress.ip_address(self.client).version != ipaddress.ip_address(self.server).version:
            raise ValueError("client and server must have the same address family")
        for name, low, high in [("port", 1, 65535), ("duration", 1, 900), ("size_mb", 1, 100),
                                ("rotations", 1, 10), ("snaplen", 96, 262144), ("packets", 1, 1000000)]:
            if not low <= getattr(self, name) <= high:
                raise ValueError(f"{name} must be between {low} and {high}")
        if self.transport not in {"tcp", "udp"}:
            raise ValueError("transport must be tcp or udp")
        if len(self.extra_filter) > 1000 or any(c in self.extra_filter for c in "\n\r\x00"):
            raise ValueError("extra filter must be a short single line")
        depth = 0
        for char in self.extra_filter:
            depth += (char == "(") - (char == ")")
            if depth < 0:
                raise ValueError("extra filter parentheses must stay within target constraints")
        if depth:
            raise ValueError("extra filter parentheses must be balanced")

    @property
    def bpf(self):
        family = "ip6" if ipaddress.ip_address(self.server).version == 6 else "ip"
        clauses = [family, f"host {self.server}", self.transport, f"port {self.port}"]
        if self.client:
            clauses.append(f"host {self.client}")
        if self.extra_filter:
            # Extra expressions can only narrow the mandatory target constraints.
            clauses.append(f"({self.extra_filter})")
        return " and ".join(clauses)

    def argv(self, output: Path):
        return [self.tcpdump, "-i", self.interface, "-p", "-n", "-U", "-s", str(self.snaplen),
                "-C", str(self.size_mb), "-W", str(self.rotations), "-c", str(self.packets),
                "-w", str(output), self.bpf]

    def describe(self, root: Path):
        return {"mode": "dry-run", "settings": asdict(self), "filter": self.bpf,
                "argv": self.argv(root / "<unique-run>" / "capture.pcap"),
                "deadline_seconds": self.duration,
                "nominal_ring_bytes": self.size_mb * 1000000 * self.rotations,
                "storage_caveat": "Each ring file can exceed -C by one packet plus headers; old rotations are overwritten.",
                "sensitive": "Packets may contain file content, names, handles and identities. Keep local; no upload.",
                "privilege": "No sudo or privilege grants. Use only existing authorized capture access."}


def execute(plan: CapturePlan, root: Path):
    if os.geteuid() == 0:
        raise ValueError("do not run the wrapper as root; use existing least-privilege capture access")
    run = new_run(root, "capture-")
    metadata = plan.describe(root)
    metadata.update(mode="executed", started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    command = plan.argv(run / "capture.pcap")
    start = time.monotonic()
    reason = "process-exit"
    # Never print packets. Preserve tcpdump's capture/drop counters locally.
    log_path = run / "tcpdump.log"
    with os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log, umask=0o077)
        try:
            process.wait(timeout=plan.duration)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            reason = "deadline" if isinstance(error, subprocess.TimeoutExpired) else "interrupted"
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                reason += "-forced-stop"
    log_text = log_path.read_text(errors="replace")
    drops = re.search(r"(\d+) packets dropped by kernel", log_text)
    metadata.update(elapsed_seconds=round(time.monotonic() - start, 3), stop_reason=reason,
                    returncode=process.returncode, kernel_drops=int(drops[1]) if drops else None,
                    argv=command, rotation_order="Use packet timestamps; filenames are ring slots, not chronology.")
    write_private(run / "metadata.json", json.dumps(metadata, indent=2) + "\n")
    if process.returncode not in {0, -signal.SIGINT}:
        raise RuntimeError(f"tcpdump failed; see private log in {run}")
    return run
