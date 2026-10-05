from dataclasses import replace
from decimal import Decimal
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from homa_nfs.analyze import analyze, quantiles
from homa_nfs.capture import CapturePlan, execute
from homa_nfs.cli import main, report_csv, report_text
from homa_nfs.decode import Frame, Rpc, tshark_frames, tshark_info
from homa_nfs.storage import private_directory, write_private
from tests.synthetic import SERVER, CLIENT, tcp_fixture, udp_fixture


def f(number, at, reply=False, xid=1, **rpc_values):
    rpc = Rpc(xid, int(reply), 100003, 3, 1, **rpc_values)
    return Frame(number, Decimal(str(at)), SERVER if reply else CLIENT, CLIENT if reply else SERVER,
                 2049 if reply else 40000, 40000 if reply else 2049, "tcp", 0, 100, 100, [rpc])


class PairingTests(unittest.TestCase):
    def test_clean_quantiles_and_counts(self):
        result = analyze([f(1, 0), f(2, .001, True, request_frame=1)], SERVER)
        q = result["operations"]["NFSv3.GETATTR"]["clean_rpc_span"]
        self.assertEqual(q, {"samples": 1, "p50_ms": 1, "p95_ms": 1, "p99_ms": 1})
        self.assertEqual(result["coverage"]["matched_nfs_calls"], 1)

    def test_retry_excluded_and_duplicate_reply_not_counted(self):
        result = analyze([f(1, 0), f(2, .001, duplicate_frame=1), f(3, .004, True, request_frame=2),
                          f(4, .005, True, request_frame=1, duplicate_frame=3)], SERVER)
        group = result["operations"]["NFSv3.GETATTR"]
        self.assertEqual(group["calls"], 1)
        self.assertEqual(group["all_matched_rpc_span"]["p50_ms"], 4)
        self.assertEqual(group["clean_rpc_span"]["samples"], 0)
        self.assertEqual(result["coverage"]["duplicate_reply_records"], 1)

    def test_connection_and_endpoint_scoped_xid(self):
        other_call = replace(f(2, .001), stream=1, sport=40001)
        other_reply = replace(f(4, .006, True), stream=1, dport=40001)
        result = analyze([f(1, 0), other_call, f(3, .002, True), other_reply], SERVER)
        self.assertEqual(result["coverage"]["matched_nfs_calls"], 2)
        self.assertEqual(result["operations"]["NFSv3.GETATTR"]["clean_rpc_span"]["p95_ms"], 5)

    def test_xid_reuse_after_reply_is_new_call(self):
        result = analyze([f(1, 0), f(2, .001, True), f(3, .002), f(4, .004, True, request_frame=3)], SERVER)
        self.assertEqual(result["coverage"]["logical_nfs_calls"], 2)

    def test_link_mismatch_is_not_guessed(self):
        result = analyze([f(1, 0), f(2, .002, True, request_frame=999)], SERVER)
        self.assertEqual(result["coverage"]["unmatched_reply_records"], 1)
        self.assertEqual(result["coverage"]["unmatched_nfs_calls"], 1)

    def test_xid_collision_excludes_both(self):
        b = f(2, .001)
        b.rpcs[0].procedure = 3
        reply = f(3, .003, True, request_frame=2)
        reply.rpcs[0].procedure = 3
        result = analyze([f(1, 0), b, reply], SERVER)
        self.assertEqual(result["coverage"]["xid_collisions"], 1)
        self.assertEqual(result["coverage"]["unmatched_nfs_calls"], 1)
        self.assertEqual(result["operations"]["NFSv3.LOOKUP"]["clean_rpc_span"]["samples"], 0)

    def test_reply_operation_mismatch_stays_unmatched(self):
        reply = f(2, .003, True, request_frame=1)
        reply.rpcs[0].procedure = 3
        result = analyze([f(1, 0), reply], SERVER)
        self.assertEqual(result["coverage"]["reply_identity_mismatches"], 1)
        self.assertEqual(result["coverage"]["unmatched_nfs_calls"], 1)

    def test_tcp_retransmission_without_rpc_excludes_overlap(self):
        retransmit = replace(f(2, .001), rpcs=[], tcp_retransmission=True)
        result = analyze([f(1, 0), retransmit, f(3, .002, True)], SERVER)
        self.assertEqual(result["operations"]["NFSv3.GETATTR"]["clean_rpc_span"]["samples"], 0)

    def test_truncation_privacy_gap_and_negative_spans(self):
        for changed in [replace(f(1, 0), captured_len=50), replace(f(1, 0), tcp_lost_segment=True), f(1, 0, privacy=True), f(1, 5)]:
            with self.subTest(changed=changed):
                result = analyze([changed, f(2, .002, True)], SERVER)
                self.assertEqual(result["operations"]["NFSv3.GETATTR"]["clean_rpc_span"]["samples"], 0)

    def test_compound_one_rpc_multiple_requested_operations(self):
        a, b = f(1, 0), f(2, .002, True)
        a.rpcs[0].version = 4
        a.rpcs[0].opcodes = (22, 15, 9, 26)
        b.rpcs[0].version = 4
        result = analyze([a, b], SERVER)
        self.assertEqual(result["nfs4_requested_suboperations"], {"PUTFH": 1, "LOOKUP": 1, "GETATTR": 1, "READDIR": 1})
        self.assertEqual(list(result["operations"]), ["NFSv4.COMPOUND"])

    def test_readdir_and_plus_are_distinct(self):
        a, b = f(1, 0, xid=1), f(2, .001, xid=2)
        a.rpcs[0].procedure, b.rpcs[0].procedure = 16, 17
        result = analyze([a, b], SERVER)
        self.assertEqual(set(result["operations"]), {"NFSv3.READDIR", "NFSv3.READDIRPLUS"})

    def test_limits_fail_closed(self):
        with self.assertRaises(ValueError):
            analyze([f(1, 0), f(2, .001, True)], SERVER, max_frames=1)
        with self.assertRaises(ValueError):
            analyze([f(1, 0)], SERVER, max_rpcs=0)

    def test_input_cap_detected_even_on_unrelated_final_frame(self):
        unrelated = replace(f(2, .001), src="198.51.100.1", dst="198.51.100.2")
        result = analyze([f(1, 0), unrelated], SERVER, max_frames=2)
        self.assertTrue(result["coverage"]["input_frame_limit_reached"])
        self.assertEqual(result["coverage"]["target_frames"], 1)
        self.assertEqual(result["coverage"]["input_frames_decoded"], 2)

    def test_no_calls_has_warning_and_empty_quantiles(self):
        result = analyze([], SERVER)
        self.assertTrue(any("No decoded NFS" in w for w in result["warnings"]))
        self.assertIsNone(quantiles([])["p99_ms"])
        self.assertEqual(quantiles([Decimal(i) for i in range(1, 101)])["p99_ms"], 99000)

    def test_output_has_no_endpoints_or_xids(self):
        result = analyze([f(1, 0), f(2, .001, True)], SERVER)
        content = json.dumps(result) + report_text(result) + report_csv(result)
        self.assertNotIn(SERVER, content)
        self.assertNotIn(CLIENT, content)
        self.assertIn("clean_rpc_span", content)


class CaptureTests(unittest.TestCase):
    def test_dry_run_never_spawns_or_writes(self):
        with patch("subprocess.Popen", side_effect=AssertionError("spawned")), patch("sys.stdout", new=io.StringIO()) as stdout:
            self.assertEqual(main(["capture", "--interface", "en0", "--server", SERVER]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["mode"], "dry-run")

    def test_refuse_broad_targets_interfaces_and_unbounded_settings(self):
        for changes in [{"server": "0.0.0.0"}, {"server": "::"}, {"server": "224.0.0.1"}, {"server": "192.0.2.0/24"},
                        {"server": "example.invalid"}, {"interface": "any"}, {"interface": "pktap:all"},
                        {"duration": 0}, {"duration": 901}, {"rotations": 0}, {"packets": 1000001}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                CapturePlan(**({"interface": "en0", "server": SERVER} | changes))

    def test_extra_filter_cannot_escape_target_gate(self):
        for extra in ["tcp) or ip or (tcp", "(tcp", "tcp\nor ip"]:
            with self.assertRaises(ValueError):
                CapturePlan("en0", SERVER, extra_filter=extra)
        self.assertIn(f"host {SERVER} and tcp and port 2049 and (tcp or udp)", CapturePlan("en0", SERVER, extra_filter="tcp or udp").bpf)

    def test_argv_bounded_no_shell_no_privilege_escalation(self):
        plan = CapturePlan("en0", SERVER)
        argv = plan.argv(Path("capture.pcap"))
        for option in ["-p", "-C", "-W", "-c", "-s", "-w"]:
            self.assertIn(option, argv)
        self.assertNotIn("sudo", argv)
        self.assertNotIn("-A", argv)

    def test_ipv6_filter_and_mixed_family_rejection(self):
        self.assertTrue(CapturePlan("en0", "2001:db8::10").bpf.startswith("ip6 and host"))
        with self.assertRaises(ValueError):
            CapturePlan("en0", SERVER, client="2001:db8::1")

    def test_root_execution_refused(self):
        with patch("os.geteuid", return_value=0), self.assertRaises(ValueError):
            execute(CapturePlan("en0", SERVER), Path("captures"))

    def test_capture_deadline_cleanup_with_mock_process(self):
        with tempfile.TemporaryDirectory() as tmp, patch("os.geteuid", return_value=501), patch("subprocess.Popen") as spawn:
            process = spawn.return_value
            process.wait.side_effect = [subprocess.TimeoutExpired("fake", 1), 0]
            process.returncode = 0
            run = execute(CapturePlan("en0", SERVER, duration=1), Path(tmp).resolve() / "captures")
            process.send_signal.assert_called_once()
            self.assertEqual(spawn.call_args.kwargs["umask"], 0o077)
            self.assertEqual(json.loads((run / "metadata.json").read_text())["stop_reason"], "deadline")

    def test_capture_forced_stop_with_mock_process(self):
        with tempfile.TemporaryDirectory() as tmp, patch("os.geteuid", return_value=501), patch("subprocess.Popen") as spawn:
            process = spawn.return_value
            process.wait.side_effect = [subprocess.TimeoutExpired("fake", 1), subprocess.TimeoutExpired("fake", 5), 0]
            process.returncode = -9
            with self.assertRaises(RuntimeError):
                execute(CapturePlan("en0", SERVER, duration=1), Path(tmp).resolve() / "captures")
            process.kill.assert_called_once()

    def test_private_storage_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = private_directory(root / "private")
            write_private(out / "test.txt", "synthetic")
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            self.assertEqual((out / "test.txt").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private(out / "test.txt", "overwrite")
            (root / "link").symlink_to(out)
            with self.assertRaises(ValueError):
                private_directory(root / "link")
            out.chmod(0o755)
            with self.assertRaises(ValueError):
                private_directory(out)


@unittest.skipUnless(shutil.which("tshark"), "tshark unavailable: offline integration not run")
class TsharkIntegrationTests(unittest.TestCase):
    def test_real_tshark_udp_duplicates_compound_and_unmatched(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "synthetic.pcap"
            udp_fixture(pcap)
            result = analyze(tshark_frames(pcap, SERVER), SERVER)
            self.assertEqual(result["coverage"]["logical_nfs_calls"], 4)
            self.assertEqual(result["coverage"]["matched_nfs_calls"], 3)
            self.assertEqual(result["coverage"]["unmatched_nfs_calls"], 1)
            self.assertEqual(result["coverage"]["duplicate_reply_records"], 1)
            self.assertEqual(result["nfs4_requested_suboperations"], {"PUTFH": 1, "LOOKUP": 1, "GETATTR": 1})
            self.assertEqual(result["operations"]["NFSv3.GETATTR"]["clean_rpc_span"]["p50_ms"], 1)
            decoded = list(tshark_frames(pcap, SERVER))
            self.assertEqual(decoded[0].rpcs[0].reply_frame, 2)
            self.assertEqual(decoded[1].rpcs[0].request_frame, 1)

    def test_real_tshark_tcp_reassembly_and_multiple_pdus(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "synthetic.pcap"
            tcp_fixture(pcap)
            result = analyze(tshark_frames(pcap, SERVER), SERVER)
            self.assertEqual(result["coverage"]["logical_nfs_calls"], 2)
            self.assertEqual(result["coverage"]["matched_nfs_calls"], 2)
            self.assertEqual(result["operations"]["NFSv3.GETATTR"]["clean_rpc_span"]["samples"], 2)

    def test_cli_creates_private_aggregate_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            pcap = root / "synthetic.pcap"
            udp_fixture(pcap)
            result = subprocess.run([sys.executable, "-m", "homa_nfs", "analyze", str(pcap), "--server", SERVER,
                                     "--out-root", str(root / "results")], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = next((root / "results").iterdir())
            self.assertEqual({p.name for p in run.iterdir()}, {"summary.json", "operations.csv", "report.txt"})
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            for path in run.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(SERVER, path.read_text())
            self.assertIn("TShark", tshark_info())

    def test_metadata_only_copies_aggregate_drop_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            pcap = root / "synthetic.pcap"
            udp_fixture(pcap)
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps({"settings": {"server": SERVER, "port": 2049}, "kernel_drops": 3,
                                           "sensitive_extra": "DO_NOT_EXPORT"}))
            with patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(main(["analyze", str(pcap), "--server", SERVER, "--capture-metadata", str(metadata),
                                       "--out-root", str(root / "results")]), 0)
            content = next((root / "results").glob("*/summary.json")).read_text()
            self.assertEqual(json.loads(content)["coverage"]["kernel_drops"], 3)
            self.assertNotIn("DO_NOT_EXPORT", content)

    def test_corrupt_pcap_fails_without_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            pcap = root / "synthetic.pcap"
            pcap.write_bytes(b"synthetic invalid capture")
            with patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(main(["analyze", str(pcap), "--server", SERVER, "--out-root", str(root / "results")]), 2)
            self.assertFalse((root / "results").exists())
