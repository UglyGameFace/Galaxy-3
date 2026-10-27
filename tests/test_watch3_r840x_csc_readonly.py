"""Synthetic only: no-watch proof of one exact Tizen CSC path and no writes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_android_sdb import VERSION, frame, receive
from watch3_r08_fota_artifact_pull import LOCAL_STREAM, SYNC_HDR
import watch3_r840x_csc_readonly as csc


class FakeSocket:
    def __init__(self, inbound):
        self.inbound = inbound
        self.sent = bytearray()

    def recv(self, length):
        piece, self.inbound = self.inbound[:length], self.inbound[length:]
        return piece

    def sendall(self, value):
        self.sent.extend(value)

    def settimeout(self, seconds):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def peer(packets):
    return FakeSocket(
        frame(b"CNXN", VERSION, 262144, b"device::\x00") +
        frame(b"OKAY", 17, LOCAL_STREAM) +
        frame(b"OKAY", 17, LOCAL_STREAM) +
        b"".join(frame(b"WRTE", 17, LOCAL_STREAM, part) for part in packets)
    )


def answer(content, *, fragmented=True):
    combined = SYNC_HDR.pack(b"DATA", len(content)) + content
    parts = [combined[:4], combined[4:9], combined[9:]] if fragmented else [combined]
    parts.append(SYNC_HDR.pack(b"DONE", 0))
    return peer(parts)


def frames(sent):
    read = FakeSocket(bytes(sent))
    result = []
    while read.inbound:
        result.append(receive(read))
    return result


class SafeCscTests(unittest.TestCase):
    def test_fixed_path_is_from_pinned_other_tizen_watch(self):
        self.assertEqual(csc.SOURCE_COMMIT, "3dcd79ca586827ea2fde9a5a23170a79d1a8e2dd")
        self.assertEqual(csc.CSC_PATH, b"/opt/system/csc-default/output/csc-active-customer.log")
        self.assertEqual(csc.MAX_CSC_BYTES, 128)
        self.assertEqual(csc.report_base()["source_watch_model"], "SM-R805U")
        self.assertFalse(csc.report_base()["flash_allowed"])
        # Physically observed Oct 27 on owner's SM-R840X; the note must
        # not keep saying its existence on this model is unverified.
        note = csc.report_base()["note"]
        self.assertIn("SM-R840X", note)
        self.assertIn("PAP", note)
        self.assertNotIn("NOT yet independently", note)
        self.assertIn("does NOT establish", note)

    def test_three_character_code_only_and_unknown_content_remains_unknown(self):
        for candidate in (b"XAR\n", b"VZW\r\n", b"KOO"):
            result = csc.parse_active_csc(candidate)
            self.assertEqual(result["state"], "ACTIVE_CSC_CANDIDATE_READ_FROM_EXACT_TIZEN_PATH")
            self.assertEqual(result["candidate_code"], candidate.decode().strip())
        for invalid in (b"", b"XXX", b"XAR\nSECRET", b"sales_code=XAR",
                        b"xar", b"A/B", b"XAR\0", b"XAR  ", b"\xff\0\xff",
                        b"A" * (csc.MAX_CSC_BYTES + 1)):
            with self.subTest(candidate=repr(invalid)):
                result = csc.parse_active_csc(invalid)
                self.assertIsNone(result["candidate_code"])

    def test_one_allowed_sdb_recv_no_shell_or_send(self):
        stream = answer(b"XAR\n")
        contents = csc.fetch_fixed_csc(stream, Path("/synthetic"))
        self.assertEqual(contents, b"XAR\n")
        packets = frames(bytes(stream.sent))
        self.assertEqual(packets[1][3], b"sync:\x00")
        expected = SYNC_HDR.pack(b"RECV", len(csc.CSC_PATH)) + csc.CSC_PATH
        self.assertEqual(packets[2][3], expected)
        self.assertEqual(sum(x[0] == b"WRTE" for x in packets), 1)
        self.assertFalse(any(y in stream.sent for y in (
            b"SEND", b"shell:", b"/dev/", b"STAT", b"EXEC", b"dbus:",
            b"ODIN", b"LOKE",
        )))

    def test_denied_and_unreadable_never_exposes_private_watch_error(self):
        secret = b"serial secret: file access denied"
        stream = peer([SYNC_HDR.pack(b"FAIL", len(secret)) + secret])
        with self.assertRaisesRegex(csc.CscError, "CSC_FILE_MISSING_DENIED_OR_UNREADABLE") as ctx:
            csc.fetch_fixed_csc(stream, Path("/synthetic"))
        self.assertNotIn("serial", str(ctx.exception))
        with patch("watch3_r840x_csc_readonly.socket.create_connection",
                   side_effect=[peer([SYNC_HDR.pack(b"FAIL", len(secret)) + secret])]):
            failed = csc.collect("10.0.0.65", Path("/synthetic"))
        self.assertEqual(failed["status"], "CSC_NOT_YET_CONFIRMED")
        self.assertEqual(failed["state"], "CSC_FILE_MISSING_DENIED_OR_UNREADABLE")
        self.assertFalse(failed["full_stock_recovery_proven"])

    def test_oversized_remote_stream_refused_before_unbounded_storage(self):
        with self.assertRaisesRegex(csc.CscError, "CSC_LOG_BYTE_LIMIT_EXCEEDED"):
            csc.fetch_fixed_csc(answer(b"X" * (csc.MAX_CSC_BYTES + 1)),
                               Path("/synthetic"))

    def test_owner_real_result_is_only_csc_candidate_and_failure_remains_unknown(self):
        with patch("watch3_r840x_csc_readonly.socket.create_connection",
                   side_effect=[answer(b"BTU\n"), peer([
                       SYNC_HDR.pack(b"FAIL", len(b"secret")) + b"secret"
                   ])]):
            success = csc.collect("10.0.0.65", Path("/synthetic"))
            denied = csc.collect("10.0.0.65", Path("/synthetic"))
        self.assertEqual(success["status"], "CSC_CANDIDATE_FROM_OWNER_WATCH_FIXED_PATH")
        self.assertEqual(success["observed_active_csc_candidate"], "BTU")
        self.assertEqual(denied["state"], "CSC_FILE_MISSING_DENIED_OR_UNREADABLE")
        self.assertIsNone(denied["observed_active_csc_candidate"])
        self.assertEqual(denied["status"], "CSC_NOT_YET_CONFIRMED")
        for result in (success, denied):
            self.assertFalse(result["watch_write_performed"])
            self.assertFalse(result["full_stock_recovery_proven"])
            self.assertFalse(result["odin_session_started"])
            self.assertFalse(result["firmware_written"])
            self.assertFalse(result["flash_allowed"])

    def test_private_exclusive_report_and_no_owner_ip_or_raw_body(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "csc.json"
            with patch("watch3_r840x_csc_readonly.socket.create_connection",
                       side_effect=[answer(b"XAR\n")]):
                self.assertEqual(csc.main(["--watch-ip", "10.0.0.65",
                                           "--output", str(path)]), 0)
            data = path.read_text()
            self.assertEqual(json.loads(data)["observed_active_csc_candidate"], "XAR")
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertNotIn("10.0.0.65", data)
            self.assertNotIn("secret", data)
            with patch("watch3_r840x_csc_readonly.socket.create_connection",
                       side_effect=AssertionError("existing report must PREVENT watch read")):
                # Refuse a duplicate output BEFORE creating even a read-only
                # SDB connection; an existing report remains immutable.
                self.assertEqual(csc.main(["--watch-ip", "10.0.0.65",
                                           "--output", str(path)]), 1)
                self.assertEqual(csc.main(["--offline-sample", str(path),
                                           "--output", str(path)]), 1)
            self.assertEqual(path.read_text(), data)

    def test_offline_sample_does_not_claim_real_watch_csc_or_open_network(self):
        with tempfile.TemporaryDirectory() as td:
            local = Path(td) / "test.txt"
            local.write_bytes(b"XAR\n")
            outfile = Path(td) / "out.json"
            with patch("watch3_r840x_csc_readonly.socket.create_connection",
                       side_effect=AssertionError("offline must not connect")):
                self.assertEqual(csc.main(["--offline-sample", str(local),
                                           "--output", str(outfile)]), 0)
            report = json.loads(outfile.read_text())
            self.assertIsNone(report["observed_active_csc_candidate"])
            self.assertEqual(report["status"], "CSC_NOT_YET_CONFIRMED")
            self.assertTrue(report["state"].startswith("OFFLINE_SAMPLE_"))

    def test_private_ip_enforced_and_no_arbitrary_paths(self):
        with self.assertRaises(Exception):
            csc.collect("8.8.8.8", Path("/synthetic"))
        self.assertNotIn(b"/dev/", csc.CSC_PATH)
        self.assertNotIn(b"../", csc.CSC_PATH)


if __name__ == "__main__":
    unittest.main()
