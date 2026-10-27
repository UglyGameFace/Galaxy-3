"""In-memory Samsung SDB fake watch only; never talk to hardware."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from watch3_r08_android_sdb import VERSION, frame, receive
from watch3_r08_fota_artifact_pull import LOCAL_STREAM, SYNC_HDR
import watch3_r08_recovery_script_pull as script
import watch3_r08_fota_handoff_pull as handoff


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, count):
        part, self.incoming = self.incoming[:count], self.incoming[count:]
        return part

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, value):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def fake_peer(chunks):
    return FakeSocket(
        frame(b"CNXN", VERSION, 262144, b"device::\x00") +
        frame(b"OKAY", 51, LOCAL_STREAM) +
        frame(b"OKAY", 51, LOCAL_STREAM) +
        b"".join(frame(b"WRTE", 51, LOCAL_STREAM, part) for part in chunks)
    )


def success(raw=b"#!/bin/sh\necho 'only for test'\n"):
    blob = SYNC_HDR.pack(b"DATA", len(raw)) + raw
    return fake_peer([blob[:3], blob[3:15], blob[15:],
                      SYNC_HDR.pack(b"DONE", 0)])


def failure():
    message = b"/private/device/serial read denied"
    return fake_peer([SYNC_HDR.pack(b"FAIL", len(message)) + message])


def sent_frames(sock):
    peer = FakeSocket(bytes(sock.sent))
    items = []
    while peer.incoming:
        items.append(receive(peer))
    return items


class RecoveryScriptTests(unittest.TestCase):
    def test_exact_observed_execstart_path_and_single_recv_only(self):
        self.assertEqual(handoff.EVIDENCED_RECOVERY_SCRIPT_PATH,
                         b"/usr/bin/recovery-update.sh")
        sock = success()
        with patch("watch3_r08_recovery_script_pull.socket.create_connection",
                   return_value=sock) as connect:
            raw = script.read_fixed_script("10.0.0.65", Path("/unused"))
        self.assertEqual(raw, b"#!/bin/sh\necho 'only for test'\n")
        self.assertEqual(connect.call_count, 1)
        frames = sent_frames(sock)
        self.assertEqual(frames[1][3], b"sync:\x00")
        remote = handoff.EVIDENCED_RECOVERY_SCRIPT_PATH
        self.assertEqual(frames[2][3], SYNC_HDR.pack(b"RECV", len(remote)) + remote)
        self.assertEqual(sum(f[0] == b"WRTE" for f in frames), 1)
        for disallowed in (b"SEND", b"shell:", b"exec:", b"dbus:", b"/dev/"):
            self.assertNotIn(disallowed, bytes(sock.sent))
        with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_PATH_NOT_ALLOWLISTED"):
            handoff.receive_one(success(), Path("/unused"), b"/etc/shadow")

    def test_fake_watch_failure_is_privacy_safe_and_local_only(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "evidence"
            with patch("watch3_r08_recovery_script_pull.socket.create_connection",
                       return_value=failure()), patch.object(
                sys, "argv", ["probe", "--watch-ip", "10.0.0.65",
                              "--output-dir", str(folder)]):
                self.assertEqual(script.main(), 1)
            self.assertEqual(list(folder.iterdir()), [])

    def test_private_no_clobber_script_and_json(self):
        data = b"#!/bin/sh\n# do not execute\n"
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "evidence"
            with patch("watch3_r08_recovery_script_pull.socket.create_connection",
                       return_value=success(data)), patch.object(
                sys, "argv", ["probe", "--watch-ip", "10.0.0.65",
                              "--output-dir", str(folder)]):
                self.assertEqual(script.main(), 0)
            self.assertEqual(folder.stat().st_mode & 0o077, 0)
            raw = folder / script.RAW_NAME
            report = folder / script.REPORT_NAME
            self.assertEqual(raw.read_bytes(), data)
            self.assertEqual(raw.stat().st_mode & 0o077, 0)
            self.assertEqual(report.stat().st_mode & 0o077, 0)
            summary = json.loads(report.read_text())
            self.assertEqual(summary["bytes"], len(data))
            self.assertEqual(summary["sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(summary["has_shell_shebang"])
            self.assertFalse(summary["script_executed"])
            self.assertFalse(summary["watch_write_performed"])
            before = report.read_bytes()
            with patch.object(sys, "argv", ["probe", "--watch-ip", "10.0.0.65",
                                            "--output-dir", str(folder)]):
                self.assertEqual(script.main(), 1)
            self.assertEqual(report.read_bytes(), before)

    def test_stream_limit_denies_excess_and_remote_access_cannot_be_selected(self):
        huge = b"x" * (handoff.MAX_FILE_BYTES + 1)
        with patch("watch3_r08_recovery_script_pull.socket.create_connection",
                   return_value=success(huge)):
            with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_FILE_EXCEEDS_EIGHT_KIB"):
                script.read_fixed_script("10.0.0.65", Path("/unused"))
        with self.assertRaises(Exception):
            script.read_fixed_script("8.8.8.8", Path("/unused"))


if __name__ == "__main__":
    unittest.main()
