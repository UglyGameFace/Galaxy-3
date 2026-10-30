"""In-memory Samsung SDB fake watch only; never talk to hardware."""
from __future__ import annotations

import hashlib
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from watch3_r08_android_sdb import VERSION, frame, receive
from watch3_r08_fota_artifact_pull import LOCAL_STREAM, SYNC_HDR
import watch3_r08_recovery_script_pull as script
import watch3_r08_fota_handoff_pull as handoff
from watch3_r08_android_sdb import Connection, RECOVERY_CONTEXT_READS, MAX_OUTPUT, SdbError


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
    def test_update_prepare_reads_the_new_literal_proven_by_the_original_consumer_only(self):
        remote = b"/usr/bin/rw-update-prepare.sh"
        self.assertEqual(handoff.EVIDENCED_UPDATE_PREPARE_SCRIPT_PATH, remote)
        sock = success()
        with patch.object(script.socket, "create_connection", return_value=sock) as connect:
            raw = script.read_fixed_script("10.0.0.65", Path("/unused"), component="update-prepare")
        self.assertTrue(raw.startswith(b"#!/bin/sh"))
        self.assertEqual(connect.call_count, 1)
        frames = sent_frames(sock)
        self.assertEqual(frames[2][3], SYNC_HDR.pack(b"RECV", len(remote)) + remote)
        self.assertNotIn(b"recovery-update.sh", bytes(sock.sent))
        for prohibited in (b"SEND", b"shell:", b"exec:", b"/dev/", b"FOTA"):
            self.assertNotIn(prohibited, bytes(sock.sent))

    def test_update_prepare_output_is_separate_private_and_exclusive(self):
        with tempfile.TemporaryDirectory() as td, patch.object(script.Path, "home", return_value=Path(td)), \
                patch.object(script.socket, "create_connection", return_value=success()) as connect:
            args = ["--watch-ip", "10.0.0.65", "--component", "update-prepare"]
            self.assertEqual(script.main(args), 0)
            folder = Path(td) / "watch3-r840x-update-prepare-evidence"
            report = folder / "update-prepare-report.json"
            data = json.loads(report.read_text())
            self.assertEqual(data["remote_path"], "/usr/bin/rw-update-prepare.sh")
            self.assertEqual(data["status"], "UPDATE_PREPARE_SCRIPT_READ_ONLY_RETRIEVED")
            self.assertFalse(data["script_executed"])
            self.assertFalse(data["watch_write_performed"])
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)
            self.assertEqual((folder / "rw-update-prepare.sh").stat().st_mode & 0o777, 0o600)
            before = report.read_bytes()
            self.assertEqual(script.main(args), 1)
            self.assertEqual(report.read_bytes(), before)
            self.assertEqual(connect.call_count, 1)
            self.assertFalse((Path(td) / "watch3-r840x-recovery-script-evidence").exists())

    def test_update_prepare_denial_stops_and_unknown_component_cannot_connect(self):
        with patch.object(script.socket, "create_connection", return_value=failure()) as connect:
            with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_MISSING_DENIED_OR_UNREADABLE"):
                script.read_fixed_script("10.0.0.65", Path("/unused"), component="update-prepare")
            self.assertEqual(connect.call_count, 1)
        with patch.object(script.socket, "create_connection") as connect:
            with self.assertRaisesRegex(handoff.HandoffError, "SCRIPT_COMPONENT_NOT_ALLOWLISTED"):
                script.read_fixed_script("10.0.0.65", Path("/unused"), component="/etc/shadow")
            connect.assert_not_called()
        with patch.object(script.socket, "create_connection", return_value=success(b"x" * (handoff.MAX_FILE_BYTES + 1))):
            with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_FILE_EXCEEDS_EIGHT_KIB"):
                script.read_fixed_script("10.0.0.65", Path("/unused"), component="update-prepare")

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


class RecoveryShellContextTests(unittest.TestCase):
    def incoming(self, raw):
        # Use exact bytes, including invalid UTF-8, to test evidence preservation.
        return FakeSocket(frame(b'CNXN', VERSION, 262144, b'device::\0') +
                          frame(b'OKAY', 42, 2) + frame(b'WRTE', 42, 2, raw) + frame(b'CLSE', 42, 2))

    def payloads(self):
        return {name: b'#!/bin/sh\n# original-byte-\xff\n' if name.endswith('.sh') else
                b'[Service]\nUser=root\n# private-unit-value\n' if name.endswith('.service') else
                b'private-metadata-value\n' for name in RECOVERY_CONTEXT_READS}

    def capture(self, root):
        return script.capture_shell_context('10.0.0.65', Path('/unused'), root / 'context',
                                            archive=root / 'context.zip')

    def test_complete_native_shell_capture_preserves_raw_bytes_and_uses_only_fixed_reads(self):
        payloads = self.payloads()
        sockets = [self.incoming(raw) for raw in payloads.values()]
        with tempfile.TemporaryDirectory() as td, patch.object(script.socket, 'create_connection', side_effect=sockets) as connect:
            root = Path(td)
            report = self.capture(root)
            self.assertEqual(report['state'], 'RECOVERY_SCRIPTS_CAPTURED_VIA_SHELL')
            self.assertEqual(report['script_payloads_copied'], 3)
            self.assertFalse(report['payload_hashes_are_independent_disk_hashes'])
            self.assertFalse(report['on_disk_file_completeness_verified'])
            self.assertFalse(report['root_mode_requested'])
            self.assertEqual(connect.call_count, len(RECOVERY_CONTEXT_READS))
            self.assertNotIn('private-unit-value', json.dumps(report))
            self.assertNotIn('private-metadata-value', json.dumps(report))
            with zipfile.ZipFile(root / 'context.zip') as z:
                self.assertEqual(set(z.namelist()), {script.CONTEXT_REPORT, *payloads})
                for name, raw in payloads.items():
                    self.assertEqual(z.read(name), raw)
            for path in [root / 'context', root / 'context.zip', *(root / 'context').iterdir()]:
                self.assertEqual(path.stat().st_mode & 0o077, 0)
        for sock, command in zip(sockets, RECOVERY_CONTEXT_READS.values()):
            frames = sent_frames(sock)
            self.assertEqual([f[3] for f in frames if f[0] == b'OPEN'],
                             [('shell:' + command).encode() + b'\0'])
            self.assertTrue(all(f[0] not in (b'WRTE',) for f in frames))
            self.assertNotIn(b'root:on', sock.sent)
            self.assertNotIn(b'/dev/mmc', sock.sent)
            self.assertNotIn(b'SEND', sock.sent)

    def test_cat_error_is_private_diagnostic_not_a_copied_script(self):
        error = b'cat: private-error-value: Permission denied\n'
        sockets = [self.incoming(error) for _ in RECOVERY_CONTEXT_READS]
        with tempfile.TemporaryDirectory() as td, patch.object(script.socket, 'create_connection', side_effect=sockets):
            root = Path(td)
            report = self.capture(root)
            self.assertEqual(report['state'], 'RECOVERY_SHELL_CONTEXT_PARTIAL')
            self.assertEqual(report['script_payloads_copied'], 0)
            self.assertNotIn('private-error-value', json.dumps(report))
            self.assertEqual(report['files'][0]['status'], 'RESPONSE_NOT_VERIFIED_AS_SCRIPT')
            with zipfile.ZipFile(root / 'context.zip') as z:
                self.assertNotIn('recovery-update.sh', z.namelist())
                self.assertEqual(z.read('recovery-update.sh.response'), error)

    def test_refused_shell_preserves_other_captures_and_always_creates_zip(self):
        closed = FakeSocket(frame(b'CNXN', VERSION, 262144, b'device::\0') + frame(b'CLSE', 0, 2))
        payloads = self.payloads()
        sockets = [closed] + [self.incoming(raw) for raw in list(payloads.values())[1:]]
        with tempfile.TemporaryDirectory() as td, patch.object(script.socket, 'create_connection', side_effect=sockets):
            root = Path(td)
            report = self.capture(root)
            self.assertEqual(report['script_payloads_copied'], 2)
            self.assertEqual(report['files'][0]['status'], 'SHELL_READ_REFUSED_OR_IO_ERROR')
            with zipfile.ZipFile(root / 'context.zip') as z:
                self.assertEqual(z.read('rw-update-prepare.sh'), payloads['rw-update-prepare.sh'])
                self.assertNotIn('recovery-update.sh', z.namelist())

    def test_oversized_payload_cannot_publish_a_script(self):
        payloads = self.payloads()
        sockets = [self.incoming(b'#!/bin/sh\n' + b'x' * MAX_OUTPUT)]
        sockets += [self.incoming(raw) for raw in list(payloads.values())[1:]]
        with tempfile.TemporaryDirectory() as td, patch.object(script.socket, 'create_connection', side_effect=sockets):
            root = Path(td)
            report = self.capture(root)
            self.assertEqual(report['script_payloads_copied'], 2)
            self.assertFalse((root / 'context/recovery-update.sh').exists())

    def test_unknown_entry_never_sends_a_command(self):
        sock = FakeSocket(b'')
        client = Connection(sock, Path('/unused'))
        for entry in ('/etc/shadow', 'root:on', 'reboot', '../recovery-update.sh'):
            with self.assertRaisesRegex(SdbError, 'not allowlisted'):
                client.recovery_context_read(entry)
        self.assertEqual(sock.sent, b'')

    def test_cli_failure_creates_new_diagnostics_and_preserves_existing_archive(self):
        with tempfile.TemporaryDirectory() as td, patch.object(script.Path, 'home', return_value=Path(td)), \
                patch.object(script.socket, 'create_connection', side_effect=OSError('private-address')) as connect:
            root = Path(td)
            args = ['--watch-ip', '10.0.0.65', '--shell-context', '--archive', str(root / 'context.zip')]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(script.main(args), 1)
            self.assertEqual(connect.call_count, len(RECOVERY_CONTEXT_READS))
            with zipfile.ZipFile(root / 'context.zip') as z:
                self.assertEqual(z.namelist(), [script.CONTEXT_REPORT])
                self.assertNotIn(b'private-address', z.read(script.CONTEXT_REPORT))
            before = (root / 'context.zip').read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(script.main(args), 1)
            self.assertEqual((root / 'context.zip').read_bytes(), before)
            self.assertEqual(connect.call_count, len(RECOVERY_CONTEXT_READS))


if __name__ == "__main__":
    unittest.main()
