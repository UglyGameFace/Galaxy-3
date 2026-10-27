"""Synthetic-only transport-stage regression. No Watch3 contact or files read."""
from __future__ import annotations

import errno
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from watch3_r08_android_sdb import SdbError, VERSION, frame, receive
import watch3_r840x_partition_sysfs_readonly as probe


class FakeConnection:
    def __init__(self, data=None):
        self.inbound = bytearray(data or frame(
            b"CNXN", VERSION, 256 * 1024, b"device::\x00"
        ))
        self.sent = bytearray()
        self.timeout = None
        self.closed = False

    def recv(self, amount):
        part = bytes(self.inbound[:amount])
        del self.inbound[:amount]
        return part

    def sendall(self, bytes_):
        self.sent.extend(bytes_)

    def settimeout(self, timeout):
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        return False


class SdbConnectionOnlyTests(unittest.TestCase):
    def test_exact_one_socket_and_sdb_hello_no_shell_sysfs_or_odin(self):
        fake = FakeConnection()
        with patch("watch3_r840x_partition_sysfs_readonly.socket.create_connection",
                   return_value=fake) as connected, patch(
            "watch3_r840x_partition_sysfs_readonly.collect",
            side_effect=AssertionError("NO SYSFS/FILES")):
            result = probe.inspect_sdb_connection_only("10.0.0.65", Path("/unused"))
        connected.assert_called_once_with(("10.0.0.65", 26101), timeout=4)
        self.assertTrue(fake.closed)
        self.assertTrue(result["tcp_connected"])
        self.assertEqual(result["tcp_error_category"], "NOT_APPLICABLE")
        self.assertTrue(result["sdb_handshake_completed"])
        self.assertEqual(result["state"], "SDB_HANDSHAKE_COMPLETE_NO_SYSFS_READ")
        self.assertIs(result["remote_device_identity_verified"], False)
        self.assertEqual(result["source_path_expression"], [])
        frames = FakeConnection(bytes(fake.sent))
        actual = []
        while frames.inbound:
            actual.append(receive(frames))
        self.assertEqual([f[0] for f in actual], [b"CNXN"])
        self.assertEqual(actual[0][3], b"host::\x00")
        self.assertNotIn(b"/sys/", bytes(fake.sent))
        self.assertNotIn(b"shell:", bytes(fake.sent))
        self.assertNotIn(b"/dev/", bytes(fake.sent))
        for key in ("owner_watch_sysfs_observed", "raw_partition_bytes_read",
                    "pit_requested", "odin_session_started", "watch_write_performed",
                    "stock_recovery_proven", "bootloader_acceptance_proven",
                    "flash_allowed"):
            self.assertFalse(result[key], key)
        self.assertEqual(result["result"], "NO_GO")

    def test_network_failures_have_safe_distinct_codes(self):
        variants = [
            (ConnectionRefusedError("address PRIVATE_TEXT refused"), "TCP_PORT_REFUSED"),
            (socket.timeout("PRIVATE_TEXT timeout"), "TCP_CONNECT_TIMED_OUT"),
            (OSError("watch IP PRIVATE_TEXT unreachable"), "TCP_NETWORK_UNREACHABLE_OR_BLOCKED"),
        ]
        for error, state in variants:
            with self.subTest(state=state), patch(
                "watch3_r840x_partition_sysfs_readonly.socket.create_connection",
                side_effect=error
            ), patch("watch3_r840x_partition_sysfs_readonly.collect",
                     side_effect=AssertionError("no sysfs")):
                result = probe.inspect_sdb_connection_only("10.0.0.65", Path("/unused"))
            self.assertFalse(result["tcp_connected"])
            self.assertFalse(result["sdb_handshake_completed"])
            self.assertEqual(result["state"], state)
            self.assertNotIn("PRIVATE_TEXT", json.dumps(result))

    def test_errno_classifies_phone_route_vs_android_policy_without_leaking(self):
        # Only synthetic phone-side exceptions; do not probe a real target.
        examples = [
            (errno.ENETUNREACH, "PHONE_HAS_NO_ROUTE_TO_TARGET"),
            (errno.EHOSTUNREACH, "TARGET_HOST_UNREACHABLE_ON_CURRENT_NETWORK"),
            (errno.ENETDOWN, "PHONE_NETWORK_INTERFACE_DOWN"),
            (errno.EPERM, "ANDROID_OS_OR_VPN_SOCKET_POLICY_BLOCKED"),
            (errno.EACCES, "ANDROID_OS_OR_VPN_SOCKET_POLICY_BLOCKED"),
            (errno.EADDRNOTAVAIL, "LOCAL_SOURCE_ADDRESS_NOT_AVAILABLE"),
            (errno.ETIMEDOUT, "OS_REPORTED_TCP_CONNECT_TIMEOUT"),
            (errno.EINVAL, "OTHER_PHONE_SIDE_CONNECT_ERROR"),
        ]
        for errorno, category in examples:
            error = OSError(errorno, "private phone/watch address TOKEN")
            with self.subTest(errno=errorno), patch(
                "watch3_r840x_partition_sysfs_readonly.socket.create_connection",
                side_effect=error
            ) as attempted, patch(
                "watch3_r840x_partition_sysfs_readonly.collect",
                side_effect=AssertionError("NEVER OPEN SYSFS WHEN TCP FAILS")
            ):
                result = probe.inspect_sdb_connection_only("10.0.0.65", Path("/unused"))
            attempted.assert_called_once_with(("10.0.0.65", 26101), timeout=4)
            self.assertEqual(result["state"], "TCP_NETWORK_UNREACHABLE_OR_BLOCKED")
            self.assertEqual(result["tcp_error_category"], category)
            self.assertFalse(result["tcp_connected"])
            self.assertFalse(result["sdb_handshake_completed"])
            self.assertFalse(result["owner_watch_sysfs_observed"])
            self.assertFalse(result["flash_allowed"])
            redacted = json.dumps(result)
            self.assertNotIn("TOKEN", redacted)
            self.assertNotIn("10.0.0.65", redacted)

    def test_after_tcp_failures_not_mislabelled_network_port(self):
        states = [
            (SdbError("Watch authorization failed; approve prompt on watch"),
             "SDB_AUTHORIZATION_OR_LOCAL_KEY_UNAVAILABLE"),
            (SdbError("Unexpected SDB authorization response"),
             "SDB_AUTHORIZATION_OR_LOCAL_KEY_UNAVAILABLE"),
            (SdbError("Unexpected frame with PRIVATE_TEXT"),
             "SDB_HANDSHAKE_PROTOCOL_FAILED"),
            (socket.timeout("PRIVATE_TEXT timeout"), "SDB_HANDSHAKE_TIMED_OUT"),
            (OSError("PRIVATE_TEXT broken socket"), "SDB_HANDSHAKE_IO_FAILURE"),
        ]
        for failure, category in states:
            class BrokenSdb:
                def __init__(self, *_): pass

                def handshake(self):
                    raise failure
            with self.subTest(category=category), patch(
                "watch3_r840x_partition_sysfs_readonly.socket.create_connection",
                return_value=FakeConnection()
            ), patch("watch3_r840x_partition_sysfs_readonly.Connection",
                     BrokenSdb):
                report = probe.inspect_sdb_connection_only("10.0.0.65", Path("/unused"))
            self.assertTrue(report["tcp_connected"])
            self.assertFalse(report["sdb_handshake_completed"])
            self.assertEqual(report["state"], category)
            self.assertNotIn("PRIVATE_TEXT", json.dumps(report))

    def test_report_is_private_redacted_and_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "watch3-sdb-connect.json"
            fake = FakeConnection()
            with patch("watch3_r840x_partition_sysfs_readonly.socket.create_connection",
                       return_value=fake):
                rc = probe.main([
                    "--watch-ip", "10.0.0.65",
                    "--connection-only", "--report", str(path)
                ])
            self.assertEqual(rc, 0)
            report = json.loads(path.read_text())
            self.assertEqual(report["probe_mode"], "SINGLE_SDB_TCP_HANDSHAKE_NO_SHELL_OR_SYSFS")
            self.assertEqual(report["state"], "SDB_HANDSHAKE_COMPLETE_NO_SYSFS_READ")
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertNotIn("10.0.0.65", path.read_text())
            before = path.read_bytes()
            with patch("watch3_r840x_partition_sysfs_readonly.socket.create_connection",
                       side_effect=AssertionError("REPORT ALREADY EXISTS; DO NOT CONNECT")):
                self.assertEqual(probe.main([
                    "--watch-ip", "10.0.0.65",
                    "--connection-only", "--report", str(path)
                ]), 1)
            self.assertEqual(path.read_bytes(), before)

    def test_bad_mode_combinations_and_public_ip_never_connect(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "fake.txt"
            sample.write_text("MAJOR=179\n")
            path = Path(tmp) / "fresh.json"
            with patch("watch3_r840x_partition_sysfs_readonly.socket.create_connection",
                       side_effect=AssertionError("NO NETWORK")):
                self.assertEqual(probe.main([
                    "--watch-ip", "10.0.0.65", "--connection-only",
                    "--fixed-paths", "--report", str(path)
                ]), 1)
                self.assertEqual(probe.main([
                    "--offline-sample", str(sample), "--connection-only",
                    "--report", str(path)
                ]), 1)
                self.assertEqual(probe.main([
                    "--watch-ip", "8.8.8.8", "--connection-only",
                    "--report", str(path)
                ]), 1)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
