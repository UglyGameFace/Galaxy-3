"""Completely fake Samsung SDB peer; never contacts a real watch."""
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_android_sdb import (
    Connection, HEADER, PORT, SdbError, VERSION, adb_public_key,
    collect, diagnose, frame, private_watch_ip, read_exact, receive,
)
from watch3_r08_live_boot_probe import PROBES, summarize


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()
        self.timeout = None

    def recv(self, size):
        result = self.incoming[:size]
        self.incoming = self.incoming[size:]
        return result

    def sendall(self, value):
        self.sent.extend(value)

    def settimeout(self, value):
        self.timeout = value

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def decode_all(value):
    result = []
    socket_mock = FakeSocket(value)
    while socket_mock.incoming:
        result.append(receive(socket_mock))
    return result


def peer(what):
    return (
        frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00")
        + frame(b"OKAY", 42, 2)
        + frame(b"WRTE", 42, 2, what.encode())
        + frame(b"CLSE", 42, 2)
    )


class AndroidSdbTests(unittest.TestCase):
    def test_packet_layout_matches_samsung_sdb_capture(self):
        packet = frame(b"CNXN", VERSION, 256 * 1024, b"host::\x00")
        self.assertEqual(len(packet), 24 + len(b"host::\x00"))
        values = struct.unpack("<6I", packet[:24])
        self.assertEqual(values[0], int.from_bytes(b"CNXN", "little"))
        self.assertEqual(values[1], VERSION)
        self.assertEqual(values[3], 7)
        self.assertEqual(values[4], sum(b"host::\x00"))
        self.assertEqual(values[5], values[0] ^ 0xffffffff)
        self.assertEqual(decode_all(packet)[0][-1], b"host::\x00")

    def test_torn_packets_reassembled_and_invalid_checksums_rejected(self):
        class Fragment:
            def __init__(self, data):
                self.data = data
            def recv(self, n):
                a, self.data = self.data[:1], self.data[1:]
                return a
        self.assertEqual(receive(Fragment(frame(b"WRTE", 9, 8, b"abc")))[-1], b"abc")
        corrupted = bytearray(frame(b"WRTE", 9, 8, b"abc"))
        corrupted[-1] ^= 1
        with self.assertRaisesRegex(SdbError, "checksum mismatch"):
            receive(FakeSocket(bytes(corrupted)))
        with self.assertRaisesRegex(SdbError, "closed"):
            read_exact(FakeSocket(b"ab"), 3)

    def test_successful_read_only_handshake_and_command(self):
        sock = FakeSocket(peer("Linux version 4.9.59 (PRIVATE)\n"))
        client = Connection(sock, Path("/not-used"))
        client.handshake()
        result = client.shell("version")
        self.assertTrue(result.startswith("Linux version 4.9.59"))
        outgoing = decode_all(bytes(sock.sent))
        self.assertEqual([x[0] for x in outgoing],
                         [b"CNXN", b"OPEN", b"OKAY", b"CLSE"])
        self.assertEqual(outgoing[1][3], b"shell:cat /proc/version\x00")
        self.assertEqual(outgoing[2][1:3], (2, 42))
        self.assertEqual(outgoing[3][1:3], (2, 42))

    def test_remote_shell_never_accepts_arbitrary_string(self):
        socket_mock = FakeSocket(b"")
        client = Connection(socket_mock, Path("/nope"))
        for operation in ("reboot", "cat /proc/cmdline; id", "dd", ""):
            with self.assertRaisesRegex(SdbError, "allowlist"):
                client.shell(operation)
        self.assertEqual(bytes(socket_mock.sent), b"")

    def test_service_denied_is_not_treated_as_real_boot_data(self):
        sock = FakeSocket(frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00")
                          + frame(b"CLSE", 0, 2))
        client = Connection(sock, Path("/unused"))
        client.handshake()
        with self.assertRaisesRegex(SdbError, "denied"):
            client.shell("cmdline")

    def test_unsolicited_auth_rejected_without_credentials(self):
        sock = FakeSocket(frame(b"AUTH", 99, 0, b"not auth"))
        with self.assertRaisesRegex(SdbError, "Unexpected"):
            Connection(sock, Path("/unused")).handshake()

    def test_mock_auth_token_and_public_key_approval_flow(self):
        sock = FakeSocket(
            frame(b"AUTH", 1, 0, b"a" * 20)
            + frame(b"AUTH", 1, 0, b"b" * 20)
            + frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00"))
        with patch("watch3_r08_android_sdb.sign_auth_token",
                   return_value=b"x" * 256) as signed, patch(
                       "watch3_r08_android_sdb.adb_public_key",
                       return_value=b"PUBKEY\x00") as public:
            Connection(sock, Path("private")).handshake()
        signed.assert_called_once_with(Path("private"), b"a" * 20)
        public.assert_called_once_with(Path("private"))
        sent = decode_all(bytes(sock.sent))
        self.assertEqual([x[0] for x in sent],
                         [b"CNXN", b"AUTH", b"AUTH"])
        self.assertEqual(sent[1][1], 2)
        self.assertEqual(sent[2][1], 3)

    def test_actual_crypto_key_structure_when_dependency_installed(self):
        try:
            import cryptography  # noqa
        except ImportError:
            self.skipTest("Optional cryptography dependency unavailable")
        with tempfile.TemporaryDirectory() as td:
            from watch3_r08_android_sdb import sign_auth_token
            key_path = Path(td) / "config" / "key"
            signature = sign_auth_token(key_path, b"x" * 20)
            pub = adb_public_key(key_path)
            self.assertEqual(len(signature), 256)
            self.assertIn(b" watch3-termux\x00", pub)
            self.assertEqual(key_path.stat().st_mode & 0o077, 0)
            # ADB RSA public structure is 524 bytes before base64.
            import base64
            self.assertEqual(len(base64.b64decode(pub.split()[0])), 524)

    def test_ip_check_allows_private_not_remote_server_or_hostname(self):
        self.assertEqual(private_watch_ip("192.168.2.32"), "192.168.2.32")
        for invalid in ("not-a-watch", "8.8.8.8"):
            with self.assertRaises(SdbError):
                private_watch_ip(invalid)

    def test_real_collection_mock_outputs_redact_serial_and_ip(self):
        data = {
            "cmdline": "root=/dev/ram0 androidboot.serialno=ABC-secret",
            "version": "Linux version 4.9.59 builder@private",
            "partitions": "179 0 10000 mmcblk0\n",
            "model": "NOBLESSE-LARGE-BT",
        }
        watched = []
        def fake_connect(addr, timeout):
            self.assertEqual(addr, ("192.168.1.34", PORT))
            watched.append(addr)
            # Each connection gets a fresh pre-scripted read-only service.
            name = list(PROBES)[len(watched) - 1]
            return FakeSocket(peer(data.get(name, "No such file or directory")))
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=fake_connect):
            observed, missing = collect("192.168.1.34", Path("unused"))
        report = summarize(observed, missing)
        payload = json.dumps(report)
        self.assertNotIn("ABC-secret", payload)
        self.assertNotIn("builder@private", payload)
        self.assertNotIn("192.168.1.34", payload)
        self.assertEqual(len(watched), len(PROBES))
        self.assertFalse(report["flashing_authorized"])

    def test_hotspot_diagnosis_identifies_tcp_refused(self):
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=ConnectionRefusedError("private address hidden")):
            with self.assertRaisesRegex(SdbError, r"FAIL\[tcp-refused\].*26101"):
                diagnose("10.54.86.131", Path("/unused"))
        # Never embed private watch IP or socket error in the exception.
        try:
            with patch("watch3_r08_android_sdb.socket.create_connection",
                       side_effect=ConnectionRefusedError("10.54.86.131")):
                diagnose("10.54.86.131", Path("/unused"))
        except SdbError as exc:
            self.assertNotIn("10.54.86.131", str(exc))

    def test_hotspot_diagnosis_identifies_timeout(self):
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=socket.timeout):
            with self.assertRaisesRegex(SdbError, r"FAIL\[tcp-timeout\]"):
                diagnose("10.54.86.131", Path("/unused"))

    def test_diagnosis_isolates_sdb_protocol_failure_after_tcp(self):
        messages = []
        fake = FakeSocket(frame(b"AUTH", 99, 0, b"private"))
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   return_value=fake):
            with self.assertRaisesRegex(SdbError, r"FAIL\[sdb\]"):
                diagnose("10.54.86.131", Path("/unused"),
                         output=messages.append)
        self.assertEqual(len(messages), 1)
        self.assertTrue(messages[0].startswith("PASS[tcp]"))

    def test_diagnosis_never_prints_raw_shell_output(self):
        messages = []
        fake = FakeSocket(peer("private raw serialABC\n"))
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   return_value=fake):
            with self.assertRaisesRegex(SdbError, r"FAIL\[shell\]") as caught:
                diagnose("10.54.86.131", Path("/unused"),
                         output=messages.append)
        self.assertNotIn("serialABC", str(caught.exception))
        self.assertNotIn("serialABC", "\n".join(messages))
        outgoing = decode_all(bytes(fake.sent))
        operations = [x[3] for x in outgoing if x[0] == b"OPEN"]
        self.assertEqual(operations, [b"shell:cat /proc/version\x00"])

    def test_hotspot_diagnosis_can_pass_mock_port_sdb_and_shell(self):
        messages = []
        fake = FakeSocket(peer("Linux version 4.9.59 builder@private\n"))
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   return_value=fake):
            diagnose("10.54.86.131", Path("/unused"),
                     output=messages.append)
        self.assertEqual([m.split(":")[0] for m in messages[:3]],
                         ["PASS[tcp]", "PASS[sdb]", "PASS[shell]"])
        self.assertNotIn("builder@private", "\n".join(messages))

    def test_no_unsafe_commands_or_watch_writes_in_direct_client(self):
        file = (Path(__file__).resolve().parents[1] /
                "tools/watch3_r08_android_sdb.py").read_text()
        for forbidden in ("fastboot flash", "sdb root on", "dd if=",
                          "heimdall flash", "shell=True", "shell:reboot"):
            self.assertNotIn(forbidden, file)


if __name__ == "__main__":
    unittest.main()
