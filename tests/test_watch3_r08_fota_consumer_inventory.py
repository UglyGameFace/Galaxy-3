"""Only synthetic SDB peers. No watch connection, update, shell or directory writes."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_android_sdb import VERSION, frame, receive
from watch3_r08_fota_consumer_inventory import (
    SYNC_HDR, SYNC_DENT, LOCAL_STREAM, DIRECTORIES, InventoryError,
    DirectoryDecoder, list_one, inventory, main,
)


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, count):
        head, self.incoming = self.incoming[:count], self.incoming[count:]
        return head

    def sendall(self, body):
        self.sent.extend(body)

    def settimeout(self, seconds):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def dent(name, mode=stat.S_IFREG | 0o755, size=123):
    name = name.encode("utf-8")
    return SYNC_DENT.pack(b"DENT", mode, size, 1, len(name)) + name


def done():
    return SYNC_DENT.pack(b"DONE", 0, 0, 0, 0)


def peer(chunks):
    return FakeSocket(
        frame(b"CNXN", VERSION, 262144, b"device::\x00") +
        frame(b"OKAY", 52, LOCAL_STREAM) +
        frame(b"OKAY", 52, LOCAL_STREAM) +
        b"".join(frame(b"WRTE", 52, LOCAL_STREAM, part) for part in chunks)
    )


def outgoing(sock):
    fake = FakeSocket(bytes(sock.sent))
    results = []
    while fake.incoming:
        results.append(receive(fake))
    return results


class FixedFotaDirectoryInventoryTests(unittest.TestCase):
    def test_allowlist_only_two_read_only_sync_list_operations(self):
        self.assertEqual(set(DIRECTORIES), {
            "consumer_binary_directory", "fota_save_directory",
        })
        for path in DIRECTORIES.values():
            self.assertTrue(path.startswith(b"/"))
            self.assertNotIn(b"..", path)
            self.assertNotIn(b"/dev/", path)
            self.assertNotIn(b"\x00", path)

    def test_fragmented_dent_headers_and_names(self):
        data = dent("fota-service") + dent("fota-consumer") + (
            dent("private-owner-SECRET")) + done()
        sock = peer([data[:3], data[3:17], data[17:29],
                     data[29:64], data[64:]])
        result = list_one(sock, Path("/unused"), "consumer_binary_directory")
        self.assertEqual(result["status"], "LIST_COMPLETE")
        self.assertEqual(list(result["matching_executable_candidates"]),
                         ["fota-service", "fota-consumer"])
        self.assertEqual(result["other_or_unreported_entries"], 1)
        self.assertNotIn("SECRET", json.dumps(result))
        frames = outgoing(sock)
        self.assertEqual(frames[1][3], b"sync:\x00")
        self.assertEqual(frames[2][3], SYNC_HDR.pack(
            b"LIST", len(DIRECTORIES["consumer_binary_directory"])) +
            DIRECTORIES["consumer_binary_directory"])
        self.assertEqual(sum(f[0] == b"WRTE" for f in frames), 1)
        self.assertNotIn(b"SEND", bytes(sock.sent))
        self.assertNotIn(b"RECV", bytes(sock.sent))
        self.assertNotIn(b"shell:", bytes(sock.sent))

    def test_fixed_archive_permission_bits_only_not_smack_proof(self):
        records = dent("delta.tar", stat.S_IFREG | 0o666, size=930) + done()
        report = list_one(peer([records]),
                          Path("/unused"), "fota_save_directory")
        self.assertEqual(report["delta_tar"]["kind"], "REGULAR_FILE")
        self.assertTrue(report["delta_tar"]["other_writable_dac"])
        self.assertIn("SMACK", report["meaning"])

    def test_empty_list_never_claims_empty_or_absent_fota(self):
        report = list_one(peer([done()]), Path("/unused"),
                          "consumer_binary_directory")
        self.assertEqual(report["status"], "EMPTY_OR_INACCESSIBLE")
        self.assertEqual(report["matching_executable_candidates"], {})

    def test_dent_extra_unlisted_binary_is_privacy_filtered(self):
        data = dent("fota-consumer") + dent(".private_token") + (
            dent("private_file_user_email.txt")) + done()
        report = list_one(peer([data]), Path("/unused"),
                          "consumer_binary_directory")
        self.assertNotIn("private", json.dumps(report))
        self.assertEqual(report["other_or_unreported_entries"], 2)

    def test_fragmented_fail_redacts_private_remote_output(self):
        result = b"Permission denied /private/serial-ABC"
        error = SYNC_HDR.pack(b"FAIL", len(result)) + result
        sock = peer([error[:4], error[4:12], error[12:]])
        with self.assertRaisesRegex(
                InventoryError, "DIRECTORY_LIST_DENIED_OR_UNSUPPORTED"):
            list_one(sock, Path("/unused"), "consumer_binary_directory")

    def test_malformed_or_oversize_dent_fails_closed(self):
        decoder = DirectoryDecoder()
        with self.assertRaisesRegex(InventoryError, "INVALID_DIRECTORY_NAME_LENGTH"):
            decoder.feed(SYNC_DENT.pack(b"DENT", 0, 0, 0, 193),
                         "consumer_binary_directory")
        decoder = DirectoryDecoder()
        with self.assertRaisesRegex(InventoryError, "INVALID_SYNC_LIST_DONE"):
            decoder.feed(SYNC_DENT.pack(b"DONE", 1, 0, 0, 0),
                         "consumer_binary_directory")
        decoder = DirectoryDecoder()
        with self.assertRaisesRegex(InventoryError, "UNEXPECTED_SYNC_REPLY"):
            decoder.feed(SYNC_HDR.pack(b"SEND", 0),
                         "consumer_binary_directory")

    def test_missing_done_fails_and_is_not_an_empty_directory(self):
        sock = peer([dent("fota-service")])
        with self.assertRaises(Exception):
            list_one(sock, Path("/unused"), "consumer_binary_directory")

    def test_both_scopes_are_independent_and_privacy_redacted(self):
        binary = peer([dent("fota-consumer") + done()])
        save = peer([dent("delta.tar", stat.S_IFREG | 0o600) + done()])
        with patch("watch3_r08_fota_consumer_inventory.socket.create_connection",
                   side_effect=[binary, save]) as connect:
            report = inventory("10.0.0.65", Path("/unused"))
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(report["directory_results"]["consumer_binary_directory"]
                         ["matching_executable_candidates"]["fota-consumer"]["kind"],
                         "REGULAR_FILE")
        self.assertFalse(report["watch_write_performed"])
        self.assertFalse(report["consumer_binary_retrieved"])
        self.assertNotIn("10.0.0.65", json.dumps(report))

    def test_report_on_phone_exclusive_private_and_no_overwrite(self):
        binary = peer([dent("fota-service") + done()])
        save = peer([done()])
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "result.json"
            with patch("watch3_r08_fota_consumer_inventory.socket.create_connection",
                       side_effect=[binary, save]), patch.object(
                           sys, "argv", ["tool", "--watch-ip", "10.0.0.65",
                                         "--report", str(out)]):
                self.assertEqual(main(), 0)
            self.assertEqual(out.stat().st_mode & 0o077, 0)
            old = out.read_bytes()
            with patch.object(sys, "argv", ["tool", "--watch-ip", "10.0.0.65",
                                      "--report", str(out)]):
                self.assertEqual(main(), 1)
            self.assertEqual(out.read_bytes(), old)


if __name__ == "__main__":
    unittest.main()
