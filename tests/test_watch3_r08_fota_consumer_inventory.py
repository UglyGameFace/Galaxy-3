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
    SYNC_HDR, SYNC_DENT, LOCAL_STREAM, DIRECTORIES, DBUS_DIRECTORIES,
    DBUS_ACTIVATION_FILENAME, PACKAGE_ROOT_SCOPE, PACKAGE_ROOT_DIRECTORY,
    PACKAGE_MANIFEST_FILENAME, InventoryError,
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

    def test_dbus_directories_are_fixed_from_standard_locations(self):
        self.assertEqual(DBUS_DIRECTORIES, {
            "dbus_system_vendor": b"/usr/share/dbus-1/system-services",
            "dbus_system_override": b"/etc/dbus-1/system-services",
            "dbus_session_vendor": b"/usr/share/dbus-1/services",
        })
        self.assertEqual(DBUS_ACTIVATION_FILENAME, "fota.consumer.service")
        for path in DBUS_DIRECTORIES.values():
            self.assertTrue(path.startswith(b"/"))
            self.assertNotIn(b"..", path)
            self.assertNotIn(b"/dev/", path)

    def test_dbus_list_reports_only_exact_fota_consumer_activation_name(self):
        packet = (dent(".private_watch_identity") +
                  dent("com.example.personal.service") +
                  dent("fota.consumer.service", stat.S_IFREG | 0o644, size=978) +
                  done())
        sock = peer([packet[:3], packet[3:18], packet[18:37], packet[37:]])
        result = list_one(sock, Path("/unused"), "dbus_system_vendor")
        self.assertEqual(result["status"], "LIST_COMPLETE")
        self.assertEqual(result["fota_consumer_activation_file"],
                         {"kind": "REGULAR_FILE", "bytes": 978})
        self.assertEqual(result["other_or_unreported_entries"], 2)
        serialized = json.dumps(result)
        self.assertNotIn("private_watch_identity", serialized)
        self.assertNotIn("com.example.personal", serialized)
        emitted = outgoing(sock)
        path = DBUS_DIRECTORIES["dbus_system_vendor"]
        self.assertEqual(emitted[2][3], SYNC_HDR.pack(b"LIST", len(path)) + path)
        self.assertEqual(sum(f[0] == b"WRTE" for f in emitted), 1)
        self.assertNotIn(b"RECV", bytes(sock.sent))
        self.assertNotIn(b"SEND", bytes(sock.sent))
        self.assertNotIn(b"shell:", bytes(sock.sent))

    def test_dbus_empty_and_no_named_activation_is_inconclusive(self):
        result = list_one(peer([done()]), Path("/unused"), "dbus_system_override")
        self.assertEqual(result["status"], "EMPTY_OR_INACCESSIBLE")
        self.assertEqual(result["fota_consumer_activation_file"], "NOT_SEEN_IN_LIST")
        self.assertIn("dynamic", result["meaning"])
        result = list_one(peer([dent("org.other.service") + done()]),
                          Path("/unused"), "dbus_session_vendor")
        self.assertEqual(result["status"], "LIST_COMPLETE")
        self.assertEqual(result["fota_consumer_activation_file"], "NOT_SEEN_IN_LIST")

    def test_dbus_only_query_uses_only_three_fixed_read_only_lists(self):
        samples = [
            peer([dent("fota.consumer.service") + done()]),
            peer([done()]),
            peer([dent("other.service") + done()]),
        ]
        with patch("watch3_r08_fota_consumer_inventory.socket.create_connection",
                   side_effect=samples) as connect:
            report = inventory("10.0.0.65", Path("/unused"),
                               dbus_services_only=True)
        self.assertEqual(connect.call_count, len(DBUS_DIRECTORIES))
        self.assertEqual(set(report["directory_results"]), set(DBUS_DIRECTORIES))
        self.assertEqual(report["status"], "READ_ONLY_FIXED_DBUS_DIRECTORY_INVENTORY")
        self.assertFalse(report["watch_write_performed"])
        self.assertNotIn("10.0.0.65", json.dumps(report))

    def test_fota_root_exact_filename_privacy_and_read_only_list(self):
        self.assertEqual(PACKAGE_ROOT_DIRECTORY,
                         b"/usr/apps/com.samsung.fota-consumer")
        self.assertEqual(PACKAGE_MANIFEST_FILENAME, "tizen-manifest.xml")
        packet = (dent("bin", stat.S_IFDIR | 0o755) +
                  dent("tizen-manifest.xml", stat.S_IFREG | 0o644, 987) +
                  dent("private-device-name-secret.txt") +
                  dent(".private") + done())
        sock = peer([packet[:3], packet[3:14], packet[14:31], packet[31:]])
        result = list_one(sock, Path("/unused"), PACKAGE_ROOT_SCOPE)
        self.assertEqual(result["status"], "LIST_COMPLETE")
        self.assertEqual(result["tizen_manifest"], {
            "kind": "REGULAR_FILE", "bytes": 987, "readable_by_someone_dac": True,
        })
        self.assertEqual(result["other_or_unreported_entries"], 3)
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("private", json.dumps(result))
        frames = outgoing(sock)
        self.assertEqual(frames[2][3], SYNC_HDR.pack(
            b"LIST", len(PACKAGE_ROOT_DIRECTORY)) + PACKAGE_ROOT_DIRECTORY)
        self.assertEqual(sum(f[0] == b"WRTE" for f in frames), 1)
        self.assertNotIn(b"RECV", bytes(sock.sent))
        self.assertNotIn(b"SEND", bytes(sock.sent))
        self.assertNotIn(b"shell:", bytes(sock.sent))

    def test_fota_root_missing_manifest_is_precise_but_not_global_absence(self):
        sock = peer([dent("bin", stat.S_IFDIR | 0o755) + done()])
        result = list_one(sock, Path("/unused"), PACKAGE_ROOT_SCOPE)
        self.assertEqual(result["status"], "LIST_COMPLETE")
        self.assertEqual(result["tizen_manifest"], "NOT_SEEN_IN_LIST")
        self.assertIn("SMACK", result["meaning"])
        sock = peer([done()])
        result = list_one(sock, Path("/unused"), PACKAGE_ROOT_SCOPE)
        self.assertEqual(result["status"], "EMPTY_OR_INACCESSIBLE")

    def test_root_only_scope_and_private_output_preserve_old_defaults(self):
        root_sock = peer([dent("tizen-manifest.xml") + done()])
        with patch("watch3_r08_fota_consumer_inventory.socket.create_connection",
                   return_value=root_sock) as connect:
            report = inventory("10.0.0.65", Path("/unused"),
                               fota_package_root_only=True)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(set(report["directory_results"]), {PACKAGE_ROOT_SCOPE})
        self.assertEqual(report["schema"], "uglyos-r840x-fota-root-manifest-list-v1")
        self.assertFalse(report["watch_write_performed"])
        with self.assertRaisesRegex(InventoryError, "SCOPES_MUTUALLY_EXCLUSIVE"):
            inventory("10.0.0.65", Path("/unused"),
                      dbus_services_only=True, fota_package_root_only=True)

        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "root.json"
            with patch("watch3_r08_fota_consumer_inventory.socket.create_connection",
                       return_value=peer([dent("tizen-manifest.xml") + done()])), patch.object(
                sys, "argv", ["tool", "--watch-ip", "10.0.0.65",
                              "--fota-package-root-only", "--report", str(target)]):
                self.assertEqual(main(), 0)
            old = target.read_bytes()
            self.assertEqual(target.stat().st_mode & 0o077, 0)
            with patch.object(sys, "argv", ["tool", "--watch-ip", "10.0.0.65",
                                            "--fota-package-root-only",
                                            "--report", str(target)]):
                self.assertEqual(main(), 1)
            self.assertEqual(target.read_bytes(), old)

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
