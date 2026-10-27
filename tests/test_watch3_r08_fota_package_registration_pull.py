"""Only a fake Watch3 peer; no physical watch or network is accessed."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from watch3_r08_android_sdb import VERSION, frame, receive
import watch3_r08_fota_manifest_probe as manifest
import watch3_r08_fota_package_registration_pull as registration


class FakeSocket:
    def __init__(self, incoming: bytes):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, length):
        chunk, self.incoming = self.incoming[:length], self.incoming[length:]
        return chunk

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, value):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def fake_watch(sync_payloads):
    return FakeSocket(
        frame(b"CNXN", VERSION, 262144, b"device::\x00") +
        frame(b"OKAY", 42, manifest.LOCAL_STREAM) +
        frame(b"OKAY", 42, manifest.LOCAL_STREAM) +
        b"".join(frame(b"WRTE", 42, manifest.LOCAL_STREAM, block)
                 for block in sync_payloads)
    )


def success_peer(xml):
    data = manifest.SYNC_HDR.pack(b"DATA", len(xml)) + xml
    return fake_watch([data[:3], data[3:22], data[22:],
                       manifest.SYNC_HDR.pack(b"DONE", 0)])


def fake_xml():
    return (
        b'<?xml version="1.0"?><manifest xmlns="http://tizen.org/ns/packages" '
        b'package="com.samsung.fota-consumer" version="1.0">'
        b'<ui-application appid="com.samsung.fota-service" exec="fota-service"/>'
        b'<service-application appid="com.samsung.fota-consumer.daemon" '
        b'exec="bin/fota-daemon"/>'
        b'<service-application appid="some.private.watchid" exec="/private/secret"/>'
        b'<description>private serial 99w283</description>'
        b'</manifest>'
    )


class R840XFotaRegistrationTests(unittest.TestCase):
    def test_real_observed_fixed_path_and_exact_read_only_recv_bytes(self):
        xml = fake_xml()
        sock = success_peer(xml)
        result = manifest.fetch_fixed_xml_bytes(
            sock, Path("/unused"), registered_package=True)
        self.assertEqual(result, xml)
        sent_socket = FakeSocket(bytes(sock.sent))
        frames = []
        while sent_socket.incoming:
            frames.append(receive(sent_socket))
        path = b"/usr/share/packages/com.samsung.fota-consumer.xml"
        self.assertEqual(manifest.REGISTERED_PACKAGE_PATH, path)
        self.assertEqual(frames[1][3], b"sync:\x00")
        self.assertEqual(frames[2][3], manifest.SYNC_HDR.pack(b"RECV", len(path)) + path)
        self.assertEqual(sum(f[0] == b"WRTE" for f in frames), 1)
        self.assertNotIn(b"SEND", bytes(sock.sent))
        self.assertNotIn(b"shell:", bytes(sock.sent))
        self.assertNotIn(b"dbus:", bytes(sock.sent))
        self.assertNotIn(b"/dev/", bytes(sock.sent))

    def test_source_json_redacts_private_xml_but_keeps_fota_basenames(self):
        xml = fake_xml()
        result = registration.examine(xml)
        self.assertEqual(result["source_bytes"], len(xml))
        self.assertEqual(result["source_sha256"], hashlib.sha256(xml).hexdigest())
        self.assertEqual(result["status"], "OBSERVED_PACKAGE_REGISTRATION_RETRIEVED")
        self.assertEqual(result["xml_root_tag"], "manifest")
        self.assertEqual(result["package_attribute"], "MATCHED")
        self.assertEqual([x["executable_filename"] for x in
                          result["declared_application_executables"]],
                         ["fota-service", "fota-daemon"])
        self.assertEqual(result["other_application_entries"], 1)
        output = json.dumps(result)
        self.assertNotIn("serial", output)
        self.assertNotIn("secret", output)
        self.assertNotIn("99w283", output)
        self.assertFalse(result["d_bus_owner_proven"])
        self.assertFalse(result["watch_write_performed"])

    def test_registry_accepts_non_manifest_root_for_offline_inspection(self):
        xml = b'<package name="com.samsung.fota-consumer"><application exec="fota-service"/></package>'
        report = registration.examine(xml)
        self.assertEqual(report["xml_root_tag"], "package")
        self.assertEqual(report["package_attribute"], "NOT_DECLARED_ON_XML_ROOT")

    def test_xml_input_bounds_entities_and_wrong_explicit_package_fail(self):
        cases = [
            (b"", "REGISTRATION_XML_INVALID_SIZE"),
            (b"x" * (manifest.MAX_REGISTERED_XML_BYTES + 1),
             "REGISTRATION_XML_INVALID_SIZE"),
            (b"<no", "REGISTRATION_XML_MALFORMED"),
            (b'<!DOCTYPE manifest [<!ENTITY a "unsafe">]><manifest>&a;</manifest>',
             "REGISTRATION_XML_DTD_OR_ENTITY"),
            (b'<manifest package="com.other.secret"/>',
             "REGISTRATION_XML_PACKAGE_MISMATCH"),
        ]
        for payload, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(registration.RegistrationError, expected):
                    registration.examine(payload)

    def test_excessive_data_is_rejected_during_streaming(self):
        huge = b"x" * (manifest.MAX_REGISTERED_XML_BYTES + 1)
        with self.assertRaisesRegex(manifest.ManifestError, "XML_BYTE_LIMIT_EXCEEDED"):
            manifest.fetch_fixed_xml_bytes(
                success_peer(huge), Path("/unused"), registered_package=True)

    def test_remote_fail_redacted_and_no_local_outputs(self):
        private_error = b"watch personal identifier: permission denied"
        sock = fake_watch([manifest.SYNC_HDR.pack(b"FAIL", len(private_error)) +
                           private_error])
        with tempfile.TemporaryDirectory() as folder:
            original = Path(folder) / "raw.xml"
            summary = Path(folder) / "report.json"
            with patch("watch3_r08_fota_package_registration_pull.socket.create_connection",
                       return_value=sock), patch.object(
                    sys, "argv", ["probe", "--watch-ip", "10.0.0.65",
                                  "--output", str(original), "--report", str(summary)]):
                self.assertEqual(registration.main(), 1)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_two_private_files_saved_exclusively_without_overwrite(self):
        xml = fake_xml()
        with tempfile.TemporaryDirectory() as folder:
            original = Path(folder) / "raw.xml"
            summary = Path(folder) / "summary.json"
            with patch("watch3_r08_fota_package_registration_pull.socket.create_connection",
                       return_value=success_peer(xml)), patch.object(
                    sys, "argv", ["probe", "--watch-ip", "10.0.0.65",
                                  "--output", str(original), "--report", str(summary)]):
                self.assertEqual(registration.main(), 0)
            self.assertEqual(original.read_bytes(), xml)
            self.assertEqual(original.stat().st_mode & 0o077, 0)
            self.assertEqual(summary.stat().st_mode & 0o077, 0)
            before = summary.read_bytes()
            with patch.object(sys, "argv", ["probe", "--watch-ip", "10.0.0.65",
                                            "--output", str(original), "--report",
                                            str(summary)]):
                self.assertEqual(registration.main(), 1)
            self.assertEqual(original.read_bytes(), xml)
            self.assertEqual(summary.read_bytes(), before)

    def test_report_collision_does_not_leave_private_xml(self):
        with tempfile.TemporaryDirectory() as folder:
            original = Path(folder) / "raw.xml"
            summary = Path(folder) / "summary.json"
            def collide(path, payload):
                if path == summary:
                    raise registration.RegistrationError("LOCAL_OUTPUT_ALREADY_EXISTS")
                return actual_write(path, payload)
            actual_write = registration.private_file
            with patch("watch3_r08_fota_package_registration_pull.socket.create_connection",
                       return_value=success_peer(fake_xml())), patch.object(
                    registration, "private_file", side_effect=collide), patch.object(
                    sys, "argv", ["probe", "--watch-ip", "10.0.0.65",
                                  "--output", str(original), "--report", str(summary)]):
                self.assertEqual(registration.main(), 1)
            self.assertFalse(original.exists())
            self.assertFalse(summary.exists())

    def test_legacy_manifest_mode_still_uses_old_fixed_path(self):
        # Existing default target and parser contract remain unchanged.
        self.assertEqual(manifest.MANIFEST_PATH,
                         b"/usr/apps/com.samsung.fota-consumer/tizen-manifest.xml")
        self.assertEqual(registration.registration_path if hasattr(registration,
                         "registration_path") else manifest.REGISTERED_PACKAGE_PATH,
                         b"/usr/share/packages/com.samsung.fota-consumer.xml")


if __name__ == "__main__":
    unittest.main()
