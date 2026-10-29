"""No-watch tests for exact-path, read-only Samsung FOTA package manifest."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_android_sdb import VERSION, frame, receive
import watch3_r08_fota_manifest_probe as manifest


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, count):
        part, self.incoming = self.incoming[:count], self.incoming[count:]
        return part

    def sendall(self, value):
        self.sent.extend(value)

    def settimeout(self, timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def watch_peer(frames):
    return FakeSocket(
        frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00") +
        frame(b"OKAY", 42, manifest.LOCAL_STREAM) +
        frame(b"OKAY", 42, manifest.LOCAL_STREAM) +
        b"".join(frame(b"WRTE", 42, manifest.LOCAL_STREAM, part)
                 for part in frames))


def response(xml: bytes, split: bool = False):
    raw = manifest.SYNC_HDR.pack(b"DATA", len(xml)) + xml
    packets = [raw[:5], raw[5:15], raw[15:]] if split else [raw]
    packets.append(manifest.SYNC_HDR.pack(b"DONE", 0))
    return watch_peer(packets)


def watch_requests(sent):
    peer = FakeSocket(sent)
    out = []
    while peer.incoming:
        out.append(receive(peer))
    return out


def sample_xml():
    return (b'<?xml version="1.0"?><manifest xmlns="http://tizen.org/ns/packages" '
            b'package="com.samsung.fota-consumer" version="1.1.3">'
            b'<service-application appid="com.samsung.fota-consumer.service" '
            b'exec="/usr/apps/com.samsung.fota-consumer/bin/fota-service"/>'
            b'<ui-application appid="com.samsung.fota-consumer.popup" '
            b'exec="/usr/apps/com.samsung.fota-consumer/bin/fota-syspopup"/>'
            b'<service-application appid="com.secret.personal_data" '
            b'exec="/tmp/private_watch_identity"/>'
            b'<description>private-watch-token</description>'
            b'</manifest>')


class ManifestReadOnlyTests(unittest.TestCase):
    def test_exact_read_only_sdb_recv_path_and_redacted_manifest(self):
        xml = sample_xml()
        peer = response(xml, split=True)
        report = manifest.fetch_manifest(peer, Path("/unused"))
        self.assertEqual(report["status"], "FIXED_FOTA_MANIFEST_PARSED")
        self.assertEqual(report["source_bytes"], len(xml))
        self.assertEqual([x["executable_filename"] for x in
                          report["declared_application_executables"]],
                         ["fota-service", "fota-syspopup"])
        self.assertEqual(report["unreported_application_entries"], 1)
        serialized = json.dumps(report)
        self.assertNotIn("private", serialized)
        self.assertNotIn("token", serialized)
        self.assertFalse(report["watch_write_performed"])
        frames = watch_requests(bytes(peer.sent))
        self.assertEqual(frames[1][3], b"sync:\x00")
        remote = manifest.MANIFEST_PATH
        self.assertEqual(frames[2][3], manifest.SYNC_HDR.pack(b"RECV", len(remote)) + remote)
        self.assertEqual(sum(frame_[0] == b"WRTE" for frame_ in frames), 1)
        self.assertNotIn(b"SEND", bytes(peer.sent))
        self.assertNotIn(b"shell:", bytes(peer.sent))
        self.assertNotIn(b"dbus:", bytes(peer.sent))

    def test_reject_wrong_package_and_unexpected_xml(self):
        wrong = sample_xml().replace(b"com.samsung.fota-consumer",
                                     b"com.other.personal")
        with self.assertRaisesRegex(manifest.ManifestError, "PACKAGE_ID_DOES_NOT_MATCH"):
            manifest.summarize(wrong)
        with self.assertRaisesRegex(manifest.ManifestError, "UNEXPECTED_XML_ROOT"):
            manifest.summarize(b"<other />")
        with self.assertRaisesRegex(manifest.ManifestError, "MANIFEST_XML_MALFORMED"):
            manifest.summarize(b"<manifest")

    def test_reject_dtd_and_large_manifest_without_processing(self):
        with self.assertRaisesRegex(manifest.ManifestError, "DTD_OR_ENTITY_NOT_ALLOWED"):
            manifest.summarize(
                b'<!DOCTYPE manifest [<!ENTITY x "bad">]><manifest package="com.samsung.fota-consumer">&x;</manifest>')
        huge = b"x" * (manifest.MAX_MANIFEST_BYTES + 1)
        with self.assertRaisesRegex(manifest.ManifestError, "MANIFEST_EXCEEDS_64_KIB"):
            manifest.fetch_manifest(response(huge), Path("/unused"))

    def test_remote_fail_redacts_private_watch_paths(self):
        private_error = b"/private/device/id: Permission denied"
        peer = watch_peer([
            manifest.SYNC_HDR.pack(b"FAIL", len(private_error)) + private_error
        ])
        with self.assertRaises(manifest.ManifestError) as ctx:
            manifest.fetch_manifest(peer, Path("/unused"))
        self.assertEqual(str(ctx.exception),
                         "MANIFEST_MISSING_DENIED_OR_UNREADABLE")
        self.assertNotIn("private", str(ctx.exception))

    def test_refusal_and_truncated_transfer_are_fail_closed(self):
        refused = FakeSocket(frame(b"CNXN", VERSION, 262144, b"device::\x00") +
                             frame(b"CLSE", 0, manifest.LOCAL_STREAM))
        with self.assertRaisesRegex(manifest.ManifestError, "SDB_SYNC_REFUSED"):
            manifest.fetch_manifest(refused, Path("/unused"))
        incomplete = watch_peer([manifest.SYNC_HDR.pack(b"DATA", 20) + b"short"])
        with self.assertRaisesRegex(manifest.ManifestError, "SDB_MANIFEST_TRANSFER_FAILED"):
            manifest.fetch_manifest(incomplete, Path("/unused"))

    def test_cli_output_private_exclusive_and_original_never_saved(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "redacted.json"
            with patch("watch3_r08_fota_manifest_probe.socket.create_connection",
                       side_effect=[response(sample_xml())]), patch.object(
                sys, "argv", ["script", "--watch-ip", "10.0.0.65",
                               "--report", str(path)]):
                self.assertEqual(manifest.main(), 0)
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            raw = path.read_bytes()
            self.assertNotIn(b"private-watch", raw)
            with patch("watch3_r08_fota_manifest_probe.socket.create_connection",
                       side_effect=[response(sample_xml())]), patch.object(sys, "argv", ["script", "--watch-ip", "10.0.0.65",
                                           "--report", str(path)]):
                self.assertEqual(manifest.main(), 1)
            self.assertEqual(raw, path.read_bytes())

    def test_no_arbitrary_path_or_device_writes(self):
        self.assertEqual(manifest.MANIFEST_PATH,
                         b"/usr/apps/com.samsung.fota-consumer/tizen-manifest.xml")
        self.assertNotIn(b"/dev", manifest.MANIFEST_PATH)
        self.assertNotIn(b"..", manifest.MANIFEST_PATH)
        with self.assertRaises(Exception):
            manifest.collect("8.8.8.8", Path("/unused"))


if __name__ == "__main__":
    unittest.main()
