"""Only in-memory simulated Samsung SDB. No real watch or network."""
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
from watch3_r08_fota_artifact_pull import SYNC_HDR, LOCAL_STREAM
import watch3_r08_fota_handoff_pull as handoff


class FakeSocket:
    def __init__(self, incoming: bytes):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, count):
        chunk, self.incoming = self.incoming[:count], self.incoming[count:]
        return chunk

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def peer(parts):
    return FakeSocket(
        frame(b"CNXN", VERSION, 262144, b"device::\x00") +
        frame(b"OKAY", 51, LOCAL_STREAM) +
        frame(b"OKAY", 51, LOCAL_STREAM) +
        b"".join(frame(b"WRTE", 51, LOCAL_STREAM, part) for part in parts))


def successful(raw):
    block = SYNC_HDR.pack(b"DATA", len(raw)) + raw
    return peer([block[:2], block[2:17], block[17:],
                 SYNC_HDR.pack(b"DONE", 0)])


def denied():
    message = b"secret watch serial: permission denied"
    return peer([SYNC_HDR.pack(b"FAIL", len(message)) + message])


def calls(sent):
    reader = FakeSocket(sent)
    frames = []
    while reader.incoming:
        frames.append(receive(reader))
    return frames


def examples():
    return {
        "fota-consumer.service": (b"[Unit]\nAfter=foo.service bar.target\n"
                                  b"[Service]\nType=dbus\nBusName=fota.consumer\n"
                                  b"ExecStart=/usr/bin/fota-daemon --secret=never-leak\n"),
        "recovery-update.service": b"[Service]\nExecStart=/usr/bin/recovery-update\n",
        "update-service.service": b"[Service]\nExecStart=/usr/bin/update-service\n",
        "rw-update.service": b"[Service]\nExecStart=/usr/bin/rw-update\n",
        "appcessoryservices.xml": b"<accessory-services><secret>private-watch-id</secret></accessory-services>",
    }


class FixedHandoffPullTests(unittest.TestCase):
    def test_observed_paths_exact_and_no_arbitrary_remote_path(self):
        self.assertEqual(handoff.OBSERVED_FILES, {
            "fota-consumer.service": (b"/usr/lib/systemd/system/fota-consumer.service", 386),
            "recovery-update.service": (b"/usr/lib/systemd/system/recovery-update.service", 238),
            "update-service.service": (b"/usr/lib/systemd/system/update-service.service", 245),
            "rw-update.service": (b"/usr/lib/systemd/system/rw-update.service", 215),
            "appcessoryservices.xml": (
                b"/usr/apps/com.samsung.fota-consumer/res/xml/appcessoryservices.xml", 2036),
        })
        for path, size in handoff.OBSERVED_FILES.values():
            self.assertTrue(path.startswith(b"/"))
            self.assertNotIn(b"..", path)
            self.assertNotIn(b"/dev/", path)
            self.assertLess(size, handoff.MAX_FILE_BYTES)
        with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_PATH_NOT_ALLOWLISTED"):
            handoff.receive_one(successful(b"data"), Path("/unused"),
                                b"/private/serial")

    def test_execstart_referenced_helper_paths_are_fixed_only(self):
        self.assertEqual(handoff.REFERENCED_HELPER_FILES, {
            "recovery-update.sh": (b"/usr/bin/recovery-update.sh", None),
            "rw-update-systemd.sh": (b"/usr/bin/rw-update-systemd.sh", None),
        })
        for path, _ in handoff.REFERENCED_HELPER_FILES.values():
            self.assertTrue(path.startswith(b"/usr/bin/"))
            self.assertNotIn(b"..", path)
            self.assertNotIn(b"/dev/", path)
        with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_PATH_NOT_ALLOWLISTED"):
            handoff.receive_one(successful(b"SECRET"), Path("/unused"),
                                b"/usr/bin/non-evidenced-helper.sh")

    def test_only_two_evidenced_helpers_no_shell_execution_or_overwrite(self):
        script_samples = {
            "recovery-update.sh": b"#!/bin/sh\n# private token do not leak\necho never-execute\n",
            "rw-update-systemd.sh": b"#!/bin/sh\n# content must remain local\nexit 0\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "helper-files"
            sockets = [successful(script_samples[name])
                       for name in handoff.REFERENCED_HELPER_FILES]
            with patch("watch3_r08_fota_handoff_pull.socket.create_connection",
                       side_effect=sockets), patch.object(
                    sys, "argv", ["pull", "--watch-ip", "10.0.0.65",
                                  "--observed-helpers-only",
                                  "--output-dir", str(output)]):
                self.assertEqual(handoff.main(), 0)
            result_path = output / handoff.REPORT_NAME
            report = json.loads(result_path.read_text())
            self.assertEqual(report["schema"],
                             "uglyos-r840x-referenced-fota-helper-recv-v1")
            self.assertEqual(report["status"], "READ_ONLY_REFERENCED_FOTA_HELPER_RECV")
            self.assertEqual(len(report["files"]), 2)
            self.assertEqual(report["files"]["recovery-update.sh"]["status"], "FETCHED")
            self.assertIsNone(
                report["files"]["recovery-update.sh"]["size_matches_previous_list"])
            self.assertIsNone(
                report["files"]["recovery-update.sh"]["observed_list_bytes"])
            self.assertEqual(report["files"]["recovery-update.sh"]["parse_status"],
                             "SHELL_TEXT_RETAINED_NOT_EXECUTED")
            self.assertFalse(report["watch_write_performed"])
            self.assertNotIn("never-execute", json.dumps(report))
            self.assertNotIn("private token", json.dumps(report))
            self.assertEqual(output.stat().st_mode & 0o077, 0)
            self.assertEqual(result_path.stat().st_mode & 0o077, 0)
            for (name, (remote, _)), sock in zip(
                    handoff.REFERENCED_HELPER_FILES.items(), sockets):
                self.assertEqual((output / name).read_bytes(), script_samples[name])
                self.assertEqual((output / name).stat().st_mode & 0o077, 0)
                frames = calls(bytes(sock.sent))
                self.assertEqual(frames[2][3], SYNC_HDR.pack(b"RECV", len(remote)) + remote)
                self.assertEqual(sum(x[0] == b"WRTE" for x in frames), 1)
                for forbidden in (b"SEND", b"shell:", b"exec:", b"dbus:",
                                  b"FOTA", b"/dev/"):
                    self.assertNotIn(forbidden, bytes(sock.sent))
            previous = result_path.read_bytes()
            with patch.object(sys, "argv", ["pull", "--watch-ip", "10.0.0.65",
                                            "--observed-helpers-only",
                                            "--output-dir", str(output)]):
                self.assertEqual(handoff.main(), 1)
            self.assertEqual(previous, result_path.read_bytes())

    def test_helper_read_fail_is_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            p = denied()
            q = successful(b"#!/bin/sh\nexit 0\n")
            with patch("watch3_r08_fota_handoff_pull.socket.create_connection",
                       side_effect=[p, q]):
                result = handoff.collect(
                    "10.0.0.65", Path("/unused"), folder,
                    observed_helpers_only=True)
            self.assertEqual(result["files"]["recovery-update.sh"]["status"],
                             "REMOTE_MISSING_DENIED_OR_UNREADABLE")
            self.assertEqual(result["files"]["rw-update-systemd.sh"]["status"],
                             "FETCHED")
            self.assertFalse((folder / "recovery-update.sh").exists())
            self.assertTrue((folder / "rw-update-systemd.sh").exists())

    def test_exact_read_only_recv_wire_and_fragmented_stream(self):
        raw = examples()["fota-consumer.service"]
        sock = successful(raw)
        result = handoff.receive_one(
            sock, Path("/unused"),
            handoff.OBSERVED_FILES["fota-consumer.service"][0])
        self.assertEqual(result, raw)
        frames = calls(bytes(sock.sent))
        self.assertEqual(frames[1][3], b"sync:\x00")
        target = handoff.OBSERVED_FILES["fota-consumer.service"][0]
        self.assertEqual(frames[2][3], SYNC_HDR.pack(b"RECV", len(target)) + target)
        self.assertEqual(sum(x[0] == b"WRTE" for x in frames), 1)
        for forbidden in (b"SEND", b"shell:", b"exec:", b"dbus:", b"FOTA", b"/dev/"):
            self.assertNotIn(forbidden, bytes(sock.sent))

    def test_unit_report_exposes_only_safe_service_fields(self):
        result = handoff.inspect_unit(examples()["fota-consumer.service"])
        self.assertEqual(result["service_type"], "dbus")
        self.assertEqual(result["bus_name"], "fota.consumer")
        self.assertEqual(result["exec_path"], "/usr/bin/fota-daemon")
        self.assertEqual(result["after"], ["foo.service", "bar.target"])
        self.assertNotIn("never-leak", json.dumps(result))
        rejected = handoff.inspect_unit(b"[Service]\nExecStart=/private/serial --id=123\n"
                                        b"BusName=secret;$USER\n")
        self.assertEqual(rejected["exec_path"], "NOT_SIMPLE_ABSOLUTE_PATH")
        self.assertNotIn("bus_name", rejected)

    def test_sap_xml_parses_root_only_not_private_values(self):
        result = handoff.inspect_sap(examples()["appcessoryservices.xml"])
        self.assertEqual(result["root_tag"], "accessory-services")
        self.assertNotIn("private-watch", json.dumps(result))
        self.assertEqual(
            handoff.inspect_sap(b'<!DOCTYPE xml [<!ENTITY x "secret">]><root>&x;</root>'),
            {"parse_status": "XML_DTD_REJECTED"})

    def test_fail_redacted_and_stream_limit_fail_closed(self):
        with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_MISSING_DENIED_OR_UNREADABLE"):
            handoff.receive_one(denied(), Path("/unused"),
                                handoff.OBSERVED_FILES["fota-consumer.service"][0])
        oversized = b"X" * (handoff.MAX_FILE_BYTES + 1)
        with self.assertRaisesRegex(handoff.HandoffError, "REMOTE_FILE_EXCEEDS_EIGHT_KIB"):
            handoff.receive_one(successful(oversized), Path("/unused"),
                                handoff.OBSERVED_FILES["fota-consumer.service"][0])
        with self.assertRaisesRegex(handoff.HandoffError, "SDB_TRANSFER_INCOMPLETE"):
            handoff.receive_one(peer([SYNC_HDR.pack(b"DATA", 100) + b"short"]),
                                Path("/unused"),
                                handoff.OBSERVED_FILES["fota-consumer.service"][0])

    def test_five_fixed_independent_reads_private_no_overwrite_and_partial_error(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "fixed"
            files = examples()
            attempts = [successful(files[key]) for key in handoff.OBSERVED_FILES]
            # Simulate failure for one file; other four must continue.
            attempts[1] = denied()
            with patch("watch3_r08_fota_handoff_pull.socket.create_connection",
                       side_effect=attempts), patch.object(
                    sys, "argv", ["pull", "--watch-ip", "10.0.0.65",
                                  "--output-dir", str(folder)]):
                self.assertEqual(handoff.main(), 0)
            self.assertEqual(folder.stat().st_mode & 0o077, 0)
            self.assertFalse((folder / "recovery-update.service").exists())
            report_file = folder / handoff.REPORT_NAME
            report = json.loads(report_file.read_text())
            self.assertEqual(report_file.stat().st_mode & 0o077, 0)
            self.assertEqual(len(report["files"]), 5)
            self.assertEqual(report["files"]["recovery-update.service"]["status"],
                             "REMOTE_MISSING_DENIED_OR_UNREADABLE")
            self.assertEqual(report["files"]["fota-consumer.service"]["bus_name"],
                             "fota.consumer")
            self.assertFalse(report["watch_write_performed"])
            self.assertNotIn("never-leak", json.dumps(report))
            self.assertNotIn("private-watch-id", json.dumps(report))
            self.assertEqual((folder / "fota-consumer.service").read_bytes(),
                             files["fota-consumer.service"])
            self.assertEqual((folder / "fota-consumer.service").stat().st_mode & 0o077, 0)
            previous = report_file.read_bytes()
            with patch.object(sys, "argv", ["pull", "--watch-ip", "10.0.0.65",
                                            "--output-dir", str(folder)]):
                self.assertEqual(handoff.main(), 1)
            self.assertEqual(report_file.read_bytes(), previous)

    def test_only_constant_remote_paths_requested_in_all_five_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            socks = [successful(examples()[key]) for key in handoff.OBSERVED_FILES]
            with patch("watch3_r08_fota_handoff_pull.socket.create_connection",
                       side_effect=socks):
                report = handoff.collect("10.0.0.65", Path("/unused"), folder)
            for (filename, (remote, _)), sock in zip(handoff.OBSERVED_FILES.items(), socks):
                wire = calls(bytes(sock.sent))
                self.assertEqual(wire[2][3], SYNC_HDR.pack(b"RECV", len(remote)) + remote)
                self.assertNotIn(b"SEND", bytes(sock.sent))
                self.assertEqual(report["files"][filename]["status"], "FETCHED")
                self.assertEqual(report["files"][filename]["sha256"],
                                 hashlib.sha256(examples()[filename]).hexdigest())


if __name__ == "__main__":
    unittest.main()
