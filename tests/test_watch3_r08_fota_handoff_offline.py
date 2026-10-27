"""Synthetic offline Watch3 metadata only, no SDB, filesystem writes to watch, or network."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import analyze_watch3_r08_fota_handoff_offline as audit


UNITS = {
    "recovery-update.service": (
        b"[Unit]\nDescription=recovery update\nWants=wait-mount@opt-usr.service\n"
        b"After=wait-mount@opt-usr.service\n[Service]\nType=oneshot\n"
        b"SmackProcessLabel=System::Privileged\n"
        b"ExecStart=/usr/bin/recovery-update.sh\n[Install]\n"
        b"WantedBy=multi-user.target\n"),
    "rw-update.service": (
        b"[Unit]\nRequires=sysinit.target\nAfter=sysinit.target\n"
        b"[Service]\nType=oneshot\nUser=root\nGroup=root\n"
        b"SmackProcessLabel=System::Privileged\n"
        b"ExecStart=/usr/bin/rw-update-systemd.sh\n"),
    "update-service.service": (
        b"[Unit]\nRequires=dbus.socket\nAfter=dbus.socket\n"
        b"[Service]\nType=dbus\n"
        b"ExecStart=/usr/bin/launch_app com.samsung.update-service\n"
        b"BusName=com.samsung.updateservice\nUser=app_fw\nGroup=app_fw\n"
        b"SmackProcessLabel=System\n"),
}
SAP = (
    b"<!DOCTYPE resources [\n"
    b"<!ELEMENT resources (application)>\n"
    b"<!ELEMENT application (serviceProfile)+>\n"
    b"<!ELEMENT serviceProfile (supportedTransports, serviceChannel+)>\n"
    b"<!ATTLIST serviceProfile id CDATA #REQUIRED>\n"
    b"]>\n<resources><application name=\"com.samsung.fota-service\">"
    b"<serviceProfile id=\"/system/sfota\" name=\"FOTA\" role=\"Consumer\" "
    b"serviceImpl=\"com.samsung.fota-service\" version=\"1.0\">"
    b"<supportedTransports><transport type=\"TRANSPORT_BT\"/>"
    b"<transport type=\"TRANSPORT_WIFI\"/></supportedTransports>"
    b"<serviceChannel id=\"125\" qosDataRate=\"high\" qosPriority=\"high\" "
    b"qosType=\"restrictedDatagramInOrder\" /><secret>private-sn</secret>"
    b"</serviceProfile></application></resources>"
)
FIXTURES = {**UNITS, "appcessoryservices.xml": SAP}


class OfflineFotaTests(unittest.TestCase):
    def test_parse_actual_unit_structure_preserves_dbus_vs_root_boundary(self):
        recovery = audit.parse_unit(UNITS["recovery-update.service"])
        self.assertEqual(recovery["exec_path"], "/usr/bin/recovery-update.sh")
        self.assertEqual(recovery["smack_process_label"], "System::Privileged")
        self.assertEqual(recovery["wantedby"], ["multi-user.target"])
        self.assertNotIn("user", recovery)
        readwrite = audit.parse_unit(UNITS["rw-update.service"])
        self.assertEqual(readwrite["user"], "root")
        self.assertEqual(readwrite["group"], "root")
        self.assertEqual(readwrite["smack_process_label"], "System::Privileged")
        update = audit.parse_unit(UNITS["update-service.service"])
        self.assertEqual(update["user"], "app_fw")
        self.assertEqual(update["bus_name"], "com.samsung.updateservice")
        self.assertEqual(update["launch_app_id"], "com.samsung.update-service")
        self.assertNotEqual(update["bus_name"], "fota.consumer")

    def test_sap_internal_dtd_without_entities_is_parsed_offline(self):
        parsed = audit.parse_sap(SAP)
        self.assertEqual(parsed["profile_id"], "/system/sfota")
        self.assertEqual(parsed["role"], "Consumer")
        self.assertEqual(parsed["transports"], ["TRANSPORT_BT", "TRANSPORT_WIFI"])
        self.assertEqual(parsed["channels"][0], {
            "id": "125", "qosDataRate": "high",
            "qosPriority": "high", "qosType": "restrictedDatagramInOrder",
        })
        self.assertTrue(parsed["source_has_internal_dtd"])
        self.assertFalse(parsed["dtd_validity_checked"])
        self.assertNotIn("private-sn", json.dumps(parsed))

    def test_dtd_entity_external_or_bad_shape_fails_closed(self):
        malicious = [
            SAP.replace(b"<!ELEMENT resources", b'<!ENTITY x "private">\n<!ELEMENT resources'),
            SAP.replace(b"<!ELEMENT resources", b'<!ENTITY x SYSTEM "file:///private">\n<!ELEMENT resources'),
            SAP.replace(b"<!ELEMENT resources", b'<!NOTATION x SYSTEM "http://x">\n<!ELEMENT resources'),
            SAP.replace(b"<!DOCTYPE resources [", b'<!DOCTYPE resources SYSTEM "http://x" ['),
            SAP.replace(b"]>\n<resources>", b"]\n<resources>"),
        ]
        for payload in malicious:
            with self.subTest(payload=payload[:90]):
                with self.assertRaises(audit.OfflineAuditError):
                    audit.parse_sap(payload)

    def test_only_preapproved_source_hashes_are_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "sample.service"
            p.write_bytes(b"original")
            good_sha = hashlib.sha256(b"original").hexdigest()
            self.assertEqual(audit.read_known(p, 8, good_sha), b"original")
            with self.assertRaisesRegex(audit.OfflineAuditError, "SOURCE_SIZE_OR_SHA256_MISMATCH"):
                audit.read_known(p, 8, "0" * 64)
            with self.assertRaisesRegex(audit.OfflineAuditError, "SOURCE_SIZE_OR_SHA256_MISMATCH"):
                audit.read_known(p, 9, good_sha)
            p.unlink()
            p.symlink_to(Path(temp) / "missing")
            with self.assertRaisesRegex(audit.OfflineAuditError, "MISSING_OR_NONREGULAR"):
                audit.read_known(p, 8, good_sha)

    def test_private_offline_json_and_cannot_overwrite_original(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "input"
            folder.mkdir()
            expectations = {}
            for name, raw in FIXTURES.items():
                (folder / name).write_bytes(raw)
                expectations[name] = (len(raw), hashlib.sha256(raw).hexdigest())
            output = Path(td) / "analysis.json"
            with patch.object(audit, "EXPECTED", expectations), patch.object(
                sys, "argv", ["offline", "--input-dir", str(folder),
                              "--output", str(output)]):
                self.assertEqual(audit.main(), 0)
            result = json.loads(output.read_text())
            self.assertEqual(len(result["files"]), 4)
            self.assertFalse(result["watch_contacted"])
            self.assertFalse(result["watch_write_performed"])
            self.assertFalse(result["script_executed"])
            self.assertEqual(output.stat().st_mode & 0o077, 0)
            self.assertNotIn("private-sn", output.read_text())
            original = output.read_bytes()
            with patch.object(audit, "EXPECTED", expectations), patch.object(
                sys, "argv", ["offline", "--input-dir", str(folder),
                              "--output", str(output)]):
                self.assertEqual(audit.main(), 1)
            self.assertEqual(original, output.read_bytes())

    def test_mismatched_file_stops_before_any_summary_is_created(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, raw in FIXTURES.items():
                (root / name).write_bytes(raw)
            expectations = {name: (len(raw), hashlib.sha256(raw).hexdigest())
                            for name, raw in FIXTURES.items()}
            (root / "recovery-update.service").write_text("CHANGED")
            output = root / "no-report.json"
            with patch.object(audit, "EXPECTED", expectations), patch.object(
                sys, "argv", ["offline", "--input-dir", str(root),
                              "--output", str(output)]):
                self.assertEqual(audit.main(), 1)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
