"""Fake-only tests for local PIT structural name inventory. No Watch3 access."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import audit_watch3_r840x_pit_offline as pit


def fixed(text: str) -> bytes:
    value = text.encode("ascii")
    assert len(value) < 32
    return value + b"\0" * (32 - len(value))


def entry(name: str, image: str = "", fota: str = "", identifier: int = 0,
          raw_words: tuple[int, ...] | None = None) -> bytes:
    # Heimdall libpit.cpp offsets 0..35: nine u32s, then names 36/68/100.
    fields = raw_words or (0, 2, identifier, 1, 2, 8192, 64, 0, 0)
    assert len(fields) == 9
    return struct.pack("<9I", *fields) + fixed(name) + fixed(image) + fixed(fota)


def build(entries: list[bytes] | None = None, trailer: bytes = b"") -> bytes:
    parts = entries if entries is not None else [
        entry("KERNEL", "boot.img", identifier=80),
        entry("RECOVERY", "recovery.img", identifier=70),
    ]
    return pit.MAGIC + struct.pack("<I", len(parts)) + b"\0" * 20 + b"".join(parts) + trailer


class OfflinePitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def file(self, name="synthetic.pit", body=None):
        path = self.root / name
        path.write_bytes(build() if body is None else body)
        return path

    def test_source_anchored_heimdall_offsets_no_numeric_geometry_claim(self):
        self.assertEqual(pit.HEIMDALL_PIN, "3997d5cc607e6c603c6e7c0d07e42e9868c62af2")
        self.assertEqual(pit.RAGNAROEK_PIN, "f9164d2c227369ba711d89f12eef99186df61387")
        self.assertEqual(pit.HEADER_BYTES, 28)
        self.assertEqual(pit.ENTRY_BYTES, 132)
        parsed = pit.inspect_pit_bytes(build(trailer=b"\0" * 512))
        self.assertEqual(parsed["entry_name_byte_offsets"], [36, 68, 100])
        self.assertEqual(parsed["entry_count"], 2)
        self.assertEqual(parsed["entries"][0]["partition_name_unverified"], "KERNEL")
        self.assertEqual(parsed["entries"][0]["flash_filename_unverified"], "boot.img")
        self.assertEqual(parsed["entries"][1]["partition_name_unverified"], "RECOVERY")
        self.assertEqual(parsed["entries"][1]["flash_filename_unverified"], "recovery.img")
        self.assertEqual(parsed["pit_version_and_numeric_geometry"], "UNKNOWN_NOT_INTERPRETED")
        self.assertTrue(parsed["partition_addresses_not_interpreted"])

    def test_pit_v1_v2_numerical_ambiguity_never_changes_names(self):
        a = entry("STEADY", "steady.img", raw_words=(0, 2, 3, 1, 2, 123, 456, 7, 9))
        b = entry("STEADY", "steady.img", raw_words=(0, 2, 3, 90, 91, 123, 456, 7, 9))
        first = pit.inspect_pit_bytes(build([a]))
        second = pit.inspect_pit_bytes(build([b]))
        self.assertEqual(first["entries"], second["entries"])
        self.assertEqual(first["pit_version_and_numeric_geometry"],
                         "UNKNOWN_NOT_INTERPRETED")
        self.assertEqual(second["storage_block_units_unknown"], True)

    def test_exactly_132_bytes_and_strict_bounded_validation(self):
        samples = [
            (b"", "TRUNCATED_PIT_HEADER"),
            (b"\0" * 28, "INVALID_PIT_MAGIC"),
            (pit.MAGIC + struct.pack("<I", 0) + b"\0" * 20, "INVALID_PIT_ENTRY_COUNT"),
            (pit.MAGIC + struct.pack("<I", 257) + b"\0" * 20, "INVALID_PIT_ENTRY_COUNT"),
            (pit.MAGIC + struct.pack("<I", 2) + b"\0" * 20 + entry("BOOT", "boot.img"),
             "TRUNCATED_PIT_ENTRIES"),
            (build(trailer=b"\0\x04"), "UNKNOWN_NONZERO_PIT_TRAILER"),
            (build([entry("BOOT"), entry("boot")]), "DUPLICATE_PARTITION_NAME"),
            (build([entry("A/B")]), "UNSAFE_PARTITION_METADATA"),
            (build([entry("BOOT", "bad/path.img")]), "UNSAFE_PARTITION_METADATA"),
            (build([entry("BOOT")[:-1] + b"X"]), "UNTERMINATED_PIT_STRING"),
            (b"x" * (pit.MAX_PIT_BYTES + 1), "PIT_FILE_TOO_LARGE"),
        ]
        for body, expected in samples:
            with self.subTest(error=expected):
                with self.assertRaisesRegex(pit.OfflinePitError, expected):
                    pit.inspect_pit_bytes(body)

    def test_strong_redacted_no_go_when_candidate_has_fake_realistic_labels(self):
        result = pit.audit(self.file())
        self.assertEqual(result["status"], "NO_GO")
        self.assertEqual(result["pit_parse"], "STRUCTURAL_NAMES_PARSED_UNVERIFIED")
        self.assertEqual(result["device_target"], "SM-R840X")
        self.assertEqual(result["pit_sha256_local_identity_only"], __import__("hashlib").sha256(build()).hexdigest())
        for key in ("samsung_pit_authenticated", "pit_from_actual_r840x_verified",
                    "model_build_compatibility_verified", "numeric_partition_geometry_verified",
                    "pit_read_from_watch", "watch_contacted", "network_packets_sent",
                    "odin_session_started", "partition_data_written", "stock_recovery_verified",
                    "custom_boot_verified"):
            self.assertIs(result[key], False, key)
        self.assertIn("NO_STOCK_RECOVERY_OR_FLASH_AUTHORIZATION", result["warnings"])

    def test_corrupt_and_symlink_inputs_fail_closed_in_report(self):
        absent = pit.audit(self.root / "absent.pit")
        self.assertEqual(absent["warnings"], ["PIT_UNREADABLE"])
        bad = pit.audit(self.file("wrong.pit", b"garbage"))
        self.assertEqual(bad["status"], "NO_GO")
        self.assertEqual(bad["pit_parse"], "NOT_PARSED")
        linked = self.root / "linked.pit"
        linked.symlink_to(self.file())
        self.assertEqual(pit.audit(linked)["warnings"], ["PIT_SYMLINK"])
        self.assertEqual(pit.audit(self.root)["warnings"], ["PIT_NOT_REGULAR_FILE"])

    def test_offline_component_report_name_comparison_is_non_authoritative(self):
        blob = {
            "schema": "uglyos-r840x-odin-components-v1",
            "status": "NO_GO",
            "watch_modified": False,
            "parts": [{
                "entries": [{"name": "boot.img"}, {"name": "different.img"}]
            }]
        }
        components = self.root / "components.json"
        components.write_text(json.dumps(blob))
        result = pit.audit(self.file(), components)
        actual = result["component_names_match_unverified"]
        self.assertEqual(actual["matched_names"], ["boot.img"])
        self.assertEqual(actual["pit_filenames_not_found"], ["recovery.img"])
        self.assertEqual(actual["component_names_unmapped"], ["different.img"])
        self.assertIs(actual["signature_or_restore_proof"], False)
        self.assertEqual(result["status"], "NO_GO")
        blob["watch_modified"] = True
        components.write_text(json.dumps(blob))
        invalid = pit.audit(self.file(), components)
        self.assertIsNone(invalid["component_names_match_unverified"])
        self.assertIn("UNTRUSTED_COMPONENT_REPORT_STATUS", invalid["warnings"])

    def test_reject_component_report_path_traversal_or_malicious_json(self):
        for blob in (
            {"schema": "not-an-odin-report", "status": "NO_GO", "watch_modified": False, "parts": []},
            {"schema": "uglyos-r840x-odin-components-v1", "status": "NO_GO",
             "watch_modified": False, "parts": [{"entries": [{"name": "../other.img"}]}]},
        ):
            with self.subTest(blob=blob["schema"]):
                f = self.root / "components.json"
                f.write_text(json.dumps(blob))
                report = pit.audit(self.file(), f)
                self.assertEqual(report["status"], "NO_GO")
                self.assertIsNone(report["component_names_match_unverified"])
                self.assertTrue(report["warnings"])

    def test_cli_uses_only_local_files_never_network_and_private_no_overwrite(self):
        self.file()
        outfile = self.root / "result.json"
        argv = [str(self.root / "synthetic.pit"), "--report", str(outfile)]
        with patch.object(socket, "socket", side_effect=AssertionError("NETWORK FORBIDDEN")), patch.object(
            subprocess, "Popen", side_effect=AssertionError("COMMAND FORBIDDEN")):
            self.assertEqual(pit.main(argv), 0)
            self.assertEqual(pit.main(argv), 2)
        report = json.loads(outfile.read_text())
        self.assertFalse(report["odin_session_started"])
        self.assertFalse(report["stock_recovery_verified"])
        self.assertEqual(outfile.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
