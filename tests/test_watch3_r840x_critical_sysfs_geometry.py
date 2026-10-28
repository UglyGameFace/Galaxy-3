"""Fake-only tests: no physical watch, no Odin, no block device access."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r08_android_sdb as sdb
import watch3_r840x_critical_sysfs_geometry as geometry


def sample():
    return {
        "critical_disk_sectors": "65536\n",
        "critical_p10_start": "2048\n",
        "critical_p10_size": "1024\n",
        "critical_p13_start": "8192\n",
        "critical_p13_size": "2048\n",
        "critical_p14_start": "12288\n",
        "critical_p14_size": "1024\n",
    }


class GeometrySafetyTests(unittest.TestCase):
    def test_seven_literal_sysfs_metadata_only_commands(self):
        self.assertEqual(sdb.CRITICAL_GEOMETRY_PROBES, {
            "critical_disk_sectors": "cat /sys/class/block/mmcblk0/size",
            "critical_p10_start": "cat /sys/class/block/mmcblk0p10/start",
            "critical_p10_size": "cat /sys/class/block/mmcblk0p10/size",
            "critical_p13_start": "cat /sys/class/block/mmcblk0p13/start",
            "critical_p13_size": "cat /sys/class/block/mmcblk0p13/size",
            "critical_p14_start": "cat /sys/class/block/mmcblk0p14/start",
            "critical_p14_size": "cat /sys/class/block/mmcblk0p14/size",
        })
        self.assertEqual(set(sdb.CRITICAL_GEOMETRY_PROBES), set(sample()))
        self.assertEqual(set(sdb.CRITICAL_GEOMETRY_PROBES) &
                         set(sdb.ALLOWED_PROBES), set(sample()))
        self.assertTrue(all(command.startswith("cat /sys/class/block/mmcblk0")
                            for command in sdb.CRITICAL_GEOMETRY_PROBES.values()))
        for command in sdb.CRITICAL_GEOMETRY_PROBES.values():
            for bad in ("/dev/", "odins", "rm ", "echo ", "dd ", "reboot",
                        "sdb root", ";", "&&", "|", "*", "../"):
                self.assertNotIn(bad, command)
        self.assertEqual(geometry.INDEX_LABELS, ((10,"param"), (13,"boot"), (14,"recovery")))

    def test_synthetic_complete_three_ranges_are_only_kernel_candidates(self):
        result = geometry.summarize(sample(), {}, owner_watch=False)
        self.assertEqual(result["state"], "THREE_CRITICAL_KERNEL_SECTOR_RANGES_OBSERVED")
        self.assertEqual(result["reported_disk_sector_count"], 65536)
        self.assertEqual(result["partition_scalar_observations"][0]["end_exclusive_sector"], 3072)
        self.assertEqual(result["partition_scalar_observations"][1]["sector_count"], 2048)
        self.assertEqual(result["source_mode"], "OFFLINE_OR_SYNTHETIC_ONLY")
        self.assertFalse(result["kernel_sector_ranges_observed"])
        self.assertEqual(result["nonoverlap_in_reported_three_candidates"], True)
        self.assertEqual(result["sector_units"],
                         "KERNEL_EXPORTED_512_BYTE_SECTOR_UNITS_NOT_SAMSUNG_PIT")
        self.assertFalse(result["flash_allowed"])
        self.assertEqual(result["result"], "NO_GO")
        for key in ("authentic_samsung_pit_obtained", "signed_stock_images_obtained",
                    "all_21_partition_geometry_established", "stock_recovery_proven",
                    "custom_boot_accepted", "odin_session_started", "firmware_written",
                    "partition_contents_read", "kernel_geometry_equivalent_to_signed_samsung_pit"):
            self.assertFalse(result[key], key)

    def test_malformed_or_unavailable_fields_fail_closed_and_cannot_infer_geom(self):
        bad = ["-1\n", "12 34\n", "99 bytes\n", "0x100\n", "0\n",
               "+123\n", "00123\n", "1\nPRIVATE\n", "9"*50, "", "9999999999999999"]
        for raw in bad:
            with self.subTest(raw=repr(raw)):
                self.assertNotEqual(geometry.summarize({**sample(), "critical_p14_size": raw}, {},
                                                       owner_watch=True)["state"],
                                    "THREE_CRITICAL_KERNEL_SECTOR_RANGES_OBSERVED")
        missing = sample()
        del missing["critical_p10_size"]
        result = geometry.summarize(missing, {"critical_p10_size": "SDB_TRANSPORT_UNREACHABLE"},
                                    owner_watch=True)
        self.assertEqual(result["state"], "PARTIAL_OR_UNAVAILABLE_KERNEL_SECTOR_FIELDS")
        self.assertIsNone(result["partition_scalar_observations"][0]["sector_count"])
        self.assertFalse(result["kernel_sector_ranges_observed"])
        self.assertFalse(result["flash_allowed"])

    def test_unavailable_disk_or_nonmatching_ranges_are_not_trusted(self):
        missing = sample()
        del missing["critical_disk_sectors"]
        result = geometry.summarize(missing, {}, owner_watch=True)
        self.assertIsNone(result["reported_disk_sector_count"])
        self.assertEqual(result["state"], "PARTIAL_OR_UNAVAILABLE_KERNEL_SECTOR_FIELDS")
        outside = geometry.summarize({**sample(), "critical_disk_sectors": "13000\n"}, {},
                                     owner_watch=True)
        self.assertEqual(outside["partition_scalar_observations"][2]["state"],
                         "INCONSISTENT_WITH_DISK_BOUNDARY")
        self.assertFalse(outside["kernel_sector_ranges_observed"])
        overlap = geometry.summarize({**sample(), "critical_p14_start": "9000\n"},
                                     {}, owner_watch=True)
        self.assertEqual(overlap["state"], "INCONSISTENT_OR_OVERLAPPING_KERNEL_SECTOR_FIELDS")
        self.assertFalse(overlap["kernel_sector_ranges_observed"])

    def test_extra_sdb_keys_rejected_not_reported(self):
        with self.assertRaisesRegex(geometry.GeometryError, "UNEXPECTED_COLLECTOR_PATH"):
            geometry.summarize({**sample(), "sensitive_serial": "owner-private-id"}, {})
        with self.assertRaisesRegex(geometry.GeometryError, "UNEXPECTED_COLLECTOR_PATH"):
            geometry.summarize(sample(), {"ssh_remote": "failed"})

    def test_local_cli_exclusive_private_report_and_preflight_prevents_second_read(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "geometry.json"
            calls = []
            def fake_collect(ip, key_path, probes):
                self.assertIs(probes, sdb.CRITICAL_GEOMETRY_PROBES)
                calls.append(1)
                return sample(), {}
            with patch.object(geometry, "collect", side_effect=fake_collect):
                self.assertEqual(geometry.main(["--watch-ip", "10.0.0.65",
                                                "--output", str(report)]), 0)
                self.assertEqual(geometry.main(["--watch-ip", "10.0.0.65",
                                                "--output", str(report)]), 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(report.stat().st_mode & 0o077, 0)
            text = report.read_text()
            self.assertNotIn("10.0.0.65", text)
            self.assertNotIn("owner-private-id", text)
            obj = json.loads(text)
            self.assertEqual(obj["state"], "THREE_CRITICAL_KERNEL_SECTOR_RANGES_OBSERVED")
            self.assertTrue(obj["watch_contacted_by_this_probe"])
            self.assertFalse(obj["flash_allowed"])
            self.assertFalse(obj["stock_recovery_proven"])

    def test_no_untrusted_source_override_or_nonlocal_ip(self):
        with patch.object(socket, "create_connection", side_effect=AssertionError("no network")):
            with self.assertRaises(sdb.SdbError):
                sdb.collect("8.8.8.8", Path("/unused"),
                            probes=sdb.CRITICAL_GEOMETRY_PROBES)
            with self.assertRaises(sdb.SdbError):
                sdb.collect("10.0.0.65", Path("/unused"),
                            probes={"forged": "cat /dev/mmcblk0p10"})


    def test_param_followup_reuses_exact_existing_two_commands(self):
        subset = sdb.CRITICAL_PARAM_GEOMETRY_PROBES
        self.assertEqual(subset, {
            "critical_p10_start": sdb.CRITICAL_GEOMETRY_PROBES["critical_p10_start"],
            "critical_p10_size": sdb.CRITICAL_GEOMETRY_PROBES["critical_p10_size"],
        })
        self.assertEqual(len(subset), 2)
        self.assertTrue(all(sdb.ALLOWED_PROBES[k] == v for k, v in subset.items()))
        self.assertIn(subset, sdb.SYSFS_PROBE_SETS)
        self.assertNotIn("critical_disk_sectors", subset)
        self.assertNotIn("critical_p13_start", subset)
        self.assertNotIn("critical_p14_size", subset)

    def test_param_followup_diagnoses_individual_categorical_failures(self):
        vals = {"critical_p10_size": "2048\n"}
        errors = {"critical_p10_start": "SYSFS_ACCESS_DENIED"}
        report = geometry.summarize_param(vals, errors, owner_watch=True)
        self.assertEqual(report["state"], "PARAM_FIELD_PARTIAL_OR_UNAVAILABLE")
        self.assertEqual(report["field_diagnostics"]["critical_p10_start"],
                         "SYSFS_ACCESS_DENIED")
        self.assertEqual(report["field_diagnostics"]["critical_p10_size"],
                         "KERNEL_NUMERIC_FIELD_OBSERVED")
        self.assertFalse(report["param_geometry_observed_on_watch"])
        self.assertFalse(report["flash_allowed"])
        self.assertFalse(report["combined_with_previous_snapshot"])
        self.assertFalse(report["stock_recovery_proven"])
        self.assertNotIn("raw_stdout", report)

        for reason in geometry.PARAM_ERROR_CATEGORIES:
            with self.subTest(reason=reason):
                report = geometry.summarize_param(
                    vals, {"critical_p10_start": reason}, owner_watch=True)
                self.assertEqual(report["field_diagnostics"]["critical_p10_start"],
                                 reason)
        unknown = geometry.summarize_param({}, {"critical_p10_start": "private watch output"})
        self.assertEqual(unknown["field_diagnostics"]["critical_p10_start"],
                         "SDB_OR_SYSFS_FIELD_UNAVAILABLE")
        self.assertNotIn("private watch output", json.dumps(unknown))
        missing = geometry.summarize_param({}, {})
        self.assertEqual(missing["field_diagnostics"]["critical_p10_start"],
                         "FIELD_NOT_RETURNED")
        malformed = geometry.summarize_param({"critical_p10_start": "uid=private"})
        self.assertEqual(malformed["field_diagnostics"]["critical_p10_start"],
                         "MALFORMED_NUMERIC_SYSFS_FIELD")
        self.assertNotIn("uid=private", json.dumps(malformed))

    def test_param_followup_numeric_range_cannot_prove_pit_or_disk_bounds(self):
        result = geometry.summarize_param(
            {"critical_p10_start": "10240\n", "critical_p10_size": "256\n"},
            owner_watch=True)
        self.assertEqual(result["state"], "TWO_PARAM_KERNEL_SCALARS_OBSERVED")
        self.assertEqual(result["param_sector_candidate"],
                         {"start_sector": 10240, "sector_count": 256,
                          "end_exclusive_sector": 10496})
        self.assertTrue(result["param_geometry_observed_on_watch"])
        self.assertFalse(result["independent_disk_capacity_verified_in_this_probe"])
        self.assertFalse(result["authentic_samsung_pit_obtained"])
        self.assertFalse(result["flash_allowed"])
        for bad in ("0\n", "-10", "0x100", "PRIVATE", "9999999999999999"):
            with self.subTest(bad=bad):
                result = geometry.summarize_param(
                    {"critical_p10_start": "10240", "critical_p10_size": bad},
                    owner_watch=True)
                self.assertFalse(result["param_geometry_observed_on_watch"])
                self.assertFalse(result["flash_allowed"])
        with self.assertRaisesRegex(geometry.GeometryError, "UNEXPECTED_COLLECTOR_PATH"):
            geometry.summarize_param({"critical_p13_size": "2048"})
        with self.assertRaisesRegex(geometry.GeometryError, "UNEXPECTED_COLLECTOR_PATH"):
            geometry.summarize_param({}, {"critical_p14_start": "error"})

    def test_param_only_cli_does_not_revisit_successful_reads_or_clobber(self):
        with tempfile.TemporaryDirectory() as td:
            old = Path(td) / "prior-critical-geometry.json"
            old.write_text("ORIGINAL EVIDENCE", encoding="utf-8")
            new = Path(td) / "param-followup.json"
            called = []
            def fake_collect(ip, key_path, probes):
                self.assertIs(probes, sdb.CRITICAL_PARAM_GEOMETRY_PROBES)
                called.append(1)
                return ({"critical_p10_size": "2048\n"},
                        {"critical_p10_start": "SYSFS_PATH_OR_COMMAND_NOT_FOUND"})
            with patch.object(geometry, "collect", side_effect=fake_collect):
                self.assertEqual(geometry.main([
                    "--watch-ip", "10.0.0.65", "--param-only",
                    "--output", str(new)]), 0)
                self.assertEqual(geometry.main([
                    "--watch-ip", "10.0.0.65", "--param-only",
                    "--output", str(new)]), 1)
            self.assertEqual(called, [1])
            self.assertEqual(old.read_text(), "ORIGINAL EVIDENCE")
            self.assertEqual(new.stat().st_mode & 0o077, 0)
            report = json.loads(new.read_text())
            self.assertEqual(len(report["source_paths_fixed_no_raw_partition_devices"]), 2)
            self.assertEqual(report["field_diagnostics"]["critical_p10_start"],
                             "SYSFS_PATH_OR_COMMAND_NOT_FOUND")
            self.assertNotIn("10.0.0.65", new.read_text())
            self.assertEqual(report["result"], "NO_GO")


if __name__ == "__main__":
    unittest.main()
