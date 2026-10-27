"""Synthetic-only no-watch regression of sysfs metadata partition labels."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_partition_sysfs_readonly as probe
from watch3_r08_android_sdb import (
    ALLOWED_PROBES, Connection, PARTITION_SYSFS_PROBES, SdbError,
)


def record(n: int, name: str, secret: str = "SECRET_UUID") -> str:
    return (f"MAJOR=179\nMINOR={n}\nDEVNAME=mmcblk0p{n}\n"
            f"DEVTYPE=partition\nPARTN={n}\nPARTNAME={name}\n"
            f"PARTUUID={secret}\n")


class FixedSysfsLabelsTests(unittest.TestCase):
    def test_exact_allowlist_command_cannot_open_partition_bytes(self):
        self.assertEqual(PARTITION_SYSFS_PROBES, {
            "partitions_uevent": "cat /sys/class/block/mmcblk0p[0-9]*/uevent",
        })
        self.assertEqual(ALLOWED_PROBES["partitions_uevent"],
                         PARTITION_SYSFS_PROBES["partitions_uevent"])
        command = PARTITION_SYSFS_PROBES["partitions_uevent"]
        for forbidden in ("&&", ";", "|", ">", "<", "/dev/",
                          "dmsetup", "dd ", "flash", "sdb", "odin"):
            self.assertNotIn(forbidden, command.lower())

    def test_exact_21_partitions_only_and_no_private_uuid_leaks(self):
        raw = "".join(record(n, "BOOT" if n == 1 else
                             "RECOVERY" if n == 2 else
                             "ROOTFS" if n == 20 else
                             "userdata" if n == 21 else
                             "UNKNOWNSECRET-123") for n in range(1, 22))
        report = probe.parse_sysfs(raw)
        self.assertEqual(report["state"], "SYSFS_PARTITION_LABELS_OBSERVED")
        self.assertEqual(report["reported_partition_count"], 21)
        self.assertTrue(report["all_21_numbered_partitions_observed"])
        self.assertEqual(report["missing_partition_indices"], [])
        labels = report["partition_name_records"]
        self.assertEqual(labels[0]["kernel_reported_label"], "boot")
        self.assertEqual(labels[1]["kernel_reported_label"], "recovery")
        self.assertEqual(labels[19]["kernel_reported_label"], "rootfs")
        self.assertEqual(labels[20]["kernel_reported_label"], "userdata")
        self.assertEqual(labels[2]["kernel_reported_label"], "unclassified")
        dumped = json.dumps(report)
        self.assertNotIn("PARTUUID", dumped)
        self.assertNotIn("SECRET", dumped)
        self.assertNotIn("MINOR", dumped)

    def test_partial_partition_map_remains_incomplete(self):
        parsed = probe.parse_sysfs(record(20, "rootfs") + record(21, "userdata"))
        self.assertEqual(parsed["reported_partition_count"], 2)
        self.assertFalse(parsed["all_21_numbered_partitions_observed"])
        self.assertIn(1, parsed["missing_partition_indices"])
        self.assertNotIn(20, parsed["missing_partition_indices"])

    def test_invalid_mapping_is_not_treated_as_valid(self):
        cases = (
            (record(1, "BOOT").replace("PARTN=1", "PARTN=20"),
             "PARTNUMBER_MISMATCH"),
            (record(2, "RECOVERY") + record(2, "RECOVERY"),
             "DUPLICATE_PARTITION_RECORD"),
            (record(1, "BOOT").replace("PARTN=1\n", "PARTN=1\nPARTN=1\n"),
             "DUPLICATE_SYSFS_KEY"),
            (record(1, "BOOT") + "\0", "BINARY_OR_NUL_SYSFS_RESPONSE"),
            ("MAJOR=179\nMINOR=0\n", None),
            (record(1, "BOOT") * 22, "TOO_MANY_SYSFS_RECORDS"),
            (record(1, "BOOT") + ("A" * 17000), "SYSFS_TEXT_EXCEEDS_16_KIB"),
        )
        for raw, error in cases:
            with self.subTest(error=error):
                if error:
                    with self.assertRaisesRegex(probe.PartitionLabelsError, error):
                        probe.parse_sysfs(raw)
                else:
                    self.assertEqual(probe.parse_sysfs(raw)["reported_partition_count"], 0)

    def test_one_fixed_read_only_collection_no_flash_claims(self):
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=({"partitions_uevent": record(4, "PARAM")}, {})) as called:
            report = probe.inspect_live("10.0.0.65", Path("/unused"))
        self.assertEqual(called.call_args.kwargs["probes"], PARTITION_SYSFS_PROBES)
        self.assertTrue(report["owner_watch_sysfs_observed"])
        self.assertEqual(report["report"]["partition_name_records"],
                         [{"index": 4, "kernel_reported_label": "param"}])
        for key in ("raw_partition_bytes_read", "pit_requested",
                    "odin_session_started", "watch_write_performed",
                    "stock_recovery_proven", "bootloader_acceptance_proven",
                    "flash_allowed"):
            self.assertIs(report[key], False, key)
        self.assertEqual(report["result"], "NO_GO")

    def test_file_denial_is_inconclusive_and_no_guess(self):
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=({}, {"partitions_uevent": "Read-only property unavailable"})):
            report = probe.inspect_live("10.0.0.65", Path("/unused"))
        self.assertEqual(report["state"], "SYSFS_READ_UNAVAILABLE_OR_UNSUPPORTED_GLOB")
        self.assertIsNone(report["report"])
        self.assertFalse(report["owner_watch_sysfs_observed"])

    def test_fake_sample_never_claims_watch_success_and_is_private(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "fake.txt"
            sample.write_text(record(1, "BOOT", "DO_NOT_LEAK_PERSONAL_UUID"))
            dest = Path(td) / "report.json"
            with patch("watch3_r840x_partition_sysfs_readonly.collect",
                       side_effect=AssertionError("OFFLINE_MUST_NEVER_CONTACT_WATCH")):
                self.assertEqual(probe.main([
                    "--offline-sample", str(sample), "--report", str(dest)
                ]), 0)
            result = json.loads(dest.read_text())
            self.assertEqual(result["state"], "OFFLINE_SAMPLE_ONLY_NOT_A_REAL_WATCH_OBSERVATION")
            self.assertIs(result["owner_watch_sysfs_observed"], False)
            self.assertIs(result["flash_allowed"], False)
            self.assertNotIn("UUID", dest.read_text())
            self.assertEqual(dest.stat().st_mode & 0o077, 0)

    def test_existing_report_stops_network_and_overwrite_before_contact(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "prior.json"
            dest.write_text("original")
            with patch("watch3_r840x_partition_sysfs_readonly.collect",
                       side_effect=AssertionError("EXISTING_REPORT_MUST_BLOCK_WATCH")):
                self.assertEqual(probe.main([
                    "--watch-ip", "10.0.0.65", "--report", str(dest)
                ]), 1)
            self.assertEqual(dest.read_text(), "original")

    def test_arbitrary_operation_name_is_not_allowed_to_sdb(self):
        # Existing Connection.shell rejects command text not present in allowlist
        # before it transmits any data to a socket.
        class EmptySocket:
            sent = bytearray()
            def sendall(self, part):
                self.sent.extend(part)
        sock = EmptySocket()
        connection = Connection(sock, Path("/synthetic"))
        for value in ("cat /dev/mmcblk0", "reboot", "dd if=/dev/mmcblk0"):
            with self.assertRaisesRegex(SdbError, "allowlist"):
                connection.shell(value)
        self.assertEqual(bytes(sock.sent), b"")


if __name__ == "__main__":
    unittest.main()
