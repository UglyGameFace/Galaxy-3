"""Tests for R08 read-only live boot facts and hard no-raw-output boundary."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_live_boot_probe import (
    ESSENTIAL, PROBES, _parameters, _partitions, _symlinks, available_devices,
    collect, from_dir, main, summarize,
)


class LiveBootEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.samples = {
            "cmdline": (
                "console=ttySAC0,115200n8 root=/dev/ram0 "
                "androidboot.serialno=THIS_IS_A_SECRET "
                "wifipsk=LEAKED_WIFI_PASS systemd.mask=irrelevant "
                "androidboot.hardware=samsungexynos9110\n"
            ),
            "version": "Linux version 4.9.59 (private_builder@example.com) #1\n",
            "partitions": (
                "major minor  #blocks  name\n"
                " 179 0 15558144 mmcblk0\n"
                " 179 1 131072 mmcblk0p1\n"
                " 253 0 64548 dm-0\n"
            ),
            "model": "NOBLESSE-LARGE-BT\x00",
            "bootargs": "console=ttySAC0,115200n8 root=/dev/ram0\x00",
            "block_links": (
                "lrwxrwxrwx 1 root root 20 boot -> /dev/block/mmcblk0p1\n"
                "lrwxrwxrwx 1 root root 20 serialno -> /dev/block/mmcblk0p2\n"
            ),
        }

    def test_redacted_report_does_not_contain_private_data(self):
        report = summarize(self.samples, {"disk_links": "Not supplied"})
        output = json.dumps(report)
        for private in ("THIS_IS_A_SECRET", "LEAKED_WIFI_PASS",
                        "private_builder@example.com", "androidboot.serialno",
                        "serialno"):
            self.assertNotIn(private, output)
        self.assertEqual(report["facts"]["runtime_root"], "/dev/ram0")
        self.assertTrue(report["facts"]["root_matches_historical_dts"])
        self.assertEqual(report["facts"]["device_tree_model"], "NOBLESSE-LARGE-BT")
        self.assertFalse(report["bootloader_acceptance_proven"])
        self.assertFalse(report["flashing_authorized"])
        self.assertEqual(report["facts"]["boot_related_partition_links"],
                         [{"partition_label": "boot", "target_device": "mmcblk0p1"}])

    def test_missing_root_does_not_claim_matching(self):
        samples = dict(self.samples)
        samples["cmdline"] = "console=ttySAC0,115200n8 secret_token=do_not_share"
        report = summarize(samples, {})
        self.assertIsNone(report["facts"]["root_matches_historical_dts"])
        self.assertEqual(report["facts"]["runtime_root"], "not provided")

    def test_different_root_is_not_a_bootloader_failure_claim(self):
        samples = dict(self.samples)
        samples["cmdline"] = "root=/dev/mmcblk0p15"
        report = summarize(samples, {})
        self.assertFalse(report["facts"]["root_matches_historical_dts"])
        self.assertFalse(report["bootloader_acceptance_proven"])

    def test_missing_essential_fails_closed(self):
        for missing in ESSENTIAL:
            samples = dict(self.samples)
            del samples[missing]
            with self.assertRaisesRegex(ValueError, missing):
                summarize(samples, {})

    def test_partition_symlinks_do_not_guess_missing_labels(self):
        self.assertEqual(_symlinks(self.samples["block_links"])[0],
                         {"partition_label": "boot", "target_device": "mmcblk0p1"})
        self.assertEqual(_partitions(self.samples["partitions"])["observed_count"], 3)

    def test_sdb_devices_require_explicit_authorized_watch(self):
        with patch("watch3_r08_live_boot_probe._run",
                   return_value=subprocess.CompletedProcess(
                       ["sdb", "devices"], 0,
                       "List of devices attached\n"
                       "192.168.1.32:26101 device SM-R840X\n"
                       "other:26101 offline SM-X\n", "")):
            self.assertEqual(available_devices("sdb"), ["192.168.1.32:26101"])

    def test_sdb_collect_only_predefined_read_operations(self):
        seen = []

        def fake_run(cmd, timeout=15):
            seen.append(cmd)
            if cmd == ["sdb", "devices"]:
                return subprocess.CompletedProcess(cmd, 0,
                         "List of devices attached\n192.168.1.9:26101 device watch\n", "")
            if cmd[-1] == "cat /proc/cmdline":
                return subprocess.CompletedProcess(cmd, 0, self.samples["cmdline"], "")
            if cmd[-1] == "cat /proc/version":
                return subprocess.CompletedProcess(cmd, 0, self.samples["version"], "")
            if cmd[-1] == "cat /proc/partitions":
                return subprocess.CompletedProcess(cmd, 0, self.samples["partitions"], "")
            return subprocess.CompletedProcess(cmd, 1, "", "permission denied SECRET")
        with patch("watch3_r08_live_boot_probe._run", side_effect=fake_run):
            values, errors = collect("sdb", target=None)
        self.assertEqual(set(values), set(ESSENTIAL))
        self.assertIn("model", errors)
        for cmd in seen[1:]:
            self.assertEqual(cmd[:4], ["sdb", "-s", "192.168.1.9:26101", "shell"])
            self.assertIn(cmd[4], PROBES.values())
            self.assertNotIn("reboot", cmd[4])
            self.assertNotIn("dd", cmd[4])
        self.assertNotIn("SECRET", json.dumps(errors))

    def test_multiple_devices_never_select_random_one(self):
        with patch("watch3_r08_live_boot_probe.available_devices",
                   return_value=["A:26101", "B:26101"]):
            with self.assertRaisesRegex(ValueError, "exactly one"):
                collect("sdb", None)

    def test_local_capture_no_sdb_client_and_no_remote_commands(self):
        directory = self.root / "local"
        directory.mkdir()
        for name, raw in self.samples.items():
            (directory / f"{name}.txt").write_text(raw)
        with patch("watch3_r08_live_boot_probe._run") as process:
            raw, problems = from_dir(directory)
            output = summarize(raw, problems)
        self.assertEqual(output["facts"]["runtime_root"], "/dev/ram0")
        self.assertNotIn("cmdline", problems)
        process.assert_not_called()

    def test_reject_symlinked_local_captures(self):
        directory = self.root / "local"
        directory.mkdir()
        origin = self.root / "secret.txt"
        origin.write_text("some secret")
        (directory / "cmdline.txt").symlink_to(origin)
        with self.assertRaisesRegex(ValueError, "Unsafe capture file"):
            from_dir(directory)

    def test_cli_writes_filtered_report_only(self):
        directory = self.root / "local"
        directory.mkdir()
        for name in ESSENTIAL:
            (directory / f"{name}.txt").write_text(self.samples[name])
        dest = self.root / "redacted.json"
        with patch.object(sys, "argv", [
            "watch3_r08_live_boot_probe.py", "--from-dir", str(directory),
            "--report", str(dest)
        ]):
            self.assertEqual(main(), 0)
        report = dest.read_text()
        self.assertNotIn("THIS_IS_A_SECRET", report)
        self.assertNotIn("private_builder@example.com", report)
        self.assertEqual(json.loads(report)["status"],
                         "READ_ONLY_TIZEN_RUNTIME_OBSERVATION")


if __name__ == "__main__":
    unittest.main()
