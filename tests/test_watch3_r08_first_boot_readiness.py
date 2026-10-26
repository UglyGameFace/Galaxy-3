"""Off-device-only first boot and stock recovery gating regression tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from watch3_r08_first_boot_readiness import (
    analyze, baseline, EvidenceError, format_markdown, inspect_artifact,
    reference_summary, report_file, storage_summary,
)

BOOT = {
    "status": "READ_ONLY_TIZEN_RUNTIME_OBSERVATION",
    "target_hardware_expected": "SM-R840X / NOBLESSE-LARGE-BT R08",
    "facts": {
        "device_tree_model": "NOBLESSE-LARGE-BT",
        "model_matches_reference": True,
        "runtime_kernel_version": "4.9.59",
        "runtime_kernel_matches_historical": True,
        "runtime_root": "/dev/ram0",
        "root_matches_historical_dts": True,
        "live_device_tree_root": "/dev/ram0",
        "partitions": {"observed_count": 32},
    },
    "flashing_authorized": False,
    "bootloader_acceptance_proven": False,
    "stock_recovery_proven": False,
}
STORAGE = {
    "status": "READ_ONLY_TIZEN_STORAGE_TOPOLOGY",
    "dm0_slaves": ["mmcblk0p20"],
    "dm0_backing_verified": True,
    "boot_partition_identified": False,
    "stock_recovery_proven": False,
    "flashing_authorized": False,
}
REFERENCE = {
    "status": "PASS_HISTORICAL_SOURCE_AUDIT",
    "board_model": "NOBLESSE-LARGE-BT",
    "reference_chosen_root": "/dev/ram0",
    "source_commit": "ec258e12887d37362b59e3291c1d3e5363c24bff",
    "flashable": False,
}


class FirstBootReadinessTests(unittest.TestCase):
    def test_no_reports_is_no_go_and_actionable(self):
        r = analyze()
        self.assertEqual(r["decision"], "NO_GO")
        self.assertIs(r["install_authorized"], False)
        self.assertIs(r["flash_authorized"], False)
        self.assertEqual(r["observation"]["status"], "NOT_SUPPLIED")
        self.assertGreater(len(r["blocking_reasons"]), 4)
        self.assertIn("recovery", format_markdown(r).lower())

    def test_all_readonly_probes_cannot_prove_installation(self):
        result = analyze(BOOT, STORAGE, REFERENCE)
        self.assertEqual(result["observation"]["status"], "OBSERVED")
        self.assertEqual(result["storage"]["status"], "OBSERVED")
        self.assertEqual(result["historical_reference"]["status"], "REFERENCE_PASS")
        self.assertIs(result["flash_authorized"], False)
        self.assertIn("Samsung bootloader", " ".join(result["blocking_reasons"]))

    def test_boot_report_rejects_model_revision_kernel_spoof_or_partial(self):
        for fact, value in (
            ("device_tree_model", "NOBLESSE-LARGE-BT-R07"),
            ("model_matches_reference", "true"),
            ("runtime_kernel_version", "5.10"),
            ("runtime_kernel_matches_historical", 1),
            ("runtime_root", "/dev/mmcblk0p20"),
            ("root_matches_historical_dts", False),
            ("live_device_tree_root", "unknown"),
        ):
            with self.subTest(fact=fact):
                modified = json.loads(json.dumps(BOOT))
                modified["facts"][fact] = value
                result = baseline(modified)
                self.assertEqual(result["status"], "INCOMPLETE")

    def test_storage_observation_is_not_boot_partition_mapping(self):
        self.assertIs(storage_summary(STORAGE)["boot_partition_identified"], False)
        for bad in ([None], ["secret_uuid"], ["mmcblk0p0"], ["mmcblk0p21"] * 33):
            modified = {**STORAGE, "dm0_slaves": bad}
            with self.subTest(value=bad), self.assertRaises(EvidenceError):
                storage_summary(modified)
        modified = {**STORAGE, "boot_partition_identified": True}
        with self.assertRaises(EvidenceError):
            storage_summary(modified)

    def test_reference_is_pinned_and_never_proves_signatures(self):
        self.assertTrue(reference_summary(REFERENCE)["historical_board_match"])
        for key, wrong in (
            ("source_commit", "0" * 40), ("board_model", "NOBLESSE R07"),
            ("reference_chosen_root", "/dev/mmcblk0p20"),
        ):
            changed = {**REFERENCE, key: wrong}
            self.assertEqual(reference_summary(changed)["status"], "REFERENCE_MISMATCH")
        with self.assertRaises(EvidenceError):
            reference_summary({**REFERENCE, "flashable": True})

    def test_read_only_json_schema_duplicate_key_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            valid = directory / "valid.json"
            valid.write_text(json.dumps(BOOT))
            self.assertEqual(report_file(valid, BOOT["status"]), BOOT)
            with self.assertRaises(EvidenceError):
                report_file(valid, STORAGE["status"])
            valid.write_text('{"status":"READ_ONLY_TIZEN_RUNTIME_OBSERVATION",'
                             '"status":"PASS", "flashing_authorized":false}')
            with self.assertRaises(EvidenceError):
                report_file(valid, BOOT["status"])
            valid.write_text(json.dumps({**BOOT, "flashing_authorized": True}))
            with self.assertRaises(EvidenceError):
                report_file(valid, BOOT["status"])
            valid.write_text(json.dumps(REFERENCE))
            self.assertEqual(report_file(valid, REFERENCE["status"]), REFERENCE)
            alias = directory / "symlink.json"
            alias.symlink_to(valid)
            with self.assertRaises(EvidenceError):
                report_file(alias, REFERENCE["status"])

    def test_local_checksum_is_real_but_not_boot_safety(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dummy-firmware.img"
            path.write_bytes(b"off-device fixture - not actual firmware")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result = inspect_artifact(f"kernel_image:{path}:{digest}")
            self.assertIs(result["sha256_verified"], True)
            self.assertIs(result["flashable"], False)
            with self.assertRaises(EvidenceError):
                inspect_artifact(f"kernel_image:{path}:{'a' * 64}")
            with self.assertRaises(EvidenceError):
                inspect_artifact(f"unknown:{path}:{digest}")
            link = Path(folder) / "indirect.img"
            link.symlink_to(path)
            with self.assertRaises(EvidenceError):
                inspect_artifact(f"kernel_image:{link}:{digest}")
            result = analyze(BOOT, STORAGE, REFERENCE, [result])
            self.assertFalse(result["install_authorized"])
            with self.assertRaises(EvidenceError):
                analyze(BOOT, STORAGE, REFERENCE, [result["artifacts"][0]] * 2)

    def test_cli_offline_json_and_markdown_and_fail_closed_deploy(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for key, source in (("boot", BOOT), ("storage", STORAGE),
                                ("reference", REFERENCE)):
                (directory / f"{key}.json").write_text(json.dumps(source))
            output = directory / "status.json"
            md = directory / "status.md"
            args = [
                sys.executable,
                str(ROOT / "tools/watch3_r08_first_boot_readiness.py"),
                "--boot-report", str(directory / "boot.json"),
                "--storage-report", str(directory / "storage.json"),
                "--reference-report", str(directory / "reference.json"),
                "--output", str(output), "--markdown", str(md),
            ]
            result = subprocess.run(args, capture_output=True, text=True,
                                    timeout=8, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertFalse(report["flash_authorized"])
            self.assertIn("NO-GO", md.read_text())
            self.assertNotIn(str(directory), output.read_text())
            enforce = subprocess.run(args + ["--enforce-install"],
                                     capture_output=True, text=True,
                                     timeout=8, check=False)
            self.assertEqual(enforce.returncode, 4)
            self.assertFalse(json.loads(output.read_text())["install_authorized"])

    def test_no_runtime_device_commands_or_secrets(self):
        script = (ROOT / "tools/watch3_r08_first_boot_readiness.py").read_text()
        for forbidden in ("socket.create_connection", "sdb shell", "fastboot flash",
                          "netodin", "sudo ", "subprocess.run(", "os.system("):
            self.assertNotIn(forbidden, script)
        ci = (ROOT / ".github/workflows/watch3-r08-firstboot-recovery-gate.yml").read_text()
        self.assertIn("test_watch3_r08_first_boot_readiness.py", ci)
        self.assertIn("--enforce-install", ci)
        self.assertIn("status=$?", ci)
        self.assertIn("test \"$status\" -eq 4", ci)
        self.assertNotIn("bitbake -c image_complete", ci)


if __name__ == "__main__":
    unittest.main()
