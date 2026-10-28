"""Off-device QEMU and GitHub artifact provenance unit tests. No ROM or network."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r08_select_derived_artifact as selection
import watch3_r08_qemu_userland_smoke as smoke


def synthetic_elf(machine=183) -> bytes:
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 2, machine)
    return bytes(data)


def fixture_run(runid=123):
    return {"workflow_runs": [{
        "id": runid, "event": "push", "status": "completed",
        "conclusion": "success", "head_sha": selection.SOURCE_MAIN_SHA,
    }]}


def fixture_artifacts(runid=123, expired=False):
    return {runid: {"artifacts": [{
        "id": 333, "name": selection.PREFIX + str(runid),
        "size_in_bytes": 249_000_000, "expired": expired,
    }]}}


class ArtifactIdentityTests(unittest.TestCase):
    def test_exact_successful_merge_and_artifact(self):
        result = selection.choose(fixture_run(), fixture_artifacts())
        self.assertEqual(result["run_id"], 123)
        self.assertEqual(result["artifact_id"], 333)
        self.assertFalse(result["flash_allowed"])

    def test_rejects_other_commit_even_if_artifact_matches(self):
        r = fixture_run()
        r["workflow_runs"][0]["head_sha"] = "f" * 40
        with self.assertRaisesRegex(selection.ArtifactError, "EXPECTED_ONE"):
            selection.choose(r, fixture_artifacts())

    def test_rejects_expired_artifact(self):
        with self.assertRaisesRegex(selection.ArtifactError, "ARTIFACT_NOT_VERIFIED"):
            selection.choose(fixture_run(), fixture_artifacts(expired=True))

    def test_rejects_missing_or_duplicate_artifacts(self):
        with self.assertRaisesRegex(selection.ArtifactError, "ARTIFACT_NOT_VERIFIED"):
            selection.choose(fixture_run(), {123: {"artifacts": []}})
        a = fixture_artifacts()
        a[123]["artifacts"].append(a[123]["artifacts"][0].copy())
        with self.assertRaisesRegex(selection.ArtifactError, "ARTIFACT_NOT_VERIFIED"):
            selection.choose(fixture_run(), a)

    def test_rejects_fake_undersized_artifact(self):
        a = fixture_artifacts()
        a[123]["artifacts"][0]["size_in_bytes"] = 1
        with self.assertRaisesRegex(selection.ArtifactError, "ARTIFACT_NOT_VERIFIED"):
            selection.choose(fixture_run(), a)


class QemuRealArm64Tests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/bin/asteroid-launcher").write_bytes(synthetic_elf())
        (self.root / "usr/bin/env").write_bytes(synthetic_elf())

    def test_arm64_header_and_provenance(self):
        found = smoke.read_arm64(self.root / "usr/bin/asteroid-launcher")
        self.assertEqual(found["size"], 256)
        self.assertEqual(len(found["sha256"]), 64)

    def test_rejects_wrong_architecture(self):
        (self.root / "usr/bin/asteroid-launcher").write_bytes(synthetic_elf(machine=40))
        with self.assertRaisesRegex(smoke.SmokeFailure, "WRONG_ELF_MACHINE"):
            smoke.read_arm64(self.root / "usr/bin/asteroid-launcher")

    def test_fixed_guest_probes_do_not_print_full_host_environment(self):
        fake = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=smoke.PROBE_TOKEN + "\n" +
                   "UGLYOS_R08_PROBE=" + smoke.PROBE_TOKEN, stderr="")
        with patch.object(smoke.shutil, "which", return_value="/usr/bin/qemu-aarch64"), \
             patch.object(smoke, "_run", return_value=fake) as runner:
            result = smoke.validate(self.root)
        self.assertEqual(result["result"], "REAL_ARM64_USERSPACE_EXECUTED_OFF_DEVICE")
        self.assertEqual(result["executed_guest_binary"], "/usr/bin/env")
        self.assertFalse(result["bootloader_acceptance_proven"])
        self.assertFalse(result["flash_allowed"])
        sent = runner.call_args
        self.assertEqual(sent.args[0][:3],
                         ["qemu-aarch64", "-L", str(self.root)])
        self.assertNotIn("GITHUB_TOKEN", sent.kwargs["env"])

    def test_no_false_positive_on_qemu_failure(self):
        fake = subprocess.CompletedProcess(args=[], returncode=127,
                                            stdout="", stderr="loader missing")
        with patch.object(smoke.shutil, "which", return_value="/usr/bin/qemu-aarch64"), \
             patch.object(smoke, "_run", return_value=fake):
            with self.assertRaisesRegex(smoke.SmokeFailure, "DID_NOT_EXECUTE"):
                smoke.validate(self.root)

    def test_outbound_utility_symlink_is_never_executed(self):
        elf = self.root / "usr/bin/env"
        elf.unlink()
        elf.symlink_to("/bin/echo")
        with patch.object(smoke.shutil, "which", return_value="/usr/bin/qemu-aarch64"):
            with self.assertRaisesRegex(smoke.SmokeFailure, "NO_REAL_ARM64"):
                smoke.validate(self.root)


if __name__ == "__main__":
    unittest.main()
