"""Synthetic-only tests. No Samsung firmware is used or bundled."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import audit_watch3_abox_firmware as audit


class FirmwareManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(audit.MANIFEST.read_text(encoding="utf-8"))

    def test_source_pinning_and_four_filenames(self):
        self.assertEqual(self.manifest["reference_commit"], audit.EXPECTED_SHA)
        self.assertEqual(
            [x["name"] for x in self.manifest["files"]],
            ["calliope_sram.bin", "calliope_dram.bin",
             "APDV_AUDIO_SLSI.bin", "APSV_AUDIO_SLSI.bin"])
        self.assertEqual(
            [x["role"] for x in self.manifest["files"]],
            ["core_abox", "core_abox", "enabled_auxiliary", "enabled_auxiliary"])

    def test_enabled_and_disabled_dt_extraction(self):
        dt = """
        ext_bin_0: ext_bin@0 { status = "okay";
          samsung,name = "APDV_AUDIO_SLSI.bin";
          samsung,area = <1>; samsung,offset = <0x502000>; };
        ext_bin_1: ext_bin@1 { status = "disabled";
          samsung,name = "AP_AUDIO_SLSI.bin";
          samsung,area = <1>; samsung,offset = <0x510000>; };
        """
        nodes = audit.extra_nodes(dt)
        self.assertEqual(nodes["APDV_AUDIO_SLSI.bin"]["dt_status"], "okay")
        self.assertEqual(nodes["APDV_AUDIO_SLSI.bin"]["dt_offset"], "0x502000")
        self.assertEqual(nodes["AP_AUDIO_SLSI.bin"]["dt_status"], "disabled")

    def test_local_inventory_rejects_missing_and_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(audit.inspect_local(directory, self.manifest))
                for item in self.manifest["files"]:
                    (directory / item["name"]).write_bytes(b"")
                self.assertFalse(audit.inspect_local(directory, self.manifest))

    def test_local_inventory_labels_synthetic_data_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for item in self.manifest["files"]:
                (directory / item["name"]).write_bytes(b"FAKE_TEST_DATA_NOT_FIRMWARE")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = audit.inspect_local(directory, self.manifest)
            self.assertTrue(result)
            self.assertEqual(output.getvalue().count("PRESENT_UNVERIFIED:"), 4)
            self.assertIn("do NOT establish", output.getvalue())


if __name__ == "__main__":
    unittest.main()
