"""Quick off-device tests for Watch3's Linux 4.9-compatible ext4 format gate."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_watch3_legacy_ext4 import ValidationError, inspect


class LegacyExt4Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / "synthetic.ext4"

    def test_r08_recipe_scoped_to_image_and_machine(self):
        repo = Path(__file__).resolve().parents[1]
        recipe = (repo / "meta-noblesse/recipes-core/images/"
                  "asteroid-image.bbappend").read_text()
        self.assertIn(
            'EXTRA_IMAGECMD:ext4:append:noblesse-r08 = " -O ^orphan_file"',
            recipe)
        self.assertNotIn("tune2fs", recipe)
        self.assertNotIn("flash", recipe.splitlines()[-1])

    def test_missing_image_rejected(self):
        with self.assertRaisesRegex(ValidationError, "Missing or empty"):
            inspect(self.image)

    def test_wrong_superblock_rejected_before_external_tools(self):
        self.image.write_bytes(b"\0" * 1024 * 10)
        with self.assertRaisesRegex(ValidationError, "bad superblock"):
            inspect(self.image)

    def test_orphan_feature_is_a_hard_failure(self):
        self.image.write_bytes(b"\0" * (1024 * 2))
        data = bytearray(self.image.read_bytes())
        data[1080:1082] = b"\x53\xef"
        self.image.write_bytes(data)
        result = subprocess.CompletedProcess(
            args=["dumpe2fs"], returncode=0,
            stdout=("Filesystem features: has_journal filetype extent "
                    "orphan_file\n"), stderr="")
        with patch("validate_watch3_legacy_ext4.command", return_value=result) as cmd:
            with self.assertRaisesRegex(ValidationError, "orphan_file=True"):
                inspect(self.image)
        self.assertEqual(cmd.call_count, 1, "Do not fsck unsupported image")

    def test_unknown_feature_is_a_hard_failure(self):
        self.image.write_bytes(b"\0" * 2048)
        data = bytearray(self.image.read_bytes())
        data[1080:1082] = b"\x53\xef"
        self.image.write_bytes(data)
        result = subprocess.CompletedProcess(
            args=["dumpe2fs"], returncode=0,
            stdout="Filesystem features: filetype extent FEATURE_C12\n",
            stderr="")
        with patch("validate_watch3_legacy_ext4.command", return_value=result):
            with self.assertRaisesRegex(ValidationError, "unrecognized"):
                inspect(self.image)

    @unittest.skipUnless(
        all(shutil.which(c) for c in ("mkfs.ext4", "dumpe2fs", "e2fsck")),
        "e2fsprogs unavailable")
    def test_old_e2fsck_inspects_mkfs_without_orphan_without_modifying(self):
        subprocess.run(["truncate", "-s", "32M", str(self.image)], check=True)
        subprocess.run(
            ["mkfs.ext4", "-F", "-q", "-i", "4096", "-O", "^orphan_file",
             str(self.image)],
            check=True, capture_output=True, text=True)
        before = self.image.read_bytes()
        report = inspect(self.image)
        self.assertEqual(report["status"], "PASS_OFF_DEVICE_LEGACY_EXT4")
        self.assertTrue(report["orphan_file_absent"])
        self.assertNotIn("orphan_file", report["filesystem_features"])
        self.assertEqual(before, self.image.read_bytes(),
                         "No filesystem writes permitted during audit")
        self.assertFalse(report["flashable"])


if __name__ == "__main__":
    unittest.main()
