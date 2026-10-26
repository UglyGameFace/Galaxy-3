"""R08-only Psplash source tests, hardware access prohibited."""
import ast
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_uglyos_boot_asset import EXPECTED_SHA256, verify_gif, verify_recipe

class PsplashContractTests(unittest.TestCase):
    def test_machine_specific_asset_overlay(self):
        verify_recipe()

    def test_mismatched_video_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "wrong.gif"
            p.write_bytes(b"GIF89a dummy")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_gif(p)
        self.assertEqual(len(EXPECTED_SHA256), 64)

    def test_no_device_writes(self):
        source = (ROOT / "tools/verify_uglyos_boot_asset.py").read_text()
        ast.parse(source)
        for forbidden in ("fastboot flash", "sdb shell", "dd if=", "/dev/block",
                          "subprocess.run(", "yt-dlp"):
            self.assertNotIn(forbidden, source)

if __name__ == "__main__":
    unittest.main()
