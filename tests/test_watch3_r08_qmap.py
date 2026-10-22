"""Regression tests for the R08-only .qmap encoder and strict input gate."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "meta-noblesse/recipes-asteroid/asteroid-launcher/asteroid-launcher-configs/r08-qmap.py"
SPEC = importlib.util.spec_from_file_location("r08_qmap", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

KEYS = """keycode 114 = VolumeDown
keycode 115 = VolumeUp
keycode 139 = MenuKB
keycode 750 = MenuKB
keycode 128 = MenuKB
keycode 116 = Sleep
"""
# Independent fixed byte-for-byte fixture for Qt's QDataStream big-endian format.
GOLDEN = bytes.fromhex(
    "514d4150000000010000000600000000"
    "0072ffff0100007000000000"
    "0073ffff0100007200000000"
    "0074ffff0102000400000000"
    "0080ffff010000dc00000000"
    "008bffff010000dc00000000"
    "02eeffff010000dc00000000"
)


class R08QmapTests(unittest.TestCase):
    def test_exact_six_key_map_matches_independent_golden(self):
        self.assertEqual(MODULE.convert(KEYS), GOLDEN)
        self.assertEqual(len(GOLDEN), 88)

    def test_header_and_sorted_keys(self):
        output = MODULE.convert(KEYS)
        self.assertEqual(struct.unpack(">IIII", output[:16]), (0x514D4150, 1, 6, 0))
        records = [struct.unpack(">HHIBBH", output[i:i + 12]) for i in range(16, len(output), 12)]
        self.assertEqual([record[0] for record in records], [114, 115, 116, 128, 139, 750])
        self.assertTrue(all(record[1] == 0xffff and record[3:] == (0, 0, 0) for record in records))

    def test_order_and_comments_do_not_change_bytes(self):
        self.assertEqual(MODULE.convert("# Watch3 keys\n" + "\n".join(reversed(KEYS.splitlines()))), GOLDEN)

    def test_reject_missing_button(self):
        with self.assertRaisesRegex(ValueError, "missing="):
            MODULE.convert(KEYS.replace("keycode 116 = Sleep\n", ""))

    def test_reject_modified_button_symbol(self):
        with self.assertRaisesRegex(ValueError, "wrong="):
            MODULE.convert(KEYS.replace("750 = MenuKB", "750 = VolumeUp"))

    def test_reject_unexpected_extra_button(self):
        with self.assertRaisesRegex(ValueError, "extra="):
            MODULE.convert(KEYS + "keycode 118 = VolumeUp\n")

    def test_reject_duplicate_button(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            MODULE.convert(KEYS + "keycode 114 = VolumeDown\n")

    def test_reject_arbitrary_keymap_syntax(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            MODULE.convert(KEYS + "shift keycode 114 = VolumeDown\n")

    def test_command_line_generates_verified_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "keys.kmap"
            target = Path(tmp) / "keys.qmap"
            source.write_text(KEYS)
            subprocess.run([sys.executable, str(TOOL), str(source), str(target)], check=True,
                           capture_output=True, text=True)
            self.assertEqual(target.read_bytes(), GOLDEN)


if __name__ == "__main__":
    unittest.main()
