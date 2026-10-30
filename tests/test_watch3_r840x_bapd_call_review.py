"""Pure synthetic tests. Never execute Samsung binaries or contact a watch."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / "tools/watch3_r840x_bapd_call_review.py"
spec = importlib.util.spec_from_file_location("watch3_r840x_bapd_review", FILE)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class BapdCallReviewTests(unittest.TestCase):
    @staticmethod
    def blx_buffer(address, hi, lo):
        data = bytearray(address + 4)
        struct.pack_into("<HH", data, address, hi, lo)
        return data

    def test_thumb_blx_dbus_call_target(self):
        self.assertEqual(review.thumb_blx(self.blx_buffer(0xab58, 0xf7f9, 0xec42), 0xab58), 0x43e0)

    def test_thumb_blx_variant_constructor(self):
        self.assertEqual(review.thumb_blx(self.blx_buffer(0xab2a, 0xf7f9, 0xe9a4), 0xab2a), 0x3e74)

    def test_non_call_is_rejected(self):
        with self.assertRaisesRegex(review.ReviewError,"NOT_THUMB_BLX_IMMEDIATE"):
            review.thumb_blx(b"\x00"*4, 0)

    def test_arm_rotated_immediate(self):
        self.assertEqual(review.arm_imm(0xa24), 0x24000)
        self.assertEqual(review.arm_imm(0x600), 0)

    def test_wrong_pinned_bytes_rejected(self):
        with self.assertRaisesRegex(review.ReviewError,"PINNED_ORIGINAL_REQUIRED"):
            review.analyze(b"\x00"*review.SIZE)

    def test_hash_override_does_not_bypass_elf_check(self):
        fake = b"\x00"*review.SIZE
        with patch.object(review,"PIN",hashlib.sha256(fake).hexdigest()):
            with self.assertRaisesRegex(review.ReviewError,"INVALID_ARM_ELF32"):
                review.analyze(fake)

    def test_elf_structure_rejected(self):
        with self.assertRaisesRegex(review.ReviewError,"INVALID_ARM_ELF32"):
            review.elf_sections(b"not-an-elf")

    def test_bad_plt_rejected(self):
        with self.assertRaisesRegex(review.ReviewError,"ADDRESS_OUTSIDE_REVIEWED_SECTIONS"):
            review.offset({}, 0x43e0, 12)

    def test_missing_original_does_not_write_report(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)/"output.json"
            self.assertEqual(review.main(["--input",str(Path(folder)/"missing"),"--report",str(out)]),1)
            self.assertFalse(out.exists())

    def test_invalid_original_does_not_write_report(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder)/"fake.bin"
            binary.write_bytes(b"fake")
            out = Path(folder)/"output.json"
            self.assertEqual(review.main(["--input",str(binary),"--report",str(out)]),1)
            self.assertFalse(out.exists())


if __name__=="__main__":
    unittest.main()
