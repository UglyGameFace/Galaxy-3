"""Fabricated-instruction regression tests; no ROM, firmware or watch used."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "watch3_sboot_pit_semantic_diff.py"
spec = importlib.util.spec_from_file_location("pitdiff", TOOL)
pit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pit)


def put(buf, offset, value):
    struct.pack_into("<I", buf, offset, value)


def synthetic(anchor=0x1000, pitaddr=0x2240, magic=True, length=True):
    blob = bytearray(0x4000)
    blob[pitaddr:pitaddr + 4] = b"PIT\x00"
    delta = ((pitaddr & ~4095) - (anchor & ~4095)) >> 12
    imm = delta & ((1 << 21) - 1)
    put(blob, anchor, 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | 4)
    put(blob, anchor+4, 0x91000000 | ((pitaddr & 4095) << 10) | (4 << 5) | 4)
    if length:
        put(blob, anchor+0x24, 0xF100001F | (1 << 22) | (2 << 10) | (2 << 5))
    if magic:
        put(blob, anchor+0x30, 0x52800000 | (0x9876 << 5) | 3)
        put(blob, anchor+0x38, 0x72800000 | (1 << 21) | (0x1234 << 5) | 3)
    put(blob, anchor+0x54, 0x54000040)
    return bytes(blob)


class PitDifferential(unittest.TestCase):
    def test_decodes_semantic_pit_validation_sequence(self):
        report = pit.inspect(synthetic(), 0x1000)
        self.assertTrue(report["pit_string_xref_verified_under_raw_file_mapping"])
        self.assertEqual(report["pit_string_reference"]["target_file_offset"], 0x2240)
        self.assertEqual(report["compare_0x2000"][0]["file_offset"], 0x1024)
        self.assertEqual(report["construct_0x12349876"][0]["value_hex"], "0x12349876")
        self.assertTrue(any(x["condition"] == 0 for x in report["conditional_branch_candidates"]))
        self.assertFalse(report["runtime_load_address_verified"])

    def test_records_changes_without_declaring_cve(self):
        report = pit.compare(synthetic(), synthetic(length=False, magic=False),
                             0x1000, 0x1000)
        self.assertTrue(report["older"]["compare_0x2000"])
        self.assertFalse(report["newer"]["compare_0x2000"])
        self.assertFalse(report["newer"]["construct_0x12349876"])
        self.assertFalse(report["both_compare_0x2000"])
        self.assertFalse(report["cve_patch_identified"])
        self.assertEqual(report["decision"], "NO_GO")

    def test_rejects_pit_without_real_code_reference(self):
        blob = bytearray(synthetic())
        put(blob, 0x1004, 0xD503201F)
        self.assertFalse(pit.inspect(bytes(blob), 0x1000)[
            "pit_string_xref_verified_under_raw_file_mapping"])

    def test_rejects_bad_anchor(self):
        blob = synthetic()
        for anchor in (-1, 3, len(blob)-100):
            with self.assertRaises(ValueError):
                pit.inspect(blob, anchor)

    def test_rejects_unpinned_data_even_at_expected_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "imposter.bin"
            f.write_bytes(b"\0" * pit.SBOOT_BYTES)
            with self.assertRaisesRegex(ValueError, "SHA256_MISMATCH"):
                pit.read_pinned(f, "R500XXU1BSD3")

    def test_rejects_symlink_and_nonregular_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            f = folder / "fake.bin"
            f.write_bytes(b"\0" * 32)
            link = folder / "link.bin"
            link.symlink_to(f)
            with self.assertRaisesRegex(ValueError, "SYMLINK"):
                pit.read_pinned(link, "R500XXU1BSD3")
            with self.assertRaisesRegex(ValueError, "REGULAR"):
                pit.read_pinned(folder, "R500XXU1BSD3")

    def test_sign_extended_backward_branch(self):
        instr = pit.decode(0x54FFFFE0, 0x1000)
        self.assertEqual(instr["op"], "B_COND")
        self.assertEqual(instr["target"], 0xffc)


if __name__ == "__main__":
    unittest.main()
