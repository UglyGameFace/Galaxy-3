"""Synthetic-only S-BOOT stage tests; no proprietary executable or watch used."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "watch3_sboot_stage_map.py"
spec = importlib.util.spec_from_file_location("stage", SOURCE)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def fixture(footer=True):
    out = bytearray(0x20000)
    struct.pack_into("<I", out, 0, 16)
    bl1_end = 16 * 512
    struct.pack_into("<I", out, bl1_end, 16)
    epbl_end = bl1_end + 16 * 512
    out[bl1_end+8:bl1_end+12] = b"daeh"
    pattern = struct.pack("<III", 7, 0, 0)
    if footer:
        out[epbl_end-512-16:epbl_end-512-4] = pattern
        out[0x11000:0x1100c] = pattern
    out[0x10000:0x10004] = b"ODIN"
    out[0x10100:0x10104] = b"LOKE"
    return bytes(out)


class SBootStage(unittest.TestCase):
    def test_valid_headers_and_hypothetical_footer(self):
        report = stage.parse(fixture())
        self.assertEqual(report["observed_header_boundaries"][0]["end_exclusive"], 8192)
        self.assertEqual(report["observed_header_boundaries"][1]["end_exclusive"], 16384)
        self.assertTrue(report["stage2_signature_footer_pattern_hypotheses"])
        self.assertFalse(report["signature_cryptographically_verified"])

    def test_footer_absence_does_not_fabricate_structure(self):
        report = stage.parse(fixture(footer=False))
        self.assertEqual(report["stage2_signature_footer_pattern_hypotheses"], [])
        self.assertFalse(report["main_bootloader_stage_boundaries_proven"])

    def test_invalid_bl1_block_lengths_fail_closed(self):
        for blocks in (0, 1, 0xffffffff):
            buf = bytearray(fixture())
            struct.pack_into("<I", buf, 0, blocks)
            with self.subTest(blocks=blocks):
                with self.assertRaisesRegex(ValueError, "BL1"):
                    stage.parse(bytes(buf))

    def test_invalid_epbl_block_lengths_fail_closed(self):
        for blocks in (0, 1, 0xffffffff):
            buf = bytearray(fixture())
            struct.pack_into("<I", buf, 8192, blocks)
            with self.subTest(blocks=blocks):
                with self.assertRaisesRegex(ValueError, "EPBL"):
                    stage.parse(bytes(buf))

    def test_missing_header_marker_rejected(self):
        buf = bytearray(fixture())
        buf[8200:8204] = b"NOPE"
        with self.assertRaisesRegex(ValueError, "NO_EPBL_HEADER_MARKER"):
            stage.parse(bytes(buf))

    def test_truncated_or_malformed_image_rejected(self):
        for size in (0, 1, 100, 4096):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    stage.parse(b"\x00" * size)

    def test_marker_lies_outside_verified_header_candidates(self):
        report = stage.parse(fixture())
        self.assertEqual(report["reference_marker_locations"]["ODIN"][0]["region"],
                         "AFTER_EPBL_UNMAPPED")
        self.assertNotIn("MAIN_BL", str(report["observed_header_boundaries"]))

    def test_fake_same_size_hash_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "fake.bin"
            file.write_bytes(b"\x00" * stage.SIZE)
            with self.assertRaisesRegex(ValueError, "SHA256_MISMATCH"):
                stage.read_pinned(file, "R500XXU1BSD3")

    def test_symlink_and_nonregular_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "fake.bin"
            file.write_bytes(b"\x00" * 100)
            link = Path(folder) / "link"
            link.symlink_to(file)
            with self.assertRaisesRegex(ValueError, "SYMLINK"):
                stage.read_pinned(link, "R500XXU1BSD3")
            with self.assertRaisesRegex(ValueError, "REGULAR"):
                stage.read_pinned(Path(folder), "R500XXU1BSD3")

    def test_compare_does_not_claim_recovery(self):
        result = stage.compare(fixture(), fixture(footer=False))
        self.assertEqual(result["status"], "NO_GO")
        self.assertFalse(result["flash_allowed"])
        self.assertFalse(result["watch_contacted"])
        self.assertFalse(result["real_r840x_sboot_obtained"])


if __name__ == "__main__":
    unittest.main()
