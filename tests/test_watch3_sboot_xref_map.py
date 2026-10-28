"""Synthetic-only tests for bounded ARM64 literal xrefs. No watch or firmware."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_sboot_xref_map as xref


def put(buf: bytearray, offset: int, instruction: int) -> None:
    struct.pack_into("<I", buf, offset, instruction)


def adrp(pc: int, target: int, reg: int = 4) -> int:
    delta = ((target & ~4095) - (pc & ~4095)) >> 12
    assert -(1 << 20) <= delta < (1 << 20)
    imm = delta & ((1 << 21) - 1)
    return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | reg


def add(target: int, reg: int = 4, dst: int | None = None) -> int:
    return 0x91000000 | ((target & 4095) << 10) | (reg << 5) | (reg if dst is None else dst)


def fixture(label=b"recovery\0", pc=0x1000, target=0x3000) -> bytes:
    b = bytearray(0x5000)
    b[target:target + len(label)] = label
    put(b, pc, adrp(pc, target))
    put(b, pc + 4, add(target))
    return bytes(b)


class PcrelXrefTests(unittest.TestCase):
    def test_source_pins_are_existing_known_historical_references(self):
        self.assertEqual(xref.REFERENCES["R500XXU1BSD3"][1], 0x58BB0)
        self.assertEqual(xref.REFERENCES["R500XXU1GUJ2"][1], 0x58E60)
        self.assertEqual(xref.STAGE_START, 0x40000)
        self.assertEqual(xref.STAGE_END, 0x115000)

    def test_consecutive_adrp_add_detects_one_literal_only(self):
        f = fixture()
        self.assertEqual(xref.decode_adrp_add(f, 0x1000), 0x3000)
        r = xref.map_references(f, start=0x1000, end=0x1010)
        self.assertEqual(r["xref_counts"]["recovery"], 1)
        item = r["candidate_xrefs"]["recovery"][0]
        self.assertEqual(item["instruction_file_offset"], 0x1000)
        self.assertEqual(item["literal_target_file_offset"], 0x3000)
        self.assertEqual(item["literal_match"], "NUL_TERMINATED_LITERAL")
        self.assertFalse(item["wireless_download_reachability_proven"])

    def test_prefix_with_separator_is_distinguished_from_exact_literal(self):
        f = fixture(b"param: caution\0")
        r = xref.map_references(f, start=0x1000, end=0x100C)
        self.assertEqual(r["candidate_xrefs"]["param"][0]["literal_match"],
                         "PREFIX_WITH_SEPARATOR")

    def test_no_suffix_substring_or_unrelated_words(self):
        for token in (b"parameter\0", b"recoveryXYZ\0", b"ODINimage\0"):
            with self.subTest(token=token):
                r = xref.map_references(fixture(token), start=0x1000, end=0x1010)
                self.assertTrue(all(not value for value in r["candidate_xrefs"].values()))

    def test_reject_wrong_register_nonadjacent_and_32bit_add(self):
        original = bytearray(fixture())
        put(original, 0x1004, add(0x3000, reg=5))
        self.assertIsNone(xref.decode_adrp_add(bytes(original), 0x1000))
        original = bytearray(fixture())
        put(original, 0x1004, 0xD503201F)
        put(original, 0x1008, add(0x3000))
        self.assertIsNone(xref.decode_adrp_add(bytes(original), 0x1000))
        original = bytearray(fixture())
        put(original, 0x1004, add(0x3000) & ~0x80000000)
        self.assertIsNone(xref.decode_adrp_add(bytes(original), 0x1000))

    def test_negative_page_signed_adrp_is_supported(self):
        f = fixture(b"PIT\0", pc=0x3000, target=0x1000)
        self.assertEqual(xref.decode_adrp_add(f, 0x3000), 0x1000)
        r = xref.map_references(f, start=0x3000, end=0x3008)
        self.assertEqual(r["xref_counts"]["PIT"], 1)

    def test_bounded_interval_fail_closed(self):
        f = fixture()
        for start, end in [(-4, 8), (3, 16), (0, 0), (0, 200000),
                           (0x4000, 0x2000)]:
            with self.subTest(start=start, end=end):
                with self.assertRaises(xref.XrefError):
                    xref.map_references(f, start=start, end=end)
        with self.assertRaises(xref.XrefError):
            xref.map_references(b"too small", start=0, end=8)

    def test_compare_never_upgrades_source_to_r840x_or_flashable(self):
        with patch.object(xref, "STAGE_START", 0x1000), patch.object(xref, "STAGE_END", 0x1008):
            result = xref.compare(fixture(b"PIT\0"), fixture(b"PIT\0"))
        self.assertEqual(result["decision"], "NO_GO")
        self.assertFalse(result["source_is_exact_owner_bootloader"])
        self.assertFalse(result["custom_boot_accepted"])
        self.assertFalse(result["firmware_written"])
        self.assertFalse(result["cve_root_cause_identified"])
        self.assertEqual(json.loads(json.dumps(result))["decision"], "NO_GO")


if __name__ == "__main__":
    unittest.main()
