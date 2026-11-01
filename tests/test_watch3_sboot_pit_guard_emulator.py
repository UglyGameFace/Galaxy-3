"""Offline synthetic fixtures for bounded, real-opcode PIT branch exercise."""
from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import watch3_sboot_pit_guard_emulator as emu
from test_watch3_sboot_pit_control_flow import synthetic, put


class ThreeOriginalOpcodePairs(unittest.TestCase):
    def setUp(self) -> None:
        self.blob = synthetic()
        self.anchor = 0x1000

    def outcome(self, status=0, length=0x2000, header=0x12349876):
        return emu.emulate_pairs(self.blob, self.anchor, status, length, header)

    def test_header_matches_literal_built_by_movz_movk(self):
        r = self.outcome()
        self.assertEqual(r["scenario_branch"], "HEADER_MATCH_BRANCH_UNVERIFIED_FOLLOWUP")
        self.assertEqual(r["original_branch_file_offsets"]["header"], 0x1088)
        self.assertTrue(r["observed_guard_branch_taken"]["pit_header_equals_constructed_magic"])
        self.assertFalse(r["signature_or_recovery_acceptance_determined"])

    def test_header_mismatch_falls_through(self):
        r = self.outcome(header=0)
        self.assertEqual(r["scenario_branch"], "HEADER_MISMATCH_FALLTHROUGH_UNVERIFIED_FOLLOWUP")
        self.assertEqual(r["original_branch_file_offsets"]["header"], 0x1058)

    def test_unsigned_length_limit_inclusive_and_overflow(self):
        for length, expected in ((0, False), (0x1FFF, False), (0x2000, False),
                                 (0x2001, True), (0xFFFFFFFF, True),
                                 (0x1_0000_0000, True), (0xFFFFFFFFFFFFFFFF, True)):
            with self.subTest(length=length):
                r = self.outcome(length=length)
                self.assertIs(r["observed_guard_branch_taken"][
                    "unsigned_length_greater_than_0x2000"], expected)
                if expected:
                    self.assertEqual(r["scenario_branch"], "LENGTH_OUT_OF_RANGE_BRANCH")

    def test_negative_status_preempts_other_guards(self):
        r = self.outcome(status=0x80000000, length=0xFFFFFFFF, header=0)
        self.assertEqual(r["scenario_branch"], "PRECHECK_ERROR_BRANCH")
        self.assertEqual(r["original_branch_file_offsets"]["precheck"], 0x1128)
        self.assertIs(r["real_firmware_external_calls_executed"], False)

    def test_wrong_status_bit_rejects_pattern(self):
        blob = bytearray(self.blob)
        # Replace bit 31 with bit 30 in TBNZ, preserving target.
        old = int.from_bytes(blob[0x1020:0x1024], "little")
        put(blob, 0x1020, (old & ~(31 << 19)) | (30 << 19))
        with self.assertRaises(ValueError):
            emu.emulate_pairs(bytes(blob), self.anchor, 0, 0x2000, 0)

    def test_32_bit_length_comparison_truncates_high_bits(self):
        blob = bytearray(self.blob)
        old = int.from_bytes(blob[0x1024:0x1028], "little")
        put(blob, 0x1024, old & ~(1 << 31))
        w = emu.emulate_pairs(bytes(blob), self.anchor, 0, 0x1_0000_0000, 0)
        x = emu.emulate_pairs(self.blob, self.anchor, 0, 0x1_0000_0000, 0)
        self.assertEqual(w["original_length_operand_bits"], 32)
        self.assertEqual(x["original_length_operand_bits"], 64)
        self.assertFalse(w["observed_guard_branch_taken"]["unsigned_length_greater_than_0x2000"])
        self.assertTrue(x["observed_guard_branch_taken"]["unsigned_length_greater_than_0x2000"])

    def test_wrong_header_register_or_branch_rejected(self):
        for offset, word in ((0x1050, 0x6B04005F), (0x1054, 0x54000181)):
            with self.subTest(offset=offset):
                blob = bytearray(self.blob)
                put(blob, offset, word)
                with self.assertRaises(ValueError):
                    emu.emulate_pairs(bytes(blob), self.anchor, 0, 0x2000, 0)

    def test_missing_magic_literal_reference_rejected(self):
        blob = bytearray(self.blob)
        put(blob, 0x1004, 0xD503201F)
        with self.assertRaises(ValueError):
            emu.emulate_pairs(bytes(blob), self.anchor, 0, 0, 0)

    def test_unsigned_32_bit_inputs_are_strict(self):
        for value in (True, -1, 0x1_0000_0000, 1.5, "1"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    emu.emulate_pairs(self.blob, self.anchor, value, 0, 0)
        for value in (True, -1, 0x1_0000_0000_0000_0000, 1.5, "1"):
            with self.subTest(length=value):
                with self.assertRaises(ValueError):
                    emu.emulate_pairs(self.blob, self.anchor, 0, value, 0)

    def test_unknown_firmware_is_not_automatically_approved(self):
        with self.assertRaises(ValueError):
            emu.compare(b"\x00" * 64, b"\x00" * 64)

    def test_case_table_has_unique_scenarios(self):
        names = [x[0] for x in emu.CASES]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 7)
        self.assertTrue(all(x[0] != "signed_image_accepted" for x in emu.CASES))


if __name__ == "__main__":
    unittest.main()
