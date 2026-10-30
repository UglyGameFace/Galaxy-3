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




class CallbackRegistrationTests(unittest.TestCase):
    @staticmethod
    def fixture():
        import struct
        data = bytearray(0x12200)
        for addr, hex_bytes in (
            (0x4e10, "2de9"),
            (0xaad0, "2de9f041"),
            (0xaafc, "1c68"),
            (0xaafe, "002c38d1"),
            (0xab74, "012008b0bde8f081"),
            (0xac6c, "08b5"),
            (0xac72, "0023034a04497a447944"),
            (0xac7c, "faf7c8f8"),
        ):
            raw = bytes.fromhex(hex_bytes)
            data[addr:addr+len(raw)] = raw
        struct.pack_into("<I", data, 0xac84, 0xfffffe55)
        struct.pack_into("<I", data, 0xac88, 0x74b6)
        data[0x12134:0x12134+15] = b"dbus-connected\0"
        sections = {".text": (0, 0, len(data), 0)}
        return data, sections

    def test_original_event_registration_and_guard_fixture(self):
        data, sections = self.fixture()
        result = review.callback_registration(data, sections)
        self.assertEqual(result["registered_event"], "dbus-connected")
        self.assertEqual(result["callback_thumb_pointer"], "0xaad1")
        self.assertEqual(result["registration_function"], "bo_add_callback")
        self.assertEqual(result["guard_return_target"], "0xab74")
        self.assertFalse(result["dbus_sender_authorization_proven"])

    def test_callback_function_pointer_mutation_fails(self):
        data, sections = self.fixture()
        data[0xac84] ^= 1
        with self.assertRaisesRegex(review.ReviewError, "EVENT_HANDLER_OR_NAME_POINTER_INVALID"):
            review.callback_registration(data, sections)

    def test_event_name_mutation_fails(self):
        data, sections = self.fixture()
        data[0x12134] = ord("x")
        with self.assertRaisesRegex(review.ReviewError, "EVENT_NAME_MISMATCH"):
            review.callback_registration(data, sections)

    def test_registration_call_mutation_fails(self):
        data, sections = self.fixture()
        data[0xac7c] ^= 0xff
        with self.assertRaisesRegex(review.ReviewError, "EVENT_REGISTRATION_CALL_INVALID"):
            review.callback_registration(data, sections)

    def test_guard_branch_mutation_fails(self):
        data, sections = self.fixture()
        data[0xab01] ^= 1
        with self.assertRaisesRegex(review.ReviewError, "EVENT_CALLBACK_GUARD_INVALID"):
            review.callback_registration(data, sections)

    def test_callback_code_entry_mutation_fails(self):
        data, sections = self.fixture()
        data[0xaad0] ^= 1
        with self.assertRaisesRegex(review.ReviewError, "EVENT_CALLBACK_ENTRY_INVALID"):
            review.callback_registration(data, sections)

    def test_original_does_not_get_executed(self):
        # The reviewer only reads bounded bytes. A missing event cannot
        # trigger SDB, Samsung code, or a D-Bus call.
        data, sections = self.fixture()
        data[0xac6c] ^= 1
        with self.assertRaisesRegex(review.ReviewError, "EVENT_REGISTRATION_INSTRUCTIONS_INVALID"):
            review.callback_registration(data, sections)

if __name__=="__main__":
    unittest.main()
