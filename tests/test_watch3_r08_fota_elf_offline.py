"""Synthetic ELF only: no physical watch, no networking, no binary execution."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import analyze_watch3_r08_fota_elf as module


def fake_elf(*, with_sections=True, corrupt=None, private_marker=b"") -> bytes:
    """Minimal structurally consistent ARM ELF32 with section AND segment views."""
    phcount = 4
    payload = bytearray(module.ELF_HDR.size + phcount * module.PROGRAM_HDR.size)
    payload.extend(b"\0" * (192 - len(payload)))

    dynstr = b"\0libc.so.6\0system\0rename\0internal_secret_9876\0"
    lib_name = dynstr.index(b"libc.so.6")
    system_name = dynstr.index(b"system")
    rename_name = dynstr.index(b"rename")
    secret_name = dynstr.index(b"internal_secret")
    str_off = len(payload)
    payload.extend(dynstr)
    symbol_off = len(payload)
    symbols = [
        (0, 0, 0, 0, 0, 0),
        (system_name, 0, 0, 18, 0, 0),
        (rename_name, 0, 0, 18, 0, 0),
        (secret_name, 0, 0, 18, 0, 0),
    ]
    for values in symbols:
        payload.extend(module.SYMBOL_ENTRY.pack(*values))
    symbol_size = len(payload) - symbol_off

    dynamic_off = len(payload)
    dynamics = [
        (1, lib_name), (5, 0x1000 + str_off),
        (10, len(dynstr)), (24, 0), (0, 0),
    ]
    for values in dynamics:
        payload.extend(module.DYNAMIC_ENTRY.pack(*values))
    dynamic_size = len(payload) - dynamic_off
    str_names = b"\0.dynstr\0.dynsym\0.dynamic\0.shstrtab\0"
    shstr_off = len(payload)
    payload.extend(str_names)
    payload.extend(private_marker)
    while len(payload) % 4:
        payload.extend(b"\0")
    section_off = len(payload)
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 3, 0, 0, str_off, len(dynstr), 0, 0, 1, 0),
        (9, 11, 0, 0, symbol_off, symbol_size, 1, 0, 4, 16),
        (17, 6, 0, 0, dynamic_off, dynamic_size, 1, 0, 4, 8),
        (26, 3, 0, 0, shstr_off, len(str_names), 0, 0, 1, 0),
    ]
    for section in sections:
        payload.extend(module.SECTION_HDR.pack(*section))

    final_size = len(payload)
    segments = [
        (1, 0, 0x1000, 0x1000, final_size, final_size, 5, 4),
        (2, dynamic_off, 0x1000 + dynamic_off, 0,
         dynamic_size, dynamic_size, 4, 4),
        (0x6474E551, 0, 0, 0, 0, 0, 6, 16),
        (0x6474E552, 0, 0, 0, 0, 0, 4, 4),
    ]
    for i, segment in enumerate(segments):
        module.PROGRAM_HDR.pack_into(payload, module.ELF_HDR.size + i * 32, *segment)
    ident = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    hdr = [
        ident, 3, 40, 1, 0x1010, module.ELF_HDR.size,
        section_off if with_sections else 0,
        0, module.ELF_HDR.size, 32, phcount,
        40, len(sections) if with_sections else 0, 4 if with_sections else 0,
    ]
    module.ELF_HDR.pack_into(payload, 0, *hdr)
    if corrupt == "section_out_of_bounds":
        module.SECTION_HDR.pack_into(payload, section_off + 40, 1, 3, 0, 0,
                                     final_size - 5, 50, 0, 0, 1, 0)
    elif corrupt == "bad_dynsym_link":
        module.SECTION_HDR.pack_into(payload, section_off + 80, 9, 11, 0, 0,
                                     symbol_off, symbol_size, 500, 0, 4, 16)
    elif corrupt == "oversized_program":
        module.PROGRAM_HDR.pack_into(payload, module.ELF_HDR.size,
                                     1, 0, 0x1000, 0, final_size + 5,
                                     final_size + 5, 5, 4)
    return bytes(payload)


class R840XFotaOfflineElfTests(unittest.TestCase):
    def test_parses_dynamic_dependencies_and_allowlisted_imports(self):
        report = module.analyze(fake_elf())
        self.assertEqual(report["status"], "TEST_ELF_ANALYZED")
        elf = report["elf"]
        self.assertEqual(elf["architecture"], "ARM_ELF32_LITTLE_ENDIAN")
        self.assertEqual(elf["elf_type"], "ET_DYN")
        self.assertEqual(elf["dependencies"], ["libc.so.6"])
        self.assertEqual(elf["dynamic_symbols_status"], "OBSERVED")
        self.assertEqual(elf["allowlisted_imports_by_category"]["process_launch"],
                         ["system"])
        self.assertEqual(elf["allowlisted_imports_by_category"]["file_io"],
                         ["rename"])
        self.assertEqual(elf["relro"], "FULL_RELRO_INDICATED")
        self.assertEqual(elf["executable_stack"], "NONEXECUTABLE")
        self.assertFalse(report["fota_vulnerability_proven"])
        self.assertFalse(report["root_obtained"])
        self.assertFalse(report["binary_executed"])

    def test_stripped_elf_uses_dynamic_segment_for_dependency(self):
        report = module.analyze(fake_elf(with_sections=False))
        elf = report["elf"]
        self.assertEqual(elf["section_header_count"], 0)
        self.assertEqual(elf["dynamic_symbols_status"], "UNAVAILABLE")
        self.assertEqual(elf["dependencies"], ["libc.so.6"])
        self.assertIsNone(elf["undefined_dynamic_symbol_count"])

    def test_strict_hash_and_length_pin(self):
        sample = fake_elf()
        digest = hashlib.sha256(sample).hexdigest()
        report = module.analyze(sample, digest, len(sample))
        self.assertEqual(report["status"], "PINNED_LOCAL_ELF_ANALYZED")
        with self.assertRaisesRegex(module.OfflineELFError, "SOURCE_SHA256_MISMATCH"):
            module.analyze(sample, "0" * 64, len(sample))
        with self.assertRaisesRegex(module.OfflineELFError, "SOURCE_FILE_SIZE_MISMATCH"):
            module.analyze(sample, digest, len(sample) + 1)

    def test_arbitrary_private_strings_and_symbol_names_never_emitted(self):
        sample = fake_elf(private_marker=b"PRIVATE-EMAIL@example.com\0"
                                         b"fota signature verify\0")
        serialized = json.dumps(module.analyze(sample))
        self.assertNotIn("PRIVATE-EMAIL", serialized)
        self.assertNotIn("internal_secret_9876", serialized)
        self.assertNotIn("/usr/share", serialized)
        self.assertEqual(module.analyze(sample)["elf"]["static_string_marker_counts"]
                         ["fota"], 1)

    def test_truncated_and_wrong_arch_rejected(self):
        with self.assertRaisesRegex(module.OfflineELFError, "INVALID_ELF_SIZE"):
            module.analyze(b"\x7fELF")
        wrong = bytearray(fake_elf())
        wrong[18:20] = (183).to_bytes(2, "little")
        with self.assertRaisesRegex(module.OfflineELFError, "NOT_SUPPORTED_ARM_ELF32"):
            module.analyze(bytes(wrong))

    def test_out_of_bounds_and_invalid_reference_fail_closed(self):
        for issue in ("section_out_of_bounds", "bad_dynsym_link",
                      "oversized_program"):
            with self.subTest(issue=issue):
                with self.assertRaises(module.OfflineELFError):
                    module.analyze(fake_elf(corrupt=issue))

    def test_report_is_created_private_without_overwriting_existing(self):
        sample = fake_elf()
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "sample.bin"
            output = Path(td) / "report.json"
            source.write_bytes(sample)
            with patch.object(module, "EXPECTED_SHA256",
                              hashlib.sha256(sample).hexdigest()), patch.object(
                                  module, "EXPECTED_BYTES", len(sample)), patch.object(
                                      sys, "argv", ["analyze", "--input", str(source),
                                                    "--report", str(output)]):
                self.assertEqual(module.main(), 0)
                self.assertEqual(output.stat().st_mode & 0o077, 0)
                before = output.read_bytes()
                self.assertEqual(module.main(), 1)
                self.assertEqual(output.read_bytes(), before)

    def test_no_watch_imports_or_network_calls_in_analyzer(self):
        source = Path(module.__file__).read_text()
        for banned in ("import socket", "import requests", "subprocess",
                       "watch3_r08_android_sdb", "socket.create_connection",
                       "os.system(", "eval(", "exec("):
            self.assertNotIn(banned, source)
        self.assertEqual(module.EXPECTED_BYTES, 87036)
        self.assertEqual(module.EXPECTED_SHA256,
                         "008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757")


if __name__ == "__main__":
    unittest.main()
