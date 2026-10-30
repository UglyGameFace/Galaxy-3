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


def fake_elf(*, with_sections=True, corrupt=None, private_marker=b"",
             needed="libc.so.6", soname=None, export=None,
             export_info=18, export_other=0, export_addr=0x1011,
             export_shindex=1) -> bytes:
    """Minimal structurally consistent ARM ELF32 with section AND segment views."""
    phcount = 4
    payload = bytearray(module.ELF_HDR.size + phcount * module.PROGRAM_HDR.size)
    payload.extend(b"\0" * (192 - len(payload)))

    dynstr = b"\0" + needed.encode() + b"\0system\0rename\0internal_secret_9876\0"
    lib_name = dynstr.index(needed.encode())
    system_name = dynstr.index(b"system")
    rename_name = dynstr.index(b"rename")
    secret_name = dynstr.index(b"internal_secret")
    soname_name = len(dynstr)
    if soname is not None:
        dynstr += soname.encode() + b"\0"
    export_name = len(dynstr)
    if export is not None:
        dynstr += export.encode() + b"\0"
    str_off = len(payload)
    payload.extend(dynstr)
    symbol_off = len(payload)
    symbols = [
        (0, 0, 0, 0, 0, 0),
        (system_name, 0, 0, 18, 0, 0),
        (rename_name, 0, 0, 18, 0, 0),
        (secret_name, 0, 0, 18, 0, 0),
    ]
    if export is not None:
        symbols.append((export_name, export_addr, 2, export_info,
                        export_other, export_shindex))
    for values in symbols:
        payload.extend(module.SYMBOL_ENTRY.pack(*values))
    symbol_size = len(payload) - symbol_off

    dynamic_off = len(payload)
    dynamics = [
        (1, lib_name), (5, 0x1000 + str_off),
        (10, len(dynstr)), (24, 0),
    ]
    if soname is not None:
        dynamics.append((14, soname_name))
    dynamics.append((0, 0))
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
    def test_pkey_and_certificate_checks_are_reported_separately_from_digest_primitives(self):
        for name in ('EVP_PKEY_verify', 'X509_verify_cert'):
            with self.subTest(name=name):
                facts = module.parse_elf32(fake_elf(export=name, export_shindex=0))
                self.assertEqual(facts['allowlisted_imports_by_category']['crypto_verification'], [name])
                self.assertEqual(facts['allowlisted_function_exports'], [])
        for name in ('EVP_DigestInit_ex', 'EVP_DigestUpdate', 'EVP_DigestFinal'):
            with self.subTest(name=name):
                facts = module.parse_elf32(fake_elf(export=name, export_shindex=0))
                self.assertEqual(facts['allowlisted_imports_by_category']['crypto_verification'], [])
                self.assertEqual(facts['allowlisted_imports_by_category']['other_crypto'], [name])

    def test_original_daemon_and_device_plugin_profiles_reject_changed_bytes_and_custom_pins(self):
        sample = fake_elf()
        for component in ('oma-dm-agent', 'dm-device-plugin'):
            with self.subTest(component=component):
                digest, size = module.PINNED_PROFILES[component]
                with self.assertRaisesRegex(module.OfflineELFError, 'SOURCE_FILE_SIZE_MISMATCH'):
                    module.analyze(sample, component=component)
                with self.assertRaisesRegex(module.OfflineELFError, 'SOURCE_SHA256_MISMATCH'):
                    module.analyze(sample + b'\0' * (size - len(sample)), component=component)
                with self.assertRaisesRegex(module.OfflineELFError, 'COMPONENT_PROFILE_MISMATCH'):
                    module.analyze(sample, hashlib.sha256(sample).hexdigest(), len(sample), component=component)

    def test_digest_imports_are_distinct_from_signature_checks_and_md5_export_is_visible(self):
        facts = module.parse_elf32(fake_elf(export="gcry_md_open", export_shindex=0))
        self.assertEqual(facts["allowlisted_imports_by_category"]["other_crypto"], ["gcry_md_open"])
        self.assertEqual(facts["allowlisted_imports_by_category"]["crypto_verification"], [])
        facts = module.parse_elf32(fake_elf(export="sync_agent_file_md5_validation"))
        self.assertEqual(facts["allowlisted_function_exports"][0]["name"], "sync_agent_file_md5_validation")

    def test_sync_agent_profile_is_pinned_and_cannot_accept_a_sibling_or_supplied_pin(self):
        sample = fake_elf(soname="libsync-agent.so.0")
        with self.assertRaisesRegex(module.OfflineELFError, "SOURCE_FILE_SIZE_MISMATCH"):
            module.analyze(sample, component="sync-agent")
        padded = sample + b"\0" * (module.SYNC_AGENT_BYTES - len(sample))
        with self.assertRaisesRegex(module.OfflineELFError, "SOURCE_SHA256_MISMATCH"):
            module.analyze(padded, component="sync-agent")
        with self.assertRaisesRegex(module.OfflineELFError, "COMPONENT_PROFILE_MISMATCH"):
            module.analyze(sample, hashlib.sha256(sample).hexdigest(), len(sample), component="sync-agent")

    def test_library_soname_and_defined_install_function_are_distinct_from_imports(self):
        facts = module.parse_elf32(fake_elf(soname="libsync-agent.so.0",
                                          export="sync_agent_dm_fota_install"))
        self.assertEqual(facts["soname"], "libsync-agent.so.0")
        self.assertEqual(facts["allowlisted_function_exports"], [{
            "name": "sync_agent_dm_fota_install", "address_hex": "0x00001011",
            "code_address_hex": "0x00001010", "bytes": 2, "thumb": True}])
        self.assertNotIn("sync_agent_dm_fota_install",
                         facts["allowlisted_imports_by_category"]["update_agent"])
        stripped = module.parse_elf32(fake_elf(with_sections=False,
                                               soname="libsync-agent.so.0"))
        self.assertEqual(stripped["soname"], "libsync-agent.so.0")
        self.assertEqual(stripped["allowlisted_function_exports"], [])

    def test_hidden_local_undefined_and_unmapped_symbols_are_not_function_implementations(self):
        cases = ({"export_other": 2}, {"export_info": 2}, {"export_info": 17},
                 {"export_shindex": 0}, {"export_shindex": 0xFFF1},
                 {"export_addr": 0x900001})
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                facts = module.parse_elf32(fake_elf(export="sync_agent_dm_fota_install", **kwargs))
                self.assertEqual(facts["allowlisted_function_exports"], [])
        facts = module.parse_elf32(fake_elf(export="internal_secret_9876"))
        self.assertEqual(facts["allowlisted_function_exports"], [])

    def test_thumb_call_decoder_matches_independently_reviewed_calls_and_alignment(self):
        # Instruction examples only, not a firmware image or an unlock test.
        for address, encoded, expected in (
            (0x6348, "fef718f8", ("BL", 0x437C)),
            (0x6686, "fff7a3fd", ("BL", 0x61D0)),
            (0x6216, "fdf7feed", ("BLX", 0x3E14)),
            (0x1002, "00f000f8", ("BL", 0x1006)),
            (0x1002, "00f000e8", ("BLX", 0x1004)),
        ):
            with self.subTest(address=address):
                self.assertEqual(module.thumb_call_target(bytes.fromhex(encoded), address), expected)

    def test_thumb_decoder_rejects_non_calls_truncation_odd_addresses_and_reserved_blx(self):
        for instruction, address in ((b"\0\0", 0), (b"\0" * 4, 0),
                                     (bytes.fromhex("00f001e8"), 0),
                                     (bytes.fromhex("00f000f8"), 1)):
            with self.assertRaises(module.OfflineELFError):
                module.thumb_call_target(instruction, address)
        self.assertEqual(module.arm_immediate(0x001), 1)
        self.assertEqual(module.arm_immediate(0x401), 0x01000000)
        self.assertEqual(module.arm_immediate(0xC80), 0x8000)

    def test_consumer_profile_cannot_accept_a_sibling_or_caller_supplied_hash(self):
        sample = fake_elf()
        with self.assertRaisesRegex(module.OfflineELFError, "SOURCE_FILE_SIZE_MISMATCH"):
            module.analyze(sample, component="fota-consumer")
        padded = sample + b"\0" * (module.CONSUMER_BYTES - len(sample))
        with self.assertRaisesRegex(module.OfflineELFError, "SOURCE_SHA256_MISMATCH"):
            module.analyze(padded, component="fota-consumer")
        with self.assertRaisesRegex(module.OfflineELFError, "COMPONENT_PROFILE_MISMATCH"):
            module.analyze(sample, hashlib.sha256(sample).hexdigest(), len(sample), component="fota-consumer")
        with self.assertRaisesRegex(module.OfflineELFError, "CONSUMER_REVIEW_REQUIRES_ORIGINAL_BYTES"):
            module.reviewed_consumer(padded, [], [])
        with self.assertRaisesRegex(module.OfflineELFError, "UNKNOWN_FOTA_COMPONENT"):
            module.analyze(sample, component="arbitrary")

    def test_consumer_default_uses_existing_phone_capture_and_rejects_wrong_bytes_before_output(self):
        with tempfile.TemporaryDirectory() as td, patch.object(module.Path, "home", return_value=Path(td)):
            folder = Path(td) / "watch3-r840x-fota-unit-evidence"
            folder.mkdir()
            original = folder / "fota-configured-executable.bin"
            original.write_bytes(fake_elf())
            before = original.read_bytes()
            self.assertEqual(module.main(["--component", "fota-consumer"]), 1)
            self.assertEqual(original.read_bytes(), before)
            self.assertFalse((Path(td) / "watch3-r840x-fota-consumer-static-analysis.json").exists())

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
