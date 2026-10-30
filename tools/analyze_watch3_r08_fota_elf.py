#!/usr/bin/env python3
"""Offline ARM ELF32 inspection of the original R840X FOTA extractions.

No Tizen/SDB imports, network, binary execution, exploit testing or watch I/O.
Reports only allowlisted dynamic imports, safe SONAMEs, bounded numeric
metadata and counts of predetermined ASCII markers. Raw strings stay private.
The separate pinned consumer profile verifies reviewed instruction targets,
PLT/GOT relocations and literal references, without executing vendor code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import xml.etree.ElementTree as ET

EXPECTED_SHA256 = "008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757"
EXPECTED_BYTES = 87036
CONSUMER_SHA256 = "19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a"
CONSUMER_BYTES = 89980
SYNC_AGENT_SHA256 = "3fbebb3d55a7e6a132f3516af88280e63278a4b3bf51cb61cca194614b605a97"
SYNC_AGENT_BYTES = 647076
MAX_BYTES = 8 * 1024 * 1024
ELF_HDR = struct.Struct("<16sHHIIIIIHHHHHH")
PROGRAM_HDR = struct.Struct("<IIIIIIII")
SECTION_HDR = struct.Struct("<IIIIIIIIII")
DYNAMIC_ENTRY = struct.Struct("<iI")
SYMBOL_ENTRY = struct.Struct("<IIIBBH")
SAFE_SONAME = re.compile(r"[A-Za-z0-9_+.-]{1,100}[.]so(?:[.][0-9]+)*\Z")
ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,512}")

# Only public API identifiers that materially help a FOTA trust-boundary audit.
# Never output arbitrary symbols (some can contain private internal paths).
IMPORT_GROUPS = {
    "file_io": frozenset(("open", "open64", "openat", "read", "pread", "pread64",
                          "write", "pwrite", "close", "fopen", "fread",
                          "fwrite", "fclose", "stat", "lstat", "fstat",
                          "access", "rename", "unlink", "remove", "chmod",
                          "chown", "realpath", "mkstemp", "mkdir")),
    "process_launch": frozenset(("system", "popen", "execve", "execl", "fork",
                                 "vfork", "posix_spawn", "posix_spawnp",
                                 "g_spawn_async", "g_spawn_sync")),
    "network_ipc": frozenset(("socket", "bind", "listen", "accept", "connect",
                              "send", "recv", "sendto", "recvfrom",
                              "dbus_bus_get", "dbus_connection_send",
                              "g_dbus_connection_call_sync")),
    "dynamic_loading": frozenset(("dlopen", "dlsym", "dlclose")),
    "parsing_memory": frozenset(("strcpy", "strcat", "sprintf", "snprintf",
                                 "memcpy", "memmove", "strcmp", "strncmp",
                                 "memcmp", "strncpy", "strncat", "sscanf",
                                 "strtol", "strtoul")),
    "crypto_verification": frozenset(("SHA256", "SHA256_Init", "SHA256_Update",
                                      "SHA256_Final", "EVP_DigestVerifyFinal",
                                      "RSA_verify", "X509_verify",
                                      "EVP_VerifyFinal")),
    "dbus_dispatch": frozenset(("g_bus_own_name", "g_dbus_connection_register_object",
                                 "g_variant_get", "g_dbus_method_invocation_return_value")),
    "update_agent": frozenset(("sync_agent_init", "sync_agent_is_existing_fs",
                                "sync_agent_dm_fota_install", "sync_agent_dm_fota_force_install",
                                "sync_agent_dm_fota_software_update", "device_power_reboot",
                                "vconf_notify_key_changed", "sync_agent_file_md5_validation")),
    # Digest/HMAC primitives are not, by themselves, signature verification.
    "other_crypto": frozenset(("DES_set_key", "DES_ecb_encrypt", "gcry_md_open",
                               "gcry_md_write", "gcry_md_setkey", "gcry_md_close",
                               "gcry_md_get_algo_dlen", "gcry_md_copy", "gcry_md_read")),
}
ALLOWED_IMPORTS = frozenset().union(*IMPORT_GROUPS.values())
# Weak strings hints are NOT call sites, privileges or proof of vulnerability.
MARKERS = (
    "fota", "firmware", "update", "signature", "verify", "rollback",
    "sha256", "md5", "rsa", "openssl", "libarchive", "zip", "tar", "sapd",
    "samsung", "dbus", "omadm", "delta", "reboot", "recovery",
    "http", "https", "ssl", "chmod", "rename",
)


class OfflineELFError(ValueError):
    """Categorical parsing failure, never raw data from the executable."""


def thumb_call_target(instruction: bytes, address: int) -> tuple[str, int]:
    """Decode a Thumb-2 immediate BL/BLX only, including BLX PC alignment.

    Reviewed against Capstone 5.0.6 on every emitted consumer call edge.
    This is instruction decoding, not execution or a reachability analysis.
    """
    if len(instruction) != 4 or address < 0 or address & 1:
        raise OfflineELFError("INVALID_THUMB_CALL_LOCATION")
    first, second = struct.unpack("<HH", instruction)
    if first & 0xF800 != 0xF000:
        raise OfflineELFError("NOT_THUMB_IMMEDIATE_CALL")
    if second & 0xD000 == 0xD000:
        kind, pc = "BL", address + 4
    elif second & 0xD001 == 0xC000:
        kind, pc = "BLX", (address + 4) & ~3
    else:
        raise OfflineELFError("NOT_THUMB_IMMEDIATE_CALL")
    sign = (first >> 10) & 1
    i1 = 1 ^ (((second >> 13) & 1) ^ sign)
    i2 = 1 ^ (((second >> 11) & 1) ^ sign)
    displacement = ((sign << 24) | (i1 << 23) | (i2 << 22) |
                    ((first & 0x3FF) << 12) | ((second & 0x7FF) << 1))
    if displacement & (1 << 24):
        displacement -= 1 << 25
    return kind, (pc + displacement) & 0xFFFFFFFF


def arm_immediate(value: int) -> int:
    """ARM data-processing modified immediate, without evaluating code."""
    shift = ((value >> 8) & 15) * 2
    byte = value & 255
    return ((byte >> shift) | (byte << ((32 - shift) & 31))) & 0xFFFFFFFF


def reviewed_consumer(data: bytes, segments: list, sections: list) -> dict:
    """Verify the original consumer's reviewed boundaries; no live RPC exists.

    This additional review is intentionally exact-file only. A similar ELF,
    changed firmware or synthetic ELF cannot inherit these conclusions.
    """
    if len(data) != CONSUMER_BYTES or hashlib.sha256(data).hexdigest() != CONSUMER_SHA256:
        raise OfflineELFError("CONSUMER_REVIEW_REQUIRES_ORIGINAL_BYTES")

    def at(address, size):
        for seg in segments:
            relative = address - seg["vaddr"]
            if (seg["type"] == 1 and 0 <= relative <= seg["filesz"] and
                    0 <= size <= seg["filesz"] - relative):
                return checked_slice(data, seg["off"] + relative, size)
        raise OfflineELFError("REVIEW_ADDRESS_NOT_FILE_BACKED")

    def symbol(table, index):
        if table["type"] != 11 or table["entsize"] != 16 or not 0 <= index < table["size"] // 16:
            raise OfflineELFError("REVIEW_SYMBOL_TABLE_INVALID")
        names = sections[table["link"]]
        entry = SYMBOL_ENTRY.unpack(checked_slice(data, table["off"] + index * 16, 16))
        name = c_string(checked_slice(data, names["off"], names["size"]), entry[0])
        return name, entry

    slots, defined = {}, {}
    for sec in sections:
        if sec["type"] == 11:
            for i in range(sec["size"] // 16):
                name, entry = symbol(sec, i)
                if name and entry[5] and entry[3] & 15 == 2:
                    defined[name] = entry[1] & ~1
        if sec["type"] == 9:
            if sec["size"] % 8 or sec["link"] >= len(sections):
                raise OfflineELFError("REVIEW_RELOCATION_TABLE_INVALID")
            for pos in range(sec["off"], sec["off"] + sec["size"], 8):
                location, info = struct.unpack("<II", checked_slice(data, pos, 8))
                if info & 255 == 22:  # R_ARM_JUMP_SLOT, never positional PLT guesses
                    name, _ = symbol(sections[sec["link"]], info >> 8)
                    slots[location] = name

    expected_calls = (
        (0xAC5C, "g_bus_own_name"), (0xA3F0, "g_dbus_connection_register_object"),
        (0xCC28, "vconf_notify_key_changed"), (0xA84E, "do_device_control"),
        (0x6566, "get_fota_consumer_state"), (0x6686, "device_ctrl_do_firmware_update"),
        (0x6348, "_pre_update_client"), (0x621E, "system_cmd"),
        (0x62BA, "system_cmd"), (0x6312, "system_cmd"), (0x63DE, "system_cmd"),
        (0x43FC, "system_cmd"), (0x447C, "system_cmd"), (0x44F0, "system_cmd"),
        (0x8E72, "fork"), (0x8F7E, "execve"), (0x66A8, "request_reboot"),
        (0x42EC, "device_power_reboot"), (0xBAB4, "g_variant_get"),
        (0xBABC, "getpid"), (0xBAD4, "g_variant_new"),
        (0xBADC, "g_dbus_method_invocation_return_value"),
        (0xBB12, "g_free"), (0xBBE8, "fopen"), (0xBBFA, "fread"),
        (0xBC44, "g_strcmp0"), (0xBC52, "g_strcmp0"),
        (0xC172, "set_current_caller"),
    )
    calls = []
    for address, name in expected_calls:
        kind, target = thumb_call_target(at(address, 4), address)
        item = {"call_hex": hex(address), "target_hex": hex(target), "kind": kind, "symbol": name}
        if name in defined:
            if kind != "BL" or target != defined[name]:
                raise OfflineELFError("REVIEW_DEFINED_CALL_MISMATCH")
        else:
            first, second, third = struct.unpack("<III", at(target, 12))
            if (kind != "BLX" or first & 0xFFFFF000 != 0xE28FC000 or
                    second & 0xFFFFF000 != 0xE28CC000 or third & 0xFFFFF000 != 0xE5BCF000):
                raise OfflineELFError("REVIEW_ARM_PLT_STUB_MISMATCH")
            got = (target + 8 + arm_immediate(first) + arm_immediate(second) + (third & 4095)) & 0xFFFFFFFF
            if slots.get(got) != name:
                raise OfflineELFError("REVIEW_JUMP_SLOT_SYMBOL_MISMATCH")
            item["got_slot_hex"] = hex(got)
        calls.append(item)

    def literal_address(load, add):
        instruction = struct.unpack("<H", at(load, 2))[0]
        register = (instruction >> 8) & 7
        if instruction & 0xF800 != 0x4800 or struct.unpack("<H", at(add, 2))[0] != (0x4478 | register):
            raise OfflineELFError("REVIEW_LITERAL_REFERENCE_MISMATCH")
        pool = ((load + 4) & ~3) + (instruction & 255) * 4
        return (struct.unpack("<I", at(pool, 4))[0] + add + 4) & 0xFFFFFFFF

    references = []
    for load, add, expected in (
        (0x6342, 0x6346, "/opt/usr/data/fota/save/delta.tar"),
        (0x6340, 0x6344, "pre_update_client_2"),
        (0x621A, 0x621C, "/usr/bin/md5sum /opt/usr/data/fota/save/delta.tar > /opt/usr/data/fota/save/fota_delta_md5.log"),
        (0x62B2, 0x62B6, "/bin/tar xvfp /opt/usr/data/fota/save/delta.tar -C /opt/usr/data/fota/save/ delta.ua"),
        (0x630A, 0x630E, "echo /opt/usr/data/fota/save > /opt/data/recovery/DELTA.PATH"),
        (0x63D4, 0x63DA, "/usr/bin/rw-update-prepare.sh FOTA"),
        (0x43EE, 0x43F2, "/bin/tar xvpf %s -C /opt/usr/data/fota/save/ pre_update.tar"),
        (0x446C, 0x4472, "/bin/tar xvpf %s -C /opt/usr/data/fota/save/ %s"),
        (0x44AE, 0x44B2, "/opt/usr/data/fota/save/%s"),
        (0x8F64, 0x8F6E, "/bin/sh"),
    ):
        address = literal_address(load, add)
        if at(address, len(expected) + 1) != expected.encode("ascii") + b"\0":
            raise OfflineELFError("REVIEW_LITERAL_TEXT_MISMATCH")
        references.append({"load_hex": hex(load), "add_hex": hex(add),
                           "literal_hex": hex(address), "reviewed_text": expected})
    table = literal_address(0xA3DC, 0xA3E0)
    if struct.unpack("<I", at(table, 4))[0] != 0xBA05:
        raise OfflineELFError("REVIEW_METHOD_CALLBACK_MISMATCH")
    checks = ((0xAC50, "0120"), (0xBA08, "0421"), (0xBA16, "0220"), (0x44EE, "3846"),
              (0x4438, "0128"), (0x44C2, "48d0"), (0x656A, "3c28"), (0x6572, "4128"))
    if any(at(address, len(bytes.fromhex(value))) != bytes.fromhex(value) for address, value in checks):
        raise OfflineELFError("REVIEW_CONTROL_INSTRUCTION_MISMATCH")
    xml = at(0x12474, 4096).split(b"\0", 1)[0]
    if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
        raise OfflineELFError("REVIEW_DBUS_XML_INVALID")
    try:
        node = ET.fromstring(xml)
    except ET.ParseError:
        raise OfflineELFError("REVIEW_DBUS_XML_INVALID") from None
    interface = node.find("interface")
    if interface is None or interface.get("name") != "fota.consumer":
        raise OfflineELFError("REVIEW_DBUS_XML_INVALID")
    methods = []
    for method in interface.findall("method"):
        name = method.get("name", "")
        args = [(arg.get("direction"), arg.get("type")) for arg in method.findall("arg")]
        if not re.fullmatch(r"[A-Za-z_]{1,32}", name) or args != [("in", "i"), ("in", "s"), ("out", "i")]:
            raise OfflineELFError("REVIEW_DBUS_XML_INVALID")
        methods.append(name)
    return {
        "status": "PINNED_INSTRUCTION_AND_RELOCATION_REVIEW",
        "method_callback_hex": "0xba04", "vtable_hex": hex(table),
        "embedded_interface": "fota.consumer", "embedded_methods": methods,
        "verified_calls": calls, "verified_literal_references": references,
        "reviewed_control_instruction_count": len(checks),
        "caller_boundary": "Handler discards callback connection/sender, accepts caller_pid in (is), frees cookie; LaunchIp label read classifies the claimed PID. Bus policy and runtime permissions remain unverified.",
        "archive_boundary": "Nested pre_update.tar yields pre_update_client_2, which the wrapper passes to system_cmd before rw-update-prepare.sh. No explicit signature gate was observed in this wrapper; earlier/later and library checks remain unresolved.",
        "recovery_boundary": "Actual consumer writes /opt/data/recovery/DELTA.PATH and calls rw-update-prepare.sh FOTA; script, update agent, recovery kernel and bootloader acceptance remain unverified.",
        "no_live_reachability_claim": True,
        "signature_bypass_proven": False,
        "bootloader_unlock_proven": False,
    }


def checked_slice(data: bytes, offset: int, count: int) -> bytes:
    if offset < 0 or count < 0 or offset > len(data) or count > len(data) - offset:
        raise OfflineELFError("ELF_OFFSET_OUT_OF_BOUNDS")
    return data[offset:offset + count]


def c_string(blob: bytes, offset: int) -> str | None:
    if not 0 <= offset < len(blob):
        return None
    end = blob.find(b"\0", offset)
    if end == -1 or end - offset > 128:
        return None
    try:
        return blob[offset:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def parse_elf32(data: bytes, *, consumer_review=False) -> dict[str, object]:
    if len(data) < ELF_HDR.size or len(data) > MAX_BYTES:
        raise OfflineELFError("INVALID_ELF_SIZE")
    (ident, kind, machine, version, entry, phoff, shoff, flags,
     ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = ELF_HDR.unpack_from(data)
    if (ident[:4] != b"\x7fELF" or ident[4:7] != b"\x01\x01\x01"
            or machine != 40 or version != 1 or kind not in (2, 3)
            or ehsize != ELF_HDR.size):
        raise OfflineELFError("NOT_SUPPORTED_ARM_ELF32")
    if phnum > 128 or shnum > 1024:
        raise OfflineELFError("UNREASONABLE_ELF_TABLE_SIZE")
    if phnum and (phoff == 0 or phentsize != PROGRAM_HDR.size):
        raise OfflineELFError("INVALID_PROGRAM_TABLE")
    if shnum and (shoff == 0 or shentsize != SECTION_HDR.size):
        raise OfflineELFError("INVALID_SECTION_TABLE")
    if not shnum and shoff:
        raise OfflineELFError("ELF_EXTENDED_SECTIONS_NOT_SUPPORTED")

    segments = []
    for i in range(phnum):
        hdr = checked_slice(data, phoff + i * phentsize, PROGRAM_HDR.size)
        ptype, off, vaddr, paddr, filesz, memsz, perms, alignment = PROGRAM_HDR.unpack(hdr)
        checked_slice(data, off, filesz)
        segments.append({"type": ptype, "off": off, "vaddr": vaddr,
                         "filesz": filesz, "memsz": memsz, "perms": perms})
    sections = []
    for i in range(shnum):
        hdr = checked_slice(data, shoff + i * shentsize, SECTION_HDR.size)
        (name, stype, sflags, vaddr, off, size, link,
         info, align, entsize) = SECTION_HDR.unpack(hdr)
        if stype != 8:  # SHT_NOBITS occupies no bytes in the file
            checked_slice(data, off, size)
        sections.append({"type": stype, "off": off, "size": size,
                         "link": link, "entsize": entsize})

    dependencies = set()
    symbols = set()
    sonames = set()
    exports = {}
    undefined_symbols_total = 0
    symbol_table_seen = False
    dynamic_pairs = []
    dynstr = None

    for s in sections:
        if s["type"] != 6:  # SHT_DYNAMIC
            continue
        if s["link"] >= len(sections):
            raise OfflineELFError("INVALID_DYNAMIC_STRING_LINK")
        ref = sections[s["link"]]
        if ref["type"] != 3:  # SHT_STRTAB
            raise OfflineELFError("INVALID_DYNAMIC_STRING_TABLE")
        dynstr = checked_slice(data, ref["off"], ref["size"])
        if s["size"] % DYNAMIC_ENTRY.size:
            raise OfflineELFError("INVALID_DYNAMIC_ENTRY_SIZE")
        for pos in range(s["off"], s["off"] + s["size"], DYNAMIC_ENTRY.size):
            tag, value = DYNAMIC_ENTRY.unpack_from(data, pos)
            if tag == 0:
                break
            dynamic_pairs.append((tag, value))

    # For executables stripped of section headers, recover DT_NEEDED via
    # PT_DYNAMIC and the virtual address map of PT_LOAD. All bounds checked.
    if dynstr is None:
        dseg = next((x for x in segments if x["type"] == 2), None)
        if dseg is not None:
            if dseg["filesz"] % DYNAMIC_ENTRY.size:
                raise OfflineELFError("INVALID_DYNAMIC_SEGMENT_SIZE")
            for pos in range(dseg["off"], dseg["off"] + dseg["filesz"], 8):
                tag, value = DYNAMIC_ENTRY.unpack_from(data, pos)
                if tag == 0:
                    break
                dynamic_pairs.append((tag, value))
            table_va = next((v for t, v in dynamic_pairs if t == 5), None)
            table_size = next((v for t, v in dynamic_pairs if t == 10), None)
            if table_va is not None and table_size is not None:
                if table_size > MAX_BYTES:
                    raise OfflineELFError("UNBOUNDED_DYNAMIC_STRTAB")
                mapping = next((x for x in segments
                                if x["type"] == 1 and
                                x["vaddr"] <= table_va and
                                table_size <= x["filesz"] -
                                (table_va - x["vaddr"])), None)
                if mapping is not None:
                    off = mapping["off"] + (table_va - mapping["vaddr"])
                    dynstr = checked_slice(data, off, table_size)

    for tag, value in dynamic_pairs:
        if tag == 1 and dynstr is not None:
            name = c_string(dynstr, value)
            if name and SAFE_SONAME.fullmatch(name):
                dependencies.add(name)
        elif tag == 14 and dynstr is not None:  # DT_SONAME
            name = c_string(dynstr, value)
            if name and SAFE_SONAME.fullmatch(name):
                sonames.add(name)
    if len(sonames) > 1:
        raise OfflineELFError("CONFLICTING_DYNAMIC_SONAMES")

    for s in sections:
        if s["type"] != 11:  # SHT_DYNSYM
            continue
        if s["link"] >= len(sections) or sections[s["link"]]["type"] != 3:
            raise OfflineELFError("INVALID_DYNSYM_STRING_TABLE")
        if s["entsize"] != SYMBOL_ENTRY.size or s["size"] % SYMBOL_ENTRY.size:
            raise OfflineELFError("INVALID_DYNSYM_ENTRY_SIZE")
        if s["size"] // SYMBOL_ENTRY.size > 30000:
            raise OfflineELFError("EXCESSIVE_DYNSYM")
        symstr = sections[s["link"]]
        names = checked_slice(data, symstr["off"], symstr["size"])
        symbol_table_seen = True
        for pos in range(s["off"], s["off"] + s["size"], SYMBOL_ENTRY.size):
            name_off, addr, size, info, other, shindex = SYMBOL_ENTRY.unpack_from(data, pos)
            if name_off == 0:
                continue
            name = c_string(names, name_off)
            if shindex == 0:
                undefined_symbols_total += 1
                if name in ALLOWED_IMPORTS:
                    symbols.add(name)
            elif (name in ALLOWED_IMPORTS and 0 < shindex < len(sections)
                  and info >> 4 in (1, 2) and info & 15 == 2
                  and other & 3 in (0, 3)):
                # A public function definition must point into file-backed
                # executable code. An undefined import or absolute symbol is
                # not the implementation sought by the dependency collector.
                code = addr & ~1
                mapped = any(x["type"] == 1 and x["perms"] & 1 and
                             x["vaddr"] <= code and
                             max(size, 1) <= x["filesz"] - (code - x["vaddr"])
                             for x in segments)
                if mapped:
                    exports[name] = {"name": name, "address_hex": f"0x{addr:08x}",
                                     "code_address_hex": f"0x{code:08x}",
                                     "bytes": size, "thumb": bool(addr & 1)}

    categories = {
        group: sorted(symbols.intersection(allowed))
        for group, allowed in IMPORT_GROUPS.items()
    }
    marker_counts = {}
    ascii_candidates = [m.group().lower() for m in ASCII_RUN.finditer(data)]
    for marker in MARKERS:
        total = sum(text.count(marker.encode()) for text in ascii_candidates)
        if total:
            marker_counts[marker] = min(total, 999)

    stack_headers = [x for x in segments if x["type"] == 0x6474E551]
    executable_stack = ("UNKNOWN" if not stack_headers else
                        "EXECUTABLE" if stack_headers[0]["perms"] & 1
                        else "NONEXECUTABLE")
    relro = any(x["type"] == 0x6474E552 for x in segments)
    bind_now = any(t == 24 or (t == 30 and v & 8) or
                   (t == 0x6FFFFFFB and v & 1) for t, v in dynamic_pairs)
    facts = {
        "elf_type": "ET_DYN" if kind == 3 else "ET_EXEC",
        "architecture": "ARM_ELF32_LITTLE_ENDIAN",
        "entry_point_hex": f"0x{entry:08x}",
        "program_header_count": len(segments),
        "section_header_count": len(sections),
        "load_segment_count": sum(x["type"] == 1 for x in segments),
        "executable_stack": executable_stack,
        "relro": ("FULL_RELRO_INDICATED" if relro and bind_now
                  else "RELRO_SEGMENT_PRESENT" if relro else "NOT_OBSERVED"),
        "dependencies": sorted(dependencies)[:80],
        "soname": next(iter(sonames), None),
        "allowlisted_function_exports": [exports[name] for name in sorted(exports)],
        "dependencies_status": ("OBSERVED" if dynstr is not None else "NO_DYNAMIC_STRING_TABLE"),
        "dynamic_symbols_status": "OBSERVED" if symbol_table_seen else "UNAVAILABLE",
        "undefined_dynamic_symbol_count": undefined_symbols_total if symbol_table_seen else None,
        "allowlisted_imports_by_category": categories,
        "static_string_marker_counts": marker_counts,
    }
    if consumer_review:
        facts["consumer_trust_map"] = reviewed_consumer(data, segments, sections)
    return facts


def analyze(data: bytes, expected_sha256: str | None = None,
            expected_bytes: int | None = None, *, component=None) -> dict[str, object]:
    if not isinstance(data, bytes):
        raise OfflineELFError("BINARY_INPUT_REQUIRED")
    if component not in (None, "fota-service", "fota-consumer", "sync-agent"):
        raise OfflineELFError("UNKNOWN_FOTA_COMPONENT")
    if component == "fota-consumer":
        if (expected_sha256 not in (None, CONSUMER_SHA256) or
                expected_bytes not in (None, CONSUMER_BYTES)):
            raise OfflineELFError("COMPONENT_PROFILE_MISMATCH")
        expected_sha256, expected_bytes = CONSUMER_SHA256, CONSUMER_BYTES
    elif component == "sync-agent":
        if (expected_sha256 not in (None, SYNC_AGENT_SHA256) or
                expected_bytes not in (None, SYNC_AGENT_BYTES)):
            raise OfflineELFError("COMPONENT_PROFILE_MISMATCH")
        expected_sha256, expected_bytes = SYNC_AGENT_SHA256, SYNC_AGENT_BYTES
    digest = hashlib.sha256(data).hexdigest()
    if expected_bytes is not None and len(data) != expected_bytes:
        raise OfflineELFError("SOURCE_FILE_SIZE_MISMATCH")
    if expected_sha256 is not None and digest != expected_sha256:
        raise OfflineELFError("SOURCE_SHA256_MISMATCH")
    facts = parse_elf32(data, consumer_review=component == "fota-consumer")
    return {
        "schema": "uglyos-r840x-fota-offline-elf-v1",
        "status": "PINNED_LOCAL_ELF_ANALYZED" if expected_sha256 else "TEST_ELF_ANALYZED",
        "source_sha256": digest,
        "source_bytes": len(data),
        "provenance": ("Matches hash and byte count reported from the owner's read-only "
                       "R840X SDB extraction; independent model attestation unavailable."),
        "elf": facts,
        "warning": ("Imports, ELF flags and embedded text are static hints. None proves "
                    "a call site is reachable, a CVE is present, firmware can be replaced, "
                    "a kernel is unsigned, or stock recovery works."),
        "root_obtained": False,
        "fota_vulnerability_proven": False,
        "custom_kernel_boot_proven": False,
        "stock_recovery_proven": False,
        "watch_write_performed": False,
        "binary_executed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=("fota-service", "fota-consumer", "sync-agent"), default="fota-service")
    parser.add_argument("--input", type=Path,
                        help="Local ELF extracted from R840X; exact physical hash required")
    parser.add_argument("--report", type=Path,
                        help="New local privacy-filtered JSON file; never overwrite")
    args = parser.parse_args(argv)
    consumer = args.component == "fota-consumer"
    library = args.component == "sync-agent"
    if args.input is None:
        args.input = (Path.home() / "watch3-r840x-sync-agent-native-evidence/libsync-agent.so.0.bin"
                      if library else Path.home() / "watch3-r840x-fota-unit-evidence/fota-configured-executable.bin"
                      if consumer else Path.home() / "watch3-r840x-fota-service-readonly.bin")
    if args.report is None:
        args.report = Path.home() / ("watch3-r840x-sync-agent-static-analysis.json" if library else
                                   "watch3-r840x-fota-consumer-static-analysis.json"
                                   if consumer else "watch3-r840x-fota-static-analysis.json")
    try:
        if args.input.stat().st_size > MAX_BYTES:
            raise OfflineELFError("SOURCE_EXCEEDS_EIGHT_MIB")
        result = (analyze(args.input.read_bytes(), component=args.component) if consumer or library else
                  analyze(args.input.read_bytes(), EXPECTED_SHA256, EXPECTED_BYTES))
        if not args.report.parent.is_dir():
            raise OfflineELFError("REPORT_DIRECTORY_MISSING")
        payload = (json.dumps(result, indent=2) + "\n").encode("utf-8")
        try:
            fd = os.open(str(args.report), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise OfflineELFError("REPORT_ALREADY_EXISTS") from None
        try:
            with os.fdopen(fd, "wb") as outfile:
                outfile.write(payload)
                outfile.flush()
                os.fsync(outfile.fileno())
        except BaseException:
            args.report.unlink(missing_ok=True)
            raise
    except (OfflineELFError, OSError) as exc:
        print("OFFLINE_ELF_ERROR: " +
              (str(exc) if isinstance(exc, OfflineELFError)
               else "LOCAL_FILE_OPERATION_FAILED"), file=sys.stderr)
        return 1
    print("PINNED_FOTA_ELF_ANALYZED: " + str(args.report))
    print("NO network, watch communication, binary execution, CVE test, or firmware write.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
