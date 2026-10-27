#!/usr/bin/env python3
"""Offline ARM ELF32 inspection of the exact R840X FOTA service extraction.

No Tizen/SDB imports, network, binary execution, exploit testing or watch I/O.
Reports only allowlisted dynamic imports, safe SONAMEs, bounded numeric
metadata and counts of predetermined ASCII markers. Raw strings stay private.
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

EXPECTED_SHA256 = "008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757"
EXPECTED_BYTES = 87036
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
}
ALLOWED_IMPORTS = frozenset().union(*IMPORT_GROUPS.values())
# Weak strings hints are NOT call sites, privileges or proof of vulnerability.
MARKERS = (
    "fota", "firmware", "update", "signature", "verify", "rollback",
    "sha256", "rsa", "openssl", "libarchive", "zip", "tar", "sapd",
    "samsung", "dbus", "omadm", "delta", "reboot", "recovery",
    "http", "https", "ssl", "chmod", "rename",
)


class OfflineELFError(ValueError):
    """Categorical parsing failure, never raw data from the executable."""


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


def parse_elf32(data: bytes) -> dict[str, object]:
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
            if shindex != 0 or name_off == 0:
                continue
            undefined_symbols_total += 1
            name = c_string(names, name_off)
            if name in ALLOWED_IMPORTS:
                symbols.add(name)

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
    return {
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
        "dependencies_status": ("OBSERVED" if dynstr is not None else "NO_DYNAMIC_STRING_TABLE"),
        "dynamic_symbols_status": "OBSERVED" if symbol_table_seen else "UNAVAILABLE",
        "undefined_dynamic_symbol_count": undefined_symbols_total if symbol_table_seen else None,
        "allowlisted_imports_by_category": categories,
        "static_string_marker_counts": marker_counts,
    }


def analyze(data: bytes, expected_sha256: str | None = None,
            expected_bytes: int | None = None) -> dict[str, object]:
    if not isinstance(data, bytes):
        raise OfflineELFError("BINARY_INPUT_REQUIRED")
    digest = hashlib.sha256(data).hexdigest()
    if expected_bytes is not None and len(data) != expected_bytes:
        raise OfflineELFError("SOURCE_FILE_SIZE_MISMATCH")
    if expected_sha256 is not None and digest != expected_sha256:
        raise OfflineELFError("SOURCE_SHA256_MISMATCH")
    facts = parse_elf32(data)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path,
                        default=Path.home() / "watch3-r840x-fota-service-readonly.bin",
                        help="Local ELF extracted from R840X; exact physical hash required")
    parser.add_argument("--report", type=Path,
                        default=Path.home() / "watch3-r840x-fota-static-analysis.json",
                        help="New local privacy-filtered JSON file; never overwrite")
    args = parser.parse_args()
    try:
        if args.input.stat().st_size > MAX_BYTES:
            raise OfflineELFError("SOURCE_EXCEEDS_EIGHT_MIB")
        result = analyze(args.input.read_bytes(), EXPECTED_SHA256, EXPECTED_BYTES)
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
