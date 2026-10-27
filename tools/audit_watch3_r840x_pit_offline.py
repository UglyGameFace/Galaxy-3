#!/usr/bin/env python3
"""OFFLINE-ONLY Samsung PIT name/filename inventory. Never connects to a watch.

Only interprets fields shared by the common Heimdall PIT layout. The two
known 132-byte entry variants share the three strings at offsets 36, 68,
100, but some numeric fields mean different things across variants. No
storage addresses, partition sizes or signing/rollback flags are inferred.
A parsed PIT is NOT authenticated, proven model-specific, nor safe to flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys

MAGIC = b"\x76\x98\x34\x12"
HEADER_BYTES = 28
ENTRY_BYTES = 132
MAX_ENTRIES = 256
MAX_PIT_BYTES = 1024 * 1024
MAX_COMPONENT_REPORT_BYTES = 256 * 1024
MAX_COMPONENT_ITEMS = 512
MODEL = "SM-R840X"
HEIMDALL_PIN = "3997d5cc607e6c603c6e7c0d07e42e9868c62af2"
RAGNAROEK_PIN = "f9164d2c227369ba711d89f12eef99186df61387"
SAFE_PARTITION = re.compile(r"[A-Za-z0-9_.-]{1,31}\Z")
SAFE_FILENAME = re.compile(r"[A-Za-z0-9_.+-]{1,31}\Z")
SAFE_COMPONENT_FILENAME = re.compile(r"[A-Za-z0-9_.+-]{1,200}\Z")

class OfflinePitError(ValueError):
    """A local-only unsafe/malformed candidate, never an Odin response."""


def _fixed_ascii(raw: bytes, *, required: bool, filename: bool) -> str:
    if len(raw) != 32:
        raise OfflinePitError("INVALID_PIT_STRING_WIDTH")
    if b"\x00" not in raw:
        raise OfflinePitError("UNTERMINATED_PIT_STRING")
    name, _, pad = raw.partition(b"\x00")
    if any(pad):
        raise OfflinePitError("NONZERO_PIT_STRING_PADDING")
    if not name:
        if required:
            raise OfflinePitError("EMPTY_PARTITION_NAME")
        return ""
    try:
        decoded = name.decode("ascii")
    except UnicodeDecodeError:
        raise OfflinePitError("NON_ASCII_PARTITION_METADATA") from None
    if not (SAFE_FILENAME if filename else SAFE_PARTITION).fullmatch(decoded):
        raise OfflinePitError("UNSAFE_PARTITION_METADATA")
    return decoded


def inspect_pit_bytes(data: bytes) -> dict:
    """Only parse a bounded, standalone local PIT; NO device/file access."""
    if len(data) > MAX_PIT_BYTES:
        raise OfflinePitError("PIT_FILE_TOO_LARGE")
    if len(data) < HEADER_BYTES:
        raise OfflinePitError("TRUNCATED_PIT_HEADER")
    if data[:4] != MAGIC:
        raise OfflinePitError("INVALID_PIT_MAGIC")
    count = struct.unpack_from("<I", data, 4)[0]
    if count < 1 or count > MAX_ENTRIES:
        raise OfflinePitError("INVALID_PIT_ENTRY_COUNT")
    expected = HEADER_BYTES + count * ENTRY_BYTES
    if len(data) < expected:
        raise OfflinePitError("TRUNCATED_PIT_ENTRIES")
    if any(data[expected:]):
        raise OfflinePitError("UNKNOWN_NONZERO_PIT_TRAILER")
    entries = []
    seen = set()
    for index in range(count):
        part = data[HEADER_BYTES + index * ENTRY_BYTES:
                    HEADER_BYTES + (index + 1) * ENTRY_BYTES]
        # All known 132-byte PIT layouts have the common name fields
        # at byte offsets 36, 68 and 100. Do not parse numeric geometry.
        name = _fixed_ascii(part[36:68], required=True, filename=False)
        image = _fixed_ascii(part[68:100], required=False, filename=True)
        fota = _fixed_ascii(part[100:132], required=False, filename=True)
        ident = name.casefold()
        if ident in seen:
            raise OfflinePitError("DUPLICATE_PARTITION_NAME")
        seen.add(ident)
        # Immutable raw identifier field, NOT physical partition number.
        identifier = struct.unpack_from("<I", part, 8)[0]
        entries.append({
            "index_in_untrusted_file": index,
            "raw_entry_identifier": identifier,
            "partition_name_unverified": name,
            "flash_filename_unverified": image,
            "fota_filename_unverified": fota,
        })
    return {
        "entry_count": count,
        "entries": entries,
        "entry_name_byte_offsets": [36, 68, 100],
        "entry_size_bytes": ENTRY_BYTES,
        "header_size_bytes": HEADER_BYTES,
        "raw_header_project_model_not_authenticated": True,
        "pit_version_and_numeric_geometry": "UNKNOWN_NOT_INTERPRETED",
        "partition_addresses_not_interpreted": True,
        "storage_block_units_unknown": True,
    }


def _file_bytes(path: Path, limit: int, *, code: str) -> bytes:
    if path.is_symlink():
        raise OfflinePitError(code + "_SYMLINK")
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise OfflinePitError(code + "_NOT_REGULAR_FILE")
        if metadata.st_size < 1 or metadata.st_size > limit:
            raise OfflinePitError(code + "_FILE_SIZE_OUT_OF_BOUNDS")
        # Bounded read prevents large/changed local files from filling RAM.
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        raise OfflinePitError(code + "_UNREADABLE") from None
    if not data or len(data) > limit:
        raise OfflinePitError(code + "_FILE_SIZE_OUT_OF_BOUNDS")
    return data


def _component_names(raw: bytes) -> set[str]:
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        raise OfflinePitError("INVALID_COMPONENT_JSON") from None
    if not isinstance(obj, dict) or obj.get("schema") != "uglyos-r840x-odin-components-v1":
        raise OfflinePitError("UNEXPECTED_COMPONENT_REPORT_SCHEMA")
    if obj.get("status") != "NO_GO" or obj.get("watch_modified") is not False:
        raise OfflinePitError("UNTRUSTED_COMPONENT_REPORT_STATUS")
    parts = obj.get("parts")
    if not isinstance(parts, list) or len(parts) > 8:
        raise OfflinePitError("INVALID_COMPONENT_PART_LIST")
    found = []
    for item in parts:
        if not isinstance(item, dict) or not isinstance(item.get("entries"), list):
            raise OfflinePitError("INVALID_COMPONENT_ENTRY_LIST")
        if len(item["entries"]) + len(found) > MAX_COMPONENT_ITEMS:
            raise OfflinePitError("COMPONENT_ENTRY_LIMIT")
        for entry in item["entries"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise OfflinePitError("INVALID_COMPONENT_ENTRY")
            name = entry["name"]
            if not SAFE_COMPONENT_FILENAME.fullmatch(name) or PurePosixPath(name).name != name:
                raise OfflinePitError("UNSAFE_COMPONENT_IMAGE_NAME")
            found.append(name.casefold())
    return set(found)


def audit(pit_path: Path, components_report: Path | None = None) -> dict:
    result = {
        "schema": "uglyos-r840x-local-pit-name-inventory-v1",
        "status": "NO_GO",
        "device_target": MODEL,
        "samsung_pit_authenticated": False,
        "pit_from_actual_r840x_verified": False,
        "model_build_compatibility_verified": False,
        "numeric_partition_geometry_verified": False,
        "pit_read_from_watch": False,
        "watch_contacted": False,
        "network_packets_sent": False,
        "odin_session_started": False,
        "partition_data_written": False,
        "stock_recovery_verified": False,
        "custom_boot_verified": False,
        "heimdall_source_pin": HEIMDALL_PIN,
        "ragnaroek_source_pin": RAGNAROEK_PIN,
        "parser_method": "OFFLINE_ONLY_SHARED_NAME_OFFSETS_NOT_PIT_VERSION_DETECTION",
        "pit_sha256_local_identity_only": None,
        "pit_parse": "NOT_PARSED",
        "pit": None,
        "component_names_match_unverified": None,
        "warnings": [],
    }
    try:
        data = _file_bytes(pit_path, MAX_PIT_BYTES, code="PIT")
        pit = inspect_pit_bytes(data)
        result["pit_sha256_local_identity_only"] = hashlib.sha256(data).hexdigest()
        result["pit_parse"] = "STRUCTURAL_NAMES_PARSED_UNVERIFIED"
        result["pit"] = pit
    except OfflinePitError as exc:
        result["warnings"].append(str(exc))
        return result
    result["warnings"].extend([
        "PIT_SOURCE_SIGNATURE_AND_MODEL_UNAUTHENTICATED",
        "NO_BOOTLOADER_PARTITION_SIZE_OFFSET_OR_ROLLBACK_INFERENCE",
        "NO_STOCK_RECOVERY_OR_FLASH_AUTHORIZATION",
    ])
    if components_report is not None:
        try:
            names = _component_names(_file_bytes(
                components_report, MAX_COMPONENT_REPORT_BYTES, code="COMPONENT_REPORT"))
            wanted = {
                entry["flash_filename_unverified"].casefold()
                for entry in pit["entries"] if entry["flash_filename_unverified"]
            }
            result["component_names_match_unverified"] = {
                "file_name_matches_only": True,
                "matched_names": sorted(wanted & names),
                "pit_filenames_not_found": sorted(wanted - names),
                "component_names_unmapped": sorted(names - wanted),
                "signature_or_restore_proof": False,
            }
            result["warnings"].append("CROSSMATCH_FILENAMES_ARE_NOT_PARTITION_OR_SIGNATURE_PROOF")
        except OfflinePitError as exc:
            result["warnings"].append(str(exc))
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pit", type=Path, help="A pre-existing LOCAL PIT file; never requested from a watch")
    ap.add_argument("--component-report", type=Path,
                    help="Optional local JSON from existing offline Odin ZIP component inventory")
    ap.add_argument("--report", type=Path,
                    help="Optional private JSON output; refuses to overwrite existing files")
    args = ap.parse_args(argv)
    result = audit(args.pit, args.component_report)
    body = (json.dumps(result, indent=2) + "\n").encode()
    if args.report is None:
        sys.stdout.write(body.decode())
    else:
        try:
            fd = os.open(str(args.report.expanduser()),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
        except OSError:
            print("FAIL: CANNOT_CREATE_PRIVATE_EXCLUSIVE_LOCAL_REPORT", file=sys.stderr)
            return 2
        print("OFFLINE_PIT_REPORT_SAVED: " + str(args.report))
    print("NO_GO: This tool NEVER connects to the watch or authorizes flashing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
