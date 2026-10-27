#!/usr/bin/env python3
"""Offline, metadata-only Odin component inventory from a local R840X ZIP.

Never extracts images, opens firmware partitions, runs tools or contacts a watch.
A nested TAR listing is *not* OEM authentication or verified stock rescue.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
from zipfile import BadZipFile, ZipFile

from audit_watch3_r840x_recovery_zip import audit, _safe_name, _role

MAX_PART_ARCHIVE = 2 * 1024 * 1024 * 1024
MAX_DECLARED_TOTAL = 3 * 1024 * 1024 * 1024
MAX_FILES_PER_TAR = 64
MAX_TAR_SCAN_BYTES = 4 * 1024 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 300

IMAGE_TYPES = (".img", ".bin", ".pit", ".lz4", ".gz", ".dtb", ".mbn")


def _is_odintar(name: str) -> bool:
    return bool(re.search(r"\.tar(?:\.md5)?$", name.lower()))


def _inventory_part(stream, outer_name: str) -> dict:
    """Read bounded TAR headers only. No extraction or payload retention."""
    result = {
        "outer_component": PurePosixPath(outer_name).name,
        "state": "UNVERIFIED",
        "entries": [],
        "possible_pit": [],
        "issue": None,
    }
    try:
        # r|* never materializes a multi-gigabyte TAR in memory.
        with tarfile.open(fileobj=stream, mode="r|*") as tar:
            total = 0
            for index, member in enumerate(tar):
                if index >= MAX_FILES_PER_TAR:
                    result["issue"] = "TAR_ENTRY_LIMIT"
                    break
                if not _safe_name(member.name):
                    result["issue"] = "UNSAFE_TAR_MEMBER_NAME"
                    break
                if not member.isfile() or member.issym() or member.islnk():
                    result["issue"] = "UNSUPPORTED_TAR_LINK_OR_MEMBER_TYPE"
                    break
                if member.size < 0 or member.size > MAX_PART_ARCHIVE:
                    result["issue"] = "UNSAFE_TAR_MEMBER_SIZE"
                    break
                total += member.size
                if total > MAX_TAR_SCAN_BYTES:
                    result["issue"] = "TAR_TOTAL_SIZE_LIMIT"
                    break
                basename = PurePosixPath(member.name).name
                # Only metadata. Never read image bytes or trust inner names.
                result["entries"].append({
                    "name": basename, "declared_bytes": member.size,
                    "known_image_extension": basename.lower().endswith(IMAGE_TYPES)
                })
                if basename.lower().endswith(".pit"):
                    result["possible_pit"].append(basename)
            if result["issue"] is None:
                result["state"] = "TAR_HEADERS_READ_UNVERIFIED"
    except (tarfile.TarError, OSError, ValueError, EOFError) as error:
        result["issue"] = "INVALID_OR_UNREADABLE_TAR"
    return result


def inspect_zip(path: Path, expected_build: str = "R840XXXU1AUA2") -> dict:
    outer = audit(path, expected_build)
    result = {
        "schema": "uglyos-r840x-odin-components-v1",
        "status": "NO_GO",
        "device": "SM-R840X",
        "outer_metadata_ok": outer["zip_metadata_readable"],
        "outer_issues": outer["issues"],
        "parts": [],
        "all_named_boot_recovery_components_present": False,
        "stock_signature_verified": False,
        "partition_mapping_verified": False,
        "restoration_verified": False,
        "watch_modified": False,
    }
    if not outer["zip_metadata_readable"]:
        return result
    try:
        with ZipFile(path, "r") as z:
            members = [m for m in z.infolist()
                       if not m.is_dir() and _role(PurePosixPath(m.filename).name)
                       and _is_odintar(m.filename)]
            selected = set()
            total = 0
            for m in members:
                role = _role(PurePosixPath(m.filename).name)
                if role in selected:
                    result["outer_issues"].append("DUPLICATE_ODIN_COMPONENT_ROLE")
                    continue
                selected.add(role)
                if m.file_size < 0 or m.file_size > MAX_PART_ARCHIVE:
                    result["outer_issues"].append("PART_ARCHIVE_SIZE_OUT_OF_BOUNDS")
                    continue
                total += m.file_size
                if total > MAX_DECLARED_TOTAL:
                    result["outer_issues"].append("TOTAL_UNCOMPRESSED_SIZE_LIMIT")
                    break
                if m.compress_size == 0 or m.file_size > max(1, m.compress_size) * MAX_ZIP_COMPRESSION_RATIO:
                    result["outer_issues"].append("UNSAFE_ZIP_COMPRESSION_RATIO")
                    continue
                with z.open(m, "r") as file:
                    result["parts"].append(_inventory_part(file, m.filename))
    except (BadZipFile, OSError, RuntimeError, EOFError, ValueError):
        result["outer_issues"].append("INNER_ODIN_METADATA_UNREADABLE")
    # This is an inventory of image *names*, not an authentication gate.
    all_names = {i["name"].lower() for p in result["parts"] for i in p["entries"]}
    result["all_named_boot_recovery_components_present"] = any(
        "boot" in n or "kernel" in n for n in all_names
    ) and any("recovery" in n for n in all_names)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    ap.add_argument("--expected-build", default="R840XXXU1AUA2")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    try:
        result = inspect_zip(args.archive, args.expected_build)
    except (OSError, ValueError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 2
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
        print("NO_GO: Offline component names inventoried. No valid recovery or boot acceptance established.")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
