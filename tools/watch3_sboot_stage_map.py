#!/usr/bin/env python3
"""Offline, bounded Exynos S-BOOT stage-header and footer candidate mapping.

Based on structural ideas from halal-beef/sboot-split-detector, independently
implemented with validation and explicit uncertainty. Signature-looking
footers are NOT verified digital signatures. Only two SHA256-pinned historical
SM-R500 (NOT SM-R840X) references are accepted. No watch, Odin or FOTA access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

REFERENCES = {
    "R500XXU1BSD3": "4715861156eeceb949899d355ccc37eefb57062888aadc76aa9f93f9eaf5966e",
    "R500XXU1GUJ2": "c96813f283e2f98d3f33a30c6215fa25b06b756b93adf55ecf8d59fc4d9211a9",
}
SIZE = 1_921_296
SECTOR = 512
MAX_BL1_BLOCKS = 0x276
MAX_EPBL_BLOCKS = 0x400
MARKERS = (b"ODIN", b"LOKE", b"PIT", b"param", b"recovery")


def parse(blob: bytes) -> dict:
    if not isinstance(blob, bytes) or not 4096 <= len(blob) <= 16 * 1024 * 1024:
        raise ValueError("INVALID_IMAGE_SIZE")
    bl1_blocks = struct.unpack_from("<I", blob, 0)[0]
    if not 4 <= bl1_blocks <= MAX_BL1_BLOCKS:
        raise ValueError("UNSUPPORTED_BL1_SECTOR_COUNT")
    bl1_end = bl1_blocks * SECTOR
    if bl1_end + 4 > len(blob):
        raise ValueError("TRUNCATED_BL1")
    epbl_blocks = struct.unpack_from("<I", blob, bl1_end)[0]
    if not 4 <= epbl_blocks <= MAX_EPBL_BLOCKS:
        raise ValueError("UNSUPPORTED_EPBL_SECTOR_COUNT")
    epbl_end = bl1_end + epbl_blocks * SECTOR
    if epbl_end > len(blob) or epbl_end + 4096 > len(blob):
        raise ValueError("TRUNCATED_OR_NO_FOLLOWING_STAGE")
    if b"daeh" not in blob[bl1_end:epbl_end]:
        raise ValueError("NO_EPBL_HEADER_MARKER")
    regions = [
        {"label": "BL1_HEADER_CANDIDATE", "start": 0, "end_exclusive": bl1_end},
        {"label": "EPBL_HEADER_CANDIDATE", "start": bl1_end, "end_exclusive": epbl_end},
    ]
    # Exynos signer conventions vary. Treat these as signatures-of-a-format
    # only, never proof of Samsung's signing keys or cryptographic acceptance.
    footer_patterns = []
    for sig_len in (512, 256):
        pos = epbl_end - sig_len - 16
        if pos < bl1_end:
            continue
        pattern = blob[pos:pos + 12]
        if len(pattern) != 12 or pattern == b"\0" * 12:
            continue
        key_type = struct.unpack_from("<I", pattern, 8)[0]
        if key_type > 3:
            continue
        for variant in (0, 1, 2):
            needle = pattern[:8] + struct.pack("<I", variant)
            matches = []
            cursor = epbl_end
            while len(matches) < 32:
                at = blob.find(needle, cursor)
                if at < 0:
                    break
                cursor = at + 1
                boundary = (at + 16 + sig_len + 4095) & ~4095
                if epbl_end < boundary <= len(blob):
                    if not matches or matches[-1]["boundary_candidate"] != boundary:
                        matches.append({
                            "footer_file_offset": at,
                            "boundary_candidate": boundary,
                            "footer_variant": variant,
                        })
            if matches:
                footer_patterns.append({
                    "signature_bytes_hypothesis": sig_len,
                    "epbl_marker_numeric_fields": [
                        struct.unpack_from("<I", pattern, 0)[0],
                        struct.unpack_from("<I", pattern, 4)[0],
                        key_type,
                    ],
                    "candidates": matches,
                })
    locations = {}
    for marker in MARKERS:
        matches = []
        cursor = 0
        while len(matches) < 64:
            at = blob.find(marker, cursor)
            if at < 0:
                break
            matches.append({
                "file_offset": at,
                "region": (
                    "BL1_HEADER_CANDIDATE" if at < bl1_end else
                    "EPBL_HEADER_CANDIDATE" if at < epbl_end else
                    "AFTER_EPBL_UNMAPPED"
                ),
            })
            cursor = at + len(marker)
        locations[marker.decode()] = matches
    return {
        "schema": "uglyos-sboot-stage-metadata-v1",
        "bl1_header_blocks": bl1_blocks,
        "epbl_header_blocks": epbl_blocks,
        "observed_header_boundaries": regions,
        "stage2_signature_footer_pattern_hypotheses": footer_patterns,
        "reference_marker_locations": locations,
        "signature_cryptographically_verified": False,
        "stage2_signature_footer_semantics_proven": False,
        "sboot_runtime_map_proven": False,
        "main_bootloader_stage_boundaries_proven": False,
    }


def read_pinned(path: Path, build: str) -> bytes:
    if build not in REFERENCES or path.is_symlink():
        raise ValueError("UNKNOWN_REFERENCE_OR_SYMLINK")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != SIZE:
            raise ValueError("NOT_REGULAR_PINNED_IMAGE_SIZE")
        with os.fdopen(fd, "rb", closefd=False) as file:
            data = file.read(SIZE + 1)
        if len(data) != SIZE or hashlib.sha256(data).hexdigest() != REFERENCES[build]:
            raise ValueError("PINNED_IMAGE_SHA256_MISMATCH")
        return data
    finally:
        os.close(fd)


def compare(old: bytes, new: bytes) -> dict:
    a, b = parse(old), parse(new)
    return {
        "schema": "uglyos-exynos9110-sibling-sboot-stage-comparison-v1",
        "source_model": "SM-R500 historical sibling; NOT physical SM-R840X",
        "images": {"R500XXU1BSD3": a, "R500XXU1GUJ2": b},
        "same_bl1_header_size": a["bl1_header_blocks"] == b["bl1_header_blocks"],
        "same_epbl_header_size": a["epbl_header_blocks"] == b["epbl_header_blocks"],
        "real_r840x_sboot_obtained": False,
        "signatures_authenticated": False,
        "recovery_proven": False,
        "custom_kernel_boot_proven": False,
        "watch_contacted": False,
        "flash_allowed": False,
        "status": "NO_GO",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--older", type=Path, required=True)
    parser.add_argument("--newer", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = compare(read_pinned(args.older, "R500XXU1BSD3"),
                         read_pinned(args.newer, "R500XXU1GUJ2"))
    except (OSError, ValueError) as exc:
        print("REJECTED: " + str(exc), file=sys.stderr)
        return 2
    report = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
        print("NO_GO: historical sibling bootloader stage hypotheses only")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
