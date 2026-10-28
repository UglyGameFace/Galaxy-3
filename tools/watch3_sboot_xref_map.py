#!/usr/bin/env python3
"""Offline ARM64 PC-relative xref map in two SHA-pinned SM-R500 S-BOOT images.

Research-only: raw file offsets and string references are NOT verified runtime
addresses, functions, wireless parsers, vulnerabilities, or boot entry points.
Never opens a socket, runs firmware, or communicates with a watch.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

from watch3_sboot_pit_semantic_diff import REFERENCES, read_pinned

# Exact candidate code interval observed in the historical reference stage
# footer study; NOT a verified memory map or complete executable interval.
STAGE_START = 0x40000
STAGE_END = 0x115000
MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_PER_LABEL = 64
LABELS = {
    "PIT": b"PIT",
    "param": b"param",
    "recovery": b"recovery",
    "ODIN": b"ODIN",
    "LOKE": b"LOKE",
}
BOUNDARIES = b" :;.,/()[]_-"


class XrefError(ValueError):
    """Reject malformed local input without elevating inference strength."""


def _signed(value: int, width: int) -> int:
    return value - (1 << width) if value & (1 << (width - 1)) else value


def decode_adrp_add(blob: bytes, pc: int) -> int | None:
    """Require consecutive ADRP+ADD Xd,Xn,#imm using the same register.

    We intentionally do not infer register liveness across intervening
    instructions. Reject ADD with a 32-bit destination or unsupported shift.
    """
    if pc < 0 or pc % 4 or pc + 8 > len(blob):
        return None
    adrp, add = struct.unpack_from("<II", blob, pc)
    if (adrp & 0x9F000000) != 0x90000000:
        return None
    if (add & 0xFF000000) != 0x91000000:
        return None
    if ((add >> 22) & 3) not in (0, 1):
        return None
    reg = adrp & 31
    if (add & 31) != reg or ((add >> 5) & 31) != reg:
        return None
    imm21 = (((adrp >> 5) & 0x7FFFF) << 2) | ((adrp >> 29) & 3)
    page = (pc & ~4095) + (_signed(imm21, 21) << 12)
    immediate = (add >> 10) & 4095
    return page + (immediate << (12 if (add >> 22) & 1 else 0))


def candidate_labels(blob: bytes, target: int) -> list[tuple[str, str]]:
    if target < 0 or target >= len(blob):
        return []
    candidates = []
    for label, marker in LABELS.items():
        tail = target + len(marker)
        if tail >= len(blob) or blob[target:tail] != marker:
            continue
        after = blob[tail]
        if after == 0:
            strength = "NUL_TERMINATED_LITERAL"
        elif after in BOUNDARIES:
            strength = "PREFIX_WITH_SEPARATOR"
        else:
            continue
        candidates.append((label, strength))
    return candidates


def map_references(blob: bytes, *, start: int = STAGE_START,
                   end: int = STAGE_END) -> dict:
    """Scan one bounded aligned file interval; never disassemble/execute code."""
    if not isinstance(blob, bytes) or not 16 <= len(blob) <= 16 * 1024 * 1024:
        raise XrefError("INVALID_LOCAL_BINARY")
    if (not isinstance(start, int) or not isinstance(end, int) or
            start < 0 or start % 4 or end % 4 or start >= end or
            end > len(blob) or end - start > MAX_SCAN_BYTES):
        raise XrefError("INVALID_BOUNDED_SCAN_INTERVAL")
    groups = {name: [] for name in LABELS}
    for pc in range(start, end - 7, 4):
        target = decode_adrp_add(blob, pc)
        if target is None:
            continue
        for label, classification in candidate_labels(blob, target):
            if len(groups[label]) >= MAX_PER_LABEL:
                raise XrefError("TOO_MANY_XREF_CANDIDATES")
            groups[label].append({
                "instruction_file_offset": pc,
                "literal_target_file_offset": target,
                "literal_match": classification,
                "target_is_runtime_address_proven": False,
                "wireless_download_reachability_proven": False,
            })
    return {
        "candidate_code_interval": [start, end],
        "xref_counts": {name: len(entries) for name, entries in groups.items()},
        "candidate_xrefs": groups,
        "raw_file_mapping_hypothesis_only": True,
        "individual_candidate_functions_identified": False,
        "entrypoints_and_callers_proven": False,
    }


def compare(old: bytes, new: bytes) -> dict:
    a = map_references(old)
    b = map_references(new)
    return {
        "schema": "uglyos-sibling-sboot-pcrel-xrefs-v1",
        "source_model": "SM-R500; NOT physical SM-R840X",
        "source_sha256": {key: pair[0] for key, pair in REFERENCES.items()},
        "source_is_exact_owner_bootloader": False,
        "models": {"R500XXU1BSD3": a, "R500XXU1GUJ2": b},
        "known_pit_xref_anchor_present": {
            "R500XXU1BSD3": any(x["instruction_file_offset"] == REFERENCES["R500XXU1BSD3"][1]
                                   for x in a["candidate_xrefs"]["PIT"]),
            "R500XXU1GUJ2": any(x["instruction_file_offset"] == REFERENCES["R500XXU1GUJ2"][1]
                                   for x in b["candidate_xrefs"]["PIT"]),
        },
        "cve_root_cause_identified": False,
        "signed_recovery_package_verified": False,
        "custom_boot_accepted": False,
        "watch_contacted": False,
        "firmware_written": False,
        "decision": "NO_GO",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--older", required=True, type=Path)
    parser.add_argument("--newer", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        old = read_pinned(args.older, "R500XXU1BSD3")
        new = read_pinned(args.newer, "R500XXU1GUJ2")
        result = compare(old, new)
    except (ValueError, XrefError, OSError) as exc:
        print("REJECTED_PINNED_REFERENCE: " + str(exc), file=sys.stderr)
        return 2
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        # A local output is a research report, never a flash manifest.
        try:
            with args.output.open("x", encoding="utf-8") as f:
                f.write(rendered)
        except OSError:
            print("CANNOT_CREATE_EXCLUSIVE_REPORT", file=sys.stderr)
            return 2
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
