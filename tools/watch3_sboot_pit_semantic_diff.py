#!/usr/bin/env python3
"""Non-executing, pinned SM-R500 S-BOOT PIT-check comparison for Issue #47.

These are Exynos9110 sibling firmware, NOT R840X recovery images.
Reads regular local files only. Does not run ROM code or contact the watch.
AArch64 decoding is deliberately narrow, not a full disassembler.
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
    "R500XXU1BSD3": ("4715861156eeceb949899d355ccc37eefb57062888aadc76aa9f93f9eaf5966e", 0x58BB0),
    "R500XXU1GUJ2": ("c96813f283e2f98d3f33a30c6215fa25b06b756b93adf55ecf8d59fc4d9211a9", 0x58E60),
}
SBOOT_BYTES = 1_921_296
WINDOW_WORDS = 40


def _signed(v: int, bits: int) -> int:
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def decode(word: int, pc: int) -> dict:
    """Decode the instruction classes relevant to a candidate PIT check."""
    if (word & 0x9F000000) == 0x90000000:
        imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
        return {"op": "ADRP", "reg": word & 31,
                "page": (pc & ~4095) + (_signed(imm, 21) << 12)}
    if (word & 0x7F000000) == 0x11000000:
        shift = (word >> 22) & 3
        if shift in (0, 1):
            return {"op": "ADD_IMM", "dst": word & 31, "src": (word >> 5) & 31,
                    "imm": ((word >> 10) & 4095) << (12 if shift else 0)}
    if (word & 0x7F000000) == 0x71000000:
        shift = (word >> 22) & 3
        if shift in (0, 1):
            return {"op": "CMP_IMM" if (word & 31) == 31 else "SUBS_IMM",
                    "src": (word >> 5) & 31,
                    "imm": ((word >> 10) & 4095) << (12 if shift else 0)}
    if (word & 0x7F800000) in (0x52800000, 0x72800000):
        return {"op": "MOVZ" if (word & 0x7F800000) == 0x52800000 else "MOVK",
                "reg": word & 31, "imm": (word >> 5) & 0xFFFF,
                "shift": ((word >> 21) & 3) * 16}
    if (word & 0xFF000010) == 0x54000000:
        return {"op": "B_COND", "cond": word & 15,
                "target": pc + (_signed((word >> 5) & 0x7FFFF, 19) * 4)}
    if (word & 0x7C000000) == 0x14000000:
        return {"op": "BL" if (word >> 31) & 1 else "B",
                "target": pc + (_signed(word & 0x3FFFFFF, 26) * 4)}
    if (word & 0x7F000000) in (0x34000000, 0x35000000):
        return {"op": "CBNZ" if word & 0x01000000 else "CBZ"}
    if (word & 0x7F000000) in (0x36000000, 0x37000000):
        return {"op": "TBNZ" if word & 0x01000000 else "TBZ"}
    if (word & 0x7FE0FC1F) == 0x6B00001F:
        return {"op": "CMP_REG"}
    return {"op": "OTHER"}


def inspect(blob: bytes, anchor: int) -> dict:
    if anchor < 0 or anchor % 4 or anchor + WINDOW_WORDS * 4 > len(blob):
        raise ValueError("INVALID_PIT_ANCHOR_OR_IMAGE_LENGTH")
    code = [decode(struct.unpack_from("<I", blob, anchor + 4 * n)[0], anchor + 4 * n)
            for n in range(WINDOW_WORDS)]
    ref = None
    if code[0]["op"] == "ADRP":
        for n in range(1, 7):
            ins = code[n]
            if (ins["op"] == "ADD_IMM" and ins["src"] == code[0]["reg"]
                    and ins["dst"] == code[0]["reg"]):
                target = code[0]["page"] + ins["imm"]
                if 0 <= target <= len(blob) - 3 and blob[target:target+3] == b"PIT":
                    ref = {"target_file_offset": target, "add_offset": anchor + 4 * n}
                    break
    length_checks = [{"file_offset": anchor + 4 * n, "register": ins["src"]}
                     for n, ins in enumerate(code)
                     if ins["op"] == "CMP_IMM" and ins["imm"] == 0x2000]
    magic = []
    for n, ins in enumerate(code):
        if ins["op"] != "MOVZ" or ins["shift"] not in (0, 16):
            continue
        initial = ins["imm"] << ins["shift"]
        for j in range(n + 1, min(n + 7, len(code))):
            nxt = code[j]
            if nxt["op"] == "MOVZ" and nxt["reg"] == ins["reg"]:
                break
            if nxt["op"] == "MOVK" and nxt["reg"] == ins["reg"]:
                mask = 0xFFFF << nxt["shift"]
                candidate = (initial & ~mask) | (nxt["imm"] << nxt["shift"])
                if candidate == 0x12349876:
                    magic.append({"movz_offset": anchor + 4*n, "movk_offset": anchor + 4*j,
                                  "register": ins["reg"], "value_hex": "0x12349876"})
                break
    conditional = [{"file_offset": anchor + 4*n, "condition": ins["cond"],
                    "target_file_offset_hypothesis": ins["target"]}
                   for n, ins in enumerate(code) if ins["op"] == "B_COND"]
    return {
        "pit_string_xref_verified_under_raw_file_mapping": ref is not None,
        "pit_string_reference": ref,
        "compare_0x2000": length_checks,
        "construct_0x12349876": magic,
        "conditional_branch_candidates": conditional,
        "instruction_class_sequence": [ins["op"] for ins in code],
        "anchor_file_offset": anchor,
        "runtime_load_address_verified": False,
        "handler_reachability_verified": False,
    }


def read_pinned(path: Path, build: str) -> bytes:
    if path.is_symlink():
        raise ValueError("SYMLINK_SOURCE_FORBIDDEN")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != SBOOT_BYTES:
            raise ValueError("NOT_PINNED_REGULAR_SBOOT_IMAGE")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(SBOOT_BYTES + 1)
        if len(data) != SBOOT_BYTES:
            raise ValueError("SHORT_OR_CHANGED_SBOOT_IMAGE")
        if hashlib.sha256(data).hexdigest() != REFERENCES[build][0]:
            raise ValueError("PINNED_REFERENCE_SHA256_MISMATCH")
        return data
    finally:
        os.close(fd)


def compare(older: bytes, newer: bytes, old_anchor: int, new_anchor: int) -> dict:
    pre = inspect(older, old_anchor)
    post = inspect(newer, new_anchor)
    return {
        "schema": "uglyos-sboot-pit-differential-v1",
        "source_model": "SM-R500 historical sibling, NOT SM-R840X",
        "reference_sha256": {k: v[0] for k, v in REFERENCES.items()},
        "older": pre, "newer": post,
        "same_opcode_class_sequence_in_bounded_window":
            pre["instruction_class_sequence"] == post["instruction_class_sequence"],
        "both_have_raw_offset_pit_xref":
            pre["pit_string_xref_verified_under_raw_file_mapping"] and
            post["pit_string_xref_verified_under_raw_file_mapping"],
        "both_compare_0x2000": bool(pre["compare_0x2000"] and post["compare_0x2000"]),
        "both_construct_0x12349876": bool(pre["construct_0x12349876"] and post["construct_0x12349876"]),
        "different_source_model_from_owners_watch": True,
        "cve_patch_identified": False,
        "live_bootloader_acceptance_proven": False,
        "stock_r840x_recovery_proven": False,
        "watch_contacted": False,
        "bootloader_executed": False,
        "flash_allowed": False,
        "decision": "NO_GO",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--older", required=True, type=Path, help="Local raw R500XXU1BSD3 sboot.bin")
    ap.add_argument("--newer", required=True, type=Path, help="Local raw R500XXU1GUJ2 sboot.bin")
    ap.add_argument("--output", type=Path, help="Optional local JSON report destination")
    args = ap.parse_args()
    try:
        result = compare(read_pinned(args.older, "R500XXU1BSD3"),
                         read_pinned(args.newer, "R500XXU1GUJ2"),
                         REFERENCES["R500XXU1BSD3"][1], REFERENCES["R500XXU1GUJ2"][1])
    except (OSError, ValueError) as exc:
        print(f"REJECTED_INPUT: {exc}", file=sys.stderr)
        return 2
    report = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
        print("NO_GO: Offline SM-R500 instruction-pattern comparison, NOT R840X boot proof.")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
