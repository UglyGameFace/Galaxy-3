#!/usr/bin/env python3
"""Offline bounded AArch64 opcode exercise for two SHA-pinned SM-R500 S-BOOT images.

Executes the semantics of ONLY three observed guard pairs on synthetic register
values. This is NOT full firmware, peripheral, signature, FOTA, PIT or recovery
emulation. File-relative branch offsets assume an UNVERIFIED flat image mapping.
No watch, Odin, firmware writing, code loading, or external process invocation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from watch3_sboot_pit_control_flow import (
    branch, donor_dispatch_context, find_gates, instruction,
)
from watch3_sboot_pit_semantic_diff import REFERENCES, decode, inspect, read_pinned

UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
CASES = (
    ("precheck_error_bit", 0x80000000, 0, 0x12349876),
    ("zero_length", 0, 0, 0x12349876),
    ("length_at_limit", 0, 0x2000, 0x12349876),
    ("length_above_limit", 0, 0x2001, 0x12349876),
    ("length_unsigned_max", 0, UINT64_MAX, 0x12349876),
    ("length_high_32_bits_only", 0, 0x1_0000_0000, 0x12349876),
    ("header_mismatch", 0, 0x2000, 0),
)


def _u32(value: int) -> int:
    if type(value) is not int or not 0 <= value <= UINT32_MAX:
        raise ValueError("INVALID_SYNTHETIC_REGISTER_VALUE")
    return value


def _guard_site(blob: bytes, anchor: int) -> dict:
    gates = find_gates(blob, anchor)
    if not gates["canonical_candidate_three_guards"]:
        raise ValueError("ORIGINAL_THREE_GUARD_SHAPE_NOT_VERIFIED")
    status, length, header = (
        gates["status_error_bit_guards"][0],
        gates["length_greater_than_0x2000_guards"][0],
        gates["header_equal_to_magic_guards"][0],
    )
    # The literal must come from the real MOVZ/MOVK operands, not just
    # from a caller-supplied expected value or a coincidental printable string.
    constructions = inspect(blob, anchor)["construct_0x12349876"]
    matches = [c for c in constructions if c["register"] == header["magic_register"]
               and c["movk_offset"] < header["cmp_offset"]]
    if len(matches) != 1:
        raise ValueError("MAGIC_REGISTER_CONSTRUCTION_UNRESOLVED")
    mz, mk = (decode(instruction(blob, matches[0][k]), matches[0][k])
              for k in ("movz_offset", "movk_offset"))
    if mz["op"] != "MOVZ" or mk["op"] != "MOVK":
        raise ValueError("MAGIC_MATERIALIZATION_CHANGED")
    mask = 0xFFFF << mk["shift"]
    magic = ((mz["imm"] << mz["shift"]) & ~mask) | (mk["imm"] << mk["shift"])
    length_word = instruction(blob, length["cmp_offset"])
    if magic != 0x12349876 or length["register"] != 21:
        raise ValueError("UNRECOGNIZED_GUARD_OPERANDS")
    # Bit 31 is sf in ADD/SUBS immediate encodings. The original opcode,
    # not a test fixture or a source-code comment, determines W21 vs X21.
    width = 64 if length_word & (1 << 31) else 32
    return {"status": status, "length": length, "header": header,
            "magic": magic, "length_operand_bits": width}


def emulate_pairs(blob: bytes, anchor: int, precheck_w0: int,
                  length_x21: int, header_w2: int) -> dict:
    """Exercise observed original ARM64 instruction operands/conditions only.

    Each guard is run independently with synthetic W-register values; the
    prelude/other calls are NOT executed. No positive verdict means an image
    was accepted by the ROM or that the real bootloader exposes this route.
    """
    precheck_w0, header_w2 = map(_u32, (precheck_w0, header_w2))
    if type(length_x21) is not int or not 0 <= length_x21 <= UINT64_MAX:
        raise ValueError("INVALID_SYNTHETIC_X21")
    site = _guard_site(blob, anchor)
    status, length, header = site["status"], site["length"], site["header"]
    s = branch(instruction(blob, status["branch_offset"]), status["branch_offset"])
    if not s or s["op"] != "TBNZ" or s["register"] != 0 or s["bit"] != 31:
        raise ValueError("STATUS_OPCODE_CHANGED")
    negative = bool(precheck_w0 & (1 << s["bit"]))

    length_compare = decode(instruction(blob, length["cmp_offset"]), length["cmp_offset"])
    length_branch = branch(instruction(blob, length["branch_offset"]), length["branch_offset"])
    if (length_compare["op"] != "CMP_IMM" or length_compare["src"] != 21
            or length_compare["imm"] != 0x2000 or not length_branch
            or length_branch["op"] != "B_COND" or length_branch["condition"] != 12):
        raise ValueError("LENGTH_OPCODE_CHANGED")
    effective_length = length_x21 & ((1 << site["length_operand_bits"]) - 1)
    too_long = effective_length > length_compare["imm"]  # AArch64 unsigned B.HI

    header_word = instruction(blob, header["cmp_offset"])
    h = branch(instruction(blob, header["branch_offset"]), header["branch_offset"])
    if (header_word & 0x7FE0FC1F != 0x6B00001F or
            (header_word >> 5) & 31 != 2 or (header_word >> 16) & 31 != 3 or
            not h or h["op"] != "B_COND" or h["condition"] != 0):
        raise ValueError("HEADER_OPCODE_CHANGED")
    header_matches = header_w2 == site["magic"]

    # The guards' target paths leave the verified slice. Their behavior after
    # this decision is explicitly unknown, including any signature checks.
    if negative:
        classification = "PRECHECK_ERROR_BRANCH"
    elif too_long:
        classification = "LENGTH_OUT_OF_RANGE_BRANCH"
    elif header_matches:
        classification = "HEADER_MATCH_BRANCH_UNVERIFIED_FOLLOWUP"
    else:
        classification = "HEADER_MISMATCH_FALLTHROUGH_UNVERIFIED_FOLLOWUP"
    return {
        "scenario_branch": classification,
        "original_length_operand_bits": site["length_operand_bits"],
        "observed_guard_branch_taken": {
            "precheck_negative_status": negative,
            "unsigned_length_greater_than_0x2000": too_long,
            "pit_header_equals_constructed_magic": header_matches,
        },
        "original_branch_file_offsets": {
            "precheck": s["target"] if negative else status["fallthrough"],
            "length": length_branch["target"] if too_long else length["fallthrough"],
            "header": h["target"] if header_matches else header["fallthrough"],
        },
        "real_firmware_external_calls_executed": False,
        "signature_or_recovery_acceptance_determined": False,
    }


def compare(older: bytes, newer: bytes) -> dict:
    results = {}
    for build, blob in (("R500XXU1BSD3", older), ("R500XXU1GUJ2", newer)):
        anchor = REFERENCES[build][1]
        if not donor_dispatch_context(blob, build)["observed_slice_matches"]:
            raise ValueError("DONOR_DISPATCH_PROVENANCE_NOT_VERIFIED:" + build)
        rows = {}
        for name, status, length, header in CASES:
            rows[name] = emulate_pairs(blob, anchor, status, length, header)
        results[build] = rows
    older_rows, newer_rows = (results[x] for x in REFERENCES)
    same = all(
        older_rows[name]["observed_guard_branch_taken"] ==
        newer_rows[name]["observed_guard_branch_taken"] and
        older_rows[name]["scenario_branch"] == newer_rows[name]["scenario_branch"]
        for name, *_ in CASES
    )
    if not same:
        raise ValueError("DONOR_GUARD_BEHAVIOR_DIFFERS")
    return {
        "schema": "uglyos-r500-sboot-pit-guard-opcode-exercise-v1",
        "source": "Two SHA-256-pinned public SM-R500 original S-BOOT blobs",
        "source_model": "SM-R500; not owner's SM-R840X",
        "firmware_hashes_sha256": {k: REFERENCES[k][0] for k in REFERENCES},
        "execution_model": "three original AArch64 guard-opcode semantics, synthetic W0/X21/W2 inputs, W21 truncation when encoded",
        "synthetic_scenarios": results,
        "both_donor_builds_same_observed_guard_decisions": same,
        "donor_length_operand_width_bits": {
            build: rows[CASES[0][0]]["original_length_operand_bits"]
            for build, rows in results.items()},
        "recovery_mechanism_equivalence_between_R840_and_R840X": "NOT_TESTED",
        "R840X_original_sboot_available": False,
        "loader_mapping_authenticated": False,
        "full_dispatch_or_security_emulated": False,
        "stock_R840X_restore_proven": False,
        "watch_contacted": False,
        "bootloader_executable_run": False,
        "flash_allowed": False,
        "decision": "NO_GO",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--older", type=Path, required=True)
    parser.add_argument("--newer", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        data = compare(read_pinned(args.older, "R500XXU1BSD3"),
                       read_pinned(args.newer, "R500XXU1GUJ2"))
    except (OSError, ValueError, KeyError) as exc:
        print("REJECTED_INPUT: " + str(exc), file=sys.stderr)
        return 2
    output = json.dumps(data, indent=2) + "\n"
    if args.output:
        if args.output.is_symlink() or args.output.exists():
            print("REJECTED_OUTPUT: FILE_EXISTS_OR_SYMLINK", file=sys.stderr)
            return 2
        try:
            # Exclusive create; no overwriting evidence or following symlinks.
            with args.output.open("x", encoding="utf-8") as fd:
                fd.write(output)
        except OSError as exc:
            print("REJECTED_OUTPUT: " + str(exc), file=sys.stderr)
            return 2
        print("NO_GO: donor PIT guard opcode exercise only; R840X absent")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
