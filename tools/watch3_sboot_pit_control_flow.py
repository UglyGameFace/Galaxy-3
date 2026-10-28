#!/usr/bin/env python3
"""Bounded control-flow reconstruction of two pinned SM-R500 PIT validators.

Issue #47 research. Instruction targets are RAW FILE OFFSETS under an
UNVERIFIED flat-image mapping; not runtime addresses. Never runs bootloader
code or interacts with SM-R840X hardware. This cannot determine CVE status.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

from watch3_sboot_pit_semantic_diff import REFERENCES, decode, inspect, read_pinned

WINDOW_BYTES = 0x180
MAX_VISITED = WINDOW_BYTES // 4
MAX_LINEAR_TRACE = 48


def signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def branch(word: int, pc: int) -> dict | None:
    """Decode only ARM64 direct control transfers or explicit returns."""
    if word & 0xFF000010 == 0x54000000:
        return {"op": "B_COND", "condition": word & 15,
                "target": pc + 4 * signed((word >> 5) & 0x7FFFF, 19)}
    if word & 0x7C000000 == 0x14000000:
        return {"op": "BL" if word & 0x80000000 else "B",
                "target": pc + 4 * signed(word & 0x3FFFFFF, 26)}
    if word & 0x7E000000 == 0x34000000:
        return {"op": "CBNZ" if word & 0x01000000 else "CBZ",
                "register": word & 31,
                "target": pc + 4 * signed((word >> 5) & 0x7FFFF, 19)}
    if word & 0x7E000000 == 0x36000000:
        return {"op": "TBNZ" if word & 0x01000000 else "TBZ",
                "register": word & 31, "bit": ((word >> 31) << 5) | ((word >> 19) & 31),
                "target": pc + 4 * signed((word >> 5) & 0x3FFF, 14)}
    if word & 0xFFFFFC1F == 0xD65F0000:
        return {"op": "RET", "register": (word >> 5) & 31}
    if word & 0xFFFFFC1F == 0xD61F0000:
        return {"op": "BR", "register": (word >> 5) & 31}
    if word & 0xFFFFFC1F == 0xD63F0000:
        return {"op": "BLR", "register": (word >> 5) & 31}
    return None


def instruction(blob: bytes, pc: int) -> int:
    return struct.unpack_from("<I", blob, pc)[0]


def address_class(pc: int, anchor: int, size: int) -> str:
    if anchor <= pc < anchor + WINDOW_BYTES and pc + 4 <= size and pc % 4 == 0:
        return "IN_BOUNDED_WINDOW"
    if 0 <= pc < size and pc % 4 == 0:
        return "OUTSIDE_WINDOW_UNVERIFIED"
    return "UNMAPPED_OR_UNALIGNED"


def walk_linear(blob: bytes, start: int, anchor: int) -> dict:
    """Follow single fallthrough path; calls are *not* interpreted as returned."""
    pc = start
    visited = set()
    movn_w0_minus_one = []
    calls = []
    for _ in range(MAX_LINEAR_TRACE):
        if address_class(pc, anchor, len(blob)) != "IN_BOUNDED_WINDOW":
            return {"stop": "OUTSIDE_BOUNDED_WINDOW", "end_file_offset": pc,
                    "movn_w0_minus_one_offsets": movn_w0_minus_one, "calls_not_followed": calls}
        if pc in visited:
            stop = "LOOP"
            break
        visited.add(pc)
        word = instruction(blob, pc)
        if (word & 0x7FFFFFFF) == 0x12800000:
            movn_w0_minus_one.append(pc)
        flow = branch(word, pc)
        if flow:
            if flow["op"] == "RET":
                return {"stop": "RET", "end_file_offset": pc,
                        "movn_w0_minus_one_offsets": movn_w0_minus_one,
                        "calls_not_followed": calls,
                        "return_value_proven": False}
            if flow["op"] == "BL":
                calls.append({"at_file_offset": pc, "target_file_offset_hypothesis": flow["target"]})
            elif flow["op"] == "B":
                pc = flow["target"]
                continue
            else:
                return {"stop": "UNRESOLVED_FORK_OR_INDIRECT", "end_file_offset": pc,
                        "movn_w0_minus_one_offsets": movn_w0_minus_one,
                        "calls_not_followed": calls}
        pc += 4
    else:
        stop = "INSTRUCTION_BUDGET"
    return {"stop": stop, "end_file_offset": pc,
            "movn_w0_minus_one_offsets": movn_w0_minus_one, "calls_not_followed": calls}


def find_gates(blob: bytes, anchor: int) -> dict:
    """Locate three *candidate* guard branches; require exact adjacent comparisons."""
    if anchor < 0 or anchor % 4 or anchor + WINDOW_BYTES > len(blob):
        raise ValueError("INVALID_BOUNDED_SBOOT_WINDOW")
    existing = inspect(blob, anchor)
    length = []
    header = []
    status = []
    for offset in range(anchor, anchor + WINDOW_BYTES - 4, 4):
        first = decode(instruction(blob, offset), offset)
        second = branch(instruction(blob, offset + 4), offset + 4)
        if first["op"] == "CMP_IMM" and first["imm"] == 0x2000 and second:
            if second["op"] == "B_COND" and second["condition"] == 12:
                length.append({"cmp_offset": offset, "register": first["src"],
                               "branch_offset": offset + 4, "branch_target": second["target"],
                               "fallthrough": offset + 8})
        if first["op"] == "CMP_REG" and second and second["op"] == "B_COND":
            if second["condition"] == 0:
                word = instruction(blob, offset)
                lhs, rhs = (word >> 5) & 31, (word >> 16) & 31
                matching_magic = [x for x in existing["construct_0x12349876"]
                                  if x["register"] == rhs and x["movk_offset"] < offset]
                if matching_magic:
                    header.append({"cmp_offset": offset, "lhs_register": lhs,
                                   "magic_register": rhs, "branch_offset": offset + 4,
                                   "branch_target": second["target"], "fallthrough": offset + 8,
                                   "magic_materialization_offset": matching_magic[-1]["movz_offset"]})
        prior = branch(instruction(blob, offset), offset)
        if prior and prior["op"] == "TBNZ" and prior["register"] == 0 and prior["bit"] == 31:
            status.append({"branch_offset": offset, "branch_target": prior["target"],
                           "fallthrough": offset + 4, "tested_bit": 31})
    # Avoid claiming a generic matching pattern as the exact expected loader routine.
    canonical = bool(
        existing["pit_string_xref_verified_under_raw_file_mapping"] and
        len(length) == len(header) == len(status) == 1 and
        status[0]["fallthrough"] == length[0]["cmp_offset"] and
        length[0]["branch_offset"] < header[0]["cmp_offset"] and
        header[0]["lhs_register"] == 2 and header[0]["magic_register"] == 3
    )
    fail_trace = (walk_linear(blob, header[0]["fallthrough"], anchor)
                  if len(header) == 1 else None)
    return {"canonical_candidate_three_guards": canonical,
            "status_error_bit_guards": status,
            "length_greater_than_0x2000_guards": length,
            "header_equal_to_magic_guards": header,
            "header_not_equal_fallthrough_trace": fail_trace,
            "code_region_start_raw_offset": anchor,
            "code_region_end_raw_offset_exclusive": anchor + WINDOW_BYTES,
            "code_region_runtime_mapping_verified": False,
            "branch_target_is_reachable_from_external_input_proven": False}


def branch_graph(blob: bytes, anchor: int) -> dict:
    """Bounded graph *from the candidate anchor*, without crossing unknown code boundaries."""
    if anchor < 0 or anchor % 4 or anchor + WINDOW_BYTES > len(blob):
        raise ValueError("INVALID_BOUNDED_SBOOT_WINDOW")
    pending = [anchor]
    visited = set()
    edges = []
    terminals = []
    while pending and len(visited) < MAX_VISITED:
        pc = pending.pop()
        if pc in visited or address_class(pc, anchor, len(blob)) != "IN_BOUNDED_WINDOW":
            continue
        visited.add(pc)
        flow = branch(instruction(blob, pc), pc)
        if flow and flow["op"] in ("RET", "BR", "BLR"):
            terminals.append({"file_offset": pc, "kind": flow["op"]})
            if flow["op"] == "BLR":
                pending.append(pc + 4)
            continue
        if flow and flow["op"] == "BL":
            edges.append({"from": pc, "kind": "CALL_NOT_FOLLOWED",
                          "target": flow["target"], "target_class":
                              address_class(flow["target"], anchor, len(blob))})
            pending.append(pc + 4)
            continue
        if flow and "target" in flow:
            edges.append({"from": pc, "kind": flow["op"],
                          "target": flow["target"], "target_class":
                              address_class(flow["target"], anchor, len(blob))})
            if address_class(flow["target"], anchor, len(blob)) == "IN_BOUNDED_WINDOW":
                pending.append(flow["target"])
            if flow["op"] != "B":
                pending.append(pc + 4)
            continue
        pending.append(pc + 4)
    return {"decoded_reachable_raw_offset_count": len(visited),
            "bounded_branch_edges": sorted(edges, key=lambda x: (x["from"], x["kind"])),
            "bounded_terminal_candidates": sorted(terminals, key=lambda x: x["file_offset"]),
            "unresolved_worklist_at_budget": bool(pending),
            "entry_is_verified_function_start": False,
            "branch_target_addresses_are_runtime_addresses": False}


# Region is a footer-derived candidate from SM-R500 S-BOOT, NOT a
# source-authenticated executable map or proven function boundary.
DONOR_STAGE_START = 0x40000
DONOR_STAGE_END = 0x115000
POSSIBLE_ENTRY_LOOKBACK_BYTES = 0x100
MAX_DIRECT_INBOUND_CANDIDATES = 128


def inbound_candidates(blob: bytes, anchor: int, *,
                       start: int = DONOR_STAGE_START,
                       end: int = DONOR_STAGE_END) -> dict:
    """Scan donor-stage direct BL/B to the PIT anchor's candidate vicinity.

    A branch target into this range is not a verified function entry:
    some code/data is undecoded, cross-stage mapping is hypothetical,
    indirect calls are invisible, and an incoming branch does not prove
    Odin or external sender reachability.
    """
    if (not isinstance(blob, bytes) or not isinstance(anchor, int) or
            not isinstance(start, int) or not isinstance(end, int) or
            start < 0 or start % 4 or end % 4 or anchor % 4 or
            anchor < start + POSSIBLE_ENTRY_LOOKBACK_BYTES or
            anchor + WINDOW_BYTES > end or end > len(blob) or
            end - start > 2 * 1024 * 1024):
        raise ValueError("INVALID_DONOR_STAGE_OR_PIT_ANCHOR")
    lower = anchor - POSSIBLE_ENTRY_LOOKBACK_BYTES
    upper = anchor + WINDOW_BYTES
    possible = []
    for pc in range(start, end, 4):
        # Only direct B/BL instructions. CBZ/TBZ/B.cond and branch-register
        # instructions cannot independently identify the candidate caller.
        found = branch(instruction(blob, pc), pc)
        if not found or found["op"] not in ("B", "BL"):
            continue
        if not lower <= found["target"] < upper:
            continue
        if lower <= pc < upper:
            continue  # Internal control edges are not incoming callers.
        if len(possible) >= MAX_DIRECT_INBOUND_CANDIDATES:
            raise ValueError("EXCESSIVE_INBOUND_CANDIDATE_MATCHES")
        possible.append({
            "source_file_offset": pc,
            "target_file_offset_hypothesis": found["target"],
            "source_op": found["op"],
            "target_relative_to_pit_xref": found["target"] - anchor,
            "possible_function_entry_only": True,
            "verified_external_wireless_caller": False,
        })
    return {
        "candidate_target_interval": [lower, upper],
        "candidate_direct_call_count": sum(x["source_op"] == "BL" for x in possible),
        "candidate_direct_branch_count": sum(x["source_op"] == "B" for x in possible),
        "incoming_direct_edges": possible,
        "candidate_stage_only": True,
        "function_entry_verified": False,
        "indirect_callers_analyzed": False,
        "call_chain_to_wireless_protocol_verified": False,
        "code_vs_data_all_offsets_verified": False,
        "device_loader_runtime_map_verified": False,
    }


def compare(older: bytes, newer: bytes) -> dict:
    gates = {}
    graphs = {}
    incoming = {}
    for build, blob in (("R500XXU1BSD3", older), ("R500XXU1GUJ2", newer)):
        anchor = REFERENCES[build][1]
        gates[build] = find_gates(blob, anchor)
        graphs[build] = branch_graph(blob, anchor)
        incoming[build] = inbound_candidates(blob, anchor)
    patterns = [gates[x]["canonical_candidate_three_guards"] for x in REFERENCES]
    return {
        "schema": "uglyos-r500-sboot-pit-bounded-branch-graph-v1",
        "source_model": "SM-R500 only, NOT owner's SM-R840X",
        "reference_sha256": {k: v[0] for k, v in REFERENCES.items()},
        "gates": gates, "graphs": graphs, "inbound_candidate_edges": incoming,
        "both_reference_versions_match_canonical_three_guard_shape": all(patterns),
        "CVE_root_cause_located": False,
        "firmware_signature_policy_proven": False,
        "runtime_load_mapping_verified": False,
        "stock_R840X_rescue_proven": False,
        "watch_contacted": False, "bootloader_executed": False, "flash_allowed": False,
        "decision": "NO_GO",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--older", required=True, type=Path)
    ap.add_argument("--newer", required=True, type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    try:
        result = compare(read_pinned(args.older, "R500XXU1BSD3"),
                         read_pinned(args.newer, "R500XXU1GUJ2"))
    except (OSError, ValueError) as exc:
        print("REJECTED_INPUT: " + str(exc), file=sys.stderr)
        return 2
    report = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
        print("NO_GO: Original SM-R500 sibling branches analyzed, not R840X boot proof.")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
