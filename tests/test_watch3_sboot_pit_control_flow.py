"""Synthetic AArch64 control-flow tests for Issue #47: no firmware or device."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "watch3_sboot_pit_control_flow.py"
spec = importlib.util.spec_from_file_location("pit_cfg", SOURCE)
# The analyzer imports its sibling module from tools/.
import sys
sys.path.insert(0, str(SOURCE.parent))
cfg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cfg)


def put(buf: bytearray, off: int, word: int) -> None:
    struct.pack_into("<I", buf, off, word)


def cond(pc: int, dest: int, condition: int) -> int:
    assert (dest-pc) % 4 == 0
    return 0x54000000 | (((dest-pc)//4 & 0x7FFFF) << 5) | condition


def tbnz(pc: int, dest: int, reg: int=0, bit: int=31) -> int:
    assert (dest-pc) % 4 == 0
    return (0x37000000 | (((bit >> 5) & 1) << 31) |
            ((bit & 31) << 19) | (((dest-pc)//4 & 0x3FFF) << 5) | reg)


def direct(pc: int, dest: int, call: bool = True) -> int:
    return (0x94000000 if call else 0x14000000) | (((dest-pc)//4) & 0x3FFFFFF)


def ldr(reg: int, base: int, off: int, width: int) -> int:
    assert off % (width // 8) == 0
    return (0xF9400000 if width == 64 else 0xB9400000) | (
        (off // (width // 8)) << 10) | (base << 5) | reg


def dispatch_fixture(build: str) -> bytes:
    """Construct only operand patterns; never copy an executable firmware image."""
    s = cfg.DISPATCH_REFERENCE_OFFSETS[build]
    root, cmp_pc, case, call, recv, adjacent = (
        s[k] for k in ("dispatcher", "command_cmp", "pit_case",
                      "validator_call", "receive_call", "next_routine"))
    b = bytearray(0x90000)
    anchor = cfg.REFERENCES[build][1]
    for n, word in enumerate((0xA9BD7BFD, 0x2A0103E2, 0x910003FD, 0xA90153F3)):
        put(b, anchor-16+4*n, word)
    for off, word in ((0, 0xD11143FF), (4, 0xAA0003E1), (8, 0xD2808002),
                      (12, 0xA9007BFD), (16, 0x910003FD), (20, 0x910143A0)):
        put(b, root+off, word)
    put(b, cmp_pc-12, ldr(19, 29, 0x50, 32))
    put(b, cmp_pc-8, 0x7101927F)
    put(b, cmp_pc-4, cond(cmp_pc-4, root+0x90, 0))
    put(b, cmp_pc, 0x7101967F)
    put(b, cmp_pc+4, cond(cmp_pc+4, case, 0))
    put(b, case, ldr(1, 29, 0x54, 32))
    put(b, case+4, 0x90000014)  # ADRP x20 to current raw-file page
    put(b, case+8, 0x91000294)  # ADD x20,x20,#0
    put(b, case+12, ldr(0, 20, 4, 32))
    put(b, case+16, 0x34000001 | ((((call+0xBC-case-16)//4) & 0x7FFFF) << 5))
    for off, value in ((20, 0x7100043F), (28, 0x7100083F), (36, 0x71000C3F)):
        put(b, case+off, value)
    for off, target, condition in ((24,call+0x84,0),(32,call+0x38,0),(40,call-0x668,1)):
        put(b, case+off, cond(case+off, target, condition))
    put(b, case+44, 0x34000000 | ((((call-8-case-44)//4) & 0x7FFFF) << 5))
    put(b, call-8, ldr(1,20,0x58,32))
    put(b, call-4, ldr(0,20,0x30,64))
    put(b, call, direct(call,anchor-16))
    put(b, call+4, tbnz(call+4,call-0x700))
    put(b, call+8, direct(call+8,adjacent))
    put(b, adjacent, 0xA9BD7BFD)
    put(b, recv-12, 0x710FFEDF)
    put(b, recv-8, ldr(0,20,0x78,64))
    put(b, recv-4, cond(recv-4,recv+0x80,13))
    put(b, recv, direct(recv,root))
    return bytes(b)


def synthetic(anchor: int=0x1000, equal_delta: int=0x88) -> bytes:
    buf = bytearray(0x6000)
    pit = 0x2240
    buf[pit:pit+4] = b"PIT\x00"
    page = ((pit & ~4095)-(anchor & ~4095)) >> 12
    imm = page & ((1 << 21)-1)
    put(buf, anchor, 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | 4)
    put(buf, anchor+4, 0x91000000 | ((pit & 4095) << 10) | (4 << 5) | 4)
    put(buf, anchor+0x20, tbnz(anchor+0x20, anchor+0x128))
    put(buf, anchor+0x24, 0xF100001F | (1 << 22) | (2 << 10) | (21 << 5))
    put(buf, anchor+0x28, cond(anchor+0x28, anchor+0x100, 12))
    put(buf, anchor+0x30, 0x52800000 | (0x9876 << 5) | 3)
    put(buf, anchor+0x38, 0x72800000 | (1 << 21) | (0x1234 << 5) | 3)
    put(buf, anchor+0x50, 0x6B03005F)
    put(buf, anchor+0x54, cond(anchor+0x54, anchor+equal_delta, 0))
    put(buf, anchor+0x70, 0x12800000) # movn w0,#0 -> -1
    put(buf, anchor+0x74, 0xD65F03C0) # ret x30
    put(buf, anchor+equal_delta, 0xD65F03C0)
    put(buf, anchor+0x100, 0xD65F03C0)
    put(buf, anchor+0x128, 0xD65F03C0)
    return bytes(buf)


class BoundedPITGuards(unittest.TestCase):
    def test_realistic_three_guard_pattern(self):
        report = cfg.find_gates(synthetic(), 0x1000)
        self.assertTrue(report["canonical_candidate_three_guards"])
        self.assertEqual(report["status_error_bit_guards"][0]["branch_target"], 0x1128)
        self.assertEqual(report["length_greater_than_0x2000_guards"][0]["register"], 21)
        self.assertEqual(report["length_greater_than_0x2000_guards"][0]["branch_target"], 0x1100)
        self.assertEqual(report["header_equal_to_magic_guards"][0]["branch_target"], 0x1088)
        self.assertEqual(report["header_equal_to_magic_guards"][0]["magic_register"], 3)

    def test_magic_mismatch_fallthrough_traces_to_return(self):
        report = cfg.find_gates(synthetic(), 0x1000)
        trace = report["header_not_equal_fallthrough_trace"]
        self.assertEqual(trace["stop"], "RET")
        self.assertEqual(trace["end_file_offset"], 0x1074)
        self.assertEqual(trace["movn_w0_minus_one_offsets"], [0x1070])
        self.assertFalse(trace["return_value_proven"])

    def test_semantic_checks_survive_layout_shift(self):
        older = cfg.find_gates(synthetic(equal_delta=0x80), 0x1000)
        newer = cfg.find_gates(synthetic(equal_delta=0x88), 0x1000)
        self.assertTrue(older["canonical_candidate_three_guards"])
        self.assertTrue(newer["canonical_candidate_three_guards"])
        self.assertNotEqual(older["header_equal_to_magic_guards"][0]["branch_target"],
                            newer["header_equal_to_magic_guards"][0]["branch_target"])

    def test_wrong_header_register_rejected(self):
        blob = bytearray(synthetic())
        put(blob, 0x1050, 0x6B04005F) # cmp w2,w4: w4 not the observed w3 magic
        report = cfg.find_gates(bytes(blob), 0x1000)
        self.assertFalse(report["canonical_candidate_three_guards"])
        self.assertFalse(report["header_equal_to_magic_guards"])

    def test_status_bit_mutation_rejected(self):
        blob = bytearray(synthetic())
        put(blob, 0x1020, tbnz(0x1020, 0x1128, bit=30))
        self.assertFalse(cfg.find_gates(bytes(blob), 0x1000)[
            "canonical_candidate_three_guards"])

    def test_bad_length_branch_condition_rejected(self):
        blob = bytearray(synthetic())
        put(blob, 0x1028, cond(0x1028, 0x1100, 0))
        self.assertFalse(cfg.find_gates(bytes(blob), 0x1000)[
            "canonical_candidate_three_guards"])

    def test_pit_string_not_just_unrelated_printable_bytes(self):
        blob = bytearray(synthetic())
        put(blob, 0x1004, 0xD503201F) # NOP destroys ADRP->ADD reference
        self.assertFalse(cfg.find_gates(bytes(blob), 0x1000)[
            "canonical_candidate_three_guards"])

    def test_branch_graph_records_conditional_successors(self):
        g = cfg.branch_graph(synthetic(), 0x1000)
        self.assertTrue(any(x["kind"] == "TBNZ" and x["target"] == 0x1128
                            for x in g["bounded_branch_edges"]))
        self.assertTrue(any(x["kind"] == "B_COND" and x["target"] == 0x1088
                            for x in g["bounded_branch_edges"]))
        self.assertTrue(any(x["kind"] == "RET" and x["file_offset"] == 0x1074
                            for x in g["bounded_terminal_candidates"]))
        self.assertFalse(g["entry_is_verified_function_start"])

    def test_outside_window_target_is_not_followed(self):
        blob = bytearray(synthetic())
        put(blob, 0x1028, cond(0x1028, 0x1900, 12))
        g = cfg.branch_graph(bytes(blob), 0x1000)
        edge = next(x for x in g["bounded_branch_edges"] if x["from"] == 0x1028)
        self.assertEqual(edge["target_class"], "OUTSIDE_WINDOW_UNVERIFIED")
        self.assertFalse(g["branch_target_addresses_are_runtime_addresses"])

    def test_sign_extended_direct_and_test_bit_branches(self):
        word = tbnz(0x1100, 0x1000, reg=5, bit=63)
        self.assertEqual(cfg.branch(word, 0x1100)["target"], 0x1000)
        self.assertEqual(cfg.branch(word, 0x1100)["bit"], 63)
        self.assertEqual(cfg.branch(cond(0x1100, 0x1000, 1), 0x1100)["target"], 0x1000)
        self.assertEqual(cfg.branch(0xD65F03C0, 0x1000)["op"], "RET")

    def test_invalid_window_is_rejected_without_reading_extra_bytes(self):
        data = synthetic()
        for a in (3, -4, len(data)-cfg.WINDOW_BYTES+4):
            with self.assertRaises(ValueError):
                cfg.find_gates(data, a)
            with self.assertRaises(ValueError):
                cfg.branch_graph(data, a)

    def test_unreachable_padding_not_marked_as_function_proof(self):
        graph = cfg.branch_graph(synthetic(), 0x1000)
        self.assertLess(graph["decoded_reachable_raw_offset_count"], cfg.MAX_VISITED)
        self.assertFalse(graph["entry_is_verified_function_start"])
        self.assertFalse(graph["unresolved_worklist_at_budget"])


    def test_inbound_direct_calls_into_candidate_region_not_function_proof(self):
        anchor = 0x1000
        blob = bytearray(synthetic(anchor))
        def jump(pc, target, call):
            assert (target - pc) % 4 == 0
            return (0x94000000 if call else 0x14000000) | (
                (target - pc) // 4 & 0x3FFFFFF)
        # Two potential external entries; neither is a verified handler.
        put(blob, 0x300, jump(0x300, 0xF80, True))
        put(blob, 0x304, jump(0x304, 0x1040, False))
        # B landing outside the 0xF00..0x1180 candidate window is ignored.
        put(blob, 0x308, jump(0x308, 0xEFC, True))
        # B landing inside itself is an internal edge, not a caller.
        put(blob, 0x1010, jump(0x1010, 0x1040, True))
        result = cfg.inbound_candidates(bytes(blob), anchor, start=0x200, end=0x2000)
        edges = result["incoming_direct_edges"]
        self.assertEqual([(e["source_file_offset"], e["source_op"]) for e in edges],
                         [(0x300, "BL"), (0x304, "B")])
        self.assertEqual(result["candidate_direct_call_count"], 1)
        self.assertEqual(result["candidate_direct_branch_count"], 1)
        self.assertFalse(result["call_chain_to_wireless_protocol_verified"])
        self.assertFalse(result["function_entry_verified"])

    def test_inbound_negative_offsets_and_boundaries_fail_closed(self):
        data = synthetic()
        for args in (
            {"anchor": 0x1000, "start": -4, "end": 0x2000},
            {"anchor": 0x1000, "start": 3, "end": 0x2000},
            {"anchor": 0x1000, "start": 0, "end": 0x1000},
            {"anchor": 0x1000, "start": 0, "end": len(data) + 4},
            {"anchor": 0x1001, "start": 0, "end": len(data)},
            {"anchor": 0x50, "start": 0, "end": len(data)},
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    cfg.inbound_candidates(data, **args)
        with self.assertRaises(ValueError):
            cfg.inbound_candidates(data, 0x1000, start=0, end=0x2001)

    def test_inbound_does_not_treat_conditional_or_indirect_branch_as_call(self):
        data = bytearray(synthetic())
        put(data, 0x300, cond(0x300, 0x1000, 0))
        put(data, 0x304, 0xD63F0000)  # BLR X0: indirect, cannot resolve
        found = cfg.inbound_candidates(bytes(data), 0x1000, start=0x200, end=0x2000)
        self.assertFalse(found["incoming_direct_edges"])
        self.assertFalse(found["indirect_callers_analyzed"])


class DonorDispatchProvenance(unittest.TestCase):
    def test_both_reference_layouts_have_separate_validator_and_following_call(self):
        for build in cfg.REFERENCES:
            with self.subTest(build=build):
                b = dispatch_fixture(build)
                r = cfg.donor_dispatch_context(b, build)
                self.assertTrue(r["observed_slice_matches"], r["checks"])
                self.assertEqual(r["path_classification"], "PIT_UPLOAD_FINALIZATION_CANDIDATE")
                self.assertEqual((r["command_value"],r["subcommand_value"],r["required_state_value"]),
                                 (0x65,3,0))
                edges = cfg.inbound_candidates(b, cfg.REFERENCES[build][1],
                                              start=0x40000,end=len(b))
                self.assertEqual(edges["candidate_direct_call_count"], 2)
                self.assertEqual(edges["candidate_direct_calls_to_pit_frame_entry"], 1)
                self.assertEqual([e["target_role"] for e in edges["incoming_direct_edges"]],
                                 ["PIT_FRAME_ENTRY_CANDIDATE", "OTHER_PIT_VICINITY_TARGET"])

    def test_operand_and_branch_mutations_do_not_establish_supported_path(self):
        build = "R500XXU1BSD3"
        s = cfg.DISPATCH_REFERENCE_OFFSETS[build]
        a, c, p, r = (s[k] for k in ("command_cmp","validator_call","pit_case","receive_call"))
        mutations = (
            (s["dispatcher"], 0xD503201F),  # No stack allocation.
            (a, 0x71019A7F),  # Command 0x66 is not PIT 0x65.
            (a+4, cond(a+4,p,1)),  # Wrong equality condition.
            (a-12, ldr(19,29,0x54,32)),  # Not command word.
            (p, ldr(1,29,0x58,32)),  # Not subcommand word.
            (p+8, 0x91000273),  # ADD wrong register breaks state-object reference.
            (p+12, ldr(0,20,8,32)),  # Wrong state-object slot.
            (p+36, 0x7100083F),  # Subcommand 2, not upload finalization 3.
            (p+40, cond(p+40,c-0x668,0)),  # Inverted reject branch.
            (p+44, 0xB4000000 | ((((c-8-p-44)//4) & 0x7FFFF) << 5)),
            (c-8, ldr(1,20,0x58,64)),  # W1 and X1 lengths differ.
            (c-4, ldr(0,20,0x30,32)),  # Truncated pointer.
            (c, direct(c,s["next_routine"])),  # Nearby entry is not validator.
            (c+4,tbnz(c+4,c-0x700,bit=30)),  # Wrong error bit.
            (c+8,direct(c+8,cfg.REFERENCES[build][1]-16)),  # Duplicated validator call.
            (r-8,ldr(0,20,0x80,64)),  # Different receive buffer.
            (r-12,0x710FFADF),  # Wrong received-byte threshold.
            (r,direct(r,s["dispatcher"]+4)),  # Skip entry.
        )
        for pc, replacement in mutations:
            with self.subTest(offset=hex(pc),word=hex(replacement)):
                blob = bytearray(dispatch_fixture(build))
                put(blob,pc,replacement)
                report=cfg.donor_dispatch_context(bytes(blob),build)
                self.assertFalse(report["observed_slice_matches"])
                self.assertEqual(report["path_classification"],"UNRESOLVED_REFERENCE_SLICE")
                self.assertIsNone(report["command_value"])
                self.assertIsNone(report["validator_buffer_object_offset"])

    def test_matching_slice_does_not_claim_wireless_unlock_or_read_safety(self):
        r=cfg.donor_dispatch_context(dispatch_fixture("R500XXU1BSD3"),"R500XXU1BSD3")
        for k in ("wireless_transport_proven","owner_R840X_equivalence_proven",
                  "signature_bypass_proven","safe_read_only_device_operation_proven"):
            self.assertIs(r[k],False)

    def test_frame_pattern_mutation_removes_specific_entry_classification(self):
        build="R500XXU1BSD3"
        b=bytearray(dispatch_fixture(build))
        anchor=cfg.REFERENCES[build][1]
        put(b,anchor-8,0xD503201F)
        r=cfg.inbound_candidates(bytes(b),anchor,start=0x40000,end=len(b))
        self.assertIsNone(r["pit_frame_entry_candidate"])
        self.assertEqual(r["candidate_direct_calls_to_pit_frame_entry"],0)
        self.assertTrue(all(e["target_role"]=="OTHER_PIT_VICINITY_TARGET"
                            for e in r["incoming_direct_edges"]))

    def test_load_decoder_rejects_signed_writeback_and_register_addressing(self):
        for word in (0xB9805A81,0xF85F8E80,0xF8606A80,0xB9005A81):
            self.assertIsNone(cfg.load_unsigned(word))

    def test_truncated_and_unknown_reference_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError,"TRUNCATED"):
            cfg.donor_dispatch_context(b"\0"*32,"R500XXU1BSD3")
        with self.assertRaisesRegex(ValueError,"UNSUPPORTED"):
            cfg.donor_dispatch_context(b"\0"*32,"R840XXXU1AUA2")

    def test_frame_candidate_rejects_bad_interval(self):
        for a in (-4,0,2,0x1000):
            self.assertIsNone(cfg.pit_entry_candidate(b"\0"*64,a))


if __name__ == "__main__":
    unittest.main()
