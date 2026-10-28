"""Fake report-only tests for SM-R840X sysfs metadata evidence merge.

Never connects to a watch. All fixtures are synthetic redacted JSON.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_merge_sysfs_reports_offline as merge

PUBLIC_OWNER_LABELS = {
    1: "unclassified",
    # Owner-provided Batch 1 on 2026-10-27, physical fixed sysfs p2..p7:
    2: "unclassified",
    3: "unclassified",
    4: "unclassified",
    5: "module",
    6: "unclassified",
    7: "steady",
    8: "unclassified",
    9: "unclassified",
    10: "param",
    11: "up_param",
    12: "unclassified",
    13: "boot",
    14: "recovery",
    15: "unclassified",
    16: "unclassified",
    17: "unclassified",
    18: "csc",
    19: "unclassified",
    20: "rootfs",
    21: "user",
}


def fake(role: str, *, all_named=True) -> dict:
    mode, indices = merge.ROLES[role]
    probes = []
    for index in indices:
        label = PUBLIC_OWNER_LABELS.get(index, "unclassified")
        probes.append({
            "partition_index": index,
            "status": "PARTNAME_FIELD_OBSERVED",
            "kernel_reported_label": label,
        })
    report = {
        "schema": merge.INPUT_SCHEMA,
        "device_target": merge.MODEL,
        "installed_build_recorded": merge.BUILD,
        "active_csc_recorded": merge.CSC,
        "state": "FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED",
        "owner_watch_sysfs_observed": True,
        "report": None,
        "source_path_expression": [
            f"cat /sys/class/block/mmcblk0p{i}/uevent" for i in indices
        ],
        "result": "NO_GO",
        "probe_mode": mode,
        "probe_summary": {
            "tested_partition_indices": list(indices),
            "readable_uevent_files": len(indices),
            "partname_fields_observed": len(indices),
            "full_partition_layout_proven": False,
            "remaining_partition_indices_not_tested": [
                i for i in range(1, 22) if i not in indices
            ],
            "probes": probes,
        },
    }
    report.update({flag: False for flag in merge.NO_GO_FLAGS})
    if role != "fixed":
        report.update({
            "remaining_batch_number": int(role[-1]),
            "prior_owner_observations_not_repeated": [1, 20, 21],
            "prior_owner_rootfs_p20_and_user_p21_not_reverified": True,
        })
    return report


def sources(roles):
    return {
        role: (fake(role), hashlib.sha256(role.encode()).hexdigest())
        for role in roles
    }


class OfflineMergeTests(unittest.TestCase):
    def test_15_actual_owner_reported_positions_reconciled_without_guessing_p2_to_p7(self):
        result = merge.reconcile(sources(("fixed", "batch2", "batch3")))
        self.assertEqual(result["state"], "PARTIAL_KERNEL_TEXT_METADATA_RECONCILED")
        self.assertEqual(result["readable_uevent_count"], 15)
        self.assertEqual(result["partname_field_count"], 15)
        self.assertEqual(result["not_in_supplied_reports"], [2, 3, 4, 5, 6, 7])
        self.assertEqual(result["recognized_public_label_count"], 7)
        self.assertEqual(result["recognized_public_label_indices"],
                         [10, 11, 13, 14, 18, 20, 21])
        self.assertEqual(result["redacted_unclassified_indices"],
                         [1, 8, 9, 12, 15, 16, 17, 19])
        self.assertEqual(len(result["positions"]), 21)
        self.assertEqual(result["positions"][9]["kernel_reported_label"], "param")
        self.assertEqual(result["positions"][13]["kernel_reported_label"], "recovery")
        self.assertEqual(result["positions"][19]["kernel_reported_label"], "rootfs")
        self.assertEqual(result["positions"][20]["kernel_reported_label"], "user")
        self.assertFalse(result["all_21_kernel_text_records_readable"])
        self.assertFalse(result["all_21_kernel_partname_fields_seen"])
        self.assertEqual(result["result"], "NO_GO")
        for key in ("samsung_pit_authenticated", "signed_stock_image_verified",
                    "partition_offsets_sizes_verified", "bootloader_accepted_custom_image",
                    "stock_recovery_proven", "watch_contacted_by_merge",
                    "odin_session_started", "firmware_written", "flash_allowed"):
            self.assertIs(result[key], False, key)

    def test_all_four_reports_allow_21_text_positions_but_never_authenticate_pit(self):
        result = merge.reconcile(sources(("fixed", "batch1", "batch2", "batch3")))
        self.assertEqual(result["state"], "ALL_21_KERNEL_TEXT_PARTNAME_FIELDS_RECONCILED")
        self.assertEqual(result["readable_uevent_count"], 21)
        self.assertEqual(result["partname_field_count"], 21)
        self.assertEqual(result["not_in_supplied_reports"], [])
        # These are known labels present in four separately supplied,
        # privacy-filtered physical reports; fixtures only in CI.
        self.assertEqual(result["recognized_public_label_count"], 9)
        self.assertEqual(result["recognized_public_label_indices"],
                         [5, 7, 10, 11, 13, 14, 18, 20, 21])
        self.assertEqual(result["redacted_unclassified_indices"],
                         [1, 2, 3, 4, 6, 8, 9, 12, 15, 16, 17, 19])
        self.assertEqual(result["positions"][4]["kernel_reported_label"], "module")
        self.assertEqual(result["positions"][6]["kernel_reported_label"], "steady")
        self.assertEqual(result["positions"][9]["kernel_reported_label"], "param")
        self.assertEqual(result["positions"][13]["kernel_reported_label"], "recovery")
        self.assertEqual(result["result"], "NO_GO")
        self.assertFalse(result["samsung_pit_authenticated"])
        self.assertFalse(result["stock_recovery_proven"])
        self.assertFalse(result["partition_offsets_sizes_verified"])
        self.assertTrue(result["unknown_partition_role_positions_still_exist"])

    def test_validator_rejects_forged_wrong_identity_mode_index_and_source_commands(self):
        edits = [
            ("model", lambda x: x.update(device_target="SM-R840")),
            ("build", lambda x: x.update(installed_build_recorded="R840XXU1ATF3")),
            ("csc", lambda x: x.update(active_csc_recorded="XAR")),
            ("mode", lambda x: x.update(probe_mode="SIX_EXPLICIT_TEXT_PATHS_BATCH_1_NO_WILDCARD")),
            ("batch", lambda x: x.update(remaining_batch_number=3)),
            ("wrong_source", lambda x: x.update(source_path_expression=["cat /dev/mmcblk0p8"] * 6)),
            ("indices", lambda x: x["probe_summary"].update(tested_partition_indices=[8, 9, 10, 11, 12, 14])),
            ("probe_index", lambda x: x["probe_summary"]["probes"][0].update(partition_index=9)),
            ("no_go", lambda x: x.update(result="GO")),
            ("device_write", lambda x: x.update(watch_write_performed=True)),
            ("full_layout", lambda x: x["probe_summary"].update(full_partition_layout_proven=True)),
            ("scoped_missing", lambda x: x["probe_summary"].update(remaining_partition_indices_not_tested=[])),
            ("counts", lambda x: x["probe_summary"].update(readable_uevent_files=5)),
            ("fake_raw_label", lambda x: x["probe_summary"]["probes"][0].update(kernel_reported_label="sensitive-personal-id")),
        ]
        for name, edit in edits:
            with self.subTest(attack=name):
                candidate = fake("batch2")
                edit(candidate)
                with self.assertRaises(merge.EvidenceError):
                    merge.validate_report(candidate, "batch2")

    def test_partial_records_and_redactions_remain_unknown(self):
        item = fake("batch2")
        probes = item["probe_summary"]["probes"]
        probes[0] = {"partition_index": 8,
                     "status": "UEVENT_READABLE_BUT_PARTNAME_ABSENT",
                     "kernel_reported_label": "not_exported"}
        probes[1] = {"partition_index": 9, "status": "SDB_TRANSPORT_UNREACHABLE"}
        item["probe_summary"].update(readable_uevent_files=5, partname_fields_observed=4)
        out = merge.validate_report(item, "batch2")
        self.assertEqual(out[0]["kernel_reported_label"], "not_exported")
        self.assertIsNone(out[1]["kernel_reported_label"])
        bag = sources(("fixed", "batch3"))
        bag["batch2"] = (item, hashlib.sha256(b"partial").hexdigest())
        result = merge.reconcile(bag)
        self.assertEqual(result["readable_uevent_count"], 14)
        self.assertEqual(result["partname_field_count"], 13)
        self.assertFalse(result["all_21_kernel_partname_fields_seen"])
        self.assertFalse(result["stock_recovery_proven"])

    def test_duplicate_or_misassigned_source_roles_rejected(self):
        with self.assertRaisesRegex(merge.EvidenceError, "FIXED_BASELINE_REPORT_REQUIRED"):
            merge.reconcile(sources(("batch2", "batch3")))
        bad = sources(("fixed", "batch2"))
        bad["batch2"] = (fake("fixed"), hashlib.sha256(b"wrongrole").hexdigest())
        with self.assertRaises(merge.EvidenceError):
            merge.reconcile(bad)
        bad = sources(("fixed", "batch2"))
        bad["batch2"] = (fake("batch2"), bad["fixed"][1])
        with self.assertRaisesRegex(merge.EvidenceError, "DUPLICATE_REPORT_BYTES"):
            merge.reconcile(bad)

    def test_json_duplicate_keys_symlink_and_size_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text('{"status": 1, "status": 2}')
            with self.assertRaisesRegex(merge.EvidenceError, "INVALID_REPORT_JSON"):
                merge.read_json_file(p)
            p.write_bytes(b"{" + b"x" * merge.MAX_JSON_BYTES)
            with self.assertRaisesRegex(merge.EvidenceError, "INPUT_NOT_REGULAR_OR_OUT_OF_BOUNDS"):
                merge.read_json_file(p)
            link = Path(td) / "link.json"
            link.symlink_to(p)
            with self.assertRaisesRegex(merge.EvidenceError, "INPUT_UNREADABLE_OR_SYMLINK"):
                merge.read_json_file(link)

    def test_cli_zero_network_private_exclusive_and_does_not_echo_raw_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paths = {}
            for role in ("fixed", "batch2", "batch3"):
                p = root / (role + ".json")
                p.write_text(json.dumps(fake(role)))
                paths[role] = str(p)
            out = root / "merged.json"
            argv = ["--fixed", paths["fixed"], "--batch2", paths["batch2"],
                    "--batch3", paths["batch3"], "--output", str(out)]
            with patch.object(socket, "socket", side_effect=AssertionError("NETWORK_FORBIDDEN")):
                self.assertEqual(merge.main(argv), 0)
                self.assertEqual(merge.main(argv), 1)
            result = json.loads(out.read_text())
            self.assertEqual(result["readable_uevent_count"], 15)
            self.assertNotIn(str(root), out.read_text())
            self.assertEqual(out.stat().st_mode & 0o077, 0)
            self.assertTrue(all("input_report_sha256_identity_only" in r
                                for r in result["reports_used"]))


if __name__ == "__main__":
    unittest.main()
