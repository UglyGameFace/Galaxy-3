"""Synthetic-only no-watch regression of sysfs metadata partition labels."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_partition_sysfs_readonly as probe
from watch3_r08_android_sdb import (
    ALLOWED_PROBES, Connection, PARTITION_SYSFS_PROBES,
    PARTITION_SYSFS_FIXED_PROBES, PARTITION_SYSFS_REMAINING_BATCH_PROBES,
    SdbError, collect, VERSION, frame, receive,
)


def record(n: int, name: str, secret: str = "SECRET_UUID") -> str:
    return (f"MAJOR=179\nMINOR={n}\nDEVNAME=mmcblk0p{n}\n"
            f"DEVTYPE=partition\nPARTN={n}\nPARTNAME={name}\n"
            f"PARTUUID={secret}\n")


class FixedSysfsLabelsTests(unittest.TestCase):
    def test_exact_allowlist_command_cannot_open_partition_bytes(self):
        self.assertEqual(PARTITION_SYSFS_PROBES, {
            "partitions_uevent": "cat /sys/class/block/mmcblk0p[0-9]*/uevent",
        })
        self.assertEqual(ALLOWED_PROBES["partitions_uevent"],
                         PARTITION_SYSFS_PROBES["partitions_uevent"])
        command = PARTITION_SYSFS_PROBES["partitions_uevent"]
        for forbidden in ("&&", ";", "|", ">", "<", "/dev/",
                          "dmsetup", "dd ", "flash", "sdb", "odin"):
            self.assertNotIn(forbidden, command.lower())

    def test_exact_21_partitions_only_and_no_private_uuid_leaks(self):
        raw = "".join(record(n, "BOOT" if n == 1 else
                             "RECOVERY" if n == 2 else
                             "ROOTFS" if n == 20 else
                             "userdata" if n == 21 else
                             "UNKNOWNSECRET-123") for n in range(1, 22))
        report = probe.parse_sysfs(raw)
        self.assertEqual(report["state"], "SYSFS_PARTITION_LABELS_OBSERVED")
        self.assertEqual(report["reported_partition_count"], 21)
        self.assertTrue(report["all_21_numbered_partitions_observed"])
        self.assertEqual(report["missing_partition_indices"], [])
        labels = report["partition_name_records"]
        self.assertEqual(labels[0]["kernel_reported_label"], "boot")
        self.assertEqual(labels[1]["kernel_reported_label"], "recovery")
        self.assertEqual(labels[19]["kernel_reported_label"], "rootfs")
        self.assertEqual(labels[20]["kernel_reported_label"], "userdata")
        self.assertEqual(labels[2]["kernel_reported_label"], "unclassified")
        dumped = json.dumps(report)
        self.assertNotIn("PARTUUID", dumped)
        self.assertNotIn("SECRET", dumped)
        self.assertNotIn("MINOR", dumped)

    def test_partial_partition_map_remains_incomplete(self):
        parsed = probe.parse_sysfs(record(20, "rootfs") + record(21, "userdata"))
        self.assertEqual(parsed["reported_partition_count"], 2)
        self.assertFalse(parsed["all_21_numbered_partitions_observed"])
        self.assertIn(1, parsed["missing_partition_indices"])
        self.assertNotIn(20, parsed["missing_partition_indices"])

    def test_invalid_mapping_is_not_treated_as_valid(self):
        cases = (
            (record(1, "BOOT").replace("PARTN=1", "PARTN=20"),
             "PARTNUMBER_MISMATCH"),
            (record(2, "RECOVERY") + record(2, "RECOVERY"),
             "DUPLICATE_PARTITION_RECORD"),
            (record(1, "BOOT").replace("PARTN=1\n", "PARTN=1\nPARTN=1\n"),
             "DUPLICATE_SYSFS_KEY"),
            (record(1, "BOOT") + "\0", "BINARY_OR_NUL_SYSFS_RESPONSE"),
            ("MAJOR=179\nMINOR=0\n", None),
            (record(1, "BOOT") * 22, "TOO_MANY_SYSFS_RECORDS"),
            (record(1, "BOOT") + ("A" * 17000), "SYSFS_TEXT_EXCEEDS_16_KIB"),
        )
        for raw, error in cases:
            with self.subTest(error=error):
                if error:
                    with self.assertRaisesRegex(probe.PartitionLabelsError, error):
                        probe.parse_sysfs(raw)
                else:
                    self.assertEqual(probe.parse_sysfs(raw)["reported_partition_count"], 0)

    def test_one_fixed_read_only_collection_no_flash_claims(self):
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=({"partitions_uevent": record(4, "PARAM")}, {})) as called:
            report = probe.inspect_live("10.0.0.65", Path("/unused"))
        self.assertEqual(called.call_args.kwargs["probes"], PARTITION_SYSFS_PROBES)
        self.assertTrue(report["owner_watch_sysfs_observed"])
        self.assertEqual(report["report"]["partition_name_records"],
                         [{"index": 4, "kernel_reported_label": "param"}])
        for key in ("raw_partition_bytes_read", "pit_requested",
                    "odin_session_started", "watch_write_performed",
                    "stock_recovery_proven", "bootloader_acceptance_proven",
                    "flash_allowed"):
            self.assertIs(report[key], False, key)
        self.assertEqual(report["result"], "NO_GO")

    def test_file_denial_is_inconclusive_and_no_guess(self):
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=({}, {"partitions_uevent": "Read-only property unavailable"})):
            report = probe.inspect_live("10.0.0.65", Path("/unused"))
        self.assertEqual(report["state"], "SYSFS_READ_UNAVAILABLE_OR_UNSUPPORTED_GLOB")
        self.assertIsNone(report["report"])
        self.assertFalse(report["owner_watch_sysfs_observed"])

    def test_fake_sample_never_claims_watch_success_and_is_private(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "fake.txt"
            sample.write_text(record(1, "BOOT", "DO_NOT_LEAK_PERSONAL_UUID"))
            dest = Path(td) / "report.json"
            with patch("watch3_r840x_partition_sysfs_readonly.collect",
                       side_effect=AssertionError("OFFLINE_MUST_NEVER_CONTACT_WATCH")):
                self.assertEqual(probe.main([
                    "--offline-sample", str(sample), "--report", str(dest)
                ]), 0)
            result = json.loads(dest.read_text())
            self.assertEqual(result["state"], "OFFLINE_SAMPLE_ONLY_NOT_A_REAL_WATCH_OBSERVATION")
            self.assertIs(result["owner_watch_sysfs_observed"], False)
            self.assertIs(result["flash_allowed"], False)
            self.assertNotIn("UUID", dest.read_text())
            self.assertEqual(dest.stat().st_mode & 0o077, 0)

    def test_existing_report_stops_network_and_overwrite_before_contact(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "prior.json"
            dest.write_text("original")
            with patch("watch3_r840x_partition_sysfs_readonly.collect",
                       side_effect=AssertionError("EXISTING_REPORT_MUST_BLOCK_WATCH")):
                self.assertEqual(probe.main([
                    "--watch-ip", "10.0.0.65", "--report", str(dest)
                ]), 1)
            self.assertEqual(dest.read_text(), "original")


    def test_partition_name_may_be_absent_even_when_uevent_readable(self):
        # Linux part_uevent adds PARTNAME only when volume label exists.
        without = (record(1, "BOOT").replace("PARTNAME=BOOT\n", ""))
        parsed = probe.parse_sysfs(without)
        self.assertEqual(parsed["state"], "SYSFS_PARTITION_METADATA_ONLY_NO_PARTNAME")
        self.assertEqual(parsed["partname_field_count"], 0)
        self.assertEqual(parsed["partition_name_records"],
                         [{"index": 1, "kernel_reported_label": "not_exported"}])
        self.assertEqual(probe.parse_sysfs(record(1, "BOOT"))["partname_field_count"], 1)

    def test_fixed_probes_have_three_exact_no_wildcard_paths_and_cannot_open_devices(self):
        expected = {
            "partition_p1_uevent": "cat /sys/class/block/mmcblk0p1/uevent",
            "partition_p20_uevent": "cat /sys/class/block/mmcblk0p20/uevent",
            "partition_p21_uevent": "cat /sys/class/block/mmcblk0p21/uevent",
        }
        self.assertEqual(PARTITION_SYSFS_FIXED_PROBES, expected)
        self.assertEqual({k: ALLOWED_PROBES[k] for k in expected}, expected)
        for cmd in expected.values():
            for forbidden in ("*", "[", "]", "/dev/", ";", "&&", "|", ">", "<",
                              "dd ", "reboot", "flash", "odin", "sdb"):
                self.assertNotIn(forbidden, cmd.lower())

    def test_three_read_only_fixed_files_require_matching_indices_and_do_not_claim_all_21(self):
        outputs = {
            "partition_p1_uevent": record(1, "BOOT", "DO_NOT_LEAK_UUID"),
            "partition_p20_uevent": record(20, "rootfs"),
            "partition_p21_uevent": record(21, "userdata").replace(
                "PARTNAME=userdata\n", ""),
        }
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=(outputs, {})) as call:
            result = probe.inspect_fixed_sample("10.0.0.65", Path("/unused"))
        self.assertIs(call.call_args.kwargs["probes"], PARTITION_SYSFS_FIXED_PROBES)
        self.assertEqual(result["state"], "FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED")
        self.assertTrue(result["owner_watch_sysfs_observed"])
        summary = result["probe_summary"]
        self.assertEqual(summary["readable_uevent_files"], 3)
        self.assertEqual(summary["partname_fields_observed"], 2)
        self.assertEqual(len(summary["remaining_partition_indices_not_tested"]), 18)
        self.assertEqual([x["status"] for x in summary["probes"]],
                         ["PARTNAME_FIELD_OBSERVED", "PARTNAME_FIELD_OBSERVED",
                          "UEVENT_READABLE_BUT_PARTNAME_ABSENT"])
        self.assertEqual(summary["probes"][2]["kernel_reported_label"], "not_exported")
        self.assertFalse(summary["full_partition_layout_proven"])
        for key in ("raw_partition_bytes_read", "pit_requested", "odin_session_started",
                    "watch_write_performed", "stock_recovery_proven",
                    "bootloader_acceptance_proven", "flash_allowed"):
            self.assertIs(result[key], False, key)
        self.assertNotIn("DO_NOT_LEAK_UUID", json.dumps(result))
        self.assertEqual(result["result"], "NO_GO")

    def test_read_only_fixed_path_errors_are_distinguished_without_leaking_watch_text(self):
        problems = {
            "partition_p1_uevent": "SDB_SHELL_CLOSED_OR_REFUSED",
            "partition_p20_uevent": "SYSFS_PATH_OR_COMMAND_NOT_FOUND",
            "partition_p21_uevent": "SDB_TRANSPORT_UNREACHABLE",
        }
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=({}, problems)):
            report = probe.inspect_fixed_sample("10.0.0.65", Path("/unused"))
        self.assertEqual(report["state"], "FIXED_SYSFS_NO_VALID_TEXT_OBSERVATIONS")
        self.assertFalse(report["owner_watch_sysfs_observed"])
        self.assertEqual([x["status"] for x in report["probe_summary"]["probes"]],
                         list(problems.values()))
        self.assertNotIn("10.0.0.65", json.dumps(report))
        self.assertIs(report["report"], None)
        self.assertEqual(report["result"], "NO_GO")

    def test_literal_sysfs_read_refuses_mismatched_partition_records(self):
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=({
                       "partition_p1_uevent": record(20, "ROOTFS"),
                       "partition_p20_uevent": record(20, "ROOTFS") +
                                                  record(21, "userdata"),
                       "partition_p21_uevent": record(21, "userdata") +
                                                  "PARTN=22\n",
                   }, {})):
            report = probe.inspect_fixed_sample("10.0.0.65", Path("/unused"))
        self.assertEqual(report["probe_summary"]["readable_uevent_files"], 0)
        self.assertFalse(report["owner_watch_sysfs_observed"])

    def test_fixed_path_mode_refuses_reuse_of_prior_report_before_contact(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "existing.json"
            dest.write_text("old watch report")
            with patch("watch3_r840x_partition_sysfs_readonly.collect",
                       side_effect=AssertionError("NO EXTRA NETWORK")):
                self.assertEqual(probe.main([
                    "--watch-ip", "10.0.0.65", "--fixed-paths",
                    "--report", str(dest)
                ]), 1)
            self.assertEqual(dest.read_text(), "old watch report")

    def test_fixed_paths_are_never_inferred_from_arbitrary_operation_or_mapping(self):
        class EmptySocket:
            sent = bytearray()
            def sendall(self, b):
                self.sent.extend(b)
        s = EmptySocket()
        channel = Connection(s, Path("/synthetic"))
        for key in ("partition_p100_uevent", "reboot", "cat /dev/mmcblk0"):
            with self.assertRaisesRegex(SdbError, "allowlist"):
                channel.shell(key)
        self.assertEqual(bytes(s.sent), b"")
        with self.assertRaisesRegex(SdbError, "predefined"):
            collect("10.0.0.65", Path("/unused"),
                    probes={"partition_p1_uevent": "cat /dev/mmcblk0p1"})

    def test_arbitrary_operation_name_is_not_allowed_to_sdb(self):
        # Existing Connection.shell rejects command text not present in allowlist
        # before it transmits any data to a socket.
        class EmptySocket:
            sent = bytearray()
            def sendall(self, part):
                self.sent.extend(part)
        sock = EmptySocket()
        connection = Connection(sock, Path("/synthetic"))
        for value in ("cat /dev/mmcblk0", "reboot", "dd if=/dev/mmcblk0"):
            with self.assertRaisesRegex(SdbError, "allowlist"):
                connection.shell(value)
        self.assertEqual(bytes(sock.sent), b"")


    def test_remaining_18_are_three_explicit_six_file_sets_not_globs(self):
        self.assertEqual(len(PARTITION_SYSFS_REMAINING_BATCH_PROBES), 3)
        expected_all = list(range(2, 20))
        found = []
        for batch, expected_indices in zip(PARTITION_SYSFS_REMAINING_BATCH_PROBES,
                                           (range(2, 8), range(8, 14), range(14, 20))):
            self.assertEqual(len(batch), 6)
            for index in expected_indices:
                name = f"partition_p{index}_uevent"
                expected = f"cat /sys/class/block/mmcblk0p{index}/uevent"
                self.assertEqual(batch[name], expected)
                self.assertEqual(ALLOWED_PROBES[name], expected)
                for forbidden in ("*", "[", "]", "/dev/", ";", "&&",
                                  "|", ">", "<", "dd ", "reboot", "flash",
                                  "odin", "sdb", "source", "chmod"):
                    self.assertNotIn(forbidden, expected.lower())
                found.append(index)
        self.assertEqual(found, expected_all)
        self.assertFalse(any(x in found for x in (1, 20, 21)))

    def test_all_three_batches_can_parse_synthetic_named_sysfs_records(self):
        for batch_number, low in ((1, 2), (2, 8), (3, 14)):
            group = PARTITION_SYSFS_REMAINING_BATCH_PROBES[batch_number - 1]
            values = {key: record(index, ("BOOT" if index == low else
                                           "RECOVERY" if index == low + 1 else
                                           "UNRECOGNIZED_PRIVATE_VALUE"))
                      for index, key in zip(range(low, low + 6), group)}
            with self.subTest(batch=batch_number), patch(
                "watch3_r840x_partition_sysfs_readonly.collect",
                return_value=(values, {})
            ) as call:
                report = probe.inspect_remaining_batch("10.0.0.65", Path("/unused"),
                                                       batch_number)
                self.assertIs(call.call_args.kwargs["probes"], group)
                summary = report["probe_summary"]
                self.assertEqual(summary["tested_partition_indices"],
                                 list(range(low, low + 6)))
                self.assertEqual(summary["readable_uevent_files"], 6)
                self.assertEqual(summary["partname_fields_observed"], 6)
                self.assertEqual(summary["probes"][0]["kernel_reported_label"], "boot")
                self.assertEqual(summary["probes"][1]["kernel_reported_label"], "recovery")
                self.assertEqual(summary["probes"][2]["kernel_reported_label"], "unclassified")
                self.assertFalse(summary["full_partition_layout_proven"])
                self.assertEqual(len(summary["remaining_partition_indices_not_tested"]), 15)
                self.assertEqual(report["prior_owner_observations_not_repeated"], [1, 20, 21])
                self.assertTrue(report["prior_owner_rootfs_p20_and_user_p21_not_reverified"])
                self.assertIn(f"BATCH_{batch_number}", report["probe_mode"])
                self.assertEqual(report["active_csc_recorded"], "PAP")
                self.assertEqual(report["result"], "NO_GO")
                for fact in ("raw_partition_bytes_read", "pit_requested",
                             "odin_session_started", "watch_write_performed",
                             "stock_recovery_proven", "bootloader_acceptance_proven",
                             "flash_allowed"):
                    self.assertIs(report[fact], False, fact)
                for secret in ("DO_NOT_LEAK", "UNRECOGNIZED_PRIVATE_VALUE",
                               "PARTUUID", "10.0.0.65"):
                    self.assertNotIn(secret, json.dumps(report))

    def test_partial_batch_and_wrong_target_cannot_claim_six_or_full_layout(self):
        group = PARTITION_SYSFS_REMAINING_BATCH_PROBES[1]
        values = {
            "partition_p8_uevent": record(8, "KERNEL"),
            "partition_p9_uevent": record(18, "RECOVERY"),
            "partition_p10_uevent": record(10, "USER").replace(
                "PARTNAME=USER" + chr(10), ""),
            "partition_p11_uevent": record(11, "ROOTFS") + record(12, "USER"),
        }
        errors = {"partition_p12_uevent": "SDB_TRANSPORT_UNREACHABLE",
                  "partition_p13_uevent": "Permission denied /private/serial"}
        with patch("watch3_r840x_partition_sysfs_readonly.collect",
                   return_value=(values, errors)):
            result = probe.inspect_remaining_batch("10.0.0.65",
                                                  Path("/unused"), 2)
        statuses = [x["status"] for x in result["probe_summary"]["probes"]]
        self.assertEqual(statuses, [
            "PARTNAME_FIELD_OBSERVED", "NO_MATCHING_SINGLE_SYSFS_RECORD",
            "UEVENT_READABLE_BUT_PARTNAME_ABSENT",
            "NO_MATCHING_SINGLE_SYSFS_RECORD", "SDB_TRANSPORT_UNREACHABLE",
            "OTHER_UNAVAILABLE",
        ])
        self.assertEqual(result["probe_summary"]["readable_uevent_files"], 2)
        self.assertEqual(result["probe_summary"]["partname_fields_observed"], 1)
        self.assertFalse(result["probe_summary"]["full_partition_layout_proven"])
        self.assertNotIn("private/serial", json.dumps(result))

    def test_invalid_batches_refused_before_any_network_or_parsing(self):
        for invalid in (0, 4, -1, "1", 1.0, None, True):
            with self.subTest(value=repr(invalid)), patch(
                "watch3_r840x_partition_sysfs_readonly.collect",
                side_effect=AssertionError("INVALID_BATCH_MUST_NOT_CONTACT_WATCH")
            ):
                with self.assertRaisesRegex(probe.PartitionLabelsError,
                                            "INVALID_REMAINING_FIXED_BATCH"):
                    probe.inspect_remaining_batch("10.0.0.65", Path("/unused"), invalid)

    def test_real_sdb_fake_peer_uses_only_six_allowed_exact_shell_commands(self):
        class FakePeer:
            def __init__(self, data):
                self.incoming = data
                self.sent = bytearray()
            def recv(self, length):
                part, self.incoming = self.incoming[:length], self.incoming[length:]
                return part
            def sendall(self, value):
                self.sent.extend(value)
            def settimeout(self, n):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False
        group = PARTITION_SYSFS_REMAINING_BATCH_PROBES[0]
        peers = []
        for index in range(2, 8):
            payload = record(index, "KERNEL", "SECRET_UUID_ABC").encode()
            peers.append(FakePeer(
                frame(b"CNXN", VERSION, 262144, b"device::" + bytes([0])) +
                frame(b"OKAY", 44, 2) +
                frame(b"WRTE", 44, 2, payload) +
                frame(b"CLSE", 44, 2)))
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=peers) as connect:
            observed, errors = collect("10.0.0.65", Path("/synthetic"),
                                       probes=group)
        self.assertFalse(errors)
        self.assertEqual(len(observed), 6)
        self.assertEqual(connect.call_count, 6)
        for key, peer in zip(group, peers):
            sent = []
            parser = FakePeer(bytes(peer.sent))
            while parser.incoming:
                sent.append(receive(parser))
            self.assertEqual([part[3] for part in sent if part[0] == b"OPEN"],
                             [(b"shell:" + group[key].encode() + bytes([0]))])
            self.assertNotIn(b"/dev/", peer.sent)
            self.assertNotIn(b"ODIN", peer.sent)
            self.assertNotIn(b"SEND", peer.sent)
        with self.assertRaisesRegex(SdbError, "predefined"):
            collect("10.0.0.65", Path("/synthetic"), probes=dict(group))

    def test_cli_batch_report_is_private_and_refuses_rerun_before_contact(self):
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "observed.json"
            group = PARTITION_SYSFS_REMAINING_BATCH_PROBES[2]
            values = {key: record(index, "RECOVERY")
                      for index, key in zip(range(14, 20), group)}
            with patch("watch3_r840x_partition_sysfs_readonly.collect",
                       return_value=(values, {})) as getter:
                self.assertEqual(probe.main([
                    "--watch-ip", "10.0.0.65", "--remaining-batch", "3",
                    "--report", str(report_path)
                ]), 0)
                self.assertEqual(getter.call_count, 1)
                self.assertIs(getter.call_args.kwargs["probes"], group)
            read = json.loads(report_path.read_text())
            self.assertEqual(read["remaining_batch_number"], 3)
            self.assertEqual(read["state"], "FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED")
            self.assertEqual(report_path.stat().st_mode & 0o077, 0)
            original = report_path.read_bytes()
            with patch("watch3_r840x_partition_sysfs_readonly.collect",
                       side_effect=AssertionError("EXISTING_REPORT_MUST_PREVENT_WATCH_READ")):
                self.assertEqual(probe.main([
                    "--watch-ip", "10.0.0.65", "--remaining-batch", "3",
                    "--report", str(report_path)
                ]), 1)
            self.assertEqual(report_path.read_bytes(), original)

    def test_batch_modes_cannot_be_mixed_with_existing_modes(self):
        with tempfile.TemporaryDirectory() as td:
            for extra in (["--fixed-paths"], ["--connection-only"],
                          ["--offline-sample", str(Path(td) / "sample.txt")]):
                args = (["--watch-ip", "10.0.0.65", "--remaining-batch", "1"] +
                        extra + ["--report", str(Path(td) / "not_created.json")])
                with patch("watch3_r840x_partition_sysfs_readonly.collect",
                           side_effect=AssertionError("CONFLICT_MUST_BE_REJECTED")):
                    if "--offline-sample" in extra:
                        # argparse itself refuses both mutually exclusive sources.
                        with self.assertRaises(SystemExit):
                            probe.main(args)
                    else:
                        self.assertEqual(probe.main(args), 1)
            self.assertFalse((Path(td) / "not_created.json").exists())



if __name__ == "__main__":
    unittest.main()
