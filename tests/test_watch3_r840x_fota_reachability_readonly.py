import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import watch3_r840x_fota_reachability_readonly as reach
from watch3_r08_android_sdb import ALLOWED_PROBES, FOTA_REACHABILITY_PROBES


class ReachabilityParserTests(unittest.TestCase):
    def test_allowlist_is_exactly_the_eight_fixed_probes(self):
        self.assertEqual(FOTA_REACHABILITY_PROBES, {
            "shell_uid": "id -u",
            "fota_parent_dir_metadata": "ls -ldn /opt/usr/data/fota",
            "fota_save_dir_metadata": "ls -ldn /opt/usr/data/fota/save",
            "fota_save_dir_listing": "ls /opt/usr/data/fota/save",
            "recovery_dir_metadata": "ls -ldn /opt/data/recovery",
            "delta_path_node": "ls /opt/data/recovery/DELTA.PATH",
            "vconf_ui_state": "vconftool get db/fotaconsumer/ui_state",
            "vconf_consumer_state": "vconftool get db/fotaconsumer/state",
        })
        for operation, command in FOTA_REACHABILITY_PROBES.items():
            self.assertEqual(ALLOWED_PROBES[operation], command)
        self.assertEqual(reach.REACH_ALLOWED_OPS,
                         frozenset(FOTA_REACHABILITY_PROBES))
        for command in FOTA_REACHABILITY_PROBES.values():
            self.assertNotIn("vconftool set", command)
            self.assertNotIn("LaunchFota", command)
            self.assertNotIn("touch", command)
            self.assertNotIn("rm ", command)

    def test_shell_uid_classes(self):
        self.assertEqual(reach.parse_shell_uid("5001\n")["uid_class"],
                         "SHELL_UID_5001")
        self.assertEqual(reach.parse_shell_uid("0\n")["uid_class"], "OTHER_UID")
        with self.assertRaisesRegex(reach.ReachabilityError,
                                    "SHELL_UID_OUTPUT_INVALID"):
            reach.parse_shell_uid("not-a-uid\n")

    def test_dir_metadata_other_class_no_access(self):
        result = reach.parse_dir_metadata(
            "drwxr-x--- 2 1000 2000 4096 Nov 20 12:00 "
            "/opt/usr/data/fota/save\n", reach.SAVE_DIR)
        self.assertEqual(result["presence"], "PRESENT")
        self.assertEqual(result["owner_relation"], "OWNER_OTHER")
        self.assertEqual(result["group_relation"], "GROUP_OTHER")
        self.assertEqual(result["shell_access_class"], "NO_ACCESS")
        self.assertNotIn("1000", json.dumps(result))
        self.assertNotIn("4096", json.dumps(result))

    def test_dir_metadata_owner_is_shell(self):
        result = reach.parse_dir_metadata(
            "drwx------ 2 5001 2000 4096 Nov 20 12:00 "
            "/opt/usr/data/fota/save\n", reach.SAVE_DIR)
        self.assertEqual(result["owner_relation"], "OWNER_IS_SHELL")
        self.assertEqual(result["shell_access_class"], "READ_WRITE_TRAVERSE")

    def test_dir_metadata_group_is_shell_gid(self):
        result = reach.parse_dir_metadata(
            "drwxrws--- 2 1000 100 4096 Nov 20 12:00 "
            "/opt/data/recovery\n", reach.RECOVERY_DIR)
        self.assertEqual(result["group_relation"], "GROUP_IS_SHELL_GID")
        self.assertEqual(result["shell_access_class"], "READ_WRITE_TRAVERSE")

    def test_dir_metadata_absent_denied_symlink_and_invalid(self):
        self.assertEqual(reach.parse_dir_metadata(
            "ls: cannot access /opt/usr/data/fota/save: "
            "No such file or directory\n", reach.SAVE_DIR)["presence"], "ABSENT")
        self.assertEqual(reach.parse_dir_metadata(
            "ls: cannot access /opt/usr/data/fota/save: "
            "Permission denied\n", reach.SAVE_DIR)["presence"], "ACCESS_DENIED")
        self.assertEqual(reach.parse_dir_metadata(
            "lrwxrwxrwx 1 0 0 12 Nov 20 12:00 "
            "/opt/usr/data/fota/save\n", reach.SAVE_DIR)["presence"],
            "SYMLINK_UNRESOLVED")
        with self.assertRaisesRegex(reach.ReachabilityError,
                                    "DIR_METADATA_OUTPUT_INVALID"):
            reach.parse_dir_metadata("total 0\n", reach.SAVE_DIR)
        with self.assertRaisesRegex(reach.ReachabilityError,
                                    "DIR_METADATA_OUTPUT_INVALID"):
            reach.parse_dir_metadata(
                "drwxr-x--- 2 1000 2000 4096 Nov 20 12:00 /other/path\n",
                reach.SAVE_DIR)

    def test_dir_listing_classes_and_names_discarded(self):
        self.assertEqual(reach.parse_dir_listing("")["entry_count_class"],
                         "ZERO")
        result = reach.parse_dir_listing("SECRET-ARCHIVE-NAME.ua\n")
        self.assertEqual(result["listing"], "LISTABLE")
        self.assertEqual(result["entry_count_class"], "ONE_TO_FIVE")
        self.assertNotIn("SECRET-ARCHIVE-NAME", json.dumps(result))
        many = "".join(f"entry{i}\n" for i in range(7))
        self.assertEqual(reach.parse_dir_listing(many)["entry_count_class"],
                         "SIX_OR_MORE")
        self.assertEqual(reach.parse_dir_listing(
            "ls: cannot open directory /opt/usr/data/fota/save: "
            "Permission denied\n")["listing"], "ACCESS_DENIED")
        self.assertEqual(reach.parse_dir_listing(
            "ls: cannot access /opt/usr/data/fota/save: "
            "No such file or directory\n")["listing"], "ABSENT")

    def test_delta_node_presence(self):
        self.assertEqual(reach.parse_delta_node(
            "/opt/data/recovery/DELTA.PATH\n")["presence"], "PRESENT")
        self.assertEqual(reach.parse_delta_node(
            "ls: cannot access /opt/data/recovery/DELTA.PATH: "
            "No such file or directory\n")["presence"], "ABSENT")
        self.assertEqual(reach.parse_delta_node(
            "ls: cannot access /opt/data/recovery/DELTA.PATH: "
            "Permission denied\n")["presence"], "ACCESS_DENIED")

    def test_vconf_state_classes(self):
        self.assertEqual(reach.parse_vconf_state(
            "db/fotaconsumer/ui_state, value = 60 (int)\n")["state_class"],
            "STATE_60")
        self.assertEqual(reach.parse_vconf_state(
            "db/fotaconsumer/state, value = 65 (int)\n")["state_class"],
            "STATE_65")
        self.assertEqual(reach.parse_vconf_state(
            "db/fotaconsumer/ui_state, value = 10 (int)\n")["state_class"],
            "STATE_OTHER_INT")
        self.assertEqual(reach.parse_vconf_state(
            "vconftool: no such key\n")["state_class"], "KEY_ABSENT")
        self.assertEqual(reach.parse_vconf_state(
            "sh: vconftool: command not found\n")["state_class"],
            "TOOL_UNAVAILABLE")
        self.assertEqual(reach.parse_vconf_state(
            "vconftool: Permission denied\n")["state_class"], "ACCESS_DENIED")
        self.assertEqual(reach.parse_vconf_state(
            "opaque response\n")["state_class"], "UNRECOGNIZED")


class ReachabilityCollectorTests(unittest.TestCase):
    SAMPLES = {
        "shell_uid": "5001\n",
        "fota_parent_dir_metadata":
            "drwxr-xr-x 3 1000 2000 4096 Nov 20 12:00 /opt/usr/data/fota\n",
        "fota_save_dir_metadata":
            "drwxr-x--- 2 1000 2000 4096 Nov 20 12:00 /opt/usr/data/fota/save\n",
        "fota_save_dir_listing":
            "ls: cannot open directory /opt/usr/data/fota/save: "
            "Permission denied\n",
        "recovery_dir_metadata":
            "drwxrwxr-x 2 1000 100 4096 Nov 20 12:00 /opt/data/recovery\n",
        "delta_path_node":
            "ls: cannot access /opt/data/recovery/DELTA.PATH: "
            "No such file or directory\n",
        "vconf_ui_state": "db/fotaconsumer/ui_state, value = 10 (int)\n",
        "vconf_consumer_state": "vconftool: no such key\n",
    }

    def test_collector_queries_exactly_the_eight_ops(self):
        observed = []

        def fake_query(ip, key, operation):
            observed.append(operation)
            return self.SAMPLES[operation]

        with patch.object(reach, "reachability_query",
                          side_effect=fake_query):
            result = reach.collect_reachability("10.115.12.131",
                                                Path("/unused"))
        self.assertEqual(observed, list(reach.REACH_OPS_IN_ORDER))
        self.assertEqual(result["shell_uid_class"], "SHELL_UID_5001")
        self.assertEqual(result["archive_dir_shell_access_class"], "NO_ACCESS")
        self.assertEqual(result["archive_dir_listing_class"], "ACCESS_DENIED")
        self.assertTrue(result["vconf_get_answered"])
        self.assertFalse(result["write_attempted"])
        self.assertFalse(result["vconf_write_performed"])
        self.assertFalse(result["fota_method_called"])
        self.assertFalse(result["watch_write_performed"])
        self.assertFalse(result["root_proven"])
        self.assertNotIn("1000", json.dumps(result["sources"]))

    def test_connection_failure_keeps_summaries_undetermined(self):
        with patch.object(reach, "reachability_query", side_effect=
                          reach.ReachabilityError(
                              "REACHABILITY_SDB_CONNECTION_FAILED")):
            result = reach.collect_reachability("10.115.12.131",
                                                Path("/unused"))
        self.assertEqual(result["archive_dir_shell_access_class"],
                         "UNDETERMINED")
        self.assertEqual(result["archive_dir_listing_class"], "UNDETERMINED")
        self.assertFalse(result["vconf_get_answered"])
        self.assertFalse(result["watch_write_performed"])

    def test_query_rejects_unlisted_operation(self):
        with self.assertRaisesRegex(reach.ReachabilityError,
                                    "REACHABILITY_OPERATION_NOT_ALLOWLISTED"):
            reach.reachability_query("10.115.12.131", Path("/unused"),
                                     "arbitrary_shell")

    def test_report_never_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "reach.json"
            reach.save_reachability_report(path, {"state": "X"})
            with self.assertRaises(FileExistsError):
                reach.save_reachability_report(path, {"state": "Y"})
            self.assertEqual(json.loads(path.read_text())["state"], "X")


if __name__ == "__main__":
    unittest.main()
