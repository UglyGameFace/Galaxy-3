import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import watch3_r840x_sync_socket_reachability_readonly as sock
from watch3_r08_android_sdb import (
    ALLOWED_PROBES, SYNC_SOCKET_REACHABILITY_PROBES)


class SocketReachabilityParserTests(unittest.TestCase):
    def test_allowlist_is_exactly_the_five_fixed_probes(self):
        self.assertEqual(SYNC_SOCKET_REACHABILITY_PROBES, {
            "shell_uid": "id -u",
            "tmp_dir_metadata": "ls -ldn /tmp",
            "event_socket_metadata": "ls -ldn /tmp/agent_fw_event_omadm",
            "omadm_dir_metadata": "ls -ldn /opt/usr/data/fota/oma-dm",
            "omadm_marker_node":
                "ls /opt/usr/data/fota/oma-dm/.oma-dm-agent-enabled",
        })
        for operation, command in SYNC_SOCKET_REACHABILITY_PROBES.items():
            self.assertEqual(ALLOWED_PROBES[operation], command)
        self.assertEqual(sock.SOCKET_ALLOWED_OPS,
                         frozenset(SYNC_SOCKET_REACHABILITY_PROBES))
        for command in SYNC_SOCKET_REACHABILITY_PROBES.values():
            self.assertNotIn("connect", command)
            self.assertNotIn("send", command)
            self.assertNotIn("touch", command)
            self.assertNotIn("rm ", command)
            self.assertNotIn("vconftool set", command)
            self.assertNotIn("LaunchFota", command)

    def test_shell_uid_classes(self):
        self.assertEqual(sock.parse_shell_uid("5001\n")["uid_class"],
                         "SHELL_UID_5001")
        self.assertEqual(sock.parse_shell_uid("0\n")["uid_class"],
                         "OTHER_UID")
        with self.assertRaisesRegex(sock.SocketReachabilityError,
                                    "SHELL_UID_OUTPUT_INVALID"):
            sock.parse_shell_uid("not-a-uid\n")

    def test_socket_metadata_world_writable_socket(self):
        result = sock.parse_socket_metadata(
            "srwxrwxrwx 1 1000 2000 0 Nov 20 12:00 "
            "/tmp/agent_fw_event_omadm\n")
        self.assertEqual(result["presence"], "PRESENT")
        self.assertEqual(result["node_kind"], "SOCKET")
        self.assertEqual(result["owner_relation"], "OWNER_OTHER")
        self.assertEqual(result["group_relation"], "GROUP_OTHER")
        self.assertEqual(result["shell_access_class"],
                         "READ_WRITE_EXECUTE")
        self.assertNotIn("1000", json.dumps(result))

    def test_socket_metadata_owner_is_shell(self):
        result = sock.parse_socket_metadata(
            "srwx------ 1 5001 2000 0 Nov 20 12:00 "
            "/tmp/agent_fw_event_omadm\n")
        self.assertEqual(result["owner_relation"], "OWNER_IS_SHELL")
        self.assertEqual(result["shell_access_class"],
                         "READ_WRITE_EXECUTE")

    def test_socket_metadata_stale_regular_file_is_other_kind(self):
        result = sock.parse_socket_metadata(
            "-rw-r--r-- 1 1000 2000 12 Nov 20 12:00 "
            "/tmp/agent_fw_event_omadm\n")
        self.assertEqual(result["presence"], "PRESENT")
        self.assertEqual(result["node_kind"], "OTHER_KIND")
        self.assertEqual(result["shell_access_class"], "READ")

    def test_socket_metadata_absent_denied_symlink_and_invalid(self):
        self.assertEqual(sock.parse_socket_metadata(
            "ls: cannot access /tmp/agent_fw_event_omadm: "
            "No such file or directory\n")["presence"], "ABSENT")
        self.assertEqual(sock.parse_socket_metadata(
            "ls: cannot access /tmp/agent_fw_event_omadm: "
            "Permission denied\n")["presence"], "ACCESS_DENIED")
        self.assertEqual(sock.parse_socket_metadata(
            "lrwxrwxrwx 1 0 0 12 Nov 20 12:00 "
            "/tmp/agent_fw_event_omadm\n")["presence"],
            "SYMLINK_UNRESOLVED")
        with self.assertRaisesRegex(sock.SocketReachabilityError,
                                    "SOCKET_METADATA_OUTPUT_INVALID"):
            sock.parse_socket_metadata("total 0\n")
        with self.assertRaisesRegex(sock.SocketReachabilityError,
                                    "SOCKET_METADATA_OUTPUT_INVALID"):
            sock.parse_socket_metadata(
                "srwxrwxrwx 1 1000 2000 0 Nov 20 12:00 /tmp/other\n")

    def test_dir_metadata_tmp_traverse(self):
        result = sock.parse_dir_metadata(
            "drwxrwxrwt 2 0 0 4096 Nov 20 12:00 /tmp\n", sock.TMP_DIR)
        self.assertEqual(result["presence"], "PRESENT")
        self.assertEqual(result["shell_access_class"],
                         "READ_WRITE_TRAVERSE")

    def test_marker_node_presence(self):
        self.assertEqual(sock.parse_marker_node(
            "/opt/usr/data/fota/oma-dm/.oma-dm-agent-enabled\n"
            )["presence"], "PRESENT")
        self.assertEqual(sock.parse_marker_node(
            "ls: cannot access "
            "/opt/usr/data/fota/oma-dm/.oma-dm-agent-enabled: "
            "No such file or directory\n")["presence"], "ABSENT")
        self.assertEqual(sock.parse_marker_node(
            "ls: cannot access "
            "/opt/usr/data/fota/oma-dm/.oma-dm-agent-enabled: "
            "Permission denied\n")["presence"], "ACCESS_DENIED")


class SocketReachabilityCollectorTests(unittest.TestCase):
    SAMPLES = {
        "shell_uid": "5001\n",
        "tmp_dir_metadata":
            "drwxrwxrwt 2 0 0 4096 Nov 20 12:00 /tmp\n",
        "event_socket_metadata":
            "srwxrwxrwx 1 1000 2000 0 Nov 20 12:00 "
            "/tmp/agent_fw_event_omadm\n",
        "omadm_dir_metadata":
            "drwxr-x--- 2 1000 2000 4096 Nov 20 12:00 "
            "/opt/usr/data/fota/oma-dm\n",
        "omadm_marker_node":
            "ls: cannot access "
            "/opt/usr/data/fota/oma-dm/.oma-dm-agent-enabled: "
            "No such file or directory\n",
    }

    def test_collector_queries_exactly_the_five_ops(self):
        observed = []

        def fake_query(ip, key, operation):
            observed.append(operation)
            return self.SAMPLES[operation]

        with patch.object(sock, "socket_reachability_query",
                          side_effect=fake_query):
            result = sock.collect_socket_reachability(
                "10.115.12.131", Path("/unused"))
        self.assertEqual(observed, list(sock.SOCKET_OPS_IN_ORDER))
        self.assertEqual(result["shell_uid_class"], "SHELL_UID_5001")
        self.assertEqual(result["tmp_dir_shell_access_class"],
                         "READ_WRITE_TRAVERSE")
        self.assertEqual(result["event_socket_presence"], "PRESENT")
        self.assertEqual(result["event_socket_node_kind"], "SOCKET")
        self.assertEqual(result["event_socket_shell_access_class"],
                         "READ_WRITE_EXECUTE")
        self.assertEqual(result["omadm_marker_presence"], "ABSENT")
        self.assertFalse(result["socket_connect_attempted"])
        self.assertFalse(result["event_sent"])
        self.assertFalse(result["write_attempted"])
        self.assertFalse(result["watch_write_performed"])
        self.assertFalse(result["root_proven"])
        self.assertNotIn("1000", json.dumps(result["sources"]))

    def test_connection_failure_keeps_summaries_undetermined(self):
        with patch.object(sock, "socket_reachability_query",
                          side_effect=sock.SocketReachabilityError(
                              "SYNC_SOCKET_SDB_CONNECTION_FAILED")):
            result = sock.collect_socket_reachability(
                "10.115.12.131", Path("/unused"))
        self.assertEqual(result["event_socket_presence"], "UNDETERMINED")
        self.assertEqual(result["event_socket_shell_access_class"],
                         "UNDETERMINED")
        self.assertFalse(result["watch_write_performed"])

    def test_query_rejects_unlisted_operation(self):
        with self.assertRaisesRegex(sock.SocketReachabilityError,
                                    "SYNC_SOCKET_OPERATION_NOT_ALLOWLISTED"):
            sock.socket_reachability_query(
                "10.115.12.131", Path("/unused"), "arbitrary_shell")

    def test_report_never_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sock.json"
            sock.save_socket_report(path, {"state": "X"})
            with self.assertRaises(FileExistsError):
                sock.save_socket_report(path, {"state": "Y"})
            self.assertEqual(json.loads(path.read_text())["state"], "X")


if __name__ == "__main__":
    unittest.main()
