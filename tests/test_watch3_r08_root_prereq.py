"""Synthetic SDB evidence only. No root attempt, payload or live watch."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_root_prereq import ROOT_PATH_PROBES, summarize_root_path
from watch3_r08_android_sdb import (
    Connection, PORT, VERSION, collect, frame, receive, _root_path_output_error,
)


class FakeSocket:
    def __init__(self, data):
        self.data = data
        self.sent = bytearray()

    def recv(self, count):
        chunk, self.data = self.data[:count], self.data[count:]
        return chunk

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, _timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def peer(value):
    return (frame(b"CNXN", VERSION, 262144, b"device::\x00")
            + frame(b"OKAY", 9, 2)
            + frame(b"WRTE", 9, 2, value.encode())
            + frame(b"CLSE", 9, 2))


def sent_commands(sock):
    fake = FakeSocket(bytes(sock.sent))
    commands = []
    while fake.data:
        kind, _, _, body = receive(fake)
        if kind == b"OPEN":
            commands.append(body)
    return commands


class RootPrerequisiteTests(unittest.TestCase):
    def sample(self):
        return {
            "dotnet_caps": "/usr/bin/dotnet cap_sys_admin,cap_setgid=ep\n",
            "launcher_caps": "/usr/sbin/sdbd-tarlauncher cap_setuid,cap_setgid=ep\n",
            "dotnet_runtime": "Microsoft.NETCore.App 3.1.32 [/usr/share/dotnet/shared/Microsoft.NETCore.App]\n",
            "tar_features": "Usage: tar\n --to-command=COMMAND\n",
        }

    def test_positive_is_only_static_prerequisite_evidence(self):
        result = summarize_root_path(self.sample(), {})
        self.assertEqual(result["status"], "STATIC_PREREQUISITES_OBSERVED")
        self.assertFalse(result["root_obtained"])
        self.assertFalse(result["unsigned_kernel_boot_proven"])
        self.assertFalse(result["stock_recovery_proven"])

    def test_absent_capability_has_actual_negative_evidence(self):
        values = self.sample()
        values["launcher_caps"] = "/usr/sbin/sdbd-tarlauncher\n"
        result = summarize_root_path(values, {})
        self.assertEqual(result["status"], "STATIC_PATH_NOT_SUPPORTED")
        self.assertEqual(result["checks"]["archive_launcher_capabilities"],
                         "REQUIRED_CAPABILITIES_ABSENT")

    def test_unsupported_dotnet_runtime_is_negative(self):
        values = self.sample()
        values["dotnet_runtime"] = "Microsoft.NETCore.App 2.1.9 [/usr/lib/dotnet]\n"
        self.assertEqual(summarize_root_path(values, {})["status"],
                         "STATIC_PATH_NOT_SUPPORTED")

    def test_missing_or_malformed_read_is_not_disproof(self):
        values = self.sample()
        values.pop("launcher_caps")
        self.assertEqual(summarize_root_path(values, {})["status"], "INCONCLUSIVE")
        values = self.sample()
        values["launcher_caps"] = "permission denied\n"
        self.assertEqual(summarize_root_path(values, {})["status"], "INCONCLUSIVE")
        values = self.sample()
        values["dotnet_caps"] = "/tmp/dotnet cap_setgid,cap_sys_admin=ep\n"
        self.assertEqual(summarize_root_path(values, {})["status"], "INCONCLUSIVE")

    def test_all_unavailable_explains_transport_not_false_missing_capabilities(self):
        result = summarize_root_path({}, {
            key: "SDB_SHELL_CLOSED_OR_REFUSED" for key in ROOT_PATH_PROBES
        })
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(set(result["acquisition"].values()),
                         {"SDB_SHELL_CLOSED_OR_REFUSED"})
        self.assertTrue(all(v == "UNAVAILABLE" for v in result["checks"].values()))

    def test_parser_mismatch_is_not_confused_with_transport_failure(self):
        values = self.sample()
        values["dotnet_caps"] = "unexpected capability report"
        result = summarize_root_path(values, {})
        self.assertEqual(result["acquisition"]["dotnet_caps"], "OUTPUT_RECEIVED")
        self.assertEqual(result["checks"]["dotnet_capabilities"], "UNAVAILABLE")

    def test_no_raw_device_output_or_secrets(self):
        values = self.sample()
        values["dotnet_caps"] += "PRIVATE_SERIAL=SECRET\n"
        report = json.dumps(summarize_root_path(values, {}))
        self.assertNotIn("SECRET", report)
        self.assertNotIn("/usr/share/dotnet/shared", report)
        self.assertNotIn("cap_sys_admin=", report)

    def test_tiny_shell_errors_are_classified_without_false_tar_help_hits(self):
        self.assertEqual(_root_path_output_error("sh: getcap: not found\n"),
                         "WATCH_REPORTED_COMMAND_OR_PATH_MISSING")
        self.assertEqual(_root_path_output_error("getcap: Permission denied"),
                         "WATCH_REPORTED_ACCESS_DENIED")
        self.assertEqual(_root_path_output_error("   "), "EMPTY_SHELL_OUTPUT")
        self.assertIsNone(_root_path_output_error(
            "tar options\n --to-command=COMMAND\n"
            "some archives have files not found\n additional help"))

    def test_fixed_allowlist_has_no_install_flash_or_injection(self):
        self.assertEqual(len(ROOT_PATH_PROBES), 4)
        for query in ROOT_PATH_PROBES.values():
            for forbidden in (";", "`", "$(", "dd ", "flash", "install",
                              "rm ", "reboot", "|", ">"):
                self.assertNotIn(forbidden, query)

    def test_sdb_closed_shell_exposes_category_not_device_exception(self):
        peers = [FakeSocket(frame(b"CNXN", VERSION, 262144, b"device::\x00")
                            + frame(b"CLSE", 0, 2)) for _ in range(8)]
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=peers):
            observed, missing = collect("10.54.86.131", Path("/unused"),
                                        probes=ROOT_PATH_PROBES)
        self.assertFalse(observed)
        self.assertEqual(set(missing.values()),
                         {"SDB_SHELL_CLOSED_OR_REFUSED"})
        serialized = json.dumps(summarize_root_path(observed, missing))
        self.assertNotIn("10.54.86.131", serialized)

    def test_short_missing_tool_reply_preserves_exact_reason_category(self):
        outputs = ["sh: getcap: not found\n"] * 4
        peers = [FakeSocket(peer(output)) for output in outputs]
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=peers):
            observed, missing = collect("10.54.86.131", Path("/unused"),
                                        probes=ROOT_PATH_PROBES)
        self.assertFalse(observed)
        self.assertEqual(set(missing.values()),
                         {"WATCH_REPORTED_COMMAND_OR_PATH_MISSING"})

    def test_sdb_collect_only_issues_fixed_read_only_queries(self):
        outputs = self.sample()
        peers = [FakeSocket(peer(outputs[key])) for key in ROOT_PATH_PROBES]
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=peers) as connected:
            observed, missing = collect("10.54.86.131", Path("/unused"),
                                        probes=ROOT_PATH_PROBES)
        self.assertFalse(missing)
        self.assertEqual(connected.call_count, 4)
        self.assertEqual(summarize_root_path(observed, {})["status"],
                         "STATIC_PREREQUISITES_OBSERVED")
        for index, key in enumerate(ROOT_PATH_PROBES):
            self.assertEqual(sent_commands(peers[index]),
                             [b"shell:" + ROOT_PATH_PROBES[key].encode() + b"\x00"])


if __name__ == "__main__":
    unittest.main()
