"""Only in-memory fake Samsung SDB peers. No physical watch or OTA actions."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_fota_services import (
    FOTA_PATH_PROBES, FOTA_FILE_PATHS, summarize_fota_path,
)
from watch3_r08_android_sdb import VERSION, collect, frame, receive


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, n):
        data, self.incoming = self.incoming[:n], self.incoming[n:]
        return data

    def sendall(self, value):
        self.sent.extend(value)

    def settimeout(self, _):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def peer(value):
    return (frame(b"CNXN", VERSION, 262144, b"device::\x00")
            + frame(b"OKAY", 33, 2)
            + frame(b"WRTE", 33, 2, value.encode())
            + frame(b"CLSE", 33, 2))


def outgoing(sock):
    fake = FakeSocket(bytes(sock.sent))
    operations = []
    while fake.incoming:
        kind, _, _, body = receive(fake)
        if kind == b"OPEN":
            operations.append(body)
    return operations


class FotaServiceEvidenceTests(unittest.TestCase):
    def sample(self):
        return {
            "fota_service_path": "-rwxr-xr-x 1 root app 44080 Jan 1 00:00 /usr/apps/com.samsung.fota-consumer/bin/fota-service\n",
            "update_client_path": "drwxr-xr-x 4 root root 4096 Jan 1 00:00 /usr/apps/com.samsung.tizen.update-client\n",
            "oma_dm_socket_path": "srw-rw-rw- 1 fota fota 0 Jan 1 00:00 /tmp/agent_fw_event_omadm\n",
            "service_process_snapshot": "PID USER VSZ STAT COMMAND\n121 service_fw 12000 S /usr/bin/sapd --private-identifier=SECRET\n",
        }

    def test_fixed_probe_commands_only(self):
        self.assertEqual(len(FOTA_PATH_PROBES), 4)
        for query in FOTA_PATH_PROBES.values():
            for forbidden in (";", "`", "$(", "dd ", "flash", "install",
                              "rm ", "reboot", "|", ">", "dbus-send"):
                self.assertNotIn(forbidden, query)

    def test_positive_is_not_root_or_vulnerability_claim(self):
        r = summarize_fota_path(self.sample(), {})
        self.assertEqual(r["status"], "FOTA_COMPONENT_CANDIDATE_OBSERVED")
        self.assertEqual(r["reference_paths"]["fota_service_path"],
                         "PRESENT_AT_REFERENCE_PATH")
        self.assertEqual(r["process_names"]["sapd"], "NAME_SEEN_IN_PS")
        self.assertFalse(r["fota_vulnerability_proven"])
        self.assertFalse(r["root_obtained"])
        self.assertFalse(r["custom_boot_verified"])

    def test_single_missing_reference_path_does_not_rule_out_services(self):
        outputs = self.sample()
        outputs.pop("fota_service_path")
        r = summarize_fota_path(
            outputs, {"fota_service_path": "TARGET_PATH_NOT_FOUND"})
        self.assertEqual(r["reference_paths"]["fota_service_path"],
                         "ABSENT_AT_REFERENCE_PATH")
        self.assertEqual(r["status"], "FOTA_COMPONENT_CANDIDATE_OBSERVED")

    def test_all_absent_is_inconclusive_not_negative_fota_proof(self):
        r = summarize_fota_path({}, {
            key: "TARGET_PATH_NOT_FOUND" for key in FOTA_FILE_PATHS
        })
        self.assertEqual(r["status"], "FOTA_SERVICE_EVIDENCE_INCONCLUSIVE")
        self.assertFalse(r["fota_vulnerability_proven"])

    def test_process_error_does_not_leak_user_data(self):
        observations = self.sample()
        observations["service_process_snapshot"] += (
            "121 owner 5000 S /bin/sh PRIVATE-EMAIL@example.com\n")
        text = json.dumps(summarize_fota_path(observations, {}))
        self.assertNotIn("PRIVATE-EMAIL", text)
        self.assertNotIn("SECRET", text)
        self.assertNotIn("121", text)

    def test_malformed_reference_path_not_accepted(self):
        data = self.sample()
        data["fota_service_path"] = "ls: secret fota-service missing\n"
        r = summarize_fota_path(data, {})
        self.assertEqual(r["reference_paths"]["fota_service_path"], "UNAVAILABLE")

    def test_integrates_fixed_authenticated_sdb_operations(self):
        data = self.sample()
        sockets = [FakeSocket(peer(data[key])) for key in FOTA_PATH_PROBES]
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=sockets) as con:
            values, errors = collect("10.0.0.65", Path("/unused"),
                                      probes=FOTA_PATH_PROBES)
        self.assertFalse(errors)
        self.assertEqual(con.call_count, len(FOTA_PATH_PROBES))
        for index, key in enumerate(FOTA_PATH_PROBES):
            self.assertEqual(outgoing(sockets[index]),
                             [b"shell:" + FOTA_PATH_PROBES[key].encode() + b"\x00"])
        self.assertEqual(summarize_fota_path(values, errors)["status"],
                         "FOTA_COMPONENT_CANDIDATE_OBSERVED")

    def test_exact_missing_target_is_classified_without_raw_output(self):
        outputs = self.sample()
        outputs["fota_service_path"] = (
            "ls: cannot access '/usr/apps/com.samsung.fota-consumer/bin/fota-service': "
            "No such file or directory\n")
        sockets = [FakeSocket(peer(outputs[key])) for key in FOTA_PATH_PROBES]
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=sockets):
            values, errors = collect("10.0.0.65", Path("/unused"),
                                      probes=FOTA_PATH_PROBES)
        self.assertEqual(errors["fota_service_path"], "TARGET_PATH_NOT_FOUND")
        result = json.dumps(summarize_fota_path(values, errors))
        self.assertNotIn("10.0.0.65", result)


if __name__ == "__main__":
    unittest.main()
