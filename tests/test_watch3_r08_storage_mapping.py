"""Offline-only regression tests: Watch3 storage topology is private and read-only."""
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_storage_mapping import summarize_storage, _mounts, _slaves
from watch3_r08_live_boot_probe import PROBES, STORAGE_PROBES
from watch3_r08_android_sdb import Connection, SdbError, collect, frame


class SocketFixture:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, count):
        value, self.incoming = self.incoming[:count], self.incoming[count:]
        return value

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def peer(text):
    return (
        frame(b"CNXN", 0x00100000, 256 * 1024, b"device::\x00")
        + frame(b"OKAY", 9, 2)
        + frame(b"WRTE", 9, 2, text.encode("utf-8"))
        + frame(b"CLSE", 0, 2)
    )


class Watch3StorageTests(unittest.TestCase):
    def setUp(self):
        self.samples = {
            "mounts": (
                "/dev/dm-0 / ext4 ro,relatime 0 0\n"
                "/dev/mmcblk0p21 /opt/usr ext4 rw,nosuid 0 0\n"
                "/dev/block/by-uuid/PRIVATE-UUID /private ext4 rw 0 0\n"
                "192.168.1.100:/SECRET /data nfs rw 0 0\n"
                "tmpfs /dev tmpfs rw 0 0\n"),
            "dm0_slaves": "mmcblk0p20\n",
            "dm0_name": "system",
            "p20_uevent": ("MAJOR=259\nMINOR=12\nDEVNAME=mmcblk0p20\n"
                           "PARTN=20\nPARTNAME=rootfs\n"
                           "PARTUUID=SECRET-PART-UUID\n"),
            "p21_uevent": ("DEVNAME=mmcblk0p21\nPARTNAME=userdata\n"
                           "PARTUUID=ANOTHER-SECRET\n"),
        }

    def test_known_dm0_backing_is_grounded_in_sysfs(self):
        report = summarize_storage(self.samples, {})
        self.assertEqual(report["status"], "READ_ONLY_TIZEN_STORAGE_TOPOLOGY")
        self.assertEqual(report["dm0_slaves"], ["mmcblk0p20"])
        self.assertTrue(report["dm0_backing_verified"])
        self.assertTrue(report["dm0_backing_mmcp20_observed"])
        self.assertEqual(report["selected_partition_role_labels"], {
            "mmcblk0p20": "rootfs", "mmcblk0p21": "userdata"
        })
        self.assertFalse(report["flashing_authorized"])
        self.assertFalse(report["boot_partition_identified"])

    def test_no_sysfs_slaves_does_not_infer_mapping_from_equal_sizes(self):
        data = dict(self.samples)
        data.pop("dm0_slaves")
        report = summarize_storage(data, {"dm0_slaves": "Unavailable"})
        self.assertFalse(report["dm0_backing_verified"])
        self.assertFalse(report["dm0_backing_mmcp20_observed"])
        self.assertEqual(report["dm0_slaves"], [])
        self.assertEqual(report["unavailable_readonly_properties"],
                         {"dm0_slaves": "Unavailable"})

    def test_privacy_filters_raw_mounts_ids_uuid_credentials(self):
        report = summarize_storage(self.samples, {})
        payload = json.dumps(report)
        for forbidden in ("SECRET", "PARTUUID=", "PRIVATE-UUID",
                          "192.168.1.100", "by-uuid", "/private"):
            self.assertNotIn(forbidden, payload)
        self.assertIn('"source": "dm-0"', payload)
        self.assertIn('"source": "mmcblk0p21"', payload)

    def test_unknown_partition_label_is_not_leaked(self):
        data = dict(self.samples)
        data["p20_uevent"] = "PARTNAME=SerialSecretNumber-ABC123\n"
        self.assertEqual(summarize_storage(data, {})[
            "selected_partition_role_labels"]["mmcblk0p20"], "unclassified")

    def test_devmapping_filter_rejects_extra_strings(self):
        self.assertEqual(_slaves("mmcblk0p20\nSECRET-GUID\n"), ["mmcblk0p20"])
        self.assertEqual(_slaves("mmcblk0p99\nrandom\n"), [])
        self.assertEqual(_mounts("secret /boot ext4 rw 0 0"), [])

    def test_storage_commands_are_five_fixed_pseudofile_reads_only(self):
        self.assertEqual(len(STORAGE_PROBES), 5)
        self.assertNotIn("mounts", PROBES,
                         "Existing seven-probe boot report must remain unchanged")
        for command in STORAGE_PROBES.values():
            self.assertTrue(
                command.startswith(("cat /proc/", "cat /sys/", "ls /sys/")))
            for forbidden in ("&&", ";", "|", ">", "<", "/dev/mmc",
                              "sudo", "dmsetup", "reboot", "setprop"):
                self.assertNotIn(forbidden, command)

    def test_only_fixed_storage_operation_name_can_be_sent(self):
        sock = SocketFixture(b"")
        connection = Connection(sock, Path("/unused"))
        for forbidden in ("cat /sys/block/dm-0/slaves",
                          "ls /dev/mmcblk0", "reboot"):
            with self.assertRaisesRegex(SdbError, "allowlist"):
                connection.shell(forbidden)
        self.assertEqual(sock.sent, b"")

    def test_collect_storage_alternative_runs_exactly_same_whitelisted_operation(self):
        replies = [SocketFixture(peer(self.samples[x])) for x in STORAGE_PROBES]
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   side_effect=replies) as connect:
            values, problems = collect("10.54.86.131", Path("/unused"),
                                       probes=STORAGE_PROBES)
        self.assertEqual(connect.call_count, len(STORAGE_PROBES))
        self.assertEqual(problems, {})
        self.assertEqual(set(values), set(STORAGE_PROBES))
        report = summarize_storage(values, problems)
        self.assertTrue(report["dm0_backing_verified"])

    def test_reject_injected_probe_map_even_if_it_looks_like_a_dict(self):
        with self.assertRaisesRegex(SdbError, "predefined"):
            collect("10.54.86.131", Path("/unused"),
                    probes={"custom": "cat /dev/mmcblk0p20"})


if __name__ == "__main__":
    unittest.main()
