import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import watch3_r840x_kernel_gate_readonly as gate
from watch3_r08_android_sdb import ALLOWED_PROBES, KERNEL_GATE_PROBES


class KernelGateParserTests(unittest.TestCase):
    def test_allowlist_is_exactly_the_four_fixed_probes(self):
        self.assertEqual(KERNEL_GATE_PROBES, {
            "kernel_machine": "uname -m",
            "binder_node": "ls /dev/binder",
            "binderfs_control_node": "ls /dev/binderfs/binder-control",
            "bpf_unprivileged_disabled":
                "cat /proc/sys/kernel/unprivileged_bpf_disabled",
        })
        for operation, command in KERNEL_GATE_PROBES.items():
            self.assertEqual(ALLOWED_PROBES[operation], command)
        self.assertEqual(gate.GATE_ALLOWED_OPS, frozenset(KERNEL_GATE_PROBES))

    def test_machine_classes(self):
        self.assertEqual(gate.parse_kernel_machine("armv7l\n")["machine_class"],
                         "ARMV7L_32BIT")
        self.assertEqual(gate.parse_kernel_machine("aarch64\n")["machine_class"],
                         "AARCH64_64BIT")
        self.assertEqual(gate.parse_kernel_machine("riscv64\n")["machine_class"],
                         "OTHER_MACHINE_CLASS")

    def test_machine_rejects_multiline_and_raw_is_not_retained(self):
        with self.assertRaisesRegex(gate.KernelGateError,
                                    "KERNEL_MACHINE_OUTPUT_INVALID"):
            gate.parse_kernel_machine("armv7l\nSECRET-ROW\n")
        result = gate.parse_kernel_machine("armv7l\n")
        self.assertNotIn("armv7l", json.dumps(result))

    def test_node_presence_classes(self):
        self.assertEqual(gate.parse_node_presence(
            "/dev/binder\n", "/dev/binder")["presence"], "PRESENT")
        self.assertEqual(gate.parse_node_presence(
            "ls: cannot access /dev/binder: No such file or directory\n",
            "/dev/binder")["presence"], "ABSENT")
        self.assertEqual(gate.parse_node_presence(
            "ls: cannot access /dev/binder: Permission denied\n",
            "/dev/binder")["presence"], "ACCESS_DENIED")
        self.assertEqual(gate.parse_node_presence(
            "unexpected listing SECRET\n", "/dev/binder")["presence"],
            "UNRECOGNIZED")

    def test_bpf_classes(self):
        self.assertEqual(gate.parse_bpf_disabled("0\n")["bpf_class"],
                         "UNPRIVILEGED_BPF_NOT_DISABLED")
        self.assertEqual(gate.parse_bpf_disabled("2\n")["bpf_class"],
                         "UNPRIVILEGED_BPF_DISABLED")
        self.assertEqual(gate.parse_bpf_disabled(
            "cat: /proc/sys/kernel/unprivileged_bpf_disabled: "
            "No such file or directory\n")["bpf_class"], "SETTING_ABSENT")
        with self.assertRaisesRegex(gate.KernelGateError,
                                    "KERNEL_BPF_OUTPUT_INVALID"):
            gate.parse_bpf_disabled("9\n")


class KernelGateCollectorTests(unittest.TestCase):
    SAMPLES = {
        "kernel_machine": "armv7l\n",
        "binder_node": "ls: cannot access /dev/binder: No such file or directory\n",
        "binderfs_control_node":
            "ls: cannot access /dev/binderfs/binder-control: No such file or directory\n",
        "bpf_unprivileged_disabled": "2\n",
    }

    def test_collector_queries_exactly_the_four_ops(self):
        observed = []

        def fake_query(ip, key, operation):
            observed.append(operation)
            return self.SAMPLES[operation]

        with patch.object(gate, "kernel_gate_query", side_effect=fake_query):
            result = gate.collect_kernel_gate("10.115.12.131", Path("/unused"))
        self.assertEqual(observed, list(gate.GATE_OPS_IN_ORDER))
        self.assertEqual(result["kernel_machine_class"], "ARMV7L_32BIT")
        self.assertEqual(result["binder_gate"], "BINDER_NODE_ABSENT_GATE_CLOSED")
        self.assertFalse(result["binder_kernel_patch_state_verified"])
        self.assertFalse(result["exploit_attempted"])
        self.assertFalse(result["device_node_opened"])
        self.assertFalse(result["watch_write_performed"])
        self.assertFalse(result["root_proven"])
        self.assertNotIn("armv7l", json.dumps(result["sources"]))

    def test_binder_present_opens_gate_but_proves_nothing(self):
        samples = dict(self.SAMPLES)
        samples["binder_node"] = "/dev/binder\n"
        with patch.object(gate, "kernel_gate_query",
                          side_effect=lambda ip, key, op: samples[op]):
            result = gate.collect_kernel_gate("10.115.12.131", Path("/unused"))
        self.assertEqual(result["binder_gate"], "BINDER_NODE_PRESENT_GATE_OPEN")
        self.assertFalse(result["binder_kernel_patch_state_verified"])
        self.assertFalse(result["root_proven"])

    def test_connection_failure_keeps_gate_undetermined(self):
        with patch.object(gate, "kernel_gate_query", side_effect=
                          gate.KernelGateError("KERNEL_GATE_SDB_CONNECTION_FAILED")):
            result = gate.collect_kernel_gate("10.115.12.131", Path("/unused"))
        self.assertEqual(result["binder_gate"], "UNDETERMINED")
        self.assertEqual(result["kernel_machine_class"], "UNDETERMINED")
        self.assertFalse(result["watch_write_performed"])

    def test_query_rejects_unlisted_operation(self):
        with self.assertRaisesRegex(gate.KernelGateError,
                                    "KERNEL_GATE_OPERATION_NOT_ALLOWLISTED"):
            gate.kernel_gate_query("10.115.12.131", Path("/unused"),
                                   "arbitrary_shell")

    def test_report_never_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "gate.json"
            gate.save_kernel_gate_report(path, {"state": "X"})
            with self.assertRaises(FileExistsError):
                gate.save_kernel_gate_report(path, {"state": "Y"})
            self.assertEqual(json.loads(path.read_text())["state"], "X")


if __name__ == "__main__":
    unittest.main()
