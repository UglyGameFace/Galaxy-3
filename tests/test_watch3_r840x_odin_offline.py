"""Synthetic offline Odin risk classifier regressions. NEVER opens watch/network."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import audit_watch3_r840x_odin_offline as audit


class OdinOfflineAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual_magic = audit.MAGIC_SCRIPT.read_text(encoding="utf-8")

    def test_source_pins_and_static_magic_contract_pass(self):
        result = audit.audit_magic_source(self.actual_magic)
        self.assertEqual(result["exact_magic_out"], "ODIN")
        self.assertEqual(result["exact_magic_in"], "LOKE")
        self.assertEqual(result["outbound_sendall_sites"], 1)
        self.assertEqual(result["command_frame_send_sites"], 0)
        self.assertEqual(result["expected_response_bytes"], 4)
        self.assertEqual(result["magic_only_static_regression_check"],
                         "PASSED_LIMITED_AST_CHECK")
        self.assertEqual(audit.RAGNAROEK_REF,
                         "f9164d2c227369ba711d89f12eef99186df61387")
        self.assertFalse(audit.LIVE_WATCH_COMMANDS_AUTHORIZED)

    def test_command_classification_all_extended_operations_blocked(self):
        report = audit.build_report()
        self.assertEqual(report["status"], "OFFLINE_ODIN_RISK_CLASSIFICATION_ONLY")
        self.assertFalse(report["new_live_command_authorized"])
        self.assertFalse(report["network_packets_sent"])
        self.assertFalse(report["watch_contacted"])
        self.assertFalse(report["socket_opened"])
        self.assertFalse(report["pit_requested"])
        self.assertFalse(report["stock_restore_proven"])
        self.assertFalse(report["unsigned_boot_proven"])
        self.assertEqual(report["hardware_result"]["all_1024_byte_commands"],
                         "NOT_SENT_TO_WATCH")
        commands = report["commands"]
        self.assertTrue(len(commands) >= 10)
        self.assertTrue(all(not item["watch_allowed_now"] for item in commands))
        self.assertEqual(commands[0]["expected_wire_bytes"], 4)
        self.assertTrue(all(item["expected_wire_bytes"] == 1024
                            for item in commands[1:]))
        ids = {(item["primary_opcode"], item["argument"]) for item in commands}
        for pair in (
            ("0x64", "0x00"), ("0x64", "0x05"),
            ("0x64", "0x07"), ("0x65", "0x00"),
            ("0x65", "0x01"), ("0x66", "0x00"),
            ("0x66", "0x01"),
        ):
            self.assertIn(pair, ids)
        destructive = next(x for x in commands if x["name"] == "Erase user data")
        self.assertEqual(destructive["intent"], "destructive_factory_reset")
        self.assertEqual(destructive["hardware_evidence"], "NOT_TESTED_ON_R840X")
        pit_read = next(x for x in commands if x["name"] == "Request partition information")
        self.assertIn("session_state_required", pit_read["intent"])
        self.assertFalse(pit_read["watch_allowed_now"])

    def test_regression_guard_rejects_1024_byte_or_extra_send(self):
        source = self.actual_magic
        mutations = (
            source.replace("peer.sendall(MAGIC_OUT)",
                           "peer.sendall(MAGIC_OUT + (b'\\x00' * 1020))", 1),
            source.replace("peer.sendall(MAGIC_OUT)",
                           "peer.sendall(MAGIC_OUT)\n            peer.sendall(MAGIC_OUT)", 1),
            source.replace("peer.sendall(MAGIC_OUT)", "peer.send(MAGIC_OUT)", 1),
            source.replace('MAGIC_OUT = b"ODIN"', 'MAGIC_OUT = b"LOKE"', 1),
            source.replace('MAGIC_IN = b"LOKE"', 'MAGIC_IN = b"ODIN"', 1),
            source.replace("PORT = 13579", "PORT = 13580", 1),
            source.replace("peer.recv(4 - len(answer))", "peer.recv(1024)", 1),
            source + "\nimport subprocess\n",
            source + "\nexec('pass')\n",
        )
        for changed in mutations:
            with self.subTest(tail=changed[-36:]):
                self.assertNotEqual(changed, source)
                with self.assertRaises(audit.OfflineAuditError):
                    audit.audit_magic_source(changed)

    def test_report_exclusive_private_and_does_not_execute_target_script(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            with patch.object(sys, "argv", ["offline", "--report", str(out)]), patch(
                "socket.socket", side_effect=AssertionError("network forbidden")), patch(
                "subprocess.Popen", side_effect=AssertionError("subprocess forbidden")):
                self.assertEqual(audit.main(), 0)
                self.assertEqual(audit.main(), 1)
            data = json.loads(out.read_text())
            self.assertFalse(data["new_live_command_authorized"])
            self.assertEqual(out.stat().st_mode & 0o077, 0)
            self.assertTrue(out.stat().st_size > 1000)

    def test_no_arbitrary_script_path_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            test_file = root / "offline_magic.py"
            test_file.write_text(self.actual_magic)
            link = root / "link.py"
            link.symlink_to(test_file)
            with self.assertRaisesRegex(audit.OfflineAuditError, "MAGIC_SCRIPT_UNAVAILABLE_OR_SYMLINK"):
                audit.build_report(link)
            with self.assertRaisesRegex(audit.OfflineAuditError, "MAGIC_SCRIPT_OVERSIZED"):
                huge = root / "too-large.py"
                huge.write_text("x" * 66000)
                audit.build_report(huge)


if __name__ == "__main__":
    unittest.main()
