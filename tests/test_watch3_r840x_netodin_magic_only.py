"""Prove the R840X live probe sends only the ODIN magic (not a command)."""
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r840x_netodin_magic_only import (
    perform_magic_once, main, MAGIC_OUT, PORT,
)


def localhost_session(peer_reply: bytes):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    result = {}
    def runner():
        result["report"] = perform_magic_once(server, 5)
    thread = threading.Thread(target=runner)
    thread.start()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
        peer.settimeout(2)
        request = peer.recv(1024)
        assert request == MAGIC_OUT, "Unexpected outgoing payload: " + repr(request)
        peer.sendall(peer_reply)
        # The listener must not emit any further packets or commands.
        after = peer.recv(1024)
        assert after == b"", "Unsafe Odin command or payload sent: " + repr(after)
    thread.join(timeout=2)
    server.close()
    assert not thread.is_alive()
    return result["report"]


class MagicOnlyTests(unittest.TestCase):
    def test_matching_loke_is_unverified_device_identity(self):
        report = localhost_session(b"LOKE")
        self.assertTrue(report["received_loke"])
        self.assertEqual(report["state"], "ODIN_LOKE_MAGIC_VERIFIED_UNAUTHENTICATED_PEER")
        self.assertEqual(report["host_port"], PORT)
        for key in ("watch_identity_verified", "odin_session_started", "pit_requested",
                    "custom_boot_verified", "stock_recovery_verified",
                    "firmware_written", "flash_allowed"):
            self.assertIs(report[key], False)
        self.assertNotIn("127.0.0.1", str(report))

    def test_wrong_magic_stays_no_go(self):
        report = localhost_session(b"NOPE")
        self.assertEqual(report["state"], "INVALID_OR_INCOMPLETE_MAGIC")
        self.assertFalse(report["received_loke"])

    def test_partial_magic_stays_no_go(self):
        report = localhost_session(b"LO")
        self.assertEqual(report["state"], "INVALID_OR_INCOMPLETE_MAGIC")
        self.assertFalse(report["firmware_written"])

    def test_no_network_by_default(self):
        with patch("watch3_r840x_netodin_magic_only.run_live") as live:
            for args in ([], ["--live-magic-only"], ["--watch-ap-confirmed"]):
                with self.subTest(args=args), patch("sys.stderr"):
                    with self.assertRaises(SystemExit):
                        main(args)
            live.assert_not_called()

    def test_invalid_time_never_binds(self):
        with patch("watch3_r840x_netodin_magic_only.run_live") as live:
            with patch("sys.stderr"), self.assertRaises(SystemExit):
                main(["--live-magic-only", "--watch-ap-confirmed",
                      "--listen-seconds", "181"])
            live.assert_not_called()

    def test_no_forbidden_packet_construction(self):
        source = (Path(__file__).resolve().parents[1] / "tools" /
                  "watch3_r840x_netodin_magic_only.py").read_text()
        self.assertIn('MAGIC_OUT = b"ODIN"', source)
        self.assertIn('MAGIC_IN = b"LOKE"', source)
        self.assertIn('peer.sendall(MAGIC_OUT)', source)
        for forbidden in ("struct.pack", "subprocess", "os.system", "EVIOCGRAB",
                          "0x65, 0x01", "0x66, 0x00", "0x67, 0x01",
                          "socket.create_connection"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
