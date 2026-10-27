"""Phone-only WLAN preflight and strictly gated magic listener tests (fake peers)."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_ap_network_preflight as pre
import watch3_r840x_netodin_magic_only as magic


class PreflightTests(unittest.TestCase):
    def test_phone_wlan_only_no_watch_network_connection(self):
        with patch.object(pre.socket, "if_nameindex", return_value=[
            (1, "lo"), (2, "rmnet_data0"), (3, "wlan0"), (4, "wlan1")]), patch.object(
                pre.socket, "socket") as sock, patch.object(pre, "read_ipv4_ioctl") as read:
            def values(_sock, name, op):
                if name == "wlan1":
                    raise OSError("not assigned")
                return "192.168.1.20" if op == pre.SIOCGIFADDR else "255.255.255.0"
            read.side_effect = values
            report = pre.preflight_report()
        self.assertEqual(report["status"], "WLAN_IPV4_OBSERVED")
        self.assertEqual(report["wlan_ipv4"], [{
            "interface": "wlan0", "ipv4": "192.168.1.20",
            "subnet": "192.168.1.0/24", "rfc1918_address": True,
        }])
        self.assertFalse(report["wifi_ssid_verified"])
        self.assertFalse(report["watch_download_ap_verified"])
        self.assertFalse(report["network_packets_sent"])
        self.assertFalse(report["watch_contacted"])
        self.assertFalse(report["watch_write_performed"])
        sock.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertNotIn("network", str(sock.method_calls).lower())

    def test_bind_requires_private_ipv4_actually_on_phone_wlan(self):
        observed = [{
            "interface": "wlan0", "ipv4": "192.168.1.20",
            "subnet": "192.168.1.0/24", "rfc1918_address": True,
        }]
        with patch.object(pre, "observe_wlan_ipv4", return_value=observed):
            subnet = pre.subnet_for_bind_ip("192.168.1.20")
            self.assertEqual(str(subnet), "192.168.1.0/24")
            for rejected in ("0.0.0.0", "127.0.0.1", "8.8.8.8",
                             "192.168.1.21", "not-an-ip", "::"):
                with self.subTest(ip=rejected), self.assertRaises(ValueError):
                    pre.subnet_for_bind_ip(rejected)

    def test_android_interface_inaccessible_is_explicitly_inconclusive(self):
        with patch.object(pre.socket, "if_nameindex", side_effect=OSError("Android denied")):
            report = pre.preflight_report()
        self.assertEqual(report["status"], "WLAN_IPV4_UNAVAILABLE_OR_ANDROID_RESTRICTED")
        self.assertEqual(report["wlan_ipv4"], [])
        self.assertFalse(report["watch_download_ap_verified"])

    def test_preflight_local_private_report_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "phone-wlan.json"
            with patch.object(pre, "observe_wlan_ipv4", return_value=[]):
                self.assertEqual(pre.main(["--report", str(report)]), 0)
                self.assertEqual(report.stat().st_mode & 0o077, 0)
                old = report.read_bytes()
                self.assertEqual(pre.main(["--report", str(report)]), 1)
                self.assertEqual(report.read_bytes(), old)

    def test_wlan_allowlist_rejects_non_wifi_interface_labels(self):
        with self.assertRaisesRegex(ValueError, "NOT_ALLOWLISTED_WLAN_INTERFACE"):
            pre.read_ipv4_ioctl(MagicMock(), "rmnet_data0", pre.SIOCGIFADDR)
        with self.assertRaisesRegex(ValueError, "NOT_ALLOWLISTED_WLAN_INTERFACE"):
            pre.read_ipv4_ioctl(MagicMock(), "wlan0/../../secret", pre.SIOCGIFADDR)

    def test_magic_cli_refuses_without_bind_ip_and_no_network_action(self):
        with patch.object(magic, "run_live") as run:
            for args in (
                ["--live-magic-only", "--watch-ap-confirmed"],
                ["--live-magic-only", "--bind-ip", "192.168.1.20"],
                ["--watch-ap-confirmed", "--bind-ip", "192.168.1.20"],
            ):
                with self.subTest(args=args), patch("sys.stderr"):
                    with self.assertRaises(SystemExit):
                        magic.main(args)
            run.assert_not_called()

    def test_run_live_uses_exact_local_wlan_ip_not_all_interfaces(self):
        mock_server = MagicMock()
        mock_server.__enter__.return_value = mock_server
        expected_subnet = ipaddress.IPv4Network("192.168.1.0/24")
        with patch.object(magic, "subnet_for_bind_ip", return_value=expected_subnet) as check, patch.object(
            magic.socket, "socket", return_value=mock_server) as creation, patch.object(
            magic, "perform_magic_once", return_value={"state": "NO_INBOUND_CONNECTION"}) as perform:
            result = magic.run_live(5, "192.168.1.20")
        self.assertEqual(result["state"], "NO_INBOUND_CONNECTION")
        check.assert_called_once_with("192.168.1.20")
        creation.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_server.bind.assert_called_once_with(("192.168.1.20", magic.PORT))
        perform.assert_called_once_with(mock_server, 5, allowed_subnet=expected_subnet)

    def test_wrong_subnet_peer_gets_zero_odins_and_is_closed(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        result = {}
        thread = threading.Thread(target=lambda: result.update(
            magic.perform_magic_once(listener, 5,
                                    allowed_subnet=ipaddress.IPv4Network("192.168.1.0/24"))))
        thread.start()
        with socket.create_connection(listener.getsockname(), timeout=2) as conn:
            conn.settimeout(2)
            self.assertEqual(conn.recv(1024), b"")
        thread.join(timeout=5)
        listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(result["state"], "PEER_OUTSIDE_CONFIRMED_LOCAL_WLAN_SUBNET")
        self.assertFalse(result["received_loke"])
        self.assertFalse(result["odin_session_started"])


    def test_manual_wifi_local_bind_checks_actual_local_assignment_without_packets(self):
        # Simulate Android 17 where WLAN interface enumeration returns [].
        probe = MagicMock()
        probe.__enter__.return_value = probe
        with patch.object(pre, "observe_wlan_ipv4", return_value=[]), patch.object(
            pre.socket, "socket", return_value=probe) as constructor:
            report = pre.preflight_report(
                manual_wifi_ip="192.168.1.23",
                manual_wifi_netmask="255.255.255.0",
                manual_wifi_settings_confirmed=True,
            )
        self.assertEqual(report["status"],
                         "MANUAL_WIFI_ADDRESS_LOCALLY_BINDABLE_NOT_SSID_VERIFIED")
        self.assertEqual(report["wlan_ipv4"][0]["ipv4"], "192.168.1.23")
        self.assertEqual(report["wlan_ipv4"][0]["subnet"], "192.168.1.0/24")
        self.assertEqual(report["wlan_ipv4"][0]["source"],
                         "ANDROID_WIFI_SETTINGS_USER_ENTERED")
        self.assertTrue(report["wlan_ipv4"][0]["local_bind_verified"])
        self.assertFalse(report["watch_download_ap_verified"])
        self.assertFalse(report["wifi_ssid_verified"])
        self.assertFalse(report["network_packets_sent"])
        self.assertFalse(report["watch_contacted"])
        self.assertFalse(report["tcp_listener_started"])
        constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind.assert_called_once_with(("192.168.1.23", 0))
        for method in ("listen", "accept", "connect", "send", "sendto", "sendall"):
            getattr(probe, method).assert_not_called()

    def test_manual_wifi_rejects_guesses_broad_ranges_and_missing_confirmation(self):
        with patch.object(pre.socket, "socket") as constructor:
            for ip, mask, confirmed, reason in (
                ("192.168.1.23", "255.255.255.0", False,
                 "ANDROID_WIFI_SETTINGS_CONFIRMATION_REQUIRED"),
                ("8.8.8.8", "255.255.255.0", True, "MANUAL_WIFI_IP_NOT_RFC1918"),
                ("0.0.0.0", "255.255.255.0", True, "MANUAL_WIFI_IP_NOT_RFC1918"),
                ("127.0.0.1", "255.255.255.0", True, "MANUAL_WIFI_IP_NOT_RFC1918"),
                ("192.168.1.0", "255.255.255.0", True, "MANUAL_WIFI_IP_NOT_HOST_ADDRESS"),
                ("192.168.1.255", "255.255.255.0", True,
                 "MANUAL_WIFI_IP_NOT_HOST_ADDRESS"),
                ("192.168.1.23", "255.255.0.0", True,
                 "MANUAL_WIFI_SUBNET_TOO_BROAD_OR_NARROW"),
                ("10.1.2.3", "255.0.0.0", True,
                 "MANUAL_WIFI_SUBNET_TOO_BROAD_OR_NARROW"),
                ("192.168.1.23", "255.0.255.0", True,
                 "MANUAL_WIFI_ADDRESS_OR_MASK_INVALID"),
                ("not-an-ip", "255.255.255.0", True,
                 "MANUAL_WIFI_ADDRESS_OR_MASK_INVALID"),
            ):
                with self.subTest(ip=ip, mask=mask, reason=reason), self.assertRaisesRegex(
                    ValueError, reason
                ):
                    pre.validate_manual_wifi_details(
                        ip, mask, settings_confirmed=confirmed)
            constructor.assert_not_called()

    def test_manual_wifi_cannot_pass_if_ip_is_not_assigned_on_phone(self):
        # Android local bind to an unassigned address must fail before any
        # TCP listen(), handshake or packet transmission.
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.bind.side_effect = OSError("Cannot assign requested address")
        with patch.object(pre.socket, "socket", return_value=mock_sock):
            with self.assertRaisesRegex(ValueError, "MANUAL_WIFI_IP_NOT_LOCALLY_BINDABLE"):
                pre.subnet_for_bind_ip(
                    "192.168.1.23", manual_wifi_netmask="255.255.255.0",
                    manual_wifi_settings_confirmed=True)
        mock_sock.listen.assert_not_called()
        mock_sock.connect.assert_not_called()
        mock_sock.sendall.assert_not_called()

    def test_manual_wifi_cli_requires_two_fields_and_confirmation(self):
        with patch.object(pre, "observe_wlan_ipv4", return_value=[]), patch.object(
            pre.socket, "socket") as constructor:
            for args in (
                ["--manual-wifi-ip", "192.168.1.23"],
                ["--manual-wifi-netmask", "255.255.255.0"],
                ["--manual-wifi-ip", "192.168.1.23",
                 "--manual-wifi-netmask", "255.255.255.0"],
            ):
                with self.subTest(args=args):
                    self.assertEqual(pre.main(args), 2)
            constructor.assert_not_called()
        with patch.object(pre, "observe_wlan_ipv4", return_value=[]), patch.object(
            pre.socket, "socket"):
            with tempfile.TemporaryDirectory() as td:
                dest = Path(td) / "manual.json"
                args = ["--manual-wifi-ip", "192.168.1.23",
                        "--manual-wifi-netmask", "24",
                        "--manual-wifi-settings-confirmed",
                        "--report", str(dest)]
                self.assertEqual(pre.main(args), 0)
                self.assertEqual(dest.stat().st_mode & 0o077, 0)
                self.assertTrue(json.loads(dest.read_text())["wlan_ipv4"][0]["local_bind_verified"])
                self.assertEqual(pre.main(args), 1)

    def test_magic_requires_manual_mask_and_settings_confirmation_together(self):
        with patch.object(magic, "run_live") as live:
            for flags in (
                ["--manual-wifi-netmask", "255.255.255.0"],
                ["--manual-wifi-settings-confirmed"],
            ):
                with self.subTest(flags=flags), patch("sys.stderr"):
                    with self.assertRaises(SystemExit):
                        magic.main(["--live-magic-only", "--watch-ap-confirmed",
                                    "--bind-ip", "192.168.1.23"] + flags)
            live.assert_not_called()

    def test_magic_manual_netmask_passes_only_to_explicit_fully_confirmed_path(self):
        listener = MagicMock()
        listener.__enter__.return_value = listener
        subnet = ipaddress.IPv4Network("192.168.1.0/24")
        with patch.object(magic, "subnet_for_bind_ip", return_value=subnet) as validate, patch.object(
            magic.socket, "socket", return_value=listener), patch.object(
            magic, "perform_magic_once",
            return_value={"state": "NO_INBOUND_CONNECTION"}):
            result = magic.run_live(
                5, "192.168.1.23",
                manual_wifi_netmask="255.255.255.0",
                manual_wifi_settings_confirmed=True)
        validate.assert_called_once_with(
            "192.168.1.23",
            manual_wifi_netmask="255.255.255.0",
            manual_wifi_settings_confirmed=True)
        self.assertEqual(result["state"], "NO_INBOUND_CONNECTION")
        listener.bind.assert_called_once_with(("192.168.1.23", magic.PORT))
        listener.listen.assert_called_once_with(1)

if __name__ == "__main__":
    unittest.main()
