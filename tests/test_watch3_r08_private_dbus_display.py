"""Private UNIX D-Bus compositor wakeup safety tests, entirely host-side.

Never connect to the host system bus or any physical watch. Original source
proves org.nemomobile.compositor.setUpdatesEnabled on object '/', and
LipstickCompositor constructor starts with m_updatesEnabled=True.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import watch3_r08_private_dbus_display as bus


class DisplayWakeTests(unittest.TestCase):
    def test_false_then_true_required_to_ensure_real_qquickwindow_shown(self):
        delivered=[]
        def respond(address,value):
            delivered.append(value)
            return True
        with patch.object(bus,"send_display_update",side_effect=respond):
            proof=bus.force_compositor_window_visible(
                "unix:path=/tmp/uglyos-TEST/uglyos-private-system.sock",
                max_wait=1.0)
        self.assertEqual(delivered,[False,True])
        self.assertTrue(proof["compositor_show_fullscreen_command_sequence_proven"])
        self.assertFalse(proof["physical_watch_contacted"])
        self.assertFalse(proof["host_system_dbus_contacted"])

    def test_missing_service_never_claimed_visible(self):
        with patch.object(bus,"send_display_update",return_value=False), \
             patch.object(bus.time,"monotonic",side_effect=[0,0,0.4,0.5,1.5,1.6]), \
             patch.object(bus.time,"sleep"):
            result=bus.force_compositor_window_visible(
                "unix:path=/tmp/uglyos-test/uglyos-private-system.sock",
                max_wait=1.0)
        self.assertFalse(result["compositor_show_fullscreen_command_sequence_proven"])
        self.assertFalse(result["system_bus_display_on_method_replied"])

    def test_invalid_remote_bus_address_cannot_be_called(self):
        for address in ("unix:path=/run/dbus/system_bus_socket",
                        "tcp:host=127.0.0.1,port=1234",
                        "unix:path=/home/runner/private.sock",
                        "unix:path=/tmp/uglyos-test/socket\nINJECTION"):
            with self.subTest(address=address):
                with self.assertRaisesRegex(bus.PrivateBusError,"UNSAFE_OR_NONLOCAL"):
                    bus.send_display_update(address,True)

    def test_dbus_send_target_is_exact_pinned_compositor_method(self):
        address="unix:path=/tmp/uglyos-offdevice/uglyos-private-system.sock"
        fake=subprocess.CompletedProcess([],0,stdout=b"method return",stderr=b"")
        with patch.object(bus.subprocess,"run",return_value=fake) as runner:
            self.assertTrue(bus.send_display_update(address,False))
        cmd=runner.call_args.args[0]
        self.assertEqual(cmd[0],"dbus-send")
        self.assertEqual(cmd[1],"--address="+address)
        self.assertEqual(cmd[4],"--reply-timeout=1200")
        self.assertEqual(cmd[5],"--dest=org.nemomobile.compositor")
        self.assertEqual(cmd[6],"/")
        self.assertEqual(cmd[7],"org.nemomobile.compositor.setUpdatesEnabled")
        self.assertEqual(cmd[8],"boolean:false")
        self.assertNotIn("DBUS_SYSTEM_BUS_ADDRESS",runner.call_args.kwargs["env"])
        self.assertNotIn("GITHUB_TOKEN",runner.call_args.kwargs["env"])

    def test_dbus_call_failure_is_not_treated_as_method_ack(self):
        fake=subprocess.CompletedProcess([],1,stdout=b"",stderr=b"service missing")
        with patch.object(bus.subprocess,"run",return_value=fake):
            self.assertFalse(bus.send_display_update(
                "unix:path=/tmp/uglyos-synthetic/uglyos-private-system.sock",True))

    def test_socket_path_must_be_in_temporary_uglyos_directory(self):
        with self.assertRaisesRegex(bus.PrivateBusError,"PRIVATE_BUS_MUST"):
            bus.bus_environment(Path("/var/run/uglyos-private-system.sock"))
        with self.assertRaisesRegex(bus.PrivateBusError,"INVALID_PRIVATE"):
            bus.bus_environment(Path("/tmp/uglyos-test/unrelated.sock"))
        self.assertEqual(bus.bus_environment(
            Path("/tmp/uglyos-test/uglyos-private-system.sock")),
            "unix:path=/tmp/uglyos-test/uglyos-private-system.sock")

    def test_private_bus_never_starts_on_nonisolated_network(self):
        import watch3_r08_qemu_vnc_capture as vnc
        with tempfile.TemporaryDirectory(prefix="uglyos-") as t:
            with patch.object(vnc,"require_network_isolation",
                              side_effect=vnc.RfbError("NETWORKED")):
                with self.assertRaisesRegex(vnc.RfbError,"NETWORKED"):
                    with bus.private_system_bus(Path(t)):
                        self.fail("not allowed inside networked container")

    def test_private_bus_timeout_bounds(self):
        with self.assertRaisesRegex(bus.PrivateBusError,"OUT_OF_BOUNDS"):
            bus.force_compositor_window_visible(
                "unix:path=/tmp/uglyos-test/uglyos-private-system.sock",
                max_wait=50.0)


if __name__=="__main__":
    unittest.main()
