"""Real host systemd show format and an INACTIVE disposable trap unit.

CI only, explicitly opted in on disposable Ubuntu runners. Creates an
exclusive fixture unit on that runner, never starts it, then removes it.
No SDB, Watch3 firmware, private LAN or watch connection exists in this test.
"""
from pathlib import Path
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_fota_owner_readonly as owner
from watch3_r08_android_sdb import FOTA_OWNER_REGISTRY_PROBES, FOTA_UNIT_METADATA_PROBES


@unittest.skipUnless(os.environ.get("WATCH3_REQUIRE_SYSTEMD") == "1",
                     "requires explicit disposable host systemd fixture opt-in")
class RealSystemdPropertiesTests(unittest.TestCase):
    def command(self, operation):
        command = (FOTA_UNIT_METADATA_PROBES | FOTA_OWNER_REGISTRY_PROBES)[operation]
        result = subprocess.run(shlex.split(command), text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_inactive_known_unit_reports_real_properties_without_starting(self):
        self.assertEqual(Path("/proc/1/comm").read_text().strip(), "systemd")
        for executable in ("sudo", "systemctl", "dbus-send"):
            self.assertIsNotNone(shutil.which(executable), executable)
        fragment = Path(owner.UNIT_FRAGMENT)
        self.assertFalse(fragment.exists(), "refuse to replace an existing unit")
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "unexpected-start"
            unit = ("[Unit]\nDescription=Disposable read-only FOTA metadata test\n"
                    "[Service]\nType=oneshot\nUser=root\nGroup=root\n"
                    "ExecStart=/usr/bin/touch " + str(marker) + "\n")
            create = subprocess.run(
                ["sudo", "-n", "python3", "-c",
                 "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644); "
                 "f=os.fdopen(fd,'w'); f.write(sys.stdin.read()); f.close()", str(fragment)],
                input=unit, text=True, capture_output=True, timeout=8)
            self.assertEqual(create.returncode, 0, create.stderr)
            try:
                bus = owner.parse_reply(self.command("fota_registry_id"), "id")
                manager = owner.parse_reply(self.command("fota_unit_manager_owner"), "owner")
                for _ in range(2):
                    observed = owner.configured_unit(self.command("fota_unit_properties"))
                    self.assertEqual(observed["unit_id"], owner.UNIT_ID)
                    self.assertEqual(observed["configured_executable"], "/usr/bin/touch")
                    self.assertEqual(observed["configured_user"], "root")
                    self.assertIsNone(observed["configured_bus_name"])
                    self.assertEqual(observed["active_state"], "inactive")
                    self.assertEqual(observed["sub_state"], "dead")
                    self.assertNotIn(str(marker), str(observed))
                    self.assertFalse(marker.exists(), "show must never execute the trap unit")
                self.assertEqual(owner.parse_reply(self.command("fota_registry_id"), "id"), bus)
                self.assertEqual(owner.parse_reply(self.command("fota_unit_manager_owner"), "owner"), manager)
                print("PASS: actual systemctl show parsed twice; trap unit stayed inactive, no start marker")
            finally:
                remove = subprocess.run(["sudo", "-n", "rm", "--", str(fragment)],
                                        text=True, capture_output=True, timeout=8)
                self.assertEqual(remove.returncode, 0, remove.stderr)


if __name__ == "__main__":
    unittest.main()
