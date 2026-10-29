"""Configured unit evidence, distinct from live ownership. NO WATCH."""
from pathlib import Path
import json
import io
from contextlib import redirect_stdout
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_fota_owner_readonly as owner
from watch3_r08_android_sdb import Connection, FOTA_UNIT_METADATA_PROBES, SdbError
from watch3_r08_fota_artifact_pull import ArtifactPullError
from test_watch3_r08_android_sdb import FakeSocket, decode_all, peer
from test_watch3_r08_fota_artifact_pull import elf32
from test_watch3_r840x_fota_owner_readonly import BUS_ID, EXE, reply


def properties(**changes):
    fields = {
        "Id": owner.UNIT_ID, "LoadState": "loaded", "ActiveState": "inactive",
        "SubState": "dead", "Type": "dbus", "BusName": "fota.consumer",
        "User": "root", "Group": "root", "FragmentPath": owner.UNIT_FRAGMENT,
        "ExecStart": "{ path=" + EXE + " ; argv[]=" + EXE +
                     " private-argument ; ignore_errors=no ; start_time=[n/a] ; "
                     "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
    }
    fields.update(changes)
    return "".join(name + "=" + value + "\n" for name, value in fields.items())


class UnitQueries:
    def __init__(self):
        self.calls = []
        self.unit_reads = 0
        self.manager_reads = 0
        self.bus_reads = 0
        self.raw = properties()
        self.change = None

    def __call__(self, ip, key, operation, **kwargs):
        self.calls.append(operation)
        if operation == "fota_registry_id":
            self.bus_reads += 1
            changed = ((self.change == "bus" and self.bus_reads > 1) or
                       (self.change == "late_bus" and self.bus_reads > 2))
            return reply("id", "b" * 32 if changed else BUS_ID)
        if operation == "fota_unit_manager_owner":
            self.manager_reads += 1
            if self.change == "no_manager":
                return "Error org.freedesktop.DBus.Error.NameHasNoOwner: private\n"
            changed = ((self.change == "manager" and self.manager_reads > 1) or
                       (self.change == "late_manager" and self.manager_reads > 2))
            return reply("owner", ":1.2" if changed else ":1.1")
        if operation == "fota_unit_properties":
            self.unit_reads += 1
            return properties(User="app_fw") if self.change == "unit" and self.unit_reads > 1 else self.raw
        raise AssertionError("Unexpected query: " + operation)


class ConfiguredUnitTests(unittest.TestCase):
    def run_capture(self, destination, queries, reader):
        with patch.object(owner, "query", queries), \
                patch.object(owner.socket, "create_connection", return_value=FakeSocket(b"")), \
                patch.object(owner, "_receive_arm_elf", reader):
            return owner.capture_configured_unit("127.0.0.1", Path("/unused"), destination)

    @staticmethod
    def copy_fixture(sock, key, out, path):
        if path != EXE.encode():
            raise AssertionError("Only the observed ExecStart path can be read")
        out.write(elf32())
        return {"bytes": len(elf32()), "sha256": "fixture-only", "elf_kind": "ARM_ELF32"}

    def test_exact_metadata_commands_use_shared_sdb_without_service_start(self):
        command = FOTA_UNIT_METADATA_PROBES["fota_unit_properties"]
        self.assertEqual(command.split()[-1], "fota-consumer.service")
        self.assertIn(" show --all ", command)
        self.assertIn("--no-pager", command)
        self.assertIn("--no-ask-password", command)
        for prohibited in (" start ", " restart ", " enable ", "reload", ";", "|", ">"):
            self.assertNotIn(prohibited, command)
        for operation, command in FOTA_UNIT_METADATA_PROBES.items():
            sock = FakeSocket(peer(properties()))
            channel = Connection(sock, Path("/unused"))
            channel.handshake()
            channel.shell(operation)
            self.assertEqual(decode_all(bytes(sock.sent))[1][3], ("shell:" + command + "\0").encode())

    def test_selected_properties_drop_arguments_pids_and_timestamps(self):
        observed = owner.configured_unit(properties())
        self.assertEqual(observed["configured_executable"], EXE)
        self.assertEqual(observed["configured_user"], "root")
        self.assertEqual(observed["active_state"], "inactive")
        for private in ("private-argument", "argv", "pid", "start_time", "stop_time"):
            self.assertNotIn(private, json.dumps(observed))
        empty = owner.configured_unit(properties(User="", Group="", BusName=""))
        self.assertIsNone(empty["configured_user"])
        self.assertIsNone(empty["configured_group"])
        self.assertIsNone(empty["configured_bus_name"])

    def test_missing_unit_wrong_identity_unknown_and_duplicate_fields_are_rejected(self):
        for raw, category in [
            (properties(LoadState="not-found"), "UNIT_NOT_LOADED_OR_UNAVAILABLE"),
            (properties(Id="other.service"), "UNIT_PROPERTIES_UNRECOGNIZED"),
            (properties(FragmentPath="/etc/systemd/system/other.service"), "UNIT_FRAGMENT_DIFFERS"),
            (properties() + "ExecStart=private\n", "UNIT_PROPERTIES_UNRECOGNIZED"),
            (properties() + "Environment=private\n", "UNIT_PROPERTIES_UNRECOGNIZED"),
            (properties().replace("User=root\n", ""), "UNIT_PROPERTIES_UNRECOGNIZED"),
            ("sh: systemctl: not found\n", "UNIT_PROPERTIES_TOOL_UNAVAILABLE"),
            ("Access denied: private\n", "UNIT_PROPERTIES_ACCESS_DENIED"),
            (None, "UNIT_PROPERTIES_UNRECOGNIZED"),
            ("x" * 8193, "UNIT_PROPERTIES_UNRECOGNIZED"),
        ]:
            with self.subTest(category=category):
                with self.assertRaisesRegex(owner.OwnerError, category):
                    owner.configured_unit(raw)

    def test_unsafe_execstart_and_multiple_commands_cannot_select_files(self):
        for path in ("/dev/mmcblk0p14", "/proc/1/mem", "/home/owner/key",
                     "/usr/bin/../secret", "/usr/bin/x;id", "/usr/bin/x$(id)"):
            with self.subTest(path=path), self.assertRaises(owner.OwnerError):
                owner.configured_unit(properties(ExecStart="{ path=" + path + " ; argv[]=ignored }"))
        for command in ("", EXE, "{ path=" + EXE + " ; argv[]=one } { path=" + EXE + " ; argv[]=two }"):
            with self.assertRaisesRegex(owner.OwnerError, "UNIT_EXECUTABLE_NOT_SINGLE_SIMPLE_PATH"):
                owner.configured_unit(properties(ExecStart=command))

    def test_success_copies_configured_elf_but_never_claims_live_owner_or_root(self):
        q = UnitQueries()
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "evidence"
            result = self.run_capture(dest, q, self.copy_fixture)
            self.assertEqual(result["state"], "CONFIGURED_FOTA_UNIT_BINARY_COPIED_READONLY")
            self.assertTrue(result["configured_fields_stable"])
            self.assertTrue(result["binary_copied"])
            self.assertEqual((dest / owner.UNIT_BINARY).read_bytes(), elf32())
            self.assertEqual(result["configured_unit"]["configured_user"], "root")
            self.assertIsNone(result["owner_uid"])
            self.assertIsNone(result["observed_executable"])
            self.assertFalse(result["owner_snapshot_stable"])
            for field in ("root_obtained", "service_activation_requested", "fota_method_called",
                          "firmware_written", "flash_allowed", "stock_recovery_proven", "custom_boot_proven"):
                self.assertFalse(result[field], field)
            saved = (dest / owner.UNIT_REPORT).read_text()
            for private in (BUS_ID, ":1.1", "private-argument", "argv", "start_time"):
                self.assertNotIn(private, saved)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
            for path in dest.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("fota_registry_owner", q.calls)
            self.assertNotIn("process_executable", q.calls)
            self.assertEqual(q.unit_reads, 2)

    def test_missing_manager_never_queries_or_starts_unit(self):
        q = UnitQueries()
        q.change = "no_manager"
        with tempfile.TemporaryDirectory() as tmp, patch.object(owner, "_receive_arm_elf") as reader:
            result = self.run_capture(Path(tmp) / "evidence", q, reader)
            self.assertEqual(result["state"], "NO_CURRENT_SYSTEMD_MANAGER")
            self.assertNotIn("fota_unit_properties", q.calls)
            reader.assert_not_called()

    def test_manager_or_bus_restart_before_copy_withholds_identity_and_copy(self):
        for changed in ("bus", "manager"):
            q = UnitQueries()
            q.change = changed
            with tempfile.TemporaryDirectory() as tmp, patch.object(owner, "_receive_arm_elf") as reader:
                result = self.run_capture(Path(tmp) / "evidence", q, reader)
                self.assertEqual(result["state"], "UNIT_MANAGER_CHANGED_DURING_OBSERVATION")
                self.assertIsNone(result["configured_unit"])
                reader.assert_not_called()

    def test_changed_unit_during_copy_discards_temporary_binary(self):
        q = UnitQueries()
        q.change = "unit"
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "evidence"
            result = self.run_capture(dest, q, self.copy_fixture)
            self.assertEqual(result["state"], "UNIT_FIELDS_CHANGED_DURING_COPY")
            self.assertFalse(result["binary_copied"])
            self.assertIsNone(result["configured_unit"])
            self.assertEqual([p.name for p in dest.iterdir()], [owner.UNIT_REPORT])

    def test_manager_restart_after_copy_also_discards_temporary_binary(self):
        for changed in ("late_bus", "late_manager"):
            q = UnitQueries()
            q.change = changed
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "evidence"
                result = self.run_capture(dest, q, self.copy_fixture)
                self.assertEqual(result["state"], "UNIT_MANAGER_CHANGED_DURING_OBSERVATION")
                self.assertFalse(result["binary_copied"])
                self.assertIsNone(result["configured_unit"])
                self.assertEqual([p.name for p in dest.iterdir()], [owner.UNIT_REPORT])

    def test_denied_or_non_elf_copy_keeps_only_configured_metadata_and_failure(self):
        def denied(*args):
            raise ArtifactPullError("REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE")
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "evidence"
            result = self.run_capture(dest, UnitQueries(), denied)
            self.assertEqual(result["state"], "CONFIGURED_UNIT_ARTIFACT_READ_REJECTED")
            self.assertEqual(result["configured_unit"]["configured_executable"], EXE)
            self.assertFalse(result["configured_fields_stable"])
            self.assertEqual([p.name for p in dest.iterdir()], [owner.UNIT_REPORT])

    def test_output_is_exclusive_and_invalid_ip_cannot_connect(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(owner, "query") as query:
            dest = Path(tmp) / "exists"
            dest.mkdir()
            (dest / "keep.txt").write_text("keep")
            with self.assertRaises(FileExistsError):
                owner.capture_configured_unit("127.0.0.1", Path("/unused"), dest)
            with self.assertRaises(SdbError):
                owner.capture_configured_unit("8.8.8.8", Path("/unused"), Path(tmp) / "new")
            query.assert_not_called()
            self.assertEqual((dest / "keep.txt").read_text(), "keep")

    def test_cli_configured_mode_uses_a_separate_output_and_never_runs_owner_probe(self):
        with patch.object(owner.Path, "home", return_value=Path("/phone")), \
                patch.object(owner, "capture_configured_unit", return_value={
                    "state": "FIXTURE_ONLY", "binary_copied": False}) as configured, \
                patch.object(owner, "capture") as live, redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(owner.main(["--watch-ip", "127.0.0.1", "--copy-configured-unit"]), 0)
            configured.assert_called_once_with(
                "127.0.0.1", Path("/phone/.config/galaxy3/watch3-sdbkey"),
                Path("/phone/watch3-r840x-fota-unit-evidence"))
            live.assert_not_called()
            self.assertIn("UNIT_REPORT: /phone/watch3-r840x-fota-unit-evidence/fota-unit-report.json",
                          stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
