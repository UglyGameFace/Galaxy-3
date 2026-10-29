"""Complete native SDB dependency capture; no watch shell or helper tools.

No physical watch, vendor-code execution, service activation or network access.
"""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import analyze_watch3_r08_fota_elf as elf
import watch3_r08_fota_artifact_pull as pull
from test_watch3_r08_fota_artifact_pull import sdb_peer, requests
from test_watch3_r08_fota_consumer_inventory import peer as directory_peer, dent, done
from watch3_r08_fota_consumer_inventory import DirectoryDecoder, InventoryError
from test_watch3_r08_fota_elf_offline import fake_elf

LIBRARY = "/usr/lib/libsync-agent.so.0"


def listing_peer(names=("libsync-agent.so.0",), *, size=123, count=0):
    payload = b"".join(dent(name, size=size) for name in names)
    payload += b"".join(dent("unreported-library-" + str(i)) for i in range(count)) + done()
    return directory_peer([payload[:3], payload[3:15], payload[15:]])


class SyncAgentCaptureTests(unittest.TestCase):
    def test_real_cross_compiled_arm_library_has_verifiable_soname_and_install_definition(self):
        compiler, linker = shutil.which("clang"), shutil.which("ld.lld")
        if not compiler or not linker:
            if os.environ.get("WATCH3_REQUIRE_ARM_ELF") == "1":
                self.fail("CI requires clang and ld.lld for the real ARM ELF fixture")
            self.skipTest("local ARM cross compiler unavailable; required in CI")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, binary = root / "fixture.c", root / "libsync-agent.so.0"
            source.write_text("int sync_agent_dm_fota_install(int value) { return value + 1; }\n")
            subprocess.run([compiler, "--target=armv7-linux-gnueabi", "-mthumb", "-shared", "-fPIC",
                            "-nostdlib", "-fuse-ld=lld", "-Wl,-soname,libsync-agent.so.0",
                            "-o", str(binary), str(source)], check=True, capture_output=True, timeout=20)
            facts = elf.parse_elf32(binary.read_bytes())
            self.assertEqual(facts["architecture"], "ARM_ELF32_LITTLE_ENDIAN")
            self.assertEqual(facts["soname"], pull.SYNC_AGENT_SONAME)
            definition = next(x for x in facts["allowlisted_function_exports"]
                              if x["name"] == pull.SYNC_AGENT_INSTALL)
            self.assertTrue(definition["thumb"])
            self.assertGreater(definition["bytes"], 0)
            # readelf is an independent implementation; no generated code runs.
            symbols = subprocess.run(["readelf", "--dyn-syms", "--wide", str(binary)],
                                     check=True, capture_output=True, text=True, timeout=5).stdout
            line = next(l for l in symbols.splitlines() if pull.SYNC_AGENT_INSTALL in l)
            self.assertIn("FUNC", line)
            self.assertNotIn("UND", line)
            self.assertEqual(int(line.split()[1], 16), int(definition["address_hex"], 16))

    def context(self, root, sockets):
        stack = ExitStack()
        original = fake_elf(needed=pull.SYNC_AGENT_SONAME)
        source = root / "original-consumer.bin"
        source.write_bytes(original)
        stack.enter_context(patch.object(elf, "CONSUMER_BYTES", len(original)))
        stack.enter_context(patch.object(elf, "CONSUMER_SHA256", hashlib.sha256(original).hexdigest()))
        connect = stack.enter_context(patch.object(pull.socket, "create_connection", side_effect=sockets))
        self.addCleanup(stack.close)
        return source, connect

    @staticmethod
    def binary_peer(binary):
        packet = pull.SYNC_HDR.pack(b"DATA", len(binary)) + binary
        return sdb_peer([packet[:5], packet[5:40], packet[40:], pull.SYNC_HDR.pack(b"DONE", 0)])

    def test_full_capture_uses_observed_path_checks_export_and_packages_private_original(self):
        binary = fake_elf(soname=pull.SYNC_AGENT_SONAME, export=pull.SYNC_AGENT_INSTALL,
                          private_marker=b"PRIVATE-CREDENTIAL-EXAMPLE\0")
        sockets = [listing_peer(), self.binary_peer(binary), listing_peer()]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, connect = self.context(root, sockets)
            folder, archive = root / "evidence", root / "evidence.zip"
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), folder,
                                             consumer_input=source, archive=archive)
            self.assertEqual(result["state"], "SYNC_AGENT_LIBRARY_COPIED")
            self.assertEqual(result["schema"], "uglyos-r840x-sync-agent-dependency-v2")
            self.assertEqual(result["resolution_method"], "SDB_SYNC_LIST")
            self.assertTrue(result["binary_copied"])
            self.assertTrue(result["directory_entry_stable"])
            self.assertFalse(result["runtime_provider_observed"])
            self.assertEqual((folder / pull.SYNC_AGENT_BINARY).read_bytes(), binary)
            self.assertEqual(result["binary"]["sha256"], hashlib.sha256(binary).hexdigest())
            self.assertNotIn("PRIVATE-CREDENTIAL", json.dumps(result))
            self.assertNotIn("flash_allowed", result)
            self.assertEqual(connect.call_count, 3)
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            for p in [*folder.iterdir(), archive]:
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()), {pull.SYNC_AGENT_REPORT, pull.SYNC_AGENT_BINARY})
                self.assertEqual(bundle.read(pull.SYNC_AGENT_BINARY), binary)
                self.assertEqual(json.loads(bundle.read(pull.SYNC_AGENT_REPORT)), result)
        opens = [m[3] for sock in sockets for m in requests(bytes(sock.sent)) if m[0] == b"OPEN"]
        self.assertEqual(opens, [b"sync:\0"] * 3)
        self.assertNotIn(b"shell:", b"".join(s.sent for s in sockets))
        recv = [m[3] for m in requests(bytes(sockets[1].sent)) if m[0] == b"WRTE"]
        self.assertEqual(recv, [pull.SYNC_HDR.pack(b"RECV", len(LIBRARY)) + LIBRARY.encode()])
        self.assertNotIn(b"SEND", b"".join(s.sent for s in sockets))

    def test_native_listing_handles_large_library_directories_and_filters_private_names(self):
        sock = listing_peer(count=1500)
        with patch.object(pull.socket, "create_connection", return_value=sock):
            result = pull.sync_agent_listing("127.0.0.1", Path("/unused"), "sync_agent_usr_lib", 8)
        self.assertEqual(set(result["matching_sync_agent_libraries"]), {pull.SYNC_AGENT_SONAME})
        self.assertEqual(result["other_or_unreported_entries"], 1500)
        self.assertNotIn("unreported-library", json.dumps(result))
        sent = requests(bytes(sock.sent))
        self.assertEqual(next(x[3] for x in sent if x[0] == b"WRTE"),
                         pull.SYNC_HDR.pack(b"LIST", len(b"/usr/lib")) + b"/usr/lib")

    def test_directory_resolver_prefers_listed_soname_and_rejects_ambiguous_version_only_names(self):
        for names, accepted in [((pull.SYNC_AGENT_SONAME, "libsync-agent.so.0.1"), True),
                                (("libsync-agent.so.0.1", "libsync-agent.so.0.2"), False)]:
            with patch.object(pull.socket, "create_connection", return_value=listing_peer(names)):
                if accepted:
                    result = pull.resolve_sync_agent("127.0.0.1", Path("/unused"), 8, [])
                    self.assertEqual(result[0], LIBRARY.encode())
                else:
                    with self.assertRaisesRegex(pull.ArtifactPullError, "DEPENDENCY_DIRECTORY_ENTRY_AMBIGUOUS"):
                        pull.resolve_sync_agent("127.0.0.1", Path("/unused"), 8, [])

    def test_library_paths_cannot_select_devices_traversal_or_unrelated_objects(self):
        for path in ("/dev/mmcblk0", "/usr/lib/../lib/libsync-agent.so.0", "/tmp/libsync-agent.so.0",
                     "/usr/lib/libc.so.6", "/usr/lib/libsync-agent.so.01", "/usr/lib/libsync-agent.so.0;id",
                     "/usr/lib//libsync-agent.so.0", "/usr/lib/$(id)/libsync-agent.so.0"):
            with self.subTest(path=path), self.assertRaises(pull.ArtifactPullError):
                pull.sync_agent_library_path(path)
        self.assertEqual(pull.sync_agent_library_path("/lib/libsync-agent.so.0.1.0"),
                         b"/lib/libsync-agent.so.0.1.0")

    def test_bad_local_consumer_fails_before_network_and_still_packages_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(pull.socket, "create_connection") as connect:
            root = Path(tmp)
            source = root / "wrong-consumer.bin"
            source.write_bytes(b"not the original")
            for name, source_path, expected in [("missing", root / "absent", "LOCAL_ORIGINAL_CONSUMER_MISSING"),
                                                 ("wrong", source, "LOCAL_ORIGINAL_CONSUMER_PIN_MISMATCH")]:
                result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), root / name,
                                                consumer_input=source_path, archive=root / (name + ".zip"))
                self.assertEqual(result["state"], expected)
                self.assertFalse(result["binary_copied"])
                with zipfile.ZipFile(root / (name + ".zip")) as bundle:
                    self.assertEqual(bundle.namelist(), [pull.SYNC_AGENT_REPORT])
            connect.assert_not_called()

    def test_both_directories_without_candidate_preserve_report_and_never_request_recv(self):
        sockets = [listing_peer(()), listing_peer(())]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, connect = self.context(root, sockets)
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), root / "evidence", consumer_input=source)
            self.assertEqual(result["state"], "DEPENDENCY_NOT_OBSERVED_IN_LIBRARY_DIRECTORIES")
            self.assertEqual(connect.call_count, 2)
            self.assertEqual(len(result["resolution_attempts"]), 2)
            for sock in sockets:
                self.assertNotIn(b"RECV", sock.sent)
                self.assertNotIn(b"shell:", sock.sent)

    def test_base_lib_is_used_when_usr_lib_has_no_matching_entry_without_helper_commands(self):
        binary = fake_elf(soname=pull.SYNC_AGENT_SONAME, export=pull.SYNC_AGENT_INSTALL)
        sockets = [listing_peer(()), listing_peer(), self.binary_peer(binary), listing_peer()]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, connect = self.context(root, sockets)
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), root / "evidence", consumer_input=source)
            self.assertEqual(result["state"], "SYNC_AGENT_LIBRARY_COPIED")
            self.assertEqual(result["observed_path"], "/lib/libsync-agent.so.0")
            self.assertEqual(connect.call_count, 4)
            for sock in sockets:
                self.assertNotIn(b"shell:", sock.sent)
                self.assertNotIn(b"ldconfig", sock.sent)
                self.assertNotIn(b"grep", sock.sent)

    def test_denied_first_directory_can_use_second_and_never_exposes_raw_failure(self):
        binary = fake_elf(soname=pull.SYNC_AGENT_SONAME, export=pull.SYNC_AGENT_INSTALL)
        failure = b"private-watch-serial: Permission denied"
        denied = directory_peer([pull.SYNC_HDR.pack(b"FAIL", len(failure)) + failure])
        sockets = [denied, listing_peer(), self.binary_peer(binary), listing_peer()]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, _ = self.context(root, sockets)
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), root / "evidence", consumer_input=source)
            self.assertEqual(result["state"], "SYNC_AGENT_LIBRARY_COPIED")
            self.assertEqual(result["resolution_attempts"][0]["status"], "DIRECTORY_LIST_DENIED_OR_UNSUPPORTED")
            self.assertNotIn("private-watch", json.dumps(result))

    def test_explicit_remote_denial_is_retained_categorically_and_failed_temp_is_removed(self):
        raw = b"private-watch-serial: Permission denied"
        sock = sdb_peer([pull.SYNC_HDR.pack(b"FAIL", len(raw)) + raw])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, _ = self.context(root, [listing_peer(), sock])
            folder = root / "evidence"
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), folder, consumer_input=source)
            self.assertEqual(result["state"], "REMOTE_REPORTED_ACCESS_DENIED")
            self.assertEqual([p.name for p in folder.iterdir()], [pull.SYNC_AGENT_REPORT])
            self.assertNotIn("private-watch", json.dumps(result))

    def test_changed_directory_or_wrong_soname_or_import_only_never_publishes_candidate(self):
        for kind in ("directory_changed", "wrong_soname", "import_only"):
            binary = fake_elf(soname="libwrong.so.0" if kind == "wrong_soname" else pull.SYNC_AGENT_SONAME,
                              export=pull.SYNC_AGENT_INSTALL,
                              export_shindex=0 if kind == "import_only" else 1)
            sockets = [listing_peer(), self.binary_peer(binary)]
            if kind == "directory_changed":
                sockets.append(listing_peer(size=124))
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, _ = self.context(root, sockets)
                folder = root / "evidence"
                result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), folder, consumer_input=source)
                self.assertFalse(result["binary_copied"])
                self.assertEqual([p.name for p in folder.iterdir()], [pull.SYNC_AGENT_REPORT])
                self.assertNotEqual(result["state"], "SYNC_AGENT_LIBRARY_COPIED")

    def test_existing_output_archive_and_public_ip_are_rejected_without_network_or_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(pull.socket, "create_connection") as connect:
            root = Path(tmp)
            folder, archive = root / "evidence", root / "evidence.zip"
            folder.mkdir()
            (folder / "user.txt").write_text("keep")
            archive.write_bytes(b"keep archive")
            for path, bundle, ip in [(folder, None, "127.0.0.1"), (root / "new", archive, "127.0.0.1"),
                                     (root / "new", None, "8.8.8.8")]:
                with self.assertRaises((pull.ArtifactPullError, ValueError)):
                    pull.capture_sync_agent(ip, Path("/unused"), path, archive=bundle)
            self.assertEqual((folder / "user.txt").read_text(), "keep")
            self.assertEqual(archive.read_bytes(), b"keep archive")
            self.assertFalse((root / "new").exists())
            connect.assert_not_called()

    def test_cli_prints_and_packages_failure_report_without_claiming_unlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with redirect_stdout(output), patch.object(pull.socket, "create_connection") as connect:
                code = pull.main(["--component", "sync-agent", "--watch-ip", "127.0.0.1",
                                  "--consumer-input", str(root / "missing"), "--output-dir", str(root / "evidence"),
                                  "--archive", str(root / "evidence.zip")])
            self.assertEqual(code, 1)
            self.assertIn("LOCAL_ORIGINAL_CONSUMER_MISSING", output.getvalue())
            self.assertIn("PRIVATE_EVIDENCE_ZIP:", output.getvalue())
            self.assertNotIn("NO_GO", output.getvalue())
            connect.assert_not_called()

    def test_library_inventory_does_not_raise_the_entry_limit_for_other_scopes(self):
        payload = b"".join(dent("entry-" + str(i)) for i in range(257)) + done()
        with self.assertRaisesRegex(InventoryError, "DIRECTORY_ENTRY_LIMIT_REACHED"):
            DirectoryDecoder().feed(payload, "consumer_binary_directory")
        decoder = DirectoryDecoder()
        decoder.feed(payload, "sync_agent_usr_lib")
        self.assertTrue(decoder.finished)



if __name__ == "__main__":
    unittest.main()
