"""Complete dependency capture with fake SDB and a real host shell fixture.

No physical watch, vendor-code execution, service activation or network access.
"""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
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
from watch3_r08_android_sdb import (
    VERSION, frame, FOTA_SYNC_AGENT_CACHE_COMMAND, FOTA_SYNC_AGENT_CACHE_END,
)
from test_watch3_r08_fota_artifact_pull import FakeSocket, sdb_peer, requests
from test_watch3_r08_fota_elf_offline import fake_elf

LIBRARY = "/usr/lib/libsync-agent.so.0"


def cache_reply(path=LIBRARY):
    return (f"\tlibsync-agent.so.0 (libc6,soft-float) => {path}\n"
            + FOTA_SYNC_AGENT_CACHE_END + "\n")


def shell_peer(text, *, refused=False):
    return FakeSocket(frame(b"CNXN", VERSION, 256 * 1024, b"device::\0") +
                      (frame(b"CLSE", 0, 2) if refused else
                       frame(b"OKAY", 42, 2) + frame(b"WRTE", 42, 2, text.encode()) +
                       frame(b"CLSE", 42, 2)))


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
        sockets = [shell_peer(cache_reply()), self.binary_peer(binary), shell_peer(cache_reply())]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, connect = self.context(root, sockets)
            folder, archive = root / "evidence", root / "evidence.zip"
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), folder,
                                             consumer_input=source, archive=archive)
            self.assertEqual(result["state"], "SYNC_AGENT_LIBRARY_COPIED")
            self.assertTrue(result["binary_copied"])
            self.assertTrue(result["cache_entry_stable"])
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
        self.assertEqual(opens, [("shell:" + FOTA_SYNC_AGENT_CACHE_COMMAND).encode() + b"\0",
                                 b"sync:\0", ("shell:" + FOTA_SYNC_AGENT_CACHE_COMMAND).encode() + b"\0"])
        recv = [m[3] for m in requests(bytes(sockets[1].sent)) if m[0] == b"WRTE"]
        self.assertEqual(recv, [pull.SYNC_HDR.pack(b"RECV", len(LIBRARY)) + LIBRARY.encode()])
        self.assertNotIn(b"SEND", b"".join(s.sent for s in sockets))

    def test_cache_parser_distinguishes_absence_denial_tool_and_ambiguity_without_raw_output(self):
        cases = [
            (FOTA_SYNC_AGENT_CACHE_END, "DEPENDENCY_NOT_IN_LINKER_CACHE"),
            ("sh: ldconfig: not found\n" + FOTA_SYNC_AGENT_CACHE_END, "DEPENDENCY_CACHE_TOOL_UNAVAILABLE"),
            ("ldconfig: /private/cache: Permission denied\n" + FOTA_SYNC_AGENT_CACHE_END,
             "DEPENDENCY_CACHE_QUERY_DENIED"),
            ("ldconfig: Can't open cache: No such file or directory\n" + FOTA_SYNC_AGENT_CACHE_END,
             "DEPENDENCY_LINKER_CACHE_UNAVAILABLE"),
            (cache_reply().replace(FOTA_SYNC_AGENT_CACHE_END, ""), "DEPENDENCY_CACHE_REPLY_INCOMPLETE"),
            (cache_reply().replace(FOTA_SYNC_AGENT_CACHE_END,
                                  "libsync-agent.so.0 (libc6) => /lib/libsync-agent.so.0\n" + FOTA_SYNC_AGENT_CACHE_END),
             "DEPENDENCY_CACHE_ENTRY_AMBIGUOUS"),
        ]
        for raw, category in cases:
            with self.subTest(category=category), self.assertRaises(pull.ArtifactPullError) as caught:
                pull.parse_sync_agent_cache(raw)
            self.assertEqual(str(caught.exception), category)
            self.assertNotIn("private", str(caught.exception))
        self.assertEqual(pull.parse_sync_agent_cache(cache_reply()), LIBRARY.encode())

    def test_cache_paths_cannot_select_devices_traversal_or_unrelated_objects(self):
        for path in ("/dev/mmcblk0", "/usr/lib/../lib/libsync-agent.so.0", "/tmp/libsync-agent.so.0",
                     "/usr/lib/libc.so.6", "/usr/lib/libsync-agent.so.01", "/usr/lib/libsync-agent.so.0;id",
                     "/usr/lib//libsync-agent.so.0", "/usr/lib/$(id)/libsync-agent.so.0"):
            with self.subTest(path=path), self.assertRaises(pull.ArtifactPullError):
                pull.parse_sync_agent_cache(cache_reply(path))
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

    def test_cache_denial_does_not_guess_path_or_attempt_recv(self):
        sock = shell_peer("ldconfig: permission denied\n" + FOTA_SYNC_AGENT_CACHE_END)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, connect = self.context(root, [sock])
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), root / "evidence", consumer_input=source)
            self.assertEqual(result["state"], "DEPENDENCY_CACHE_QUERY_DENIED")
            self.assertEqual(connect.call_count, 1)
            self.assertNotIn(b"sync:", sock.sent)

    def test_refused_standard_shell_uses_same_command_in_tizen_encoding(self):
        sockets = [shell_peer("", refused=True), shell_peer(cache_reply())]
        with patch.object(pull.socket, "create_connection", side_effect=sockets):
            self.assertEqual(pull.query_sync_agent_cache("127.0.0.1", Path("/unused"), 8), cache_reply())
        self.assertIn(("shell:0 " + FOTA_SYNC_AGENT_CACHE_COMMAND).encode(), sockets[1].sent)

    def test_explicit_remote_denial_is_retained_categorically_and_failed_temp_is_removed(self):
        raw = b"private-watch-serial: Permission denied"
        sock = sdb_peer([pull.SYNC_HDR.pack(b"FAIL", len(raw)) + raw])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, _ = self.context(root, [shell_peer(cache_reply()), sock])
            folder = root / "evidence"
            result = pull.capture_sync_agent("127.0.0.1", Path("/unused"), folder, consumer_input=source)
            self.assertEqual(result["state"], "REMOTE_REPORTED_ACCESS_DENIED")
            self.assertEqual([p.name for p in folder.iterdir()], [pull.SYNC_AGENT_REPORT])
            self.assertNotIn("private-watch", json.dumps(result))

    def test_changed_cache_or_wrong_soname_or_import_only_never_publishes_candidate(self):
        for kind in ("cache_changed", "wrong_soname", "import_only"):
            binary = fake_elf(soname="libwrong.so.0" if kind == "wrong_soname" else pull.SYNC_AGENT_SONAME,
                              export=pull.SYNC_AGENT_INSTALL,
                              export_shindex=0 if kind == "import_only" else 1)
            sockets = [shell_peer(cache_reply()), self.binary_peer(binary)]
            if kind == "cache_changed":
                sockets.append(shell_peer(cache_reply("/lib/libsync-agent.so.0")))
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

    def test_fixed_cache_command_with_real_posix_shell_preserves_errors_and_filters_nonmatches(self):
        # Execute only our metadata query against a host CLI fixture, never
        # any target binary. Both cache formats and tool failures retain the
        # terminator, so empty output cannot masquerade as SDB refusal.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program = root / "ldconfig"
            scenarios = [("printf '%s\\n' " + shlex.quote(cache_reply().splitlines()[0]) +
                          " 'libprivate.so.1 (libc6) => /private/secret'", None),
                         ("printf '%s\\n' 'ldconfig: permission denied' >&2; exit 1",
                          "DEPENDENCY_CACHE_QUERY_DENIED")]
            for body, error in scenarios:
                program.write_text("#!/bin/sh\n" + body + "\n")
                program.chmod(0o700)
                result = subprocess.run(["/bin/sh", "-c", FOTA_SYNC_AGENT_CACHE_COMMAND],
                                        env={**os.environ, "PATH": str(root) + os.pathsep + os.defpath},
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=3)
                self.assertNotIn("libprivate", result.stdout)
                if error:
                    with self.assertRaisesRegex(pull.ArtifactPullError, error):
                        pull.parse_sync_agent_cache(result.stdout)
                else:
                    self.assertEqual(pull.parse_sync_agent_cache(result.stdout), LIBRARY.encode())


if __name__ == "__main__":
    unittest.main()
