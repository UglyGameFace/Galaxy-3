"""Native read-only framework context with fake SDB, not owner-firmware proof."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r08_fota_framework_context as context
import watch3_r08_fota_handoff_pull as handoff
from test_watch3_r08_fota_handoff_pull import successful, denied, calls
from test_watch3_r08_fota_elf_offline import fake_elf

CHILD = b"/usr/share/oma-dm-cfg/events/fota.xml"
LIB = b"/usr/lib/libframework-test.so.0"
ROOT_XML = (b'<Framework><Event-Config>' + CHILD + b'</Event-Config>'
            b'<private>not-a-report-value</private></Framework>')
LIB_XML = b'<Events plugin="' + LIB + b'"/>'


class FrameworkContextTests(unittest.TestCase):
    def setup_capture(self, stack, root, sockets):
        source = root / "original.bin"
        # Source pin matching is tested with a declared synthetic local input.
        source.write_bytes(b"LOCAL-LIBRARY-FIXTURE")
        stack.enter_context(patch.object(context, "LIBRARY_BYTES", source.stat().st_size))
        stack.enter_context(patch.object(context, "LIBRARY_SHA256",
                                         hashlib.sha256(source.read_bytes()).hexdigest()))
        connect = stack.enter_context(patch.object(context.socket, "create_connection", side_effect=sockets))
        return source, connect

    def test_full_native_configuration_chain_captures_declared_elf_and_private_zip(self):
        binary = fake_elf(soname="libframework-test.so.0")
        sockets = [successful(ROOT_XML), successful(LIB_XML), successful(binary)]
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, connect = self.setup_capture(stack, root, sockets)
            folder, archive = root / "context", root / "context.zip"
            report = context.capture_context("10.0.0.65", Path("/unused"), folder,
                                              library_input=source, archive=archive)
            self.assertEqual(report["state"], "CONTEXT_CAPTURED")
            self.assertTrue(report["source_library_verified"])
            self.assertFalse(report["runtime_receiver_observed"])
            self.assertEqual(connect.call_count, 3)
            self.assertEqual([r["remote_path"] for r in report["files"]],
                             [context.ROOT_CONFIG.decode(), CHILD.decode(), LIB.decode()])
            self.assertNotIn("not-a-report-value", json.dumps(report))
            with zipfile.ZipFile(archive) as z:
                self.assertEqual(z.read("context-01.xml"), ROOT_XML)
                self.assertEqual(z.read("context-02.xml"), LIB_XML)
                self.assertEqual(z.read("context-03.bin"), binary)
                self.assertEqual(json.loads(z.read(context.REPORT_NAME)), report)
            self.assertEqual(folder.stat().st_mode & 0o077, 0)
            for p in [archive, *folder.iterdir()]:
                self.assertEqual(p.stat().st_mode & 0o077, 0)
        for sock, path in zip(sockets, (context.ROOT_CONFIG, CHILD, LIB)):
            sent = calls(bytes(sock.sent))
            self.assertEqual([f[3] for f in sent if f[0] == b"OPEN"], [b"sync:\0"])
            self.assertEqual([f[3] for f in sent if f[0] == b"WRTE"],
                             [handoff.SYNC_HDR.pack(b"RECV", len(path)) + path])
            self.assertNotIn(b"shell:", sock.sent)
            self.assertNotIn(b"SEND", sock.sent)

    def test_failed_root_read_still_creates_diagnostic_zip_without_private_error_text(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, _ = self.setup_capture(stack, root, [denied()])
            report = context.capture_context("10.0.0.65", Path("/unused"), root / "context",
                                              library_input=source, archive=root / "context.zip")
            self.assertEqual(report["state"], "CONTEXT_PARTIAL_OR_UNAVAILABLE")
            self.assertNotIn("secret watch", json.dumps(report))
            with zipfile.ZipFile(root / "context.zip") as z:
                self.assertEqual(z.namelist(), [context.REPORT_NAME])

    def test_mismatched_source_pin_makes_no_connection_and_preserves_report(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(context.socket, "create_connection") as connect:
            root = Path(tmp)
            source = root / "changed.bin"
            source.write_bytes(b"not the original")
            report = context.capture_context("10.0.0.65", Path("/unused"), root / "context",
                                              library_input=source, archive=root / "context.zip")
            self.assertEqual(report["state"], "LOCAL_ORIGINAL_LIBRARY_PIN_MISMATCH")
            connect.assert_not_called()
            self.assertTrue((root / "context.zip").is_file())

    def test_xml_only_follows_complete_absolute_paths_in_fixed_system_roots(self):
        bad = ("/dev/mmcblk0", "/usr/share/oma-dm-cfg/../private.xml",
               "/usr/share/oma-dm-cfg//event.xml", "relative.xml", "https://example.com/a.xml",
               "/tmp/private.xml", "/usr/bin/daemon --secret", "/usr/lib/$(id).so",
               "/usr/bin/../sbin/daemon", "/usr/share/oma-dm-cfg/event.xml;id")
        for value in bad:
            with self.subTest(value=value):
                self.assertIsNone(context.classify_reference(value))
        self.assertEqual(context.declared_references(ROOT_XML), [("xml", CHILD)])
        self.assertEqual(context.declared_references(LIB_XML), [("elf", LIB)])
        self.assertEqual(context.classify_reference("/usr/bin/oma-dm-agent"), "elf")

    def test_entities_utf16_malformed_and_oversized_xml_are_rejected(self):
        for raw in (b'<!DOCTYPE x [<!ENTITY y "secret">]><x>&y;</x>',
                    '<x>secret</x>'.encode('utf-16'), b'<x>',
                    b'x' * (context.MAX_XML_BYTES + 1)):
            with self.subTest(raw_bytes=len(raw)), self.assertRaises(context.ContextError):
                context.declared_references(raw)

    def test_cycles_and_file_count_limits_bound_reads(self):
        children = [f"/usr/share/oma-dm-cfg/e{i}.xml".encode() for i in range(18)]
        raw = b'<x>' + b''.join(b'<path>'+p+b'</path>' for p in children) + b'</x>'
        # Each child links to the original file; it must never be fetched twice.
        cycle = b'<x><path>' + context.ROOT_CONFIG + b'</path></x>'
        sockets = [successful(raw)] + [successful(cycle) for _ in range(15)]
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, connect = self.setup_capture(stack, root, sockets)
            report = context.capture_context("10.0.0.65", Path("/unused"), root / "context",
                                              library_input=source)
            self.assertTrue(report["limits_reached"])
            self.assertEqual(connect.call_count, 16)
            self.assertEqual(len(report["files"]), 16)

    def test_byte_limit_is_profile_specific_and_non_elf_declaration_is_not_published(self):
        oversized = b'x' * (context.MAX_XML_BYTES + 1)
        sockets = [successful(ROOT_XML), successful(oversized)]
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, _ = self.setup_capture(stack, root, sockets)
            report = context.capture_context("10.0.0.65", Path("/unused"), root / "context",
                                              library_input=source)
            self.assertEqual(report['files'][1]['status'], 'REMOTE_FILE_EXCEEDS_CONTEXT_LIMIT')
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, _ = self.setup_capture(stack, root, [successful(LIB_XML), successful(b'#!/bin/sh\n')])
            report = context.capture_context("10.0.0.65", Path("/unused"), root / "context",
                                              library_input=source)
            self.assertNotEqual(report['files'][1]['status'], 'COPIED')
            self.assertFalse((root / 'context/context-02.bin').exists())

    def test_cli_failures_and_existing_evidence_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, connect = self.setup_capture(stack, root, [denied()])
            folder, archive = root / 'context', root / 'context.zip'
            args = ['--watch-ip', '10.0.0.65', '--library-input', str(source),
                    '--output-dir', str(folder), '--archive', str(archive)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(context.main(args), 1)
            original = archive.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(context.main(args), 1)
            self.assertEqual(archive.read_bytes(), original)
            self.assertEqual(connect.call_count, 1)


if __name__ == '__main__':
    unittest.main()
