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
from test_watch3_r08_fota_consumer_inventory import peer as directory_peer, dent, done
from watch3_r08_fota_consumer_inventory import DirectoryDecoder

CHILD = b"/usr/share/oma-dm-cfg/events/fota.xml"
LIB = b"/usr/lib/libframework-test.so.0"
ROOT_XML = (b'<Framework><Event-Config>' + CHILD + b'</Event-Config>'
            b'<private>not-a-report-value</private></Framework>')
LIB_XML = b'<Events plugin="' + LIB + b'"/>'
# Production-shaped initializer: these two declared files have no .xml suffix.
EVENT_CONFIG = b'/usr/share/oma-dm-cfg/ipc/eventconfig_omadm'
NOTI_CONFIG = b'/usr/share/oma-dm-cfg/ipc/noticonfig_omadm'
EXTENSIONLESS_XML = (b'<INIT><Agent-Key>omadm_fota_ui</Agent-Key><Event>'
                     b'<Event-Key>omadm</Event-Key><Event-Config>' + EVENT_CONFIG +
                     b'</Event-Config><RunEventHandler>0</RunEventHandler></Event>'
                     b'<Noti><Noti-Config>' + NOTI_CONFIG + b'</Noti-Config></Noti></INIT>')


def directory_listing(names):
    return directory_peer([b''.join(dent(name) for name in names) + done()])


class FrameworkContextTests(unittest.TestCase):
    def setup_capture(self, stack, root, sockets, *, native_discovery=False, discovered=()):
        source = root / "original.bin"
        # Source pin matching is tested with a declared synthetic local input.
        source.write_bytes(b"LOCAL-LIBRARY-FIXTURE")
        stack.enter_context(patch.object(context, "LIBRARY_BYTES", source.stat().st_size))
        stack.enter_context(patch.object(context, "LIBRARY_SHA256",
                                         hashlib.sha256(source.read_bytes()).hexdigest()))
        if not native_discovery:
            # These cases isolate file chaining. A separate case below exercises
            # every native LIST and RECV without replacing discovery.
            stack.enter_context(patch.object(context, 'discover_receiver_paths', return_value=list(discovered)))
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

    def test_actual_extensionless_configuration_shape_reads_both_plain_files(self):
        events, notices = b'4, 1, 1, 1, I\n', b'1, 0, 0, private-notice-value\n'
        sockets = [successful(EXTENSIONLESS_XML), successful(events), successful(notices)]
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, connect = self.setup_capture(stack, root, sockets)
            report = context.capture_context('10.0.0.65', Path('/unused'), root / 'context',
                                              library_input=source, archive=root / 'context.zip')
            self.assertEqual(report['schema'], 'uglyos-r840x-sync-agent-context-v2')
            self.assertEqual(report['copied_by_kind']['config'], 2)
            self.assertFalse(report['receiver_candidate_code_copied'])
            self.assertEqual(connect.call_count, 3)
            fields = report['files'][0]['framework_fields']
            self.assertEqual(fields['event_key'], 'omadm')
            self.assertFalse(fields['run_event_handler_declared'])
            self.assertEqual(fields['event_socket_from_config'], '/tmp/agent_fw_event_omadm')
            self.assertNotIn('private-notice-value', json.dumps(report))
            with zipfile.ZipFile(root / 'context.zip') as z:
                self.assertEqual(z.read('context-02.conf'), events)
                self.assertEqual(z.read('context-03.conf'), notices)
        self.assertEqual(context.declared_references(EXTENSIONLESS_XML),
                         [('config', EVENT_CONFIG), ('config', NOTI_CONFIG)])

    def test_native_discovery_captures_observed_daemon_unit_binary_and_initializer_once(self):
        unit = b'[Service]\nUser=root\nExecStart=/usr/bin/oma-dm-agent --private-token=hidden\n'
        binary = fake_elf(soname='libsimulated-daemon.so.0')
        listings = [directory_listing(['oma-dm.service', 'private-unit.service']),
                    directory_listing([]),
                    directory_listing(['oma-dm-agent', 'private-executable']),
                    directory_listing(['omadmagent_fw_config.xml'])]
        sockets = listings + [successful(EXTENSIONLESS_XML), successful(unit), successful(binary),
                              successful(b'<INIT/>'), successful(b'4, 1, 1, 1, I\n'), successful(b'1, 0\n')]
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, connect = self.setup_capture(stack, root, sockets, native_discovery=True)
            report = context.capture_context('10.0.0.65', Path('/unused'), root / 'context',
                                              library_input=source, archive=root / 'context.zip')
            self.assertEqual(report['state'], 'CONTEXT_CAPTURED')
            self.assertEqual(connect.call_count, 10)
            self.assertEqual(report['copied_by_kind'], {'xml': 2, 'config': 2, 'unit': 1, 'elf': 1})
            self.assertTrue(report['receiver_candidate_code_copied'])
            self.assertFalse(report['runtime_receiver_observed'])
            self.assertFalse(report['root_obtained'])
            paths = [r['remote_path'] for r in report['files']]
            self.assertEqual(paths.count('/usr/bin/oma-dm-agent'), 1)
            self.assertNotIn('private-token', json.dumps(report))
            self.assertNotIn('private-executable', json.dumps(report))
            self.assertNotIn('private-unit', json.dumps(report))
        for sock, directory in zip(listings, context.FOTA_FRAMEWORK_DIRECTORIES.values()):
            frames = calls(bytes(sock.sent))
            self.assertEqual([f[3] for f in frames if f[0] == b'WRTE'],
                             [handoff.SYNC_HDR.pack(b'LIST', len(directory)) + directory])
        for sock in sockets:
            self.assertNotIn(b'shell:', sock.sent)
            self.assertNotIn(b'SEND', sock.sent)

    def test_discovery_denial_is_categorical_and_other_directories_continue(self):
        message = b'private-device-label: permission denied'
        blocked = directory_peer([handoff.SYNC_HDR.pack(b'FAIL', len(message)) + message])
        sockets = [blocked, directory_listing([]), directory_listing(['oma-dm-agent']), directory_listing([])]
        with patch.object(context.socket, 'create_connection', side_effect=sockets):
            reports = []
            paths = context.discover_receiver_paths('10.0.0.65', Path('/unused'), 12, reports)
        self.assertEqual(paths, [('elf', b'/usr/bin/oma-dm-agent')])
        self.assertEqual(reports[0]['status'], 'DIRECTORY_LIST_DENIED_OR_UNSUPPORTED')
        self.assertNotIn('private-device-label', json.dumps(reports))

    def test_observed_unit_can_declare_an_executable_not_matched_by_the_bin_inventory(self):
        unit_path = b'/usr/lib/systemd/system/oma-dm.service'
        unit = b'[Service]\nExecStart=/usr/libexec/device-management --private-token=hidden\n'
        binary = fake_elf()
        sockets = [successful(b'<INIT/>'), successful(unit), successful(binary)]
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            source, connect = self.setup_capture(stack, root, sockets, discovered=[('unit', unit_path)])
            report = context.capture_context('10.0.0.65', Path('/unused'), root / 'context',
                                              library_input=source)
            self.assertEqual(connect.call_count, 3)
            self.assertEqual(report['files'][-1]['remote_path'], '/usr/libexec/device-management')
            self.assertTrue(report['receiver_candidate_code_copied'])
            self.assertFalse(report['runtime_receiver_observed'])
            self.assertNotIn('private-token', json.dumps(report))

    def test_receiver_inventory_handles_large_bin_directories_without_reporting_other_names(self):
        decoder = DirectoryDecoder()
        payload = b''.join(dent('unreported-' + str(i)) for i in range(1500))
        decoder.feed(payload + dent('oma-dm-agent') + done(), 'sync_agent_receiver_binaries')
        report = decoder.report('sync_agent_receiver_binaries')
        self.assertEqual(set(report['matching_framework_files']), {'oma-dm-agent'})
        self.assertNotIn('unreported-', json.dumps(report))

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
        self.assertEqual(context.classify_reference("/usr/apps/com.samsung.omadm/bin/daemon"), "elf")

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


class FirmwareFocusTests(unittest.TestCase):
    """Declared synthetic pins test transport/selection, never owner firmware."""

    PLUGIN = b'/usr/lib/sync-agent/dm-private/libplugin-mo-fumo.so'
    CONFIG = (b'<INIT><PlugIn-Mgr><Domain name="MO">'
              b'<!-- <Plug-In><Type>FUMO</Type><Path>/usr/lib/libignored.so</Path></Plug-In> -->'
              b'<Plug-In><Type>FUMO</Type><Path>' + PLUGIN + b'</Path></Plug-In>'
              b'<Plug-In><Type>DEVINFO</Type><Path>/usr/lib/libother.so</Path></Plug-In>'
              b'</Domain></PlugIn-Mgr><private>unreported-value</private></INIT>')

    def fixture(self, stack, root, sockets=(), config=None):
        library = root / 'library.bin'
        library.write_bytes(b'SYNTHETIC-LIBRARY')
        daemon = b'SYNTHETIC-DAEMON\0' + context.PUBLIC_CERTIFICATE + b'\0'
        config = self.CONFIG if config is None else config
        receiver = root / 'receiver'
        receiver.mkdir()
        files = []
        for remote, name, raw in (
                ('/usr/bin/oma-dm-agent', 'context-07.bin', daemon),
                (context.BACKEND_CONFIG, 'context-18.xml', config)):
            (receiver / name).write_bytes(raw)
            files.append(dict(remote_path=remote, local_file=name, bytes=len(raw),
                              sha256=hashlib.sha256(raw).hexdigest(), status='COPIED'))
        (receiver / context.REPORT_NAME).write_text(json.dumps({'files': files}))
        for prefix, raw in [('LIBRARY', library.read_bytes()), ('OMADM_AGENT', daemon),
                            ('BACKEND_CONFIG', config)]:
            stack.enter_context(patch.object(context, prefix + '_BYTES', len(raw)))
            stack.enter_context(patch.object(context, prefix + '_SHA256', hashlib.sha256(raw).hexdigest()))
        connect = stack.enter_context(patch.object(context.socket, 'create_connection', side_effect=sockets))
        discover = stack.enter_context(patch.object(context, 'discover_receiver_paths',
                                                     side_effect=AssertionError('No discovery in focus mode')))
        return library, receiver, connect, discover

    def capture(self, root, library, receiver):
        return context.capture_context('10.0.0.65', Path('/unused'), root / 'focus',
                                       library_input=library, firmware_focus=True,
                                       receiver_input_dir=receiver, archive=root / 'focus.zip')

    def test_focus_native_recv_only_selects_fumo_and_public_certificate(self):
        binary, certificate = fake_elf(), b'SYNTHETIC PUBLIC CERTIFICATE'
        sockets = [successful(binary), successful(certificate)]
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            library, receiver, connect, discover = self.fixture(stack, root, sockets)
            report = self.capture(root, library, receiver)
            self.assertEqual(report['state'], 'FIRMWARE_FOCUS_CAPTURED')
            self.assertEqual(report['capture_scope'], 'FIRMWARE_FOCUS')
            self.assertTrue(report['firmware_focus_source']['sources_verified'])
            self.assertEqual(report['copied_by_kind'], {'xml': 0, 'config': 1, 'unit': 0, 'elf': 1})
            self.assertEqual(connect.call_count, 2)
            discover.assert_not_called()
            self.assertFalse(report['runtime_receiver_observed'])
            self.assertFalse(report['watch_write_performed'])
            self.assertNotIn('unreported-value', json.dumps(report))
            with zipfile.ZipFile(root / 'focus.zip') as z:
                self.assertEqual(z.namelist(), [context.REPORT_NAME, 'context-01.bin', 'context-02.conf'])
                self.assertEqual(z.read('context-01.bin'), binary)
                self.assertEqual(z.read('context-02.conf'), certificate)
            for p in [root / 'focus', root / 'focus.zip', *(root / 'focus').iterdir()]:
                self.assertEqual(p.stat().st_mode & 0o077, 0)
        for sock, path in zip(sockets, (self.PLUGIN, context.PUBLIC_CERTIFICATE)):
            frames = calls(bytes(sock.sent))
            self.assertEqual([f[3] for f in frames if f[0] == b'OPEN'], [b'sync:\0'])
            self.assertEqual([f[3] for f in frames if f[0] == b'WRTE'],
                             [handoff.SYNC_HDR.pack(b'RECV', len(path)) + path])

    def test_changed_source_bytes_are_rejected_before_connection(self):
        for name in ('context-07.bin', 'context-18.xml'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                root = Path(tmp)
                library, receiver, connect, _ = self.fixture(stack, root)
                path = receiver / name
                raw = path.read_bytes()
                path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                report = self.capture(root, library, receiver)
                self.assertEqual(report['state'], 'LOCAL_RECEIVER_SOURCE_PIN_MISMATCH')
                connect.assert_not_called()
                with zipfile.ZipFile(root / 'focus.zip') as z:
                    self.assertEqual(z.namelist(), [context.REPORT_NAME])

    def test_manifest_cannot_select_parent_path_duplicate_or_symlink(self):
        for variant in ('parent', 'duplicate', 'symlink'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                root = Path(tmp)
                library, receiver, connect, _ = self.fixture(stack, root)
                path = receiver / context.REPORT_NAME
                report = json.loads(path.read_text())
                if variant == 'parent':
                    report['files'][0]['local_file'] = '../context-07.bin'
                elif variant == 'duplicate':
                    report['files'].append(report['files'][0])
                else:
                    source = receiver / 'context-07.bin'
                    source.rename(root / 'daemon.bin')
                    source.symlink_to(root / 'daemon.bin')
                path.write_text(json.dumps(report))
                result = self.capture(root, library, receiver)
                self.assertEqual(result['state'], 'LOCAL_RECEIVER_SOURCE_RECORD_INVALID')
                connect.assert_not_called()

    def test_missing_or_malformed_report_has_specific_diagnostic(self):
        for content, expected in ((None, 'LOCAL_RECEIVER_SOURCE_MISSING'),
                                  ('{private-invalid', 'LOCAL_RECEIVER_REPORT_INVALID'),
                                  ('x' * (128 * 1024 + 1), 'LOCAL_RECEIVER_REPORT_SIZE_INVALID')):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                root = Path(tmp)
                library, receiver, connect, _ = self.fixture(stack, root)
                path = receiver / context.REPORT_NAME
                path.unlink() if content is None else path.write_text(content)
                report = self.capture(root, library, receiver)
                self.assertEqual(report['state'], expected)
                self.assertNotIn('private-invalid', json.dumps(report))
                connect.assert_not_called()

    def test_fumo_selection_requires_one_valid_mo_declaration(self):
        for config in (b'<INIT/>', self.CONFIG.replace(b'name="MO"', b'name="OTHER"'),
                       self.CONFIG.replace(self.PLUGIN, b'/dev/mmcblk0'),
                       self.CONFIG.replace(b'</Domain>', b'<Plug-In><Type>FUMO</Type>'
                                           b'<Path>/usr/lib/libduplicate.so</Path></Plug-In></Domain>')):
            with self.subTest(config_bytes=len(config)), tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                root = Path(tmp)
                library, receiver, connect, _ = self.fixture(stack, root, config=config)
                report = self.capture(root, library, receiver)
                self.assertEqual(report['state'], 'LOCAL_FUMO_DECLARATION_INVALID')
                connect.assert_not_called()

    def test_certificate_failure_preserves_plugin_and_diagnostic_zip(self):
        binary = fake_elf()
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            library, receiver, connect, _ = self.fixture(stack, root, [successful(binary), denied()])
            report = self.capture(root, library, receiver)
            self.assertEqual(report['state'], 'CONTEXT_PARTIAL_OR_UNAVAILABLE')
            self.assertEqual(report['files'][1]['status'], 'REMOTE_MISSING_DENIED_OR_UNREADABLE')
            self.assertEqual(connect.call_count, 2)
            with zipfile.ZipFile(root / 'focus.zip') as z:
                self.assertEqual(z.read('context-01.bin'), binary)
                self.assertEqual(len(z.namelist()), 2)

    def test_cli_uses_fresh_focus_default_and_preserves_existing_capture(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            library, receiver, connect, _ = self.fixture(stack, root, [successful(fake_elf()), successful(b'cert')])
            stack.enter_context(patch.object(context.Path, 'home', return_value=root))
            before = (receiver / context.REPORT_NAME).read_bytes()
            args = ['--watch-ip', '10.0.0.65', '--firmware-focus', '--library-input', str(library),
                    '--receiver-input-dir', str(receiver), '--archive', str(root / 'focus.zip')]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(context.main(args), 0)
            self.assertTrue((root / 'watch3-r840x-firmware-focus-evidence' / context.REPORT_NAME).is_file())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(context.main(args), 1)
            self.assertEqual(connect.call_count, 2)
            self.assertEqual((receiver / context.REPORT_NAME).read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
