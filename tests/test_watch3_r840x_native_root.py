"""Fake SDB tests: native root control is explicit; no physical watch exists."""
import contextlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_native_root as root
from test_watch3_r08_android_sdb import FakeSocket, peer, decode_all
from test_watch3_r08_fota_handoff_pull import successful, denied, peer as file_peer
from watch3_r08_android_sdb import Connection, VERSION, frame

MODEL = 'NOBLESSE-LARGE-BT R08\0'
CAPS = 'rootonoff_support:enabled\nsdbd_rootperm:disabled\nsdk_toolpath:/private/unreported\n'


def status(uid):
    return f'Name:\tprivate-name\nPid:\t771\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t0\t0\t0\t0\nCapEff:\t0000003fffffffff\n'


def replies(*values):
    return [FakeSocket(peer(v)) for v in values]


class NativeRootTests(unittest.TestCase):
    def run_capture(self, temp, sockets):
        # These cases isolate mode/identity/script behavior. The backup-specific
        # cases below exercise the default conditional image path separately.
        return root.capture('10.0.0.65', Path('/unused'), temp / 'evidence', archive=temp / 'evidence.zip',
                            backup_images=False)

    def test_complete_native_root_request_uid_proof_and_conditional_recovery_reads(self):
        scripts = [b'#!/bin/sh\n# original-one\n', b'#!/bin/sh\n# original-two\n', b'[Service]\nUser=root\n']
        sockets = replies(MODEL, CAPS, '5001\n', status(5001), "Switched to 'root' account mode\n", '0\n', status(0))
        sockets += [successful(data) for data in scripts]
        with tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=sockets) as connect:
            temp = Path(td)
            report = self.run_capture(temp, sockets)
            self.assertEqual(report['state'], 'ROOT_VERIFIED_RECOVERY_INPUTS_COPIED')
            self.assertTrue(report['root_observed'])
            self.assertTrue(report['root_obtained'])
            self.assertTrue(report['account_mode_change_requested'])
            self.assertFalse(report['root_mode_persistence_verified'])
            self.assertFalse(report['bootloader_unlock_proven'])
            self.assertFalse(report['stock_recovery_proven'])
            self.assertEqual(connect.call_count, 10)
            self.assertEqual(report['advertised_root_capabilities'],
                             {'sdbd_rootperm': 'disabled', 'rootonoff_support': 'enabled'})
            for private in ('private-name', '/private/unreported', '771'):
                self.assertNotIn(private, json.dumps(report))
            with zipfile.ZipFile(temp / 'evidence.zip') as z:
                self.assertEqual(z.namelist(), [root.REPORT_NAME, *root.FILES])
                self.assertEqual(json.loads(z.read(root.REPORT_NAME)), report)
                for name, data in zip(root.FILES, scripts):
                    self.assertEqual(z.read(name), data)
            for path in [temp / 'evidence', temp / 'evidence.zip', *(temp / 'evidence').iterdir()]:
                self.assertEqual(path.stat().st_mode & 0o077, 0)
        destinations = [f[3] for sock in sockets for f in decode_all(bytes(sock.sent)) if f[0] == b'OPEN']
        self.assertEqual(destinations[:7], [b'shell:cat /proc/device-tree/model\0', b'capability:\0',
                         b'shell:id -u\0', b'shell:cat /proc/self/status\0', b'root:on\0',
                         b'shell:id -u\0', b'shell:cat /proc/self/status\0'])
        self.assertEqual(destinations[7:], [b'sync:\0'] * 3)
        for sock in sockets:
            self.assertNotIn(b'SEND', sock.sent)
            self.assertNotIn(b'/dev/mmc', sock.sent)
            self.assertNotIn(b'root:off', sock.sent)

    def test_success_message_without_root_uid_is_not_success_and_does_not_read_files(self):
        for uid, euid, expected in ((5001, 5001, 'NATIVE_ROOT_NOT_GRANTED'),
                                     (0, 5001, 'ROOT_IDENTITY_INCONSISTENT'),
                                     (5001, 0, 'ROOT_IDENTITY_INCONSISTENT')):
            sockets = replies(MODEL, CAPS, '5001\n', status(5001), "Switched to 'root' account mode\n",
                              str(uid)+'\n', status(euid))
            with self.subTest(uid=uid, euid=euid), tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=sockets) as connect:
                temp = Path(td)
                report = self.run_capture(temp, sockets)
                self.assertEqual(report['state'], expected)
                self.assertFalse(report['root_observed'])
                self.assertEqual(connect.call_count, 7)
                self.assertEqual(report['files'], [])
                with zipfile.ZipFile(temp / 'evidence.zip') as z:
                    self.assertEqual(z.namelist(), [root.REPORT_NAME])

    def test_explicit_denial_is_categorical_and_is_followed_by_identity_readback(self):
        sockets = replies(MODEL, CAPS.replace('enabled', 'disabled'), '5001\n', status(5001),
                          'Permission denied private-error-token\n', '5001\n', status(5001))
        with tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=sockets):
            report = self.run_capture(Path(td), sockets)
            self.assertEqual(report['root_mode_reply'], 'WATCH_REPORTED_DENIAL')
            self.assertTrue(report['root_mode_attempted'])
            self.assertEqual(report['state'], 'NATIVE_ROOT_NOT_GRANTED')
            self.assertNotIn('private-error-token', json.dumps(report))

    def test_root_stream_close_does_not_prevent_fresh_uid_verification(self):
        closed = FakeSocket(frame(b'CNXN', VERSION, 256 * 1024, b'device::\0') + frame(b'CLSE', 0, 2))
        sockets = replies(MODEL, CAPS, '5001\n', status(5001)) + [closed] + replies('0\n', status(0))
        sockets += [denied(), successful(b'original-prepare'), denied()]
        with tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=sockets):
            temp = Path(td)
            report = self.run_capture(temp, sockets)
            self.assertTrue(report['root_observed'])
            self.assertEqual(report['state'], 'ROOT_VERIFIED_RECOVERY_INPUTS_PARTIAL')
            self.assertEqual(report['root_mode_reply'], 'SERVICE_UNAVAILABLE_OR_CONNECTION_CLOSED')
            self.assertEqual(report['files'][0]['status'], 'REMOTE_MISSING_DENIED_OR_UNREADABLE')
            with zipfile.ZipFile(temp / 'evidence.zip') as z:
                self.assertEqual(z.namelist(), [root.REPORT_NAME, 'rw-update-prepare.sh'])

    def test_already_root_captures_inputs_without_a_root_switch(self):
        sockets = replies(MODEL, CAPS, '0\n', status(0)) + [denied(), denied(), denied()]
        with tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=sockets):
            report = self.run_capture(Path(td), sockets)
            self.assertTrue(report['root_observed'])
            self.assertFalse(report['root_obtained'])
            self.assertFalse(report['root_mode_attempted'])
        self.assertTrue(all(b'root:on' not in sock.sent for sock in sockets))

    def test_wrong_board_never_requests_root_or_copies_files(self):
        sockets = replies('DIFFERENT-BOARD\n', 'DIFFERENT-BOARD\n')
        with tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=sockets) as connect:
            report = self.run_capture(Path(td), sockets)
            self.assertEqual(report['state'], 'TARGET_BOARD_MISMATCH')
            self.assertFalse(report['root_mode_attempted'])
            self.assertEqual(connect.call_count, 2)

    def test_identity_fallback_uses_fresh_connections_and_requires_both_uid_and_euid(self):
        sockets = replies('0\n', status(5001), '0\n', status(0))
        with patch.object(socket, 'create_connection', side_effect=sockets) as connect:
            first = root.identity('10.0.0.65', Path('/unused'))
            self.assertFalse(first['root_verified'])
            self.assertEqual(connect.call_count, 2)
        sockets = replies('closed\n', 'unrecognized\n', '0\n', status(0))
        with patch.object(socket, 'create_connection', side_effect=sockets) as connect:
            result = root.identity('10.0.0.65', Path('/unused'))
            self.assertTrue(result['root_verified'])
            self.assertEqual(connect.call_count, 4)
            self.assertEqual(decode_all(bytes(sockets[2].sent))[1][3], b'shell:0 id -u\0')

    def test_malformed_duplicate_identity_fields_cannot_claim_root(self):
        for text in ('0 extra', '00\n', '-1\n', '4294967296\n', '0\n0\n'):
            self.assertIsNone(root.parse_uid(text))
        for text in ('Uid:\t0 0 0\n', 'Uid:\t0 0 0 0\nUid:\t0 0 0 0\n', 'Uid:\t0 4294967296 0 0\n'):
            self.assertNotIn('uids', root.parse_status(text))
        self.assertEqual(root.parse_capabilities('rootonoff_support:enabled\nrootonoff_support:disabled\n'), {})

    def test_existing_outputs_and_nonallowlisted_operations_never_contact_watch(self):
        with tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection') as connect:
            temp = Path(td)
            (temp / 'evidence.zip').write_bytes(b'preserved')
            with self.assertRaisesRegex(root.NativeRootError, 'LOCAL_ARCHIVE_ALREADY_EXISTS'):
                self.run_capture(temp, [])
            self.assertEqual((temp / 'evidence.zip').read_bytes(), b'preserved')
            with self.assertRaisesRegex(root.NativeRootError, 'OPERATION_NOT_ALLOWLISTED'):
                root.query('10.0.0.65', Path('/unused'), 'reboot')
            connect.assert_not_called()

    def test_cli_failure_still_preserves_diagnostic_zip(self):
        with tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=OSError('private-address')):
            temp = Path(td)
            with contextlib.redirect_stdout(io.StringIO()):
                code = root.main(['--watch-ip', '10.0.0.65', '--output-dir', str(temp / 'evidence'),
                                  '--archive', str(temp / 'evidence.zip')])
            self.assertEqual(code, 1)
            with zipfile.ZipFile(temp / 'evidence.zip') as z:
                text = z.read(root.REPORT_NAME).decode()
                self.assertNotIn('private-address', text)
                self.assertEqual(json.loads(text)['state'], 'TARGET_BOARD_UNAVAILABLE')

    def test_default_root_flow_copies_only_geometry_matched_boot_recovery_and_scripts(self):
        # Small, explicitly synthetic sector counts avoid shipping/mimicking
        # firmware images. The >8 MiB transport boundary has a separate case.
        partitions = ((13, 'boot', 169984, 2), (14, 'recovery', 206848, 3))
        contents = [b'B' * 1024, b'R' * 1536]
        sockets = replies(MODEL, CAPS, '5001\n', status(5001), 'mode switched\n', '0\n', status(0))
        for (index, label, start, size), raw in zip(partitions, contents):
            sockets += replies(f'DEVNAME=mmcblk0p{index}\nPARTNAME={label}\n', str(start)+'\n', str(size)+'\n')
            sockets.append(successful(raw))
        sockets += [successful(b'original-script') for _ in root.FILES]
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            temp = Path(td)
            stack.enter_context(patch.object(root, 'PARTITIONS', partitions))
            connect = stack.enter_context(patch.object(socket, 'create_connection', side_effect=sockets))
            report = root.capture('10.0.0.65', Path('/unused'), temp / 'evidence', archive=temp / 'evidence.zip')
            self.assertEqual(report['state'], 'ROOT_VERIFIED_RECOVERY_INPUTS_COPIED')
            self.assertTrue(report['partition_backup_complete'])
            self.assertTrue(report['partition_reads_attempted'])
            self.assertFalse(report['stock_recovery_proven'])
            self.assertEqual(connect.call_count, 18)
            with zipfile.ZipFile(temp / 'evidence.zip') as z:
                for name, raw in zip(('boot-original.bin', 'recovery-original.bin'), contents):
                    self.assertEqual(z.read(name), raw)
            self.assertEqual([p['remote_path'] for p in report['partition_copies']],
                             ['/dev/mmcblk0p13', '/dev/mmcblk0p14'])
        self.assertTrue(all(b'SEND' not in sock.sent for sock in sockets))

    def test_changed_or_duplicate_partition_metadata_never_opens_a_block_device(self):
        for bad in ('PARTNAME=wrong\n', 'PARTNAME=boot\nPARTNAME=boot\n', 'PARTNAME=boot\n'):
            # In the last variant, the label matches but geometry changed.
            sockets = replies('DEVNAME=mmcblk0p13\n'+bad, '169984\n', '2\n',
                              'DEVNAME=mmcblk0p14\nPARTNAME=recovery\n', '206849\n', '36864\n')
            with self.subTest(metadata=bad), tempfile.TemporaryDirectory() as td, patch.object(socket, 'create_connection', side_effect=sockets) as connect:
                report = {'after': {'shell_style': 'standard'}, 'partition_copies': [],
                          'partition_reads_attempted': False}
                root.partition_backup('10.0.0.65', Path('/unused'), Path(td), report, [])
                self.assertEqual(connect.call_count, 6)
                self.assertFalse(report['partition_reads_attempted'])
                self.assertFalse(report['partition_backup_complete'])
            self.assertTrue(all(b'/dev/mmc' not in sock.sent for sock in sockets))

    def test_truncated_partition_copy_is_not_saved_and_other_failures_stay_categorical(self):
        partitions = ((13, 'boot', 169984, 2), (14, 'recovery', 206848, 3))
        sockets = replies('DEVNAME=mmcblk0p13\nPARTNAME=boot\n', '169984\n', '2\n')
        sockets += [successful(b'short')]
        sockets += replies('DEVNAME=mmcblk0p14\nPARTNAME=recovery\n', '206848\n', '3\n')
        sockets += [denied()]
        with tempfile.TemporaryDirectory() as td, patch.object(root, 'PARTITIONS', partitions), patch.object(socket, 'create_connection', side_effect=sockets):
            temp = Path(td)
            report = {'after': {'shell_style': 'standard'}, 'partition_copies': [],
                      'partition_reads_attempted': False}
            saved = []
            root.partition_backup('10.0.0.65', Path('/unused'), temp, report, saved)
            self.assertEqual(saved, [])
            self.assertFalse(any(temp.iterdir()))
            self.assertEqual([p['status'] for p in report['partition_copies']],
                             ['PARTITION_COPY_SIZE_MISMATCH', 'REMOTE_MISSING_DENIED_OR_UNREADABLE'])

    def test_backup_transport_can_cross_old_elf_limit_but_legacy_decoder_keeps_eight_mib(self):
        from watch3_r08_fota_artifact_pull import (ReadOnlySyncDecoder, ArtifactPullError,
                                                   MAX_BINARY_BYTES, MAX_SYNC_CHUNK, SYNC_HDR)
        from watch3_r08_fota_handoff_pull import _receive_bounded_file
        # The sync DATA header also occupies bytes in the enclosing SDB frame.
        chunk = b'T' * min(MAX_SYNC_CHUNK, 64 * 1024)
        parts = [SYNC_HDR.pack(b'DATA', len(chunk)) + chunk] * (MAX_BINARY_BYTES // len(chunk) + 1)
        total = sum(len(p)-8 for p in parts)
        sock = file_peer(parts + [SYNC_HDR.pack(b'DONE', 0)])
        raw = _receive_bounded_file(sock, Path('/unused'), b'/dev/mmcblk0p13', total)
        self.assertEqual(len(raw), total)
        self.assertEqual(raw, b'T' * total)
        decoder = ReadOnlySyncDecoder(io.BytesIO())
        for piece in parts[:-1]:
            decoder.feed(piece)
        with self.assertRaisesRegex(ArtifactPullError, 'REMOTE_FILE_EXCEEDS_EIGHT_MIB'):
            decoder.feed(parts[-1])
        with self.assertRaisesRegex(ArtifactPullError, 'INVALID_SYNC_BYTE_LIMIT'):
            ReadOnlySyncDecoder(io.BytesIO(), max_bytes=32 * 1024 * 1024 + 1)


if __name__ == '__main__':
    unittest.main()
