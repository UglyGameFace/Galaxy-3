"""Archive-tampering and bounded offline checks: no physical watch needed."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

MODULE = Path(__file__).resolve().parents[1] / 'tools' / 'watch3_r840x_privilege_offline.py'
spec = importlib.util.spec_from_file_location('watch3_r840x_privilege_offline', MODULE)
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)


def fake_elf():
    b = bytearray(64)
    b[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<H', b, 16, 3)
    struct.pack_into('<H', b, 18, 40)
    return bytes(b) + b'\0_fota_launch_cb\0fota.consumer.LaunchFota\0'


def sample():
    data = fake_elf()
    name = 'helper-01.bin'
    path = '/bin/bapd'
    dirs = []
    for root in ('/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/libexec', '/usr/lib'):
        rows = []
        if root == '/bin':
            rows.append({'name': 'bapd', 'mode': 0o100755, 'size_hex': f'{len(data):016x}'})
        dirs.append({'path': root, 'files': rows, 'dropped_records': 0,
                     'entries_scanned': len(rows), 'stat_errors': 0, 'complete': True})
    probe = {'test_fixture': False, 'uid': 5001, 'euid': 5001, 'capget_rc': 0,
             'effective_caps_hex': '0'*16, 'permitted_caps_hex': '0'*16,
             'inheritable_caps_hex': '0'*16,
             'privilege_inventory': {'schema': 'uglyos-system-helper-metadata-v1', 'directories': dirs}}
    copied = {'path': path, 'copied': True, 'file': name,
              'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    report = {'schema': 'uglyos-r840x-native-security-metadata-v1', 'state': 'NATIVE_PRIVILEGE_INVENTORY_CAPTURED',
              'privilege_inventory_requested': True, 'stage_cleanup_verified': True,
              'probe': probe, 'inventory_summary': {'candidates': [{'path': path}],
                  'original_inputs': [copied], 'scope_complete': True}}
    for field in ('root_mode_requested', 'vendor_script_executed', 'existing_security_attributes_modified',
                  'fota_method_called', 'partition_reads_attempted', 'firmware_written',
                  'bootloader_unlock_proven', 'stock_recovery_proven'):
        report[field] = False
    return report, data


def archive(report, data=None, extras=None):
    if data is None:
        data = fake_elf()
    members = {'security-metadata-report.json': json.dumps(report).encode(),
               'probe-output.response': json.dumps(report['probe']).encode(),
               'stage-cleanup.response': b'UGLYOS_STAGE_REMOVED\n', 'helper-01.bin': data}
    members.update(extras or {})
    with io.BytesIO() as buf:
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            for k, v in members.items():
                z.writestr(k, v)
        return buf.getvalue()


class OfflinePrivilegeTests(unittest.TestCase):
    def review(self, payload):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'input.zip'
            p.write_bytes(payload)
            return reviewer.review(p)

    def test_valid_private_archive_marks_static_link_not_unlock(self):
        report, data = sample()
        result = self.review(archive(report, data))
        self.assertEqual(result['candidate_count'], 1)
        self.assertEqual(result['dropped_candidate_records'], 0)
        self.assertEqual(result['setuid_or_setgid_count'], 0)
        self.assertIn('fota.consumer.LaunchFota', result['original_inputs'][0]['fota_literal_matches'])
        self.assertFalse(result['binary_executed'])
        self.assertFalse(result['bootloader_unlock_proven'])

    def test_wrong_hash_rejected(self):
        report, data = sample()
        self.assertRaisesRegex(reviewer.EvidenceError, 'ORIGINAL_HASH_OR_SIZE_MISMATCH',
                               self.review, archive(report, data+b'changed'))

    def test_not_cleaned_rejected(self):
        report, data = sample()
        report['stage_cleanup_verified'] = False
        self.assertRaisesRegex(reviewer.EvidenceError, 'INVENTORY_CAPTURE_UNVERIFIED',
                               self.review, archive(report, data))

    def test_raw_probe_disagreement_rejected(self):
        report, data = sample()
        self.assertRaisesRegex(reviewer.EvidenceError, 'INVENTORY_CAPTURE_UNVERIFIED',
                               self.review, archive(report, data, {'probe-output.response': b'{}'}))

    def test_unsafe_marker_rejected(self):
        report, data = sample()
        report['firmware_written'] = True
        self.assertRaisesRegex(reviewer.EvidenceError, 'UNSAFE_OR_INCONSISTENT_CAPTURE',
                               self.review, archive(report, data))

    def test_non_arm_original_rejected(self):
        report, data = sample()
        data = b'X'*len(data)
        report['inventory_summary']['original_inputs'][0]['sha256'] = hashlib.sha256(data).hexdigest()
        self.assertRaisesRegex(reviewer.EvidenceError, 'ORIGINAL_NOT_ARM_ELF32',
                               self.review, archive(report, data))

    def test_path_escape_rejected(self):
        report, data = sample()
        self.assertRaisesRegex(reviewer.EvidenceError, 'ARCHIVE_MEMBER_INVALID',
                               self.review, archive(report, data, {'../private': b'oops'}))

    def test_extra_file_rejected(self):
        report, data = sample()
        self.assertRaisesRegex(reviewer.EvidenceError, 'ARCHIVE_MEMBER_INVALID',
                               self.review, archive(report, data, {'script.sh': b'exit 0'}))

    def test_unknown_state_rejected(self):
        report, data = sample()
        report['state'] = 'NOT_CAPTURED'
        self.assertRaisesRegex(reviewer.EvidenceError, 'INVENTORY_CAPTURE_UNVERIFIED',
                               self.review, archive(report, data))

    def test_capability_does_not_equal_root(self):
        report, data = sample()
        report['probe']['effective_caps_hex'] = '0000000000000001'
        result = self.review(archive(report, data))
        self.assertEqual(result['privilege_boundary'], 'OWNER_PRIVILEGE_BOUNDARY_NOT_ESTABLISHED')
        self.assertFalse(result['root_proven'])


if __name__ == '__main__':
    unittest.main()
