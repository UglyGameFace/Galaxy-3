"""Own read-only probe: fake SDB, native host logic, compiled ARM/QEMU ABI.

No Samsung binary is executed or physical watch contacted. Fixture metadata
is synthetic; compilation with PROBE_TEST marks it as such.
"""
import contextlib
import copy
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import watch3_r840x_security_metadata as metadata
from analyze_watch3_r08_fota_elf import ELF_HDR, PROGRAM_HDR
from test_watch3_r08_android_sdb import FakeSocket, peer, decode_all
from watch3_r08_android_sdb import VERSION, frame

STAGE = '/tmp/sdk_tools/uglyos-metadata-' + 'a'*32


def elf_fixture():
    """Structurally valid static ARM ELF; never executed or vendor-derived."""
    size = ELF_HDR.size + 2*PROGRAM_HDR.size + 16
    hdr = ELF_HDR.pack(b'\x7fELF\x01\x01\x01'+b'\0'*9, 2, 40, 1, 0x1000,
                       ELF_HDR.size, 0, 0x5000200, ELF_HDR.size, 32, 2, 40, 0, 0)
    return hdr + PROGRAM_HDR.pack(1, 0, 0x1000, 0, size, size, 5, 4) + \
        PROGRAM_HDR.pack(0x6474e551, 0, 0, 0, 0, 0, 6, 4) + b'\0'*16


def probe_fixture():
    return dict(schema='uglyos-watch3-security-metadata-v1', test_fixture=False,
                uid=5001, euid=5001, groups_rc=1, groups=[100], capget_rc=0,
                effective_caps_hex='0'*16, permitted_caps_hex='0'*16,
                inheritable_caps_hex='0'*16, current_label_rc=11,
                current_label_hex=b'User::Shell'.hex(), files=[
                    dict(path=p, write_access_rc=-13, attrs=[dict(name=a, rc=-61, hex='')
                         for a in metadata.ATTRIBUTES]) for p in metadata.TARGETS])


def upload_peer(reply=b'OKAY'+b'\0'*4):
    return FakeSocket(frame(b'CNXN', VERSION, 262144, b'device::\0') + frame(b'OKAY', 42, 2) +
                      frame(b'OKAY', 42, 2) + frame(b'WRTE', 42, 2, reply))


class SecurityMetadataTests(unittest.TestCase):
    def test_upload_is_exact_bounded_send_into_validated_sdk_stage(self):
        raw = elf_fixture(); sock = upload_peer()
        with patch.object(socket, 'create_connection', return_value=sock):
            metadata.send_probe('10.0.0.65', Path('/unused'), STAGE, raw)
        frames = decode_all(bytes(sock.sent))
        self.assertEqual([f[3] for f in frames if f[0]==b'OPEN'], [b'sync:\0'])
        path = (STAGE+'/probe,'+str(0o100700)).encode()
        expected = (metadata.SYNC.pack(b'SEND', len(path))+path+metadata.SYNC.pack(b'DATA', len(raw))+
                    raw+metadata.SYNC.pack(b'DONE', 0))
        self.assertEqual([f[3] for f in frames if f[0]==b'WRTE'], [expected])
        self.assertNotIn(b'/dev/', bytes(sock.sent))

    def test_stage_paths_reject_firmware_traversal_shell_and_nonrandom_destinations(self):
        for p in ('/usr/bin/uglyos-metadata-'+'a'*32, STAGE+'/probe', STAGE+';id',
                  '/tmp/../tmp/uglyos-metadata-'+'a'*32, '/tmp/uglyos-metadata-short'):
            with self.subTest(path=p), self.assertRaises(metadata.MetadataError):
                metadata.validate_stage(p)
        self.assertEqual(metadata.sdk_stage('sdk_toolpath:/tmp/sdk_tools\n', 'a'*32), STAGE)
        with self.assertRaises(metadata.MetadataError):
            metadata.sdk_stage('sdk_toolpath:/tmp/a\nsdk_toolpath:/tmp/b\n', 'a'*32)

    def test_stage_candidates_include_missing_sdk_parent_then_tmp_without_ancestor_walk(self):
        suffix='/uglyos-metadata-'+'a'*32
        self.assertEqual(metadata.sdk_stages('sdk_toolpath:/home/owner/share/tmp/sdk_tools\n','a'*32),
                         [p+suffix for p in ('/home/owner/share/tmp/sdk_tools','/home/owner/share/tmp','/tmp')])
        self.assertEqual(metadata.sdk_stages('sdk_toolpath:/tmp\n','a'*32), ['/tmp'+suffix])
        self.assertEqual(metadata.sdk_stages('sdk_toolpath:/home/owner/other\n','a'*32),
                         ['/home/owner/other'+suffix,'/tmp'+suffix])

    def test_real_shell_missing_parent_is_not_created_and_existing_stage_is_not_claimed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); suffix='/uglyos-metadata-'+'b'*32
            stage=str(root/'missing')+suffix
            raw=subprocess.check_output(['sh','-c',metadata.stage_command('create',stage)])
            self.assertEqual(raw,b'UGLYOS_STAGE_PARENT_MISSING\n')
            self.assertFalse((root/'missing').exists())
            stage=str(root)+suffix
            raw=subprocess.check_output(['sh','-c',metadata.stage_command('create',stage)])
            self.assertEqual(raw,b'UGLYOS_STAGE_CREATED\n')
            self.assertEqual(Path(stage).stat().st_mode & 0o777,0o700)
            Path(stage,'existing').write_bytes(b'preserve')
            raw=subprocess.check_output(['sh','-c',metadata.stage_command('create',stage)],stderr=subprocess.STDOUT)
            self.assertTrue(raw.endswith(b'UGLYOS_STAGE_NOT_CREATED\n'))
            self.assertEqual(Path(stage,'existing').read_bytes(),b'preserve')

    def test_probe_parser_rejects_synthetic_truncated_or_unbounded_attribute_data(self):
        value = probe_fixture()
        self.assertEqual(metadata.parse_probe(json.dumps(value).encode()), value)
        cases = [dict(value, test_fixture=True), dict(value, groups=[0, 100]), dict(value, uid=-1)]
        bad = copy.deepcopy(value); bad['files'][0]['attrs'][0].update(rc=20, hex='00'); cases.append(bad)
        bad = copy.deepcopy(value); bad['files'][0]['path']='/etc/shadow'; cases.append(bad)
        for case in cases:
            with self.assertRaises(metadata.MetadataError): metadata.parse_probe(json.dumps(case).encode())

    def test_complete_capture_cleans_up_and_creates_private_zip_without_firmware_action(self):
        value = probe_fixture()
        sockets = [FakeSocket(peer('sdk_toolpath:/tmp/sdk_tools\n')), FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),
                   upload_peer(), FakeSocket(peer(json.dumps(value))), FakeSocket(peer('UGLYOS_STAGE_REMOVED\n'))]
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            root = Path(td)
            stack.enter_context(patch.object(metadata, 'build_probe', return_value=(elf_fixture(), {'test_build':True})))
            connect = stack.enter_context(patch.object(socket, 'create_connection', side_effect=sockets))
            report = metadata.capture('10.0.0.65', Path('/unused'), root/'evidence', archive=root/'evidence.zip')
            self.assertEqual(report['state'], 'NATIVE_SECURITY_METADATA_CAPTURED')
            self.assertTrue(report['stage_cleanup_verified'])
            self.assertFalse(report['firmware_written'])
            self.assertFalse(report['existing_security_attributes_modified'])
            self.assertFalse(report['vendor_script_executed'])
            self.assertEqual(connect.call_count, 5)
            with zipfile.ZipFile(root/'evidence.zip') as z:
                self.assertEqual(set(z.namelist()), {metadata.REPORT_NAME, 'probe-output.response',
                                                    'stage-create.response','stage-cleanup.response'})
            for path in [root/'evidence', root/'evidence.zip', *(root/'evidence').iterdir()]:
                self.assertEqual(path.stat().st_mode & 0o077, 0)
        self.assertTrue(all(b'root:on' not in s.sent and b'FOTA' not in s.sent for s in sockets))
        commands = [f[3] for s in sockets for f in decode_all(bytes(s.sent)) if f[0]==b'OPEN']
        self.assertIn(b'shell:rm -f ', commands[-1])
        self.assertNotIn(b'rm -rf', commands[-1])

    def test_upload_or_probe_failure_still_cleans_only_our_stage(self):
        for failure in ('upload', 'run'):
            sockets = [FakeSocket(peer('sdk_toolpath:/tmp\n')), FakeSocket(peer('UGLYOS_STAGE_CREATED\n'))]
            sockets += [upload_peer(b'FAIL'+(4).to_bytes(4,'little')+b'nope')] if failure=='upload' else [upload_peer(), FakeSocket(peer('Permission denied\n'))]
            sockets += [FakeSocket(peer('UGLYOS_STAGE_REMOVED\n')),FakeSocket(peer('fixture stage context'))]
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as td, patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})), patch.object(socket,'create_connection',side_effect=sockets):
                root=Path(td)
                report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
                self.assertTrue(report['stage_cleanup_verified'])
                self.assertIn(report['state'], ('PROBE_UPLOAD_DENIED','PROBE_OUTPUT_INVALID'))
                if failure=='run':
                    self.assertEqual((root/'evidence/probe-output.response').read_bytes(),b'Permission denied\n')
                else:
                    self.assertEqual((root/'evidence/probe-upload.response').read_bytes(),b'FAIL\4\0\0\0nope')

    def test_real_report_missing_sdk_directory_falls_back_and_captures_in_one_run(self):
        sockets=[FakeSocket(peer('sdk_toolpath:/home/owner/share/tmp/sdk_tools\n')),
                 FakeSocket(peer('UGLYOS_STAGE_PARENT_MISSING\n')),
                 FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),upload_peer(),
                 FakeSocket(peer(json.dumps(probe_fixture()))),FakeSocket(peer('UGLYOS_STAGE_REMOVED\n'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'NATIVE_SECURITY_METADATA_CAPTURED')
            self.assertEqual(len(report['stage_attempts']),2)
            self.assertFalse(report['stage_attempts'][0]['created'])
            self.assertTrue(report['stage_attempts'][1]['cleanup_verified'])
            commands=[f[3] for s in sockets for f in decode_all(bytes(s.sent)) if f[0]==b'OPEN']
            self.assertTrue(commands[2].startswith(b'shell:if [ ! -d /home/owner/share/tmp ]'))
            self.assertNotIn(b'mkdir -p',b''.join(commands))
            self.assertNotIn(b'/sdk_tools/',commands[-1])

    def test_execution_refusal_is_cleaned_before_retry_and_diagnostics_are_preserved(self):
        sockets=[FakeSocket(peer('sdk_toolpath:/tmp/sdk_tools\n')),FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),
                 upload_peer(),FakeSocket(peer('Permission denied\n')),FakeSocket(peer('UGLYOS_STAGE_REMOVED\n')),
                 FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),upload_peer(),FakeSocket(peer(json.dumps(probe_fixture()))),
                 FakeSocket(peer('UGLYOS_STAGE_REMOVED\n'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'NATIVE_SECURITY_METADATA_CAPTURED')
            self.assertEqual(report['stage_attempts'][0]['error'],'PROBE_OUTPUT_INVALID')
            self.assertTrue(all(a['cleanup_verified'] for a in report['stage_attempts']))
            self.assertEqual((root/'evidence/probe-output.response').read_bytes(),b'Permission denied\n')
            self.assertTrue((root/'evidence/attempt-2-probe-output.response').exists())

    def test_all_unavailable_stages_keep_fixed_mount_context_without_upload_or_cleanup(self):
        sockets=[FakeSocket(peer('sdk_toolpath:/tmp/sdk_tools\n')),
                 FakeSocket(peer('UGLYOS_STAGE_PARENT_MISSING\n')),
                 FakeSocket(peer('mkdir: Permission denied\nUGLYOS_STAGE_NOT_CREATED\n')),
                 FakeSocket(peer('fixture mount context'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'SDK_STAGE_UNAVAILABLE')
            self.assertFalse(report['probe_uploaded'])
            self.assertNotIn('unverified_sdk_stage',report)
            self.assertEqual((root/'evidence/stage-context.response').read_bytes(),b'fixture mount context')
            self.assertTrue(all(b'rm -f' not in s.sent and b'sync:' not in s.sent for s in sockets))

    def test_transport_failure_or_unverified_cleanup_stops_fallback(self):
        for phase in ('upload_transport','cleanup'):
            sockets=[FakeSocket(peer('sdk_toolpath:/tmp/sdk_tools\n')),
                     FakeSocket(peer('UGLYOS_STAGE_CREATED\n'))]
            sockets += [OSError('connection lost')] if phase=='upload_transport' else [upload_peer(),FakeSocket(peer('Permission denied\n'))]
            sockets += [FakeSocket(peer('UGLYOS_STAGE_REMOVED\n' if phase=='upload_transport' else 'cleanup failed\n')),
                        FakeSocket(peer('fixture context'))]
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
                root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence')
                self.assertEqual(len(report['stage_attempts']),1)
                self.assertEqual(report['state'],'LOCAL_OR_SDB_IO_ERROR' if phase=='upload_transport' else 'SDK_STAGE_CLEANUP_UNVERIFIED')

    def test_local_create_diagnostic_failure_still_removes_verified_stage(self):
        sockets=[FakeSocket(peer('sdk_toolpath:/tmp\n')),FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),
                 FakeSocket(peer('UGLYOS_STAGE_REMOVED\n')),FakeSocket(peer('fixture context'))]
        real_write=metadata.private_write
        def write(path,raw):
            if path.name=='stage-create.response': raise OSError('local write failed')
            return real_write(path,raw)
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets),patch.object(metadata,'private_write',side_effect=write):
            report=metadata.capture('10.0.0.65',Path('/unused'),Path(td)/'evidence')
            self.assertTrue(report['stage_cleanup_verified'])
            self.assertFalse(report['probe_uploaded'])

    def test_cleanup_failure_is_explicit_and_preserves_evidence_and_exact_stage(self):
        sockets=[FakeSocket(peer('sdk_toolpath:/tmp/sdk_tools\n')),FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),
                 upload_peer(),FakeSocket(peer(json.dumps(probe_fixture()))),FakeSocket(peer('rmdir failed\n')),
                 FakeSocket(peer('fixture stage context'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'SDK_STAGE_CLEANUP_UNVERIFIED')
            self.assertEqual(metadata.validate_stage(report['remaining_sdk_stage']),report['remaining_sdk_stage'])
            self.assertIsNotNone(report['probe'])

    def test_missing_compiler_and_existing_outputs_make_no_watch_connection(self):
        with tempfile.TemporaryDirectory() as td,patch.object(metadata.shutil,'which',return_value=None),patch.object(socket,'create_connection') as connect:
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'CLANG_MISSING_RUN_PKG_INSTALL_CLANG')
            connect.assert_not_called()
            original=(root/'evidence.zip').read_bytes()
            with self.assertRaises(metadata.MetadataError):
                metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual((root/'evidence.zip').read_bytes(),original)

    def test_unverified_stage_creation_never_uploads_or_removes_an_unowned_directory(self):
        sockets=[FakeSocket(peer('sdk_toolpath:/tmp/sdk_tools\n')),FakeSocket(peer('mkdir: File exists\n')),
                 FakeSocket(peer('fixture stage context'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets) as connect:
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'SDK_STAGE_CREATION_NOT_VERIFIED')
            self.assertEqual(connect.call_count,3)
            self.assertFalse(report['probe_uploaded'])
            self.assertIn('unverified_sdk_stage',report)
            self.assertTrue(all(b'rm -f' not in s.sent for s in sockets))

    def test_compiler_failure_preserves_private_diagnostic_before_any_watch_connection(self):
        failed=subprocess.CompletedProcess([],1,b'',b'private-compiler-detail')
        with tempfile.TemporaryDirectory() as td,patch.object(metadata.subprocess,'run',return_value=failed),patch.object(socket,'create_connection') as connect:
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip',compiler='/fixture/compiler')
            self.assertEqual(report['state'],'PROBE_COMPILER_FAILED');connect.assert_not_called()
            self.assertNotIn('private-compiler-detail',json.dumps(report))
            with zipfile.ZipFile(root/'evidence.zip') as z:
                self.assertEqual(z.read('compiler.response'),b'private-compiler-detail')


class NativeProbeProgramTests(unittest.TestCase):
    def check_fixture(self, compiler, *, arm):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); fixture=root/'fixture'; values={}
            for i,path in enumerate(metadata.TARGETS):
                file=fixture/path.lstrip('/');file.parent.mkdir(parents=True,exist_ok=True);file.touch()
                value=bytes([0,255,i])*7
                os.setxattr(file,'user.uglyos_fixture',value);values[path]=value
            # One oversized attribute must report ERANGE, not overflow the buffer.
            os.setxattr(fixture/metadata.TARGETS[-1].lstrip('/'),'user.uglyos_fixture',b'x'*257)
            try:
                _raw,_facts=metadata.build_probe(root,compiler,fixture=fixture,host_test=not arm)
            except metadata.MetadataError as exc:
                if getattr(exc,'diagnostic',None):
                    self.fail(exc.diagnostic.decode('utf-8','replace'))
                raise
            program=root/'security-metadata-probe'
            command=[shutil.which('qemu-arm'),str(program)] if arm else [str(program)]
            result=json.loads(subprocess.check_output(command,timeout=10))
            self.assertTrue(result['test_fixture'])
            self.assertEqual(result['uid'],os.getuid());self.assertEqual(result['euid'],os.geteuid())
            self.assertEqual(result['groups'],os.getgroups())
            self.assertEqual(result['capget_rc'],0)
            for item in result['files'][:-1]:
                attr=item['attrs'][-1];self.assertEqual(attr['rc'],len(values[item['path']]))
                self.assertEqual(bytes.fromhex(attr['hex']),values[item['path']])
            self.assertEqual(result['files'][-1]['attrs'][-1]['rc'],-errno.ERANGE)
            self.assertEqual(result['files'][-1]['attrs'][-1]['hex'],'')

    @unittest.skipUnless(shutil.which('gcc'),'host C compiler unavailable')
    def test_native_host_reader_matches_real_positive_xattrs_and_bounds(self):
        self.check_fixture(shutil.which('gcc'),arm=False)

    def test_static_arm_reader_matches_real_xattrs_under_qemu(self):
        if not shutil.which('clang') or not shutil.which('qemu-arm'):
            if os.environ.get('WATCH3_REQUIRE_ARM_ELF')=='1': self.fail('Required ARM compiler/QEMU missing')
            self.skipTest('ARM compiler/QEMU unavailable locally')
        self.check_fixture(shutil.which('clang'),arm=True)
        # Also compile/run the exact production configuration; its output must
        # pass the real controller parser, independently of fixture-mode tests.
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            metadata.build_probe(root,shutil.which('clang'))
            raw=subprocess.check_output([shutil.which('qemu-arm'),str(root/'security-metadata-probe')],timeout=10)
            value=metadata.parse_probe(raw)
            self.assertFalse(value['test_fixture'])


if __name__=='__main__': unittest.main()
