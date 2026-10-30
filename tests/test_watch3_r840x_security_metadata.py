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
import struct
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


CAPABILITIES = 'sdk_toolpath:/home/owner/share/tmp/sdk_tools\n'
BASES = metadata.stage_bases(CAPABILITIES)
MOUNTINFO = ('11 1 1:1 / / ro,relatime - ext4 /dev/root ro\n'
             '12 11 1:2 / /opt rw,nosuid - ext4 /dev/data rw\n'
             '13 11 0:1 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n')


def preflight_fixture(*, bases=BASES, records=None, mountinfo=MOUNTINFO):
    records = records or {base: ('/opt/home/owner/share', True) if base == '/home/owner/share'
                         else ('MISSING', False) for base in bases}
    lines = ['UGLYOS_PREFLIGHT_V1']
    for base in bases:
        resolved, access = records[base]
        lines += ['UGLYOS_DIR '+base, resolved, 'ACCESS_OK' if access else 'ACCESS_DENIED', 'UGLYOS_DIR_END']
    return ('\n'.join([*lines,'UGLYOS_MOUNTINFO',mountinfo.rstrip('\n'),'UGLYOS_PREFLIGHT_END'])+'\n').encode()


def initial_sockets(raw=None):
    return [FakeSocket(peer(CAPABILITIES)),FakeSocket(peer((raw if raw is not None else preflight_fixture()).decode()))]


def inventory_fixture():
    cap=struct.pack('<5I',0x02000001,0,0x002000c2,0,0).hex()
    row=dict(name='helper',mode=0o104755,uid=0,gid=0,size_hex=f'{len(elf_fixture()):016x}',
             capability_rc=20,capability_hex=cap,read_access_rc=0,exec_access_rc=0,
             label_rc=1,label_hex='5f',exec_label_rc=-61,exec_label_hex='')
    dirs=[dict(path=p,open_rc=0,scan_rc=0,complete=True,entries_scanned=0,regular_files=0,
               stat_errors=0,capability_errors=0,unsafe_names=0,dropped_records=0,files=[])
          for p in metadata.INVENTORY_ROOTS]
    dirs[2].update(entries_scanned=1,regular_files=1,files=[row])
    return dict(schema='uglyos-system-helper-metadata-v1',no_new_privs_rc=0,securebits_rc=0,
                bounding_caps_hex='0000003fffffffff',bounding_read_errors=0,directories=dirs)


class PrivilegeInventoryTests(unittest.TestCase):
    def test_capability_decoder_preserves_errors_and_distinguishes_three_revisions(self):
        for version in (1,2,3):
            words=[version<<24|1,0x80,0x42]
            if version>=2:words += [1,2]
            if version==3:words += [1000]
            raw=struct.pack('<'+'I'*len(words),*words)
            cap=metadata.decode_file_capability(len(raw),raw.hex())
            self.assertEqual(cap['state'],'DECODED');self.assertTrue(cap['effective_flag'])
            self.assertEqual(cap['rootid'],1000 if version==3 else None)
            self.assertEqual(int(cap['permitted_hex'],16),0x80|((1<<32) if version>=2 else 0))
        self.assertEqual(metadata.decode_file_capability(-61,'')['state'],'ATTRIBUTE_ABSENT')
        self.assertEqual(metadata.decode_file_capability(-13,'')['state'],'READ_ERROR')
        self.assertEqual(metadata.decode_file_capability(3,'000000')['state'],'UNRECOGNIZED_ATTRIBUTE')

    def test_inventory_parser_rejects_path_escape_bad_lengths_and_unbounded_records(self):
        probe=probe_fixture();probe['privilege_inventory']=inventory_fixture()
        metadata.parse_probe(json.dumps(probe).encode(),inventory=True)
        cases=[]
        for key,value in (('name','../root'),('capability_hex','00'),('mode',0o120777)):
            bad=copy.deepcopy(probe);bad['privilege_inventory']['directories'][2]['files'][0][key]=value;cases.append(bad)
        bad=copy.deepcopy(probe);bad['privilege_inventory']['directories'][2]['dropped_records']=999999;cases.append(bad)
        bad=copy.deepcopy(probe);bad['test_fixture']=True;cases.append(bad)
        for value in cases:
            with self.assertRaises(metadata.MetadataError):metadata.parse_probe(json.dumps(value).encode(),inventory=True)
        probe['inheritable_caps_hex']='00000000002000c2'
        summary=metadata.inventory_summary(probe)
        self.assertTrue(summary['scope_complete'])
        self.assertEqual(summary['candidates'][0]['matching_inheritable_hex'],'00000000002000c2')
        self.assertFalse(summary['root_proven'])

    def test_inventory_capture_copies_only_bounded_originals_after_cleanup_and_never_runs_them(self):
        value=probe_fixture();value['privilege_inventory']=inventory_fixture()
        sockets=initial_sockets()+[FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),upload_peer(),
                 FakeSocket(peer(json.dumps(value))),FakeSocket(peer('UGLYOS_STAGE_REMOVED\n')),
                 FakeSocket(b''),FakeSocket(b''),FakeSocket(peer('fixed unit context'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets),patch.object(metadata,'_receive_bounded_file',return_value=elf_fixture()) as read:
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip',inventory=True)
            self.assertEqual(report['state'],'NATIVE_PRIVILEGE_INVENTORY_CAPTURED')
            self.assertTrue(report['stage_cleanup_verified'])
            self.assertEqual([c.args[2] for c in read.call_args_list],[b'/usr/bin/launch_app',b'/usr/bin/helper'])
            self.assertTrue(all(c.args[3]==metadata.MAX_INPUT_BYTES for c in read.call_args_list))
            self.assertTrue(all(r['copied'] for r in report['inventory_summary']['original_inputs']))
            with zipfile.ZipFile(root/'evidence.zip') as z:
                self.assertEqual(z.read('helper-01.bin'),elf_fixture());self.assertIn('privilege-context.response',z.namelist())
            self.assertFalse(report['inventory_summary']['privileged_helper_executed'])
        commands=[f[3] for s in sockets for f in decode_all(bytes(s.sent)) if f[0]==b'OPEN']
        self.assertNotIn(b'shell:/usr/bin/helper',b'\n'.join(commands))
        self.assertTrue(all(b'root:on' not in s.sent for s in sockets))

    def test_candidate_budget_and_invalid_input_preserve_metadata_without_running_helpers(self):
        value=probe_fixture();inventory=inventory_fixture();value['privilege_inventory']=inventory
        row=inventory['directories'][2]['files'][0]
        inventory['directories'][2].update(entries_scanned=12,regular_files=12,
            files=[dict(row,name='helper'+str(n)) for n in range(12)])
        with tempfile.TemporaryDirectory() as td,patch.object(socket,'create_connection',return_value=FakeSocket(b'')),patch.object(metadata,'_receive_bounded_file',return_value=b'not an ELF') as read:
            summary=metadata.collect_inventory_inputs('10.0.0.65',Path('/unused'),value,Path(td),[])
            self.assertEqual(read.call_count,metadata.MAX_INPUTS)
            self.assertTrue(all(not c['copied'] for c in summary['original_inputs']))
            self.assertGreater(summary['inputs_not_selected'],0)
            self.assertFalse(summary['root_proven'])

    def test_inventory_cleanup_failure_prevents_followup_copy(self):
        value=probe_fixture();value['privilege_inventory']=inventory_fixture()
        sockets=initial_sockets()+[FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),upload_peer(),
                                  FakeSocket(peer(json.dumps(value))),FakeSocket(peer('cleanup failed'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets),patch.object(metadata,'collect_inventory_inputs') as collect:
            report=metadata.capture('10.0.0.65',Path('/unused'),Path(td)/'evidence',inventory=True)
            self.assertEqual(report['state'],'SDK_STAGE_CLEANUP_UNVERIFIED');collect.assert_not_called()


class SecurityMetadataTests(unittest.TestCase):
    def test_upload_is_exact_bounded_send_into_validated_sdk_stage(self):
        raw=elf_fixture();sock=upload_peer()
        with patch.object(socket,'create_connection',return_value=sock):
            metadata.send_probe('10.0.0.65',Path('/unused'),STAGE,raw)
        frames=decode_all(bytes(sock.sent))
        self.assertEqual([f[3] for f in frames if f[0]==b'OPEN'],[b'sync:\0'])
        path=(STAGE+'/probe,'+str(0o100700)).encode()
        expected=(metadata.SYNC.pack(b'SEND',len(path))+path+metadata.SYNC.pack(b'DATA',len(raw))+
                  raw+metadata.SYNC.pack(b'DONE',0))
        self.assertEqual([f[3] for f in frames if f[0]==b'WRTE'],[expected])
        self.assertNotIn(b'/dev/',bytes(sock.sent))

    def test_fragmented_upload_failure_preserves_exact_bounded_diagnostic(self):
        reply=b'FAIL\4\0\0\0nope'
        sock=FakeSocket(frame(b'CNXN',VERSION,262144,b'device::\0')+frame(b'OKAY',42,2)+
                        frame(b'WRTE',42,2,reply[:8])+frame(b'WRTE',42,2,reply[8:]))
        with patch.object(socket,'create_connection',return_value=sock),self.assertRaises(metadata.MetadataError) as cm:
            metadata.send_probe('10.0.0.65',Path('/unused'),STAGE,elf_fixture())
        self.assertEqual(str(cm.exception),'PROBE_UPLOAD_DENIED')
        self.assertEqual(cm.exception.upload_response,reply)

    def test_stage_paths_reject_firmware_traversal_shell_and_nonrandom_destinations(self):
        for p in ('/usr/bin/uglyos-metadata-'+'a'*32,STAGE+'/probe',STAGE+';id',
                  '/tmp/../tmp/uglyos-metadata-'+'a'*32,'/tmp/uglyos-metadata-short'):
            with self.subTest(path=p),self.assertRaises(metadata.MetadataError):metadata.validate_stage(p)
        for base in ('/home/owner/share','/opt/home/owner/share','/opt/usr/home/owner/share'):
            self.assertEqual(metadata.validate_stage(base+'/uglyos-metadata-'+'a'*32),base+'/uglyos-metadata-'+'a'*32)
        with self.assertRaises(metadata.MetadataError):
            metadata.sdk_stage('sdk_toolpath:/tmp/a\nsdk_toolpath:/tmp/b\n','a'*32)

    def test_fixed_preflight_candidates_do_not_walk_ancestors_or_add_tmp(self):
        self.assertEqual(BASES,('/home/owner/share/tmp/sdk_tools','/home/owner/share',
                                '/opt/home/owner/share','/opt/usr/home/owner/share'))
        self.assertNotIn('/tmp',BASES)
        for bases in (('/tmp;id',),('/tmp',)*2,('/usr/bin',),()):
            with self.assertRaises(metadata.MetadataError):metadata.preflight_command(bases)

    def test_preflight_resolves_owner_share_onto_writable_exec_mount(self):
        value=metadata.parse_preflight(preflight_fixture(),BASES)
        self.assertEqual(value['selected_base'],'/opt/home/owner/share')
        self.assertEqual(value['candidates'][0]['reason'],'MISSING')
        selected=value['candidates'][1]
        self.assertEqual(selected['mount']['point'],'/opt')
        self.assertIn('nosuid',selected['mount']['options'])
        self.assertTrue(selected['eligible'])  # nosuid does not prevent this ordinary program.

    def test_noexec_readonly_denied_and_unsafe_resolutions_are_not_selected(self):
        for resolved,access,flags,reason in (
                ('/tmp',True,'rw','MOUNT_NOEXEC'),
                ('/opt/home/owner/share',True,'ro','MOUNT_READ_ONLY'),
                ('/opt/home/owner/share',False,'rw','ACCESS_DENIED'),
                ('/usr/bin',True,'rw','SDK_STAGE_PATH_REJECTED')):
            with self.subTest(reason=reason):
                raw=preflight_fixture(bases=('/tmp',),records={'/tmp':(resolved,access)},
                                      mountinfo=MOUNTINFO.replace('/opt rw,nosuid','/opt '+flags+',nosuid'))
                value=metadata.parse_preflight(raw,('/tmp',))
                self.assertIsNone(value['selected_base'])
                self.assertEqual(value['candidates'][0]['reason'],reason)

    def test_mount_parser_uses_deepest_bind_and_rejects_ambiguous_stacked_mounts(self):
        mounts=metadata.parse_mountinfo(MOUNTINFO+'14 12 1:2 / /opt/home rw,noexec - ext4 /dev/data rw\n')
        self.assertEqual(metadata.containing_mount('/opt/home/owner/share',mounts)['id'],14)
        self.assertEqual(metadata.containing_mount('/opt/homeother',mounts)['id'],12)
        mounts+= [dict(mounts[-1],id=15,parent=14)]
        with self.assertRaisesRegex(metadata.MetadataError,'AMBIGUOUS'):
            metadata.containing_mount('/opt/home/owner/share',mounts)
        escaped=metadata.parse_mountinfo('11 1 1:1 / /with\\040space rw - ext4 /dev/root rw\n')
        self.assertEqual(escaped[0]['point'],'/with space')

    def test_malformed_or_truncated_preflight_never_produces_a_stage(self):
        raw=preflight_fixture()
        for value in (raw[:-30],raw.replace(b'UGLYOS_DIR /home/owner/share\n',b'UGLYOS_DIR /usr/bin\n'),
                      raw.replace(b'/opt rw,nosuid',b'/opt invalid'),raw+b'x',b'x'*(metadata.MAX_PREFLIGHT+1)):
            with self.assertRaises(metadata.MetadataError):metadata.parse_preflight(value,BASES)
        for value in ('','bogus',MOUNTINFO+MOUNTINFO):
            with self.assertRaises(metadata.MetadataError):metadata.parse_mountinfo(value)

    def test_real_shell_preflight_resolves_existing_symlink_without_creating_parents(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);directory=root/'existing';directory.mkdir();alias=root/'alias';alias.symlink_to(directory)
            bases=(str(root/'missing'),str(alias))
            raw=subprocess.check_output(['sh','-c',metadata.preflight_command(bases)])
            value=metadata.parse_preflight(raw,bases)
            self.assertEqual(value['candidates'][0]['reason'],'MISSING')
            self.assertEqual(value['candidates'][1]['resolved'],str(directory.resolve()))
            self.assertFalse((root/'missing').exists())
            self.assertEqual(set(root.iterdir()),{directory,alias})

    def test_real_shell_missing_parent_is_not_created_and_existing_stage_is_not_claimed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);suffix='/uglyos-metadata-'+'b'*32
            stage=str(root/'missing')+suffix
            raw=subprocess.check_output(['sh','-c',metadata.stage_command('create',stage)])
            self.assertEqual(raw,b'UGLYOS_STAGE_PARENT_MISSING\n');self.assertFalse((root/'missing').exists())
            stage=str(root)+suffix
            raw=subprocess.check_output(['sh','-c',metadata.stage_command('create',stage)])
            self.assertEqual(raw,b'UGLYOS_STAGE_CREATED\n');self.assertEqual(Path(stage).stat().st_mode&0o777,0o700)
            Path(stage,'existing').write_bytes(b'preserve')
            raw=subprocess.check_output(['sh','-c',metadata.stage_command('create',stage)],stderr=subprocess.STDOUT)
            self.assertTrue(raw.endswith(b'UGLYOS_STAGE_NOT_CREATED\n'))
            self.assertEqual(Path(stage,'existing').read_bytes(),b'preserve')

    def test_probe_parser_rejects_synthetic_truncated_or_unbounded_attribute_data(self):
        value=probe_fixture();self.assertEqual(metadata.parse_probe(json.dumps(value).encode()),value)
        cases=[dict(value,test_fixture=True),dict(value,groups=[0,100]),dict(value,uid=-1)]
        bad=copy.deepcopy(value);bad['files'][0]['attrs'][0].update(rc=20,hex='00');cases.append(bad)
        bad=copy.deepcopy(value);bad['files'][0]['path']='/etc/shadow';cases.append(bad)
        for case in cases:
            with self.assertRaises(metadata.MetadataError):metadata.parse_probe(json.dumps(case).encode())

    def test_complete_capture_uses_one_checked_canonical_stage_and_private_zip(self):
        sockets=initial_sockets()+[FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),upload_peer(),
                                  FakeSocket(peer(json.dumps(probe_fixture()))),FakeSocket(peer('UGLYOS_STAGE_REMOVED\n'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets) as connect:
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'NATIVE_SECURITY_METADATA_CAPTURED')
            self.assertTrue(report['stage_cleanup_verified']);self.assertEqual(connect.call_count,6)
            self.assertEqual(len(report['stage_attempts']),1)
            self.assertTrue(report['stage_attempts'][0]['stage'].startswith('/opt/home/owner/share/uglyos-metadata-'))
            for field in ('firmware_written','vendor_script_executed','existing_security_attributes_modified','root_mode_requested'):
                self.assertFalse(report[field])
            with zipfile.ZipFile(root/'evidence.zip') as z:
                self.assertEqual(set(z.namelist()),{metadata.REPORT_NAME,'stage-preflight.response',
                                                    'probe-output.response','stage-create.response','stage-cleanup.response'})
            for path in [root/'evidence',root/'evidence.zip',*(root/'evidence').iterdir()]:
                self.assertEqual(path.stat().st_mode&0o077,0)
        commands=[f[3] for s in sockets for f in decode_all(bytes(s.sent)) if f[0]==b'OPEN']
        self.assertIn(b'/proc/self/mountinfo',commands[1])
        self.assertIn(b'shell:rm -f ',commands[-1]);self.assertNotIn(b'rm -rf',commands[-1])
        self.assertTrue(all(b'root:on' not in s.sent and b'FOTA' not in s.sent for s in sockets))

    def test_no_eligible_mount_or_invalid_preflight_makes_no_upload_or_mkdir(self):
        for raw,state in ((preflight_fixture(records={b:('MISSING',False) for b in BASES}),'NO_WRITABLE_EXECUTABLE_STAGE'),
                          (b'cat: Permission denied\n','STAGING_PREFLIGHT_INVALID')):
            sockets=initial_sockets(raw)
            with self.subTest(state=state),tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets) as connect:
                root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
                self.assertEqual(report['state'],state);self.assertEqual(connect.call_count,2)
                self.assertFalse(report['temporary_sdk_write_requested']);self.assertEqual(report['stage_attempts'],[])
                self.assertEqual((root/'evidence/stage-preflight.response').read_bytes(),raw)
                self.assertTrue(all(b'mkdir ' not in s.sent and b'sync:' not in s.sent for s in sockets))

    def test_upload_or_execution_failure_preserves_context_then_cleans_without_retry(self):
        for failure,state in (('upload','PROBE_UPLOAD_DENIED'),('run','PROBE_EXECUTION_DENIED'),('invalid','PROBE_OUTPUT_INVALID')):
            sockets=initial_sockets()+[FakeSocket(peer('UGLYOS_STAGE_CREATED\n'))]
            sockets += [upload_peer(b'FAIL\4\0\0\0nope')] if failure=='upload' else [upload_peer(),FakeSocket(peer('Permission denied\n' if failure=='run' else 'invalid\n'))]
            sockets += [FakeSocket(peer('700 5001 100 probe-label')),FakeSocket(peer('UGLYOS_STAGE_REMOVED\n')),
                        FakeSocket(peer('fixture stage context'))]
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
                root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
                self.assertEqual(report['state'],state);self.assertTrue(report['stage_cleanup_verified'])
                self.assertEqual(len(report['stage_attempts']),1)
                self.assertEqual((root/'evidence/probe-context.response').read_bytes(),b'700 5001 100 probe-label')
                if failure=='upload':self.assertEqual((root/'evidence/probe-upload.response').read_bytes(),b'FAIL\4\0\0\0nope')
                else:self.assertTrue((root/'evidence/probe-output.response').exists())

    def test_unverified_creation_never_uploads_removes_or_retries_unknown_directory(self):
        for creation,state in (('mkdir: File exists\n','SDK_STAGE_CREATION_NOT_VERIFIED'),
                               ('UGLYOS_STAGE_NOT_CREATED\n','SDK_STAGE_UNAVAILABLE')):
            sockets=initial_sockets()+[FakeSocket(peer(creation)),FakeSocket(peer('fixture context'))]
            with self.subTest(creation=creation),tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets) as connect:
                report=metadata.capture('10.0.0.65',Path('/unused'),Path(td)/'evidence')
                self.assertEqual(report['state'],state);self.assertEqual(connect.call_count,4)
                self.assertFalse(report['probe_uploaded']);self.assertEqual(len(report['stage_attempts']),1)
                self.assertEqual('unverified_sdk_stage' in report,state=='SDK_STAGE_CREATION_NOT_VERIFIED')
                self.assertTrue(all(b'rm -f' not in s.sent and b'sync:' not in s.sent for s in sockets))

    def test_cleanup_failure_is_explicit_and_retains_successful_metadata(self):
        sockets=initial_sockets()+[FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),upload_peer(),
                                  FakeSocket(peer(json.dumps(probe_fixture()))),FakeSocket(peer('rmdir failed\n')),
                                  FakeSocket(peer('fixture context'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
            report=metadata.capture('10.0.0.65',Path('/unused'),Path(td)/'evidence')
            self.assertEqual(report['state'],'SDK_STAGE_CLEANUP_UNVERIFIED')
            self.assertEqual(metadata.validate_stage(report['remaining_sdk_stage']),report['remaining_sdk_stage'])
            self.assertIsNotNone(report['probe']);self.assertEqual(len(report['stage_attempts']),1)

    def test_upload_transport_failure_still_cleans_and_does_not_retry(self):
        sockets=initial_sockets()+[FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),OSError('lost connection'),
                                  FakeSocket(peer('UGLYOS_STAGE_REMOVED\n')),FakeSocket(peer('fixture context'))]
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets):
            report=metadata.capture('10.0.0.65',Path('/unused'),Path(td)/'evidence')
            self.assertEqual(report['state'],'LOCAL_OR_SDB_IO_ERROR');self.assertTrue(report['stage_cleanup_verified'])
            self.assertEqual(len(report['stage_attempts']),1)

    def test_local_create_diagnostic_failure_still_removes_verified_stage(self):
        sockets=initial_sockets()+[FakeSocket(peer('UGLYOS_STAGE_CREATED\n')),FakeSocket(peer('UGLYOS_STAGE_REMOVED\n')),
                                  FakeSocket(peer('fixture context'))]
        real_write=metadata.private_write
        def write(path,raw):
            if path.name=='stage-create.response':raise OSError('local write failed')
            return real_write(path,raw)
        with tempfile.TemporaryDirectory() as td,patch.object(metadata,'build_probe',return_value=(elf_fixture(),{})),patch.object(socket,'create_connection',side_effect=sockets),patch.object(metadata,'private_write',side_effect=write):
            report=metadata.capture('10.0.0.65',Path('/unused'),Path(td)/'evidence')
            self.assertTrue(report['stage_cleanup_verified']);self.assertFalse(report['probe_uploaded'])

    def test_missing_compiler_and_existing_outputs_make_no_watch_connection(self):
        with tempfile.TemporaryDirectory() as td,patch.object(metadata.shutil,'which',return_value=None),patch.object(socket,'create_connection') as connect:
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual(report['state'],'CLANG_MISSING_RUN_PKG_INSTALL_CLANG');connect.assert_not_called()
            original=(root/'evidence.zip').read_bytes()
            with self.assertRaises(metadata.MetadataError):metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip')
            self.assertEqual((root/'evidence.zip').read_bytes(),original)

    def test_compiler_failure_preserves_private_diagnostic_before_watch_connection(self):
        failed=subprocess.CompletedProcess([],1,b'',b'private-compiler-detail')
        with tempfile.TemporaryDirectory() as td,patch.object(metadata.subprocess,'run',return_value=failed),patch.object(socket,'create_connection') as connect:
            root=Path(td);report=metadata.capture('10.0.0.65',Path('/unused'),root/'evidence',archive=root/'evidence.zip',compiler='/fixture/compiler')
            self.assertEqual(report['state'],'PROBE_COMPILER_FAILED');connect.assert_not_called()
            self.assertNotIn('private-compiler-detail',json.dumps(report))
            with zipfile.ZipFile(root/'evidence.zip') as z:self.assertEqual(z.read('compiler.response'),b'private-compiler-detail')


class NativeProbeProgramTests(unittest.TestCase):
    def check_inventory(self, compiler, *, arm):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);fixture=root/'fixture'
            cap=struct.pack('<5I',0x02000001,0,0x002000c2,0,0)
            for directory in metadata.INVENTORY_ROOTS:(fixture/directory.lstrip('/')).mkdir(parents=True,exist_ok=True)
            for path in metadata.TARGETS:
                file=fixture/path.lstrip('/');file.parent.mkdir(parents=True,exist_ok=True);file.touch()
                os.setxattr(file,'user.uglyos_fixture',cap)
            helper=fixture/'bin/owned-helper';helper.write_bytes(b'read only fixture');helper.chmod(0o4755)
            os.setxattr(helper,'user.uglyos_fixture',cap)
            sparse=fixture/'sbin/sparse-helper'
            with sparse.open('wb') as f:f.truncate((1<<32)+7)
            sparse.chmod(0o4755)
            os.setxattr(sparse,'user.uglyos_fixture',cap)
            (fixture/'bin/linked-helper').symlink_to(helper)
            unsafe=fixture/'bin/quote"name';unsafe.touch()
            for number in range(70):
                file=fixture/f'usr/bin/candidate-{number:02d}';file.touch();file.chmod(0o755)
                os.setxattr(file,'user.uglyos_fixture',cap)
            try:
                metadata.build_probe(root,compiler,fixture=fixture,host_test=not arm,inventory=True)
            except metadata.MetadataError as exc:
                self.fail(getattr(exc,'diagnostic',str(exc).encode()).decode('utf-8','replace'))
            command=([shutil.which('qemu-arm')] if arm else [])+[str(root/'security-metadata-probe')]
            value=json.loads(subprocess.check_output(command,timeout=20));self.assertTrue(value['test_fixture'])
            inventory=value['privilege_inventory'];metadata.validate_inventory(inventory)
            directories={d['path']:d for d in inventory['directories']}
            owned=next(r for r in directories['/bin']['files'] if r['name']=='owned-helper')
            self.assertEqual((owned['mode'],owned['uid'],owned['gid']),
                             (helper.stat().st_mode,helper.stat().st_uid,helper.stat().st_gid))
            self.assertEqual(owned['capability_hex'],cap.hex())
            self.assertEqual(owned['size_hex'],f'{helper.stat().st_size:016x}')
            self.assertEqual(next(r['size_hex'] for r in directories['/sbin']['files'] if r['name']=='sparse-helper'),
                             '0000000100000007')
            self.assertNotIn('linked-helper',[r['name'] for r in directories['/bin']['files']])
            self.assertEqual(directories['/bin']['unsafe_names'],1)
            self.assertEqual(sum(len(d['files']) for d in inventory['directories']),64)
            self.assertGreater(sum(d['dropped_records'] for d in inventory['directories']),0)
            self.assertTrue(all(d['complete'] for d in inventory['directories']))
            with self.assertRaises(metadata.MetadataError):metadata.parse_probe(json.dumps(value).encode(),inventory=True)
            # Native fixture layout is independently verified above; schema tests
            # use a synthetic copy, never claim these are watch capabilities.
            value['test_fixture']=False
            for file in value['files']:file['attrs']=file['attrs'][:3]
            metadata.parse_probe(json.dumps(value).encode(),inventory=True)
            self.assertFalse(metadata.inventory_summary(value)['scope_complete'])
            for file in (fixture/'usr/bin').iterdir():
                if file.is_file():
                    for attribute in ('user.uglyos_fixture','user.uglyos_label','user.uglyos_exec_label'):
                        os.setxattr(file,attribute,b'Z'*256)
            # Real maximum-size xattrs stress the total-output reserve as well
            # as the independent 64-record budget; output must remain valid.
            raw=subprocess.check_output(command,timeout=20)
            self.assertLessEqual(len(raw),65536)
            stressed=json.loads(raw)['privilege_inventory'];metadata.validate_inventory(stressed)
            self.assertGreater(sum(d['dropped_records'] for d in stressed['directories']),0)

    @unittest.skipUnless(shutil.which('gcc'),'host C compiler unavailable')
    def test_native_inventory_matches_real_modes_xattrs_sparse_sizes_and_bounds(self):
        self.check_inventory(shutil.which('gcc'),arm=False)

    def test_arm_inventory_matches_stat64_dirent64_and_query_abi_under_qemu(self):
        if not shutil.which('clang') or not shutil.which('qemu-arm'):
            if os.environ.get('WATCH3_REQUIRE_ARM_ELF')=='1':self.fail('Required ARM compiler/QEMU missing')
            self.skipTest('ARM compiler/QEMU unavailable locally')
        self.check_inventory(shutil.which('clang'),arm=True)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            metadata.build_probe(root,shutil.which('clang'),inventory=True)
            raw=subprocess.check_output([shutil.which('qemu-arm'),str(root/'security-metadata-probe')],timeout=20)
            metadata.parse_probe(raw,inventory=True)

    @unittest.skipUnless(shutil.which('gcc'), 'host C compiler unavailable')
    def test_real_noexec_mount_refuses_our_host_probe_despite_mode_0700(self):
        mounts=metadata.parse_mountinfo(Path('/proc/self/mountinfo').read_text())
        fixture=os.environ.get('WATCH3_NOEXEC_FIXTURE')
        if not fixture:
            if os.environ.get('WATCH3_REQUIRE_ARM_ELF')=='1':self.fail('Required real noexec fixture unavailable')
            self.skipTest('Disposable noexec mount supplied by CI')
        directory=Path(fixture)
        self.assertTrue(directory.is_dir())
        self.assertIn('noexec',metadata.containing_mount(str(directory),mounts)['options'])
        with tempfile.TemporaryDirectory() as td,tempfile.TemporaryDirectory(dir=directory,prefix='uglyos-noexec-') as nd:
            raw,_=metadata.build_probe(Path(td),shutil.which('gcc'),host_test=True)
            program=Path(nd)/'probe';program.write_bytes(raw);program.chmod(0o700)
            self.assertEqual(program.stat().st_mode&0o777,0o700)
            with self.assertRaises(PermissionError) as cm:subprocess.check_output([str(program)],timeout=5)
            self.assertEqual(cm.exception.errno,errno.EACCES)

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
