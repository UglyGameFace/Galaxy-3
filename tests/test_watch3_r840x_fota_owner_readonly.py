"""Fake SDB, typed D-Bus reply, race and private artifact regressions. NO WATCH."""
from pathlib import Path
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import watch3_r840x_fota_owner_readonly as owner
from watch3_r08_android_sdb import Connection, FOTA_OWNER_REGISTRY_PROBES, SdbError
from watch3_r08_fota_artifact_pull import ArtifactPullError, vendor_executable_path, _receive_arm_elf
from test_watch3_r08_android_sdb import FakeSocket, peer, decode_all
from test_watch3_r08_fota_artifact_pull import elf32, sdb_peer, SYNC_HDR, requests

HEADER='method return time=1.0 sender=org.freedesktop.DBus -> destination=:1.99 serial=3 reply_serial=2\n'
BUS_ID='a'*32
EXE='/usr/bin/fota-consumer'


def reply(kind,value):
    return HEADER+(f'   string "{value}"\n' if kind in ('id','owner') else f'   uint32 {value}\n')


class Queries:
    def __init__(self):
        self.calls=[]
        self.owner_reads=0
        self.id_reads=0
        self.path_reads=0
        self.fail_operation=None
        self.change_owner_after=None
        self.change_id_after=None
        self.change_path_after=None

    def __call__(self,ip,key,operation,**kwargs):
        self.calls.append((operation,kwargs))
        if operation==self.fail_operation:
            raise owner.OwnerError('NO_CURRENT_FOTA_OWNER')
        if operation=='fota_registry_id':
            self.id_reads+=1
            return reply('id',('b'*32 if self.change_id_after and self.id_reads>=self.change_id_after else BUS_ID))
        if operation=='fota_registry_owner':
            self.owner_reads+=1
            return reply('owner',(':1.101' if self.change_owner_after and self.owner_reads>=self.change_owner_after else ':1.100'))
        if operation=='fota_registry_pid':return reply('pid',2345)
        if operation=='fota_registry_uid':return reply('uid',0)
        if operation=='process_executable':
            self.path_reads+=1
            return ('/usr/bin/other' if self.change_path_after and self.path_reads>=self.change_path_after else EXE)+'\n'
        raise AssertionError(operation)


class ExistingFotaOwnerTests(unittest.TestCase):
    def test_registry_commands_target_bus_daemon_without_activation(self):
        for operation,command in FOTA_OWNER_REGISTRY_PROBES.items():
            self.assertIn('--system',command)
            self.assertIn('--dest=org.freedesktop.DBus ',command)
            self.assertIn('/org/freedesktop/DBus org.freedesktop.DBus.',command)
            self.assertIn('--reply-timeout=1500',command)
            for forbidden in ('Launch','DeleteTempFile','StartService','Introspect','--dest=fota.consumer',';','|','>'):
                self.assertNotIn(forbidden,command)
            sock=FakeSocket(peer(reply('owner',':1.100')))
            conn=Connection(sock,Path('/unused'));conn.handshake();conn.shell(operation)
            emitted=decode_all(bytes(sock.sent))
            self.assertEqual(emitted[1][3],('shell:'+command+'\0').encode())

    def test_proc_link_accepts_bounded_integer_only(self):
        for bad in (0,-1,4194305,True,'1; reboot','1','../mem',None):
            sock=FakeSocket(b'')
            with self.assertRaises(SdbError):Connection(sock,Path('/unused')).process_executable(bad)
            self.assertEqual(sock.sent,b'')
        sock=FakeSocket(peer(EXE+'\n'))
        c=Connection(sock,Path('/unused'));c.handshake();c.process_executable(2345)
        self.assertEqual(decode_all(bytes(sock.sent))[1][3],b'shell:readlink /proc/2345/exe\0')

    def test_typed_reply_parser_and_error_categories(self):
        for kind,value in [('id',BUS_ID),('owner',':1.17'),('pid',123),('uid',0)]:
            self.assertEqual(owner.parse_reply(reply(kind,value),kind),value)
        for text,category in [
            ('Error org.freedesktop.DBus.Error.NameHasNoOwner: private','NO_CURRENT_FOTA_OWNER'),
            ('Error org.freedesktop.DBus.Error.AccessDenied: private','REGISTRY_QUERY_DENIED'),
            ('sh: dbus-send: not found','REGISTRY_TOOL_UNAVAILABLE')]:
            with self.assertRaisesRegex(owner.OwnerError,category):owner.parse_reply(text,'owner')

    def test_malformed_or_injected_replies_cannot_become_identity(self):
        for kind,value in [('pid',0),('pid',4194305),('uid',4294967296),('owner',':1.2;id'),
                           ('id','private serial'),('pid','-1'),('uid','01')]:
            with self.subTest(kind=kind,value=value):
                with self.assertRaises(owner.OwnerError):owner.parse_reply(reply(kind,value),kind)
        for text in ('string ":1.5"',HEADER+'string ":1.5"\nuint32 0','x'*2049,'',None):
            with self.assertRaises(owner.OwnerError):owner.parse_reply(text,'owner')

    def test_vendor_path_rejects_raw_devices_injection_traversal_deleted_and_unrelated_user_files(self):
        self.assertEqual(vendor_executable_path(EXE+'\n'),EXE.encode())
        for path in ('/dev/mmcblk0','/proc/1/mem','/usr/bin/../secret','/usr/bin/x;id',
                     '/home/owner/personal.bin','/usr/bin/x (deleted)','/usr/bin//x','/usr/bin/',
                     EXE+'\nsecret',EXE+'\x00',EXE+'\n\n'):
            with self.subTest(path=path):
                with self.assertRaises(ArtifactPullError):vendor_executable_path(path)

    def test_denied_or_missing_process_link_is_not_misreported_as_binary_failure(self):
        for text,category in [('readlink: /proc/private/exe: Permission denied','OWNER_PROCESS_LINK_ACCESS_DENIED'),
                              ('readlink: no such file or directory','OWNER_PROCESS_LINK_UNAVAILABLE'),
                              ('private unexpected text','OWNER_PROCESS_LINK_UNRECOGNIZED')]:
            q=Queries()
            def observed(ip,key,operation,**kwargs):
                return text if operation=='process_executable' else q(ip,key,operation,**kwargs)
            with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query',observed),patch.object(owner,'_receive_arm_elf') as reader:
                r=owner.capture('127.0.0.1',Path('/unused'),Path(tmp)/'evidence',copy_binary=True)
                self.assertEqual(r['state'],category);self.assertNotIn('artifact_error',r)
                self.assertNotIn('private',json.dumps(r));reader.assert_not_called()

    def test_shared_arm_reader_sends_exact_observed_recv_and_never_send_or_shell(self):
        binary=elf32(b'owner-fixture')
        sock=sdb_peer([SYNC_HDR.pack(b'DATA',len(binary))+binary,SYNC_HDR.pack(b'DONE',0)])
        out=io.BytesIO();r=_receive_arm_elf(sock,Path('/unused'),out,EXE.encode())
        self.assertEqual(out.getvalue(),binary)
        self.assertEqual(requests(bytes(sock.sent))[2][3],SYNC_HDR.pack(b'RECV',len(EXE))+EXE.encode())
        self.assertEqual(r['bytes'],len(binary))
        self.assertNotIn(b'SEND',sock.sent);self.assertNotIn(b'shell:',sock.sent)
        for path in (b'/dev/mmcblk0',b'/proc/1/mem',b'/usr/bin/../x'):
            with self.assertRaises(ArtifactPullError):_receive_arm_elf(None,Path('/unused'),out,path)

    def test_observation_only_does_not_copy_or_infer_root(self):
        queries=Queries()
        with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query',queries),patch.object(owner,'_receive_arm_elf') as reader:
            dest=Path(tmp)/'evidence'
            r=owner.capture('127.0.0.1',Path('/unused'),dest)
            self.assertEqual(r['state'],'EXISTING_FOTA_OWNER_EXECUTABLE_OBSERVED')
            self.assertTrue(r['owner_snapshot_stable'])
            self.assertNotIn('flash_allowed',r)
            self.assertEqual(r['result'],'EVIDENCE_ONLY')
            self.assertEqual(r['schema'],'uglyos-r840x-existing-fota-owner-v2')
            self.assertEqual(r['owner_uid'],0);self.assertFalse(r['root_obtained'])
            self.assertFalse(r['binary_copied']);reader.assert_not_called()
            saved=(dest/owner.REPORT).read_text()
            self.assertNotIn(BUS_ID,saved);self.assertNotIn(':1.100',saved);self.assertNotIn('2345',saved)
            self.assertEqual(dest.stat().st_mode&0o777,0o700)
            self.assertEqual((dest/owner.REPORT).stat().st_mode&0o777,0o600)

    def test_missing_owner_stops_without_pid_proc_or_copy(self):
        q=Queries();q.fail_operation='fota_registry_owner'
        with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query',q),patch.object(owner,'_receive_arm_elf') as reader:
            dest=Path(tmp)/'evidence';r=owner.capture('127.0.0.1',Path('/unused'),dest,copy_binary=True)
            self.assertEqual(r['state'],'NO_CURRENT_FOTA_OWNER');reader.assert_not_called()
            self.assertEqual([x[0] for x in q.calls],['fota_registry_id','fota_registry_owner'])
            self.assertEqual([p.name for p in dest.iterdir()],[owner.REPORT])

    def test_owner_or_bus_restart_before_copy_rejects_identity(self):
        for attribute in ('change_owner_after','change_id_after'):
            q=Queries();setattr(q,attribute,2)
            with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query',q),patch.object(owner,'_receive_arm_elf') as reader:
                dest=Path(tmp)/'evidence';r=owner.capture('127.0.0.1',Path('/unused'),dest,copy_binary=True)
                self.assertEqual(r['state'],'FOTA_OWNER_CHANGED_DURING_OBSERVATION')
                self.assertFalse(r['owner_snapshot_stable']);reader.assert_not_called()

    def test_copy_from_observed_owner_reuses_reader_and_publishes_only_after_recheck(self):
        q=Queries();binary=elf32(b'test-owner')
        def read(sock,key,out,path):
            self.assertEqual(path,EXE.encode());out.write(binary)
            return {'bytes':len(binary),'sha256':'test-fixture-only','elf_kind':'ARM_ELF32'}
        with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query',q),patch.object(owner.socket,'create_connection',return_value=FakeSocket(b'')),patch.object(owner,'_receive_arm_elf',read):
            dest=Path(tmp)/'evidence';r=owner.capture('127.0.0.1',Path('/unused'),dest,copy_binary=True)
            self.assertTrue(r['binary_copied']);self.assertEqual((dest/owner.BINARY).read_bytes(),binary)
            self.assertEqual((dest/owner.BINARY).stat().st_mode&0o777,0o600)
            self.assertEqual(set(p.name for p in dest.iterdir()),{owner.REPORT,owner.BINARY})
            self.assertEqual(q.path_reads,2);self.assertEqual(q.owner_reads,4)

    def test_identity_change_during_copy_discards_private_temporary_bytes(self):
        for attribute in ('change_owner_after','change_id_after','change_path_after'):
            q=Queries();setattr(q,attribute,3 if attribute!='change_path_after' else 2)
            def read(sock,key,out,path):
                out.write(elf32());return {'bytes':len(elf32()),'sha256':'fixture','elf_kind':'ARM_ELF32'}
            with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query',q),patch.object(owner.socket,'create_connection',return_value=FakeSocket(b'')),patch.object(owner,'_receive_arm_elf',read):
                dest=Path(tmp)/'evidence';r=owner.capture('127.0.0.1',Path('/unused'),dest,copy_binary=True)
                self.assertFalse(r['binary_copied']);self.assertFalse(r['owner_snapshot_stable'])
                self.assertIsNone(r['observed_executable'])
                self.assertEqual([p.name for p in dest.iterdir()],[owner.REPORT])

    def test_denied_binary_read_is_not_success_and_preserves_existing_snapshot_only(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query',Queries()),patch.object(owner.socket,'create_connection',return_value=FakeSocket(b'')),patch.object(owner,'_receive_arm_elf',side_effect=ArtifactPullError('REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE')):
            dest=Path(tmp)/'evidence';r=owner.capture('127.0.0.1',Path('/unused'),dest,copy_binary=True)
            self.assertEqual(r['state'],'OWNER_ARTIFACT_READ_REJECTED');self.assertFalse(r['binary_copied'])
            self.assertEqual([p.name for p in dest.iterdir()],[owner.REPORT])

    def test_existing_output_or_invalid_ip_never_connects(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(owner,'query') as query:
            dest=Path(tmp)/'exists';dest.mkdir();(dest/'user.txt').write_text('keep')
            with self.assertRaises(FileExistsError):owner.capture('127.0.0.1',Path('/unused'),dest)
            with self.assertRaises(SdbError):owner.capture('8.8.8.8',Path('/unused'),Path(tmp)/'new')
            query.assert_not_called();self.assertEqual((dest/'user.txt').read_text(),'keep')

    def test_query_rejects_arbitrary_operation_or_pid_before_socket(self):
        with patch.object(owner.socket,'create_connection') as connect:
            for op,pid in [('Launch',None),('process_executable','1;id'),('process_executable',True)]:
                with self.assertRaises(owner.OwnerError):owner.query('127.0.0.1',Path('/unused'),op,pid=pid)
            connect.assert_not_called()


if __name__=='__main__':unittest.main()
