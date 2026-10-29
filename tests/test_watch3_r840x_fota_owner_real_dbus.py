"""Real PRIVATE host D-Bus, real owner process and proc link. NO WATCH/SDB LAN.

The query adapter replaces only the SDB link with execution of the exact
allowlisted CLI commands on an isolated bus. This is not Watch3 execution.
"""
from pathlib import Path
import os
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import watch3_r840x_fota_owner_readonly as owner
from watch3_r08_android_sdb import FOTA_OWNER_REGISTRY_PROBES

OWNER_PROCESS = r'''
import ctypes,sys
dbus=ctypes.CDLL('libdbus-1.so.3')
dbus.dbus_connection_open_private.argtypes=[ctypes.c_char_p,ctypes.c_void_p]
dbus.dbus_connection_open_private.restype=ctypes.c_void_p
dbus.dbus_bus_register.argtypes=[ctypes.c_void_p,ctypes.c_void_p]
dbus.dbus_bus_register.restype=ctypes.c_int
dbus.dbus_bus_request_name.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_uint,ctypes.c_void_p]
dbus.dbus_bus_request_name.restype=ctypes.c_int
dbus.dbus_connection_set_exit_on_disconnect.argtypes=[ctypes.c_void_p,ctypes.c_int]
dbus.dbus_connection_close.argtypes=[ctypes.c_void_p]
dbus.dbus_connection_unref.argtypes=[ctypes.c_void_p]
conn=dbus.dbus_connection_open_private(sys.argv[1].encode(),None)
assert conn and dbus.dbus_bus_register(conn,None)
dbus.dbus_connection_set_exit_on_disconnect(conn,0)
assert dbus.dbus_bus_request_name(conn,b'fota.consumer',4,None)==1
print('OWNER_READY',flush=True)
sys.stdin.buffer.read(1)
dbus.dbus_connection_close(conn)
dbus.dbus_connection_unref(conn)
'''


@unittest.skipUnless(shutil.which('dbus-daemon') and shutil.which('dbus-send')
                     and Path('/usr/bin/python3').exists() or
                     os.environ.get('WATCH3_REQUIRE_PRIVATE_DBUS')=='1',
                     'private D-Bus tools unavailable')
class RealPrivateBusTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        services=self.root/'services';services.mkdir()
        self.marker=self.root/'unexpected-activation'
        (services/'fota.consumer.service').write_text(
            '[D-BUS Service]\nName=fota.consumer\nExec=/usr/bin/touch '+str(self.marker)+'\n')
        config=self.root/'bus.conf'
        config.write_text('<busconfig><type>session</type><listen>unix:path='+
                          str(self.root/'bus')+'</listen><servicedir>'+str(services)+
                          '</servicedir><policy context="default"><allow user="*"/>'
                          '<allow own="*"/><allow send_destination="*"/>'
                          '<allow receive_sender="*"/></policy></busconfig>')
        self.daemon=subprocess.Popen(['dbus-daemon','--nofork','--print-address=1',
                                      '--config-file='+str(config)],stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,text=True)
        self.addCleanup(self.stop_process,self.daemon)
        self.assertTrue(select.select([self.daemon.stdout],[],[],3)[0], 'private bus startup timed out')
        self.address=self.daemon.stdout.readline().strip()
        if not self.address:
            self.daemon.wait(timeout=3)
            error=self.daemon.stderr.read(2000)
            if 'Operation not permitted' in error and os.environ.get('WATCH3_REQUIRE_PRIVATE_DBUS')!='1':
                self.skipTest('local environment forbids sockets; real private bus is required in CI')
            self.fail('Private bus failed to start: '+error)
        self.assertTrue(self.address.startswith('unix:path='+str(self.root/'bus')))
        self.env={**os.environ,'DBUS_SYSTEM_BUS_ADDRESS':self.address}

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        for pipe in (process.stdin,process.stdout,process.stderr):
            if pipe:pipe.close()

    def query_on_private_host(self,ip,key,operation,*,pid=None,timeout=8):
        if operation=='process_executable':
            self.assertEqual(pid,self.fixture.pid)
            command=['readlink',f'/proc/{pid}/exe']
        else:
            command=shlex.split(FOTA_OWNER_REGISTRY_PROBES[operation])
            self.assertIn('--dest=org.freedesktop.DBus',command)
        result=subprocess.run(command,env=self.env,text=True,capture_output=True,timeout=4)
        return result.stdout+result.stderr

    def test_no_owner_does_not_activate_available_service(self):
        with patch.object(owner,'query',self.query_on_private_host):
            r=owner.capture('127.0.0.1',Path('/unused'),self.root/'evidence',copy_binary=True)
        self.assertEqual(r['state'],'NO_CURRENT_FOTA_OWNER')
        self.assertFalse(self.marker.exists())
        self.assertFalse(r['service_activation_requested'])
        self.assertFalse(r['binary_copied'])

    def test_existing_process_pid_uid_and_executable_are_observed_without_service_rpc(self):
        self.fixture=subprocess.Popen(['/usr/bin/python3','-c',OWNER_PROCESS,self.address],
                                      stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,text=True)
        self.addCleanup(self.stop_process,self.fixture)
        self.assertTrue(select.select([self.fixture.stdout],[],[],3)[0])
        self.assertEqual(self.fixture.stdout.readline().strip(),'OWNER_READY')
        with patch.object(owner,'query',self.query_on_private_host):
            r=owner.capture('127.0.0.1',Path('/unused'),self.root/'evidence')
        self.assertEqual(r['state'],'EXISTING_FOTA_OWNER_EXECUTABLE_OBSERVED')
        self.assertEqual(r['owner_uid'],os.getuid())
        self.assertEqual(r['observed_executable'],os.readlink(f'/proc/{self.fixture.pid}/exe'))
        self.assertTrue(r['owner_snapshot_stable'])
        self.assertFalse(self.marker.exists())
        self.assertFalse(r['root_obtained'])
        self.assertFalse(r['fota_method_called'])


if __name__=='__main__':unittest.main()
