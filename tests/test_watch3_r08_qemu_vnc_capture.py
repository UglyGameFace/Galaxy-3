"""Synthetic ONLY RFB 3.3 protocol fixtures for no-network ARM64 capture.

The complete actual R840X-style OS guest is exercised by GitHub Actions;
these tests do NOT assert the target binary exists or a real pixel was seen.
"""
from __future__ import annotations

from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest

from PIL import Image
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r08_qemu_vnc_capture as visual


def fake_elf(machine=183):
    b=bytearray(256)
    b[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH",b,16,3,machine)
    return bytes(b)


def read(sock,size):
    data=bytearray()
    while len(data)<size:
        block=sock.recv(size-len(data))
        if not block:
            raise EOFError()
        data.extend(block)
    return bytes(data)


def fake_server(sock, *, malformed=None):
    try:
        sock.sendall(b"RFB 003.003\n" if malformed != "version" else b"RFB 010.010\n")
        if malformed == "version":
            return
        assert read(sock,12)==b"RFB 003.003\n"
        sock.sendall(struct.pack(">I",2 if malformed=="auth" else 1))
        if malformed == "auth":
            return
        assert read(sock,1)==b"\x01"
        fmt=struct.pack(">BBBBHHHBBBxxx",32,24,0,1,255,255,255,16,8,0)
        dimensions=(700,360) if malformed=="dimensions" else visual.SIZE
        name=b"Qt for Embedded Linux VNC Server"
        sock.sendall(struct.pack(">HH",*dimensions)+fmt+
                     struct.pack(">I",len(name))+name)
        if malformed == "dimensions":
            return
        assert len(read(sock,20))==20  # client SetPixelFormat
        assert len(read(sock,8))==8    # client raw SetEncodings
        req=read(sock,10)
        assert req[0]==3 and req[1]==0
        assert req[2:]==struct.pack(">HHHH",0,0,360,360)
        red_pixel=b"\x00\x00\xff\x00" # BGRA (R=255)
        pixels=red_pixel * (360*360)
        if malformed=="nonraw":
            sock.sendall(b"\x00\x00\x00\x01"+
                         struct.pack(">HHHHi",0,0,360,360,5))
            return
        sock.sendall(b"\x00\x00\x00\x01"+
                     struct.pack(">HHHHi",0,0,360,360,0)+pixels)
    finally:
        sock.close()


class OfflineRFBSafetyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.interfaces=self.root/"netdev"
        self.interfaces.mkdir()
        (self.interfaces/"lo").mkdir()
        self.guest=self.root/"guest"
        self.guest.mkdir()
        (self.guest/"usr/lib/plugins/platforms").mkdir(parents=True)
        self.plugin=self.guest/"usr/lib/plugins/platforms/libqvnc.so"
        self.plugin.write_bytes(fake_elf())

    def test_only_loopback_is_permitted(self):
        self.assertEqual(visual.require_network_isolation(self.interfaces),["lo"])

    def test_any_non_loopback_interface_blocks_unauthenticated_vnc(self):
        (self.interfaces/"eth0").mkdir()
        with self.assertRaisesRegex(visual.RfbError, "REFUSING_NETWORKED_NAMESPACE"):
            visual.require_network_isolation(self.interfaces)

    def test_real_target_qvnc_plugin_candidate_architecture(self):
        self.assertEqual(visual.find_arm64_qvnc(self.guest),self.plugin)

    def test_absent_guest_qvnc_must_not_use_host_plugin(self):
        self.plugin.unlink()
        with self.assertRaisesRegex(visual.RfbError,"ABSENT_OR_AMBIGUOUS"):
            visual.find_arm64_qvnc(self.guest)

    def test_wrong_architecture_qvnc_rejected(self):
        self.plugin.write_bytes(fake_elf(machine=62))
        with self.assertRaisesRegex(visual.RfbError,"NOT_AARCH64"):
            visual.find_arm64_qvnc(self.guest)

    def test_host_symlink_escape_rejected(self):
        self.plugin.unlink()
        self.plugin.symlink_to("/usr/bin/true")
        with self.assertRaisesRegex(visual.RfbError,"ESCAPES_TARGET_ROOT"):
            visual.find_arm64_qvnc(self.guest)

    def use_protocol(self, malformed=None):
        client,server=socket.socketpair()
        client.settimeout(3)
        worker=threading.Thread(target=fake_server,args=(server,),
                                kwargs={"malformed":malformed},daemon=True)
        worker.start()
        return client,worker

    def test_full_raw_360x360_rectangle_decoded_from_rfb_bytes(self):
        conn,worker=self.use_protocol()
        with conn:
            w,h=visual.handshake(conn)
            self.assertEqual((w,h),(360,360))
            image=Image.new("RGB",(w,h))
            image,rects=visual.framebuffer_update(conn,w,h,image)
            self.assertEqual(rects,1)
            self.assertEqual(image.getpixel((0,0)),(255,0,0))
            self.assertEqual(image.getpixel((359,359)),(255,0,0))
            self.assertFalse(visual.metrics(image)["nonuniform_real_pixels"])
        worker.join(3)
        self.assertFalse(worker.is_alive())

    def test_unknown_rfb_version_rejected(self):
        conn,worker=self.use_protocol("version")
        with conn:
            with self.assertRaisesRegex(visual.RfbError,"PROTOCOL"):
                visual.handshake(conn)
        worker.join(3)

    def test_rfb_auth_never_negotiates_a_password(self):
        conn,worker=self.use_protocol("auth")
        with conn:
            with self.assertRaisesRegex(visual.RfbError,"AUTHENTICATION"):
                visual.handshake(conn)
        worker.join(3)

    def test_unexpected_dimensions_rejected(self):
        conn,worker=self.use_protocol("dimensions")
        with conn:
            with self.assertRaisesRegex(visual.RfbError,"DIMENSIONS"):
                visual.handshake(conn)
        worker.join(3)

    def test_nonraw_framebuffer_encoding_rejected(self):
        conn,worker=self.use_protocol("nonraw")
        with conn:
            w,h=visual.handshake(conn)
            with self.assertRaisesRegex(visual.RfbError,"NONRAW"):
                visual.framebuffer_update(conn,w,h,Image.new("RGB",(w,h)))
        worker.join(3)

    def test_nonblank_gradient_required_for_success(self):
        image=Image.new("RGB", visual.SIZE)
        for row in range(360):
            for col in range(360):
                image.putpixel((col,row),(col % 256, row % 256,(row+col)%256))
        self.assertTrue(visual.metrics(image)["nonuniform_real_pixels"])
        self.assertGreater(visual.metrics(image)["maximum_rgb_channel_spread"],12)

    def test_invalid_rfb_length_is_rejected_before_allocation(self):
        a,b=socket.socketpair()
        with a,b:
            with self.assertRaisesRegex(visual.RfbError,"LENGTH_OUT_OF_BOUNDS"):
                visual.exactly(a,10_000_000)


if __name__=="__main__":
    unittest.main()
