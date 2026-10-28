"""Synthetic ELF interpreter and QEMU dynamic-loader checks, no firmware/device."""
from __future__ import annotations

from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import watch3_r08_qemu_launcher_closure as tool


def fake_elf(interpreter: bytes | None = None) -> bytes:
    blob=bytearray(512)
    blob[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH",blob,16,3,183)
    if interpreter is not None:
        struct.pack_into("<Q",blob,32,64)
        struct.pack_into("<HH",blob,54,56,1)
        struct.pack_into("<I",blob,64,3)
        struct.pack_into("<Q",blob,64+8,160)
        struct.pack_into("<Q",blob,64+32,len(interpreter))
        blob[160:160+len(interpreter)]=interpreter
    return bytes(blob)


class LauncherClosureTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        (self.root/"usr/bin").mkdir(parents=True)
        (self.root/"lib").mkdir()
        (self.root/"usr/bin/asteroid-launcher").write_bytes(
            fake_elf(b"/lib/ld-linux-aarch64.so.1\x00"))
        (self.root/"lib/ld-linux-aarch64.so.1").write_bytes(fake_elf())

    def test_real_elf_pt_interp_read_from_program_headers(self):
        self.assertEqual(tool.guest_interpreter(self.root/"usr/bin/asteroid-launcher"),
                         "/lib/ld-linux-aarch64.so.1")

    def test_missing_pt_interp_is_not_guessed(self):
        data=bytearray(fake_elf())
        struct.pack_into("<Q",data,32,64)
        struct.pack_into("<HH",data,54,56,1)
        struct.pack_into("<I",data,64,0)  # valid table; no PT_INTERP
        (self.root/"usr/bin/asteroid-launcher").write_bytes(data)
        with self.assertRaisesRegex(tool.ClosureError,"MISSING_OR_DUPLICATE"):
            tool.guest_interpreter(self.root/"usr/bin/asteroid-launcher")

    def test_rejects_host_file_interpreter_traversal(self):
        (self.root/"usr/bin/asteroid-launcher").write_bytes(
            fake_elf(b"/lib/../../tmp/evil-loader\x00"))
        with self.assertRaisesRegex(tool.ClosureError,"UNSAFE"):
            tool.guest_interpreter(self.root/"usr/bin/asteroid-launcher")

    def test_rejects_wrong_non_aarch64_loader(self):
        (self.root/"lib/ld-linux-aarch64.so.1").write_bytes(fake_elf()[:18]+b"\x3e"+
                       fake_elf()[19:])
        with self.assertRaises(ValueError):
            tool.rooted_link(self.root,"/lib/ld-linux-aarch64.so.1")

    def test_resolves_absolute_guest_symlink_under_root(self):
        (self.root/"usr/lib").mkdir()
        dest=self.root/"usr/lib/ld-linux-aarch64.so.1"
        dest.write_bytes(fake_elf())
        (self.root/"lib/ld-linux-aarch64.so.1").unlink()
        (self.root/"lib/ld-linux-aarch64.so.1").symlink_to("/usr/lib/ld-linux-aarch64.so.1")
        self.assertEqual(tool.rooted_link(self.root,"/lib/ld-linux-aarch64.so.1"),dest)

    def test_real_qemu_loader_resolution_requires_qt_dependency(self):
        fake=subprocess.CompletedProcess([],0,
            "libQt6Core.so.6 => /usr/lib/libQt6Core.so.6\n"
            "libQt6WaylandCompositor.so.6 => /usr/lib/libQt6WaylandCompositor.so.6\n","")
        with patch.object(tool.shutil,"which",return_value="/usr/bin/qemu-aarch64"),\
             patch.object(tool.subprocess,"run",return_value=fake) as runner:
            result=tool.check(self.root)
        self.assertEqual(result["result"],"REAL_ARM64_LAUNCHER_DYNAMIC_DEPENDENCIES_RESOLVED")
        self.assertEqual(result["qt6_dependency_count"],2)
        self.assertFalse(result["launchers_main_function_called"])
        self.assertFalse(result["flash_allowed"])
        args=runner.call_args.args[0]
        self.assertEqual(args[:3],["qemu-aarch64","-L",str(self.root)])
        self.assertEqual(args[-2:],
            ["--list",str(self.root/"usr/bin/asteroid-launcher")])
        self.assertNotIn("GITHUB_TOKEN",runner.call_args.kwargs["env"])

    def test_missing_qt_dependencies_cannot_claim_success(self):
        fake=subprocess.CompletedProcess([],0,"libc.so.6 => /lib/libc.so.6\n","")
        with patch.object(tool.shutil,"which",return_value="/usr/bin/qemu-aarch64"),\
             patch.object(tool.subprocess,"run",return_value=fake):
            with self.assertRaisesRegex(tool.ClosureError,"NO_QT6_LIBRARIES"):
                tool.check(self.root)

    def test_nonzero_exit_or_missing_dependency_is_rejected(self):
        for rc, output in ((127,"libQt6Core.so.6 => not found"),(0,"libQt6Core.so.6 => not found")):
            with self.subTest(rc=rc):
                fake=subprocess.CompletedProcess([],rc,output,"")
                with patch.object(tool.shutil,"which",return_value="/usr/bin/qemu-aarch64"),\
                     patch.object(tool.subprocess,"run",return_value=fake):
                    with self.assertRaises(tool.ClosureError):
                        tool.check(self.root)

    def test_launcher_symlink_to_outside_host_is_blocked(self):
        launcher=self.root/"usr/bin/asteroid-launcher"
        launcher.unlink()
        launcher.symlink_to("/bin/sh")
        with self.assertRaises(tool.ClosureError):
            tool.check(self.root)


if __name__=="__main__":
    unittest.main()
