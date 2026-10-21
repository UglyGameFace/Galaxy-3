"""Synthetic regression tests for the packaged Watch3 LinuxFB QPA validator."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_watch3_qt_linuxfb_package import validate_package


def fake_shared_object(machine=183, elf_class=2, kind=3):
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = 1
    struct.pack_into("<HH", header, 16, kind, machine)
    return bytes(header)


class TestLinuxFBPackage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugin = (self.root / "qtbase-plugins" / "usr" / "lib" /
                       "qt6" / "plugins" / "platforms" / "libqlinuxfb.so")
        self.plugin.parent.mkdir(parents=True)
        self.plugin.write_bytes(fake_shared_object())

    def test_valid_aarch64_platform_plugin(self):
        self.assertEqual(validate_package(self.root), [])

    def test_missing_package(self):
        self.plugin.unlink()
        self.assertTrue(validate_package(self.root / "no-package"))

    def test_missing_plugin(self):
        self.plugin.unlink()
        self.assertIn("found 0", validate_package(self.root)[0])

    def test_wrong_platform_directory(self):
        other = self.plugin.parent.parent / "imageformats" / self.plugin.name
        other.parent.mkdir()
        self.plugin.rename(other)
        self.assertIn("outside the Qt platforms directory", validate_package(self.root)[0])

    def test_wrong_architecture(self):
        self.plugin.write_bytes(fake_shared_object(machine=62))
        self.assertIn("not an AArch64", validate_package(self.root)[0])

    def test_wrong_object_type(self):
        self.plugin.write_bytes(fake_shared_object(kind=2))
        self.assertIn("not an AArch64 shared object", validate_package(self.root)[0])

    def test_not_elf(self):
        self.plugin.write_bytes(b"broken")
        self.assertIn("not a complete ELF64 header", validate_package(self.root)[0])

    def test_wrong_class(self):
        self.plugin.write_bytes(fake_shared_object(elf_class=1))
        self.assertIn("not a little-endian ELF64", validate_package(self.root)[0])

    def test_multiple_plugins(self):
        other = self.root / "qtbase-plugins" / "opt" / "qt6" / "plugins" / "platforms" / self.plugin.name
        other.parent.mkdir(parents=True)
        other.write_bytes(fake_shared_object())
        self.assertIn("found 2", validate_package(self.root)[0])


if __name__ == "__main__":
    unittest.main()
