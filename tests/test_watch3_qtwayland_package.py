"""Post-build QtWayland packaging tests; synthetic ARM64 ELF isn't executable."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_watch3_qtwayland_package import validate_package


def elf(machine=183, kind=3, bits=2):
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = bits
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, kind, machine, 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, 1)
    phdr = bytearray(56)
    struct.pack_into("<I", phdr, 0, 1)
    return bytes(header + phdr)


class TestQtWaylandPackage(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "packages-split"
        self.lib = self.root / "qtwayland/usr/lib/libQt6WaylandCompositor.so.6.11.3"
        self.plugin = self.root / "qtwayland-plugins/usr/lib/qt6/plugins/platforms/libqwayland-generic.so"
        self.lib.parent.mkdir(parents=True)
        self.lib.write_bytes(elf())

    def assert_problem(self, expected):
        errors = validate_package(self.root)
        self.assertTrue(any(expected in e for e in errors), errors)

    def test_compositor_only_package_passes_with_aarch64_elf(self):
        # Since Qt 6.10, the Wayland client QPA is built in QtBase.
        self.assertEqual(validate_package(self.root), [])

    def test_optional_qtwayland_plugin_is_checked_when_present(self):
        self.plugin.parent.mkdir(parents=True)
        self.plugin.write_bytes(elf())
        self.assertEqual(validate_package(self.root), [])

    def test_optional_plugin_wrong_architecture_rejected(self):
        self.plugin.parent.mkdir(parents=True)
        self.plugin.write_bytes(elf(machine=62))
        self.assert_problem("QtWayland plugin is not ARM64")

    def test_valid_versioned_so_symlink_does_not_duplicate_or_leave_pkg(self):
        (self.lib.parent / "libQt6WaylandCompositor.so.6").symlink_to(self.lib.name)
        self.assertEqual(validate_package(self.root), [])

    def test_missing_compositor_runtime_package(self):
        self.lib.unlink()
        self.lib.parent.rmdir()
        self.assert_problem("missing ABI-versioned")

    def test_missing_compositor_library(self):
        self.lib.unlink()
        self.assert_problem("missing ABI-versioned")

    def test_wrong_cpu_library(self):
        self.lib.write_bytes(elf(machine=62))
        self.assert_problem("compositor library has no valid ARM64")

    def test_header_only_library_rejected(self):
        self.lib.write_bytes(elf()[:64])
        self.assert_problem("compositor library has no valid ARM64")

    def test_external_symlink_is_rejected(self):
        self.plugin.parent.mkdir(parents=True)
        escaping = self.plugin.parent / "external.so"
        escaping.symlink_to("/etc/passwd")
        self.assert_problem("external packaged symlink")

    def test_not_confused_by_host_elf(self):
        self.lib.write_bytes(elf(machine=62))
        self.plugin.parent.mkdir(parents=True)
        self.plugin.write_bytes(elf(machine=62))
        self.assert_problem("compositor library has no valid ARM64")
        self.assert_problem("QtWayland plugin is not ARM64")


if __name__ == "__main__":
    unittest.main()
