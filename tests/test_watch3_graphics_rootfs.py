"""Fixture-based actual-file checks; never pretend fake ELF fixtures ran on ARM64."""
from pathlib import Path
import tempfile
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from validate_watch3_graphics_rootfs import elf_aarch64, validate, REQUIRED_MANIFEST


def elf(machine=183, bits=2):
    header = bytearray(64)
    header[:4] = b'\x7fELF'
    header[4] = bits
    header[5] = 1  # little-endian ARM64
    header[6] = 1  # ELF version
    header[16:18] = (3).to_bytes(2, 'little')  # ET_DYN
    header[18:20] = machine.to_bytes(2, 'little')
    header[20:24] = (1).to_bytes(4, 'little')
    header[52:54] = (64).to_bytes(2, 'little')
    return bytes(header)

class TestGraphicsRootfs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'rootfs'
        self.root.mkdir()
        self.write('var/lib/environment/compositor/10-platform.conf',
                   'QT_QPA_PLATFORM=linuxfb\nQT_QUICK_BACKEND=software\nQT_QPA_FB_DRM=0\n')
        self.write('usr/lib/systemd/user/asteroid-launcher.service',
                   'EnvironmentFile=-/var/lib/environment/compositor/*.conf\n')
        for path in ('usr/bin/asteroid-launcher',
                     'usr/lib/plugins/platforms/libqlinuxfb.so',
                     'usr/lib/plugins/platforms/libqwayland-generic.so',
                     'usr/lib/libQt6WaylandCompositor.so.6.11.3'):
            self.write(path, elf())
        self.write('usr/lib/qml/QtQuick/qmldir', 'module QtQuick\n')
        self.manifest = Path(self.tmp.name) / 'installed-package-names.txt'
        self.manifest.write_text('\n'.join(sorted(REQUIRED_MANIFEST)) + '\n')

    def write(self, relative, data):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)

    def assert_fails_with(self, text, package=False):
        errors = validate(self.root, self.manifest if package else None)
        self.assertTrue(any(text in error for error in errors), errors)

    def test_fixture_passes(self):
        self.assertEqual(validate(self.root, self.manifest), [])

    def test_missing_rootfs(self):
        self.assertIn('missing extracted rootfs', validate(self.root / 'absent')[0])

    def test_wrong_architecture_rejected(self):
        self.write('usr/bin/asteroid-launcher', elf(machine=62))
        self.assert_fails_with('wrong ELF machine')

    def test_bad_elf_rejected(self):
        self.write('usr/lib/plugins/platforms/libqlinuxfb.so', b'fake')
        self.assert_fails_with('LinuxFB QPA has no ELF64 AArch64')

    def test_missing_linuxfb(self):
        (self.root / 'usr/lib/plugins/platforms/libqlinuxfb.so').unlink()
        self.assert_fails_with('missing LinuxFB QPA')

    def test_missing_wayland_qpa(self):
        (self.root / 'usr/lib/plugins/platforms/libqwayland-generic.so').unlink()
        self.assert_fails_with('missing Wayland client QPA')

    def test_missing_compositor_library(self):
        (self.root / 'usr/lib/libQt6WaylandCompositor.so.6.11.3').unlink()
        self.assert_fails_with('missing QtWayland compositor library')

    def test_wrong_r08_environment(self):
        self.write('var/lib/environment/compositor/10-platform.conf', 'QT_QPA_PLATFORM=eglfs\n')
        self.assert_fails_with('QT_QPA_PLATFORM=linuxfb')

    def test_missing_qml(self):
        (self.root / 'usr/lib/qml/QtQuick/qmldir').unlink()
        self.assert_fails_with('missing QtQuick QML')

    def test_missing_manifest_packages(self):
        self.manifest.write_text('asteroid-launcher\n')
        self.assert_fails_with('installed-package manifest lacks qtbase-plugins', package=True)

    def test_not_fooled_by_recommendations_or_history(self):
        self.manifest.write_text('RRECOMMENDS:qtbase-plugins\n')
        self.assert_fails_with('installed-package manifest lacks qtbase-plugins', package=True)

    def test_big_endian_target_rejected(self):
        fixture = Path(self.tmp.name) / 'big.elf'
        big = bytearray(elf())
        big[5] = 2  # ELF big-endian, not this Watch3 target
        fixture.write_bytes(big)
        success, reason = elf_aarch64(fixture)
        self.assertFalse(success)
        self.assertIn('little-endian', reason)

    def test_truncated_elf_header_rejected(self):
        fixture = Path(self.tmp.name) / 'short.elf'
        fixture.write_bytes(elf()[:20])
        success, reason = elf_aarch64(fixture)
        self.assertFalse(success)
        self.assertIn('complete ELF64', reason)

    def test_actual_yocto_three_column_manifest_is_parsed(self):
        self.manifest.write_text(''.join(
            f'{name} cortexa53 6.11.3\n' for name in sorted(REQUIRED_MANIFEST)
        ))
        self.assertEqual(validate(self.root, self.manifest), [])

if __name__ == '__main__':
    unittest.main()
