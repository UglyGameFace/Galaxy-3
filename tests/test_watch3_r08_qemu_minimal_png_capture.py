"""Only synthetic image/ELF fixtures for safe AArch64 Qt PNG capture harness."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r08_qemu_minimal_png_capture as probe


def elf(machine=183) -> bytes:
    b = bytearray(256)
    b[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", b, 16, 3, machine)
    return bytes(b)


def picture(path: Path, *, blank=False):
    im = Image.new("RGB", (200, 200), (15, 15, 15))
    if not blank:
        for y in range(200):
            for x in range(200):
                im.putpixel((x, y), (x % 256, y % 256, (x + y) % 256))
    im.save(path)


class QtPngCaptureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "root"
        self.root.mkdir()
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/bin/asteroid-launcher").write_bytes(elf())
        (self.root / "usr/lib/plugins/platforms").mkdir(parents=True)
        self.plugin = self.root / "usr/lib/plugins/platforms/libqminimal.so"
        self.plugin.write_bytes(elf())
        (self.root / "usr/lib/qml").mkdir(parents=True)
        self.artifacts = Path(tmp.name) / "frames"
        self.artifacts.mkdir()

    def test_valid_target_aarch64_minimal_plugin(self):
        self.assertEqual(probe.find_minimal(self.root), self.plugin)

    def test_missing_minimal_plugin_rejected(self):
        self.plugin.unlink()
        with self.assertRaisesRegex(probe.VisualError, "REQUIRE_EXACTLY_ONE"):
            probe.find_minimal(self.root)

    def test_wrong_arch_minimal_plugin_rejected(self):
        self.plugin.write_bytes(elf(machine=62))
        with self.assertRaisesRegex(probe.VisualError, "WRONG_ARCH"):
            probe.find_minimal(self.root)

    def test_symlink_to_host_plugin_rejected(self):
        self.plugin.unlink()
        self.plugin.symlink_to("/bin/sh")
        with self.assertRaisesRegex(probe.VisualError, "ESCAPES_GUEST"):
            probe.find_minimal(self.root)

    def test_genuine_png_dimensions_pixels_hash(self):
        path = self.artifacts / "output0001.png"
        picture(path)
        metadata = probe.inspect_png(path)
        self.assertEqual((metadata["width"], metadata["height"]), (200, 200))
        self.assertTrue(metadata["nontrivial_pixel_variation"])
        self.assertEqual(metadata["png_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_rejects_blank_screen_not_claiming_visual_proof(self):
        path = self.artifacts / "output0002.png"
        picture(path, blank=True)
        with self.assertRaisesRegex(probe.VisualError, "BLANK_OR_NEAR_UNIFORM"):
            probe.inspect_png(path)

    def test_rejects_garbage_as_png(self):
        path = self.artifacts / "output0003.png"
        path.write_bytes(b"n" * 150)
        with self.assertRaisesRegex(probe.VisualError, "INVALID_PNG"):
            probe.inspect_png(path)

    def test_rejects_other_filename(self):
        path = self.artifacts / "fake-screenshot.png"
        picture(path)
        with self.assertRaisesRegex(probe.VisualError, "NOT_ORIGINAL"):
            probe.inspect_png(path)

    def test_rejects_symlink_to_host_image(self):
        path = self.artifacts / "output0005.png"
        path.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(probe.VisualError, "NOT_ORIGINAL"):
            probe.inspect_png(path)

    def test_runtime_command_does_not_use_network_or_host_credentials(self):
        class Fake:
            pid = 99878
            returncode = -9
            def poll(self): return None
            def wait(self, timeout):
                return self.returncode

        def launched(*args, **kwargs):
            self.assertEqual(args[0][-2:], ["-platform", "minimal"])
            self.assertEqual(args[0][:3], ["qemu-aarch64", "-L", str(self.root)])
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(kwargs["env"]["QT_DEBUG_BACKINGSTORE"], "1")
            self.assertEqual(kwargs["env"]["QT_QUICK_BACKEND"], "software")
            self.assertEqual(kwargs["env"]["QT_QPA_PLATFORM"], "minimal")
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
            directory = kwargs["cwd"]
            for i in range(3):
                picture(directory / f"output{i:04d}.png")
            kwargs["stdout"].write(
                b'QMinimalBackingStore::flush() saving contents to output0002.png\n')
            return Fake()

        with patch.object(probe.shutil, "which", return_value="/usr/bin/qemu-aarch64"), \
             patch.object(probe.subprocess, "Popen", side_effect=launched), \
             patch.object(probe.os, "killpg") as killpg, \
             patch.object(probe.time, "monotonic", side_effect=[0.0, 8.0, 8.0, 8.1]):
            report, pixels = probe.run(self.root)
        self.assertEqual(report["status"], "REAL_ARM64_QT_BACKINGSTORE_NONBLANK_PNG_CAPTURED")
        self.assertEqual(report["qt_created_output_png_count"], 3)
        self.assertEqual(hashlib.sha256(pixels).hexdigest(),
                         report["frame"]["png_sha256"])
        self.assertFalse(report["physical_watch_contacted"])
        self.assertFalse(report["flashable"])
        killpg.assert_called_once_with(99878, probe.signal.SIGKILL)

    def test_absent_frame_does_not_claim_visual_success(self):
        class Fake:
            pid = 99879
            returncode = -9
            def poll(self): return None
            def wait(self, timeout): return self.returncode

        def launched(*args, **kwargs):
            kwargs["stdout"].write(b"QtQuick scenegraph started\n")
            return Fake()
        with patch.object(probe.shutil, "which", return_value="/usr/bin/qemu-aarch64"), \
             patch.object(probe.subprocess, "Popen", side_effect=launched), \
             patch.object(probe.os, "killpg"), \
             patch.object(probe.time, "monotonic", side_effect=[0.0, 30.0, 30.0]):
            report, pixels = probe.run(self.root, max_seconds=24)
        self.assertEqual(report["status"], "REAL_QT_PIXEL_FRAME_UNVERIFIED")
        self.assertEqual(report["no_png_reason"], "NO_QT_BACKINGSTORE_FLUSH")
        self.assertIsNone(pixels)

    def test_max_runtime_bounds(self):
        with self.assertRaisesRegex(probe.VisualError, "OUT_OF_RANGE"):
            probe.run(self.root, max_seconds=70)


if __name__ == "__main__":
    unittest.main()
