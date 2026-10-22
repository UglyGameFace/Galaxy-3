"""Regression tests for the real R08 staged package with an empty 20-device.conf."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/validate_watch3_compositor_ipk.py"
spec = importlib.util.spec_from_file_location("r08_package", SOURCE)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

# Independent golden constructed from Qt6's documented QDataStream field order,
# used by the passed compiled host Qt6 reader (#39845554241).
GOLDEN = bytes.fromhex(
    "514d4150000000010000000600000000"
    "0072ffff0100007000000000"
    "0073ffff0100007200000000"
    "0074ffff0102000400000000"
    "0080ffff010000dc00000000"
    "008bffff010000dc00000000"
    "02eeffff010000dc00000000"
)


class CompositorPackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "asteroid-launcher-configs"
        self.envdir = self.root / "var/lib/environment/compositor"
        self.envdir.mkdir(parents=True)
        self.keymap = self.root / "usr/share/qt6/keymaps/keys.qmap"
        self.keymap.parent.mkdir(parents=True)
        (self.envdir / "00-default.conf").write_text("QT_IM_MODULE=qtvirtualkeyboard\n")
        (self.envdir / "10-platform.conf").write_text(
            "# R08 LinuxFB mode\nQT_QPA_PLATFORM=linuxfb\nQT_QUICK_BACKEND=software\n"
            "QT_QPA_FB_DRM=0\n"
        )
        (self.envdir / "20-device.conf").write_bytes(b"")
        self.keymap.write_bytes(GOLDEN)

    def assertPass(self):
        with redirect_stdout(io.StringIO()):
            validator.check(self.root)

    def test_intentionally_empty_device_placeholder_is_valid(self):
        self.assertPass()

    def test_missing_device_placeholder_rejected(self):
        (self.envdir / "20-device.conf").unlink()
        with self.assertRaisesRegex(ValueError, "Missing actual staged package file"):
            validator.check(self.root)

    def test_unexpected_nonempty_device_override_rejected(self):
        (self.envdir / "20-device.conf").write_text("QT_QPA_PLATFORM=eglfs\n")
        with self.assertRaisesRegex(ValueError, "unexpectedly contains"):
            validator.check(self.root)

    def test_missing_linuxfb_setting_rejected(self):
        (self.envdir / "10-platform.conf").write_text("QT_QPA_PLATFORM=eglfs\n")
        with self.assertRaisesRegex(ValueError, "Wrong Qt compositor setting QT_QPA_PLATFORM"):
            validator.check(self.root)

    def test_duplicate_linuxfb_setting_rejected(self):
        with (self.envdir / "10-platform.conf").open("a") as stream:
            stream.write("QT_QPA_PLATFORM=eglfs\n")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validator.check(self.root)

    def test_missing_keymap_rejected(self):
        self.keymap.unlink()
        with self.assertRaisesRegex(ValueError, "Missing actual staged"):
            validator.check(self.root)

    def test_corrupt_six_button_payload_rejected(self):
        data = bytearray(GOLDEN)
        data[-1] ^= 1
        self.keymap.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "differs from Qt6-validated"):
            validator.check(self.root)

    def test_truncated_keymap_rejected(self):
        self.keymap.write_bytes(GOLDEN[:-1])
        with self.assertRaisesRegex(ValueError, "byte length"):
            validator.check(self.root)

    def test_incorrect_default_input_environment_rejected(self):
        (self.envdir / "00-default.conf").write_text("QT_IM_MODULE=none\n")
        with self.assertRaisesRegex(ValueError, "input environment"):
            validator.check(self.root)


if __name__ == "__main__":
    unittest.main()
