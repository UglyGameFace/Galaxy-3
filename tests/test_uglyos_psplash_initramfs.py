"""Fail-closed native Psplash to R08 initramfs integration contracts."""
from pathlib import Path
import ast
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_uglyos_face_package import PackageError
from validate_uglyos_psplash_initramfs import (check_metadata, variables,
                                                expected_native_version, EXPECTED_MACHINE,
                                                EXPECTED_SRCREV)
from verify_uglyos_boot_asset import verify_gif


class R08SmokeBootIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.pkg = {"PN": "psplash", "MACHINE": EXPECTED_MACHINE,
                    "DISTRO": "asteroid", "datadir": "/usr/share",
                    "PACKAGE_ARCH": "noblesse_r08", "PACKAGES": "psplash",
                    "PACKAGECONFIG": "animated-gif disable-progress-bar",
                    "SRC_URI": "file://psplash-img-280-154.gif file://uglyos-smoke.gif"}
        self.initrd = {"MACHINE": EXPECTED_MACHINE, "DISTRO": "asteroid",
                       "IMAGE_INSTALL": "busybox initramfs-scripts-android psplash",
                       "ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL": " psplash"}

    def test_exact_reviewed_smoke_asset(self):
        verify_gif()
        self.assertIn('ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL:append:noblesse-r08 = " psplash"',
                      (ROOT / "meta-noblesse/conf/machine/noblesse-r08.conf").read_text())
        check_metadata(self.pkg, self.initrd)

    def test_missing_early_boot_psplash_fails(self):
        altered = self.initrd.copy()
        altered["IMAGE_INSTALL"] = "busybox initramfs-scripts-android"
        with self.assertRaises(PackageError):
            check_metadata(self.pkg, altered)
        altered = self.initrd.copy()
        altered["ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL"] = ""
        with self.assertRaises(PackageError):
            check_metadata(self.pkg, altered)

    def test_wrong_machine_or_disabled_animated_gif_fails(self):
        bad = self.pkg.copy()
        bad["MACHINE"] = "another-watch"
        with self.assertRaises(PackageError):
            check_metadata(bad, self.initrd)
        bad = self.pkg.copy()
        bad["PACKAGECONFIG"] = "disable-progress-bar"
        with self.assertRaises(PackageError):
            check_metadata(bad, self.initrd)
        bad = self.pkg.copy()
        bad["SRC_URI"] = "file://psplash-img-280-154.gif"
        with self.assertRaises(PackageError):
            check_metadata(bad, self.initrd)

    def test_pinned_git_revision_package_version_not_raw_pv(self):
        source = {"PV": "0.1+git", "PR": "r0", "SRCREV": EXPECTED_SRCREV}
        self.assertEqual(expected_native_version(source),
                         "0.1+git0+53ae74a36b-r0")
        for key, wrong in (("SRCREV", "0" * 40),
                           ("PV", "0.1+gitfake"), ("PR", "r1")):
            modified = source.copy()
            modified[key] = wrong
            with self.subTest(key=key), self.assertRaises(PackageError):
                expected_native_version(modified)

    def test_native_psplash_binary_is_split_into_default_subpackage(self):
        code = (ROOT / "tools/validate_uglyos_psplash_initramfs.py").read_text()
        self.assertIn('split / "psplash-default"', code)
        self.assertIn('usr/bin/psplash-default', code)
        self.assertIn('read_real_ipk(default_ipk)', code)
        self.assertIn('Need both main Psplash and psplash-default native IPKs', code)
        self.assertIn('psplash-default executable', code)
        self.assertIn('update-alternatives psplash link', code)

    def test_runner_really_builds_psplash_and_initramfs(self):
        code = (ROOT / "tools/validate_uglyos_psplash_initramfs.py").read_text()
        ast.parse(code)
        workflow = (ROOT / ".github/workflows/watch3-r08-native-smoke-initramfs.yml").read_text()
        self.assertIn("bitbake -g -c package_write_ipk psplash", workflow)
        self.assertIn("bitbake -c package_write_ipk psplash", workflow)
        self.assertIn("'psplash-default_*.ipk'", workflow)
        self.assertIn('"$default_archive"', workflow)
        self.assertIn("bitbake -g -c image_complete initramfs-android-image", workflow)
        self.assertIn("bitbake -c image_complete initramfs-android-image", workflow)
        self.assertIn("assert len(tasks) <= 3000", workflow)
        self.assertIn("validate_uglyos_psplash_initramfs.py", workflow)
        self.assertIn("OFFDEVICE-NOT-FLASHABLE", workflow)
        self.assertNotIn("fastboot flash", workflow)
        self.assertNotIn("sdb shell", workflow)


if __name__ == "__main__":
    unittest.main()
