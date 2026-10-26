"""Fail-closed R08 launcher package metadata, file integrity and CI contracts."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_uglyos_face_package import PackageError
from validate_uglyos_native_launchers import check_metadata, expected_assets, inspect_tree, PN, ASSETS


class LauncherNativeTests(unittest.TestCase):
    def test_correct_machine_image_and_dependency_are_required(self):
        recipe = {"PN": PN, "MACHINE": "noblesse-r08", "DISTRO": "asteroid",
                  "INHIBIT_DEFAULT_DEPS": "1", "PACKAGE_ARCH": "noblesse_r08",
                  "RDEPENDS:uglyos-launchers": "asteroid-launcher",
                  "PACKAGES": "uglyos-launchers"}
        image = {"MACHINE": "noblesse-r08", "DISTRO": "asteroid",
                 "IMAGE_INSTALL": "watch3-faces uglyos-launchers"}
        check_metadata(recipe, image)
        for changed, new in (("PACKAGE_ARCH", "wrong"), ("INHIBIT_DEFAULT_DEPS", "0"),
                             ("RDEPENDS:uglyos-launchers", ""),
                             ("RDEPENDS:uglyos-launchers", "asteroid-launcher other")):
            bad = recipe.copy()
            bad[changed] = new
            with self.subTest(changed=changed, new=new), self.assertRaises(PackageError):
                check_metadata(bad, image)
        bad = image.copy()
        bad["IMAGE_INSTALL"] = "watch3-faces"
        with self.assertRaises(PackageError):
            check_metadata(recipe, bad)

    def test_exact_four_sources_and_no_extra_staged_files(self):
        assets = ROOT / "meta-noblesse/recipes-asteroid/uglyos-launchers/uglyos-launchers"
        data = expected_assets(assets)
        self.assertEqual(len(data), 4)
        self.assertEqual(tuple(sorted(ASSETS)), tuple(sorted(p.name for p in assets.glob("*.qml"))))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for rel, content in data.items():
                output = root / "usr/share" / rel
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(content)
            inspect_tree(root, data, "/usr/share")
            extra = root / "usr/share/asteroid-launcher/applauncher/fake.qml"
            extra.write_text("bad")
            with self.assertRaises(PackageError):
                inspect_tree(root, data, "/usr/share")
            extra.unlink()
            first = root / "usr/share" / next(iter(data))
            first.write_text("wrong bytes")
            with self.assertRaises(PackageError):
                inspect_tree(root, data, "/usr/share")

    def test_native_task_budget_and_real_ipk_not_faked(self):
        workflow = (ROOT / ".github/workflows/watch3-r08-native-launcher-ipk.yml").read_text()
        self.assertIn("bitbake -g -c package_write_ipk uglyos-launchers", workflow)
        self.assertIn("bitbake -c package_write_ipk uglyos-launchers", workflow)
        self.assertIn("validate_uglyos_native_launchers.py", workflow)
        self.assertIn("assert len(tasks) <= 800", workflow)
        self.assertIn("REAL-YOCTO-OFFDEVICE-NOT-FLASHABLE", workflow)
        self.assertNotIn("bitbake -b ", workflow)


if __name__ == "__main__":
    unittest.main()
