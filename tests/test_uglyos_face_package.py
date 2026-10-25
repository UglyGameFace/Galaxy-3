"""Fixture-only tests for the actual BitBake package validator."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_uglyos_face_package import (PackageError, FACES, metadata,
                                          inspect_installed, inspect_package, variables)


class UgLyOSPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "assets"
        self.source.mkdir()
        self.package_root = self.root / "pkg"
        self.installed_root = self.root / "image"
        self.share = "usr/share"
        edition = {"display_name": "UgLy|OS", "slug": "uglyos",
                   "base_system": "AsteroidOS",
                   "boot_status": "not-boot-tested",
                   "install_status": "not-flashable"}
        for name in FACES:
            self.write(self.source / name, f"// SPDX-License-Identifier: MIT\n{name}")
        self.write(self.source / "uglyos-edition.json", json.dumps(edition))
        for location in (self.installed_root / self.share,
                         self.package_root / "watch3-faces" / self.share):
            for name in FACES:
                self.write(location / "asteroid-launcher/watchfaces" / name,
                           (self.source / name).read_bytes())
            self.write(location / "uglyos/edition.json",
                       (self.source / "uglyos-edition.json").read_bytes())
        self.info = {"D": str(self.installed_root),
                     "PKGDEST": str(self.package_root),
                     "datadir": "/usr/share"}

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())

    def test_workflow_creates_logdir_before_each_bitbake_redirect(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/watch3-r08-uglyos-face-package.yml").read_text()
        steps = [
            "Confirm real BitBake recipe and image dependency metadata",
            "Install only UgLyOS QML assets using isolated BitBake recipe",
            "Verify actual BitBake installed files against source",
        ]
        for name in steps:
            with self.subTest(step=name):
                head = "      - name: " + name
                section = workflow.split(head, 1)[1].split("      - name:", 1)[0]
                create = 'mkdir -p "$GITHUB_WORKSPACE/uglyos-logs"'
                self.assertIn(create, section)
                self.assertLess(section.index(create),
                                section.index('source src/oe-core/oe-init-build-env'))
                self.assertIn('"$GITHUB_WORKSPACE/uglyos-logs/', section)

    def test_native_fakeroot_is_prepared_before_isolated_package(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/watch3-r08-uglyos-face-package.yml").read_text()
        prep_head = "      - name: Prepare Yocto pseudo-native fakeroot for isolated packaging"
        package_head = "      - name: Install only UgLyOS QML assets using isolated BitBake recipe"
        self.assertEqual(workflow.count(prep_head), 1)
        self.assertLess(workflow.index(prep_head), workflow.index(package_head))
        prep = workflow.split(prep_head, 1)[1].split("      - name:", 1)[0]
        self.assertIn("bitbake -c populate_sysroot pseudo-native", prep)
        self.assertIn("timeout --signal=TERM --kill-after=5s 900s", prep)
        self.assertIn('mkdir -p "$GITHUB_WORKSPACE/uglyos-logs"', prep)
        self.assertLess(prep.index('mkdir -p "$GITHUB_WORKSPACE/uglyos-logs"'),
                        prep.index('tee "$GITHUB_WORKSPACE/uglyos-logs/'))
        self.assertIn('pseudo_bin="$BUILDDIR/tmp/sysroots-components/', prep)
        self.assertIn('if [[ ! -x "$pseudo_bin" ]]', prep)
        self.assertNotIn("bitbake watch3-faces", prep)
        self.assertNotIn("-c package pseudo-native", prep)

    def test_real_install_bypasses_cold_cross_recipe_task_graph(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/watch3-r08-uglyos-face-package.yml").read_text()
        step = workflow.split(
            "      - name: Install only UgLyOS QML assets using isolated BitBake recipe",
            1)[1].split("      - name:", 1)[0]
        self.assertIn('bitbake -b "$recipe" -c install', step)
        self.assertNotIn('bitbake -b "$recipe" -c package', step)
        self.assertIn('watch3-faces_1.0.bb', step)
        self.assertIn('600s', step)
        self.assertNotIn('bitbake watch3-faces 2>&1', step)
        self.assertIn("INHIBIT_DEFAULT_DEPS=1", step)
        self.assertIn('timeout --signal=TERM --kill-after=5s', step)
        # The original full dependency build timed out on task 655/3359.
        # Do not "fix" the cost of unnecessary compilation by increasing time.
        self.assertNotIn('1200s', step)

    def test_small_data_recipe_has_no_compile_or_codegen(self):
        recipe = (Path(__file__).resolve().parents[1] /
                  "meta-noblesse/recipes-asteroid/watch3-faces/"
                  "watch3-faces_1.0.bb").read_text()
        self.assertIn('INHIBIT_DEFAULT_DEPS = "1"', recipe)
        self.assertIn('do_compile[noexec] = "1"', recipe)
        self.assertIn('do_configure[noexec] = "1"', recipe)
        self.assertIn('install -m 0644', recipe)
        self.assertNotIn('DEPENDS +=', recipe)

    def test_unchanged_payload_is_verified(self):
        inspect_installed(self.info, self.source)
        inspect_package(self.info, self.source)

    def test_staged_extra_file_is_rejected(self):
        self.write(self.installed_root / "usr/share/uglyos/unknown.txt", "extra")
        with self.assertRaisesRegex(PackageError, "Unexpected installed assets"):
            inspect_installed(self.info, self.source)

    def test_modified_installed_face_is_rejected(self):
        self.write(self.installed_root / "usr/share/asteroid-launcher/watchfaces" / FACES[0], "wrong")
        with self.assertRaisesRegex(PackageError, "Source/install mismatch"):
            inspect_installed(self.info, self.source)

    def test_lightweight_ci_does_not_claim_finished_package(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/watch3-r08-uglyos-face-package.yml").read_text()
        self.assertIn('validate_uglyos_face_package.py" installed', workflow)
        self.assertIn("NOT TESTED: do_package, package split, IPK creation", workflow)
        self.assertNotIn('validate_uglyos_face_package.py" packaged', workflow)

    def test_modified_packaged_face_is_rejected(self):
        p = self.package_root / "watch3-faces/usr/share/asteroid-launcher/watchfaces" / FACES[0]
        p.write_text("wrong payload")
        with self.assertRaisesRegex(PackageError, "mismatch"):
            inspect_package(self.info, self.source)

    def test_edition_name_must_keep_vertical_bar(self):
        p = self.package_root / "watch3-faces/usr/share/uglyos/edition.json"
        obj = json.loads(p.read_text())
        obj["display_name"] = "UgLyOS"
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(PackageError, "differs"):
            inspect_package(self.info, self.source)

    def test_recipe_metadata_stays_machine_specific(self):
        recipe = {
            "PN": "watch3-faces", "MACHINE": "noblesse-r08",
            "DISTRO": "asteroid", "INHIBIT_DEFAULT_DEPS": "1",
            "RDEPENDS:watch3-faces": "asteroid-launcher",
            "PACKAGES": "watch3-faces-dbg watch3-faces",
            "FILES:watch3-faces":
                "/usr/share/asteroid-launcher/watchfaces/*.qml /usr/share/uglyos/edition.json",
            "DEPENDS": "", "BASEDEPENDS": "",
        }
        image = {"MACHINE": "noblesse-r08", "DISTRO": "asteroid",
                 "IMAGE_INSTALL": "asteroid-launcher watch3-faces"}
        metadata(recipe, image)
        image["IMAGE_INSTALL"] = "asteroid-launcher"
        with self.assertRaisesRegex(PackageError, "does not install"):
            metadata(recipe, image)
        image["IMAGE_INSTALL"] += " watch3-faces"
        recipe["DEPENDS"] = "virtual/cross-cc"
        with self.assertRaisesRegex(PackageError, "compiler"):
            metadata(recipe, image)

    def test_bitbake_env_reader_skips_comment_history(self):
        file = self.root / "sample.env"
        file.write_text(
            '# MACHINE="some-other-watch"\n'
            'MACHINE="noblesse-r08"\n'
            'PN="watch3-faces"\n'
            'RDEPENDS:watch3-faces="asteroid-launcher"\n')
        self.assertEqual(variables(file), {
            "MACHINE": "noblesse-r08", "PN": "watch3-faces",
            "RDEPENDS:watch3-faces": "asteroid-launcher"
        })

    def test_unknown_or_root_paths_rejected(self):
        with self.assertRaisesRegex(PackageError, "Unsafe package path"):
            inspect_package({"D": "/", "PKGDEST": "/", "datadir": "/usr/share"},
                            self.source)


if __name__ == "__main__":
    unittest.main()
