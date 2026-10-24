"""Fixture-only tests for the actual BitBake package validator."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_uglyos_face_package import (PackageError, FACES, metadata,
                                          inspect_package, variables)


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

    def test_unchanged_payload_is_verified(self):
        inspect_package(self.info, self.source)

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
