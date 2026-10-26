"""Fail-closed regression checks for the offline-only IPK builder."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_uglyos_face_ipk import create_ipk, verify_ipk, _ar_members, _untar, PackageError, REQUIRED_FILES


class OfflineIpkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.stage = self.root / "image"
        share = self.stage / "usr/share"
        for name in ("900-watch3-orbit.qml", "901-watch3-focus.qml", "902-watch3-signal.qml",
                     "903-watch3-solo-arcade.qml", "904-watch3-solo-lounge.qml"):
            src = self.source / name
            src.write_text(f"// QML {name}")
            dest = share / "asteroid-launcher/watchfaces" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(src.read_bytes())
        edition = {"display_name": "UgLy|OS", "slug": "uglyos",
                   "base_system": "AsteroidOS", "boot_status": "not-boot-tested",
                   "install_status": "not-flashable"}
        (self.source / "uglyos-edition.json").write_text(json.dumps(edition))
        dest = share / "uglyos/edition.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((self.source / "uglyos-edition.json").read_bytes())
        self.env = {"PN": "watch3-faces", "MACHINE": "noblesse-r08",
                    "DISTRO": "asteroid", "PV": "1.0", "PR": "r0",
                    "PACKAGE_ARCH": "noblesse_r08",
                    "RDEPENDS:watch3-faces": "asteroid-launcher",
                    "D": str(self.stage), "datadir": "/usr/share"}

    def test_offline_ipk_has_real_ar_layout_and_payload(self):
        file = create_ipk(self.env, self.source, self.root / "out")
        contents = _ar_members(file.read_bytes())
        self.assertEqual(list(contents), ["debian-binary", "control.tar.gz", "data.tar.gz"])
        self.assertEqual(set(_untar(contents["data.tar.gz"])), set(REQUIRED_FILES))
        self.assertEqual(subprocess.check_output(["ar", "t", str(file)], text=True).splitlines(), list(contents))
        self.assertIn(b"Architecture: noblesse_r08", _untar(contents["control.tar.gz"])["control"])

    def test_deterministic_archive(self):
        first = create_ipk(self.env, self.source, self.root / "a")
        second = create_ipk(self.env, self.source, self.root / "b")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_reject_wrong_architecture(self):
        self.env["PACKAGE_ARCH"] = "arm64"
        with self.assertRaisesRegex(PackageError, "architecture"):
            create_ipk(self.env, self.source, self.root / "out")

    def test_reject_modified_install_data(self):
        (self.stage / "usr/share/uglyos/edition.json").write_text("tampered")
        with self.assertRaisesRegex(PackageError, "Source/install mismatch"):
            create_ipk(self.env, self.source, self.root / "out")

    def test_reject_extra_staged_file(self):
        (self.stage / "usr/share/uglyos/unexpected.txt").write_text("tampered")
        with self.assertRaisesRegex(PackageError, "Unexpected installed assets"):
            create_ipk(self.env, self.source, self.root / "out")

    def test_reject_corrupted_archive(self):
        file = create_ipk(self.env, self.source, self.root / "out")
        file.write_bytes(file.read_bytes()[:-1])
        expected = {n: (self.stage / n).read_bytes() for n in REQUIRED_FILES}
        with self.assertRaises(PackageError):
            verify_ipk(file, self.env, expected)


if __name__ == "__main__":
    unittest.main()
