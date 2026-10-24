"""Fixture-based deployed-image discovery; no real firmware is built here."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from find_watch3_image_outputs import discover, main


class ImageOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.rootfs = self.root / "work" / "rootfs"
        self.rootfs.mkdir(parents=True)
        self.deploy = self.root / "deploy"
        self.deploy.mkdir()
        self.prefix = "asteroid-image-noblesse-r08.rootfs"
        self.stem = self.prefix + "-20261024060727"
        self.image = self.deploy / (self.stem + ".ext4")
        self.image.write_bytes(b"OFF-DEVICE-DUMMY")
        self.manifest = self.deploy / (self.stem + ".manifest")
        self.manifest.write_text("asteroid-launcher aarch64 1.0\n")
        self.values = {
            "PN": "asteroid-image", "MACHINE": "noblesse-r08",
            "DISTRO": "asteroid", "IMAGE_ROOTFS": str(self.rootfs),
            "IMAGE_MANIFEST": str(self.root / "work" / "deploy" /
                                  (self.prefix + "-20261024060907.manifest")),
            "DEPLOY_DIR_IMAGE": str(self.deploy),
            "IMAGE_LINK_NAME": self.prefix,
        }

    def test_postbuild_datetime_mismatch_still_finds_paired_manifest(self):
        self.assertFalse(Path(self.values["IMAGE_MANIFEST"]).exists())
        self.assertEqual(discover(self.values), (self.rootfs, self.manifest, self.image))

    def test_real_image_wins_over_link(self):
        (self.deploy / (self.prefix + ".ext4")).symlink_to(self.image.name)
        (self.deploy / (self.prefix + ".manifest")).symlink_to(self.manifest.name)
        self.assertEqual(discover(self.values)[2], self.image)

    def test_reject_unpaired_manifest_rather_than_unrelated_stale_build(self):
        self.manifest.unlink()
        (self.deploy / (self.prefix + "-20261023120000.manifest")).write_text("old\n")
        with self.assertRaisesRegex(ValueError, "No paired installed-package manifest"):
            discover(self.values)

    def test_missing_rootfs_is_explicit(self):
        self.rootfs.rmdir()
        with self.assertRaisesRegex(ValueError, "Actual extracted rootfs missing"):
            discover(self.values)

    def test_bad_machine_is_rejected(self):
        self.values["MACHINE"] = "other-watch"
        with self.assertRaisesRegex(ValueError, "MACHINE"):
            discover(self.values)

    def test_empty_image_is_rejected(self):
        self.image.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "No non-empty"):
            discover(self.values)

    def test_symlink_escape_is_rejected(self):
        self.image.unlink()
        outside = self.root / "outside.ext4"
        outside.write_bytes(b"not a deploy artifact")
        self.image.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "No non-empty"):
            discover(self.values)

    def test_writes_validated_paths_only_after_manifest_found(self):
        from unittest.mock import patch
        env = self.root / "postbuild.env"
        env.write_text("\n".join(f'{k}="{v}"' for k, v in self.values.items()))
        output = self.root / "paths.txt"
        github_env = self.root / "github.env"
        github_env.touch()
        with patch.object(sys, "argv", ["find", str(env), str(output), str(github_env)]):
            self.assertEqual(main(), 0)
        self.assertEqual(output.read_text().splitlines(),
                         [str(self.rootfs), str(self.manifest), str(self.image)])
        self.assertEqual(github_env.read_text(),
                         "UNVALIDATED_IMAGE_PATH=" + str(self.image) + "\n")

    def test_missing_manifest_records_diagnostic_image_but_not_paths(self):
        from unittest.mock import patch
        self.manifest.unlink()
        env = self.root / "postbuild.env"
        env.write_text("\n".join(f'{k}="{v}"' for k, v in self.values.items()))
        output = self.root / "paths.txt"
        github_env = self.root / "github.env"
        github_env.touch()
        with patch.object(sys, "argv", ["find", str(env), str(output), str(github_env)]):
            self.assertEqual(main(), 1)
        self.assertFalse(output.exists())
        self.assertIn("UNVALIDATED_IMAGE_PATH=", github_env.read_text())


if __name__ == "__main__":
    unittest.main()
