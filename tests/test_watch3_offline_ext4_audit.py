"""Host-only fixture tests; synthetic ELF never proves a real watch can boot."""
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_watch3_offline_ext4 import (audit, expected_digest, one_real_file,
                                      package_closure, sha256_file)
from validate_watch3_graphics_rootfs import REQUIRED_MANIFEST


def fake_elf_aarch64() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:7] = b"\x02\x01\x01"
    header[16:18] = (3).to_bytes(2, "little")
    header[18:20] = (183).to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[52:54] = (64).to_bytes(2, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = (1).to_bytes(2, "little")
    return bytes(header + bytearray(56))


class OfflineArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image_dir = self.root / "image"
        self.image_dir.mkdir()
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.filename = "asteroid-image-noblesse-r08.rootfs-20261024125252.ext4"
        self.image = self.image_dir / self.filename
        self.sha = self.stage / "asteroid-image.sha256"
        self.manifest = self.stage / "installed-packages.manifest"
        self.manifest.write_text("".join(
            f"{n} cortexa53 1.0\n" for n in sorted(REQUIRED_MANIFEST)))

    def test_checksum_parser_uses_original_image_basename(self):
        self.sha.write_text("f" * 64 + "  /old/runner/" + self.filename + "\n")
        self.assertEqual(expected_digest(self.sha, self.filename), "f" * 64)
        with self.assertRaisesRegex(ValueError, "different ext4"):
            expected_digest(self.sha, "another.ext4")

    def test_manifest_requires_installed_packages(self):
        self.assertEqual(package_closure(self.manifest)["package_count"],
                         len(REQUIRED_MANIFEST))
        self.manifest.write_text("asteroid-launcher cortexa53 1.0\n")
        with self.assertRaisesRegex(ValueError, "lacks"):
            package_closure(self.manifest)

    def test_reject_multiple_images_and_symlink_only(self):
        self.image.write_bytes(b"x")
        self.assertEqual(one_real_file(self.image_dir, "*.ext4"), self.image)
        (self.image_dir / "another.ext4").write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            one_real_file(self.image_dir, "*.ext4")
        self.image.unlink()
        (self.image_dir / "another.ext4").unlink()
        self.image.symlink_to(self.sha)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            one_real_file(self.image_dir, "*.ext4")

    @unittest.skipUnless(shutil.which("mkfs.ext4") and
                         shutil.which("debugfs") and
                         shutil.which("e2fsck") and
                         shutil.which("dumpe2fs"), "e2fsprogs not available")
    def test_offline_ext4_fixture_audits_readonly_without_mutating(self):
        import subprocess
        source = self.root / "fixture-rootfs"
        def put(relative, data):
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data.encode() if isinstance(data, str) else data)
        put("usr/bin/asteroid-launcher", fake_elf_aarch64())
        put("usr/lib/systemd/user/asteroid-launcher.service",
            "EnvironmentFile=-/var/lib/environment/compositor/*.conf\n")
        put("var/lib/environment/compositor/10-platform.conf",
            "QT_QPA_PLATFORM=linuxfb\nQT_QUICK_BACKEND=software\nQT_QPA_FB_DRM=0\n")
        subprocess.run(["truncate", "-s", "48M", str(self.image)], check=True)
        subprocess.run(["mkfs.ext4", "-F", "-q", "-d", str(source), str(self.image)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        digest = sha256_file(self.image)
        self.sha.write_text(f"{digest}  /prior/runner/{self.filename}\n")
        report = audit(self.image_dir, self.stage)
        self.assertEqual(report["result"], "PASS_OFF_DEVICE_IMAGE_AUDIT")
        self.assertEqual(report["verified_sha256"], digest)
        self.assertFalse(report["flashable"])
        self.assertEqual(sha256_file(self.image), digest,
                         "Read-only audit must never modify the image")

    @unittest.skipUnless(shutil.which("mkfs.ext4"), "e2fsprogs not available")
    def test_corrupt_image_hash_is_rejected_before_filesystem_commands(self):
        self.image.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        self.sha.write_text("a" * 64 + "  /prior/runner/" + self.filename + "\n")
        with self.assertRaisesRegex(ValueError, "SHA256 does not match"):
            audit(self.image_dir, self.stage)


if __name__ == "__main__":
    unittest.main()
