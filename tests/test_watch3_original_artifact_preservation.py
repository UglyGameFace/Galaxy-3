"""Offline-only tests. Tiny synthetic byte fixtures, no real image/watch/network."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import verify_watch3_original_artifact_preservation as preserve


class OriginalOfflineArtifactPreservationTests(unittest.TestCase):
    def test_exact_real_firmware_provenance_is_pinned(self):
        self.assertEqual(preserve.SOURCE_RUN, 40095182440)
        self.assertEqual(preserve.IMAGE_FILENAME,
                         "asteroid-image-noblesse-r08.rootfs-20261024125252.ext4")
        self.assertEqual(preserve.IMAGE_BYTES, 755658752)
        self.assertEqual(preserve.IMAGE_SHA256,
                         "8358d60f213c7acf8857a7a9795e7de9a35acbc70d6d3743b72299dfe8a3ed72")
        self.assertEqual(preserve.SOURCE_ARCHIVE_EXPIRES_UTC,
                         "2026-10-31T13:01:30Z")

    def test_fixture_accepted_only_with_matching_size_hash_and_name(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / preserve.IMAGE_FILENAME
            data = b"obviously fake test fixture, NOT the real watch image"
            target.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            result = preserve.verify_file(target, expected_size=len(data),
                                          expected_hash=digest)
            self.assertFalse(result["flashable"])
            self.assertFalse(result["boot_proven"])
            self.assertFalse(result["stock_restore_proven"])
            self.assertFalse(result["watch_contacted"])
            self.assertTrue(result["original_unmodified"])
            with self.assertRaisesRegex(preserve.PreservationError,
                                        "ORIGINAL_IMAGE_LENGTH_MISMATCH"):
                preserve.verify_file(target, expected_size=len(data)+1,
                                     expected_hash=digest)
            with self.assertRaisesRegex(preserve.PreservationError,
                                        "ORIGINAL_IMAGE_SHA256_MISMATCH"):
                preserve.verify_file(target, expected_size=len(data),
                                     expected_hash="0"*64)

    def test_reject_alias_symlink_and_wrong_file_name(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            real = base / preserve.IMAGE_FILENAME
            real.write_bytes(b"hello")
            link = base / "alternate.ext4"
            link.symlink_to(real)
            with self.assertRaisesRegex(preserve.PreservationError,
                                        "UNEXPECTED_IMAGE_NAME_OR_SYMLINK"):
                preserve.verify_file(link, name=link.name, expected_size=5,
                                     expected_hash=hashlib.sha256(b"hello").hexdigest())
            with self.assertRaisesRegex(preserve.PreservationError,
                                        "UNEXPECTED_IMAGE_NAME_OR_SYMLINK"):
                preserve.verify_file(real, name="other.ext4", expected_size=5,
                                     expected_hash=hashlib.sha256(b"hello").hexdigest())

    def test_report_is_local_private_exclusive_and_does_not_change_image(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            image = root / preserve.IMAGE_FILENAME
            image.write_bytes(b"test image bytes")
            output = root / "verified.json"
            length = image.stat().st_size
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            original_verify = preserve.verify_file

            def fake_small_fixture(path):
                return original_verify(path, expected_size=length,
                                       expected_hash=digest)

            with patch.object(preserve, "verify_file", side_effect=fake_small_fixture), patch.object(
                sys, "argv", ["verify", "--image-dir", td, "--output", str(output)]
            ):
                self.assertEqual(preserve.main(), 0)
            self.assertEqual(output.stat().st_mode & 0o077, 0)
            self.assertEqual(image.read_bytes(), b"test image bytes")
            self.assertFalse(json.loads(output.read_text())["flashable"])
            previous = output.read_bytes()
            with patch.object(preserve, "verify_file", side_effect=fake_small_fixture), patch.object(
                sys, "argv", ["verify", "--image-dir", td, "--output", str(output)]
            ):
                self.assertEqual(preserve.main(), 1)
            self.assertEqual(output.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
