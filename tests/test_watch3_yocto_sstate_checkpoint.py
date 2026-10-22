"""Tests for bounded portable Yocto shared-state cache pair snapshots."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_yocto_sstate_checkpoint import checkpoint, restore


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "raw"
        self.saved = self.root / "snapshot"
        self.warm = self.root / "warm"

    def create(self, name, length=64, signed=True):
        path = self.source / "universal" / "aa" / "bb" / (
            f"sstate:{name}:aarch64-oe-linux:6.11.3:r0:aarch64:14:abcdef_do_populate_sysroot.tar.zst"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * length)
        if signed:
            path.with_name(path.name + ".siginfo").write_bytes(b"sig")
        return path

    def test_archive_and_sidecar_round_trip(self):
        package = self.create("qtbase")
        result = checkpoint(self.source, self.saved, 1024)
        self.assertEqual(result["archive_pairs"], 1)
        self.assertEqual(restore(self.saved, self.warm)["restored_pairs"], 1)
        restored = self.warm / package.relative_to(self.source)
        self.assertEqual(restored.read_bytes(), package.read_bytes())
        self.assertEqual(restored.with_name(restored.name + ".siginfo").read_bytes(), b"sig")

    def test_prioritize_qt_over_misc_under_budget(self):
        other = self.create("zlib", length=800)
        preferred = self.create("qtbase", length=800)
        checkpoint(self.source, self.saved, 4096)
        self.assertTrue((self.saved / preferred.relative_to(self.source)).exists())
        self.assertTrue((self.saved / other.relative_to(self.source)).exists())
        checkpoint(self.source, self.saved, 1024)
        self.assertTrue((self.saved / preferred.relative_to(self.source)).exists())
        self.assertFalse((self.saved / other.relative_to(self.source)).exists())

    def test_no_unpaired_archive(self):
        self.create("qtbase", signed=False)
        self.assertEqual(checkpoint(self.source, self.saved, 1024)["archive_pairs"], 0)

    def test_empty_snapshot_is_safe_and_reported(self):
        stats = checkpoint(self.source, self.saved, 1024)
        self.assertEqual(stats["archive_pairs"], 0)
        self.assertEqual(restore(self.saved, self.warm)["restored_pairs"], 0)

    def test_cache_snapshot_does_not_delete_real_sstate(self):
        package = self.create("qtdeclarative")
        checkpoint(self.source, self.saved, 1024)
        checkpoint(self.source, self.saved, 1024)
        self.assertTrue(package.is_file())

    def test_reject_bad_snapshot_counts(self):
        self.create("qtbase")
        checkpoint(self.source, self.saved, 1024)
        manifest = self.saved / "watch3-sstate-manifest.json"
        info = json.loads(manifest.read_text())
        info["archive_pairs"] = 55
        manifest.write_text(json.dumps(info))
        with self.assertRaisesRegex(ValueError, "manifest"):
            restore(self.saved, self.warm)

    def test_no_source_destination_overlap(self):
        self.create("qtbase")
        with self.assertRaisesRegex(ValueError, "disjoint"):
            checkpoint(self.source, self.source, 1024)
        with self.assertRaisesRegex(ValueError, "disjoint"):
            restore(self.saved, self.saved / "warm")

    def test_reject_tiny_budget(self):
        with self.assertRaisesRegex(ValueError, "at least"):
            checkpoint(self.source, self.saved, 0)

    def test_reject_missing_manifest(self):
        self.saved.mkdir()
        with self.assertRaisesRegex(ValueError, "no manifest"):
            restore(self.saved, self.warm)

    def test_discard_archive_symlinks(self):
        original = self.create("qtbase")
        link = self.source / "universal" / "zz" / "zz" / original.name
        link.parent.mkdir(parents=True)
        link.symlink_to(original)
        link.with_name(link.name + ".siginfo").write_bytes(b"sig")
        self.assertEqual(checkpoint(self.source, self.saved, 1024)["archive_pairs"], 1)


if __name__ == "__main__":
    unittest.main()
