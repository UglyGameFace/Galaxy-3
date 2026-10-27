"""Use fabricated ZIP > Odin TAR fixtures to test offline R840X inventory."""
from __future__ import annotations
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from audit_watch3_r840x_odin_components import inspect_zip, _inventory_part

BUILD = "R840XXXU1AUA2"


def fake_tar(entries: list[tuple[str, bytes]]) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as f:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            f.addfile(info, io.BytesIO(payload))
    return bio.getvalue()


class OdinComponentInventory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make_zip(self, entries, name=f"R840XXXU1AUA2.zip"):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as z:
            for n, payload in entries:
                z.writestr(n, payload)
        return path

    def test_fabricated_full_parts_are_only_unverified_metadata(self):
        path = self.make_zip([
            (f"BL_{BUILD}.tar.md5", fake_tar([("sboot.bin", b"fakeboot"),("param.bin", b"fake")])),
            (f"AP_{BUILD}.tar.md5", fake_tar([("boot.img", b"fake-image"),("recovery.img", b"fake")])),
            (f"CSC_{BUILD}.tar.md5", fake_tar([("layout.pit", b"not-a-PIT")])),
        ])
        r = inspect_zip(path)
        self.assertEqual(r["status"], "NO_GO")
        self.assertEqual(len(r["parts"]), 3)
        self.assertTrue(r["all_named_boot_recovery_components_present"])
        self.assertTrue(any(p["possible_pit"] == ["layout.pit"] for p in r["parts"]))
        self.assertFalse(r["stock_signature_verified"])
        self.assertFalse(r["partition_mapping_verified"])
        self.assertFalse(r["restoration_verified"])
        self.assertFalse(r["watch_modified"])
        self.assertEqual(r["parts"][0]["state"], "TAR_HEADERS_READ_UNVERIFIED")

    def test_path_traversal_inner_rejected(self):
        path=self.make_zip([
            (f"BL_{BUILD}.tar.md5", fake_tar([("../evil.sh", b"x")]))
        ])
        r=inspect_zip(path)
        self.assertEqual(r["parts"][0]["issue"], "UNSAFE_TAR_MEMBER_NAME")
        self.assertFalse(r["all_named_boot_recovery_components_present"])

    def test_tar_symlink_is_rejected(self):
        bio=io.BytesIO()
        with tarfile.open(fileobj=bio,mode="w") as t:
            info=tarfile.TarInfo("sboot.bin")
            info.type=tarfile.SYMTYPE
            info.linkname="/evil"
            t.addfile(info)
        path=self.make_zip([(f"BL_{BUILD}.tar.md5", bio.getvalue())])
        r=inspect_zip(path)
        self.assertEqual(r["parts"][0]["issue"], "UNSUPPORTED_TAR_LINK_OR_MEMBER_TYPE")

    def test_duplicate_odin_roles_flagged(self):
        t=fake_tar([("kernel.img", b"fake")])
        p=self.make_zip([(f"BL_{BUILD}.tar.md5",t),(f"BL_{BUILD}_copy.tar.md5",t)])
        result=inspect_zip(p)
        self.assertIn("DUPLICATE_ODIN_COMPONENT_ROLE",result["outer_issues"])
        self.assertEqual(len(result["parts"]),1)

    def test_retail_only_zip_is_never_accepted(self):
        p=self.make_zip([("BL_R840XXU1ATF9.tar.md5",fake_tar([("sboot.bin",b"x")]))],
                        name="R840XXU1ATF9.zip")
        r=inspect_zip(p)
        self.assertIn("RETAIL_R840_BUILD_PRESENT_NOT_R840X_PROOF",r["outer_issues"])
        self.assertEqual(r["status"],"NO_GO")

    def test_invalid_nested_tar_recorded_without_extraction(self):
        p=self.make_zip([(f"BL_{BUILD}.tar.md5",b"not-a-real-tar")])
        r=inspect_zip(p)
        self.assertEqual(r["parts"][0]["issue"],"INVALID_OR_UNREADABLE_TAR")
        self.assertEqual(r["status"],"NO_GO")

    def test_does_not_open_non_tar_nested_payloads(self):
        p=self.make_zip([(f"AP_{BUILD}.img",b"a"*1000)])
        r=inspect_zip(p)
        self.assertEqual(r["parts"],[])
        self.assertFalse(r["all_named_boot_recovery_components_present"])

    def test_fake_filename_no_claims_about_boot_acceptance(self):
        t=fake_tar([("recovery.img",b"any")])
        r=inspect_zip(self.make_zip([(f"AP_{BUILD}.tar.md5",t)]))
        self.assertFalse(r["all_named_boot_recovery_components_present"])
        self.assertFalse(r["restoration_verified"])

if __name__ == "__main__":
    unittest.main()
