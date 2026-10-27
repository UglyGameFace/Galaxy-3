"""Off-device ZIP metadata safety checks for exact-model Watch3 stock rescue."""
from pathlib import Path
import hashlib
import io
import json
import stat
import sys
import tempfile
import unittest
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from audit_watch3_r840x_recovery_zip import audit, _safe_name

TARGET = "R840XXXU1AUA2"
OLDER = "R840XXXU1ATFA"


class RecoveryZipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, filename="candidate.zip", entries=None):
        path = self.root / filename
        if entries is None:
            entries = [
                "BL_R840XXXU1AUA2.tar.md5",
                "AP_R840XXXU1AUA2.tar.md5",
                "CSC_R840XXXU1AUA2.tar.md5",
            ]
        with ZipFile(path, "w") as z:
            for name in entries:
                z.writestr(name, b"FAKE-TEST-FIXTURE-NOT-SAMSUNG-FIRMWARE")
        return path

    def test_exact_matching_names_still_never_mark_package_flashable(self):
        r = audit(self.archive(), TARGET)
        self.assertEqual(r["status"], "NO_GO")
        self.assertTrue(r["zip_metadata_readable"])
        self.assertTrue(r["candidate_build_matches_installed"])
        self.assertEqual(r["parts_named"], ["AP", "BL", "CSC"])
        self.assertEqual(r["watch_build_tokens"], [TARGET])
        self.assertIn("ARCHIVE_IDENTITY_AND_SAMSUNG_SIGNATURE_UNVERIFIED", r["issues"])
        for key in ("signature_verified", "bootloader_acceptance_verified",
                    "stock_restoration_verified", "watch_modified"):
            self.assertIs(r[key], False)

    def test_real_lead_older_R840X_build_is_mismatch(self):
        r = audit(self.archive("R840XXXU1ATFA-(OXA).zip", [
            "BL_R840XXXU1ATFA.tar.md5",
            "AP_R840XXXU1ATFA.tar.md5",
            "CSC_R840XXXU1ATFA.tar.md5",
        ]), TARGET)
        self.assertIn("R840X_BUILD_DIFFERS_FROM_INSTALLED", r["issues"])
        self.assertIs(r["candidate_build_matches_installed"], False)
        self.assertEqual(r["watch_build_tokens"], [OLDER])

    def test_retail_R840_never_converts_to_R840X(self):
        r = audit(self.archive("R840XXU1ATF9.zip", [
            "BL_R840XXU1ATF9.tar.md5",
            "AP_R840XXU1ATF9.tar.md5",
            "CSC_R840XXU1ATF9.tar.md5",
        ]), TARGET)
        self.assertFalse(r["watch_build_tokens"])
        self.assertIn("RETAIL_R840_BUILD_PRESENT_NOT_R840X_PROOF", r["issues"])
        self.assertIn("NO_R840X_BUILD_EVIDENCE", r["issues"])

    def test_combination_not_treated_as_stock_recovery(self):
        r = audit(self.archive("COMBINATION-R840XXXU1AUA2.zip", [
            "COMBINATION_R840XXXU1AUA2.tar.md5",
        ]), TARGET)
        self.assertTrue(r["combination_or_engineering_firmware"])
        self.assertIn("ENGINEERING_FIRMWARE_NOT_STOCK_RESCUE", r["issues"])
        self.assertIn("STOCK_BL_AP_CSC_COMPONENT_NAMES_NOT_PROVEN", r["issues"])

    def test_missing_component_and_multiple_build_tokens(self):
        r = audit(self.archive(entries=[
            "BL_R840XXXU1AUA2.tar.md5",
            "AP_R840XXXU1ATFA.tar.md5",
        ]), TARGET)
        self.assertIn("MULTIPLE_R840X_BUILD_IDENTITIES", r["issues"])
        self.assertIn("STOCK_BL_AP_CSC_COMPONENT_NAMES_NOT_PROVEN", r["issues"])

    def test_zip_slip_and_symbolic_link_rejected_without_extracting(self):
        for member in ("../malicious.sh", "/root/danger", "evil\\backdoor", "x:\bad",
                       "odd\nentry"):
            with self.subTest(member=repr(member)):
                self.assertFalse(_safe_name(member))
                r = audit(self.archive("bad.zip", [member]), TARGET)
                self.assertEqual(r["issues"], ["UNSAFE_MEMBER_NAME_OR_LINK"])
        path = self.root / "symlink.zip"
        info = ZipInfo("BL_R840XXXU1AUA2.tar.md5")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with ZipFile(path, "w") as z:
            z.writestr(info, "target")
        self.assertEqual(audit(path, TARGET)["issues"], ["UNSAFE_MEMBER_NAME_OR_LINK"])

    def test_invalid_zip_and_missing_archive_fail_closed(self):
        bad = self.root / "bad.zip"
        bad.write_text("not an archive")
        self.assertIn("INVALID_OR_UNREADABLE_ZIP", audit(bad, TARGET)["issues"])
        self.assertIn("ARCHIVE_UNREADABLE", audit(self.root / "none.zip", TARGET)["issues"])

    def test_declared_central_directory_limits_before_parsing_metadata(self):
        path = self.archive()
        original = path.read_bytes()
        signature = bytes.fromhex("504b0506")
        offset = original.rfind(signature)
        self.assertGreaterEqual(offset, 0)
        # EOCD: entries total is at offset+10; central-directory size +12.
        excessive = bytearray(original)
        excessive[offset + 8:offset + 12] = (600).to_bytes(2, "little") * 2
        path.write_bytes(excessive)
        self.assertEqual(audit(path, TARGET)["issues"], ["UNSAFE_MEMBER_COUNT"])
        oversized = bytearray(original)
        oversized[offset + 12:offset + 16] = (1048576).to_bytes(4, "little")
        path.write_bytes(oversized)
        self.assertEqual(audit(path, TARGET)["issues"], ["UNSAFE_CENTRAL_DIRECTORY"])
        path.write_bytes(original)
        self.assertTrue(audit(path, TARGET)["zip_metadata_readable"])

    def test_streamed_sha256_is_identity_not_authenticity(self):
        path = self.archive()
        report = audit(path, TARGET, checksum=True)
        self.assertEqual(report["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(report["status"], "NO_GO")
        self.assertFalse(report["signature_verified"])

    def test_wrong_expected_model_rejected(self):
        path = self.archive()
        for value in ("R840XXU1ATF9", "R840XXXU1AUA2;rm -rf /", "R850XXXU1AUA2"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    audit(path, value)


if __name__ == "__main__":
    unittest.main()
