"""Regression tests for real rootfs English QTranslator catalog integrity gate."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r08_qemu_locale_gate as locale


class GuestEnglishCatalogTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)/"guest"
        self.qmdir=self.root/"usr/share/translations"
        self.qmdir.mkdir(parents=True)
        self.qm=self.qmdir/"asteroid-launcher.en.qm"

    def write_qm(self, data=None):
        content = data if data is not None else locale.QM_MAGIC+b"\x01\x02\x03"*64
        self.qm.write_bytes(content)
        return content

    def test_compiled_actual_guest_catalog_has_correct_magic_and_sha(self):
        raw=self.write_qm()
        data=locale.inspect(self.root)
        self.assertEqual(data["status"],"ACTUAL_GUEST_COMPILED_ENGLISH_QM_VERIFIED")
        self.assertEqual(data["english_qm_sha256"],hashlib.sha256(raw).hexdigest())
        self.assertFalse(data["catalog_loaded_by_arm64_process_proven"])
        self.assertFalse(data["translated_pixels_proven"])
        self.assertFalse(data["flashable"])

    def test_missing_english_not_replaced_with_other_locale(self):
        (self.qmdir/"asteroid-launcher.fr.qm").write_bytes(locale.QM_MAGIC+b"x"*30)
        with self.assertRaisesRegex(locale.LocaleAuditError,"FALLBACK_CATALOG_MISSING"):
            locale.inspect(self.root)

    def test_uncompiled_ts_xml_rejected(self):
        self.write_qm(b"<TS version='2.1'>"+b" " * 150)
        with self.assertRaisesRegex(locale.LocaleAuditError,"WRONG_MAGIC"):
            locale.inspect(self.root)

    def test_catalog_symlink_rejected_even_if_inside_root(self):
        target=self.qmdir/"real.qm"
        target.write_bytes(locale.QM_MAGIC+b"x"*200)
        self.qm.symlink_to(target.name)
        with self.assertRaisesRegex(locale.LocaleAuditError,"SYMLINK"):
            locale.inspect(self.root)

    def test_catalog_symlink_to_host_rejected(self):
        self.qm.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(locale.LocaleAuditError,"MISSING|UNSAFE"):
            locale.inspect(self.root)

    def test_empty_or_truncated_catalog_rejected(self):
        self.write_qm(locale.QM_MAGIC)
        with self.assertRaisesRegex(locale.LocaleAuditError,"BAD_FILE_SIZE"):
            locale.inspect(self.root)

    def test_no_silent_host_translation_directory_fallback(self):
        self.qmdir.rmdir()
        with self.assertRaisesRegex(locale.LocaleAuditError,"DIRECTORY_ABSENT"):
            locale.inspect(self.root)

    def test_no_symlinked_root_directory(self):
        actual=self.root
        proxy=actual.parent/"alias"
        proxy.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(locale.LocaleAuditError,"INVALID_EXTRACTED"):
            locale.inspect(proxy)


if __name__=="__main__":
    unittest.main()
