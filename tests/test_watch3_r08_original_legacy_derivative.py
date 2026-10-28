"""Safety regression tests for the real-image legacy-ext4 derivative.

Synthetic bytes only. The full original ext4 is audited in GitHub Actions.
"""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from derive_watch3_r08_original_legacy_ext4 import (
    DERIVED_NAME, DeriveError, copy_exclusive
)
import derive_watch3_r08_original_legacy_ext4 as derivative

class OfflineDerivativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder=Path(self.tmp.name)
        self.original=folder/"asteroid-image-noblesse-r08.rootfs-20261024125252.ext4"
        self.target=folder/DERIVED_NAME
        self.original.write_bytes(b"synthetic-original-test-only")
        self.sha=hashlib.sha256(self.original.read_bytes()).hexdigest()

    def test_refuses_existing_output_without_overwriting(self):
        self.target.write_bytes(b"do-not-clobber")
        with self.assertRaisesRegex(DeriveError,"UNSAFE"):
            copy_exclusive(self.original,self.target)
        self.assertEqual(self.target.read_bytes(),b"do-not-clobber")

    def test_refuses_symlink_as_output(self):
        self.target.symlink_to(self.original)
        with self.assertRaisesRegex(DeriveError,"UNSAFE"):
            copy_exclusive(self.original,self.target)
        self.assertEqual(self.original.read_bytes(),b"synthetic-original-test-only")

    def test_rejects_fake_original_before_tune_is_invoked(self):
        with patch.object(derivative,"run") as external:
            with self.assertRaises(ValueError):
                derivative.derive(self.original,self.target)
        external.assert_not_called()
        self.assertFalse(self.target.exists())

    def test_rejects_absent_orphan_file_without_creating_copy(self):
        proof={"source_workflow_run":40095182440,"original_ext4_sha256":self.sha}
        with patch.object(derivative,"verify_file",return_value=proof), \
             patch.object(derivative,"features",return_value={"extent","filetype"}), \
             patch.object(derivative,"run") as external:
            with self.assertRaisesRegex(DeriveError,"NOT_PRESENT"):
                derivative.derive(self.original,self.target)
        external.assert_not_called()
        self.assertFalse(self.target.exists())

    def test_derived_copy_only_mutated_and_source_remains_identical(self):
        proof={"source_workflow_run":40095182440,"original_ext4_sha256":self.sha}
        seen=[]
        def external(*args,**kwargs):
            self.assertEqual(args[:3],("tune2fs","-O","^orphan_file"))
            self.assertEqual(Path(args[3]),self.target)
            seen.append(args)
            # Fake the post-conversion difference on SYNTHETIC bytes only.
            with self.target.open("r+b") as f:
                f.write(b"S")
        original_before=self.original.read_bytes()
        with patch.object(derivative,"verify_file",return_value=proof), \
             patch.object(derivative,"IMAGE_SHA256",self.sha), \
             patch.object(derivative,"IMAGE_BYTES",len(original_before)), \
             patch.object(derivative,"features",side_effect=[
                 {"filetype","extent","orphan_file"},{"filetype","extent"}]), \
             patch.object(derivative,"run",side_effect=external), \
             patch.object(derivative,"check_legacy",return_value={
                 "status":"PASS_OFF_DEVICE_LEGACY_EXT4"}):
            result=derivative.derive(self.original,self.target)
        self.assertEqual(len(seen),1)
        self.assertEqual(self.original.read_bytes(),original_before)
        self.assertNotEqual(self.target.read_bytes(),original_before)
        self.assertFalse(result["watch_contacted"])
        self.assertFalse(result["flashable"])
        self.assertTrue(result["orphan_file_absent"])
        self.assertFalse(result["older_e2fsprogs_checked"])

    def test_failed_tuner_deletes_untrusted_derivative(self):
        proof={"source_workflow_run":40095182440,"original_ext4_sha256":self.sha}
        with patch.object(derivative,"verify_file",return_value=proof), \
             patch.object(derivative,"IMAGE_SHA256",self.sha), \
             patch.object(derivative,"IMAGE_BYTES",self.original.stat().st_size), \
             patch.object(derivative,"features",return_value={
                 "filetype","extent","orphan_file"}), \
             patch.object(derivative,"run",side_effect=DeriveError("TUNE_FAILED")):
            with self.assertRaisesRegex(DeriveError,"TUNE_FAILED"):
                derivative.derive(self.original,self.target)
        self.assertFalse(self.target.exists())
        self.assertEqual(hashlib.sha256(self.original.read_bytes()).hexdigest(),self.sha)

if __name__=="__main__":
    unittest.main()
