"""Regression tests for BitBake's build-directory change, using fake metadata."""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_watch3_compositor_env import check_paths, SOURCE_FRAGMENT


class TestCompositorMetadataPaths(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / "workspace"
        self.workspace.mkdir()
        self.build = self.workspace / "build"
        self.build.mkdir()
        self.meta = self.workspace / "preflight-logs" / "metadata.env"
        self.meta.parent.mkdir()
        self.output = self.workspace / "preflight-logs" / "compositor-unpackdir.txt"
        self.unpack = self.build / "tmp" / "sources-unpack"
        self.env = 'MACHINE="noblesse-r08"\nFILESPATH="/repo/' + SOURCE_FRAGMENT + ':..."\nUNPACKDIR="' + str(self.unpack) + '"\n'
        self.meta.write_text(self.env)

    def test_absolute_output_after_switching_to_build_directory(self):
        original = Path.cwd()
        try:
            os.chdir(self.build)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(check_paths(self.meta, self.output))
        finally:
            os.chdir(original)
        self.assertEqual(self.output.read_text(), str(self.unpack) + "\n")
        self.assertFalse((self.build / "preflight-logs").exists())

    def test_relative_output_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(check_paths(self.meta, Path("preflight-logs/out.txt")))

    def test_wrong_machine_and_missing_override_are_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.meta.write_text(self.env.replace("noblesse-r08", "other-watch"))
            self.assertFalse(check_paths(self.meta, self.output))
            self.meta.write_text(self.env.replace(SOURCE_FRAGMENT, "upstream-only"))
            self.assertFalse(check_paths(self.meta, self.output))

    def test_missing_input_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(check_paths(self.workspace / "missing.env", self.output))


if __name__ == "__main__":
    unittest.main()
