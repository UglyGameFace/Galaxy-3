"""Offline launcher runtime probe tests; all binaries are fabricated mini-ELFs."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r08_qemu_launcher_runtime as probe


def elf(machine=183):
    b = bytearray(256)
    b[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", b, 16, 3, machine)
    return bytes(b)


def trace(platform="offscreen"):
    return (
        'qt.core.plugin.loader: loaded library "/guest/usr/lib/plugins/platforms/libq' +
        platform + '.so"\n' +
        'QQmlImportDatabase::addLibraryImport: "qrc:/Launcher/compositor.qml" '
        '"QtQuick" version 6.0 as ""\n')


class RuntimeAnalysisTests(unittest.TestCase):
    def test_real_import_plus_real_plugin_and_clean_exit(self):
        result = probe.analyze(trace(), platform="offscreen",
                               returncode=0, timed_out=False, elapsed=0.9)
        self.assertEqual(result["status"],
                         "REAL_ARM64_LAUNCHER_QML_RUNTIME_OBSERVED_OFF_DEVICE")
        self.assertFalse(result["compositor_pixel_output_proven"])
        self.assertFalse(result["flashable"])

    def test_timeout_without_specific_import_not_success(self):
        result = probe.analyze('qt debug: running\n', platform="offscreen",
                               returncode=-9, timed_out=True, elapsed=9)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")

    def test_qml_import_without_loaded_qpa_plugin_not_success(self):
        result = probe.analyze('QQmlImportDatabase qrc:/Launcher/compositor.qml',
                               platform="offscreen", returncode=0,
                               timed_out=False, elapsed=1)
        self.assertFalse(result["actual_qpa_plugin_loaded_in_qemu_trace"])

    def test_loaded_qpa_with_wrong_qml_uri_not_success(self):
        result = probe.analyze(
            'loaded library "/guest/usr/lib/plugins/platforms/libqoffscreen.so"\n'
            'QQmlImportDatabase::addLibraryImport: "qrc:/Other/other.qml"',
            platform="offscreen", returncode=0,
            timed_out=False, elapsed=1)
        self.assertFalse(result["actual_compositor_qrc_qml_import_trace_seen"])

    def test_fatal_qml_error_overrides_successful_trace(self):
        result = probe.analyze(trace()+'\nmodule "QtQuick" is not installed\n',
                               platform="offscreen", returncode=0,
                               timed_out=False, elapsed=1)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")
        self.assertTrue(result["fatal_messages_seen"])

    def test_crash_after_successful_trace_not_success(self):
        result = probe.analyze(trace(), platform="offscreen",
                               returncode=-11, timed_out=False, elapsed=2)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")

    def test_source_grounded_real_tutorial_state_and_delegates_is_runtime_proof(self):
        # The exact WELCOME transition is defined in pinned source
        # src/qml/firstrun/Tutorial.qml; not generic host Qt log chatter.
        real = ('qt.qml.states: 0x10df350 changing state from: "" to: "WELCOME"\n'
                'qt.qml.delegatemodel.recycling: pool size after drain: 0\n')
        result = probe.analyze(real, platform="offscreen",
                               returncode=-9, timed_out=True, elapsed=9.0)
        self.assertEqual(result["status"],
                         "REAL_ARM64_LAUNCHER_QML_RUNTIME_OBSERVED_OFF_DEVICE")
        self.assertEqual(result["evidence_mode"],
                         "PINNED_SOURCE_TUTORIAL_WELCOME_AND_QML_DELEGATES")
        self.assertTrue(result["pinned_source_tutorial_welcome_state_changed"])
        self.assertTrue(result["qml_delegate_processing_observed"])
        self.assertFalse(result["actual_qpa_plugin_loaded_in_qemu_trace"])
        self.assertFalse(result["actual_compositor_qrc_qml_import_trace_seen"])
        self.assertFalse(result["compositor_pixel_output_proven"])

    def test_welcome_string_without_actual_qml_state_transition_rejected(self):
        result = probe.analyze("Welcome to AsteroidOS\nqt.qml.delegatemodel.recycling: hello",
                               platform="offscreen", returncode=0,
                               timed_out=False, elapsed=1)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")

    def test_state_transition_without_qml_delegate_processing_rejected(self):
        result = probe.analyze(
            'qt.qml.states: 0x1 changing state from: "" to: "WELCOME"',
            platform="offscreen", returncode=0, timed_out=False, elapsed=1)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")

    def test_fatal_qml_error_blocks_source_grounded_state_evidence(self):
        real = ('qt.qml.states: 0x1 changing state from: "" to: "WELCOME"\n'
                'qt.qml.delegatemodel.recycling: no available item\n'
                'module "QtQuick" is not installed\n')
        result = probe.analyze(real, platform="offscreen",
                               returncode=-9, timed_out=True, elapsed=9)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")

    def test_sustained_real_qml_delegate_activity_proves_bounded_engine_runtime(self):
        lines = ('qt.qml.delegatemodel.recycling: no available item\n' * 24)
        result = probe.analyze(lines, platform="offscreen",
                               returncode=-9, timed_out=True, elapsed=9.0)
        self.assertEqual(result["status"],
                         "REAL_ARM64_LAUNCHER_QML_RUNTIME_OBSERVED_OFF_DEVICE")
        self.assertEqual(result["evidence_mode"],
                         "BOUNDED_ARM64_QML_DELEGATE_EVENT_PROCESSING")
        self.assertEqual(result["qml_delegate_trace_line_count"], 24)
        self.assertTrue(result["qml_delegate_processing_sustained"])
        self.assertFalse(result["actual_qpa_plugin_loaded_in_qemu_trace"])
        self.assertFalse(result["compositor_pixel_output_proven"])

    def test_sparse_delegates_do_not_prove_runtime(self):
        lines = ('qt.qml.delegatemodel.recycling: no available item\n' * 19)
        result = probe.analyze(lines, platform="offscreen",
                               returncode=-9, timed_out=True, elapsed=9.0)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")

    def test_sustained_delegates_with_early_crash_do_not_pass(self):
        lines = ('qt.qml.delegatemodel.recycling: active\n' * 40)
        result = probe.analyze(lines, platform="offscreen",
                               returncode=-11, timed_out=False, elapsed=2.0)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")

    def test_svg_runtime_decode_error_is_not_silently_accepted(self):
        error = ('qrc:/qt-project.org/imports/QtQuick/VirtualKeyboard/'
                 'Styles/Builtin/default/style.qml: QML Image: Error decoding: '
                 'image.svg: Unsupported image format\n')
        result = probe.analyze(trace() + error,
                               platform="offscreen", returncode=0,
                               timed_out=False, elapsed=18)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")
        self.assertIn("unsupported image format", result["fatal_messages_seen"])

    def test_short_timeout_cannot_be_accepted(self):
        result = probe.analyze(trace(), platform="offscreen",
                               returncode=-9, timed_out=True, elapsed=0.2)
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")


class RealPluginSelectionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.plugin_dir = self.root / "usr/lib/plugins/platforms"
        self.plugin_dir.mkdir(parents=True)
        (self.root/"usr/bin").mkdir(parents=True)
        (self.root/"usr/bin/asteroid-launcher").write_bytes(elf())
        (self.root/"usr/lib/qml").mkdir(parents=True)

    def test_prefers_offscreen_real_aarch64_plugin(self):
        p = self.plugin_dir/"libqoffscreen.so"
        p.write_bytes(elf())
        (self.plugin_dir/"libqminimal.so").write_bytes(elf())
        platform, found = probe.locate_plugin(self.root)
        self.assertEqual(platform, "offscreen")
        self.assertEqual(found, p)

    def test_falls_back_to_real_minimal_plugin(self):
        (self.plugin_dir/"libqminimal.so").write_bytes(elf())
        self.assertEqual(probe.locate_plugin(self.root)[0], "minimal")

    def test_absent_plugins_never_fake_success(self):
        with self.assertRaisesRegex(probe.RuntimeFailure, "NO_ARM64_"):
            probe.locate_plugin(self.root)

    def test_wrong_architecture_plugin_never_used(self):
        (self.plugin_dir/"libqoffscreen.so").write_bytes(elf(machine=62))
        with self.assertRaisesRegex(probe.RuntimeFailure, "NOT_AARCH64"):
            probe.locate_plugin(self.root)

    def test_host_symlink_escape_is_rejected(self):
        (self.plugin_dir/"libqoffscreen.so").symlink_to("/usr/bin/true")
        with self.assertRaisesRegex(probe.RuntimeFailure, "ESCAPES_ROOT"):
            probe.locate_plugin(self.root)

    def test_installed_aarch64_svg_decoder_detected_inside_real_qt_plugin_root(self):
        formats=self.plugin_dir.parent/"imageformats"
        formats.mkdir()
        candidate=formats/"libqsvg.so"
        candidate.write_bytes(elf())
        roots,svg=probe.actual_qt_plugin_roots(self.root)
        self.assertIn(formats.parent,roots)
        self.assertEqual(svg,[candidate])

    def test_non_arm64_svg_decoder_fails_explicitly(self):
        formats=self.plugin_dir.parent/"imageformats"
        formats.mkdir()
        (formats/"libqsvg.so").write_bytes(elf(machine=62))
        with self.assertRaisesRegex(probe.RuntimeFailure,"QT_SVG_PLUGIN_WRONG_ARCH"):
            probe.actual_qt_plugin_roots(self.root)

    def test_svg_decoder_missing_cannot_be_silently_assumed_present(self):
        roots,svg=probe.actual_qt_plugin_roots(self.root)
        self.assertTrue(roots)
        self.assertFalse(svg)

    def test_timeout_bound(self):
        with self.assertRaisesRegex(probe.RuntimeFailure, "OUT_OF_BOUNDS"):
            probe.inspect(self.root, duration=99)

    def test_excess_qt_output_preserves_prefix_and_tail_but_fails_closed(self):
        (self.plugin_dir/"libqoffscreen.so").write_bytes(elf())
        class Completed:
            pid = 1011
            returncode = 0
            def wait(self, timeout):
                return 0
        def verbose(*args, **kwargs):
            handle=kwargs["stdout"]
            handle.write(trace().encode())
            handle.write(b"q" * (probe.MAX_LOG_BYTES + 100))
            handle.write(b"QML_END_DIAGNOSTIC")
            return Completed()
        with patch.object(probe.shutil, "which", return_value="/usr/bin/qemu-aarch64"), \
             patch.object(probe.subprocess, "Popen", side_effect=verbose):
            result, log = probe.inspect(self.root)
        self.assertTrue(result["guest_log_truncated_for_analysis"])
        self.assertEqual(result["reason"], "EXCESSIVE_QT_STARTUP_OUTPUT")
        self.assertEqual(result["status"], "LAUNCHER_RUNTIME_NOT_PROVEN")
        self.assertIn("QML_END_DIAGNOSTIC", log)
        self.assertIn("compositor.qml", log)

    def test_bounded_actual_qemu_command_and_environment(self):
        (self.plugin_dir/"libqoffscreen.so").write_bytes(elf())
        class Completed:
            pid = 1010
            returncode = 0
            def wait(self, timeout):
                return self.returncode
        def start(*args, **kwargs):
            kwargs["stdout"].write(trace().encode())
            return Completed()
        with patch.object(probe.shutil, "which", return_value="/usr/bin/qemu-aarch64"), \
             patch.object(probe.subprocess, "Popen", side_effect=start) as popen:
            result, log = probe.inspect(self.root)
        self.assertEqual(result["status"], "REAL_ARM64_LAUNCHER_QML_RUNTIME_OBSERVED_OFF_DEVICE")
        args = popen.call_args.args[0]
        self.assertEqual(args[:3], ["qemu-aarch64", "-L", str(self.root)])
        self.assertEqual(args[-2:], ["-platform", "offscreen"])
        env = popen.call_args.kwargs["env"]
        self.assertEqual(env["QT_QPA_PLATFORM"], "offscreen")
        self.assertEqual(env["QT_QUICK_BACKEND"], "software")
        self.assertEqual(env["QT_PLUGIN_PATH"], str(self.plugin_dir.parent))
        self.assertEqual(env["QT_DEBUG_PLUGINS"], "0")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertFalse(result["watch_contacted"])


if __name__ == "__main__":
    unittest.main()
