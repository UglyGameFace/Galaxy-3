"""Static safety checks for host-render validation, no device or fake boot gate."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/render_uglyos_faces.py"
WORKFLOW = ROOT / ".github/workflows/watch3-r08-uglyos-visual-proofs.yml"
MOCK = ROOT / "tools/uglyos-render-fixtures/Nemo/Mce/MceBatteryLevel.qml"


class HostRenderContracts(unittest.TestCase):
    def test_runner_is_parseable_and_loads_real_faces(self):
        src = SCRIPT.read_text()
        ast.parse(src)
        self.assertIn("FACES / name", src)
        self.assertIn("QQuickView()", src)
        self.assertIn('QT_QUICK_BACKEND", "software"', src)
        self.assertIn("view.grabWindow()", src)
        self.assertIn("view.engine().warnings.connect", src)
        self.assertIn("QQuickView.Ready", src)
        self.assertIn("Burn-in offset invalid", src)
        self.assertIn('expected_time = "3:42 PM" if use12 else "15:42"', src)
        self.assertIn('property("currentTime")', src)

    def test_coverage_and_automated_pixel_guards(self):
        src = SCRIPT.read_text()
        for case in ('"active-24h"', '"active-12h"', '"ambient"',
                     '"nightstand"', '"compact-240"'):
            self.assertIn(case, src)
        self.assertIn("highlights < 40", src)
        self.assertIn("len(distinct) < 5", src)
        self.assertIn('image_bytes[(name, "active-24h")] == image_bytes[(name, "ambient")]', src)
        self.assertIn('image_bytes[(name, "active-24h")] == image_bytes[(name, "active-12h")]', src)

    def test_palette_choices_have_full_host_render_coverage(self):
        src = SCRIPT.read_text()
        for name in ("emerald", "ice", "violet", "ember", "rose"):
            self.assertIn('"palette-' + name + '"', src)
        self.assertIn("mockAccentPreset", src)
        self.assertIn("Accent preset mismatch", src)
        self.assertIn("Accent palettes do not produce distinct renders", src)
        self.assertIn('30 real QML previews', src)
        self.assertTrue((ROOT / "tools/uglyos-render-fixtures/Nemo/Configuration/qmldir").is_file())

    def test_mock_is_explicit_and_watch_writes_are_absent(self):
        src = SCRIPT.read_text()
        self.assertIn("MOCK clock, battery", src)
        self.assertIn('"not_verified"', src)
        self.assertNotIn("subprocess.run", src)
        self.assertNotIn("sdb shell", src)
        self.assertNotIn("fastboot", src)
        self.assertEqual(MOCK.read_text().count("property int percent: 73"), 1)

    def test_ci_only_uploads_preview_artifacts(self):
        flow = WORKFLOW.read_text()
        self.assertIn("ubuntu-24.04", flow)
        self.assertIn("PySide6==6.8.3", flow)
        self.assertIn("QT_QPA_PLATFORM: offscreen", flow)
        self.assertIn("QT_QUICK_BACKEND: software", flow)
        self.assertIn("render_uglyos_faces.py --output", flow)
        self.assertIn("render-report.json", flow)
        self.assertIn("OFFDEVICE-MOCK-SIGNALS", flow)
        self.assertNotIn("bitbake ", flow)
        self.assertNotIn("sdb ", flow)


if __name__ == "__main__":
    unittest.main()
