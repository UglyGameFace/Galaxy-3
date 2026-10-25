"""R08-only appearance source guards; actual git apply occurs in separate CI."""
from pathlib import Path
import ast
import unittest

ROOT = Path(__file__).resolve().parents[1]
FACES = ROOT / "meta-noblesse/recipes-asteroid/watch3-faces/watch3-faces"
SETTINGS = ROOT / "meta-noblesse/recipes-asteroid/asteroid-settings"
NAMES = ("900-watch3-orbit.qml", "901-watch3-focus.qml", "902-watch3-signal.qml")
PALETTES = ("emerald", "ice", "violet", "ember", "rose")
KEY = "/desktop/uglyos/appearance/accent"


class AppearanceContractTests(unittest.TestCase):
    def test_original_colors_and_one_shared_key(self):
        for name in NAMES:
            with self.subTest(face=name):
                qml = (FACES / name).read_text()
                self.assertIn("import Nemo.Configuration", qml)
                self.assertEqual(qml.count('key: "' + KEY + '"'), 1)
                self.assertEqual(qml.count('defaultValue: "original"'), 1)
                self.assertIn('accentChoice !== "original"', qml)
                for preset in PALETTES:
                    self.assertIn('accentChoice === "' + preset + '"', qml)
        for name, color in zip(NAMES, ("#6EED9A", "#DDDDDD", "#FFC36B")):
            self.assertIn(': "' + color + '"', (FACES / name).read_text())

    def test_settings_patch_scoped_and_existing_selector_kept(self):
        bb = (SETTINGS / "asteroid-settings_%.bbappend").read_text()
        self.assertIn("SRC_URI:append:noblesse-r08", bb)
        self.assertNotIn("SRC_URI:append = ", bb)
        patch = (SETTINGS / "files/0001-uglyos-watchface-accent.patch").read_text()
        self.assertIn('text: qsTr("UgLy|OS accent")', patch)
        self.assertIn("OptionCycler {", patch)
        self.assertIn('key: "' + KEY + '"', patch)
        self.assertIn("WatchfaceSelector {", patch)

    def test_pinned_patch_verifier_and_no_hardware_commands(self):
        source = (ROOT / "tools/validate_uglyos_settings_patch.py").read_text()
        ast.parse(source)
        self.assertIn("60340bd1c27a7b9e4884bd61c0563d091bc8b240", source)
        self.assertIn('run(repo, "apply", "--check", str(PATCH))', source)
        self.assertNotIn("sdb shell", source)
        self.assertNotIn("fastboot flash", source)


if __name__ == "__main__":
    unittest.main()
