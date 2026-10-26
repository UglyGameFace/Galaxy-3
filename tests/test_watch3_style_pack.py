"""Host-only checks for optional Watch3 AsteroidOS faces.

These tests do not render QML, run BitBake or demonstrate device boot.
"""
from pathlib import Path
import re
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "meta-noblesse/recipes-asteroid/watch3-faces/watch3-faces"
RECIPE = ROOT / "meta-noblesse/recipes-asteroid/watch3-faces/watch3-faces_1.0.bb"
IMAGE = ROOT / "meta-noblesse/recipes-core/images/asteroid-image.bbappend"
LEGACY_FILES = ("900-watch3-orbit.qml", "901-watch3-focus.qml", "902-watch3-signal.qml")
SOLO_FILES = ("903-watch3-solo-arcade.qml", "904-watch3-solo-lounge.qml")
FILES = (*LEGACY_FILES, *SOLO_FILES)


class StyleTests(unittest.TestCase):
    def test_recipe_and_assets_restricted_to_r08(self):
        recipe = RECIPE.read_text()
        self.assertEqual(tuple(sorted(x.name for x in ASSETS.glob("*.qml"))), FILES)
        for filename in FILES:
            self.assertIn("file://" + filename, recipe)
            self.assertIn(filename, recipe.split("do_install() {", 1)[1])
        for item in ('COMPATIBLE_MACHINE = "(noblesse-r08)"',
                     "PACKAGE_ARCH", "MACHINE_ARCH", "INHIBIT_DEFAULT_DEPS",
                     "UNPACKDIR", "asteroid-launcher/watchfaces",
                     "RDEPENDS:", "LIC_FILES_CHKSUM"):
            self.assertIn(item, recipe)

    def test_image_package_is_additive_and_legacy_ext4_preserved(self):
        image = IMAGE.read_text()
        self.assertIn('IMAGE_INSTALL:append:noblesse-r08 = " watch3-faces"', image)
        self.assertNotIn('IMAGE_INSTALL:append = " watch3-faces"', image)
        self.assertIn("-O ^orphan_file", image)

    def test_exact_uglyos_brand_and_safe_identifier(self):
        branding = ASSETS / "uglyos-edition.json"
        info = json.loads(branding.read_text())
        self.assertEqual(info["display_name"], "UgLy|OS")
        self.assertEqual(info["slug"], "uglyos")
        self.assertEqual(info["base_system"], "AsteroidOS")
        self.assertEqual(info["boot_status"], "not-boot-tested")
        self.assertEqual(info["install_status"], "not-flashable")
        self.assertIn('text: "UgLy|OS"', (ASSETS / FILES[0]).read_text())
        recipe = RECIPE.read_text()
        self.assertIn("file://uglyos-edition.json", recipe)
        self.assertIn("/uglyos/edition.json", recipe)
        self.assertIn("UNPACKDIR", recipe)
        self.assertNotIn("UgLy|OS", IMAGE.read_text(),
                         "The user-facing brand must not corrupt BitBake identifiers")

    def test_watchfaces_use_upstream_bindings_no_gpu_effects(self):
        banned = ("ShaderEffect", "DropShadow", "FastBlur", "Canvas {",
                  "layer.enabled", "MouseArea", "WebView", "Timer {",
                  "RotationAnimation", "NumberAnimation", "QtQuick.Effects",
                  "Qt5Compat.GraphicalEffects", "XMLHttpRequest", "eval(")
        palette = set()
        for name in FILES:
            with self.subTest(face=name):
                source = (ASSETS / name).read_text()
                self.assertTrue(source.startswith("// SPDX-License-Identifier: MIT"))
                for required in ("import QtQuick", "import Nemo.Mce",
                                 "MceBatteryLevel {", "wallClock.time",
                                 "use12H.value", "displayAmbient", "nightstand",
                                 "burnInProtectionManager.widthOffset",
                                 "burnInProtectionManager.heightOffset",
                                 "Text.NativeRendering",
                                 "Math.min(width, height)",
                                 "visible: !face.dimmed",
                                 "face.diameter * 0.80", "Qt.binding("):
                    self.assertIn(required, source)
                for value in banned:
                    if value == "MouseArea" and name in SOLO_FILES:
                        continue
                    self.assertNotIn(value, source)
                if name in SOLO_FILES:
                    self.assertIn("MouseArea", source)
                    self.assertIn("onClicked:", source)
                    self.assertIn("enabled: !face.dimmed", source)
                    self.assertLess(len(source), 6000)
                else:
                    self.assertLess(len(source), 5000)
                self.assertEqual(source.count("{"), source.count("}"))
                palette |= set(re.findall(r"#[0-9a-fA-F]{6}", source))
        self.assertGreaterEqual(len(palette), 10)


if __name__ == "__main__":
    unittest.main()
