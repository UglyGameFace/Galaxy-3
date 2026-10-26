"""Machine-scoped and low-power launcher source checks (host only)."""
from pathlib import Path
import ast
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "meta-noblesse/recipes-asteroid/uglyos-launchers/uglyos-launchers"
RECIPE = ROOT / "meta-noblesse/recipes-asteroid/uglyos-launchers/uglyos-launchers_1.0.bb"
IMAGE = ROOT / "meta-noblesse/recipes-core/images/asteroid-image.bbappend"
LAYOUTS = ("900-uglyos-fast-list.qml", "901-uglyos-compact-grid.qml",
           "902-uglyos-stoner-lounge.qml", "903-uglyos-gamer-arcade.qml")


class LauncherContracts(unittest.TestCase):
    def test_four_selectable_additive_layouts(self):
        self.assertEqual(tuple(sorted(p.name for p in ASSETS.glob("*.qml"))), LAYOUTS)
        recipe = RECIPE.read_text()
        for name in LAYOUTS:
            self.assertIn("file://" + name, recipe)
            self.assertIn(name, recipe.split("do_install() {", 1)[1])
        self.assertIn('COMPATIBLE_MACHINE = "(noblesse-r08)"', recipe)
        self.assertIn('INHIBIT_DEFAULT_DEPS = "1"', recipe)
        self.assertIn("PACKAGE_ARCH", recipe)
        self.assertIn("asteroid-launcher/applauncher", recipe)
        self.assertIn('RDEPENDS:' + '$' + '{PN} = "asteroid-launcher"', recipe)
        self.assertIn('deps != ["asteroid-launcher"]', recipe)
        self.assertIn('IMAGE_INSTALL:append:noblesse-r08 = " uglyos-launchers"', IMAGE.read_text())
        self.assertIn('IMAGE_INSTALL:append:noblesse-r08 = " watch3-faces"', IMAGE.read_text())
        self.assertNotIn("000-default-horizontal.qml", recipe)

    def test_lightweight_bounded_virtualized_rendering(self):
        for name in LAYOUTS:
            with self.subTest(name=name):
                source = (ASSETS / name).read_text()
                self.assertTrue(source.startswith("// SPDX-License-Identifier: MIT"))
                self.assertLess(len(source), 6000)
                self.assertIn("model: launcherModel", source)
                self.assertIn("model.object.launchApplication()", source)
                self.assertIn('objectName: "uglyos-app-item-" + index', source)
                self.assertTrue("cacheBuffer: height * 0.55" in source or
                                "cacheBuffer: height * 0.5" in source)
                self.assertIn("enabled: !appsView.dragging", source)
                self.assertIn("Text.ElideRight", source)
                if name.startswith(("900", "901")):
                    self.assertIn('key: "/desktop/uglyos/appearance/accent"', source)
                    self.assertIn('defaultValue: "original"', source)
                else:
                    self.assertIn('key: "/desktop/uglyos/appearance/effects"', source)
                    self.assertIn('defaultValue: "subtle"', source)
                    self.assertIn("Behavior on color", source)
                    self.assertIn("ColorAnimation { duration:", source)
                    self.assertNotIn("running: true", source)
                    self.assertNotIn("loops:", source)
                self.assertIn("grid.changeAllowedDirections()", source)
                for forbidden in ("ShaderEffect", "DropShadow", "FastBlur", "Canvas {",
                                  "WebView", "Timer {", "NumberAnimation", "RotationAnimation",
                                  "ParticleSystem", "Repeater {", "PathView", "XMLHttpRequest",
                                  "eval(", "layer.enabled"):
                    self.assertNotIn(forbidden, source)
                self.assertEqual(source.count("{"), source.count("}"))

    def test_host_renderer_compiles_and_avoids_hardware(self):
        program = (ROOT / "tools/render_uglyos_launchers.py").read_text()
        ast.parse(program)
        self.assertIn("class AppModel(QAbstractListModel)", program)
        self.assertIn("QTest.mouseClick", program)
        self.assertIn("OFF-DEVICE ONLY", program)
        self.assertNotIn("sdb shell", program)
        self.assertNotIn("fastboot flash", program)
        settings = (ROOT / "meta-noblesse/recipes-asteroid/asteroid-settings/files/0002-uglyos-launcher-effects.patch").read_text()
        self.assertIn('key: "/desktop/uglyos/appearance/effects"', settings)
        self.assertIn("OptionCycler {", settings)
        self.assertIn("Off", settings)
        self.assertIn("Subtle", settings)


if __name__ == "__main__":
    unittest.main()
