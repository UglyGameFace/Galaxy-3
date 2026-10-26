"""Guard native UgLy|OS App Hub from becoming a fake APK/opkg installer."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"tools"))
from build_uglyos_app_hub import load
from generate_uglyos_watch_catalog import make_catalog

APP = ROOT/"meta-noblesse/recipes-asteroid/uglyos-app-hub/uglyos-app-hub"
RECIPE = ROOT/"meta-noblesse/recipes-asteroid/uglyos-app-hub/uglyos-app-hub_0.1.bb"
IMAGE = ROOT/"meta-noblesse/recipes-core/images/asteroid-image.bbappend"
CATALOG = ROOT/"app-hub/catalog.json"

class NativeHubTests(unittest.TestCase):
    def test_exact_validated_catalog_data_is_used(self):
        source = make_catalog(CATALOG)
        self.assertEqual((APP/"HubCatalog.js").read_text(), source)
        self.assertEqual(len(load(CATALOG)["entries"]), 10)
        self.assertIn("var entries =", source)
        self.assertIn('"installable": false', source)
        self.assertEqual(source.count('"installable": false'), 10)

    def test_offline_qml_no_package_mgmt_and_no_web_navigation(self):
        src = (APP/"HubPage.qml").read_text()
        main = (APP/"main.qml").read_text()
        self.assertIn('import "HubCatalog.js" as Catalog', src)
        self.assertIn('objectName: "uglyos-hub-list"', src)
        self.assertIn('objectName: "uglyos-hub-next-filter"', src)
        self.assertIn('objectName: "uglyos-hub-details"', src)
        self.assertIn('property bool installEnabled: false', src)
        self.assertIn("Application {", main)
        self.assertIn("HubPage {", main)
        for path in (APP/"HubPage.qml", APP/"main.qml", APP/"main.cpp"):
            body = path.read_text()
            for needle in ("XMLHttpRequest", "fetch(", "opkg install", "QProcess",
                           "WebEngineView", "Qt.openUrlExternally", "fastboot",
                           "su -c", "Settings.System", "networkAccess"):
                self.assertNotIn(needle, body)
        self.assertNotIn("Timer {", src)
        self.assertNotIn("ShaderEffect", src)

    def test_real_upstream_qt6_app_contract_used(self):
        cmake = (APP/"CMakeLists.txt").read_text()
        bb = RECIPE.read_text()
        for keyword in ("AsteroidApp6 REQUIRED","asteroid_app_qml_module",
                        "generate_desktop","add_library(uglyos-app-hub",
                        "Asteroid::AsteroidApp6"):
            self.assertIn(keyword, cmake)
        self.assertIn("AsteroidApp::main", (APP/"main.cpp").read_text())
        self.assertIn("invoker --single-instance --type=asteroid-qt6",
                      (APP/"uglyos-app-hub.in").read_text())
        self.assertIn("Exec=uglyos-app-hub", (APP/"uglyos-app-hub.desktop.template").read_text())
        for name in ("CMakeLists.txt","main.cpp","main.qml","HubPage.qml",
                     "HubCatalog.js","uglyos-app-hub.in","uglyos-app-hub.desktop.template"):
            self.assertIn("file://"+name, bb)
            self.assertTrue((APP/name).is_file())
        self.assertIn('COMPATIBLE_MACHINE = "^noblesse-r08$"', bb)
        self.assertIn("inherit qt6-cmake", bb)
        self.assertIn('S = "\${UNPACKDIR}"'.replace("\\",""), bb)
        self.assertIn('IMAGE_INSTALL:append:noblesse-r08 = " uglyos-app-hub"', IMAGE.read_text())
        self.assertNotIn("do_install:append()",bb)
        self.assertNotIn("postinst",bb)
        self.assertNotIn("SRCREV = \${AUTOREV}".replace("\\",""),bb)

    def test_generated_catalog_prevents_install_enabled_regression(self):
        bad = json.loads(CATALOG.read_text())
        bad["entries"][0]["installable"] = True
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"catalog.json"
            p.write_text(json.dumps(bad))
            from build_uglyos_app_hub import CatalogError
            with self.assertRaises(CatalogError):
                make_catalog(p)
        self.assertEqual(make_catalog(CATALOG),make_catalog(CATALOG))

if __name__ == "__main__":
    unittest.main()
