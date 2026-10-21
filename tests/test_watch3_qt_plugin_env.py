"""Regression coverage for Qt platform plugin packaging metadata checks."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_watch3_qt_plugin_env import check_metadata, read_variable

QTBASE = ('MACHINE="noblesse-r08"\n'
          'PACKAGECONFIG="dbus gui linuxfb widgets"\n'
          'FILES:qtbase-plugins="/usr/lib/qt6/plugins/*/*.so"\n')
LAUNCHER = ('MACHINE="noblesse-r08"\n'
            'RDEPENDS:asteroid-launcher="qml-asteroid qtbase-plugins qtwayland-plugins"\n')


class TestQtPluginMetadata(unittest.TestCase):
    def test_realistic_passing_environment(self):
        self.assertEqual(check_metadata(QTBASE, LAUNCHER), [])

    def test_missing_linuxfb_feature(self):
        self.assertIn("qtbase PACKAGECONFIG is missing 'linuxfb'",
                      check_metadata(QTBASE.replace(" linuxfb", ""), LAUNCHER))

    def test_missing_qpa_plugin_package(self):
        self.assertIn("asteroid-launcher RDEPENDS is missing 'qtbase-plugins'",
                      check_metadata(QTBASE, LAUNCHER.replace("qtbase-plugins ", "")))

    def test_missing_wayland_plugin_package(self):
        self.assertIn("asteroid-launcher RDEPENDS is missing 'qtwayland-plugins'",
                      check_metadata(QTBASE, LAUNCHER.replace(" qtwayland-plugins", "")))

    def test_missing_package_file_mapping(self):
        self.assertIn("qtbase-plugins does not include Qt's plugin directory",
                      check_metadata(QTBASE.replace("/usr/lib/qt6/plugins/", "/other/"), LAUNCHER))

    def test_rejects_other_machine(self):
        errors = check_metadata(QTBASE, LAUNCHER.replace("noblesse-r08", "other"))
        self.assertTrue(any("expected MACHINE" in error for error in errors))

    def test_assignment_history_is_ignored(self):
        env = '# $PACKAGECONFIG [1 operations]\n#   set "disabled"\n' + QTBASE
        self.assertEqual(read_variable(env, "PACKAGECONFIG"), "dbus gui linuxfb widgets")


if __name__ == "__main__":
    unittest.main()
