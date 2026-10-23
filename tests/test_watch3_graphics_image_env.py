"""Ensure graphics metadata preflight fails closed on missing runtime pieces."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from check_watch3_graphics_image_env import check_graphics_image_closure, read_variable

MACHINE = 'MACHINE="noblesse-r08"\n'
IMAGE = MACHINE + ('DISTRO="asteroid"\nDISTRO_FEATURES="wayland bluetooth"\n'
                   'IMAGE_INSTALL="kernel-modules asteroid-launcher asteroid-settings"\n')
LAUNCHER = MACHINE + (
    'RDEPENDS:asteroid-launcher="qtbase-plugins qtwayland-plugins '
    'qtdeclarative-qmlplugins asteroid-launcher-configs qml-asteroid"\n')
BASE = MACHINE + ('PACKAGECONFIG="gui linuxfb wayland widgets"\n'
                  'PACKAGES="qtbase-plugins qtbase"\n'
                  'FILES:qtbase-plugins="/usr/lib/qt6/plugins/*/*.so"\n')
WAYLAND = MACHINE + ('REQUIRED_DISTRO_FEATURES="wayland"\n'
                     'PACKAGES="qtwayland-plugins qtwayland-qmlplugins qtwayland"\n'
                     'FILES:qtwayland-plugins="/usr/lib/qt6/plugins/*/*.so"\n')
DECL = MACHINE + ('PACKAGES="qtdeclarative-qmlplugins qtdeclarative"\n'
                  'FILES:qtdeclarative-qmlplugins="/usr/lib/qt6/qml"\n')


def check(image=IMAGE, launcher=LAUNCHER, base=BASE,
          wayland=WAYLAND, decl=DECL):
    return check_graphics_image_closure(image, launcher, base, wayland, decl)


class TestGraphicsImageClosure(unittest.TestCase):
    def test_expected_packages_and_image_pass(self):
        self.assertEqual(check(), [])

    def test_distro_and_machine_cannot_be_wrong(self):
        self.assertTrue(any('DISTRO' in e for e in
                            check(image=IMAGE.replace('DISTRO="asteroid"', 'DISTRO="other"'))))
        self.assertTrue(any('MACHINE' in e for e in
                            check(wayland=WAYLAND.replace('noblesse-r08', 'another'))))

    def test_launcher_must_be_in_image(self):
        self.assertTrue(any('IMAGE_INSTALL' in e for e in
                            check(image=IMAGE.replace('asteroid-launcher ', ''))))

    def test_wayland_feature_required(self):
        self.assertTrue(any('DISTRO_FEATURES' in e for e in
                            check(image=IMAGE.replace('wayland ', ''))))
        self.assertTrue(any('REQUIRED_DISTRO_FEATURES' in e for e in
                            check(wayland=WAYLAND.replace('"wayland"', '""'))))

    def test_requires_all_explicit_launcher_packages(self):
        for pkg in ('qtbase-plugins', 'qtwayland-plugins',
                    'qtdeclarative-qmlplugins', 'asteroid-launcher-configs'):
            with self.subTest(pkg=pkg):
                self.assertTrue(any(pkg in e for e in
                                    check(launcher=LAUNCHER.replace(pkg + ' ', ''))))

    def test_recommendations_are_not_accepted(self):
        different = LAUNCHER.replace('qtwayland-plugins ', '') + \
            'RRECOMMENDS:asteroid-launcher="qtwayland-plugins"\n'
        self.assertTrue(any('qtwayland-plugins' in e for e in check(launcher=different)))

    def test_qtwayland_compositor_package_required(self):
        self.assertTrue(any('qtwayland PACKAGES' in e for e in
                            check(wayland=WAYLAND.replace(' qtwayland"', '"'))))

    def test_plugin_files_must_map_to_plugins(self):
        self.assertTrue(any('qtbase-plugins FILES' in e for e in
                            check(base=BASE.replace('/plugins/', '/nowhere/'))))
        self.assertTrue(any('qtdeclarative-qmlplugins FILES' in e for e in
                            check(decl=DECL.replace('/qml', '/nowhere'))))

    def test_linuxfb_and_qtbase_wayland_features_are_required(self):
        for feature in ('linuxfb', 'wayland'):
            with self.subTest(feature=feature):
                self.assertTrue(any('PACKAGECONFIG' in e for e in
                                    check(base=BASE.replace(' ' + feature, ''))))

    def test_bitbake_history_comment_is_ignored(self):
        self.assertEqual(read_variable('# PACKAGECONFIG="bad"\n' + BASE,
                                       'PACKAGECONFIG'), 'gui linuxfb widgets')


if __name__ == '__main__':
    unittest.main()
