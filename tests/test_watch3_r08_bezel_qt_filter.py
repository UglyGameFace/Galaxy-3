"""Check R08 Qt input patch policy before a costly target QtBase build.

This is a pinned-source check, not an AArch64 Qt compile or on-watch input test.
"""
from pathlib import Path
import os
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "meta-noblesse/recipes-qt/qt6/qtbase_%.bbappend"
PATCH = ROOT / "meta-noblesse/recipes-qt/qt6/qtbase/0001-noblesse-r08-tizen-detent-wheel-only.patch"
SOURCE = Path(os.environ.get("UGLYOS_PINNED_QTBASE_ROOT", "/nonexistent/qtbase"))

EVDEV = "src/platformsupport/input/evdevmouse/qevdevmousehandler.cpp"
EVDEV_HEADER = "src/platformsupport/input/evdevmouse/qevdevmousehandler_p.h"
LIBINPUT = "src/platformsupport/input/libinput/qlibinputhandler.cpp"


class BezelQtFilterTests(unittest.TestCase):
    def test_r08_only_meta_qt6_recipe(self):
        b = RECIPE.read_text()
        self.assertIn('FILESEXTRAPATHS:prepend:noblesse-r08 := "${THISDIR}/qtbase:"', b)
        self.assertIn(
            'SRC_URI:append:noblesse-r08 = " file://0001-noblesse-r08-tizen-detent-wheel-only.patch"', b)
        self.assertNotIn("QT_QPA_FB_NO_LIBINPUT=1", b)
        self.assertNotIn("IMAGE_INSTALL", b)

    def test_source_delta_is_explicitly_named_and_both_input_backends(self):
        p = PATCH.read_text()
        self.assertIn("Upstream-Status: Pending", p)
        for path in (EVDEV, EVDEV_HEADER, LIBINPUT):
            self.assertIn("--- a/" + path, p)
            self.assertIn("+++ b/" + path, p)
        self.assertEqual(p.count("--- a/src/"), 3)
        self.assertIn('std::strcmp(inputName, "tizen_detent") == 0', p)
        self.assertIn('std::strcmp(deviceName, "tizen_detent") == 0', p)
        self.assertIn('EVIOCGNAME(sizeof(inputName))', p)
        self.assertIn('EVIOCGBIT(EV_REL, sizeof(relFeatures))', p)
        self.assertIn('TEST_BIT(relFeatures, REL_WHEEL)', p)
        self.assertIn('m_watch3Detent = true;', p)
        self.assertIn('bool m_watch3Detent = false;', p)
        self.assertIn('m_watch3Detent && (data->code == REL_X || data->code == REL_Y)', p)
        self.assertIn('type == LIBINPUT_EVENT_POINTER_MOTION', p)
        self.assertIn('type == LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE', p)
        for forbidden in ("event18", "/dev/input/", "EVIOCGRAB", "KEY_POWER",
                          "QT_QPA_FB_DISABLE_INPUT", "QT_QPA_FB_NO_LIBINPUT=1",
                          "sudo ", "chmod", "system("):
            self.assertNotIn(forbidden, p)

    def test_exact_pinned_sources_are_patched_and_wheel_paths_preserved(self):
        if not (SOURCE / EVDEV).is_file():
            self.skipTest("Pass UGLYOS_PINNED_QTBASE_ROOT for full source check")
        evdev = (SOURCE / EVDEV).read_text()
        header = (SOURCE / EVDEV_HEADER).read_text()
        libinput = (SOURCE / LIBINPUT).read_text()
        self.assertIn('std::strcmp(inputName, "tizen_detent") == 0', evdev)
        self.assertIn('std::strcmp(deviceName, "tizen_detent") == 0', libinput)
        self.assertIn('bool m_watch3Detent = false;', header)
        # The original Qt6 120-angleDelta wheel and libinput axis dispatch
        # MUST survive. The code may suppress only pointer-movement events.
        self.assertIn('delta.setY(120 * data->value);', evdev)
        self.assertIn('emit handleWheelEvent(delta);', evdev)
        self.assertIn('m_pointer->processAxis(libinput_event_get_pointer_event(ev));', libinput)
        self.assertIn('m_pointer->processButton(libinput_event_get_pointer_event(ev));', libinput)
        self.assertIn('m_touch->processTouchDown(libinput_event_get_touch_event(ev));', libinput)
        self.assertIn('m_keyboard->processKey(libinput_event_get_keyboard_event(ev));', libinput)
        self.assertRegex(
            evdev,
            r'if \(m_watch3Detent && \(data->code == REL_X \|\| data->code == REL_Y\)\)\s+continue;')
        self.assertRegex(
            libinput,
            r'if \(deviceName && std::strcmp\(deviceName, "tizen_detent"\) == 0\s+&& '
            r'\(type == LIBINPUT_EVENT_POINTER_MOTION\s+\|\| '
            r'type == LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE\)\)\s+return;')
        # Must not change wheel semantics or introduce new polling / services.
        self.assertNotIn("EVIOCGRAB", evdev[evdev.index("Watch3 R08"):evdev.index("detectHiResWheelSupport();",evdev.index("Watch3 R08"))])
        self.assertEqual(evdev.count('std::strcmp(inputName, "tizen_detent")'), 1)
        self.assertEqual(libinput.count('std::strcmp(deviceName, "tizen_detent")'), 1)


if __name__ == "__main__":
    unittest.main()
