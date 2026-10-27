"""Fail-closed metadata + real patched Qt source prebuild gate regressions.

Host fixtures are not evidence of a target QtBase package or on-watch input.
"""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_watch3_qtbase_bezel_stage import GateError, verify

APPEND = ROOT / "meta-noblesse/recipes-qt/qt6/qtbase_%.bbappend"
PATCH = ROOT / "meta-noblesse/recipes-qt/qt6/qtbase/0001-noblesse-r08-tizen-detent-wheel-only.patch"
WORKFLOWS = [
    ROOT / ".github/workflows/watch3-r08-qt-staged-runtime.yml",
    ROOT / ".github/workflows/watch3-r08-qt-linuxfb-package.yml",
]


def fixture(root: Path, src: Path) -> str:
    path = root / "meta-noblesse/recipes-qt/qt6/qtbase"
    return "\n".join((
        'PN="qtbase"', 'MACHINE="noblesse-r08"', 'DISTRO="asteroid"',
        'PV="6.11.3"', 'OVERRIDES="class-target:noblesse-r08:forcevariable"',
        'SRC_URI="git://example.invalid/qtbase file://0001-noblesse-r08-tizen-detent-wheel-only.patch"',
        'FILESPATH="' + str(path) + ":" + str(path / "noblesse-r08") + '"',
        'PACKAGECONFIG="gui linuxfb libinput udev"', 'S="' + str(src) + '"',
    )) + "\n"


def tree(root: Path, src: Path) -> None:
    (root / "meta-noblesse/recipes-qt/qt6/qtbase").mkdir(parents=True)
    (root / "meta-noblesse/recipes-qt/qt6/qtbase_%.bbappend").write_text(
        APPEND.read_text())
    (root / "meta-noblesse/recipes-qt/qt6/qtbase" / PATCH.name).write_text(
        PATCH.read_text())
    items = {
        "src/platformsupport/input/evdevmouse/qevdevmousehandler.cpp": """
          std::strcmp(inputName, "tizen_detent") == 0
          EVIOCGNAME(sizeof(inputName))
          EVIOCGBIT(EV_REL, sizeof(relFeatures))
          TEST_BIT(relFeatures, REL_WHEEL)
          if (m_watch3Detent && (data->code == REL_X || data->code == REL_Y))
              continue;
          delta.setY(120 * data->value);
          emit handleWheelEvent(delta);
        """,
        "src/platformsupport/input/evdevmouse/qevdevmousehandler_p.h":
            "bool m_watch3Detent = false;\n",
        "src/platformsupport/input/libinput/qlibinputhandler.cpp": """
          if (deviceName && std::strcmp(deviceName, "tizen_detent") == 0
                  && (type == LIBINPUT_EVENT_POINTER_MOTION
                      || type == LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE))
              return;
          m_pointer->processAxis(libinput_event_get_pointer_event(ev));
          m_pointer->processButton(libinput_event_get_pointer_event(ev));
          m_touch->processTouchDown(libinput_event_get_touch_event(ev));
          m_keyboard->processKey(libinput_event_get_keyboard_event(ev));
        """,
    }
    for filename, value in items.items():
        out = src / filename
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(value)


class QtBaseBezelPrebuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.src = self.root / "source" / "git"
        tree(self.root, self.src)
        self.env = fixture(self.root, self.src)

    def test_effective_metadata_and_actual_patched_sources(self):
        self.assertEqual(verify(self.env, "metadata", self.root)["patch_selected"], "true")
        self.assertEqual(verify(self.env, "patched", self.root)["real_sources_patched"], "true")

    def test_malformed_or_wrong_context_rejected_before_costly_build(self):
        mutations = (
            ("PN=\"qtbase\"", "PN=\"qtbase-native\""),
            ("MACHINE=\"noblesse-r08\"", "MACHINE=\"other-watch\""),
            ("DISTRO=\"asteroid\"", "DISTRO=\"poky\""),
            ("PV=\"6.11.3\"", "PV=\"6.12.0\""),
            ("noblesse-r08:forcevariable", "other-machine:forcevariable"),
            (" file://0001-noblesse-r08-tizen-detent-wheel-only.patch", ""),
            ("linuxfb libinput", "linuxfb"),
            ("linuxfb libinput", "libinput"),
            ('FILESPATH="' + str(self.root / "meta-noblesse/recipes-qt/qt6/qtbase") + ":" +
             str(self.root / "meta-noblesse/recipes-qt/qt6/qtbase/noblesse-r08") + '"',
             'FILESPATH="/wrong/location"'),
            ('PN="qtbase"', 'PN=qtbase'),
        )
        for a, b in mutations:
            with self.subTest(before=a, after=b):
                self.assertIn(a, self.env)
                with self.assertRaises(GateError):
                    verify(self.env.replace(a, b), "metadata", self.root)

    def test_missing_actual_patch_or_input_paths_rejected(self):
        path = self.src / "src/platformsupport/input/evdevmouse/qevdevmousehandler.cpp"
        original = path.read_text()
        for token in ("std::strcmp(inputName", "m_watch3Detent &&",
                      "delta.setY(120 * data->value);"):
            with self.subTest(token=token):
                path.write_text(original.replace(token, "MISSING_FILTER"))
                with self.assertRaises(GateError):
                    verify(self.env, "patched", self.root)
        path.write_text(original)
        li = self.src / "src/platformsupport/input/libinput/qlibinputhandler.cpp"
        old = li.read_text()
        li.write_text(old.replace("LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE", "FAKE"))
        with self.assertRaises(GateError):
            verify(self.env, "patched", self.root)
        li.write_text(old)
        self.assertEqual(verify(self.env, "patched", self.root)["real_sources_patched"], "true")

    def test_r08_bitbake_patch_header_and_recipe_required(self):
        target = self.root / "meta-noblesse/recipes-qt/qt6/qtbase" / PATCH.name
        target.write_text(target.read_text().replace("Upstream-Status: Pending", ""))
        with self.assertRaisesRegex(GateError, "patch status"):
            verify(self.env, "metadata", self.root)
        target.write_text(PATCH.read_text())
        bb = self.root / "meta-noblesse/recipes-qt/qt6/qtbase_%.bbappend"
        bb.write_text(bb.read_text().replace("SRC_URI:append:noblesse-r08",
                                             "SRC_URI:append"))
        with self.assertRaises(GateError):
            verify(self.env, "metadata", self.root)

    def test_both_existing_cached_qtbase_workflows_stop_before_compile(self):
        for workflow in WORKFLOWS:
            text = workflow.read_text()
            with self.subTest(workflow=workflow.name):
                self.assertIn("verify_watch3_qtbase_bezel_stage.py", text)
                self.assertIn("--stage metadata", text)
                self.assertIn("bitbake -c patch qtbase", text)
                self.assertIn("--stage patched", text)
                first = text.index("bitbake -c patch qtbase")
                self.assertLess(first, text.index("--stage patched"))
                self.assertLess(text.index("--stage patched"),
                                text.index("bitbake -c package"))
                self.assertNotIn("EVIOCGRAB", text)
                self.assertNotIn("sdb shell", text)


if __name__ == "__main__":
    unittest.main()
