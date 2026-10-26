"""Off-device, R08-only Solo Saver plus offline watchface contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FACES = ROOT / "meta-noblesse/recipes-asteroid/watch3-faces/watch3-faces"
RECIPE = ROOT / "meta-noblesse/recipes-asteroid/watch3-faces/watch3-faces_1.0.bb"
SETTINGS = ROOT / "meta-noblesse/recipes-asteroid/asteroid-settings"
PATCH = SETTINGS / "files/0004-uglyos-solo-saver.patch"
CI = ROOT / ".github/workflows/watch3-r08-uglyos-notifications.yml"

class WatchOnlySoloContracts(unittest.TestCase):
    def test_optional_real_clock_five_faces_same_upstream_selector(self):
        recipe=RECIPE.read_text()
        names=("903-watch3-solo-arcade.qml", "904-watch3-solo-lounge.qml")
        self.assertEqual(len(tuple(FACES.glob("*.qml"))), 5)
        self.assertIn('COMPATIBLE_MACHINE = "(noblesse-r08)"', recipe)
        for name in names:
            with self.subTest(face=name):
                self.assertIn("file://" + name, recipe)
                self.assertIn(name, recipe.split("do_install()",1)[1])
                qml=(FACES / name).read_text()
                self.assertIn("wallClock.time", qml)
                self.assertIn("MceBatteryLevel", qml)
                self.assertIn("burnInProtectionManager", qml)
                self.assertIn("displayAmbient || nightstand", qml)
                self.assertIn("visible: !face.dimmed", qml)
                self.assertIn('color: "#000000"', qml)
                self.assertIn('key: "/desktop/uglyos/appearance/accent"', qml)
                self.assertIn('defaultValue: "original"', qml)
                self.assertIn("onClicked:", qml)
                self.assertIn("enabled: !face.dimmed", qml)
                for banned in ("Timer {", "Animation {", "NumberAnimation",
                               "ShaderEffect", "ParticleSystem", "XMLHttpRequest",
                               "BluetoothStatus", "NetworkTechnology", "running: true",
                               "loops:", "import QtMultimedia"):
                    self.assertNotIn(banned, qml)
        arcade=(FACES/names[0]).read_text()
        lounge=(FACES/names[1]).read_text()
        self.assertIn("questCompleted",arcade)
        self.assertIn('key: "/desktop/uglyos/solo/daily-checkpoint"',arcade)
        self.assertIn("finishQuest()",arcade)
        self.assertIn("completed >= 3",arcade)
        self.assertIn('key: "/desktop/uglyos/solo/lounge-mood"',lounge)
        self.assertIn("nextMood()",lounge)

    def test_solo_controls_only_existing_upstream_interfaces_and_reversible(self):
        bb=(SETTINGS/"asteroid-settings_%.bbappend").read_text()
        self.assertIn('SRC_URI:append:noblesse-r08 = " file://0004-uglyos-solo-saver.patch"',bb)
        self.assertNotIn("SRC_URI:append = ",bb)
        patch=PATCH.read_text()
        self.assertIn("+import Connman",patch)
        for match in ("BluetoothStatus", "NetworkTechnology", "DisplaySettings",
                      "TiltToWake", 'key: "/org/asteroidos/settings/always-on-display"',
                      'key: "/desktop/uglyos/solo/previous-controls"',
                      "function goSolo()", "function resume()",
                      "RemorseTimer", "duration: 3000", "Tap-to-wake stays unchanged",
                      'title: qsTr("Watch-only Solo")',
                      'onClicked: layerStack.push(soloSaverLayer)'):
            self.assertIn(match,patch)
        self.assertIn("soloBt.powered = false",patch)
        self.assertIn("soloWifi.powered = false",patch)
        self.assertIn("soloAod.value = false",patch)
        self.assertIn("soloTilt.enabled = false",patch)
        self.assertIn("soloBt.powered = previous.bt",patch)
        self.assertIn("soloWifi.powered = previous.wifi",patch)
        self.assertIn('enabled: soloSnapshot.value === ""',patch)
        self.assertNotIn("call(",patch)
        for banned in ("fastboot", "sdb shell", "opkg ", "sudo ", "rootfs",
                       "unlock", "flash", "adb ", "exec(", "system("):
            self.assertNotIn(banned,patch)

    def test_pinned_upstream_patch_verification_and_qt_host_interactions(self):
        ci=CI.read_text()
        self.assertIn("0004-uglyos-solo-saver.patch",ci)
        self.assertIn("git -C \"$settings\" apply --check",ci)
        self.assertIn("test_watch3_r08_solo.py",ci)
        renderer=(ROOT/"tools/render_uglyos_faces.py").read_text()
        self.assertIn('uglyos-solo-quest-card',renderer)
        self.assertIn('uglyos-solo-mood-card',renderer)
        self.assertIn('QTest.mouseClick',renderer)
        self.assertIn('questCompleted',renderer)
        self.assertIn('currentMood',renderer)
        self.assertIn('50 real QML previews',renderer)
        self.assertNotIn("sdb shell",renderer)

if __name__ == "__main__":
    unittest.main()
