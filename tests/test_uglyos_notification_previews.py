"""UgLy|OS R08 notification preference, privacy and action source contracts.

Full source-patch application against pinned upstream commits runs in CI.
Hardware Watch3 notification transport, real haptics and BLE are NOT tested.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "meta-noblesse/recipes-asteroid/asteroid-launcher"
SETTINGS = ROOT / "meta-noblesse/recipes-asteroid/asteroid-settings"
LAUNCHER_PATCH = LAUNCHER / "asteroid-launcher/0003-uglyos-notification-previews.patch"
SETTINGS_PATCH = SETTINGS / "files/0003-uglyos-notification-preferences.patch"
PRIVACY = "/desktop/uglyos/notifications/privacy"
DURATION = "/desktop/uglyos/notifications/previewSeconds"

class NotificationControlsTest(unittest.TestCase):
    def test_patches_machine_scoped_and_upstream_kept(self):
        launch = (LAUNCHER / "asteroid-launcher_%.bbappend").read_text()
        setting = (SETTINGS / "asteroid-settings_%.bbappend").read_text()
        self.assertIn('SRC_URI:append:noblesse-r08 = " file://0003-uglyos-notification-previews.patch"',launch)
        self.assertIn('SRC_URI:append:noblesse-r08 = " file://0003-uglyos-notification-preferences.patch"',setting)
        self.assertIn("0001-noblesse-r08-remove-gpu-only-round-mask.patch",launch)
        self.assertIn("0002-uglyos-launcher-effects.patch",setting)

    def test_real_notification_dismiss_fix_only_removes_when_allowed(self):
        patch=LAUNCHER_PATCH.read_text()
        self.assertIn('notification.removeRequested()',patch)
        self.assertIn('notification.userRemovable',patch)
        self.assertIn('-            onClicked: if (notification !== undefined && notification.userRemovable) notification.actionInvoked("default")',patch)
        self.assertIn('+            onClicked: if (notification !== undefined && notification !== null && notification.userRemovable) notification.removeRequested()',patch)

    def test_watch_uses_same_local_keys_as_settings(self):
        a=LAUNCHER_PATCH.read_text()
        b=SETTINGS_PATCH.read_text()
        for key in (PRIVACY,DURATION):
            self.assertIn(key,a)
            self.assertIn(key,b)
        self.assertIn('defaultValue: "full"',a)
        self.assertIn('defaultValue: "full"',b)
        self.assertIn('defaultValue: "5"',a)
        self.assertIn('defaultValue: "5"',b)
        for mode in ("full","title","hidden"):
            self.assertIn('"'+mode+'"',a)
            self.assertIn('"'+mode+'"',b)
        self.assertIn('notificationWindow.privacy === "hidden"',a)
        self.assertIn('notificationWindow.privacy === "full"',a)
        self.assertIn('uglyDuration.value === "3" ? 3000',a)
        self.assertIn('uglyDuration.value === "10" ? 10000 : 5000',a)
        self.assertIn('interval: notificationWindow.previewMilliseconds',a)
        for choice in ('Full text','Title only','Hide content','3 seconds','5 seconds','10 seconds'):
            self.assertIn(choice,b)

    def test_no_new_network_audio_or_firmware_scripts(self):
        all_new=LAUNCHER_PATCH.read_text()+"\n"+SETTINGS_PATCH.read_text()
        for token in ('XMLHttpRequest','QTcpSocket','fetch(','dd if=','fastboot',
                      'systemctl','reboot(', 'sudo ', 'su -c', 'QProcess'):
            self.assertNotIn(token, all_new)
        self.assertNotIn('+++ b/src/notificationsnoozer.cpp',all_new)
        self.assertNotIn('+++ b/lipstick/src/notifications',all_new)

    def test_pinned_patch_ci_contract(self):
        workflow=(ROOT/".github/workflows/watch3-r08-uglyos-notifications.yml").read_text()
        self.assertIn('0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31',workflow)
        self.assertIn('60340bd1c27a7b9e4884bd61c0563d091bc8b240',workflow)
        self.assertIn('git -C "$launcher" apply --check',workflow)
        self.assertIn('git -C "$settings" apply --check',workflow)
        self.assertNotIn('bitbake -c image_complete',workflow)
        self.assertNotIn('fastboot flash',workflow)

if __name__=="__main__":
    unittest.main()
