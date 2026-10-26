"""Test the actual adaptive QML policy with mocked hardware events, no watch."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = ROOT / "meta-noblesse/recipes-asteroid/asteroid-settings"
LAUNCHER = ROOT / "meta-noblesse/recipes-asteroid/asteroid-launcher"
SP = SETTINGS / "files/0005-uglyos-adaptive-battery.patch"
LP = LAUNCHER / "asteroid-launcher/0004-uglyos-adaptive-battery.patch"
CONFIG_ENABLED = "/desktop/uglyos/power/adaptive-enabled"
CONFIG_ORIGINAL = "/desktop/uglyos/power/adaptive-original"
CONFIG_PROFILE = "/desktop/uglyos/power/adaptive-profile"


def added_source(patch: Path) -> str:
    return "\n".join(
        line[1:] for line in patch.read_text().splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def actual_reconcile() -> str:
    source = added_source(LP)
    marker = "function reconcile() {"
    start = source.index(marker)
    depth, end = 0, None
    for i in range(source.index("{", start), len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise AssertionError("Missing complete QML policy function")
    return source[start:end]


class AdaptiveBatteryContracts(unittest.TestCase):
    def test_both_r08_recipe_scopes_and_shared_keys(self):
        setting = (SETTINGS / "asteroid-settings_%.bbappend").read_text()
        launcher = (LAUNCHER / "asteroid-launcher_%.bbappend").read_text()
        self.assertIn(
            'SRC_URI:append:noblesse-r08 = " file://0005-uglyos-adaptive-battery.patch"',
            setting)
        self.assertIn(
            'SRC_URI:append:noblesse-r08 = " file://0004-uglyos-adaptive-battery.patch"',
            launcher)
        self.assertNotIn("SRC_URI:append = ", setting + launcher)
        ss, ls = added_source(SP), added_source(LP)
        for key in (CONFIG_ENABLED, CONFIG_ORIGINAL, CONFIG_PROFILE):
            self.assertIn(key, ss)
            self.assertIn(key, ls)
        self.assertIn("defaultValue: false", ss)
        self.assertIn("defaultValue: false", ls)
        self.assertIn("Battery & Power", ss)
        self.assertIn("MceBatteryLevel", ss)
        self.assertIn("MceChargerType", ss)
        self.assertIn("Live battery", ss)
        self.assertIn('onClicked: layerStack.push(adaptivePowerLayer)', ss)
        self.assertIn("restore", ss.lower())
        self.assertIn('defaultValue: "extended"', ss)
        self.assertIn('defaultValue: "extended"', ls)
        self.assertIn('enabled: powerSaved.value === ""', ss)
        self.assertIn('id: powerContents', ss)
        self.assertIn('Flickable {', ss)
        self.assertIn("Keep wrist wake", ss)
        self.assertIn("Quiet display", ss)
        self.assertIn('key: "/desktop/uglyos/power/low-threshold"', ss)
        self.assertIn('key: "/desktop/uglyos/power/low-threshold"', ls)
        self.assertIn('defaultValue: "20"', ss)
        self.assertIn('defaultValue: "20"', ls)
        self.assertIn('key: "/desktop/uglyos/power/custom-aod"', ss)
        self.assertIn('key: "/desktop/uglyos/power/custom-tilt"', ls)
        self.assertIn('qsTr("Custom")', ss)
        self.assertIn('qsTr("Start saving at")', ss)
        self.assertIn('qsTr("Always-on display")', ss)
        self.assertIn('qsTr("Wrist wake")', ss)
        self.assertIn('enabled: powerSaved.value === ""', ss)

    def test_no_unattended_network_or_fake_benchmark(self):
        ls = added_source(LP)
        for forbidden in (
            "Timer {", "Animation {", "BluetoothStatus", "NetworkTechnology",
            "soloBt.powered", "soloWifi.powered", "WiFi", "XMLHttpRequest",
            "fetch(", "opkg", "sdb ", "sudo ", "rm -rf", "process.",
            "shell:", "rootfs", "system(", "exec(", "download"
        ):
            self.assertNotIn(forbidden, ls, forbidden)
        self.assertIn("onPercentChanged", ls)
        self.assertIn("onTypeChanged", ls)
        self.assertIn("onActiveChanged", ls)
        self.assertIn("onValueChanged: adaptiveBattery.reconcile()", ls)
        self.assertIn("adaptiveSolo.value !==", ls)
        self.assertIn("nightstandMode.active", ls)
        self.assertIn("adaptiveOriginal.value = JSON.stringify", ls)
        self.assertLess(ls.index("adaptiveOriginal.value = JSON.stringify"),
                        ls.index("alwaysOnDisplay.value = false"))
        self.assertNotIn("measure drain", ls.lower())

    @unittest.skipUnless(shutil.which("node"), "Node is required for actual JS behavior testing")
    def test_actual_controller_event_behavior(self):
        js = r"""
const vm = require('node:vm');
const fs = require('node:fs');
const actual = JSON.parse(fs.readFileSync(0, 'utf8'));
const fn = '(' + actual.fn + ')';
function test(name, opts, checks) {
    const state = {
       changing: false,
       adaptiveEnabled: {value: opts.enabled === true},
       adaptiveProfile: {value: opts.profile ?? "extended"},
       adaptiveThreshold: {value: opts.threshold ?? "20"},
       adaptiveCustomAod: {value: opts.customAod !== false},
       adaptiveCustomTilt: {value: opts.customTilt === true},
       adaptiveOriginal: {value: ''},
       adaptiveSolo: {value: opts.solo ? '{"version":1}' : ''},
       adaptiveGauge: {percent: opts.level ?? 18},
       mceChargerType: {type: opts.charging ? 1 : 0},
       MceChargerType: {None: 0},
       nightstandMode: {active: opts.nightstand || false},
       alwaysOnDisplay: {value: opts.aod !== false},
       displaySettings: {lowPowerModeEnabled: opts.aod !== false},
       adaptiveTilt: {available: opts.tiltAvailable !== false,
                      enabled: opts.tilt !== false}
    };
    const run = vm.runInNewContext(fn, state);
    run();
    checks(state, run);
    console.log('PASS:', name);
}
test('off default preserves radios and display', {}, s => {
   if(!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled ||
      s.adaptiveOriginal.value !== '') throw Error('off not inert');
});
test('20% turns off only screen wake controls', {enabled:true,level:20},
(s, run) => {
    if(s.alwaysOnDisplay.value || s.adaptiveTilt.enabled) throw Error('did not conserve');
    const previous=JSON.parse(s.adaptiveOriginal.value);
    if(previous.version!==1||!previous.changedAod||!previous.changedTilt)
        throw Error('missing reversible snapshot');
    s.adaptiveGauge.percent=25;
    run();
    if(s.alwaysOnDisplay.value || s.adaptiveOriginal.value==='') throw Error('no hysteresis');
    s.adaptiveGauge.percent=30;
    run();
    if(!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled ||
       s.adaptiveOriginal.value!=='') throw Error('restore failed');
});
test('low battery while charging never engages', {enabled:true,charging:true},
s => { if(!s.alwaysOnDisplay.value || s.adaptiveOriginal.value!=='') throw Error('charger');});
test('nightstand has precedence', {enabled:true,nightstand:true},
s => { if(s.adaptiveOriginal.value!=='') throw Error('nightstand');});
test('Solo Saver has precedence', {enabled:true,solo:true},
s => { if(s.adaptiveOriginal.value!=='') throw Error('Solo Saver');});
test('no validated gauge no changes', {enabled:true,level:-1},
s => { if(s.adaptiveOriginal.value!=='') throw Error('invalid gauge');});
test('preserve unsupported tilt', {enabled:true,tiltAvailable:false},
(s,run) => {
    if(!s.adaptiveTilt.enabled || s.alwaysOnDisplay.value) throw Error('tilt');
    s.adaptiveEnabled.value=false;
    run();
    if(!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled) throw Error('restore');
});
test('opt-out restores and preserves manual AOD override', {enabled:true},
(s,run) => {
    if(s.adaptiveOriginal.value==='') throw Error('not enabled');
    s.alwaysOnDisplay.value=true;  // User toggles back on while saver owns snapshot.
    s.adaptiveEnabled.value=false;
    run();
    if(!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled ||
       s.adaptiveOriginal.value!=='') throw Error('manual override clobbered');
});
test('connected saver only changes AOD, preserves wrist wake', {enabled:true, profile:'connected'},
(s, run) => {
    if (s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled) throw Error('connected wake broken');
    let previous = JSON.parse(s.adaptiveOriginal.value);
    if(!previous.changedAod || previous.changedTilt) throw Error('wrong ownership');
    s.adaptiveGauge.percent=30; run();
    if (!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled ||
        s.adaptiveOriginal.value!=='') throw Error('not restored');
});
test('connected saver does nothing when AOD already off', {enabled:true, profile:'connected', aod:false},
s => {
    if(s.adaptiveOriginal.value!=='' || s.alwaysOnDisplay.value) throw Error('unwanted snapshot');
});
test('invalid profile never defaults to aggressive behavior', {enabled:true, profile:'bad'},
s => {
    if(s.adaptiveOriginal.value!=='' || !s.alwaysOnDisplay.value ||
       !s.adaptiveTilt.enabled) throw Error('unverified policy changed screen');
});
test('profile change during snapshot is deferred until restore', {enabled:true, profile:'extended'},
(s,run) => {
    if(!s.adaptiveOriginal.value) throw Error('no snapshot');
    s.adaptiveProfile.value = 'connected';
    run();
    if (s.adaptiveTilt.enabled || s.alwaysOnDisplay.value) throw Error('active switch');
    s.adaptiveEnabled.value=false;run();
    if(!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled ||
       s.adaptiveOriginal.value!=='') throw Error('lost old settings');
    s.adaptiveEnabled.value=true;run();
    if(s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled) throw Error('new profile');
});
test('threshold 15 does not trigger at 16; triggers at 15 and restores at 25',
{enabled:true, threshold:"15", level:16}, (s,run) => {
    if(s.adaptiveOriginal.value!=='' || !s.alwaysOnDisplay.value) throw Error('early');
    s.adaptiveGauge.percent=15;run();
    if(s.alwaysOnDisplay.value || JSON.parse(s.adaptiveOriginal.value).restoreAt!==25)
        throw Error('threshold start');
    s.adaptiveGauge.percent=24;run();
    if(s.alwaysOnDisplay.value) throw Error('hysteresis');
    s.adaptiveGauge.percent=25;run();
    if(!s.alwaysOnDisplay.value || s.adaptiveOriginal.value!=='') throw Error('restore');
});
test('threshold 25 only restores at 35', {enabled:true,threshold:"25",level:25},
(s,run) => {
    if(s.alwaysOnDisplay.value) throw Error('not triggered');
    s.adaptiveGauge.percent=34;run();
    if(s.alwaysOnDisplay.value) throw Error('early restore');
    s.adaptiveGauge.percent=35;run();
    if(!s.alwaysOnDisplay.value) throw Error('not restored');
});
test('custom AOD only preserves wrist wake', {enabled:true,profile:"custom",customTilt:false},
(s,run) => {
    if(s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled) throw Error('wrist disrupted');
    s.adaptiveEnabled.value=false;run();
    if(!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled) throw Error('restore');
});
test('custom wrist-wake only preserves AOD', {enabled:true,profile:"custom",customAod:false,customTilt:true},
(s,run) => {
    if(!s.alwaysOnDisplay.value || s.adaptiveTilt.enabled) throw Error('wrong controls');
    s.adaptiveEnabled.value=false;run();
    if(!s.alwaysOnDisplay.value || !s.adaptiveTilt.enabled) throw Error('restore');
});
test('custom neither is inert', {enabled:true,profile:"custom",customAod:false,customTilt:false},
s => {if(s.adaptiveOriginal.value!=='' || !s.alwaysOnDisplay.value ||
       !s.adaptiveTilt.enabled) throw Error('modified with no controls');});
test('invalid threshold fails closed', {enabled:true,threshold:"0"}, s => {
    if(s.adaptiveOriginal.value!=='' || !s.alwaysOnDisplay.value) throw Error('invalid trigger');
});
test('threshold edit cannot overwrite saved restoreAt', {enabled:true,threshold:"15"},
(s,run) => {
    const previous=JSON.parse(s.adaptiveOriginal.value);
    if(previous.restoreAt!==25) throw Error('missing threshold snapshot');
    s.adaptiveThreshold.value="25";s.adaptiveGauge.percent=25;run();
    if(!s.alwaysOnDisplay.value || s.adaptiveOriginal.value!=='') throw Error('snapshot changed');
});
test('legacy version one snapshot restores at 30', {enabled:true},
(s,run) => {
    const original=JSON.parse(s.adaptiveOriginal.value);
    s.adaptiveOriginal.value=JSON.stringify({...original,version:1,restoreAt:undefined});
    s.adaptiveGauge.percent=29;run();
    if(!s.adaptiveOriginal.value) throw Error('premature v1 restore');
    s.adaptiveGauge.percent=30;run();
    if(s.adaptiveOriginal.value!=='' || !s.alwaysOnDisplay.value ||
       !s.adaptiveTilt.enabled) throw Error('v1 not restored');
});
test('unknown gauge pauses auto control but manual stop restores', {enabled:true},
(s,run) => {
    if(!s.adaptiveOriginal.value) throw Error('missing active snapshot');
    s.adaptiveGauge.percent=-1;run();
    if(s.adaptiveOriginal.value==='') throw Error('lost snapshot');
    s.adaptiveEnabled.value=false;run();
    if(s.adaptiveOriginal.value!=='' || !s.alwaysOnDisplay.value ||
       !s.adaptiveTilt.enabled) throw Error('manual restore blocked');
});
test('charging stops saver even below threshold', {enabled:true},(s,run) => {
    if(!s.adaptiveOriginal.value) throw Error('missing active snapshot');
    s.mceChargerType.type=1;run();
    if(s.adaptiveOriginal.value!=='' || !s.alwaysOnDisplay.value ||
       !s.adaptiveTilt.enabled) throw Error('plugging in did not restore');
});
"""
        r = subprocess.run(
            ["node", "-e", js],
            input=json.dumps({"fn": actual_reconcile()}),
            text=True, capture_output=True, check=False, timeout=20,
        )
        self.assertEqual(r.returncode, 0, r.stdout + "\n" + r.stderr)
        self.assertEqual(r.stdout.count("PASS:"), 22, r.stdout)


if __name__ == "__main__":
    unittest.main()
