"""R08 Bezel Engine: execute the *actual* QML JavaScript with mocked detents.

No watch, phone, radio, firmware, notifications, haptic, or native graphics.
"""
from pathlib import Path
import json
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "meta-noblesse/recipes-asteroid/uglyos-bezel-lab/uglyos-bezel-lab"
RECIPE = APP.parent / "uglyos-bezel-lab_0.1.bb"
MATRIX = ROOT / "bezel/features.json"
WORKFLOW = ROOT / ".github/workflows/watch3-r08-bezel-engine.yml"

NODE_CHECKS = r"""
'use strict';
const vm = require('node:vm');
const fs = require('node:fs');
const path = process.argv[1];
const source = fs.readFileSync(path, 'utf8').replace(/^\.pragma library\s*$/m, '');
const api = {};
vm.createContext(api);
vm.runInContext(source, api, {timeout: 2000});
const assert = require('node:assert/strict');
let passed=0;
function run(name, fn) {fn();passed++;console.log('PASS: '+name)}
function wheel(s,delta,ms) {return api.apply(s,{kind:'rotate',steps:delta,ms})}
run('exact REL_WHEEL +1/-1; ignore REL_X and out-of-bound values',()=>{
  assert.equal(api.normalizeEvdev(2,8,1,100).steps,1);
  assert.equal(api.normalizeEvdev(2,8,-1,100).steps,-1);
  assert.equal(api.normalizeEvdev(2,0,1,100),null);
  assert.equal(api.normalizeEvdev(1,8,1,100),null);
  assert.equal(api.normalizeEvdev(2,8,99,100),null);
  assert.equal(api.normalizeEvdev(2,8,0,100),null);
});
run('native normal ring navigation wraps and is not accelerated',()=>{
  let s=api.makeState();
  s=wheel(s,-1,100);
  assert.equal(s.focus,api.LOCAL_ACTIONS.length-1);
  s=wheel(s,1,125);
  assert.equal(s.focus,0);
  s=wheel(s,1,150);
  assert.equal(s.focus,1);
  s=api.apply(s,{kind:'choose'});
  assert.equal(s.page,'precision');
  s=api.apply(s,{kind:'back'});
  assert.equal(s.page,'ring');
});
run('precision accel only after fast detents; bounded 0..100',()=>{
  let s=api.makeState();s.page='precision';
  s=wheel(s,1,100); assert.equal(s.dial,51);
  s=wheel(s,1,150); assert.equal(s.dial,54);
  s=wheel(s,-1,300); assert.equal(s.dial,53);
  for(let i=0;i<100;i++)s=wheel(s,8,400+i*20);
  assert.equal(s.dial,100);
});
run('rotary keyboard wraps and selects without touch',()=>{
  let s=api.makeState();s.page='keyboard';
  s=wheel(s,1,100);s=api.apply(s,{kind:'choose'});
  assert.equal(s.keyboardText,'A');
  for(let i=0;i<100;i++)s=api.apply(s,{kind:'choose'});
  assert.equal(s.keyboardText.length,48);
  s=api.apply(s,{kind:'back'});assert.equal(s.page,'ring');
});
run('timeline step and game inventory have clamped and circular domains',()=>{
  let s=api.makeState();s.page='timeline';
  s=wheel(s,-4,100);assert.equal(s.timelineSeconds,0);
  s=wheel(s,3,200);assert.equal(s.timelineSeconds,15);
  s.page='game';s=wheel(s,-1,300);assert.equal(s.gameSlot,23);
  s=wheel(s,1,400);assert.equal(s.gameSlot,0);
});
run('gestures require explicit arm, bounded duration and confirmation',()=>{
  let s=api.makeState();
  s=wheel(s,1,10);assert.equal(s.gestures.length,0);
  s=api.apply(s,{kind:'target',value:'game'});
  s=api.apply(s,{kind:'arm',record:true});
  s=wheel(s,1,100);s=wheel(s,1,200);s=wheel(s,-1,300);
  s=api.apply(s,{kind:'choose'});
  assert.deepEqual(JSON.parse(JSON.stringify(s.gestures)),[{key:'RRL',target:'game'}]);
  s=api.apply(s,{kind:'arm',record:false});
  s=wheel(s,1,400);s=wheel(s,1,500);s=wheel(s,-1,600);
  s=api.apply(s,{kind:'choose'});assert.equal(s.page,'game');
  s=api.apply(s,{kind:'back'});assert.equal(s.page,'ring');
  s=api.apply(s,{kind:'arm',record:false});s=wheel(s,1,700);s=wheel(s,1,3700);
  assert.equal(s.gestureSteps.length,1);
});
run('gesture input/import cannot execute non-local actions',()=>{
  let s=api.makeState();
  s=api.registerGesture(s,[1,1,-1],'phone-automation');
  assert.equal(s.gestures.length,0);
  s=api.registerGesture(s,[1,-1],'ring');
  assert.equal(s.gestures.length,1);
  s=api.loadGestures(s,[{key:'RR',target:'phone-camera'}]);
  assert.equal(s.gestures.length,1);
  s=api.loadGestures(s,[{key:'RRL',target:'keyboard'}]);
  assert.equal(s.gestures[0].target,'keyboard');
  s=api.loadGestures(s,[{key:'RRL',target:'game'},{key:'RRL',target:'ring'}]);
  assert.equal(s.gestures[0].target,'keyboard');
  s=api.clearGesture(s,'RRL');assert.equal(s.gestures.length,0);
});
run('gesture count is limited, long or duplicate keys rejected',()=>{
  let s=api.makeState();
  let keys=[[1,1],[1,-1],[-1,1],[-1,-1],[1,1,1],[-1,1,1]];
  for(let k of keys)s=api.registerGesture(s,k,'ring');
  assert.equal(s.gestures.length,6);
  s=api.registerGesture(s,[1,-1,1],'game');
  assert.equal(s.gestures.length,6);
  s=api.registerGesture(s,[1,1,1,1,1,1,1,1,1],'ring');
  assert.equal(s.gestures.length,6);
});
run('remote intents are inert until a permissioned companion exists',()=>{
  let s=api.makeState();
  s=api.remoteIntent(s,'phone-camera',{zoom:100});
  assert.equal(s.intents.length,0);
  assert.match(s.lastResult,/not connected/);
  s=api.remoteIntent(s,'shell',{payload:'danger'});
  assert.equal(s.intents.length,0);
});
run('explicit context changes only; no app tracking',()=>{
  let s=api.makeState();
  s=api.apply(s,{kind:'context',value:'gaming'});
  assert.equal(s.context,'gaming');
  s=api.apply(s,{kind:'context',value:'superuser'});
  assert.equal(s.context,'gaming');
});
run('invalid or spurious events do not mutate controls',()=>{
  let s=api.makeState();
  s=wheel(s,0,0);
  s=wheel(s,900,5);
  s=wheel(s,1,-1);
  assert.equal(s.totalTurns,0);
  assert.equal(s.focus,0);
});
console.log('TOTAL_PASSED='+passed);
"""

class BezelContractTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node needed for actual QML JavaScript tests")
    def test_actual_bezel_engine(self):
        result = subprocess.run(
            ["node", "-e", NODE_CHECKS, str(APP / "BezelEngine.js")],
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
        self.assertIn("TOTAL_PASSED=11", result.stdout)

    def test_machine_scoped_native_app_and_no_flash(self):
        cmake = (APP / "CMakeLists.txt").read_text()
        recipe = RECIPE.read_text()
        sources = ["CMakeLists.txt", "main.cpp", "main.qml",
                   "BezelPage.qml", "BezelEngine.js",
                   "uglyos-bezel-lab.in", "uglyos-bezel-lab.desktop.template",
                   "i18n/uglyos-bezel-lab.desktop.h"]
        for name in sources:
            self.assertIn("file://" + name, recipe)
            self.assertTrue((APP / name).is_file(), name)
        for val in ("AsteroidApp6 REQUIRED", "asteroid_app_qml_module",
                    "generate_desktop", "Asteroid::AsteroidApp6"):
            self.assertIn(val, cmake)
        self.assertIn('COMPATIBLE_MACHINE = "^noblesse-r08$"', recipe)
        self.assertIn("inherit qt6-cmake", recipe)
        self.assertIn("AsteroidApp::main", (APP/"main.cpp").read_text())
        image = ROOT/"meta-noblesse/recipes-core/images/asteroid-image.bbappend"
        self.assertNotIn('IMAGE_INSTALL:append:noblesse-r08 = " uglyos-bezel-lab"', image.read_text())
        self.assertNotIn("do_install:append()", recipe)

    def test_native_interaction_source_uses_one_engine_not_direct_evdev(self):
        page = (APP/"BezelPage.qml").read_text()
        for token in ('import "BezelEngine.js" as Bezel', "WheelHandler {",
                      "onWheel: (event) =>", "Keys.onPressed:", "kind:\"choose\"",
                      "kind:\"back\"", "root.snapshot", "storedGestures.value"):
            self.assertIn(token, page)
        for path in (APP/"main.cpp", APP/"main.qml", APP/"BezelPage.qml",
                     APP/"BezelEngine.js"):
            source = path.read_text()
            for forbidden in ("QProcess", "process.start", "system(", "exec(", "sdb shell",
                              "fastboot", "opkg install", "curl ", "XMLHttpRequest",
                              "WebSocket", "WebEngineView", "openUrlExternally",
                              "Qt.openUrlExternally"):
                self.assertNotIn(forbidden, source, (path.name, forbidden))
        self.assertNotIn("Timer {",page)
        self.assertNotIn("ShaderEffect",page)
        self.assertNotIn('"/dev/input/event18"',page)
        self.assertIn("hardwareWheelVerified: false",page)
        self.assertIn("companionConnected: false",page)
        self.assertIn("hapticsVerified: false",page)

    def test_feature_matrix_is_explicit_and_never_claims_live_on_watch(self):
        matrix=json.loads(MATRIX.read_text())
        self.assertEqual(matrix["schema"],1)
        self.assertEqual(len(matrix["features"]),22)
        ids=[f["id"] for f in matrix["features"]]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertIn("not validated",matrix["physical_input_status"])
        self.assertIn("not booted",matrix["app_state"])
        self.assertTrue(all(f["state"] in {
            "engine-implemented","native-lab-source","native-lab-prototype",
            "adapter-blocked","accessibility-prototype","provider-blocked",
            "companion-blocked","companion-and-hardware-blocked",
            "companion-and-sensor-blocked","design-only",
        } for f in matrix["features"]))

if __name__=="__main__":
    unittest.main()
