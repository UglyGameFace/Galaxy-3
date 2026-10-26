"""Real native App Hub build gates must reject spoofed metadata and fake IPKs."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from validate_uglyos_native_app_hub import (
    check_metadata, check_graph, NativeHubError, INPUTS,
    check_ipk, PN
)
APP=ROOT/"meta-noblesse/recipes-asteroid/uglyos-app-hub/uglyos-app-hub"
RECIPE=ROOT/"meta-noblesse/recipes-asteroid/uglyos-app-hub/uglyos-app-hub_0.1.bb"
FLOW=ROOT/".github/workflows/watch3-r08-app-hub-native-ipk.yml"

class NativeHubGates(unittest.TestCase):
    def example(self):
        recipe={"PN":PN,"MACHINE":"noblesse-r08","DISTRO":"asteroid",
                "PACKAGE_ARCH":"noblesse_r08","PACKAGES":PN,
                "DEPENDS":"qtbase qml-asteroid asteroid-generate-desktop-native",
                "SRC_URI":" ".join("file://"+p for p in INPUTS)}
        image={"MACHINE":"noblesse-r08","DISTRO":"asteroid",
               "IMAGE_INSTALL":"watch3-faces uglyos-app-hub uglyos-launchers"}
        return recipe,image

    def test_actual_source_has_verified_upstream_desktop_generator_inputs(self):
        cmake=(APP/"CMakeLists.txt").read_text()
        self.assertIn("include(Asteroid6Translations)",cmake)
        self.assertIn("generate_desktop(",cmake)
        header=(APP/"i18n/uglyos-app-hub.desktop.h").read_text()
        self.assertIn('//% "UgLy|OS App Hub"',header)
        recipe=RECIPE.read_text()
        for item in INPUTS:
            self.assertIn("file://"+item,recipe)
            self.assertTrue((APP/item).is_file(),item)

    def test_exact_bitbake_image_and_dependencies(self):
        recipe,image=self.example()
        check_metadata(recipe,image)
        for k,bad in (("MACHINE","another-watch"),("PN","asteroid-launcher"),
                      ("PACKAGE_ARCH","qemux86"),("DEPENDS","qtbase"),
                      ("SRC_URI","file://main.qml")):
            with self.subTest(k=k):
                modified=recipe.copy()
                modified[k]=bad
                with self.assertRaises(NativeHubError):
                    check_metadata(modified,image)
        bad=image.copy()
        bad["IMAGE_INSTALL"]="watch3-faces"
        with self.assertRaises(NativeHubError):
            check_metadata(recipe,bad)

    def test_native_graph_rejects_firmware_and_excessive_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"pn-buildlist"
            d=Path(tmp)/"task-depends.dot"
            p.write_text("uglyos-app-hub\nqtbase\n")
            d.write_text('digraph dependencies {\n'+
                '\n'.join(f'"uglyos-app-hub.do_{i}" -> "qtbase.do_{i}"'
                          for i in range(120))+'\n}\n')
            check_graph(p,d)
            p.write_text("uglyos-app-hub\nlinux-noblesse\n")
            with self.assertRaises(NativeHubError):
                check_graph(p,d)
            p.write_text("uglyos-app-hub\nqtbase\n")
            d.write_text('digraph dependencies { "uglyos-app-hub.do_package_write_ipk"; }\n')
            with self.assertRaises(NativeHubError):
                check_graph(p,d)

    def test_real_ipk_must_exist_and_never_proves_flash(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/"uglyos-app-hub_0.1-r0_noblesse_r08.ipk"
            f.write_bytes(b"fake native IPK")
            env={"PV":"0.1","PR":"r0","PACKAGE_ARCH":"noblesse_r08",
                 "bindir":"/usr/bin","libdir":"/usr/lib","datadir":"/usr/share",
                 "D":str(Path(tmp)/"image"),"PKGDEST":str(Path(tmp)/"packages-split")}
            with self.assertRaises((NativeHubError,ValueError,OSError)):
                check_ipk(env,f)
        workflow=FLOW.read_text()
        self.assertIn("bitbake -e uglyos-app-hub",workflow)
        self.assertIn("bitbake -g -c package_write_ipk uglyos-app-hub",workflow)
        self.assertIn("validate_uglyos_native_app_hub.py",workflow)
        self.assertIn("bitbake -c package_write_ipk uglyos-app-hub",workflow)
        self.assertIn("OFFDEVICE-NOT-FLASHABLE",workflow)
        self.assertNotIn("fastboot flash",workflow)
        self.assertNotIn("sdb shell",workflow)

if __name__=="__main__":
    unittest.main()
