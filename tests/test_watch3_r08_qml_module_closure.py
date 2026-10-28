"""Fail-closed QML deployment checks on tiny synthetic guest files only."""
from __future__ import annotations
from pathlib import Path
import hashlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import watch3_r08_qml_module_closure as modules


def elf(machine=183):
    data=bytearray(256)
    data[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH",data,16,3,machine)
    return bytes(data)


class RealQmlModuleClosureTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        for name in modules.REQUIRED:
            self.write_module(name)

    def write_module(self,name,extra="",rootname="usr/lib/qml"):
        folder=self.root/rootname/Path(*name.split("."))
        folder.mkdir(parents=True,exist_ok=True)
        (folder/"qmldir").write_text("module "+name+"\n"+extra)
        return folder

    def test_all_required_real_modules_resolve_and_safety_flags(self):
        result=modules.audit(self.root)
        self.assertEqual(result["status"],"REAL_ARM64_QML_MODULE_DEPLOYMENT_VERIFIED")
        self.assertEqual([x["module"] for x in result["required_modules"]],
                         list(modules.REQUIRED))
        self.assertFalse(result["module_loading_at_runtime_tested"])
        self.assertFalse(result["flashable"])

    def test_missing_required_fails(self):
        (self.root/"usr/lib/qml/QtQuick/qmldir").unlink()
        with self.assertRaisesRegex(modules.ModuleClosureError,"REQUIRED_QML_MODULE_MISSING"):
            modules.audit(self.root)

    def test_wrong_module_identity_fails(self):
        (self.root/"usr/lib/qml/QtQuick/qmldir").write_text("module QtSensors\n")
        with self.assertRaisesRegex(modules.ModuleClosureError,"IDENTITY_MISMATCH"):
            modules.audit(self.root)

    def test_required_aarch64_plugin_passes_with_checksum(self):
        folder=self.write_module("QtQuick",extra="plugin qtquick2plugin\n")
        (folder/"libqtquick2plugin.so").write_bytes(elf())
        item=modules.locate_module(self.root,"QtQuick")
        self.assertEqual(item["plugins_aarch64_verified"][0]["name"],"qtquick2plugin")
        self.assertEqual(item["plugins_aarch64_verified"][0]["sha256"],
                         hashlib.sha256(elf()).hexdigest())

    def test_required_missing_plugin_fails(self):
        self.write_module("QtQuick",extra="plugin qtquick2plugin\n")
        with self.assertRaisesRegex(modules.ModuleClosureError,"REQUIRED_QML_PLUGIN_MISSING"):
            modules.audit(self.root)

    def test_optional_absent_plugin_reported_not_fatal(self):
        self.write_module("QtQuick",extra="optional plugin qtquick2plugin\n")
        item=modules.locate_module(self.root,"QtQuick")
        self.assertEqual(item["optional_plugins_absent"],["qtquick2plugin"])

    def test_wrong_arch_plugin_fails(self):
        folder=self.write_module("QtQuick",extra="plugin qtquick2plugin\n")
        (folder/"libqtquick2plugin.so").write_bytes(elf(machine=62))
        with self.assertRaisesRegex(modules.ModuleClosureError,"NOT_REAL_AARCH64"):
            modules.audit(self.root)

    def test_outbound_symlink_cannot_resolve_host(self):
        folder=self.root/"usr/lib/qml/QtQuick"
        (folder/"qmldir").unlink()
        (folder/"qmldir").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(modules.ModuleClosureError,"QMLDIR_ESCAPES_GUEST_ROOT"):
            modules.audit(self.root)

    def test_ambiguous_module_roots_fail(self):
        self.write_module("QtQuick",rootname="usr/lib64/qml")
        with self.assertRaisesRegex(modules.ModuleClosureError,"AMBIGUOUS"):
            modules.audit(self.root)

    def test_same_real_qmldir_exposed_via_lib64_alias_is_allowed(self):
        alias=self.root/"usr/lib64"
        alias.symlink_to("lib")
        # The symlink target must be a real guest path. Build a correct alias:
        alias.unlink()
        alias.symlink_to("lib")
        # This alias resolves to /usr/lib64 -> /usr/lib only if "lib" is
        # a sibling under /usr, not a root-host absolute path.
        result=modules.audit(self.root)
        self.assertTrue(result["required_modules_present"])

    def test_malicious_plugin_name_rejected(self):
        self.write_module("QtQuick",extra="plugin ../../tmp/host\n")
        with self.assertRaisesRegex(modules.ModuleClosureError,"UNSAFE_QML_PLUGIN_NAME"):
            modules.audit(self.root)

    def test_optional_missing_module_marked_as_unverified(self):
        result=modules.audit(self.root)
        self.assertEqual(result["optional_modules"]["QtQuick.Window"]["status"],
                         "ABSENT_NOT_REQUIRED_BY_THIS_GATE")

    def test_oversized_qmldir_fails(self):
        (self.root/"usr/lib/qml/QtQuick/qmldir").write_text("module QtQuick\n"+ "a"*modules.MAX_QMLDIR)
        with self.assertRaisesRegex(modules.ModuleClosureError,"UNBOUNDED"):
            modules.audit(self.root)

if __name__=="__main__":
    unittest.main()
