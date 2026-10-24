"""Synthetic reference fixtures; does not claim the watch runs these values."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_watch3_reference_boot import audit, parse_configs


BASE = """
CONFIG_ARM64=y
CONFIG_BLK_DEV_INITRD=y
# CONFIG_KEXEC is not set
CONFIG_EXT4_FS=y
CONFIG_DM_VERITY=y
CONFIG_DEVTMPFS=y
"""
DTS = """/dts-v1/;
#include "exynos9110-tizen_noblesse_large_bt-r08.dtsi"
/ { model = "NOBLESSE-LARGE-BT";
 samsung,exynos-id = <0x00009110 8 0>; };
"""
DTSI = """/ {
memory@80000000 {
 device_type = "memory";
 reg = <0x0 0x80000000 0x60000000>;
};
chosen {
 bootargs = "console=ttySAC0,115200n8 root=/dev/ram0 androidboot.hardware=samsungexynos9110";
 linux,initrd-start = <0x84000000>;
 linux,initrd-end = <0x841FFFFF>;
};
};"""


class ReferenceBootTests(unittest.TestCase):
    def test_expected_reference_properties_are_labeled_historical(self):
        result = audit(BASE, ["CONFIG_NOBLESSE_LARGE=y", ""], DTS, DTSI)
        self.assertEqual(result["status"], "PASS_HISTORICAL_SOURCE_AUDIT")
        self.assertEqual(result["reference_chosen_root"], "/dev/ram0")
        self.assertEqual(result["reference_kconfig"]["CONFIG_KEXEC"], "n")
        self.assertFalse(result["bootable"])
        self.assertFalse(result["flashable"])
        self.assertIn("ACTUAL deployed kernel config or /proc/cmdline",
                      result["not_verified"])

    def test_kexec_fragment_override_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "CONFIG_KEXEC"):
            audit(BASE, ["CONFIG_KEXEC=y", ""], DTS, DTSI)
        self.assertEqual(parse_configs(BASE, ["CONFIG_KEXEC=y"])["resolved_explicit_values"]["CONFIG_KEXEC"], "y")

    def test_wrong_model_or_revision_fails(self):
        with self.assertRaisesRegex(ValueError, "model mismatch"):
            audit(BASE, ["", ""], DTS.replace("NOBLESSE-LARGE-BT", "NOBLESSE"), DTSI)
        with self.assertRaisesRegex(ValueError, "identifier mismatch"):
            audit(BASE, ["", ""], DTS.replace("0x00009110 8 0", "0x00009110 5 0"), DTSI)

    def test_no_root_ramdisk_or_missing_initrd_fails(self):
        with self.assertRaisesRegex(ValueError, "ramdisk root"):
            audit(BASE, ["", ""], DTS, DTSI.replace("root=/dev/ram0", "root=/dev/mmcblk0p1"))
        with self.assertRaisesRegex(ValueError, "initrd address missing"):
            audit(BASE, ["", ""], DTS, DTSI.replace("linux,initrd-start", "initrd-base"))

    def test_invalid_memory_range_fails(self):
        with self.assertRaisesRegex(ValueError, "outside declared memory"):
            audit(BASE, ["", ""], DTS, DTSI.replace("0x84000000", "0xF4000000"))

    def test_reference_only_not_installer(self):
        script = (Path(__file__).resolve().parents[1] /
                  "tools/audit_watch3_reference_boot.py").read_text()
        self.assertIn('"flashable": False', script)
        self.assertIn('"bootable": False', script)
        self.assertNotIn("fastboot flash", script)
        self.assertNotIn("odin flash", script)


if __name__ == "__main__":
    unittest.main()
