#!/usr/bin/env python3
"""Static checks for the experimental Watch3 R08 OpenEmbedded metadata.

Does NOT execute BitBake, compile the layer, or validate on-watch boot.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
LAYER = ROOT / "meta-noblesse"
EXPECTED_SHA = "ec258e12887d37362b59e3291c1d3e5363c24bff"
EXPECTED_DTB = "exynos9110-tizen_noblesse_large_bt-r08.dtb"

FILES = {
    "layer": LAYER / "conf" / "layer.conf",
    "machine": LAYER / "conf" / "machine" / "noblesse-r08.conf",
    "kernel": LAYER / "recipes-kernel" / "linux" / "linux-noblesse_4.9.59.bb",
    "readme": LAYER / "README.md",
    "image": LAYER / "recipes-core" / "images" / "noblesse-research-image.bb",
}

def main() -> int:
    errors = []
    for name, path in FILES.items():
        if not path.is_file():
            errors.append(f"missing {name}: {path}")
    if errors:
        print("\n".join(errors))
        return 1

    data = {name: path.read_text(encoding="utf-8") for name, path in FILES.items()}
    checks = {
        "distinct layer collection": 'BBFILE_COLLECTIONS += "noblesse-layer"' in data["layer"],
        "AsteroidOS upstream layer series": 'LAYERSERIES_COMPAT_noblesse-layer = "whinlatter"' in data["layer"],
        "ARMv8-A cortex A53 tune": "arm/armv8a/tune-cortexa53.inc" in data["machine"],
        "AArch64 default tune": 'DEFAULTTUNE = "cortexa53-nocrypto"' in data["machine"],
        "kernel provider selection": 'PREFERRED_PROVIDER_virtual/kernel = "linux-noblesse"' in data["machine"],
        "ARM64 kernel Image": 'KERNEL_IMAGETYPE = "Image"' in data["machine"],
        "4.9.59 glibc ABI target": 'OLDEST_KERNEL = "4.9.59"' in data["machine"],
        "correct R08 device tree": EXPECTED_DTB in data["machine"],
        "kernel pinned to audited SHA": f'SRCREV = "{EXPECTED_SHA}"' in data["kernel"],
        "correct reference repository": "UsrBinLuna/kernel_samsung_galileo.git" in data["kernel"],
        "machine compatibility scoped": 'COMPATIBLE_MACHINE = "^noblesse-r08$"' in data["kernel"],
        "main base kernel config": "tizen_noblesse_defconfig" in data["kernel"],
        "large watch fragment": "tizen_noblesse_large_defconfig" in data["kernel"],
        "Broadcom sensor fragment": "tizen_noblesse_brcm_defconfig" in data["kernel"],
        "checks large watch selection": 'grep -qx "CONFIG_NOBLESSE_LARGE=y"' in data["kernel"],
        "vendor ELF build path explicit": '"${B}/init/uh.elf"' in data["kernel"],
        "generated Unicode mapping path normalized": 'do_compile:append() {' in data["kernel"] and 'consolemap_deftbl.c' in data["kernel"] and 's#${TMPDIR}#<build-tmpdir>#g' in data["kernel"],
        "research image uses minimal OE-Core image": "recipes-core/images/core-image-minimal.bb" in data["image"],
        "research image ext4": 'IMAGE_FSTYPES = "ext4"' in data["image"],
        "documentation records untested boot": "Not yet tested" in data["readme"] and "On-watch boot" in data["readme"],
        "no direct flashing or recovery modification commands": not bool(re.search(
            r"(?m)^\s*(?:sdb\s+root|heimdall\s+flash|fastboot\s+flash|dd\s+if=.*\s+of=/dev/)",
            data["kernel"] + data["machine"] + data["image"]
        )),
    }
    for name, ok in checks.items():
        print(("PASS" if ok else "FAIL") + ": " + name)
        if not ok:
            errors.append(name)
    print(f"Static checks: {len(checks) - len(errors)}/{len(checks)}")
    if errors:
        print("Layer metadata is not ready for a BitBake experiment:", ", ".join(errors))
        return 1
    print("Static metadata checks passed. CI verifies BitBake build; watch boot remains UNTESTED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
