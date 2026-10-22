#!/usr/bin/env python3
"""Validate the actual R08 AsteroidOS compositor package staging directory.

Do not confuse an intentionally empty upstream 20-device.conf with a missing
file. This checks the files in packages-split, not the source recipe alone.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct

EXPECTED_QMAP_SHA256 = "480250ec53e8a65e5bac7566597a957fcb96b59f0439602c0591da14cb49c767"
EXPECTED_KEYS = {
    114: 0x01000070,  # VolumeDown
    115: 0x01000072,  # VolumeUp
    116: 0x01020004,  # Sleep
    128: 0x010000DC,  # MenuKB
    139: 0x010000DC,  # MenuKB
    750: 0x010000DC,  # MenuKB
}


def check(package_root: Path) -> None:
    base = package_root / "var/lib/environment/compositor"
    default = base / "00-default.conf"
    platform = base / "10-platform.conf"
    device = base / "20-device.conf"
    keymap = package_root / "usr/share/qt6/keymaps/keys.qmap"

    for path in (default, platform, device, keymap):
        if not path.is_file():
            raise ValueError(f"Missing actual staged package file: {path}")

    # Upstream pinned meta-asteroid commit 1af66a6 deliberately ships an
    # empty placeholder for machine-specific 20-device.conf on this target.
    if device.stat().st_size != 0:
        raise ValueError("R08 20-device.conf unexpectedly contains device overrides")

    if "QT_IM_MODULE=qtvirtualkeyboard" not in default.read_text().splitlines():
        raise ValueError("Default Qt input environment is missing")

    lines = [
        line.strip() for line in platform.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    required = {
        "QT_QPA_PLATFORM": "linuxfb",
        "QT_QUICK_BACKEND": "software",
        "QT_QPA_FB_DRM": "0",
    }
    assignments = {}
    for line in lines:
        if "=" not in line:
            raise ValueError(f"Invalid Qt compositor environment line: {line}")
        name, value = line.split("=", 1)
        if name in assignments:
            raise ValueError(f"Duplicate Qt compositor setting: {name}")
        assignments[name] = value
    for name, wanted in required.items():
        if assignments.get(name) != wanted:
            raise ValueError(f"Wrong Qt compositor setting {name}: {assignments.get(name)}")

    data = keymap.read_bytes()
    if len(data) != 88:
        raise ValueError(f"Wrong Qt keymap byte length: {len(data)}; expected 88")
    if hashlib.sha256(data).hexdigest() != EXPECTED_QMAP_SHA256:
        raise ValueError("Staged Watch3 keymap differs from Qt6-validated golden bytes")
    if struct.unpack_from(">IIII", data) != (0x514D4150, 1, 6, 0):
        raise ValueError("Wrong Qt keymap file header")
    for index, (code, qt_code) in enumerate(EXPECTED_KEYS.items()):
        entry = struct.unpack_from(">HHIBBH", data, 16 + 12 * index)
        if entry != (code, 0xFFFF, qt_code, 0, 0, 0):
            raise ValueError(f"Invalid Watch3 button mapping at index {index}: {entry}")

    print("PASS: real R08 compositor package has LinuxFB + software Qt Quick")
    print("PASS: upstream 20-device.conf empty placeholder is present")
    print("PASS: all six Watch3 button mappings match actual Qt6-validated .qmap")
    print("NOT TESTED: hardware buttons, Watch3 framebuffer, or boot")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path, help="packages-split/asteroid-launcher-configs")
    args = parser.parse_args()
    try:
        check(args.package_root)
    except ValueError as error:
        parser.exit(1, f"FAIL: {error}\n")


if __name__ == "__main__":
    main()
