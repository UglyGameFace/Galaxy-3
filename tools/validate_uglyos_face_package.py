#!/usr/bin/env python3
"""Check real R08 BitBake metadata and packaged UgLy|OS watch faces.

BitBake provides effective recipe variables through -e; actual installed
files are verified against source assets, D, and PKGDEST.
This never accesses the watch or runs a full firmware image build.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

FACES = ("900-watch3-orbit.qml", "901-watch3-focus.qml",
         "902-watch3-signal.qml")
PACKAGE = "watch3-faces"


class PackageError(ValueError):
    pass


def variables(file: Path) -> dict[str, str]:
    wanted = ("PN", "MACHINE", "DISTRO", "INHIBIT_DEFAULT_DEPS",
              "BASEDEPENDS", "DEPENDS", "IMAGE_INSTALL", "RDEPENDS:watch3-faces",
              "PACKAGES", "FILES:watch3-faces", "PKGDEST", "D", "datadir")
    collected: dict[str, str] = {}
    for line in file.read_text().splitlines():
        for name in wanted:
            if line.startswith(name + '="') and line.endswith('"'):
                collected[name] = line[len(name) + 2:-1]
    return collected


def metadata(recipe: dict[str, str], image: dict[str, str]) -> None:
    for name, expected in (("PN", PACKAGE), ("MACHINE", "noblesse-r08"),
                           ("DISTRO", "asteroid"), ("INHIBIT_DEFAULT_DEPS", "1")):
        if recipe.get(name) != expected:
            raise PackageError(f"Actual recipe {name} expected {expected}")
    if "asteroid-launcher" not in recipe.get("RDEPENDS:watch3-faces", "").split():
        raise PackageError("Missing dependency on upstream AsteroidOS launcher")
    if PACKAGE not in recipe.get("PACKAGES", "").split():
        raise PackageError("watch3-faces missing from package split")
    for value in ("/asteroid-launcher/watchfaces", "/uglyos/edition.json"):
        if value not in recipe.get("FILES:watch3-faces", ""):
            raise PackageError(f"Package files must contain {value}")
    for key in ("BASEDEPENDS", "DEPENDS"):
        extra = {"virtual/cross-cc", "virtual/compilerlibs",
                 "virtual/libc"}.intersection(recipe.get(key, "").split())
        if extra:
            raise PackageError(f"Unexpected cold compiler dependencies: {extra}")
    if image.get("MACHINE") != "noblesse-r08" or image.get("DISTRO") != "asteroid":
        raise PackageError("Wrong image machine/distribution")
    if PACKAGE not in image.get("IMAGE_INSTALL", "").split():
        raise PackageError("Actual asteroid-image does not install face package")
    print("PASS[metadata]: pinned BitBake resolves R08 face pack in actual AsteroidOS")


def verify_identity(file: Path) -> None:
    obj = json.loads(file.read_text())
    expected = {
        "display_name": "UgLy|OS", "slug": "uglyos",
        "base_system": "AsteroidOS", "boot_status": "not-boot-tested",
        "install_status": "not-flashable",
    }
    if not isinstance(obj, dict) or any(obj.get(k) != v for k, v in expected.items()):
        raise PackageError("Branding, upstream credit, or flash-status mismatch")


def inspect_package(info: dict[str, str], source: Path) -> None:
    stage_value = info.get("D", "")
    package_value = info.get("PKGDEST", "")
    if not stage_value.startswith("/") or not package_value.startswith("/"):
        raise PackageError("Missing absolute BitBake installation and package roots")
    if stage_value == "/" or package_value == "/":
        raise PackageError("Unsafe package path root")
    stage = Path(stage_value) / info.get("datadir", "/usr/share").lstrip("/")
    packaged = Path(package_value) / PACKAGE / info.get("datadir", "/usr/share").lstrip("/")
    for name in FACES:
        source_file = source / name
        installed_file = stage / "asteroid-launcher/watchfaces" / name
        packaged_file = packaged / "asteroid-launcher/watchfaces" / name
        if not all(p.is_file() for p in (source_file, installed_file, packaged_file)):
            raise PackageError(f"Missing staged/packaged QML {name}")
        expected = source_file.read_bytes()
        if not expected or any(p.read_bytes() != expected
                               for p in (installed_file, packaged_file)):
            raise PackageError(f"Source/package mismatch for QML {name}")
    identity = source / "uglyos-edition.json"
    installed = stage / "uglyos/edition.json"
    final = packaged / "uglyos/edition.json"
    if not all(p.is_file() for p in (identity, installed, final)):
        raise PackageError("UgLy|OS edition identity not packaged")
    if not (identity.read_bytes() == installed.read_bytes() == final.read_bytes()):
        raise PackageError("Brand metadata differs from source")
    verify_identity(final)
    print("PASS[package]: 3 real QML faces + identity staged and packaged byte-for-byte")
    print("NOT TESTED: actual Qt rendering, full filesystem, Watch3 boot or flashing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("metadata", "packaged"))
    parser.add_argument("environment", type=Path)
    parser.add_argument("other", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "metadata":
            metadata(variables(args.environment), variables(args.other))
        else:
            inspect_package(variables(args.environment), args.other)
    except (PackageError, OSError, ValueError) as error:
        print("FAIL[uglyos-face]: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
