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
              "PACKAGES", "FILES:watch3-faces", "PKGDEST", "D", "datadir", "PV", "PR", "PACKAGE_ARCH")
    collected: dict[str, str] = {}
    for line in file.read_text().splitlines():
        # Real "bitbake -e" exports datadir (and other shell variables).
        # Normalize only the exact export prefix, not commented history.
        if line.startswith("export "):
            line = line[len("export "):]
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


def inspect_installed(info: dict[str, str], source: Path) -> None:
    """Validate the actual BitBake do_install tree without claiming an IPK."""
    root = info.get("D", "")
    datadir = info.get("datadir", "")
    if not root.startswith("/") or root == "/":
        raise PackageError("Unsafe BitBake installation root")
    if not datadir.startswith("/") or ".." in Path(datadir).parts:
        raise PackageError("Unsafe datadir from BitBake metadata")
    stage = Path(root) / datadir.lstrip("/")
    expected = {f"asteroid-launcher/watchfaces/{name}": source / name
                for name in FACES}
    expected["uglyos/edition.json"] = source / "uglyos-edition.json"
    for relative, original in expected.items():
        installed = stage / relative
        if not original.is_file() or not installed.is_file():
            raise PackageError(f"Missing staged/source asset {relative}")
        if not original.read_bytes() or installed.read_bytes() != original.read_bytes():
            raise PackageError(f"Source/install mismatch for {relative}")
    found = {p.relative_to(stage).as_posix() for p in stage.rglob("*")
             if p.is_file() or p.is_symlink()}
    if found != set(expected):
        raise PackageError(f"Unexpected installed assets: {sorted(found ^ set(expected))}")
    verify_identity(stage / "uglyos/edition.json")
    print("PASS[installed]: 3 QML faces + identity match actual BitBake D")
    print("NOT TESTED: do_package, package split, IPK, image, Qt or watch boot")


def inspect_package(info: dict[str, str], source: Path) -> None:
    """Optional full split check, only valid after a genuine do_package."""
    pkgdest = info.get("PKGDEST", "")
    if not pkgdest.startswith("/") or pkgdest == "/":
        raise PackageError("Unsafe package path root")
    inspect_installed(info, source)
    package = Path(pkgdest) / PACKAGE / info.get("datadir", "/usr/share").lstrip("/")
    for name in FACES:
        target = package / "asteroid-launcher/watchfaces" / name
        if not target.is_file() or target.read_bytes() != (source / name).read_bytes():
            raise PackageError(f"Source/package mismatch for QML {name}")
    edition = package / "uglyos/edition.json"
    if not edition.is_file() or edition.read_bytes() != (source / "uglyos-edition.json").read_bytes():
        raise PackageError("Brand metadata differs from source")
    verify_identity(edition)
    actual = {p.relative_to(package).as_posix() for p in package.rglob("*")
              if p.is_file() or p.is_symlink()}
    expected = {f"asteroid-launcher/watchfaces/{name}" for name in FACES}
    expected.add("uglyos/edition.json")
    if actual != expected:
        raise PackageError(f"Unexpected package-split assets: {sorted(actual ^ expected)}")
    print("PASS[package]: all four sources match the real package split")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("metadata", "installed", "packaged"))
    parser.add_argument("environment", type=Path)
    parser.add_argument("other", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "metadata":
            metadata(variables(args.environment), variables(args.other))
        elif args.mode == "installed":
            inspect_installed(variables(args.environment), args.other)
        else:
            inspect_package(variables(args.environment), args.other)
    except (PackageError, OSError, ValueError) as error:
        print("FAIL[uglyos-face]: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
