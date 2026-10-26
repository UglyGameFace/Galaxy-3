#!/usr/bin/env python3
"""Verify real, R08-only Yocto uglyos-launchers staging and native IPK.

No off-device artifact from here authorizes rootfs installation or flashing.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys

from validate_uglyos_face_package import PackageError
from validate_watch3_native_face_ipk import read_real_ipk

PN = "uglyos-launchers"
ASSETS = ("900-uglyos-fast-list.qml", "901-uglyos-compact-grid.qml",
          "902-uglyos-stoner-lounge.qml", "903-uglyos-gamer-arcade.qml")
SUBDIR = "asteroid-launcher/applauncher"


def variables(path: Path) -> dict[str, str]:
    wanted = {"PN", "MACHINE", "DISTRO", "PACKAGE_ARCH", "INHIBIT_DEFAULT_DEPS",
              "RDEPENDS:uglyos-launchers", "IMAGE_INSTALL", "D", "PKGDEST",
              "datadir", "PV", "PR", "PACKAGES"}
    parsed: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.removeprefix("export ")
        for name in wanted:
            prefix = name + '="'
            if line.startswith(prefix) and line.endswith('"'):
                parsed[name] = line[len(prefix):-1]
    return parsed


def check_metadata(info: dict[str, str], image: dict[str, str]) -> None:
    for key, expected in (("PN", PN), ("MACHINE", "noblesse-r08"),
                          ("DISTRO", "asteroid"), ("INHIBIT_DEFAULT_DEPS", "1"),
                          ("PACKAGE_ARCH", "noblesse_r08"),
                          ("RDEPENDS:uglyos-launchers", "asteroid-launcher")):
        if info.get(key) != expected:
            raise PackageError(f"Unexpected R08 {key}: {info.get(key)!r}, expected {expected!r}")
    if PN not in info.get("PACKAGES", "").split():
        raise PackageError("Real BitBake PACKAGES does not include launcher package")
    if image.get("MACHINE") != "noblesse-r08" or image.get("DISTRO") != "asteroid":
        raise PackageError("Wrong actual AsteroidOS image target")
    if PN not in image.get("IMAGE_INSTALL", "").split():
        raise PackageError("Actual R08 image IMAGE_INSTALL does not contain new launchers")
    print("PASS[launcher-metadata]: actual pinned BitBake resolves the R08-only launcher package")


def expected_assets(source: Path) -> dict[str, bytes]:
    if sorted(p.name for p in source.glob("*.qml")) != sorted(ASSETS):
        raise PackageError("Unexpected/missing source launcher QML files")
    data = {f"{SUBDIR}/{name}": (source / name).read_bytes() for name in ASSETS}
    if any(not content for content in data.values()):
        raise PackageError("Empty launchable QML source asset")
    return data


def inspect_tree(root: Path, data: dict[str, bytes], datadir: str) -> None:
    if not str(root).startswith("/") or str(root) == "/" or not datadir.startswith("/"):
        raise PackageError("Unsafe Yocto package install root")
    if ".." in root.parts or ".." in Path(datadir).parts:
        raise PackageError("Unsafe Yocto package paths")
    share = root / datadir.lstrip("/")
    found = {p.relative_to(share).as_posix() for p in share.rglob("*")
             if p.is_file() or p.is_symlink()} if share.is_dir() else set()
    if found != set(data):
        raise PackageError(f"Unexpected/missing staged launcher files: {sorted(found ^ set(data))}")
    for name, content in data.items():
        file = share / name
        if file.is_symlink() or file.read_bytes() != content:
            raise PackageError(f"Launcher source bytes differ in package staging: {name}")


def check_ipk(info: dict[str, str], source: Path, archive: Path) -> str:
    data = expected_assets(source)
    datadir = info.get("datadir", "")
    if datadir != "/usr/share":
        raise PackageError(f"Unexpected Yocto datadir: {datadir!r}")
    for variable, suffix in (("D", ""), ("PKGDEST", "/" + PN)):
        value = info.get(variable, "")
        if not value.startswith("/") or value == "/":
            raise PackageError(f"Unsafe BitBake {variable} root")
        inspect_tree(Path(value + suffix), data, datadir)
    arch, version = info.get("PACKAGE_ARCH"), info.get("PV", "") + "-" + info.get("PR", "")
    if arch != "noblesse_r08" or not re.fullmatch(r"[A-Za-z0-9.+_~-]+", version):
        raise PackageError("Unexpected launcher version or architecture")
    name = f"{PN}_{version}_{arch}.ipk"
    if archive.name != name:
        raise PackageError(f"Wrong Yocto IPK filename: {archive.name}, expected {name}")
    control, payload = read_real_ipk(archive)
    for key, expected in (("Package", PN), ("Version", version), ("Architecture", arch),
                          ("Depends", "asteroid-launcher")):
        if control.get(key) != expected:
            raise PackageError(f"Actual opkg {key} incorrect: {control.get(key)!r}")
    packed = {p.removeprefix("usr/share/"): content for p, content in payload.items()
              if p.startswith("usr/share/")}
    if len(packed) != len(payload) or packed != data:
        raise PackageError(f"Yocto IPK contents don't match four QML sources: {sorted(set(packed) ^ set(data))}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    print(f"PASS[launcher-ipk]: Yocto-native {name} contains exactly four original QML assets")
    print(f"PASS[launcher-ipk]: install and package-split trees match bytes; Depends: asteroid-launcher")
    print(f"SHA256: {digest}")
    print("NOT TESTED: native Settings build, rootfs boot, actual launcher execution, watch flashing")
    return digest


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("mode", choices=("metadata", "native-ipk"))
    cli.add_argument("environment", type=Path)
    cli.add_argument("first", type=Path)
    cli.add_argument("second", type=Path, nargs="?")
    args = cli.parse_args()
    try:
        info = variables(args.environment)
        if args.mode == "metadata":
            check_metadata(info, variables(args.first))
        else:
            if args.second is None:
                raise PackageError("Need actual Yocto native IPK archive path")
            check_ipk(info, args.first, args.second)
    except (OSError, PackageError, ValueError, UnicodeError) as err:
        print(f"FAIL[launcher-native]: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
