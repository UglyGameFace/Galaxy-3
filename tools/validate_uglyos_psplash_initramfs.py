#!/usr/bin/env python3
"""Fail-closed *real BitBake* Psplash/IPK/initramfs checks for noblesse-r08.

This tool does not flash, install or establish physical Watch3 bootability.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path
import re
import subprocess
import sys

from verify_uglyos_boot_asset import (ASSET, EXPECTED_SHA256,
                                       verify_gif, verify_recipe)
from validate_uglyos_face_package import PackageError
from validate_watch3_native_face_ipk import read_real_ipk

FILENAME = "uglyos-smoke.gif"
FALLBACK = "psplash-upstream.gif"
PN = "psplash"
EXPECTED_MACHINE = "noblesse-r08"


def variables(path: Path) -> dict[str, str]:
    fields = ("PN", "MACHINE", "DISTRO", "PACKAGE_ARCH", "PACKAGECONFIG",
              "IMAGE_INSTALL", "ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL", "SRC_URI",
              "D", "PKGDEST", "PACKAGES", "datadir", "PV", "PR")
    parsed: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.removeprefix("export ")
        for key in fields:
            match = re.fullmatch(re.escape(key) + r'="(.*)"', line)
            if match:
                parsed[key] = match.group(1)
    return parsed


def check_metadata(package: dict[str, str], initramfs: dict[str, str]) -> None:
    verify_recipe()
    verify_gif()
    if package.get("PN") != PN or package.get("MACHINE") != EXPECTED_MACHINE:
        raise PackageError("Real psplash package is not for experimental R08")
    if package.get("DISTRO") != "asteroid" or package.get("datadir") != "/usr/share":
        raise PackageError("Unexpected BitBake distro/data path")
    if package.get("PACKAGE_ARCH") != "noblesse_r08":
        raise PackageError("Wrong R08 Psplash machine package architecture")
    if PN not in package.get("PACKAGES", "").split():
        raise PackageError("Psplash package not in real BitBake PACKAGES")
    if "animated-gif" not in package.get("PACKAGECONFIG", "").split():
        raise PackageError("Pinned Psplash animated-gif feature disabled")
    if f"file://{FILENAME}" not in package.get("SRC_URI", "").split():
        raise PackageError("R08 Psplash source URI does not include reviewed smoke GIF")
    if initramfs.get("MACHINE") != EXPECTED_MACHINE or initramfs.get("DISTRO") != "asteroid":
        raise PackageError("Not the pinned experimental R08 initramfs image")
    if PN not in initramfs.get("IMAGE_INSTALL", "").split():
        raise PackageError("CRITICAL: psplash absent from actual early-boot IMAGE_INSTALL")
    if PN not in initramfs.get("ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL", "").split():
        raise PackageError("Missing R08-specific initramfs inclusion")
    if "initramfs-scripts-android" not in initramfs.get("IMAGE_INSTALL", "").split():
        raise PackageError("Pinned early-boot init script absent from initramfs image")
    print("PASS[psplash-bitbake]: R08-only animated-gif Psplash metadata plus early-boot IMAGE_INSTALL")


def _real_dir(root: str, name: str) -> Path:
    path = Path(root)
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise PackageError(f"Unsafe {name} staging root")
    return path


def check_package(env: dict[str, str], ipk: Path) -> None:
    verify_gif()
    version = env.get("PV", "") + "-" + env.get("PR", "")
    arch = env.get("PACKAGE_ARCH")
    if not re.fullmatch(r"[A-Za-z0-9.+_~-]+", version) or arch != "noblesse_r08":
        raise PackageError("Unknown package version/arch")
    if ipk.name != f"{PN}_{version}_{arch}.ipk":
        raise PackageError(f"Unexpected native Yocto package name: {ipk.name}")
    source = ASSET.read_bytes()
    for root in (_real_dir(env.get("D", ""), "D"),
                 _real_dir(env.get("PKGDEST", ""), "PKGDEST") / PN):
        share = root / "usr/share"
        main = share / "psplash.gif"
        backup = share / FALLBACK
        if not main.is_file() or main.is_symlink() or main.read_bytes() != source:
            raise PackageError(f"Real Yocto staging lacks exact smoke asset: {main}")
        if not backup.is_file() or backup.is_symlink() or backup.stat().st_size < 500:
            raise PackageError(f"Real Yocto staging lacks preserved stock fallback: {backup}")
        if backup.read_bytes() == source:
            raise PackageError("Fallback was accidentally overwritten with new smoke")
        if not (root / "usr/bin/psplash").is_file():
            raise PackageError(f"Real Yocto staging missing native Psplash executable: {root}")
    controls, contents = read_real_ipk(ipk)
    if controls.get("Package") != PN or controls.get("Architecture") != arch:
        raise PackageError("Real opkg Psplash control mismatch")
    if controls.get("Version") != version:
        raise PackageError("Real opkg Psplash version mismatch")
    if contents.get("usr/share/psplash.gif") != source:
        raise PackageError("Real native IPK doesn't contain exact smoke GIF")
    backup = contents.get(f"usr/share/{FALLBACK}")
    if backup is None or len(backup) < 500 or backup == source:
        raise PackageError("Real native IPK missing independent original fallback")
    if "usr/bin/psplash" not in contents:
        raise PackageError("Real native IPK contains no Psplash executable")
    digest = hashlib.sha256(ipk.read_bytes()).hexdigest()
    print("PASS[psplash-native]: real IPK plus D/packages-split contain exact user smoke and fallback")
    print(f"PASS[psplash-native]: original smoke SHA256 {EXPECTED_SHA256}; IPK SHA256 {digest}")


def cpio_extract(archive: Path, member: str) -> bytes:
    compressed = gzip.decompress(archive.read_bytes())
    names = subprocess.run(["cpio", "-it", "--quiet"], input=compressed,
                           capture_output=True, check=True).stdout.decode().splitlines()
    canonical = {x.lstrip("./"): x for x in names}
    if member not in canonical:
        raise PackageError(f"ACTUAL initramfs lacks {member}")
    actual = canonical[member]
    result = subprocess.run(["cpio", "--quiet", "-i", "--to-stdout", actual],
                            input=compressed, capture_output=True, check=True)
    if not result.stdout:
        raise PackageError(f"Empty initramfs member {member}")
    return result.stdout


def check_initramfs(archive: Path) -> None:
    verify_gif()
    if archive.suffix != ".gz" or ".cpio.gz" not in archive.name:
        raise PackageError("Need a real initramfs-android-image .cpio.gz")
    if archive.stat().st_size < 10_000:
        raise PackageError("Suspiciously small early-boot initramfs")
    main = cpio_extract(archive, "usr/share/psplash.gif")
    original = cpio_extract(archive, f"usr/share/{FALLBACK}")
    program = cpio_extract(archive, "usr/bin/psplash")
    boot_init = cpio_extract(archive, "init")
    if hashlib.sha256(main).hexdigest() != EXPECTED_SHA256:
        raise PackageError("ACTUAL initramfs smoke GIF is not the approved video derivative")
    if len(original) < 500 or main == original:
        raise PackageError("No distinct original Psplash fallback in actual initramfs")
    if len(program) < 5000 or not program.startswith(b"\x7fELF"):
        raise PackageError("Initramfs Psplash executable is missing or not ELF")
    if b"psplash" not in boot_init:
        raise PackageError("Initramfs boot script doesn't launch Psplash")
    print(f"PASS[psplash-initramfs]: actual {archive.name} includes smoke, distinct fallback, ELF, launcher")
    print("NOT TESTED: Watch3 boot-chain acceptance, framebuffer driver, actual playback, stock recovery")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("metadata", "native-ipk", "initramfs"))
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        if args.mode == "metadata":
            if args.second is None:
                raise PackageError("Need psplash and initramfs BitBake -e snapshots")
            check_metadata(variables(args.first), variables(args.second))
        elif args.mode == "native-ipk":
            if args.second is None:
                raise PackageError("Need real Yocto archive alongside -e snapshot")
            check_package(variables(args.first), args.second)
        else:
            check_initramfs(args.first)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, PackageError) as err:
        print(f"FAIL[psplash-integration]: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
