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
# Exact psplash revision pinned in OE-Core and meta-asteroid for this build.
EXPECTED_SRCREV = "53ae74a36bf17675228552abb927d2f981940a6a"


def variables(path: Path) -> dict[str, str]:
    fields = ("PN", "MACHINE", "DISTRO", "PACKAGE_ARCH", "PACKAGECONFIG",
              "IMAGE_INSTALL", "ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL", "SRC_URI",
              "D", "PKGDEST", "PACKAGES", "datadir", "PV", "PR", "SRCREV")
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


def expected_native_version(env: dict[str, str]) -> str:
    """Match pinned BitBake git package version, not incomplete recipe PV-PR.

    OE package_setup_pkgv appends its git sortable revision to PKGV at
    do_package time; bitbake -e PV alone excludes the appended revision.
    Pinned git sortable revision is "0+" plus ten SRCREV hex digits.
    """
    if env.get("SRCREV") != EXPECTED_SRCREV:
        raise PackageError("Unexpected pinned Psplash source revision")
    pv, pr = env.get("PV", ""), env.get("PR", "")
    if pv != "0.1+git" or pr != "r0":
        raise PackageError(f"Unexpected source recipe PV/PR: {pv!r}/{pr!r}")
    version = f"{pv}0+{EXPECTED_SRCREV[:10]}-{pr}"
    if not re.fullmatch(r"[0-9A-Za-z.+_~-]+", version):
        raise PackageError("Unsafe native opkg version")
    return version


def _check_elf(elf: bytes | None, label: str) -> None:
    if not elf or len(elf) < 5000 or not elf.startswith(b"\x7fELF"):
        raise PackageError(f"Real compiled Psplash ELF missing: {label}")


def check_package(env: dict[str, str], ipk: Path, default_ipk: Path) -> None:
    verify_gif()
    version = expected_native_version(env)
    arch = env.get("PACKAGE_ARCH")
    if arch != "noblesse_r08":
        raise PackageError("Wrong R08 IPK package architecture")
    if ipk.name != f"{PN}_{version}_{arch}.ipk":
        raise PackageError(f"Wrong real Psplash GIF package filename: {ipk.name}")
    if default_ipk.name != f"psplash-default_{version}_{arch}.ipk":
        raise PackageError(f"Wrong native Psplash executable package: {default_ipk.name}")
    source = ASSET.read_bytes()
    install = _real_dir(env.get("D", ""), "D")
    split = _real_dir(env.get("PKGDEST", ""), "PKGDEST")
    for root in (install, split / PN):
        share = root / "usr/share"
        main, backup = share / "psplash.gif", share / FALLBACK
        if not main.is_file() or main.is_symlink() or main.read_bytes() != source:
            raise PackageError(f"Native Psplash staging lacks exact smoke: {main}")
        if not backup.is_file() or backup.is_symlink() or backup.stat().st_size < 500:
            raise PackageError(f"Native Psplash staging lacks upstream GIF: {backup}")
        if backup.read_bytes() == source:
            raise PackageError("Stock fallback unexpectedly replaced with smoke GIF")
    # Pinned psplash_git.bb puts /usr/bin/psplash-default in the separate
    # psplash-default package via SPLASH_IMAGES + update-alternatives.
    for root in (install, split / "psplash-default"):
        binary = root / "usr/bin/psplash-default"
        if not binary.is_file() or binary.is_symlink():
            raise PackageError(f"Native Psplash default executable not staged: {binary}")
        _check_elf(binary.read_bytes(), str(binary))
    control, contents = read_real_ipk(ipk)
    if control.get("Package") != PN or control.get("Architecture") != arch:
        raise PackageError("Real Psplash asset control fields mismatch")
    if control.get("Version") != version:
        raise PackageError("Real Psplash asset control version mismatch")
    depends = control.get("Depends", "")
    if not re.search(r"(?:^|,\s*)psplash-default(?:\s|,|$)", depends):
        raise PackageError("Psplash main package must depend on psplash-default executable")
    if contents.get("usr/share/psplash.gif") != source:
        raise PackageError("Native Psplash main IPK lacks approved smoke bytes")
    original = contents.get(f"usr/share/{FALLBACK}")
    if not original or len(original) < 500 or original == source:
        raise PackageError("Native Psplash main IPK lacks distinct stock fallback")
    binary_control, binary_files = read_real_ipk(default_ipk)
    for field, expected in (("Package", "psplash-default"), ("Version", version),
                            ("Architecture", arch)):
        if binary_control.get(field) != expected:
            raise PackageError(f"Native executable IPK {field} mismatch")
    binary = binary_files.get("usr/bin/psplash-default")
    _check_elf(binary, "psplash-default IPK")
    staged = (split / "psplash-default/usr/bin/psplash-default").read_bytes()
    if binary != staged:
        raise PackageError("Native executable archive bytes do not match package split")
    print("PASS[psplash-native]: approved smoke and stock fallback present in native main IPK")
    print("PASS[psplash-native]: distinct psplash-default IPK includes exact compiled ELF")
    print(f"PASS[psplash-native]: main SHA256 {hashlib.sha256(ipk.read_bytes()).hexdigest()}")
    print(f"PASS[psplash-native]: default SHA256 {hashlib.sha256(default_ipk.read_bytes()).hexdigest()}")


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
    program = cpio_extract(archive, "usr/bin/psplash-default")
    boot_init = cpio_extract(archive, "init")
    if hashlib.sha256(main).hexdigest() != EXPECTED_SHA256:
        raise PackageError("ACTUAL initramfs smoke GIF is not the approved video derivative")
    if len(original) < 500 or main == original:
        raise PackageError("No distinct original Psplash fallback in actual initramfs")
    _check_elf(program, "real initramfs psplash-default")
    # update-alternatives links /usr/bin/psplash to psplash-default when
    # the initramfs rootfs is assembled. The launcher script uses psplash.
    compressed = gzip.decompress(archive.read_bytes())
    names = subprocess.run(["cpio", "-it", "--quiet"], input=compressed,
                           capture_output=True, check=True).stdout.decode().splitlines()
    if not any(x.lstrip("./") == "usr/bin/psplash" for x in names):
        raise PackageError("Early-boot initramfs has no update-alternatives psplash link")
    if b"psplash" not in boot_init:
        raise PackageError("Initramfs boot script doesn't launch Psplash")
    print(f"PASS[psplash-initramfs]: actual {archive.name} includes smoke, distinct fallback, ELF, launcher")
    print("NOT TESTED: Watch3 boot-chain acceptance, framebuffer driver, actual playback, stock recovery")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("metadata", "native-ipk", "initramfs"))
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path, nargs="?")
    parser.add_argument("third", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        if args.mode == "metadata":
            if args.second is None:
                raise PackageError("Need psplash and initramfs BitBake -e snapshots")
            check_metadata(variables(args.first), variables(args.second))
        elif args.mode == "native-ipk":
            if args.second is None or args.third is None:
                raise PackageError("Need both main Psplash and psplash-default native IPKs")
            check_package(variables(args.first), args.second, args.third)
        else:
            check_initramfs(args.first)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, PackageError) as err:
        print(f"FAIL[psplash-integration]: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
