#!/usr/bin/env python3
"""Check real staged QtWayland target packages, never run ARM64 code on CI.

Input is BitBake PKGDEST from 'bitbake -e qtwayland'.  The pinned meta-qt6
recipe uses qt6.inc, which splits native platform plugins into
qtwayland-plugins and shared libraries into qtwayland.  This gate is meant
to run AFTER target packaging; metadata-only success is insufficient.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from validate_watch3_graphics_rootfs import elf_aarch64


def _files_within(base: Path, pattern: str) -> list[Path]:
    root = base.resolve()
    if not base.is_dir():
        return []
    return sorted(
        p for p in base.rglob(pattern)
        if p.is_file() and p.resolve().is_relative_to(root)
    )


def validate_package(pkgdest: Path) -> list[str]:
    problems: list[str] = []
    runtime = pkgdest / "qtwayland"
    plugins = pkgdest / "qtwayland-plugins"
    if not runtime.is_dir():
        problems.append(f"missing qtwayland runtime package directory: {runtime}")
    if not plugins.is_dir():
        problems.append(f"missing qtwayland-plugins package directory: {plugins}")

    libs = [
        p for p in _files_within(runtime, "libQt6WaylandCompositor.so.*")
        if p.name.rsplit(".", 1)[-1][0:1].isdigit()
    ]
    # qt6.inc splits real ABI-versioned .so files into the main package.
    if not libs:
        problems.append("missing ABI-versioned libQt6WaylandCompositor.so.* in qtwayland")
    else:
        if not any(elf_aarch64(p)[0] for p in libs):
            problems.append("QtWayland compositor library has no valid ARM64 ELF64 binary")

    platform_plugins = [
        p for p in _files_within(plugins, "libqwayland*.so")
        if p.parent.name == "platforms" and p.parent.parent.name == "plugins"
    ]
    if not platform_plugins:
        problems.append("missing plugins/platforms/libqwayland*.so in qtwayland-plugins")
    else:
        if not any(elf_aarch64(p)[0] for p in platform_plugins):
            problems.append("QtWayland QPA plugins have no valid ARM64 ELF64 binary")

    # Reject deceptive symlinks leaving the staged package tree. Since BitBake
    # packages contain relative symlinks, a symlink resolving outside its
    # package root here requires explanation rather than silent acceptance.
    for folder in (runtime, plugins):
        if not folder.is_dir():
            continue
        root = folder.resolve()
        for p in folder.rglob("*"):
            if p.is_symlink() and p.is_file() and not p.resolve().is_relative_to(root):
                problems.append(f"external packaged symlink: {p}")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pkgdest", type=Path, help="effective QtWayland BitBake PKGDEST")
    args = parser.parse_args()
    errors = validate_package(args.pkgdest)
    if errors:
        for error in errors:
            print("FAIL[qtwayland]: " + error, file=sys.stderr)
        return 1
    print("PASS[qtwayland]: packaged compositor lib + QPA Wayland plugin are ELF64 AArch64")
    print("PASS[qtwayland]: required packages contain real files, not merely BitBake metadata")
    print("NOT TESTED: watch framebuffer, QPA plugin loading, graphical rootfs or boot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
