#!/usr/bin/env python3
"""Validate real ARM64 QtWayland compositor packages after BitBake packaging.

In Qt 6.11 the Wayland *client QPA plugin* is built by QtBase, not QtWayland.
QtWayland owns the compositor library; its optional plugin split can be empty.
The final rootfs validator separately requires the client QPA in the image.
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

    # Qt 6.11 moved libqwayland*.so to QtBase. Do not require it here.
    # If this recipe does ship other optional QtWayland plugins, verify their
    # architecture rather than treating an empty ALLOW_EMPTY split as a failure.
    if plugins.is_dir():
        for plugin in _files_within(plugins, "*.so"):
            if not elf_aarch64(plugin)[0]:
                problems.append(f"QtWayland plugin is not ARM64 ELF64: {plugin}")

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
    print("PASS[qtwayland]: packaged compositor library is ELF64 AArch64")
    print("PASS[qtwayland]: optional QtWayland plugins checked; client QPA belongs to QtBase")
    print("NOT TESTED: watch framebuffer, QPA plugin loading, graphical rootfs or boot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
