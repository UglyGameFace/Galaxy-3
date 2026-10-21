#!/usr/bin/env python3
"""Verify a built Watch3 QtBase LinuxFB QPA plugin, not on-watch rendering."""
from pathlib import Path
import argparse
import struct
import sys


def validate_package(pkgdest: Path) -> list[str]:
    package = pkgdest / "qtbase-plugins"
    if not package.is_dir():
        return [f"Missing QtBase QPA plugin package: {package}"]

    matches = sorted(package.rglob("libqlinuxfb.so"))
    if len(matches) != 1:
        return [f"Expected one libqlinuxfb.so in qtbase-plugins; found {len(matches)}"]

    plugin = matches[0]
    if plugin.parts[-3:] != ("plugins", "platforms", "libqlinuxfb.so"):
        return [f"LinuxFB plugin is outside the Qt platforms directory: {plugin}"]
    try:
        with plugin.open("rb") as stream:
            header = stream.read(64)
    except OSError as exc:
        return [f"Cannot inspect LinuxFB plugin: {exc}"]

    if len(header) < 64 or header[:4] != b"\x7fELF":
        return ["LinuxFB plugin is not a complete ELF64 header"]
    # Watch3 machine tune is aarch64. ELF class, endianness, type and machine
    # are a cheap check that the plugin isn't accidentally a host build.
    if header[4] != 2 or header[5] != 1:
        return ["LinuxFB plugin is not a little-endian ELF64 binary"]
    e_type, e_machine = struct.unpack_from("<HH", header, 16)
    if e_type != 3 or e_machine != 183:
        return [f"LinuxFB plugin is not an AArch64 shared object (type={e_type}, machine={e_machine})"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pkgdest", type=Path, help="Effective BitBake PKGDEST from bitbake -e qtbase")
    args = parser.parse_args()
    errors = validate_package(args.pkgdest)
    if errors:
        for error in errors:
            print("FAIL: " + error, file=sys.stderr)
        return 1
    print("PASS: qtbase-plugins contains an AArch64 ELF64 LinuxFB QPA shared object.")
    print("NOT TESTED: plugin load, compositor startup, Wayland buffers or Watch3 framebuffer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
