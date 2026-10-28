#!/usr/bin/env python3
"""Validate real UgLy|OS ARM64 launcher dynamic-library closure under QEMU.

Never starts the GUI or executes the launcher main() function: execute its
own ARM64 dynamic loader with --list against the actual target ELF. Real
images and libs come from a separately verified historical rootfs; NO WATCH.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys

from watch3_r08_qemu_userland_smoke import read_arm64, SmokeFailure

MAX_OUTPUT = 120_000


class ClosureError(ValueError):
    pass


def guest_interpreter(elf: Path) -> str:
    """Read ELF64 little-endian PT_INTERP, not guessed host loader paths."""
    read_arm64(elf)
    with elf.open("rb") as f:
        header = f.read(64)
        phoff = struct.unpack_from("<Q", header, 32)[0]
        phsize, phcount = struct.unpack_from("<HH", header, 54)
        if phsize != 56 or not 1 <= phcount <= 100:
            raise ClosureError("INVALID_ELF_PROGRAM_HEADER_TABLE")
        if phoff < 64 or phoff + phsize * phcount > elf.stat().st_size:
            raise ClosureError("TRUNCATED_ELF_PROGRAM_HEADERS")
        found = []
        for n in range(phcount):
            f.seek(phoff + n * phsize)
            ph = f.read(phsize)
            if struct.unpack_from("<I", ph, 0)[0] != 3:
                continue
            offset = struct.unpack_from("<Q", ph, 8)[0]
            filesz = struct.unpack_from("<Q", ph, 32)[0]
            if filesz < 8 or filesz > 200 or offset + filesz > elf.stat().st_size:
                raise ClosureError("BAD_ELF_INTERPRETER_ENTRY")
            f.seek(offset)
            raw = f.read(filesz)
            if raw[-1:] != b"\x00" or b"\x00" in raw[:-1]:
                raise ClosureError("INVALID_ELF_INTERPRETER_TERMINATOR")
            try:
                found.append(raw[:-1].decode("ascii"))
            except UnicodeDecodeError as e:
                raise ClosureError("NONASCII_ELF_INTERPRETER") from e
        if len(found) != 1:
            raise ClosureError("MISSING_OR_DUPLICATE_ARM64_INTERPRETER")
        result = found[0]
        # Linux standard guest-interpreter path, no traversal or host path.
        if (not result.startswith("/") or ".." in PurePosixPath(result).parts
                or not re.fullmatch(r"/(?:lib|lib64|usr/lib|usr/lib64)/[A-Za-z0-9_.-]+", result)):
            raise ClosureError("UNSAFE_OR_UNEXPECTED_GUEST_INTERPRETER")
        if "ld-linux-aarch64" not in result:
            raise ClosureError("NOT_AARCH64_LINUX_DYNAMIC_INTERPRETER")
        return result


def rooted_link(root: Path, relative: str) -> Path:
    """Resolve absolute *guest* symlinks inside the extracted sysroot, not host."""
    root = root.resolve()
    current = root / relative.lstrip("/")
    for _ in range(10):
        # Validate lexical parent before following symlinks.
        if not current.parent.resolve().is_relative_to(root):
            raise ClosureError("GUEST_LOADER_PATH_ESCAPES_ROOT")
        if current.is_symlink():
            link = os.readlink(current)
            current = (root / link.lstrip("/")) if link.startswith("/") else (current.parent / link)
            continue
        if not current.is_file() or not current.resolve().is_relative_to(root):
            raise ClosureError("GUEST_ARM64_LOADER_NOT_FOUND")
        read_arm64(current)
        return current
    raise ClosureError("GUEST_LOADER_SYMLINK_LOOP")


def check(root: Path, emulator: str = "qemu-aarch64") -> dict:
    if not root.is_dir() or root.is_symlink():
        raise ClosureError("INVALID_ROOTFS")
    root = root.resolve()
    launcher = root / "usr/bin/asteroid-launcher"
    if not launcher.resolve().is_relative_to(root):
        raise ClosureError("LAUNCHER_OUTSIDE_GUEST_ROOT")
    read_arm64(launcher)
    interpreter = guest_interpreter(launcher)
    loader = rooted_link(root, interpreter)
    if not shutil.which(emulator):
        raise ClosureError("QEMU_NOT_AVAILABLE")
    env = {"PATH": "/usr/bin:/bin", "LANG": "C",
           "HOME": "/tmp", "QEMU_LD_PREFIX": str(root)}
    # This is a glibc linker dependency enumeration, NOT startup of the GUI.
    cmd = [emulator, "-L", str(root), str(loader),
           "--list", str(launcher)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=40, stdin=subprocess.DEVNULL,
                                env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ClosureError("QEMU_LINKER_UNAVAILABLE_OR_TIMEOUT") from None
    output = result.stdout + "\n" + result.stderr
    if len(output) > MAX_OUTPUT:
        raise ClosureError("UNBOUNDED_QEMU_LINKER_OUTPUT")
    if result.returncode != 0:
        raise ClosureError("QEMU_LAUNCHER_LINKER_FAILED:" +
                           str(result.returncode) + ":" + result.stderr[-500:])
    if "not found" in output.lower() or "error while loading" in output.lower():
        raise ClosureError("LAUNCHER_DEPENDENCIES_UNRESOLVED")
    qt = sorted(set(re.findall(r"libQt6[A-Za-z0-9_]*\.so(?:\.[0-9]+)*", output)))
    if not qt:
        raise ClosureError("NO_QT6_LIBRARIES_IN_ACTUAL_LINKER_RESOLUTION")
    return {
        "schema": "uglyos-r08-arm64-qt-launcher-linker-closure-v1",
        "result": "REAL_ARM64_LAUNCHER_DYNAMIC_DEPENDENCIES_RESOLVED",
        "launcher_path": "/usr/bin/asteroid-launcher",
        "guest_interpreter": interpreter,
        "qt6_dependency_names": qt[:32],
        "qt6_dependency_count": len(qt),
        "linker_exit_status": result.returncode,
        "real_aarch64_glibc_linker_executed": True,
        "launchers_main_function_called": False,
        "wayland_or_gui_display_tested": False,
        "watch3_linux_4_9_kernel_tested": False,
        "bootloader_acceptance_proven": False,
        "stock_recovery_proven": False,
        "physical_watch_contacted": False,
        "flash_allowed": False,
        "decision": "NO_GO",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--extracted-rootfs", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    try:
        result = check(args.extracted_rootfs)
        if args.output.exists() or args.output.is_symlink():
            raise ClosureError("OUTPUT_ALREADY_EXISTS")
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    except (OSError, ValueError, SmokeFailure) as error:
        print("LAUNCHER_CLOSURE_UNVERIFIED: " + str(error), file=sys.stderr)
        return 2
    print("PASS: real built AArch64 launcher library closure; NO GUI OR WATCH BOOT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
