#!/usr/bin/env python3
"""Run a bounded ARM64 userland smoke test on an EXTRACTED saved UgLy|OS rootfs.

No bootloader/firmware execution, no device connection, no direct framebuffer,
no mounts, no network and no image writes. QEMU linux-user runs one audited
ARM64 system utility through the target's own dynamic linker and libraries.
This does NOT model the SM-R840X's Linux 4.9 kernel or prove custom boot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

MAGIC = b"\x7fELF"
ARM64 = 183
MAX_OUTPUT = 100_000
PROBE_TOKEN = "UGLYOS_REAL_ARM64_ROOTFS_PROBE_47"
CANDIDATES = (
    # Standard systemd executables should be real target AArch64 ELF binaries.
    # --version runs no service manager or hardware-device initialization.
    ("usr/bin/systemctl", ["--version"], "systemd"),
    ("usr/bin/journalctl", ["--version"], "systemd"),
    ("usr/lib/systemd/systemd", ["--version"], "systemd"),
    ("lib/systemd/systemd", ["--version"], "systemd"),
    ("usr/bin/env", ["UGLYOS_R08_PROBE=" + PROBE_TOKEN], "UGLYOS_R08_PROBE=" + PROBE_TOKEN),
    ("bin/busybox", ["echo", PROBE_TOKEN], PROBE_TOKEN),
    ("usr/bin/busybox", ["echo", PROBE_TOKEN], PROBE_TOKEN),
)


class SmokeFailure(ValueError):
    pass


def _inside(root: Path, path: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


def read_arm64(path: Path) -> dict:
    """Reject non-ARM64, symlink-to-host or truncated ELF candidates."""
    if not path.is_file() or path.is_symlink():
        raise SmokeFailure("MISSING_OR_SYMLINK_BINARY:" + path.name)
    size = path.stat().st_size
    if not 64 <= size <= 64 * 1024 * 1024:
        raise SmokeFailure("INVALID_BINARY_LENGTH:" + path.name)
    with path.open("rb") as f:
        h = f.read(64)
    if h[:4] != MAGIC or h[4:7] != b"\x02\x01\x01":
        raise SmokeFailure("NOT_AARCH64_ELF64:" + path.name)
    if int.from_bytes(h[18:20], "little") != ARM64:
        raise SmokeFailure("WRONG_ELF_MACHINE:" + path.name)
    if int.from_bytes(h[16:18], "little") not in (2, 3):
        raise SmokeFailure("NOT_EXECUTABLE_OR_DSO:" + path.name)
    return {"size": size, "sha256": _sha(path)}


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(cmd: list[str], env: dict[str,str] | None = None, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise SmokeFailure("OFFLINE_EXECUTOR_UNAVAILABLE_OR_TIMEOUT") from None
    if len(r.stdout) + len(r.stderr) > MAX_OUTPUT:
        raise SmokeFailure("UNBOUNDED_GUEST_OUTPUT")
    return r


def validate(root: Path, *, emulator: str = "qemu-aarch64", expected_image_sha: str | None = None) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise SmokeFailure("INVALID_EXTRACTED_ROOT")
    root = root.resolve()
    launcher = root / "usr/bin/asteroid-launcher"
    if not _inside(root, launcher):
        raise SmokeFailure("LAUNCHER_ESCAPES_ROOT")
    launcher_meta = read_arm64(launcher)
    if not shutil.which(emulator):
        raise SmokeFailure("QEMU_AARCH64_NOT_INSTALLED")

    selected = None
    for relative, args, expected in CANDIDATES:
        candidate = root / relative
        if not candidate.exists() or not candidate.is_file() or not _inside(root, candidate):
            continue
        # Busybox links may resolve within root; do not execute a host binary.
        if candidate.is_symlink() and not _inside(root, candidate):
            continue
        try:
            metadata = read_arm64(candidate)
        except SmokeFailure:
            continue
        selected = (relative, candidate, args, expected, metadata)
        break
    if selected is None:
        # Print only fixed path basenames and type/ELF metadata, never guest contents.
        checks=[]
        for relative, _, _ in CANDIDATES:
            file=root/relative
            checks.append(relative + ":" + ("symlink" if file.is_symlink() else
                          "file" if file.is_file() else "absent"))
        raise SmokeFailure("NO_REAL_ARM64_SYSTEM_UTILITY_FOR_QEMU_PROBE:" + ",".join(checks))
    relative, candidate, args, expected, metadata = selected
    # The real rootfs is ALREADY extracted by debugfs to a disposable host
    # directory. qemu-aarch64 -L supplies the guest's ELF interpreter/libs.
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C",
        "QEMU_LD_PREFIX": str(root),
        "UGLYOS_R08_SMOKE_ONLY": "1",
    }
    command = [emulator, "-L", str(root), str(candidate), *args]
    result = _run(command, env=environment, timeout=25)
    if result.returncode != 0 or expected not in result.stdout:
        raise SmokeFailure("ARM64_NATIVE_UTILITY_DID_NOT_EXECUTE:" +
                           str(result.returncode) + ":" + result.stderr[-500:])
    return {
        "schema": "uglyos-r08-real-arm64-qemu-userland-smoke-v1",
        "result": "REAL_ARM64_USERSPACE_EXECUTED_OFF_DEVICE",
        "source": "unmodified copy of previously built UgLy|OS rootfs",
        "launcher_elf64_aarch64": True,
        "launcher_sha256": launcher_meta["sha256"],
        "executed_guest_binary": "/" + relative,
        "executed_guest_binary_sha256": metadata["sha256"],
        "probe_output_exact_marker_seen": True,
        "qemu_linux_user_execution_returncode": result.returncode,
        "qemu_executes_on_HOST_kernel_not_Watch3_kernel": True,
        "rootfs_image_expected_sha256": expected_image_sha,
        "real_display_or_wayland_tested": False,
        "linux_4_9_59_syscalls_tested": False,
        "physical_watch_contacted": False,
        "stock_recovery_proven": False,
        "bootloader_acceptance_proven": False,
        "flash_allowed": False,
        "status": "NO_GO",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--extracted-rootfs", type=Path, required=True)
    p.add_argument("--expected-image-sha256", help="Provenance of ext4 image from which rootfs was extracted")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        if args.expected_image_sha256 and not re.fullmatch("[a-f0-9]{64}", args.expected_image_sha256):
            raise SmokeFailure("INVALID_ORIGINAL_IMAGE_HASH")
        report = validate(args.extracted_rootfs, expected_image_sha=args.expected_image_sha256)
    except (SmokeFailure, OSError, ValueError) as err:
        print("NO_USERSPACE_PROOF: " + str(err), file=sys.stderr)
        return 2
    if args.output.exists() or args.output.is_symlink():
        print("REFUSE_OVERWRITE_REPORT", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print("PASS: real ARM64 utility executed using the built rootfs; NOT A WATCH BOOT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
