#!/usr/bin/env python3
"""Read-only R08 image filesystem compatibility gate.

This only verifies the generated ext4's on-disk features and whether the older
e2fsck on ubuntu-22.04 can inspect it without errors. It does NOT prove that
the physical Galaxy Watch3 boots, mounts it, or can be safely flashed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


class ValidationError(ValueError):
    pass


def command(*argv: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False,
                              stdin=subprocess.DEVNULL, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(f"Read-only ext4 inspection unavailable: {exc}") from exc


def inspect(image: Path) -> dict:
    if not image.is_file() or not image.stat().st_size:
        raise ValidationError(f"Missing or empty generated ext4: {image}")
    with image.open("rb") as source:
        source.seek(1024 + 56)
        if source.read(2) != b"\x53\xef":
            raise ValidationError(f"Not an ext4 filesystem (bad superblock): {image}")
    header = command("dumpe2fs", "-h", str(image))
    if header.returncode:
        raise ValidationError(
            "dumpe2fs cannot read image: " + (header.stdout + header.stderr)[-700:])
    features_match = re.search(
        r"^Filesystem features:\s*(.+)$", header.stdout, re.MULTILINE)
    if not features_match:
        raise ValidationError("dumpe2fs did not report filesystem features")
    features = features_match.group(1).split()
    unexpected = sorted(set(
        f for f in features if f.lower().startswith("feature_")
    ))
    if "orphan_file" in features or "FEATURE_C12" in features or unexpected:
        raise ValidationError(
            "Legacy kernel incompatible or unknown ext4 features: "
            f"orphan_file={'orphan_file' in features}, "
            f"unrecognized={unexpected}. Rebuild only image tasks with "
            "EXTRA_IMAGECMD:ext4 disabled orphan_file.")
    if "extent" not in features or "filetype" not in features:
        raise ValidationError("Missing expected ext4 extent/filetype features")

    # -n means never change the original ext4, including journal replay.
    # Fail on fixable errors instead of quietly 'repairing' the artifact.
    fsck = command("e2fsck", "-f", "-n", str(image), timeout=240)
    if fsck.returncode != 0:
        raise ValidationError(
            f"Older read-only e2fsck failed (status {fsck.returncode}): "
            + (fsck.stdout + fsck.stderr)[-1200:])
    return {
        "status": "PASS_OFF_DEVICE_LEGACY_EXT4",
        "filesystem_features": features,
        "orphan_file_absent": True,
        "legacy_e2fsck_readonly_exit_code": fsck.returncode,
        "image_size_bytes": image.stat().st_size,
        "kernel_4_9_mount_tested": False,
        "device_boot_tested": False,
        "stock_recovery_verified": False,
        "flashable": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = inspect(args.image)
    except (OSError, ValidationError) as exc:
        result = {"status": "FAIL", "reason": str(exc), "flashable": False}
        exit_code = 1
    else:
        exit_code = 0
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if exit_code:
        print(f"FAIL[legacy-ext4]: {result['reason']}", file=sys.stderr)
    else:
        print("PASS[legacy-ext4]: orphan_file absent; old e2fsck checked clean.")
        print("NOT TESTED: R08 kernel mount, boot, recovery, touchscreen or audio.")
        print("NOT FLASHABLE.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
