#!/usr/bin/env python3
"""Create a separate Linux-4.9-oriented ext4 candidate from the REAL saved image.

Issue #47: purely offline host operation. It NEVER changes the original image,
contacts the watch, or produces a signed Samsung installation package.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from verify_watch3_original_artifact_preservation import (
    IMAGE_FILENAME, IMAGE_BYTES, IMAGE_SHA256, verify_file,
)
from validate_watch3_legacy_ext4 import inspect as check_legacy, ValidationError

DERIVED_NAME = "asteroid-image-noblesse-r08.rootfs-20261024125252.legacy-ext4-OFFLINE-NOT-FLASHABLE.ext4"
SCHEMA = "uglyos-r08-real-original-ext4-legacy-derivative-v1"


class DeriveError(ValueError):
    pass


def run(*argv: str, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                   stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DeriveError("OFFLINE_IMAGE_TOOL_UNAVAILABLE_OR_TIMED_OUT") from None
    if completed.returncode:
        raise DeriveError("OFFLINE_IMAGE_TOOL_FAILED:" + Path(argv[0]).name +
                          ":" + str(completed.returncode) +
                          ":" + (completed.stderr or completed.stdout)[-500:])
    return completed


def features(path: Path) -> set[str]:
    header = run("dumpe2fs", "-h", str(path), timeout=35)
    match = re.search(r"^Filesystem features:\s*(.+)$", header.stdout, re.MULTILINE)
    if not match:
        raise DeriveError("EXT4_FEATURES_UNREADABLE")
    return set(match.group(1).split())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(2 * 1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def copy_exclusive(src: Path, dst: Path) -> None:
    if src.is_symlink() or dst.is_symlink() or dst.exists():
        raise DeriveError("SOURCE_OR_DESTINATION_UNSAFE")
    if not dst.parent.is_dir():
        raise DeriveError("DESTINATION_PARENT_UNAVAILABLE")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(dst, flags, 0o600)
    try:
        with src.open("rb") as source, os.fdopen(fd, "wb", closefd=False) as target:
            for chunk in iter(lambda: source.read(2 * 1024 * 1024), b""):
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
    finally:
        os.close(fd)


def derive(src: Path, dst: Path) -> dict:
    # This also pins exact size, filename, SHA256 and regular-file identity
    # before a single byte can be created in the destination.
    source_proof = verify_file(src)
    if dst.name != DERIVED_NAME or dst.exists() or dst.is_symlink():
        raise DeriveError("DERIVED_PATH_MUST_BE_NEW_AND_EXACT_NAME")
    before_features = features(src)
    if "orphan_file" not in before_features:
        raise DeriveError("ORIGINAL_ORPHAN_FILE_FEATURE_NOT_PRESENT")
    completed = False
    try:
        copy_exclusive(src, dst)
        if dst.stat().st_size != IMAGE_BYTES or sha256(dst) != IMAGE_SHA256:
            raise DeriveError("COPIED_SOURCE_IDENTITY_MISMATCH")
        # This is the ONLY filesystem mutation. It targets the distinct
        # disposable local image copy, never the preserved source ext4.
        run("tune2fs", "-O", "^orphan_file", str(dst))
        after_features = features(dst)
        if "orphan_file" in after_features or "FEATURE_C12" in after_features:
            raise DeriveError("ORPHAN_FILE_STILL_SET")
        if after_features != before_features - {"orphan_file", "orphan_present"}:
            raise DeriveError("UNEXPECTED_FILESYSTEM_FEATURE_CHANGES")
        # Existing audited checker invokes read-only e2fsck -fn.
        legacy = check_legacy(dst)
        if legacy["status"] != "PASS_OFF_DEVICE_LEGACY_EXT4":
            raise DeriveError("LEGACY_VALIDATOR_UNEXPECTED_STATE")
        # Check source identity AGAIN after running tuning and e2fsck.
        if verify_file(src)["original_ext4_sha256"] != IMAGE_SHA256:
            raise DeriveError("SOURCE_IMAGE_CHANGED")
        derived_hash = sha256(dst)
        if derived_hash == IMAGE_SHA256 or dst.stat().st_size != IMAGE_BYTES:
            raise DeriveError("NO_VERIFIED_DISTINCT_DERIVATIVE")
        completed = True
        return {
            "schema": SCHEMA,
            "status": "OFF_DEVICE_DERIVED_EXT4_VALIDATED",
            "source_run": source_proof["source_workflow_run"],
            "source_sha256": IMAGE_SHA256,
            "source_bytes": IMAGE_BYTES,
            "source_original_unchanged": True,
            "derived_filename": DERIVED_NAME,
            "derived_bytes": dst.stat().st_size,
            "derived_sha256": derived_hash,
            "features_removed": sorted(before_features - after_features),
            "features_added": sorted(after_features - before_features),
            "orphan_file_absent": True,
            "modern_e2fsck_passed_readonly": True,
            "older_e2fsprogs_checked": False,
            "linux_4_9_mount_tested": False,
            "stock_r840x_recovery_verified": False,
            "watch_contacted": False,
            "bootloader_accepted_kernel": False,
            "flashable": False,
        }
    finally:
        # Never leave a failing derivative to be accidentally uploaded.
        if not completed:
            dst.unlink(missing_ok=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original", type=Path, required=True)
    p.add_argument("--derived", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    try:
        if args.report.exists() or args.report.is_symlink():
            raise DeriveError("REPORT_ALREADY_EXISTS")
        result = derive(args.original, args.derived)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(args.report, flags, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError, ValidationError) as e:
        print("NO_DERIVATIVE: " + str(e), file=sys.stderr)
        return 2
    print("OFF_DEVICE_DERIVED_EXT4_VALIDATED; original unchanged, NOT FLASHABLE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
