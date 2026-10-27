#!/usr/bin/env python3
"""Validate the original, completed 2026-10-24 R840X offline ext4 before preserving it.

Host-side ONLY. No SDB, firmware flashing, filesystem mount, image rewrite
or BitBake. Production CLI pins the actual build's exact name, byte length
and independently re-audited SHA-256. The original artifact is untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SOURCE_RUN = 40095182440
SOURCE_ARTIFACT = "galaxy3-r08-OFFLINE-NOT-FLASHABLE-image-40095182440"
SOURCE_STAGE_ARTIFACT = "galaxy3-r08-build-stage-40095182440"
IMAGE_FILENAME = "asteroid-image-noblesse-r08.rootfs-20261024125252.ext4"
IMAGE_BYTES = 755658752
IMAGE_SHA256 = "8358d60f213c7acf8857a7a9795e7de9a35acbc70d6d3743b72299dfe8a3ed72"
SOURCE_ARCHIVE_EXPIRES_UTC = "2026-10-31T13:01:30Z"
SCHEMA = "uglyos-r840x-preserve-original-offline-image-v1"


class PreservationError(ValueError):
    """A categorical validation error without user file contents."""


def verify_file(path: Path, *, name: str = IMAGE_FILENAME,
                expected_size: int = IMAGE_BYTES,
                expected_hash: str = IMAGE_SHA256) -> dict:
    if path.name != name or path.is_symlink():
        raise PreservationError("UNEXPECTED_IMAGE_NAME_OR_SYMLINK")
    try:
        info = path.stat()
    except OSError:
        raise PreservationError("IMAGE_FILE_UNAVAILABLE") from None
    if not stat.S_ISREG(info.st_mode):
        raise PreservationError("NOT_A_REGULAR_IMAGE_FILE")
    if info.st_size != expected_size:
        raise PreservationError("ORIGINAL_IMAGE_LENGTH_MISMATCH")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            part = stream.read(2 * 1024 * 1024)
            if not part:
                break
            digest.update(part)
    if digest.hexdigest() != expected_hash:
        raise PreservationError("ORIGINAL_IMAGE_SHA256_MISMATCH")
    return {
        "schema": SCHEMA,
        "result": "ORIGINAL_OFFLINE_IMAGE_BYTES_VERIFIED",
        "source_workflow_run": SOURCE_RUN,
        "source_artifact": SOURCE_ARTIFACT,
        "source_stage_artifact": SOURCE_STAGE_ARTIFACT,
        "source_artifact_original_expires_utc": SOURCE_ARCHIVE_EXPIRES_UTC,
        "original_image_filename": name,
        "original_ext4_size_bytes": info.st_size,
        "original_ext4_sha256": digest.hexdigest(),
        "original_unmodified": True,
        "flashable": False,
        "boot_proven": False,
        "stock_restore_proven": False,
        "watch_contacted": False,
        "watch_write_performed": False,
        "note": (
            "Resaving an already built offline ext4 is a retention operation, "
            "not an update package, bootloader validation or permission to flash."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    image = args.image_dir / IMAGE_FILENAME
    report_path = args.output
    try:
        result = verify_file(image)
        if not report_path.parent.is_dir():
            raise PreservationError("REPORT_PARENT_NOT_FOUND")
        payload = (json.dumps(result, indent=2) + "\n").encode()
        fd = os.open(str(report_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            report_path.unlink(missing_ok=True)
            raise
    except (PreservationError, OSError) as exc:
        msg = str(exc) if isinstance(exc, PreservationError) else "HOST_IO_FAILURE"
        print("PRESERVATION_BLOCKED: " + msg, file=sys.stderr)
        return 1
    print("ORIGINAL_OFFLINE_IMAGE_VERIFIED_FOR_RETENTION")
    print("NO image rebuild, mounts, remote watch access or firmware writes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
