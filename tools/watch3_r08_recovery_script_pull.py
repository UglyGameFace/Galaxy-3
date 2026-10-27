#!/usr/bin/env python3
"""Read exactly the recovery script named by the owner's actual R840X unit.

This uses our existing authenticated SDB sync:RECV implementation, not a
Termux sdb executable. The script is NEVER run, displayed, or uploaded.
One fixed read; the only outputs are private host-local files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

from watch3_r08_android_sdb import PORT, SdbError, private_watch_ip
from watch3_r08_fota_handoff_pull import (
    EVIDENCED_RECOVERY_SCRIPT_PATH,
    HandoffError,
    receive_one,
)

SCHEMA = "uglyos-r840x-recovery-script-readonly-v1"
RAW_NAME = "recovery-update.sh"
REPORT_NAME = "recovery-script-report.json"


def read_fixed_script(ip: str, key_path: Path, timeout: int = 12) -> bytes:
    validated_ip = private_watch_ip(ip)
    try:
        with socket.create_connection((validated_ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return receive_one(sock, key_path, EVIDENCED_RECOVERY_SCRIPT_PATH)
    except (OSError, SdbError, TimeoutError):
        raise HandoffError("SDB_UNAVAILABLE") from None


def report_for(raw: bytes) -> dict:
    return {
        "schema": SCHEMA,
        "status": "RECOVERY_SCRIPT_READ_ONLY_RETRIEVED",
        "remote_path": "/usr/bin/recovery-update.sh",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "has_shell_shebang": raw.startswith((b"#!/bin/sh", b"#!/bin/bash",
                                              b"#!/usr/bin/env sh",
                                              b"#!/usr/bin/env bash")),
        "meaning": (
            "Script bytes saved privately for OFFLINE inspection only; "
            "no execution, firmware installation or safe rescue proven."
        ),
        "watch_write_performed": False,
        "script_executed": False,
        "stock_recovery_proven": False,
        "unsigned_boot_proven": False,
    }


def private_write(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--output-dir", type=Path,
                        default=Path.home() / "watch3-r840x-recovery-script-evidence")
    args = parser.parse_args()
    folder = args.output_dir.expanduser()
    raw_path = folder / RAW_NAME
    summary_path = folder / REPORT_NAME
    try:
        if not folder.parent.is_dir():
            raise HandoffError("LOCAL_PARENT_DIRECTORY_MISSING")
        os.mkdir(folder, 0o700)
        raw = read_fixed_script(args.watch_ip, args.key_path)
        private_write(raw_path, raw)
        try:
            private_write(summary_path, (json.dumps(report_for(raw), indent=2) + "\n").encode("utf-8"))
        except BaseException:
            raw_path.unlink(missing_ok=True)
            raise
    except (HandoffError, OSError, SdbError) as exc:
        reason = str(exc) if isinstance(exc, HandoffError) else "LOCAL_OR_NETWORK_ERROR"
        print("RECOVERY_SCRIPT_ERROR: " + reason, file=sys.stderr)
        return 1
    print("READ_ONLY_RECOVERY_SCRIPT: " + str(raw_path))
    print("REPORT: " + str(summary_path))
    print("NO script execution, SDB SEND, shell, FOTA call, or watch write attempted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
