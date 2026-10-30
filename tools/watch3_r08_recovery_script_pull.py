#!/usr/bin/env python3
"""Read one fixed recovery script evidenced by an original R840X artifact.

Default: authenticated SDB sync:RECV for one fixed file. Explicit
--shell-context: fixed cat reads plus permissions/capability/unit metadata.
Recovered scripts are never executed or displayed. Outputs stay private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import zipfile

from watch3_r08_android_sdb import Connection, PORT, SdbError, private_watch_ip, RECOVERY_CONTEXT_READS
from watch3_r08_fota_handoff_pull import (
    EVIDENCED_RECOVERY_SCRIPT_PATH,
    EVIDENCED_UPDATE_PREPARE_SCRIPT_PATH,
    HandoffError,
    receive_one,
)

SCHEMA = "uglyos-r840x-recovery-script-readonly-v1"
RAW_NAME = "recovery-update.sh"
REPORT_NAME = "recovery-script-report.json"
COMPONENTS = {"recovery-update": EVIDENCED_RECOVERY_SCRIPT_PATH,
              "update-prepare": EVIDENCED_UPDATE_PREPARE_SCRIPT_PATH}
CONTEXT_REPORT = "recovery-shell-report.json"


def read_fixed_script(ip: str, key_path: Path, timeout: int = 12, *, component="recovery-update") -> bytes:
    if component not in COMPONENTS:
        raise HandoffError("SCRIPT_COMPONENT_NOT_ALLOWLISTED")
    validated_ip = private_watch_ip(ip)
    try:
        with socket.create_connection((validated_ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return receive_one(sock, key_path, COMPONENTS[component])
    except (OSError, SdbError, TimeoutError):
        raise HandoffError("SDB_UNAVAILABLE") from None


def report_for(raw: bytes, component="recovery-update") -> dict:
    if component not in COMPONENTS:
        raise HandoffError("SCRIPT_COMPONENT_NOT_ALLOWLISTED")
    prepare = component == "update-prepare"
    return {
        "schema": "uglyos-r840x-update-prepare-script-readonly-v1" if prepare else SCHEMA,
        "status": "UPDATE_PREPARE_SCRIPT_READ_ONLY_RETRIEVED" if prepare else "RECOVERY_SCRIPT_READ_ONLY_RETRIEVED",
        "remote_path": COMPONENTS[component].decode("ascii"),
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


def capture_shell_context(ip: str, key: Path, folder: Path, *, archive: Path | None = None,
                          timeout=8, progress=None) -> dict:
    """Read the missing recovery inputs through the proven ordinary shell.

    This explicitly changes transport from the failed RECV attempts; it does
    not retry native root. A payload hash describes SDB shell output, not an
    independently authenticated on-disk file hash. Raw diagnostics stay private.
    """
    ip = private_watch_ip(ip)
    folder = folder.expanduser()
    archive = archive.expanduser() if archive is not None else None
    if archive is not None and (archive.exists() or archive.is_symlink()):
        raise HandoffError("LOCAL_ARCHIVE_ALREADY_EXISTS")
    if not folder.parent.is_dir() or archive is not None and not archive.parent.is_dir():
        raise HandoffError("LOCAL_PARENT_DIRECTORY_MISSING")
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        raise HandoffError("LOCAL_OUTPUT_ALREADY_EXISTS") from None
    report = {
        "schema": "uglyos-r840x-recovery-shell-context-v1", "state": "NOT_CAPTURED",
        "transport": "AUTHENTICATED_SDB_STANDARD_SHELL_FIXED_READS",
        "payload_hashes_are_independent_disk_hashes": False,
        "on_disk_file_completeness_verified": False,
        "files": [], "script_payloads_copied": 0,
        "root_mode_requested": False, "root_obtained": False,
        "recovery_script_executed": False, "service_activation_requested": False,
        "firmware_written": False, "partition_reads_attempted": False,
        "bootloader_unlock_proven": False, "stock_recovery_proven": False,
    }
    saved = []
    for entry, command in RECOVERY_CONTEXT_READS.items():
        item = {"entry": entry, "read_operation": command}
        report["files"].append(item)
        if progress:
            progress(entry)
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                channel = Connection(sock, key)
                channel.handshake()
                raw = channel.recovery_context_read(entry)
            if entry.endswith(".sh"):
                plausible = raw.startswith((b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env sh", b"#!/usr/bin/env bash"))
                status = "SCRIPT_PAYLOAD_COPIED" if plausible else "RESPONSE_NOT_VERIFIED_AS_SCRIPT"
                if plausible:
                    report["script_payloads_copied"] += 1
            elif entry.endswith(".service"):
                plausible = b"[Service]" in raw and b"\x00" not in raw
                status = "UNIT_PAYLOAD_COPIED" if plausible else "RESPONSE_NOT_VERIFIED_AS_UNIT"
            else:
                plausible = True
                status = "METADATA_RESPONSE_CAPTURED"
            local = entry if plausible else entry + ".response"
            private_write(folder / local, raw)
            saved.append(local)
            item.update(status=status, local_file=local, bytes=len(raw),
                        payload_sha256=hashlib.sha256(raw).hexdigest())
        except (OSError, SdbError):
            item["status"] = "SHELL_READ_REFUSED_OR_IO_ERROR"
    report["state"] = ("RECOVERY_SCRIPTS_CAPTURED_VIA_SHELL" if report["script_payloads_copied"] == 3
                       else "RECOVERY_SHELL_CONTEXT_PARTIAL")
    private_write(folder / CONTEXT_REPORT, (json.dumps(report, indent=2) + "\n").encode())
    if archive is not None:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
                    for name in [CONTEXT_REPORT, *saved]:
                        z.write(folder / name, name)
                target.flush()
                os.fsync(target.fileno())
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--component", choices=tuple(COMPONENTS), default="recovery-update")
    mode.add_argument("--shell-context", action="store_true",
                      help="Read three recovery scripts and fixed privilege metadata through the ordinary shell")
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--archive", type=Path, help="Private diagnostic ZIP for --shell-context")
    args = parser.parse_args(argv)
    if args.shell_context:
        folder = args.output_dir or Path.home() / "watch3-r840x-recovery-shell-evidence"
        try:
            report = capture_shell_context(args.watch_ip, args.key_path, folder, archive=args.archive,
                                           progress=lambda entry: print("Reading " + entry, flush=True))
        except (HandoffError, OSError, SdbError) as exc:
            print("RECOVERY_CONTEXT_ERROR: " + (str(exc) if isinstance(exc, HandoffError)
                                              else "LOCAL_OR_SDB_IO_ERROR"), file=sys.stderr)
            return 1
        print("RECOVERY_CONTEXT_STATE: " + report["state"])
        print("RECOVERY_CONTEXT_REPORT: " + str(folder.expanduser() / CONTEXT_REPORT))
        if args.archive:
            print("RECOVERY_CONTEXT_ARCHIVE: " + str(args.archive.expanduser()))
        return 0 if report["script_payloads_copied"] == 3 else 1
    if args.archive is not None:
        parser.error("--archive requires --shell-context")
    prepare = args.component == "update-prepare"
    if args.output_dir is None:
        args.output_dir = Path.home() / ("watch3-r840x-update-prepare-evidence" if prepare
                                       else "watch3-r840x-recovery-script-evidence")
    folder = args.output_dir.expanduser()
    raw_path = folder / ("rw-update-prepare.sh" if prepare else RAW_NAME)
    summary_path = folder / ("update-prepare-report.json" if prepare else REPORT_NAME)
    try:
        if not folder.parent.is_dir():
            raise HandoffError("LOCAL_PARENT_DIRECTORY_MISSING")
        os.mkdir(folder, 0o700)
        raw = read_fixed_script(args.watch_ip, args.key_path, component=args.component)
        private_write(raw_path, raw)
        try:
            private_write(summary_path, (json.dumps(report_for(raw, args.component), indent=2) + "\n").encode("utf-8"))
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
