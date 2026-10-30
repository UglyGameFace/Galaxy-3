#!/usr/bin/env python3
"""Try standard Tizen SDB root mode and verify access on the owner's Watch3.

One native root:on request at most. Fresh authenticated UID/EUID reads decide
whether root is available. If verified, back up the known boot/recovery
partitions after fresh label/geometry checks and copy the recovery scripts
and observed OMA-DM unit. No payload, service activation, reboot, SDB SEND
or firmware write. Backup copies do not prove restoration or custom boot.
The root-mode request itself asks the daemon to change account mode.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import zipfile

from watch3_r08_android_sdb import Connection, PORT, SdbError, private_watch_ip
from watch3_r08_fota_handoff_pull import (
    EVIDENCED_RECOVERY_SCRIPT_PATH, EVIDENCED_UPDATE_PREPARE_SCRIPT_PATH,
    HandoffError, _receive_bounded_file, private_write,
)
from watch3_r840x_critical_sysfs_geometry import _sector

REPORT_NAME = "native-root-report.json"
FILES = {
    "recovery-update.sh": EVIDENCED_RECOVERY_SCRIPT_PATH,
    "rw-update-prepare.sh": EVIDENCED_UPDATE_PREPARE_SCRIPT_PATH,
    # The owner's receiver LIST observed this exact 453-byte unit; RECV failed.
    "oma-dm-agent.service": b"/usr/lib/systemd/system/oma-dm-agent.service",
}
MAX_FILE_BYTES = 64 * 1024
# The owner's prior sysfs observations, never Samsung PIT or flash offsets.
# Used only to verify which two block devices may be opened for RECV backup.
PARTITIONS = ((13, "boot", 169984, 36864), (14, "recovery", 206848, 36864))
PARTITION_PROBES = frozenset(
    key for index, _label, _start, _size in PARTITIONS
    for key in (f"partition_p{index}_uevent", f"critical_p{index}_start", f"critical_p{index}_size"))


class NativeRootError(ValueError):
    """Categorical diagnostics only; never serialize arbitrary watch output."""


def parse_uid(value: str) -> int | None:
    if isinstance(value, str) and re.fullmatch(r"(?:0|[1-9][0-9]{0,9})\r?\n?", value):
        number = int(value)
        return number if number <= 0xffffffff else None
    return None


def parse_status(value: str) -> dict:
    if not isinstance(value, str) or len(value) > 64 * 1024:
        return {}
    result = {}
    for field, name in (("Uid", "uids"), ("Gid", "gids")):
        lines = [line for line in value.splitlines() if line.startswith(field + ":")]
        if len(lines) == 1:
            match = re.fullmatch(field + r":\s+([0-9]{1,10})\s+([0-9]{1,10})\s+"
                                 r"([0-9]{1,10})\s+([0-9]{1,10})\s*", lines[0])
            if match and all(int(v) <= 0xffffffff for v in match.groups()):
                result[name] = [int(v) for v in match.groups()]
    lines = [line for line in value.splitlines() if line.startswith("CapEff:")]
    if len(lines) == 1:
        match = re.fullmatch(r"CapEff:\s+([0-9a-fA-F]{1,16})\s*", lines[0])
        if match:
            result["effective_capabilities_hex"] = match[1].lower()
    return result


def parse_capabilities(value: str) -> dict:
    """Keep root flags only, never device names, DUIDs or SDK paths."""
    if not isinstance(value, str) or len(value) > 64 * 1024:
        return {}
    fields = {}
    for key in ("sdbd_rootperm", "rootonoff_support"):
        matches = re.findall(r"(?m)^" + key + r":[ \t]*(enabled|disabled)[ \t]*\r?$", value)
        if len(matches) == 1:
            fields[key] = matches[0]
    return fields


def query(ip: str, key: Path, operation: str, *, style="standard", timeout=8) -> str:
    """One connection per request, including every identity readback."""
    if operation not in {"model", "native_root_uid", "native_root_status", "capabilities", "root_on", *PARTITION_PROBES}:
        raise NativeRootError("OPERATION_NOT_ALLOWLISTED")
    with socket.create_connection((ip, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        channel = Connection(sock, key)
        channel.handshake()
        if operation == "capabilities":
            return channel.capabilities()
        if operation == "root_on":
            return channel.enable_native_root()
        return channel.shell(operation, style=style)


def identity(ip: str, key: Path, *, timeout=8) -> dict:
    observed = {"uid": None, "status": {}, "root_verified": False}
    for style in ("standard", "tizen-command"):
        try:
            uid = parse_uid(query(ip, key, "native_root_uid", style=style, timeout=timeout))
            status = parse_status(query(ip, key, "native_root_status", style=style, timeout=timeout))
        except (OSError, SdbError):
            continue
        if uid is not None and "uids" in status:
            observed.update(uid=uid, status=status, shell_style=style,
                            root_verified=uid == 0 and status["uids"][1] == 0)
            return observed
    return observed


def partition_backup(ip: str, key: Path, folder: Path, report: dict, saved: list, *, timeout=8):
    """Only known p13/p14, matched to fresh exact labels and sector geometry."""
    style = report["after"]["shell_style"]
    for index, label, prior_start, prior_size in PARTITIONS:
        item = {"role": label, "remote_path": f"/dev/mmcblk0p{index}"}
        report["partition_copies"].append(item)
        try:
            uevent = query(ip, key, f"partition_p{index}_uevent", style=style, timeout=timeout)
            start = _sector(query(ip, key, f"critical_p{index}_start", style=style, timeout=timeout))
            size = _sector(query(ip, key, f"critical_p{index}_size", style=style, timeout=timeout))
            devnames = re.findall(r"(?m)^DEVNAME=([^\r\n]+)\r?$", uevent)
            labels = re.findall(r"(?m)^PARTNAME=([^\r\n]+)\r?$", uevent)
            if (devnames != [f"mmcblk0p{index}"] or labels != [label] or
                    start != prior_start or size != prior_size):
                raise HandoffError("PARTITION_METADATA_UNAVAILABLE_OR_MISMATCHED")
            item["current_kernel_metadata_matches_prior"] = True
            byte_count = size * 512
            report["partition_reads_attempted"] = True
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                raw = _receive_bounded_file(sock, key, item["remote_path"].encode("ascii"), byte_count)
            if len(raw) != byte_count:
                raise HandoffError("PARTITION_COPY_SIZE_MISMATCH")
            name = label + "-original.bin"
            private_write(folder / name, raw)
            saved.append(name)
            item.update(status="COPIED", local_file=name, bytes=len(raw),
                        sha256=hashlib.sha256(raw).hexdigest())
        except HandoffError as exc:
            item["status"] = str(exc)
        except (OSError, SdbError):
            item["status"] = "LOCAL_OR_SDB_IO_ERROR"
    report["partition_backup_complete"] = all(r["status"] == "COPIED" for r in report["partition_copies"])


def capture(ip: str, key: Path, folder: Path, *, archive: Path | None = None,
            timeout=8, progress=None, backup_images=True) -> dict:
    ip = private_watch_ip(ip)
    folder = folder.expanduser()
    archive = archive.expanduser() if archive is not None else None
    if archive is not None and (archive.exists() or archive.is_symlink()):
        raise NativeRootError("LOCAL_ARCHIVE_ALREADY_EXISTS")
    if not folder.parent.is_dir() or archive is not None and not archive.parent.is_dir():
        raise NativeRootError("LOCAL_PARENT_DIRECTORY_MISSING")
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        raise NativeRootError("LOCAL_OUTPUT_ALREADY_EXISTS") from None
    report = {
        "schema": "uglyos-r840x-native-sdb-root-v1",
        "state": "NOT_ATTEMPTED", "target_board_matched": False,
        "device_identity_cryptographically_attested": False,
        "advertised_root_capabilities": {},
        "before": None, "after": None, "root_mode_attempted": False,
        "root_mode_reply": None, "root_observed": False, "root_obtained": False,
        "account_mode_change_requested": False, "root_mode_persistence_verified": False,
        "files": [], "firmware_write_requested": False,
        "partition_backup_requested": backup_images, "partition_reads_attempted": False,
        "partition_backup_complete": False, "partition_copies": [],
        "service_activation_requested": False, "acquired_file_executed": False,
        "firmware_helper_executed": False,
        "bootloader_unlock_proven": False, "stock_recovery_proven": False,
        "custom_boot_proven": False,
    }
    saved = []
    try:
        if progress:
            progress("Checking the connected watch model")
        model = None
        for style in ("standard", "tizen-command"):
            try:
                value = query(ip, key, "model", style=style, timeout=timeout)
            except (OSError, SdbError):
                continue
            value = value.replace("\x00", "").strip()
            if re.fullmatch(r"NOBLESSE-LARGE-BT(?:\s+R08)?", value):
                model = True
                break
            if value and len(value) <= 100 and re.fullmatch(r"[A-Za-z0-9 ._-]+", value):
                model = False
        if model is not True:
            raise NativeRootError("TARGET_BOARD_MISMATCH" if model is False else "TARGET_BOARD_UNAVAILABLE")
        report["target_board_matched"] = True
        try:
            report["advertised_root_capabilities"] = parse_capabilities(
                query(ip, key, "capabilities", timeout=timeout))
        except (OSError, SdbError):
            pass
        report["before"] = identity(ip, key, timeout=timeout)
        if report["before"]["root_verified"]:
            report["after"] = report["before"]
            report["root_mode_reply"] = "ALREADY_ROOT_NO_SWITCH_REQUESTED"
        else:
            if progress:
                progress("Requesting Tizen's standard root mode once")
            report.update(root_mode_attempted=True, account_mode_change_requested=True)
            try:
                reply = query(ip, key, "root_on", timeout=timeout)
                report["root_mode_reply"] = ("WATCH_REPORTED_DENIAL" if
                    any(s in reply.lower() for s in ("permission denied", "access denied"))
                    else "REPLY_RECEIVED_REQUIRES_UID_VERIFICATION")
            except (OSError, SdbError):
                # Daemon restart/stream refusal is not success or a known denial.
                report["root_mode_reply"] = "SERVICE_UNAVAILABLE_OR_CONNECTION_CLOSED"
            if progress:
                progress("Verifying UID and effective UID on fresh authenticated connections")
            report["after"] = identity(ip, key, timeout=timeout)
        report["root_observed"] = report["after"]["root_verified"]
        report["root_obtained"] = report["root_observed"] and not report["before"]["root_verified"]
        if not report["root_observed"]:
            after = report["after"]
            if after["uid"] is None:
                raise NativeRootError("ROOT_IDENTITY_UNAVAILABLE")
            if after["uid"] == 0 or after["status"]["uids"][1] == 0:
                raise NativeRootError("ROOT_IDENTITY_INCONSISTENT")
            raise NativeRootError("NATIVE_ROOT_NOT_GRANTED")
        if progress:
            progress("Root identity verified")
        if backup_images:
            if progress:
                progress("Checking known boot/recovery labels and geometry, then reading backups")
            partition_backup(ip, key, folder, report, saved, timeout=timeout)
        if progress:
            progress("Copying recovery scripts for offline review")
        for name, path in FILES.items():
            item = {"remote_path": path.decode("ascii")}
            report["files"].append(item)
            try:
                with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    raw = _receive_bounded_file(sock, key, path, MAX_FILE_BYTES)
                if not raw:
                    raise HandoffError("REMOTE_RECOVERY_INPUT_EMPTY")
                private_write(folder / name, raw)
                saved.append(name)
                item.update(status="COPIED", local_file=name, bytes=len(raw),
                            sha256=hashlib.sha256(raw).hexdigest())
            except HandoffError as exc:
                item["status"] = str(exc)
            except (OSError, SdbError):
                item["status"] = "LOCAL_OR_SDB_IO_ERROR"
        complete = (all(item["status"] == "COPIED" for item in report["files"]) and
                    (not backup_images or report["partition_backup_complete"]))
        report["state"] = ("ROOT_VERIFIED_RECOVERY_INPUTS_COPIED" if complete
                           else "ROOT_VERIFIED_RECOVERY_INPUTS_PARTIAL")
    except NativeRootError as exc:
        report["state"] = str(exc)
    except (OSError, SdbError):
        report["state"] = "SDB_UNAVAILABLE"
    private_write(folder / REPORT_NAME, (json.dumps(report, indent=2) + "\n").encode())
    if archive is not None:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as bundle:
                    for name in [REPORT_NAME, *saved]:
                        bundle.write(folder / name, name)
                target.flush()
                os.fsync(target.fileno())
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    parser.add_argument("--key-path", type=Path, default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--output-dir", type=Path, default=Path.home() / "watch3-r840x-native-root-evidence")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    try:
        report = capture(args.watch_ip, args.key_path, args.output_dir, archive=args.archive,
                         progress=lambda message: print(message, flush=True))
    except (NativeRootError, OSError, SdbError) as exc:
        print("NATIVE_ROOT_ERROR: " + (str(exc) if isinstance(exc, NativeRootError)
                                     else "LOCAL_OR_SDB_IO_ERROR"), file=sys.stderr)
        return 1
    print("NATIVE_ROOT_STATE: " + report["state"])
    print("NATIVE_ROOT_REPORT: " + str(args.output_dir.expanduser() / REPORT_NAME))
    if args.archive:
        print("NATIVE_ROOT_ARCHIVE: " + str(args.archive.expanduser()))
    return 0 if report["root_observed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
