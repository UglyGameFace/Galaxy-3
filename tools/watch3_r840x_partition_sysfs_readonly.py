#!/usr/bin/env python3
"""Read only kernel-exported Watch3 partition LABELS, never partition bytes.

Uses exactly one opt-in fixed Tizen SDB shell operation to read text
/sys/class/block/mmcblk0p[0-9]*/uevent. No PIT/Odin/raw-block access,
factory reset, firmware modification or write authorization.

This is a hypothesis: the shell glob and PARTNAME fields might not be
available to the owner's unprivileged SM-R840X Tizen shell.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

from watch3_r08_android_sdb import (
    PARTITION_SYSFS_PROBES, SdbError, collect,
)

SCHEMA = "uglyos-r840x-sysfs-partition-names-v1"
MAX_TEXT_BYTES = 16 * 1024
EXPECTED_PARTITIONS = 21
# Deliberately do NOT echo unknown/custom name strings from watch sysfs.
# Never emit PARTUUID, MAJOR/MINOR, device serial, phone/watch IP.
KNOWN_PARTITION_LABELS = frozenset({
    "boot", "recovery", "param", "kernel", "rootfs", "system",
    "userdata", "user", "data", "cache", "csc", "efs",
    "misc", "vbmeta", "dtb", "dtbo", "vendor", "ramdisk",
    "sboot", "tzsw", "steady", "module", "wd-reserved",
    "loader", "updater", "modem", "up_param", "persist",
})
NAME_RE = re.compile(r"mmcblk0p([1-9]|1[0-9]|2[01])\Z")
PARTNO_RE = re.compile(r"(?:[1-9]|1[0-9]|2[01])\Z")
LABEL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]{0,31}\Z")

class PartitionLabelsError(ValueError):
    """All errors are categorical; never pass raw sysfs text to caller."""


def _parse_one_block(lines: list[str]) -> tuple[int, str] | None:
    values = {}
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("DEVNAME", "PARTN", "PARTNAME"):
            if key in values:
                raise PartitionLabelsError("DUPLICATE_SYSFS_KEY")
            values[key] = value
    match = NAME_RE.fullmatch(values.get("DEVNAME", ""))
    if not match:
        return None
    number = int(match.group(1))
    if not PARTNO_RE.fullmatch(values.get("PARTN", "")) or int(values["PARTN"]) != number:
        raise PartitionLabelsError("PARTNUMBER_MISMATCH")
    label = values.get("PARTNAME", "")
    if not LABEL_RE.fullmatch(label):
        return number, "unclassified"
    return number, label.lower() if label.lower() in KNOWN_PARTITION_LABELS else "unclassified"


def parse_sysfs(raw: str) -> dict:
    """Parse multiple concatenated sysfs text records without leaking UUIDs."""
    if len(raw.encode("utf-8", errors="replace")) > MAX_TEXT_BYTES:
        raise PartitionLabelsError("SYSFS_TEXT_EXCEEDS_16_KIB")
    if "\x00" in raw:
        raise PartitionLabelsError("BINARY_OR_NUL_SYSFS_RESPONSE")
    # uevent normally begins with MAJOR= and also contains DEVNAME=.
    # Each new MAJOR marks another regular text pseudo-file.
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in raw.splitlines():
        if len(line) > 300:
            raise PartitionLabelsError("UNBOUNDED_SYSFS_LINE")
        if line.startswith("MAJOR=") and current:
            blocks.append(current)
            current = []
        current.append(line)
        if len(blocks) > EXPECTED_PARTITIONS:
            raise PartitionLabelsError("TOO_MANY_SYSFS_RECORDS")
    if current:
        blocks.append(current)
    if len(blocks) > EXPECTED_PARTITIONS:
        raise PartitionLabelsError("TOO_MANY_SYSFS_RECORDS")
    found: dict[int, str] = {}
    for lines in blocks:
        entry = _parse_one_block(lines)
        if entry is None:
            continue
        index, label = entry
        if index in found:
            raise PartitionLabelsError("DUPLICATE_PARTITION_RECORD")
        found[index] = label
    return {
        "state": ("SYSFS_PARTITION_LABELS_OBSERVED" if found
                  else "NO_VALID_SYSFS_PARTITION_RECORDS"),
        "reported_partition_count": len(found),
        "all_21_numbered_partitions_observed": len(found) == EXPECTED_PARTITIONS,
        "missing_partition_indices": sorted(set(range(1, EXPECTED_PARTITIONS + 1)) - set(found)),
        "partition_name_records": [
            {"index": i, "kernel_reported_label": found[i]}
            for i in sorted(found)
        ],
        "unknown_or_unrecognized_labels_count": sum(
            x == "unclassified" for x in found.values()
        ),
    }


def _base_report() -> dict:
    return {
        "schema": SCHEMA,
        "device_target": "SM-R840X",
        "installed_build_recorded": "R840XXXU1AUA2",
        "active_csc_recorded": "PAP",
        "state": "NOT_ATTEMPTED",
        "owner_watch_sysfs_observed": False,
        "report": None,
        "source_path_expression": PARTITION_SYSFS_PROBES["partitions_uevent"],
        "note": ("Linux uevent PARTNAME is kernel-supplied metadata, NOT "
                 "a verified Samsung PIT, firmware image, actual physical "
                 "data backup, accepted custom boot or restore mechanism."),
        "raw_partition_bytes_read": False,
        "pit_requested": False,
        "odin_session_started": False,
        "watch_write_performed": False,
        "stock_recovery_proven": False,
        "bootloader_acceptance_proven": False,
        "flash_allowed": False,
        "result": "NO_GO",
    }


def inspect_live(ip: str, key_path: Path) -> dict:
    result = _base_report()
    values, errors = collect(ip, key_path, probes=PARTITION_SYSFS_PROBES)
    if errors or "partitions_uevent" not in values:
        result["state"] = "SYSFS_READ_UNAVAILABLE_OR_UNSUPPORTED_GLOB"
        return result
    try:
        parsed = parse_sysfs(values["partitions_uevent"])
    except PartitionLabelsError as exc:
        result["state"] = str(exc)
        return result
    result["state"] = parsed["state"]
    result["report"] = parsed
    result["owner_watch_sysfs_observed"] = parsed["reported_partition_count"] > 0
    return result


def _private_write(path: Path, body: dict) -> None:
    if not path.parent.is_dir():
        raise PartitionLabelsError("REPORT_DIRECTORY_MISSING")
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as writer:
            json.dump(body, writer, indent=2)
            writer.write("\n")
            writer.flush()
            os.fsync(writer.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--watch-ip", help="Current private IP shown by the watch in normal Tizen")
    mode.add_argument("--offline-sample", type=Path, help="Synthetic local text only, no watch")
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--report", type=Path,
                        default=Path.home() / "watch3-r840x-sysfs-partition-names.json")
    args = parser.parse_args(argv)
    try:
        path = args.report.expanduser()
        # Avoid even the optional networked read when local evidence exists.
        if path.exists() or path.is_symlink():
            raise PartitionLabelsError("REPORT_ALREADY_EXISTS")
        if not path.parent.is_dir():
            raise PartitionLabelsError("REPORT_DIRECTORY_MISSING")
        if args.offline_sample:
            source = args.offline_sample.expanduser()
            if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_TEXT_BYTES:
                raise PartitionLabelsError("LOCAL_SAMPLE_UNSAFE_OR_OVERSIZED")
            raw = source.read_text(encoding="utf-8")
            result = _base_report()
            result["report"] = parse_sysfs(raw)
            result["state"] = "OFFLINE_SAMPLE_ONLY_NOT_A_REAL_WATCH_OBSERVATION"
        else:
            result = inspect_live(args.watch_ip, args.key_path.expanduser())
        _private_write(path, result)
    except (PartitionLabelsError, SdbError, OSError, UnicodeError) as exc:
        reason = str(exc) if isinstance(exc, PartitionLabelsError) else "LOCAL_OR_AUTHENTICATED_SDB_ERROR"
        print("PARTITION_PROBE_ERROR: " + reason, file=sys.stderr)
        return 1
    print("PARTITION_SYSFS_RESULT: " + str(path))
    print("PARTITION_SYSFS_STATE: " + result["state"])
    print("NO raw block bytes, PIT request, Odin session, firmware write or flash authorization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
