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
import socket
import sys

from watch3_r08_android_sdb import (
    PARTITION_SYSFS_PROBES, PARTITION_SYSFS_FIXED_PROBES,
    Connection, PORT, SdbError, collect, private_watch_ip,
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
    # The Linux kernel *optionally* exports PARTNAME when the partition
    # metadata contains a volume name. Missing PARTNAME != unknown name.
    if "PARTNAME" not in values:
        return number, "not_exported"
    label = values["PARTNAME"]
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
    name_field_count = sum(label != "not_exported" for label in found.values())
    return {
        "state": ("SYSFS_PARTITION_LABELS_OBSERVED" if name_field_count else
                  "SYSFS_PARTITION_METADATA_ONLY_NO_PARTNAME" if found else
                  "NO_VALID_SYSFS_PARTITION_RECORDS"),
        "reported_partition_count": len(found),
        "partname_field_count": name_field_count,
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


def inspect_fixed_sample(ip: str, key_path: Path) -> dict:
    """Three explicit sysfs files only; no shell wildcard or partition dump.

    A successful uevent read establishes at most *that file's* metadata,
    NOT the missing 18 entries nor a PIT/stock restoration.
    """
    result = _base_report()
    result["source_path_expression"] = list(PARTITION_SYSFS_FIXED_PROBES.values())
    result["probe_mode"] = "THREE_EXPLICIT_TEXT_PATHS_NO_WILDCARD"
    values, errors = collect(ip, key_path, probes=PARTITION_SYSFS_FIXED_PROBES)
    observations = []
    witnessed = 0
    name_fields = 0
    for key, expected in (("partition_p1_uevent", 1),
                          ("partition_p20_uevent", 20),
                          ("partition_p21_uevent", 21)):
        item = {"partition_index": expected, "status": "NOT_READ"}
        if key in errors:
            # These are fixed internal categories only; never raw shell text.
            code = errors[key]
            allowed = {
                "SDB_SHELL_TIMED_OUT", "SDB_SHELL_CLOSED_OR_REFUSED",
                "SDB_PROTOCOL_OR_READ_FAILURE", "SDB_TRANSPORT_UNREACHABLE",
                "SYSFS_EMPTY_SHELL_OUTPUT", "SYSFS_ACCESS_DENIED",
                "SYSFS_PATH_OR_COMMAND_NOT_FOUND",
            }
            item["status"] = code if code in allowed else "OTHER_UNAVAILABLE"
        elif key in values:
            try:
                parsed = parse_sysfs(values[key])
                fields = parsed["partition_name_records"]
                # Refuse unrelated device output or multiple records from a
                # command that should have opened ONE literal sysfs file.
                if len(fields) != 1 or fields[0]["index"] != expected:
                    item["status"] = "NO_MATCHING_SINGLE_SYSFS_RECORD"
                else:
                    item["status"] = ("PARTNAME_FIELD_OBSERVED" if
                                      parsed["partname_field_count"] else
                                      "UEVENT_READABLE_BUT_PARTNAME_ABSENT")
                    item["kernel_reported_label"] = fields[0]["kernel_reported_label"]
                    witnessed += 1
                    name_fields += parsed["partname_field_count"]
            except PartitionLabelsError:
                item["status"] = "MALFORMED_OR_CONFLICTING_SYSFS_RECORD"
        observations.append(item)
    result["probe_summary"] = {
        "tested_partition_indices": [1, 20, 21],
        "readable_uevent_files": witnessed,
        "partname_fields_observed": name_fields,
        "probes": observations,
        "remaining_partition_indices_not_tested": [
            i for i in range(1, EXPECTED_PARTITIONS + 1) if i not in (1, 20, 21)
        ],
        "full_partition_layout_proven": False,
    }
    result["owner_watch_sysfs_observed"] = witnessed > 0
    result["state"] = ("FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED" if name_fields else
                       "FIXED_SYSFS_UEVENT_READABLE_WITHOUT_NAMES" if witnessed else
                       "FIXED_SYSFS_NO_VALID_TEXT_OBSERVATIONS")
    return result


def inspect_sdb_connection_only(ip: str, key_path: Path) -> dict:
    """One port-26101 connect and authenticated SDB hello; NO shell or sysfs.

    This intentionally avoids repeating 3 sysfs probes when the user supplied
    a stale watch IP or SDB is not reachable. No raw socket exception, IP,
    tokens, serial numbers or untrusted SDB payload enter the result.
    """
    result = _base_report()
    result["probe_mode"] = "SINGLE_SDB_TCP_HANDSHAKE_NO_SHELL_OR_SYSFS"
    result["source_path_expression"] = []
    result["transport_diagnosis_only"] = True
    result["tcp_connected"] = False
    result["sdb_handshake_completed"] = False
    result["remote_device_identity_verified"] = False
    result["state"] = "CONNECT_NOT_ATTEMPTED"
    address = private_watch_ip(ip)
    try:
        with socket.create_connection((address, PORT), timeout=4) as sock:
            result["tcp_connected"] = True
            sock.settimeout(8)
            try:
                Connection(sock, key_path).handshake()
                result["sdb_handshake_completed"] = True
                result["state"] = "SDB_HANDSHAKE_COMPLETE_NO_SYSFS_READ"
            except (TimeoutError, socket.timeout):
                result["state"] = "SDB_HANDSHAKE_TIMED_OUT"
            except SdbError as exc:
                # Categorize locally without writing arbitrary SDB exception
                # text, which might reveal private file locations or tokens.
                detail = str(exc).lower()
                if any(term in detail for term in (
                    "authorization", "authentication", "private key",
                    "rsa", "crypto", "approve prompt"
                )):
                    result["state"] = "SDB_AUTHORIZATION_OR_LOCAL_KEY_UNAVAILABLE"
                else:
                    result["state"] = "SDB_HANDSHAKE_PROTOCOL_FAILED"
            except OSError:
                result["state"] = "SDB_HANDSHAKE_IO_FAILURE"
    except ConnectionRefusedError:
        result["state"] = "TCP_PORT_REFUSED"
    except (TimeoutError, socket.timeout):
        result["state"] = "TCP_CONNECT_TIMED_OUT"
    except OSError:
        result["state"] = "TCP_NETWORK_UNREACHABLE_OR_BLOCKED"
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
    parser.add_argument("--fixed-paths", action="store_true",
                        help="Use only three explicit sysfs text files: p1/p20/p21; no wildcard")
    parser.add_argument("--connection-only", action="store_true",
                        help="Single TCP/SDB handshake check, NO shell, sysfs or partition reads")
    parser.add_argument("--report", type=Path, default=None,
                        help="Private exclusive JSON output; use new name per observation")
    args = parser.parse_args(argv)
    try:
        if args.fixed_paths and args.offline_sample:
            raise PartitionLabelsError("FIXED_PATHS_AND_OFFLINE_SAMPLE_ARE_SEPARATE_MODES")
        if args.connection_only and (args.offline_sample or args.fixed_paths):
            raise PartitionLabelsError("CONNECTION_ONLY_IS_SEPARATE_FROM_SYSFS_MODES")
        path = (args.report or (Path.home() /
                ("watch3-r840x-sdb-connection-redacted.json" if args.connection_only
                 else "watch3-r840x-sysfs-fixed-three.json" if args.fixed_paths
                 else "watch3-r840x-sysfs-partition-names.json"))).expanduser()
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
        elif args.connection_only:
            result = inspect_sdb_connection_only(args.watch_ip, args.key_path.expanduser())
        else:
            result = (inspect_fixed_sample(args.watch_ip, args.key_path.expanduser())
                      if args.fixed_paths else
                      inspect_live(args.watch_ip, args.key_path.expanduser()))
        _private_write(path, result)
    except (PartitionLabelsError, SdbError, OSError, UnicodeError) as exc:
        reason = str(exc) if isinstance(exc, PartitionLabelsError) else "LOCAL_OR_AUTHENTICATED_SDB_ERROR"
        print("PARTITION_PROBE_ERROR: " + reason, file=sys.stderr)
        return 1
    print(("SDB_CONNECTION_RESULT: " if args.connection_only else
           "PARTITION_SYSFS_RESULT: ") + str(path))
    print(("SDB_CONNECTION_STATE: " if args.connection_only else
           "PARTITION_SYSFS_STATE: ") + result["state"])
    print("NO raw block bytes, PIT request, Odin session, firmware write or flash authorization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
