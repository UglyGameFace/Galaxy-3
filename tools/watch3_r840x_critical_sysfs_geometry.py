#!/usr/bin/env python3
"""Read seven EXACT Linux sysfs scalar pseudo-files from an authorized R840X.

This is opt-in normal-Tizen SDB shell 'cat' only: p10(param), p13(boot),
p14(recovery) partition start/size plus whole mmcblk0 sector count.
It does NOT read any raw block contents, PIT, device secrets, bootloader,
NetOdin or firmware. It cannot establish a restorable Samsung partition map.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

from watch3_r08_android_sdb import CRITICAL_GEOMETRY_PROBES, SdbError, collect

SCHEMA = "uglyos-r840x-critical-sysfs-sector-geometry-v1"
TARGET = "SM-R840X"
FIRMWARE = "R840XXXU1AUA2"
CSC = "PAP"
INDEX_LABELS = ((10, "param"), (13, "boot"), (14, "recovery"))
MAX_SECTORS = 10**15
SECTOR_RE = re.compile(r"(?:0|[1-9][0-9]{0,14})\Z")
# Numbers are Linux sector units, NOT independently verified Samsung PIT.
SECTOR_UNIT = "KERNEL_EXPORTED_512_BYTE_SECTOR_UNITS_NOT_SAMSUNG_PIT"

class GeometryError(ValueError):
    """Private-free categorical local input/report error."""


def _sector(raw) -> int | None:
    """Accept one strict bounded unsigned sysfs number only, no injected text."""
    if not isinstance(raw, str) or len(raw) > 40:
        return None
    value = raw.removesuffix("\n").removesuffix("\r")
    if not SECTOR_RE.fullmatch(value):
        return None
    result = int(value)
    return result if result < MAX_SECTORS else None


def summarize(values: dict[str, str], errors: dict[str, str] | None = None,
              *, owner_watch: bool = False) -> dict:
    """Parse a preconfigured collector response, not a raw partition device.

    Use start/size only as KERNEL REPORTED geometric candidates. Never
    authenticate PIT, partition images, signed recovery or boot acceptance.
    """
    if not isinstance(values, dict) or not isinstance(errors, dict | type(None)):
        raise GeometryError("INTERNAL_COLLECTOR_RESULT_INVALID")
    errors = {} if errors is None else errors
    if set(values) - set(CRITICAL_GEOMETRY_PROBES) or set(errors) - set(CRITICAL_GEOMETRY_PROBES):
        raise GeometryError("UNEXPECTED_COLLECTOR_PATH")
    disk = _sector(values.get("critical_disk_sectors"))
    if disk == 0:
        disk = None
    entries = []
    for index, label in INDEX_LABELS:
        start_key = f"critical_p{index}_start"
        size_key = f"critical_p{index}_size"
        start = _sector(values.get(start_key))
        count = _sector(values.get(size_key))
        if start is None or count is None or count == 0:
            state = ("REPORTED_FIELD_UNAVAILABLE" if
                     (start_key in errors or size_key in errors or
                      start_key not in values or size_key not in values)
                     else "MALFORMED_NUMERIC_SYSFS_FIELD")
            entry = {"index": index, "label_from_prior_sysfs_merge": label,
                     "state": state, "start_sector": None,
                     "sector_count": None, "end_exclusive_sector": None}
        else:
            upper = start + count
            if upper > MAX_SECTORS or disk is not None and upper > disk:
                state = "INCONSISTENT_WITH_DISK_BOUNDARY"
            else:
                state = ("KERNEL_NUMERIC_FIELDS_OBSERVED" if disk is not None
                         else "KERNEL_FIELDS_BUT_DISK_CAPACITY_UNKNOWN")
            entry = {"index": index, "label_from_prior_sysfs_merge": label,
                     "state": state, "start_sector": start,
                     "sector_count": count, "end_exclusive_sector": upper}
        entries.append(entry)

    complete = disk is not None and all(
        entry["state"] == "KERNEL_NUMERIC_FIELDS_OBSERVED" for entry in entries)
    overlap = False
    if complete:
        ordered = sorted(entries, key=lambda e: e["start_sector"])
        overlap = any(a["end_exclusive_sector"] > b["start_sector"]
                      for a, b in zip(ordered, ordered[1:]))
        if overlap:
            complete = False
    return {
        "schema": SCHEMA,
        "model_recorded": TARGET,
        "installed_build_recorded": FIRMWARE,
        "active_csc_previously_observed": CSC,
        "source_mode": ("PHYSICAL_SDB_FIXED_SYSFS_SCALAR_PROBE"
                        if owner_watch else "OFFLINE_OR_SYNTHETIC_ONLY"),
        "state": ("THREE_CRITICAL_KERNEL_SECTOR_RANGES_OBSERVED" if complete
                  else "INCONSISTENT_OR_OVERLAPPING_KERNEL_SECTOR_FIELDS" if overlap
                  else "PARTIAL_OR_UNAVAILABLE_KERNEL_SECTOR_FIELDS"),
        "source_paths_fixed_no_raw_partition_devices": list(CRITICAL_GEOMETRY_PROBES.values()),
        "reported_disk_sector_count": disk,
        "sector_units": SECTOR_UNIT,
        "critical_partition_name_provenance": "OWNER_21_SYSFS_PARTNAME_TEXT_MERGE_NOT_SAMSUNG_PIT",
        "partition_scalar_observations": entries,
        "nonoverlap_in_reported_three_candidates": not overlap if complete else None,
        "watch_contacted_by_this_probe": owner_watch,
        "kernel_sector_ranges_observed": bool(complete and owner_watch),
        "all_21_partition_geometry_established": False,
        "kernel_geometry_equivalent_to_signed_samsung_pit": False,
        "authentic_samsung_pit_obtained": False,
        "partition_contents_read": False,
        "signed_stock_images_obtained": False,
        "stock_recovery_proven": False,
        "custom_boot_accepted": False,
        "odin_session_started": False,
        "firmware_written": False,
        "flash_allowed": False,
        "result": "NO_GO",
        "interpretation": ("Only seven text-valued Linux sysfs readouts on three "
                           "previously label-identified partitions and mmcblk0. "
                           "They neither authenticate a PIT nor supply backup bytes. "
                           "Never use these values to calculate a flash command."),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--watch-ip", required=True,
                    help="Current private Wi-Fi IP shown by the watch in normal Tizen")
    ap.add_argument("--key-path", type=Path,
                    default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    ap.add_argument("--output", type=Path,
                    default=Path.home() / "watch3-r840x-critical-geometry-redacted.json")
    args = ap.parse_args(argv)
    path = args.output.expanduser()
    try:
        # Preserve earlier evidence and skip watch contact on accidental reruns.
        if path.exists() or path.is_symlink():
            raise GeometryError("REPORT_ALREADY_EXISTS")
        if not path.parent.is_dir():
            raise GeometryError("REPORT_PARENT_MISSING")
        values, errors = collect(args.watch_ip, args.key_path.expanduser(),
                                 probes=CRITICAL_GEOMETRY_PROBES)
        report = summarize(values, errors, owner_watch=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=2)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    except (GeometryError, SdbError, OSError, UnicodeError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, GeometryError) else "LOCAL_OR_AUTHENTICATED_SDB_ERROR"
        print("CRITICAL_GEOMETRY_ERROR: " + reason, file=sys.stderr)
        return 1
    print("CRITICAL_GEOMETRY_RESULT: " + str(path))
    print("GEOMETRY_STATE: " + report["state"])
    print("NO raw block bytes, Odin, PIT request, stock recovery or flash authorization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
