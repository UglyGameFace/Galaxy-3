#!/usr/bin/env python3
"""Privacy-filtered, offline comparison of two read-only Watch3 battery snapshots.

Snapshot collection is delegated to the existing authenticated, allowlisted
Termux/SDB client. This module performs no on-watch work on its own.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

_KEYS = {"NAME", "TYPE", "CAPACITY", "STATUS"}
_STATES = {"Charging", "Discharging", "Full", "Not charging", "Unknown"}
_SCHEMA = "uglyos-watch3-power-v1"


def _battery_records(raw: str) -> list[dict[str, str]]:
    """Parse concatenated Linux power_supply uevents without retaining raw data."""
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in raw[:65536].splitlines():
        if not line.startswith("POWER_SUPPLY_") or "=" not in line:
            continue
        key, value = line[len("POWER_SUPPLY_"):].split("=", 1)
        if key == "NAME":
            if current:
                records.append(current)
            current = {}
        if key in _KEYS and len(value) <= 80:
            current[key] = value
    if current:
        records.append(current)
    return [row for row in records if row.get("TYPE", "").lower() == "battery"]


def summarize_power(
    observations: dict[str, str], problems: dict[str, str],
    sampled_at: datetime | None = None,
) -> dict:
    now = sampled_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Power capture timestamp must contain a timezone")
    batteries = _battery_records(observations.get("battery_uevent", ""))
    report = {
        "schema": _SCHEMA,
        "status": "CAPACITY_UNAVAILABLE",
        "captured_at_utc": now.astimezone(timezone.utc).isoformat(),
        "runtime": "Tizen (expected; custom UgLy|OS not installed)",
        "expected_target": "Galaxy Watch3 SM-R840X",
        "capacity_percent": None,
        "charging_state": None,
        "probe_available": "battery_uevent" in observations and not problems,
        "privacy": "Raw sysfs, watch IP, serial, keys and identifiers not retained",
        "limits": "Read-only rounded capacity, NOT physical power or UgLy|OS drain proof",
    }
    # Do not silently pick a USB/charger device or an arbitrary one of
    # several batteries. Fail closed when the kernel layout is uncertain.
    if len(batteries) != 1:
        return report
    record = batteries[0]
    percent = record.get("CAPACITY", "")
    if not re.fullmatch(r"\d{1,3}", percent):
        return report
    amount = int(percent)
    if amount > 100:
        return report
    state = record.get("STATUS", "Unknown")
    if state not in _STATES:
        state = "Unknown"
    report.update(status="OBSERVED_TIZEN_BATTERY", capacity_percent=amount,
                  charging_state=state)
    return report


def _checked_snapshot(path: Path) -> tuple[dict, datetime]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise ValueError("Expected a small regular local battery JSON report")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != _SCHEMA:
        raise ValueError("Incompatible battery report schema")
    if data.get("status") != "OBSERVED_TIZEN_BATTERY":
        raise ValueError("Battery capacity was not observed in this report")
    level = data.get("capacity_percent")
    if type(level) is not int or not 0 <= level <= 100:
        raise ValueError("Battery percentage invalid")
    if data.get("charging_state") not in _STATES:
        raise ValueError("Battery charging state invalid")
    ts = datetime.fromisoformat(data["captured_at_utc"].replace("Z", "+00:00"))
    if ts.tzinfo is None:
        raise ValueError("Snapshot time has no timezone")
    return data, ts.astimezone(timezone.utc)


def compare_snapshots(start: Path, end: Path) -> dict:
    before, a = _checked_snapshot(start)
    after, b = _checked_snapshot(end)
    seconds = (b - a).total_seconds()
    if not 1800 <= seconds <= 72 * 3600:
        raise ValueError("Capture interval must be 30 minutes to 72 hours, in order")
    if before["charging_state"] != "Discharging" or after["charging_state"] != "Discharging":
        raise ValueError("Both snapshots must show Discharging; no charging-rate claims")
    drop = before["capacity_percent"] - after["capacity_percent"]
    if drop < 0:
        raise ValueError("Capacity increased; interval is not a clean discharge sample")
    hours = seconds / 3600
    return {
        "schema": "uglyos-watch3-power-interval-v1",
        "source": "Two read-only Tizen gauge snapshots, no intervening-state verification",
        "duration_hours": round(hours, 3),
        "drop_percentage_points": drop,
        "observed_pp_per_hour": round(drop / hours, 3) if drop else None,
        "result": ("COARSE_DISCHARGE_OBSERVATION" if drop else
                   "INSUFFICIENT_GAUGE_RESOLUTION"),
        "warning": ("Not a battery-life prediction, physical mAh measurement, "
                    "proof of uninterrupted discharge, or UgLy|OS/solo-mode result. "
                    "SDB/Wi-Fi collection itself changes power use."),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("START", "END"),
                        required=True, help="Two locally saved power-only reports")
    args = parser.parse_args()
    try:
        report = compare_snapshots(*args.compare)
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        # Do not echo private file contents or file locations.
        print("FAIL[power-compare]: " + type(exc).__name__ + ": invalid snapshots or interval",
              file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
