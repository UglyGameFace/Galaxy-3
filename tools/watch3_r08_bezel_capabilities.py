#!/usr/bin/env python3
"""Privacy-filtered capability check for Watch3's Tizen bezel input device.

Parses the *read-only* text registry /proc/bus/input/devices. Does not open
/dev/input/event*, record movement, claim Qt delivery, or alter firmware.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re

# Linux input-event bit definitions, not a Tizen binary decoder.
EV_REL = 2
REL_X = 0
REL_WHEEL = 8
MAX_SOURCE = 64 * 1024


def _bits(value: str) -> int | None:
    """Linux /proc input registry prints hex words separated by spaces."""
    if not value or len(value) > 256 or not re.fullmatch(r"[0-9A-Fa-f]+(?:\s+[0-9A-Fa-f]+)*", value):
        return None
    try:
        return int("".join(value.split()), 16)
    except ValueError:
        return None


def summarize_bezel(observations: dict[str, str], problems: dict[str, str],
                    now: datetime | None = None) -> dict[str, object]:
    t = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    report: dict[str, object] = {
        "schema": "uglyos-watch3-bezel-capabilities-v1",
        "source": "read-only Tizen /proc/bus/input/devices; not an event capture",
        "captured_at_utc": t.isoformat(),
        "status": "BEZEL_CAPABILITY_UNAVAILABLE",
        "input_name": None,
        "event_handler": None,
        "ev_rel_supported": None,
        "rel_wheel_supported": None,
        "rel_x_supported": None,
        "live_rotation_observed": False,
        "qt_wheel_delivery_observed": False,
        "firmware_changed": False,
    }
    if problems or set(observations) != {"input_devices"}:
        return report
    raw = observations.get("input_devices")
    if not isinstance(raw, str) or not raw or len(raw) > MAX_SOURCE:
        return report
    matches: list[tuple[str, dict[str, str]]] = []
    for block in re.split(r"\r?\n\s*\r?\n", raw):
        entries: dict[str, str] = {}
        name_count = 0
        for line in block.splitlines():
            if line.startswith("N: Name="):
                name_count += 1
                name = re.fullmatch(r'N: Name="([^"\r\n]{1,64})"', line.strip())
                if name:
                    entries["name"] = name.group(1)
            elif line.startswith("H: Handlers="):
                if "handlers" in entries:
                    entries["invalid"] = "duplicate"
                entries["handlers"] = line.removeprefix("H: Handlers=").strip()
            elif line.startswith("B: EV=") or line.startswith("B: REL="):
                key = "ev" if line.startswith("B: EV=") else "rel"
                if key in entries:
                    entries["invalid"] = "duplicate"
                entries[key] = line.split("=", 1)[1].strip()
        if entries.get("name") == "tizen_detent" or name_count > 1 and entries.get("name") == "tizen_detent":
            matches.append((block, entries))
    # Reject duplicate drivers, ambiguous handler names, missing/invalid bitmaps
    # and error-prefixed shell output instead of guessing from event18 alone.
    if len(matches) != 1:
        return report
    block, entry = matches[0]
    if entry.get("invalid") or block.count('N: Name=') != 1:
        return report
    handlers = entry.get("handlers", "")
    names = re.findall(r"(?<!\S)event([0-9]{1,4})(?!\S)", handlers)
    if len(names) != 1 or len(set(names)) != 1:
        return report
    ev = _bits(entry.get("ev", ""))
    rel = _bits(entry.get("rel", ""))
    if ev is None or rel is None or (ev & (1 << EV_REL)) == 0:
        return report
    # Expose only the exact recognized name, event handler token and three
    # booleans. No device serial, IDs, Phys, other input devices or keymaps.
    report.update({
        "status": ("BEZEL_REL_WHEEL_ADVERTISED"
                   if rel & (1 << REL_WHEEL) else "BEZEL_WHEEL_NOT_ADVERTISED"),
        "input_name": "tizen_detent",
        "event_handler": "event" + names[0],
        "ev_rel_supported": True,
        "rel_wheel_supported": bool(rel & (1 << REL_WHEEL)),
        "rel_x_supported": bool(rel & (1 << REL_X)),
    })
    return report
