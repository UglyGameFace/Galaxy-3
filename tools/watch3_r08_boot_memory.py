#!/usr/bin/env python3
"""Read-only Watch3 R08 live Linux RAM map, not a bootloader unlock probe.

Treat vendor reference DTS as a *historical hypothesis*, not measured RAM.
Never save raw /proc/iomem, serial data, private kernel addresses, or other
hardware resources. Only exact System RAM ranges and MemTotal are reported.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone

MEM_RE = re.compile(r"^MemTotal:\s*([0-9]{1,12})\s+kB$")
REGION_RE = re.compile(r"^[ \t]*([0-9a-fA-F]{8,16})-([0-9a-fA-F]{8,16}) : System RAM$")
REF_BASE = 0x80000000
REF_LENGTH = 0x60000000  # 1.5 GiB from historical R08 board DTS
REF_INITRD_START = 0x84000000
REF_INITRD_END = 0x841FFFFF
MAX_TEXT = 64 * 1024
MAX_REGIONS = 24


def summarize_memory(values: dict[str, str], errors: dict[str, str],
                     now: datetime | None = None) -> dict[str, object]:
    when = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    report: dict[str, object] = {
        "schema": "uglyos-watch3-r08-boot-memory-v1",
        "source": "read-only Tizen /proc/meminfo and /proc/iomem",
        "captured_at_utc": when.isoformat(),
        "status": "LIVE_MEMORY_UNAVAILABLE",
        "memtotal_kib": None,
        "system_ram_ranges": [],
        "system_ram_bytes": None,
        "reference_dts_ram_window": "0x80000000..0xdfffffff",
        "reference_dts_initrd_window": "0x84000000..0x841fffff",
        "reference_dts_is_live_proof": False,
        "physical_ram_size_proven": False,
        "custom_boot_accepted": False,
        "recovery_proven": False,
        "firmware_changed": False,
    }
    if not isinstance(values, dict) or not isinstance(errors, dict):
        return report
    raw_mem = values.get("meminfo", "")
    if ("meminfo" not in errors and isinstance(raw_mem, str)
            and len(raw_mem) <= MAX_TEXT and raw_mem):
        lines = [m.group(1) for line in raw_mem.splitlines()
                 if (m := MEM_RE.fullmatch(line.strip()))]
        if len(lines) == 1:
            total = int(lines[0])
            if 65536 <= total <= 2 * 1024 * 1024:
                report["memtotal_kib"] = total
                report["status"] = "LIVE_MEMTOTAL_ONLY"
    raw_iomem = values.get("iomem", "")
    if "iomem" in errors or not isinstance(raw_iomem, str) or not raw_iomem or len(raw_iomem) > MAX_TEXT:
        return report
    regions: list[tuple[int, int]] = []
    for line in raw_iomem.splitlines():
        if "System RAM" not in line:
            continue
        match = REGION_RE.fullmatch(line)
        if not match:
            return report
        start, end = (int(match.group(i), 16) for i in (1, 2))
        if start == 0 or end <= start or end >= 1 << 48:
            return report
        regions.append((start, end))
        if len(regions) > MAX_REGIONS:
            return report
    if not regions:
        return report
    regions.sort()
    for i in range(1, len(regions)):
        if regions[i][0] <= regions[i - 1][1]:
            return report
    # Output only exact System RAM spans, excluding all other iomem lines.
    report["system_ram_ranges"] = [
        {"start": f"0x{start:x}", "end_inclusive": f"0x{end:x}"}
        for start, end in regions
    ]
    report["system_ram_bytes"] = sum(end - start + 1 for start, end in regions)
    report["status"] = "LIVE_RAM_REGIONS_OBSERVED"
    # /proc/meminfo counts usable OS memory, not all installed DRAM.
    # /proc/iomem may omit reserved RAM. Neither proves physical soldered capacity.
    return report
