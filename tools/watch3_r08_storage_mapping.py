#!/usr/bin/env python3
"""Privacy-filtered Watch3 R08 live storage topology, NEVER firmware access.

Consume only read-only pseudo-file output collected by the fixed Samsung SDB
allowlist. Does not access raw block data, issue ioctl, mount, backup, unlock,
change permissions or claim that a partition is safe to overwrite.
"""
from __future__ import annotations

import re

from watch3_r08_live_boot_probe import STORAGE_PROBES

_DEVICE = re.compile(r"^(?:mmcblk0p(?:[1-9]|1\d|2[01])|dm-\d+)$")
_SYS_PART = re.compile(r"^mmcblk0p(?:20|21)$")
_LABEL = re.compile(r"^[A-Za-z][A-Za-z0-9_.+-]{0,63}$")
# Only report a few mountpoints materially relevant to storage provenance.
_MOUNTS = {"/", "/system", "/opt", "/opt/usr", "/usr", "/data"}
_FS = {"ext4", "squashfs", "f2fs", "overlay", "rootfs", "tmpfs", "vfat"}
# Avoid exposing arbitrary shell output or device identifiers in JSON.
_KNOWN_ROLES = {"system", "rootfs", "userdata", "user", "data", "opt",
                "recovery", "boot", "ramdisk", "param", "kernel", "dtb",
                "dtbo", "vendor", "vbmeta"}


def _slaves(raw: str) -> list[str]:
    """Only exact eMMC partition or dm-N basenames, never arbitrary ls data."""
    candidates = raw.strip().split()
    if len(candidates) > 32:
        return []
    return sorted({x for x in candidates if _DEVICE.fullmatch(x)})


def _partition_role(raw: str) -> str:
    for line in raw.splitlines():
        if line.startswith("PARTNAME="):
            value = line.partition("=")[2].strip()
            if _LABEL.fullmatch(value) and value.lower() in _KNOWN_ROLES:
                return value.lower()
            return "unclassified"
    return "not exposed"


def _device(source: str) -> str:
    if source in ("rootfs", "tmpfs", "overlay", "none"):
        return source
    # No custom labels/UUID, network paths, or sensitive mount sources.
    if source.startswith("/dev/"):
        last = source.rsplit("/", 1)[-1]
        if _DEVICE.fullmatch(last):
            return last
    return "redacted/other"


def _mounts(raw: str) -> list[dict[str, str]]:
    collected: list[dict[str, str]] = []
    for line in raw.splitlines():
        cols = line.split()
        if len(cols) < 4 or cols[1] not in _MOUNTS or cols[2] not in _FS:
            continue
        options = cols[3].split(",")
        mode = "ro" if "ro" in options else ("rw" if "rw" in options else "unspecified")
        candidate = {"target": cols[1], "source": _device(cols[0]),
                     "filesystem": cols[2], "mount_mode": mode}
        if candidate not in collected:
            collected.append(candidate)
        if len(collected) >= 24:
            break
    return sorted(collected, key=lambda x: (x["target"], x["source"]))


def summarize_storage(data: dict[str, str], problems: dict[str, str]) -> dict:
    slaves_observed = bool(data.get("dm0_slaves", "").strip())
    slaves = _slaves(data.get("dm0_slaves", ""))
    mounts = _mounts(data.get("mounts", ""))
    result = {
        "status": "READ_ONLY_TIZEN_STORAGE_TOPOLOGY",
        "target_expected": "Galaxy Watch3 SM-R840X / R08",
        "dm0_slaves": slaves,
        "dm0_backing_verified": bool(slaves_observed and slaves),
        "dm0_backing_mmcp20_observed": "mmcblk0p20" in slaves,
        "selected_mounted_filesystems": mounts,
        "selected_partition_role_labels": {
            "mmcblk0p20": _partition_role(data.get("p20_uevent", "")),
            "mmcblk0p21": _partition_role(data.get("p21_uevent", "")),
        },
        "dm0_label": _partition_role(
            "PARTNAME=" + data.get("dm0_name", "").strip()
            if data.get("dm0_name", "").strip() else ""),
        "unavailable_readonly_properties": {
            name: problems[name] for name in STORAGE_PROBES if name in problems
        },
        "no_raw_mounts_cmdline_uuid_or_serial_stored": True,
        "boot_partition_identified": False,
        "signed_boot_acceptance_proven": False,
        "stock_recovery_proven": False,
        "flashing_authorized": False,
        "interpretation": (
            "Sysfs dependency and selected mount records can establish the "
            "actual dm-0 block-device backing when readable. They do not "
            "identify Samsung boot/recovery layout or permit any device writes."
        ),
    }
    return result
