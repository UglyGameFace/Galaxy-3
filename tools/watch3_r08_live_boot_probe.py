#!/usr/bin/env python3
"""Compare *actual* Tizen boot facts with historical Samsung R08 reference.

Two modes: (1) use an already installed/authorized SDB CLI on the same Wi-Fi
as the watch, only issuing a fixed set of read-only commands; or (2) parse
previously captured local text files, entirely offline.

NO root, shell escalation, reboot, downloads, device writes, PIT access,
partition reads, flashing, or changes to bootloader. This is not an installer.
Never upload unredacted source captures to a public GitHub repository.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


# ONLY these literal commands can be run on the watch. No user-supplied
# shell text, no substitution, and no arbitrary remote command argument.
PROBES = {
    "cmdline": "cat /proc/cmdline",
    "version": "cat /proc/version",
    "partitions": "cat /proc/partitions",
    "model": "cat /proc/device-tree/model",
    "bootargs": "cat /proc/device-tree/chosen/bootargs",
    "block_links": "ls -l /dev/block/by-name",
    "disk_links": "ls -l /dev/disk/by-name",
}
# Optional next-phase storage topology observation after a successful live-boot
# report. Exact fixed Linux pseudo-file operations ONLY. No block-device data
# reads, dmsetup, root, mounting, repartitioning or bootloader access.
STORAGE_PROBES = {
    "mounts": "cat /proc/mounts",
    "dm0_slaves": "ls /sys/block/dm-0/slaves",
    "dm0_name": "cat /sys/block/dm-0/dm/name",
    "p20_uevent": "cat /sys/class/block/mmcblk0p20/uevent",
    "p21_uevent": "cat /sys/class/block/mmcblk0p21/uevent",
}
ESSENTIAL = ("cmdline", "version", "partitions")
PUBLIC_FIELDS = ("root", "console", "init", "rootfstype", "rootflags")
EXPECTED_MODEL = "NOBLESSE-LARGE-BT"
DEVICE_NAME = re.compile(r"^[a-zA-Z0-9_.:+-]{1,80}$")
PART_NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,80}$")


def _run(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, text=True, errors="replace", capture_output=True,
        stdin=subprocess.DEVNULL, timeout=timeout, check=False,
    )


def available_devices(binary: str) -> list[str]:
    try:
        proc = _run([binary, "devices"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(
            "No usable SDB client available. ADB is not SDB. "
            "Use --from-dir if you already collected the read-only files."
        ) from exc
    if proc.returncode:
        raise ValueError("SDB failed to list authorized Tizen devices")
    devices: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if (len(parts) >= 2 and parts[1] == "device"
                and DEVICE_NAME.fullmatch(parts[0])):
            devices.append(parts[0])
    return devices


def collect(binary: str, target: str | None) -> tuple[dict[str, str], dict[str, str]]:
    devices = available_devices(binary)
    if target is None:
        if len(devices) != 1:
            raise ValueError(
                f"Expected exactly one authorized Tizen SDB device; found "
                f"{len(devices)}. Connect and approve the watch first."
            )
        target = devices[0]
    elif target not in devices:
        raise ValueError("The selected SDB target is not an authorized connected device")

    data: dict[str, str] = {}
    problems: dict[str, str] = {}
    for name, fixed_shell_command in PROBES.items():
        try:
            proc = _run([binary, "-s", target, "shell", fixed_shell_command])
        except (OSError, subprocess.TimeoutExpired):
            problems[name] = "SDB command unavailable"
            continue
        if proc.returncode:
            problems[name] = "Access denied or path missing"
            continue
        payload = proc.stdout[:65536]
        if not payload.strip() or re.search(
                r"(permission denied|no such file|not found|access denied)",
                payload, re.IGNORECASE):
            problems[name] = "Access denied or path missing"
            continue
        data[name] = payload
    return data, problems


def from_dir(directory: Path) -> tuple[dict[str, str], dict[str, str]]:
    if not directory.is_dir():
        raise ValueError("Local capture directory not found")
    values = {}
    problems = {}
    for name in PROBES:
        source = directory / (name + ".txt")
        if not source.exists():
            problems[name] = "Not supplied"
            continue
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"Unsafe capture file: {name}")
        if source.stat().st_size > 65536:
            raise ValueError(f"Capture file too large: {name}")
        values[name] = source.read_text(encoding="utf-8", errors="replace")
    return values, problems


def _parameters(raw: str) -> dict[str, str]:
    result = {}
    for part in raw.replace("\x00", " ").split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key in PUBLIC_FIELDS and len(value) <= 120:
            # Public report only includes a narrow allowlist. Prevent
            # masquerading control codes and non-boot metadata.
            if re.fullmatch(r"[\w./,:+=-]+", value, re.ASCII):
                result[key] = value
    return result


def _partitions(raw: str) -> dict:
    entries = []
    for line in raw.splitlines():
        parts = line.split()
        if (len(parts) != 4 or not all(x.isdecimal() for x in parts[:3])
                or not PART_NAME.fullmatch(parts[3])):
            continue
        major, minor, kib, name = parts
        entries.append({
            "name": name, "major": int(major), "minor": int(minor),
            "blocks_1k": int(kib),
        })
        if len(entries) == 128:
            break
    return {"observed_count": len(entries), "block_devices": entries}


def _symlinks(raw: str) -> list[dict]:
    links = []
    for line in raw.splitlines():
        if " -> " not in line:
            continue
        left, right = line.rsplit(" -> ", 1)
        parts = left.split()
        if not parts or not left.startswith("l"):
            continue
        name = parts[-1]
        leaf = right.split("/")[-1]
        if PART_NAME.fullmatch(name) and PART_NAME.fullmatch(leaf):
            links.append({"partition_label": name, "target_device": leaf})
        if len(links) == 128:
            break
    return links


def summarize(data: dict[str, str], problems: dict[str, str]) -> dict:
    missing = [k for k in ESSENTIAL if not data.get(k, "").strip()]
    if missing:
        raise ValueError(
            "Cannot compare actual boot without cmdline, version and partitions: "
            + ", ".join(missing)
        )
    version_match = re.search(r"\bLinux version ([^\s]+)", data["version"])
    running_version = version_match.group(1) if version_match else "unavailable"
    actual_cmdline = _parameters(data["cmdline"])
    dts_bootargs = _parameters(data.get("bootargs", ""))
    observed_model = data.get("model", "").replace("\x00", "").strip()
    if observed_model and len(observed_model) > 100:
        observed_model = "unavailable"
    if observed_model and not re.fullmatch(r"[\w .:-]+", observed_model, re.ASCII):
        observed_model = "unavailable"

    link_map = _symlinks(data.get("block_links", "") + "\n"
                         + data.get("disk_links", ""))
    # Only expose a short, model-specific allowlist of boot-related names.
    boot_labels = {"boot", "recovery", "param", "dtb", "dtbo", "kernel",
                   "ramdisk", "rootfs", "system", "vendor", "vbmeta", "efs"}
    boot_links = sorted(
        (item for item in link_map if item["partition_label"].lower() in boot_labels),
        key=lambda item: (item["partition_label"], item["target_device"]))
    unique = []
    seen = set()
    for item in boot_links:
        key = (item["partition_label"], item["target_device"])
        if key not in seen:
            unique.append(item)
            seen.add(key)
    state = {
        "runtime_kernel_version": running_version,
        "historical_kernel_version": "4.9.59",
        "reference_root": "/dev/ram0",
        "runtime_root": actual_cmdline.get("root", "not provided"),
        "runtime_console": actual_cmdline.get("console", "not provided"),
        "runtime_init": actual_cmdline.get("init", "not provided"),
        "live_device_tree_root": dts_bootargs.get("root", "unavailable"),
        "device_tree_model": observed_model or "unavailable",
        "model_matches_reference": (
            observed_model == EXPECTED_MODEL if observed_model else None),
        "root_matches_historical_dts": (
            actual_cmdline["root"] == "/dev/ram0"
            if "root" in actual_cmdline else None),
        "runtime_kernel_matches_historical": running_version == "4.9.59",
        "partitions": _partitions(data["partitions"]),
        "boot_related_partition_links": unique,
        "read_only_probe_limitations": {
            name: problems[name] for name in PROBES if name in problems
        },
    }
    return {
        "status": "READ_ONLY_TIZEN_RUNTIME_OBSERVATION",
        "target_hardware_expected": "SM-R840X / NOBLESSE-LARGE-BT R08",
        "facts": state,
        "no_raw_private_kernel_arguments_stored": True,
        "bootloader_acceptance_proven": False,
        "stock_recovery_proven": False,
        "flashing_authorized": False,
        "interpretation": (
            "Actual boot chain and signed kernel acceptance are NOT proven by "
            "procfs metadata. Partition symlinks are labels, not permission "
            "to read or write partitions. Mismatches require investigation."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--collect-sdb", action="store_true")
    mode.add_argument("--from-dir", type=Path)
    parser.add_argument("--sdb", default="sdb", help="Existing authorized SDB CLI")
    parser.add_argument("--target", help="SDB target from devices list; never a network scan")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        values, errors = (
            collect(args.sdb, args.target) if args.collect_sdb
            else from_dir(args.from_dir)
        )
        report = summarize(values, errors)
    except ValueError as error:
        # Never embed raw stdout/stderr or submitted command line in an error.
        print(f"FAIL[read-only-boot]: {error}", file=sys.stderr)
        return 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: generated filtered actual R08 Tizen boot comparison.")
    print("Report is local only. No raw /proc/cmdline, serial, network or "
          "SDB output is saved in the report.")
    print("NOT PROVEN: unsigned boot, stock recovery or safe flashing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
