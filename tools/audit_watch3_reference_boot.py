#!/usr/bin/env python3
"""Read-only reference source audit for Galaxy Watch3 SM-R840X R08.

Inputs are historical Samsung Exynos 9110 reference source, NOT extracted
stock firmware. The report describes candidate boot requirements, NEVER
custom-boot acceptance, signing keys, current partition layout or recovery.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


KEYS = ("CONFIG_ARM64", "CONFIG_KEXEC", "CONFIG_BLK_DEV_INITRD",
        "CONFIG_EXT4_FS", "CONFIG_DM_VERITY", "CONFIG_DEVTMPFS")
SOURCE_COMMIT = "ec258e12887d37362b59e3291c1d3e5363c24bff"
EXPECTED_MODEL = "NOBLESSE-LARGE-BT"
EXPECTED_BOARD_ID = ("0x00009110", "8", "0")


def parse_configs(base: str, overlays: list[str]) -> dict:
    """Track explicit Kconfig lines; do not masquerade as a built .config."""
    result = {}
    history = {}
    for origin, content in [("base", base)] + [
        (f"fragment_{i}", x) for i, x in enumerate(overlays)
    ]:
        for line in content.splitlines():
            positive = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.+)", line)
            negative = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
            if positive:
                key, value = positive.groups()
            elif negative:
                key, value = negative.group(1), "n"
            else:
                continue
            if key in KEYS:
                result[key] = value
                history.setdefault(key, []).append(
                    {"source": origin, "value": value})
    return {"resolved_explicit_values": result, "change_history": history}


def quoted_property(text: str, name: str) -> str:
    match = re.search(r"\b" + re.escape(name) + r'\s*=\s*"([^"]+)"\s*;', text)
    if not match:
        raise ValueError(f"Historical DTS property missing: {name}")
    return match.group(1)


def address_property(text: str, name: str) -> str:
    match = re.search(
        r"\b" + re.escape(name) + r"\s*=\s*<\s*(0x[0-9a-fA-F]+)\s*>\s*;",
        text)
    if not match:
        raise ValueError(f"Historical DTS address missing: {name}")
    return match.group(1)


def audit(base: str, overlays: list[str], dt: str, dtsi: str) -> dict:
    if quoted_property(dt, "model") != EXPECTED_MODEL:
        raise ValueError("R08 model mismatch")
    board = re.search(
        r"samsung,exynos-id\s*=\s*<\s*(0x[0-9a-fA-F]+)\s+"
        r"(\d+)\s+(\d+)\s*>\s*;", dt)
    if not board or board.groups() != EXPECTED_BOARD_ID:
        raise ValueError("R08 Exynos identifier mismatch or missing")
    if 'exynos9110-tizen_noblesse_large_bt-r08.dtsi' not in dt:
        raise ValueError("R08 board DTS does not include expected reference board source")
    config = parse_configs(base, overlays)
    opts = config["resolved_explicit_values"]
    expected = {
        "CONFIG_ARM64": "y", "CONFIG_KEXEC": "n",
        "CONFIG_BLK_DEV_INITRD": "y", "CONFIG_EXT4_FS": "y",
        "CONFIG_DM_VERITY": "y", "CONFIG_DEVTMPFS": "y",
    }
    changes = {k: {"expected": v, "reference": opts.get(k)} for k, v in
               expected.items() if opts.get(k) != v}
    if changes:
        raise ValueError(f"Reference config flags differ: {changes}")
    bootargs = quoted_property(dtsi, "bootargs")
    params = dict(pair.split("=", 1) for pair in bootargs.split(" ")
                  if "=" in pair)
    if params.get("root") != "/dev/ram0":
        raise ValueError("Reference /chosen/bootargs does not select ramdisk root")
    initrd_start = int(address_property(dtsi, "linux,initrd-start"), 16)
    initrd_end = int(address_property(dtsi, "linux,initrd-end"), 16)
    if initrd_start <= 0 or initrd_end <= initrd_start:
        raise ValueError("Reference DTS initrd address range invalid")
    memory = re.search(
        r"memory@80000000\s*{\s*device_type\s*=\s*\"memory\";\s*"
        r"reg\s*=\s*<\s*0x0\s+(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s*>\s*;", dtsi)
    if not memory:
        raise ValueError("Reference DTS RAM region not found; do not infer addresses")
    ram_start, ram_size = (int(x, 16) for x in memory.groups())
    if not (ram_start <= initrd_start < initrd_end < ram_start + ram_size):
        raise ValueError("Reference DTS initrd addresses outside declared memory")
    return {
        "status": "PASS_HISTORICAL_SOURCE_AUDIT",
        "source_repo": "UsrBinLuna/kernel_samsung_galileo",
        "source_commit": SOURCE_COMMIT,
        "board_model": EXPECTED_MODEL,
        "exynos_id": list(EXPECTED_BOARD_ID),
        "reference_kconfig": opts,
        "reference_kconfig_overlay_history": config["change_history"],
        "reference_chosen_root": params["root"],
        "reference_console": params.get("console", "unknown"),
        "reference_initrd_start": hex(initrd_start),
        "reference_initrd_end": hex(initrd_end),
        "reference_ram_start": hex(ram_start),
        "reference_ram_size_bytes": ram_size,
        "findings": [
            "Historical reference source has KEXEC disabled in base and both fragments",
            "Historical DT expects initramfs root=/dev/ram0",
            "Historical reference supports initrd, ext4, dm-verity and ARM64",
        ],
        "not_verified": [
            "ACTUAL deployed kernel config or /proc/cmdline",
            "ACTUAL R840X bootloader signatures and custom kernel acceptance",
            "ACTUAL stock boot partition sizes and by-name mapping",
            "STOCK firmware backup, restoration route or non-destructive first boot",
        ],
        "bootable": False,
        "flashable": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--large", type=Path, required=True)
    parser.add_argument("--brcm", type=Path, required=True)
    parser.add_argument("--dts", type=Path, required=True)
    parser.add_argument("--dtsi", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(
            args.base.read_text(), [args.large.read_text(), args.brcm.read_text()],
            args.dts.read_text(), args.dtsi.read_text())
    except (OSError, ValueError) as error:
        result = {"status": "FAIL", "reason": str(error), "flashable": False}
        code = 1
    else:
        code = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if code:
        print(f"FAIL[R08-boot-ref]: {result['reason']}", file=sys.stderr)
    else:
        print("PASS[R08-boot-ref]: historical board and initramfs config audited.")
        print("NOT VERIFIED: deployed firmware boot chain, stock recovery or "
              "unsigned boot. NOT FLASHABLE.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
