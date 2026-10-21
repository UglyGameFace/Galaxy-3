#!/usr/bin/env python3
"""Read-only R08 ABOX firmware source audit and local inventory.

Only downloads PUBLIC PINNED TEXT SOURCE. NEVER downloads, uploads,
modifies, redistributes, installs, or validates the authenticity of firmware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "meta-noblesse/conf/watch3-r08-abox-firmware.json"
BASE = "https://raw.githubusercontent.com/UsrBinLuna/kernel_samsung_galileo/"
EXPECTED_SHA = "ec258e12887d37362b59e3291c1d3e5363c24bff"
ABOX_C = "sound/soc/samsung/abox/abox.c"
EXYNOS_DTSI = "arch/arm64/boot/dts/exynos/exynos9110.dtsi"
R08_DTSI = "arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dtsi"


def fetch_source(revision: str, path: str) -> str:
    url = BASE + revision + "/" + path
    req = urllib.request.Request(url, headers={"User-Agent": "Galaxy3-R08-ABOX-audit"})
    with urllib.request.urlopen(req, timeout=35) as res:
        return res.read().decode("utf-8")


def extra_nodes(source: str) -> dict:
    nodes = {}
    for match in re.finditer(r"ext_bin_\d+:\s*ext_bin@(\d+)\s*\{([^{}]*)\};", source, re.S):
        index, body = match.groups()
        name = re.search(r'samsung,name\s*=\s*"([^"]+)";', body)
        status = re.search(r'status\s*=\s*"([^"]+)";', body)
        area = re.search(r"samsung,area\s*=\s*<(\d+)>;", body)
        offset = re.search(r"samsung,offset\s*=\s*<(0x[0-9a-fA-F]+)>;", body)
        if not name or not status:
            raise ValueError(f"Unparseable ext_bin@{index} firmware node")
        nodes[name.group(1)] = {
            "dt_node": "ext_bin@" + index,
            "dt_status": status.group(1),
            "dt_area": int(area.group(1)) if area else None,
            "dt_offset": offset.group(1) if offset else None,
        }
    return nodes


def verify_source(manifest: dict) -> bool:
    revision = manifest["reference_commit"]
    if revision != EXPECTED_SHA:
        raise ValueError("Pinned source revision changed; requires a fresh hardware audit")
    sources = {path: fetch_source(revision, path) for path in (ABOX_C, EXYNOS_DTSI, R08_DTSI)}
    abox, dt, board = sources[ABOX_C], sources[EXYNOS_DTSI], sources[R08_DTSI]
    nodes = extra_nodes(dt)
    expected_enabled = {x["name"] for x in manifest["files"] if x["role"] == "enabled_auxiliary"}
    source_enabled = {n for n, v in nodes.items() if v["dt_status"] in ("okay", "ok")}
    tests = {
        "R08 includes the audited Exynos9110 base device tree": '#include "exynos9110.dtsi"' in board,
        "R08 does not override these extra-firmware nodes": not bool(re.search(r"&ext_bin_[01]\b", board)),
        "ABOX request for core SRAM firmware": bool(re.search(r'request_firmware_nowait\s*\([^;]*?"calliope_sram\.bin"', abox, re.S)),
        "ABOX request for core DRAM firmware": 'abox_request_firmware(dev, &data->firmware_dram, "calliope_dram.bin")' in abox,
        "ABOX loads enabled extra device-tree firmware": "abox_request_extra_firmware(data)" in abox and 'of_property_read_string(child_np, "samsung,name"' in abox,
        "ABOX logs missing auxiliary files and continues": '"%s: %s request failed' in abox and 'ext_fw++' in abox,
        "two enabled auxiliary entries match the manifest": source_enabled == expected_enabled,
    }
    for entry in manifest["files"]:
        if entry["role"] != "enabled_auxiliary":
            continue
        actual = nodes.get(entry["name"])
        tests["match source DT for " + entry["name"]] = bool(actual and all(
            str(actual[field]).lower() == str(entry[field]).lower()
            for field in ("dt_node", "dt_status", "dt_area", "dt_offset")
        ))
    for name in manifest["explicitly_disabled_dt_examples"]:
        tests["disabled DT example: " + name] = nodes.get(name, {}).get("dt_status") == "disabled"
    for label, ok in tests.items():
        print(("PASS" if ok else "FAIL") + ": " + label)
    good = sum(tests.values())
    print(f"Firmware source checks: {good}/{len(tests)}")
    return good == len(tests)


def inspect_local(directory: Path, manifest: dict) -> bool:
    """Inspect only user-owned local files; never copy or upload firmware bytes.

    Presence and hashes are *not* evidence that a blob is safe or compatible.
    """
    if not directory.is_dir():
        print("FAIL: given local firmware directory does not exist", file=sys.stderr)
        return False
    complete = True
    for entry in manifest["files"]:
        name = entry["name"]
        path = directory / name
        role = entry["role"]
        if path.is_symlink():
            print(f"FAIL: {name} is a symlink; refusing to follow it")
            complete = False
            continue
        if not path.is_file():
            print(f"MISSING: {name} ({role})")
            complete = False
            continue
        try:
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    size += len(chunk)
                    digest.update(chunk)
        except OSError:
            print(f"FAIL: cannot read {name}")
            complete = False
            continue
        if not size:
            print(f"FAIL: {name} is empty")
            complete = False
            continue
        print(f"PRESENT_UNVERIFIED: {name} ({role}) size={size} sha256={digest.hexdigest()}")
    print("No file copied, uploaded, written or installed.")
    print("CRITICAL: file existence and SHA-256 do NOT establish SM-R840X firmware")
    print("compatibility, licensing, authenticity or correct audio operation.")
    return complete


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-dir", type=Path, help="Optional local folder of user-supplied firmware files")
    parser.add_argument("--skip-source", action="store_true", help="Skip public source access when inventorying local files")
    opts = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    names = [entry["name"] for entry in manifest["files"]]
    if len(names) != 4 or len(set(names)) != 4:
        print("FAIL: expected exactly four distinct audited filenames", file=sys.stderr)
        return 1
    if manifest.get("device") != "Samsung Galaxy Watch3 SM-R840X":
        print("FAIL: device mismatch", file=sys.stderr)
        return 1
    ok = True
    if not opts.skip_source:
        try:
            ok = verify_source(manifest) and ok
        except (OSError, ValueError, UnicodeError) as error:
            print(f"FAIL: source audit unavailable: {error}", file=sys.stderr)
            ok = False
    if opts.local_dir:
        ok = inspect_local(opts.local_dir, manifest) and ok
    else:
        print("No firmware blobs checked or included in this GitHub repository.")
    print("Source audit != binary provenance != boot compatibility != speaker playback.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
