#!/usr/bin/env python3
"""Verify owner-supplied R840X privilege-inventory ZIP and inspect originals offline.

No SDB, network, extracted executable execution, service calls, or writes to the
watch. The private report contains hashes, observations and confidence limits,
not copied Samsung executable bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import zipfile

ARCHIVE_MAX = 16 * 1024 * 1024
UNPACKED_MAX = 32 * 1024 * 1024
REPORT_MAX = 128 * 1024
PROBE_MAX = 64 * 1024
INPUT_MAX = 2 * 1024 * 1024
BASE_NAMES = {"security-metadata-report.json", "probe-output.response",
              "stage-cleanup.response", "stage-create.response",
              "stage-preflight.response", "privilege-context.response"}
FOTA_LITERALS = (
    b"_fota_launch_cb", b"fota.consumer.LaunchFota", b"/fota/consumer",
    b"fota.consumer", b"LaunchFota", b"csc_svc_config_upgrade_pre_config_for_fota_mode",
    b"csc_svc_config_upgrade_pre_config_for_normal_booting", b"/opt/data/recovery/",
    b"/dev/mmcblk", b"recovery-update.sh", b"rw-update-prepare.sh",
)


class EvidenceError(ValueError):
    pass


def read_zip(path: Path) -> dict[str, bytes]:
    if path.stat().st_size > ARCHIVE_MAX:
        raise EvidenceError("ARCHIVE_EXCEEDS_LIMIT")
    contents: dict[str, bytes] = {}
    with zipfile.ZipFile(path, "r") as z:
        members = z.infolist()
        if len(members) > 20:
            raise EvidenceError("ARCHIVE_MEMBER_LIMIT")
        total = 0
        for info in members:
            name = info.filename
            if (name in contents or name not in BASE_NAMES and not re.fullmatch(r"helper-\d\d\.bin", name)
                    or info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000):
                raise EvidenceError("ARCHIVE_MEMBER_INVALID")
            cap = INPUT_MAX if name.endswith(".bin") else REPORT_MAX if name.endswith(".json") else PROBE_MAX
            if info.file_size > cap:
                raise EvidenceError("ARCHIVE_MEMBER_EXCEEDS_LIMIT")
            total += info.file_size
            if total > UNPACKED_MAX:
                raise EvidenceError("ARCHIVE_UNPACKED_LIMIT")
            data = z.read(info)
            if len(data) != info.file_size:
                raise EvidenceError("ARCHIVE_SIZE_MISMATCH")
            contents[name] = data
    required = {"security-metadata-report.json", "probe-output.response", "stage-cleanup.response"}
    if not required.issubset(contents):
        raise EvidenceError("REQUIRED_EVIDENCE_MISSING")
    return contents


def arm_elf(data: bytes) -> dict:
    # Inspect only header. This is NOT full ELF semantic or control-flow review.
    if (len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01" or data[7] not in (0, 3)
            or int.from_bytes(data[18:20], "little") != 40
            or int.from_bytes(data[16:18], "little") not in (2, 3)):
        raise EvidenceError("ORIGINAL_NOT_ARM_ELF32")
    return {"class": "ELF32", "machine": "ARM", "kind": "ET_DYN" if data[16] == 3 else "ET_EXEC",
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def compare_capture(contents: dict[str, bytes]) -> dict:
    try:
        report = json.loads(contents["security-metadata-report.json"])
        raw_probe = json.loads(contents["probe-output.response"])
    except (ValueError, UnicodeError) as exc:
        raise EvidenceError("EVIDENCE_JSON_INVALID") from exc
    if (report.get("schema") != "uglyos-r840x-native-security-metadata-v1"
            or report.get("state") != "NATIVE_PRIVILEGE_INVENTORY_CAPTURED"
            or report.get("privilege_inventory_requested") is not True
            or report.get("stage_cleanup_verified") is not True
            or contents["stage-cleanup.response"].strip() != b"UGLYOS_STAGE_REMOVED"
            or raw_probe != report.get("probe") or raw_probe.get("test_fixture") is not False):
        raise EvidenceError("INVENTORY_CAPTURE_UNVERIFIED")
    forbidden = ("root_mode_requested", "vendor_script_executed", "existing_security_attributes_modified",
                 "fota_method_called", "partition_reads_attempted", "firmware_written",
                 "bootloader_unlock_proven", "stock_recovery_proven")
    if any(report.get(name) is not False for name in forbidden):
        raise EvidenceError("UNSAFE_OR_INCONSISTENT_CAPTURE")
    inv = raw_probe.get("privilege_inventory", {})
    summary = report.get("inventory_summary", {})
    roots = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib")
    dirs = inv.get("directories", [])
    if (inv.get("schema") != "uglyos-system-helper-metadata-v1" or
            [d.get("path") for d in dirs] != list(roots) or
            raw_probe.get("uid") != raw_probe.get("euid") or
            not re.fullmatch(r"[0-9a-f]{16}", raw_probe.get("effective_caps_hex", "")) or
            not re.fullmatch(r"[0-9a-f]{16}", raw_probe.get("permitted_caps_hex", "")) or
            not isinstance(summary.get("candidates"), list)):
        raise EvidenceError("INVENTORY_STRUCTURE_INVALID")
    retained = []
    dropped = 0
    stats = []
    for directory in dirs:
        rows = directory.get("files", [])
        if not isinstance(rows, list) or not isinstance(directory.get("dropped_records"), int):
            raise EvidenceError("INVENTORY_DIRECTORY_INVALID")
        dropped += directory["dropped_records"]
        stats.append({"path": directory["path"], "entries_scanned": directory.get("entries_scanned"),
                      "stat_errors": directory.get("stat_errors"), "dropped_records": directory["dropped_records"],
                      "complete": directory.get("complete") is True})
        for row in rows:
            name = row.get("name", "")
            if (not re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}", name) or name in (".", "..") or
                    type(row.get("mode")) is not int):
                raise EvidenceError("INVENTORY_CANDIDATE_INVALID")
            retained.append((directory["path"] + "/" + name, row))
    if (len(retained) > 64 or len(retained) != len(summary["candidates"]) or
            any(record["path"] != path for (path, _), record in zip(retained, summary["candidates"]))):
        raise EvidenceError("INVENTORY_SUMMARY_MISMATCH")
    observed = set()
    originals = []
    copied_names = set()
    for item in summary.get("original_inputs", []):
        name = item.get("file")
        source = item.get("path")
        if source in observed or not isinstance(source, str):
            raise EvidenceError("ORIGINAL_PATH_DUPLICATED")
        observed.add(source)
        if item.get("copied") is not True:
            originals.append({"path": source, "copied": False})
            continue
        if (not isinstance(name, str) or not re.fullmatch(r"helper-\d\d\.bin", name)
                or name not in contents or name in copied_names):
            raise EvidenceError("ORIGINAL_MISSING")
        copied_names.add(name)
        meta = arm_elf(contents[name])
        if meta["sha256"] != item.get("sha256") or meta["bytes"] != item.get("bytes"):
            raise EvidenceError("ORIGINAL_HASH_OR_SIZE_MISMATCH")
        file_record = dict(next((r for p, r in retained if p == source), {}))
        if file_record and int(file_record.get("size_hex", "0"), 16) != meta["bytes"]:
            raise EvidenceError("ORIGINAL_INVENTORY_SIZE_MISMATCH")
        matches = [term.decode("ascii") for term in FOTA_LITERALS if term in contents[name]]
        originals.append({"path": source, **meta, "copied": True,
                          "fota_literal_matches": matches,
                          "static_evidence_only": True})
    if len(originals) > 8 or {n for n in contents if n.endswith(".bin")} != {
            it["file"] for it in summary["original_inputs"] if it.get("copied") is True}:
        raise EvidenceError("ORIGINAL_MANIFEST_MISMATCH")
    if any(item["path"] != "/usr/bin/launch_app" and item["path"] not in {p for p, _ in retained}
           for item in originals):
        raise EvidenceError("ORIGINAL_NOT_IN_INVENTORY")
    if (raw_probe.get("capget_rc") != 0 or raw_probe.get("effective_caps_hex") != "0000000000000000"
            or raw_probe.get("permitted_caps_hex") != "0000000000000000"):
        privilege = "OWNER_PRIVILEGE_BOUNDARY_NOT_ESTABLISHED"
    else:
        privilege = "OWNER_NO_EFFECTIVE_OR_PERMITTED_CAPABILITIES"
    return {"schema": "uglyos-r840x-privilege-offline-review-v1",
            "state": "OFFLINE_INVENTORY_CHECKED", "watch_access": False, "binary_executed": False,
            "source_report_sha256": hashlib.sha256(contents["security-metadata-report.json"]).hexdigest(),
            "uid": raw_probe.get("uid"), "euid": raw_probe.get("euid"),
            "privilege_boundary": privilege,
            "inheritable_caps_hex": raw_probe.get("inheritable_caps_hex"),
            "candidate_count": len(retained), "setuid_or_setgid_count": sum(bool(r["mode"] & 0o6000) for _, r in retained),
            "dropped_candidate_records": dropped, "scope_complete": summary.get("scope_complete") is True and dropped == 0,
            "directory_coverage": stats, "original_inputs": originals,
            "firmware_service_integration_evidence": "Observed static literals only; no call authorization, privilege gain, signing bypass, or safe recovery proven",
            "bootloader_unlock_proven": False, "root_proven": False, "stock_recovery_proven": False}


def review(path: Path) -> dict:
    return compare_capture(read_zip(path))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = review(args.archive.expanduser())
        out = args.report.expanduser()
        if not out.parent.is_dir():
            raise EvidenceError("REPORT_PARENT_NOT_FOUND")
        payload = (json.dumps(result, indent=2) + "\n").encode("utf-8")
        fd = os.open(out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            out.unlink(missing_ok=True)
            raise
    except (OSError, ValueError, zipfile.BadZipFile, KeyError, TypeError) as exc:
        print("OFFLINE_PRIVILEGE_ERROR: " + (str(exc) if isinstance(exc, EvidenceError)
              else "INVALID_OR_UNREADABLE_LOCAL_EVIDENCE"), file=sys.stderr)
        return 1
    print("OFFLINE_PRIVILEGE_STATE: " + result["state"])
    print("CANDIDATES: %d retained; %d dropped" % (result["candidate_count"], result["dropped_candidate_records"]))
    print("REPORT: " + str(out))
    print("No Samsung executable launched; watch and firmware unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
