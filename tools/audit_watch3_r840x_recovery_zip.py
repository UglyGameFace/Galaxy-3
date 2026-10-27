#!/usr/bin/env python3
"""Offline, read-only ZIP metadata triage for Galaxy Watch3 R840X recovery research.

Does not extract, execute, connect to a watch, verify Samsung signatures,
decode PIT partitions or authorize firmware installation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from zipfile import BadZipFile, ZipFile

MAX_ARCHIVE_BYTES = 3 * 1024 * 1024 * 1024
MAX_MEMBERS = 256
MAX_NAME_LENGTH = 200
# The exact X suffix and XXX firmware marker distinguish a demo watch from
# SM-R840 retail firmware. Do not equate the two.
R840X_BUILD = re.compile(r"(?<![A-Z0-9])R840XXXU[0-9][A-Z0-9]{4}(?![A-Z0-9])")
R840_BUILD = re.compile(r"(?<![A-Z0-9])R840XXU[0-9][A-Z0-9]{4}(?![A-Z0-9])")
PARTS = ("BL", "AP", "CSC", "CP")


def _safe_name(name: str) -> bool:
    if not name or len(name) > MAX_NAME_LENGTH or "\\" in name or "\x00" in name:
        return False
    if any(ord(c) < 32 or ord(c) > 126 for c in name):
        return False
    p = PurePosixPath(name)
    return (not p.is_absolute() and ".." not in p.parts and
            not name.startswith(("./", "//")) and ":" not in name)


def _role(basename: str) -> str | None:
    match = re.match(r"^(BL|AP|CSC|CP)[_.-]", basename.upper())
    return match.group(1) if match else None


def _identity(tokens: list[str]) -> tuple[list[str], list[str]]:
    watch, retail = set(), set()
    for token in tokens:
        token = token.upper()
        watch.update(R840X_BUILD.findall(token))
        retail.update(R840_BUILD.findall(token))
    return sorted(watch), sorted(retail)


def audit(path: Path, expected_build: str, checksum: bool = False) -> dict:
    expected_build = expected_build.upper()
    if not R840X_BUILD.fullmatch(expected_build):
        raise ValueError("expected-build must be an exact R840X full build such as R840XXXU1AUA2")
    report = {
        "schema": "uglyos-r840x-recovery-zip-triage-v1",
        "status": "NO_GO",
        "device_model": "SM-R840X",
        "installed_build": expected_build,
        "file": path.name,
        "archive_bytes": None,
        "sha256": None,
        "zip_metadata_readable": False,
        "member_count": None,
        "parts_named": [],
        "watch_build_tokens": [],
        "retail_build_tokens": [],
        "candidate_build_matches_installed": False,
        "combination_or_engineering_firmware": False,
        "issues": [],
        "signature_verified": False,
        "stock_restoration_verified": False,
        "bootloader_acceptance_verified": False,
        "watch_modified": False,
    }
    issues = report["issues"]
    try:
        size = path.stat().st_size
    except OSError:
        issues.append("ARCHIVE_UNREADABLE")
        return report
    report["archive_bytes"] = size
    if size <= 0 or size > MAX_ARCHIVE_BYTES:
        issues.append("ARCHIVE_SIZE_OUT_OF_BOUNDS")
        return report

    if checksum:
        h = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                h.update(chunk)
        report["sha256"] = h.hexdigest()

    try:
        with ZipFile(path, "r", allowZip64=True) as archive:
            entries = archive.infolist()
            if len(entries) == 0 or len(entries) > MAX_MEMBERS:
                issues.append("UNSAFE_MEMBER_COUNT")
                return report
            all_names: list[str] = []
            role_names: set[str] = set()
            unsafe = False
            for member in entries:
                name = member.filename
                if not _safe_name(name):
                    unsafe = True
                    break
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    unsafe = True
                    break
                if not member.is_dir():
                    basename = PurePosixPath(name).name
                    all_names.append(basename)
                    role = _role(basename)
                    if role:
                        role_names.add(role)
            if unsafe:
                issues.append("UNSAFE_MEMBER_NAME_OR_LINK")
                return report
            report["member_count"] = len(entries)
            report["zip_metadata_readable"] = True
            report["parts_named"] = sorted(role_names)
            # Filename evidence is *not* a cryptographic signature.
            tokens = [path.name, *all_names]
            watch, retail = _identity(tokens)
            report["watch_build_tokens"] = watch
            report["retail_build_tokens"] = retail
            report["candidate_build_matches_installed"] = expected_build in watch
            is_combo = any(("COMBINATION" in x.upper() or
                            re.search(r"(^|[_-])(?:FACTORY|ENGINEERING|ENG)(?:[_-]|$)", x.upper()))
                           for x in tokens)
            report["combination_or_engineering_firmware"] = bool(is_combo)
            if is_combo:
                issues.append("ENGINEERING_FIRMWARE_NOT_STOCK_RESCUE")
            if retail:
                issues.append("RETAIL_R840_BUILD_PRESENT_NOT_R840X_PROOF")
            if not watch:
                issues.append("NO_R840X_BUILD_EVIDENCE")
            if watch and expected_build not in watch:
                issues.append("R840X_BUILD_DIFFERS_FROM_INSTALLED")
            if len(watch) > 1:
                issues.append("MULTIPLE_R840X_BUILD_IDENTITIES")
            if not {"BL", "AP", "CSC"}.issubset(role_names):
                issues.append("STOCK_BL_AP_CSC_COMPONENT_NAMES_NOT_PROVEN")
            # Archive names and layout cannot establish OEM authenticity.
            issues.append("ARCHIVE_IDENTITY_AND_SAMSUNG_SIGNATURE_UNVERIFIED")
            issues.append("R840X_DOWNLOAD_MODE_AND_STOCK_RECOVERY_UNVERIFIED")
    except (BadZipFile, OSError, EOFError, ValueError, RuntimeError):
        issues.append("INVALID_OR_UNREADABLE_ZIP")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Existing local recovery ZIP; never downloaded automatically")
    parser.add_argument("--expected-build", default="R840XXXU1AUA2")
    parser.add_argument("--sha256", action="store_true", help="Stream-hash the archive; slower for 800MB+ files")
    parser.add_argument("--output", type=Path, help="Optional JSON report path; no archive extraction")
    args = parser.parse_args()
    try:
        report = audit(args.archive, args.expected_build, args.sha256)
    except (ValueError, OSError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 2
    result = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
        print("NO_GO: ZIP metadata triage saved; NOT verified firmware and NOT FLASHABLE.")
    else:
        print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
