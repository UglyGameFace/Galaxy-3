#!/usr/bin/env python3
"""Read one physically observed R840X FOTA package registration via SDB RECV.

The owner's physical fixed-directory LIST confirmed this exact system XML file.
The 16 KiB download is read-only; no shell, FOTA trigger, service call, or
device write. The raw XML is saved ONLY on the owner's phone, never in GitHub.
A separately private, redacted JSON reports structural package facts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import xml.etree.ElementTree as ET

from watch3_r08_android_sdb import PORT, SdbError, private_watch_ip
from watch3_r08_fota_manifest_probe import (
    ManifestError, MAX_REGISTERED_XML_BYTES, REGISTERED_PACKAGE_PATH,
    fetch_fixed_xml_bytes,
)

EXPECTED_PACKAGE = "com.samsung.fota-consumer"
KNOWN_BIN_PREFIX = "/usr/apps/com.samsung.fota-consumer/bin/"
APP_TAGS = {"ui-application", "service-application", "watch-application", "application"}
SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")
SAFE_ID = re.compile(r"com[.]samsung[.][A-Za-z0-9_.-]{1,115}\Z")
SCHEMA = "uglyos-r840x-observed-fota-package-registration-v1"


class RegistrationError(ValueError):
    """Redacted local error; never includes raw file or watch contents."""


def examine(xml_data: bytes) -> dict:
    if not xml_data or len(xml_data) > MAX_REGISTERED_XML_BYTES:
        raise RegistrationError("REGISTRATION_XML_INVALID_SIZE")
    if b"<!DOCTYPE" in xml_data.upper() or b"<!ENTITY" in xml_data.upper():
        raise RegistrationError("REGISTRATION_XML_DTD_OR_ENTITY")
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        raise RegistrationError("REGISTRATION_XML_MALFORMED") from None
    tag = root.tag.rsplit("}", 1)[-1]
    if not SAFE_NAME.fullmatch(tag):
        raise RegistrationError("REGISTRATION_XML_ROOT_INVALID")
    declared_package = root.attrib.get("package")
    if declared_package and declared_package != EXPECTED_PACKAGE:
        raise RegistrationError("REGISTRATION_XML_PACKAGE_MISMATCH")
    applications = []
    unreported = 0
    for element in root.iter():
        kind = element.tag.rsplit("}", 1)[-1]
        if kind not in APP_TAGS:
            continue
        raw_exec = element.attrib.get("exec", "")
        if raw_exec.startswith(KNOWN_BIN_PREFIX):
            basename = raw_exec[len(KNOWN_BIN_PREFIX):]
        elif raw_exec.startswith("bin/"):
            basename = raw_exec[4:]
        else:
            basename = raw_exec
        if not SAFE_NAME.fullmatch(basename):
            unreported += 1
            continue
        appid = element.attrib.get("appid", "")
        applications.append({
            "kind": kind,
            "app_id": appid if SAFE_ID.fullmatch(appid) else "UNREPORTED_ID",
            "executable_filename": basename,
        })
        if len(applications) > 32:
            raise RegistrationError("REGISTRATION_XML_TOO_MANY_APPS")
    return {
        "schema": SCHEMA,
        "status": "OBSERVED_PACKAGE_REGISTRATION_RETRIEVED",
        "source": "usr_share_packages_exact_confirmed_xml",
        "source_bytes": len(xml_data),
        "source_sha256": hashlib.sha256(xml_data).hexdigest(),
        "xml_root_tag": tag,
        "package_attribute": (
            "MATCHED" if declared_package == EXPECTED_PACKAGE
            else "NOT_DECLARED_ON_XML_ROOT"),
        "declared_application_executables": applications,
        "other_application_entries": unreported,
        "meaning": ("This is registration metadata, not proof of which process "
                    "owns D-Bus fota.consumer, verifies firmware, or boots kernels. "
                    "The original XML remains private on the owner's phone."),
        "root_obtained": False,
        "d_bus_owner_proven": False,
        "unsigned_boot_proven": False,
        "stock_recovery_proven": False,
        "watch_write_performed": False,
    }


def retrieve(ip: str, key_path: Path, timeout: int = 12):
    private_ip = private_watch_ip(ip)
    try:
        with socket.create_connection((private_ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = fetch_fixed_xml_bytes(sock, key_path, registered_package=True)
    except ManifestError as exc:
        if str(exc) == "MANIFEST_MISSING_DENIED_OR_UNREADABLE":
            raise RegistrationError("OBSERVED_XML_RECV_MISSING_DENIED_OR_UNREADABLE") from None
        raise RegistrationError("REGISTRATION_SDB_" + str(exc)) from None
    except (OSError, SdbError, TimeoutError):
        raise RegistrationError("REGISTRATION_SDB_UNAVAILABLE") from None
    report = examine(raw)
    return raw, report


def private_file(path: Path, payload: bytes) -> None:
    """Exclusive, mode-0600, no-overwrite local output. No remote writes."""
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise RegistrationError("LOCAL_OUTPUT_ALREADY_EXISTS") from None
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--output", type=Path,
                        default=Path.home() / "watch3-r840x-fota-package-registration.xml")
    parser.add_argument("--report", type=Path,
                        default=Path.home() / "watch3-r840x-fota-package-registration.json")
    args = parser.parse_args()
    original = args.output.expanduser()
    report_path = args.report.expanduser()
    if original == report_path:
        print("REGISTRATION_ERROR: OUTPUT_PATHS_IDENTICAL", file=sys.stderr)
        return 1
    if (original.exists() or original.is_symlink() or
            report_path.exists() or report_path.is_symlink()):
        print("REGISTRATION_ERROR: LOCAL_OUTPUT_ALREADY_EXISTS", file=sys.stderr)
        return 1
    if not original.parent.is_dir() or not report_path.parent.is_dir():
        print("REGISTRATION_ERROR: LOCAL_PARENT_DIRECTORY_MISSING", file=sys.stderr)
        return 1
    created_xml = False
    try:
        raw, report = retrieve(args.watch_ip, args.key_path)
        payload = (json.dumps(report, indent=2) + "\n").encode("utf-8")
        private_file(original, raw)
        created_xml = True
        private_file(report_path, payload)
    except (RegistrationError, ManifestError, OSError, SdbError) as exc:
        if created_xml:
            original.unlink(missing_ok=True)
        reason = str(exc) if isinstance(exc, RegistrationError) else "LOCAL_IO_ERROR"
        print("REGISTRATION_ERROR: " + reason, file=sys.stderr)
        return 1
    print("READ_ONLY_PACKAGE_REGISTRATION_RETRIEVED: " + str(original))
    print("REDACTED_REPORT: " + str(report_path))
    print("NO watch writes, service launches, firmware updates, or root obtained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
