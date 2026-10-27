#!/usr/bin/env python3
"""Offline-only audit of four physically extracted SM-R840X FOTA metadata files.

NO network, device connection, command execution, script sourcing, firmware
writing, or modified package data. Input is a local directory already
populated by the separate read-only SDB extractor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from xml.etree import ElementTree as ET

SCHEMA = "uglyos-r840x-fota-handoff-offline-v1"
EXPECTED = {
    "recovery-update.service": (238, "8e511434fd0be3f6be16d23242c364cc570c317518ce60210b573b694bb9fda8"),
    "rw-update.service": (215, "8c20c8e1064a9f7b4521a01cf64ed62da7da499c241e90343353a602b50a9f80"),
    "update-service.service": (245, "017640aa04aa8c2290eac37c9af95da54612b4163be75964f89412c759fc30ff"),
    "appcessoryservices.xml": (2036, "1ece1d36e8cba9d4a6527295f67c5d0ddf7b2ae0a3b2fb5e7243935fb40533a1"),
}
MAX_FILE_BYTES = 8192
SAFE_UNIT = re.compile(r"[A-Za-z0-9_.@-]{1,100}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,160}\Z")
SAFE_PATH = re.compile(r"/(?:usr|bin|sbin|opt)/[A-Za-z0-9_.-]{1,96}(?:/[A-Za-z0-9_.-]{1,96}){0,8}\Z")
SAFE_LABEL = re.compile(r"[A-Za-z0-9_:.-]{1,100}\Z")
SAFE_QOS = re.compile(r"[A-Za-z0-9_:-]{1,96}\Z")


class OfflineAuditError(ValueError):
    """Categorical no-private-data error."""


def read_known(path: Path, expected_size: int, expected_sha: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise OfflineAuditError("MISSING_OR_NONREGULAR_LOCAL_FILE")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise OfflineAuditError("OVERSIZED_LOCAL_FILE")
    raw = path.read_bytes()
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise OfflineAuditError("SOURCE_SIZE_OR_SHA256_MISMATCH")
    return raw


def safe_text(value: str, pattern) -> str | None:
    value = value.strip()
    return value if pattern.fullmatch(value) else None


def parse_unit(raw: bytes) -> dict:
    """Extract only short allowlisted systemd fields, never arbitrary content."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise OfflineAuditError("NON_UTF8_UNIT") from None
    section = ""
    values: dict[str, object] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if section == "Service" and key in (
            "Type", "User", "Group", "BusName", "SmackProcessLabel",
            "ExecStart",
        ):
            if key == "ExecStart":
                parts = value.split()
                executable = safe_text(parts[0], SAFE_PATH) if parts else None
                values["exec_path"] = executable or "NON_SIMPLE_EXEC"
                if len(parts) == 2 and executable == "/usr/bin/launch_app":
                    app_id = safe_text(parts[1], SAFE_ID)
                    if app_id:
                        values["launch_app_id"] = app_id
            else:
                pattern = SAFE_LABEL if key == "SmackProcessLabel" else SAFE_ID
                cleaned = safe_text(value, pattern)
                if cleaned is not None:
                    values[{"Type": "type", "User": "user", "Group": "group",
                            "BusName": "bus_name",
                            "SmackProcessLabel": "smack_process_label"}[key]] = cleaned
        if section in ("Unit", "Install") and key in (
            "Wants", "After", "Requires", "WantedBy",
        ):
            short = [w for w in value.split()[:20] if SAFE_UNIT.fullmatch(w)]
            values[key.lower()] = short
    return values


def parse_sap(raw: bytes) -> dict:
    """Recognize ONLY a local non-entity internal DTD; parse no external data."""
    if len(raw) > MAX_FILE_BYTES or not raw.startswith(b"<!DOCTYPE resources ["):
        raise OfflineAuditError("UNEXPECTED_SAP_DTD_SHAPE")
    end = raw.find(b"]>")
    if not 0 <= end <= 4096:
        raise OfflineAuditError("UNTERMINATED_SAP_DTD")
    declaration = raw[:end + 2].upper()
    if any(bad in declaration for bad in (b"<!ENTITY", b"SYSTEM", b"PUBLIC",
                                            b"<!NOTATION", b"<![")):
        raise OfflineAuditError("DTD_EXTERNAL_OR_ENTITY_NOT_ALLOWED")
    # The actual R840X file uses only ELEMENT and ATTLIST statements.
    # Strip the internal DTD before invoking a NON-VALIDATING parser.
    # This intentionally does not apply any DTD defaults or expand entities.
    payload = raw[end + 2:]
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise OfflineAuditError("UNSAFE_XML_DECLARATION")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        raise OfflineAuditError("SAP_XML_NOT_WELL_FORMED") from None
    if root.tag != "resources":
        raise OfflineAuditError("UNEXPECTED_SAP_ROOT")
    apps = list(root.findall("application"))
    if len(apps) != 1:
        raise OfflineAuditError("UNEXPECTED_SAP_APP_COUNT")
    app = apps[0]
    if app.attrib.get("name") != "com.samsung.fota-service":
        raise OfflineAuditError("UNEXPECTED_SAP_APP")
    profiles = app.findall("serviceProfile")
    if len(profiles) != 1:
        raise OfflineAuditError("UNEXPECTED_SAP_PROFILE_COUNT")
    profile = profiles[0]
    if (profile.attrib.get("id") != "/system/sfota" or
            profile.attrib.get("serviceImpl") != "com.samsung.fota-service"):
        raise OfflineAuditError("UNEXPECTED_SAP_PROFILE")
    transports_node = profile.find("supportedTransports")
    if transports_node is None:
        raise OfflineAuditError("MISSING_SAP_TRANSPORTS")
    transports = []
    for item in transports_node.findall("transport"):
        kind = item.attrib.get("type", "")
        if kind in ("TRANSPORT_BT", "TRANSPORT_WIFI", "TRANSPORT_BLE",
                    "TRANSPORT_USB") and kind not in transports:
            transports.append(kind)
    channels = []
    for node in profile.findall("serviceChannel")[:10]:
        channel = {}
        for key in ("id", "qosDataRate", "qosPriority", "qosType"):
            raw_value = node.attrib.get(key, "")
            safe = safe_text(raw_value, SAFE_QOS)
            if safe:
                channel[key] = safe
        channels.append(channel)
    return {
        "app_name": app.attrib["name"],
        "profile_id": profile.attrib["id"],
        "profile_name": safe_text(profile.attrib.get("name", ""), SAFE_QOS),
        "role": safe_text(profile.attrib.get("role", ""), SAFE_QOS),
        "service_impl": profile.attrib["serviceImpl"],
        "version": safe_text(profile.attrib.get("version", ""), SAFE_QOS),
        "transports": transports,
        "channels": channels,
        "source_has_internal_dtd": True,
        "dtd_validity_checked": False,
    }


def audit(folder: Path) -> dict:
    files = {}
    for name, (size, sha) in EXPECTED.items():
        data = read_known(folder / name, size, sha)
        files[name] = {
            "verified_size": size,
            "verified_sha256": sha,
            "facts": parse_sap(data) if name.endswith(".xml") else parse_unit(data),
        }
    return {
        "schema": SCHEMA,
        "status": "FOUR_PHYSICAL_R840X_METADATA_FILES_VERIFIED",
        "files": files,
        "interpretation": (
            "Static service configuration and SAP metadata ONLY. "
            "No watch service started, no D-Bus owner proved, no recovery image "
            "acceptance, root access, stock restoration or unsigned kernel boot."
        ),
        "watch_contacted": False,
        "watch_write_performed": False,
        "script_executed": False,
        "stock_recovery_proven": False,
        "unsigned_kernel_boot_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path,
                        default=Path.home() / "watch3-r840x-fota-offline-analysis.json")
    args = parser.parse_args()
    try:
        result = audit(args.input_dir.expanduser())
        output = args.output.expanduser()
        fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write((json.dumps(result, indent=2) + "\n").encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    except (OfflineAuditError, OSError) as exc:
        reason = str(exc) if isinstance(exc, OfflineAuditError) else "LOCAL_IO_ERROR"
        print("OFFLINE_AUDIT_ERROR: " + reason, file=sys.stderr)
        return 1
    print("OFFLINE_FOTA_HANDOFF_ANALYSIS: " + str(output))
    print("NO network, watch, firmware, script execution or service invocation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
