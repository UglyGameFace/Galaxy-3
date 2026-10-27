#!/usr/bin/env python3
"""Read five physically LIST-confirmed Watch3 FOTA handoff files.

Host-side read-only, exact allowlist only. SDB sync RECV only: no shell,
SEND, D-Bus invocation, service launch, package update, exploit, or flashing.
Raw vendor service configurations stay in a private Termux directory.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import sys
import xml.etree.ElementTree as ET

from watch3_r08_android_sdb import Connection, PORT, SdbError, private_watch_ip, receive
from watch3_r08_fota_artifact_pull import (
    ArtifactPullError, LOCAL_STREAM, MAX_STREAM_FRAMES, ReadOnlySyncDecoder, SYNC_HDR,
)

# ALL five locations and byte counts originated in the owner's actual
# READ_ONLY_FOTA_HANDOFF_INDEX observation. No user-controlled remote paths.
OBSERVED_FILES = {
    "fota-consumer.service": (b"/usr/lib/systemd/system/fota-consumer.service", 386),
    "recovery-update.service": (b"/usr/lib/systemd/system/recovery-update.service", 238),
    "update-service.service": (b"/usr/lib/systemd/system/update-service.service", 245),
    "rw-update.service": (b"/usr/lib/systemd/system/rw-update.service", 215),
    "appcessoryservices.xml": (
        b"/usr/apps/com.samsung.fota-consumer/res/xml/appcessoryservices.xml", 2036),
}
# Both literal paths are grounded by ExecStart in the successfully
# retrieved physical service unit files, NOT by guessing filenames.
# The owner has not yet confirmed the script files' existence or readability.
REFERENCED_HELPER_FILES = {
    "recovery-update.sh": (b"/usr/bin/recovery-update.sh", None),
    "rw-update-systemd.sh": (b"/usr/bin/rw-update-systemd.sh", None),
}
MAX_FILE_BYTES = 8 * 1024
REPORT_NAME = "fota-handoff-report.json"
SCHEMA = "uglyos-r840x-exact-fota-handoff-recv-v1"
SAFE_DAEMON_PATH = re.compile(r"/(?:usr|bin|sbin|opt)/[A-Za-z0-9_./-]{1,220}\Z")
SAFE_UNIT_VALUE = re.compile(r"[A-Za-z0-9_.@-]{1,128}\Z")
SAFE_BUS_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class HandoffError(ValueError):
    """Categorical error. Do not expose private watch protocol payloads."""


class CappedBytes(io.BytesIO):
    def write(self, part: bytes) -> int:
        if self.tell() + len(part) > MAX_FILE_BYTES:
            raise HandoffError("REMOTE_FILE_EXCEEDS_EIGHT_KIB")
        return super().write(part)


def receive_one(sock, key_path: Path, remote_path: bytes) -> bytes:
    """Exactly one SDB OPEN sync: plus read-only RECV for a fixed-path caller."""
    if remote_path not in {item[0] for item in (
            list(OBSERVED_FILES.values()) + list(REFERENCED_HELPER_FILES.values()))}:
        raise HandoffError("REMOTE_PATH_NOT_ALLOWLISTED")
    conn = Connection(sock, key_path)
    try:
        conn.handshake()
        conn.send(b"OPEN", LOCAL_STREAM, 0, b"sync:\x00")
        kind, remote, local, body = receive(sock)
    except (OSError, SdbError, TimeoutError):
        raise HandoffError("SDB_OPEN_FAILED") from None
    if kind == b"CLSE" and local == LOCAL_STREAM:
        raise HandoffError("SDB_SYNC_SERVICE_REFUSED")
    if kind != b"OKAY" or local != LOCAL_STREAM or not remote or body:
        raise HandoffError("SDB_SYNC_OPEN_INVALID")
    try:
        conn.send(b"WRTE", LOCAL_STREAM, remote,
                  SYNC_HDR.pack(b"RECV", len(remote_path)) + remote_path)
    except (OSError, SdbError, TimeoutError):
        raise HandoffError("SDB_RECV_REQUEST_FAILED") from None
    buffer = CappedBytes()
    decoder = ReadOnlySyncDecoder(buffer)
    for _ in range(MAX_STREAM_FRAMES):
        try:
            kind, sender, receiver, part = receive(sock)
        except (OSError, SdbError, TimeoutError):
            raise HandoffError("SDB_TRANSFER_INCOMPLETE") from None
        if sender != remote or receiver != LOCAL_STREAM:
            raise HandoffError("SDB_STREAM_MISMATCH")
        if kind == b"OKAY":
            continue
        if kind == b"CLSE":
            raise HandoffError("SDB_CLOSED_BEFORE_DONE")
        if kind != b"WRTE":
            raise HandoffError("SDB_UNEXPECTED_FRAME")
        try:
            conn.send(b"OKAY", LOCAL_STREAM, remote)
            decoder.feed(part)
        except ArtifactPullError as exc:
            if str(exc) == "REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE":
                raise HandoffError("REMOTE_MISSING_DENIED_OR_UNREADABLE") from None
            raise HandoffError("SDB_INVALID_SYNC_PAYLOAD") from None
        except (OSError, SdbError, TimeoutError):
            raise HandoffError("SDB_TRANSFER_INCOMPLETE") from None
        if decoder.done:
            return buffer.getvalue()
    raise HandoffError("SDB_FRAME_LIMIT")


def inspect_unit(raw: bytes) -> dict:
    """Emit only bounded identity fields; retain complete raw bytes privately."""
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"parse_status": "NOT_UTF8"}
    section = ""
    fields: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if section == "Service" and key in ("Type", "BusName", "ExecStart"):
            if key == "Type" and SAFE_UNIT_VALUE.fullmatch(value):
                fields["service_type"] = value
            if key == "BusName" and SAFE_BUS_NAME.fullmatch(value):
                fields["bus_name"] = value
            if key == "ExecStart":
                token = value.strip().split(" ", 1)[0].lstrip("-+!:@")
                if SAFE_DAEMON_PATH.fullmatch(token):
                    fields["exec_path"] = token
                else:
                    fields["exec_path"] = "NOT_SIMPLE_ABSOLUTE_PATH"
        if section == "Unit" and key in ("After", "Wants", "Requires"):
            names = value.split()
            fields[key.lower()] = [n for n in names[:16]
                                   if SAFE_UNIT_VALUE.fullmatch(n)]
    return {"parse_status": "SYSTEMD_UNIT_FIELDS", **fields}


def inspect_sap(raw: bytes) -> dict:
    # SAP metadata is not firmware D-Bus metadata; do not expose unknown fields.
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        return {"parse_status": "XML_DTD_REJECTED"}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"parse_status": "XML_UNPARSEABLE"}
    name = root.tag.rsplit("}", 1)[-1]
    return {"parse_status": "XML_PARSED",
            "root_tag": name if SAFE_UNIT_VALUE.fullmatch(name) else "UNREPORTED"}


def private_write(path: Path, payload: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def collect(ip: str, key_path: Path, folder: Path, timeout: int = 12,
            *, observed_helpers_only: bool = False) -> dict:
    """Read only literal observed unit files or exact ExecStart-referenced scripts."""
    private_ip = private_watch_ip(ip)
    results = {}
    selected = REFERENCED_HELPER_FILES if observed_helpers_only else OBSERVED_FILES
    for filename, (remote_path, expected_size) in selected.items():
        try:
            with socket.create_connection((private_ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                raw = receive_one(sock, key_path, remote_path)
            private_write(folder / filename, raw)
            report = {
                "status": "FETCHED",
                "bytes": len(raw),
                "observed_list_bytes": expected_size,
                "size_matches_previous_list": (
                    len(raw) == expected_size if expected_size is not None else None),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if observed_helpers_only:
                # Shell content stays private on owner's phone. NEVER execute it.
                report["parse_status"] = "SHELL_TEXT_RETAINED_NOT_EXECUTED"
                report["source"] = "EXACT_EXECSTART_IN_PHYSICAL_SYSTEMD_UNIT"
            else:
                report.update(inspect_sap(raw) if filename.endswith(".xml")
                              else inspect_unit(raw))
            results[filename] = report
        except HandoffError as exc:
            results[filename] = {"status": str(exc)}
        except (OSError, SdbError, TimeoutError):
            results[filename] = {"status": "SDB_OR_LOCAL_IO_ERROR"}
    return {
        "schema": ("uglyos-r840x-referenced-fota-helper-recv-v1"
                   if observed_helpers_only else SCHEMA),
        "status": ("READ_ONLY_REFERENCED_FOTA_HELPER_RECV" if observed_helpers_only
                   else "READ_ONLY_FIXED_FOTA_HANDOFF_RECV"),
        "files": results,
        "meaning": ("Only owner-observed systemd/SAP metadata. No active D-Bus owner, "
                    "firmware signing rights, bootloader acceptance, root or rescue proven."),
        "watch_write_performed": False,
        "fota_launch_performed": False,
        "unsigned_boot_proven": False,
        "stock_recovery_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    parser.add_argument("--observed-helpers-only", action="store_true",
                        help="Read only two exact shell script paths from physical unit ExecStart")
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--output-dir", type=Path,
                        default=Path.home() / "watch3-r840x-fota-handoff-evidence")
    args = parser.parse_args()
    folder = args.output_dir.expanduser()
    if (args.observed_helpers_only and folder ==
            Path.home() / "watch3-r840x-fota-handoff-evidence"):
        folder = Path.home() / "watch3-r840x-fota-recovery-helpers"
    try:
        if not folder.parent.is_dir():
            raise HandoffError("LOCAL_PARENT_DIRECTORY_MISSING")
        # Directory creation is local and exclusive. Never overwrite evidence.
        os.mkdir(folder, 0o700)
        report = collect(args.watch_ip, args.key_path, folder,
                         observed_helpers_only=args.observed_helpers_only)
        payload = (json.dumps(report, indent=2) + "\n").encode("utf-8")
        private_write(folder / REPORT_NAME, payload)
    except (HandoffError, OSError, SdbError) as exc:
        reason = str(exc) if isinstance(exc, HandoffError) else "LOCAL_OR_NETWORK_ERROR"
        print("HANDOFF_ERROR: " + reason, file=sys.stderr)
        return 1
    print("READ_ONLY_FOTA_HANDOFF_EVIDENCE: " + str(folder))
    print("SUMMARY: " + str(folder / REPORT_NAME))
    print("NO device writes, systemctl, FOTA calls, root, or custom boot attempted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
