#!/usr/bin/env python3
"""Read ONLY the known R840X FOTA package manifest via authenticated SDB sync.

No shell, arbitrary remote path, device writes, package launch, D-Bus calls,
root, or flashing. Parse the local XML in memory and save a redacted report.
The target path is grounded by Samsung's installed Tizen app layout.
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
    ArtifactPullError, LOCAL_STREAM, MAX_STREAM_FRAMES, ReadOnlySyncDecoder,
    SYNC_HDR,
)

MANIFEST_PATH = b"/usr/apps/com.samsung.fota-consumer/tizen-manifest.xml"
PACKAGE_NAME = "com.samsung.fota-consumer"
BIN_PREFIX = "/usr/apps/com.samsung.fota-consumer/bin/"
MAX_MANIFEST_BYTES = 64 * 1024
SAFE_BINARY = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")
APPLICATION_TAGS = frozenset(("service-application", "ui-application", "watch-application"))
SCHEMA = "uglyos-r840x-fota-manifest-readonly-v1"


class ManifestError(ValueError):
    """Private-free categorical error."""


class LimitedBuffer(io.BytesIO):
    def write(self, part: bytes) -> int:
        if self.tell() + len(part) > MAX_MANIFEST_BYTES:
            raise ManifestError("MANIFEST_EXCEEDS_64_KIB")
        return super().write(part)


def summarize(xml_bytes: bytes) -> dict:
    if not xml_bytes or len(xml_bytes) > MAX_MANIFEST_BYTES:
        raise ManifestError("MANIFEST_SIZE_INVALID")
    # Do not permit DTD/entity processing or XML resources.
    upper = xml_bytes.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ManifestError("DTD_OR_ENTITY_NOT_ALLOWED")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        raise ManifestError("MANIFEST_XML_MALFORMED") from None
    if root.tag.rsplit("}", 1)[-1] != "manifest":
        raise ManifestError("UNEXPECTED_XML_ROOT")
    if root.attrib.get("package") != PACKAGE_NAME:
        raise ManifestError("PACKAGE_ID_DOES_NOT_MATCH_FIXED_PATH")

    apps = []
    filtered = 0
    for element in root.iter():
        kind = element.tag.rsplit("}", 1)[-1]
        if kind not in APPLICATION_TAGS:
            continue
        raw_exec = element.attrib.get("exec", "")
        app_id = element.attrib.get("appid", "")
        if (not raw_exec.startswith(BIN_PREFIX) or
                not SAFE_BINARY.fullmatch(raw_exec[len(BIN_PREFIX):])):
            filtered += 1
            continue
        # App IDs must belong to the expected fixed vendor/package identity.
        safe_id = (app_id if (app_id == PACKAGE_NAME or
                   app_id.startswith(PACKAGE_NAME + ".")) and
                   len(app_id) <= 128 else "UNREPORTED_ID")
        apps.append({
            "kind": kind,
            "app_id": safe_id,
            "executable_filename": raw_exec[len(BIN_PREFIX):],
        })
        if len(apps) > 20:
            raise ManifestError("UNREASONABLE_APP_COUNT")
    return {
        "schema": SCHEMA,
        "status": "FIXED_FOTA_MANIFEST_PARSED",
        "source_sha256": hashlib.sha256(xml_bytes).hexdigest(),
        "source_bytes": len(xml_bytes),
        "package_matches_expected": True,
        "declared_application_executables": apps,
        "unreported_application_entries": filtered,
        "meaning": ("Installed Tizen package declarations only. Manifest entries "
                    "do not prove D-Bus name ownership, signature bypass or boot."),
        "root_obtained": False,
        "stock_recovery_proven": False,
        "unsigned_boot_proven": False,
        "watch_write_performed": False,
    }


def fetch_manifest(sock, key_path: Path) -> dict:
    """Single exact read-only RECV using existing SDB framing/stream decoder."""
    connection = Connection(sock, key_path)
    try:
        connection.handshake()
        connection.send(b"OPEN", LOCAL_STREAM, 0, b"sync:\x00")
        kind, remote, local, body = receive(sock)
    except (OSError, SdbError, TimeoutError):
        raise ManifestError("SDB_HANDSHAKE_OR_OPEN_FAILED") from None
    if kind == b"CLSE" and local == LOCAL_STREAM:
        raise ManifestError("SDB_SYNC_REFUSED")
    if kind != b"OKAY" or local != LOCAL_STREAM or remote == 0 or body:
        raise ManifestError("SDB_SYNC_OPEN_INVALID")
    try:
        connection.send(b"WRTE", LOCAL_STREAM, remote,
                        SYNC_HDR.pack(b"RECV", len(MANIFEST_PATH)) + MANIFEST_PATH)
    except (OSError, SdbError, TimeoutError):
        raise ManifestError("SDB_MANIFEST_REQUEST_FAILED") from None
    limited = LimitedBuffer()
    decoder = ReadOnlySyncDecoder(limited)
    for _ in range(MAX_STREAM_FRAMES):
        try:
            kind, sender, receiver, body = receive(sock)
        except (OSError, SdbError, TimeoutError):
            raise ManifestError("SDB_MANIFEST_TRANSFER_FAILED") from None
        if sender != remote or receiver != LOCAL_STREAM:
            raise ManifestError("SDB_STREAM_MISMATCH")
        if kind == b"OKAY":
            continue
        if kind == b"CLSE":
            raise ManifestError("SDB_MANIFEST_CLOSED")
        if kind != b"WRTE":
            raise ManifestError("SDB_UNEXPECTED_FRAME")
        try:
            connection.send(b"OKAY", LOCAL_STREAM, remote)
            decoder.feed(body)
        except ArtifactPullError as exc:
            if str(exc) == "REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE":
                raise ManifestError("MANIFEST_MISSING_DENIED_OR_UNREADABLE") from None
            raise ManifestError("INVALID_SYNC_MANIFEST_STREAM") from None
        except (OSError, SdbError, TimeoutError):
            raise ManifestError("SDB_MANIFEST_TRANSFER_FAILED") from None
        if decoder.done:
            return summarize(limited.getvalue())
    raise ManifestError("SDB_FRAME_LIMIT")


def collect(ip: str, key_path: Path, timeout: int = 12) -> dict:
    ip = private_watch_ip(ip)
    try:
        with socket.create_connection((ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return fetch_manifest(sock, key_path)
    except (OSError, SdbError, TimeoutError):
        raise ManifestError("SDB_UNAVAILABLE_OR_TIMED_OUT") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--report", type=Path,
                        default=Path.home() / "watch3-r840x-fota-manifest.json")
    args = parser.parse_args()
    try:
        result = collect(args.watch_ip, args.key_path)
        report = args.report.expanduser()
        if not report.parent.is_dir():
            raise ManifestError("REPORT_DIRECTORY_MISSING")
        payload = (json.dumps(result, indent=2) + "\n").encode("utf-8")
        try:
            fd = os.open(str(report), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise ManifestError("REPORT_ALREADY_EXISTS") from None
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            report.unlink(missing_ok=True)
            raise
    except (ManifestError, OSError, SdbError) as exc:
        reason = str(exc) if isinstance(exc, ManifestError) else "LOCAL_OR_CONFIG_ERROR"
        print("MANIFEST_ERROR: " + reason, file=sys.stderr)
        return 1
    print("READ_ONLY_FOTA_MANIFEST: " + str(report))
    print("NO device writes, service execution, D-Bus calls or firmware modification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
