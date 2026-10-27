#!/usr/bin/env python3
"""Inventory the fixed Watch3 FOTA package bin directory using read-only SDB sync LIST.

Authenticated SDB, exactly one fixed directory, no shell, arbitrary paths,
remote writes, service activation, install, root, exploit or firmware action.
Only bounded basename metadata is emitted; unrecognized names are redacted.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

from watch3_r08_android_sdb import Connection, PORT, SdbError, private_watch_ip, receive

FOTA_BIN_DIRECTORY = b"/usr/apps/com.samsung.fota-consumer/bin"
LOCAL_STREAM = 19
SYNC_HEADER = struct.Struct("<4sI")
DENT_HEADER = struct.Struct("<4s4I")
MAX_ITEMS = 512
MAX_NAME_LEN = 128
MAX_FRAME_COUNT = 512
MAX_BUFFER = 192 * 1024
CANDIDATE_NAME = re.compile(r"(?i)^[a-z0-9._+-]{1,80}$")
# Only system-package executable basenames containing these concepts are shown.
RELEVANT_NAME = re.compile(r"(?i)(fota|updat|firmware|consumer|recover|install|delta)")


class InventoryError(ValueError):
    """Categorical error that excludes watch paths, names and identifiers."""


def classify_mode(mode: int) -> str:
    kind = stat.S_IFMT(mode)
    return {
        stat.S_IFREG: "REGULAR_FILE",
        stat.S_IFDIR: "DIRECTORY",
        stat.S_IFLNK: "SYMLINK",
    }.get(kind, "OTHER_OR_UNKNOWN")


class SyncListDecoder:
    """Legacy ADB/SDB sync DENT/DONE/FAIL parser, bounded and fragmented-safe."""

    def __init__(self):
        self.buffer = bytearray()
        self.entries = []
        self.total = 0
        self.filtered = 0
        self.done = False

    def feed(self, part: bytes) -> None:
        if self.done:
            if part:
                raise InventoryError("TRAILING_SYNC_DIRECTORY_DATA")
            return
        if len(self.buffer) + len(part) > MAX_BUFFER:
            raise InventoryError("SYNC_DIRECTORY_RESPONSE_TOO_LARGE")
        self.buffer.extend(part)
        while True:
            if len(self.buffer) < 4:
                return
            tag = bytes(self.buffer[:4])
            if tag == b"FAIL":
                if len(self.buffer) < SYNC_HEADER.size:
                    return
                _, length = SYNC_HEADER.unpack_from(self.buffer)
                if length > 512:
                    raise InventoryError("SYNC_FAILURE_RESPONSE_TOO_LARGE")
                if len(self.buffer) < SYNC_HEADER.size + length:
                    return
                # Remote error bytes are deliberately never included in reports.
                raise InventoryError("FOTA_DIRECTORY_MISSING_DENIED_OR_UNREADABLE")
            if tag not in (b"DENT", b"DONE"):
                raise InventoryError("UNEXPECTED_SYNC_DIRECTORY_REPLY")
            if len(self.buffer) < DENT_HEADER.size:
                return
            _, mode, size, mtime, namelen = DENT_HEADER.unpack_from(self.buffer)
            if tag == b"DONE":
                if mode != 0 or size != 0 or mtime != 0 or namelen != 0:
                    raise InventoryError("INVALID_SYNC_DIRECTORY_DONE")
                if len(self.buffer) != DENT_HEADER.size:
                    raise InventoryError("TRAILING_SYNC_DIRECTORY_DATA")
                self.buffer.clear()
                self.done = True
                return
            if not (0 < namelen <= MAX_NAME_LEN):
                raise InventoryError("INVALID_SYNC_DIRECTORY_NAME_SIZE")
            if len(self.buffer) < DENT_HEADER.size + namelen:
                return
            name = bytes(self.buffer[DENT_HEADER.size:DENT_HEADER.size + namelen])
            del self.buffer[:DENT_HEADER.size + namelen]
            self.total += 1
            if self.total > MAX_ITEMS:
                raise InventoryError("SYNC_DIRECTORY_HAS_TOO_MANY_ITEMS")
            try:
                basename = name.decode("ascii")
            except UnicodeDecodeError:
                self.filtered += 1
                continue
            if (basename not in (".", "..")
                    and CANDIDATE_NAME.fullmatch(basename)
                    and RELEVANT_NAME.search(basename)):
                self.entries.append({
                    "name": basename,
                    "kind": classify_mode(mode),
                    "size_bytes": size if stat.S_IFMT(mode) == stat.S_IFREG else None,
                })
            else:
                self.filtered += 1

    def report(self) -> dict[str, object]:
        if not self.done:
            raise InventoryError("SYNC_DIRECTORY_DID_NOT_COMPLETE")
        return {
            "schema": "uglyos-r840x-fota-package-directory-v1",
            "status": "FOTA_PACKAGE_BIN_DIRECTORY_LISTED",
            "directory": FOTA_BIN_DIRECTORY.decode("ascii"),
            "entries": sorted(self.entries, key=lambda item: item["name"]),
            "total_entries": self.total,
            "redacted_other_entries": self.filtered,
            "scope": "One fixed Samsung FOTA package bin directory. A file listed "
                     "does not imply executable reachability or privilege.",
            "root_obtained": False,
            "fota_exploit_proven": False,
            "bootloader_bypass_proven": False,
            "stock_recovery_proven": False,
            "watch_write_performed": False,
        }


def inventory(sock, key_path: Path) -> dict[str, object]:
    """Send exactly one legacy sync LIST; never execute or modify watch files."""
    channel = Connection(sock, key_path)
    channel.handshake()
    channel.send(b"OPEN", LOCAL_STREAM, 0, b"sync:\x00")
    kind, remote, local, body = receive(sock)
    if kind == b"CLSE" and local == LOCAL_STREAM:
        raise InventoryError("SDB_SYNC_DIRECTORY_SERVICE_REFUSED")
    if kind != b"OKAY" or local != LOCAL_STREAM or remote == 0 or body:
        raise InventoryError("SDB_SYNC_DIRECTORY_NOT_ACKNOWLEDGED")
    channel.send(
        b"WRTE", LOCAL_STREAM, remote,
        SYNC_HEADER.pack(b"LIST", len(FOTA_BIN_DIRECTORY)) + FOTA_BIN_DIRECTORY,
    )
    parser = SyncListDecoder()
    for _ in range(MAX_FRAME_COUNT):
        kind, src, dst, payload = receive(sock)
        if src != remote or dst != LOCAL_STREAM:
            raise InventoryError("SDB_DIRECTORY_STREAM_ID_MISMATCH")
        if kind == b"OKAY":
            continue
        if kind == b"CLSE":
            raise InventoryError("SDB_SYNC_DIRECTORY_CLOSED_BEFORE_DONE")
        if kind != b"WRTE":
            raise InventoryError("SDB_UNEXPECTED_DIRECTORY_FRAME")
        channel.send(b"OKAY", LOCAL_STREAM, remote)
        parser.feed(payload)
        if parser.done:
            break
    return parser.report()


def collect(watch_ip: str, key_path: Path, timeout: int = 12) -> dict[str, object]:
    watch_ip = private_watch_ip(watch_ip)
    with socket.create_connection((watch_ip, PORT), timeout=timeout) as connection:
        connection.settimeout(timeout)
        return inventory(connection, key_path)


def main() -> int:
    cmd = argparse.ArgumentParser(description=__doc__)
    cmd.add_argument("--watch-ip", required=True)
    cmd.add_argument("--key-path", type=Path,
                     default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    cmd.add_argument("--report", type=Path,
                     default=Path.home() / "watch3-r840x-fota-package-inventory.json")
    opts = cmd.parse_args()
    try:
        result = collect(opts.watch_ip, opts.key_path)
        if not opts.report.parent.is_dir():
            raise InventoryError("REPORT_DIRECTORY_MISSING")
        payload = (json.dumps(result, indent=2) + "\n").encode("utf-8")
        try:
            fd = os.open(str(opts.report),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise InventoryError("LOCAL_REPORT_ALREADY_EXISTS") from None
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(payload)
                file.flush()
                os.fsync(file.fileno())
        except BaseException:
            opts.report.unlink(missing_ok=True)
            raise
    except (InventoryError, SdbError, OSError, TimeoutError) as exc:
        reason = str(exc) if isinstance(exc, InventoryError) else "SDB_DIRECTORY_UNAVAILABLE"
        print("FOTA_DIRECTORY_NOT_OBSERVED: " + reason, file=sys.stderr)
        return 1
    print("READ_ONLY_FOTA_DIRECTORY_OBSERVED: " + str(opts.report))
    print("No watch writes, payload transfers, firmware updates or root attempted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
