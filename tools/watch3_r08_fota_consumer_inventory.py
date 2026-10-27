#!/usr/bin/env python3
"""Inventory fixed, allowlisted Watch3 FOTA directories via read-only SDB sync LIST.

READ ONLY: No SDB shell, SEND, push, process launch, FOTA request, reboot,
partition access, arbitrary remote path, or writes to the watch. Report is
private on the owner's phone. Does not use Linux shell directory permissions.
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

from watch3_r08_android_sdb import Connection, PORT, private_watch_ip, receive

SYNC_HDR = struct.Struct("<4sI")
SYNC_DENT = struct.Struct("<4sIIII")
LOCAL_STREAM = 23
MAX_DENTS = 256
MAX_LIST_BYTES = 512 * 1024
MAX_NAME_BYTES = 192
MAX_FRAMES = 1024

# The source binary confirms this package and the FOTA save directory.
# These are fixed literal paths; callers cannot request arbitrary paths.
DIRECTORIES = {
    "consumer_binary_directory": b"/usr/apps/com.samsung.fota-consumer/bin",
    "fota_save_directory": b"/opt/usr/data/fota/save",
}
# Standard D-Bus activation directories per dbus.freedesktop.org specification.
# These are hypothesis locations; only the named service is reported.
# Do not infer service absence if LIST is empty, denied, or inconclusive.
DBUS_DIRECTORIES = {
    "dbus_system_vendor": b"/usr/share/dbus-1/system-services",
    "dbus_system_override": b"/etc/dbus-1/system-services",
    "dbus_session_vendor": b"/usr/share/dbus-1/services",
}
DBUS_ACTIVATION_FILENAME = "fota.consumer.service"
# The owner's actual fota-service ELF pins the package's bin directory;
# Samsung's published Tizen package layout places the manifest in the root.
# The RECV of this exact manifest returned FAIL on the physical watch.
# One direct parent LIST is more informative than guessing alternative paths.
PACKAGE_ROOT_DIRECTORY = b"/usr/apps/com.samsung.fota-consumer"
PACKAGE_ROOT_SCOPE = "fota_package_root"
PACKAGE_MANIFEST_FILENAME = "tizen-manifest.xml"
# Tizen native RPM example Cobalt places package executable under /usr/apps
# while registering <package-id>.xml under /usr/share/packages.
# Tizen web/hybrid package docs identify /opt/share/packages instead.
# Both are bounded read-only hypotheses for this Samsung platform package.
# refs: cobalt.googlesource.com/cobalt/+/refs/heads/release_11/src/starboard/tizen/packaging/com.youtube.cobalt.spec
# https://github.com/Samsung/tizen-docs/blob/master/docs/application/web/index.md
PACKAGE_INDEX_DIRECTORIES = {
    "system_package_registry": b"/usr/share/packages",
    "opt_package_registry": b"/opt/share/packages",
}
PACKAGE_INDEX_FILENAME = "com.samsung.fota-consumer.xml"
# Owner-verified original 2,215-byte installed XML declares exactly
# "accessory-services-location=/res/xml/appcessoryservices.xml".
# Preserve Samsung's unusual spelling (appcessory, NOT accessory).
SAP_RESOURCE_SCOPE = "fota_sap_profile_directory"
SAP_RESOURCE_DIRECTORY = b"/usr/apps/com.samsung.fota-consumer/res/xml"
SAP_RESOURCE_FILENAME = "appcessoryservices.xml"

# Tizen platform white paper defines these vendor daemon unit paths.
# /etc/systemd/system is the standard systemd override directory.
SYSTEMD_DIRECTORIES = {
    "fota_systemd_vendor_system": b"/usr/lib/systemd/system",
    "fota_systemd_vendor_user": b"/usr/lib/systemd/user",
    "fota_systemd_override": b"/etc/systemd/system",
}
SYSTEMD_FOTA_UNIT = re.compile(
    r"[a-z0-9_.@-]{0,80}(?:fota|firmware|update)[a-z0-9_.@-]{0,40}"
    r"\.(?:service|socket|target|timer)\Z",
    re.IGNORECASE,
)
MAX_SYSTEMD_DENTS = 1024
MAX_REPORTED_FOTA_UNITS = 32
MAX_PACKAGE_INDEX_DENTS = 2048
CANDIDATE_NAME = re.compile(r"(?:fota|update)[a-z0-9._-]{0,63}\Z")
EXACT_BIN_NAMES = frozenset((
    "fota-service", "fota-consumer", "fota_consumer",
    "fota.consumer", "fota_updater", "fota-updater",
))
FILE_TYPE_NAMES = {
    stat.S_IFREG: "REGULAR_FILE",
    stat.S_IFDIR: "DIRECTORY",
    stat.S_IFLNK: "SYMLINK",
}


class InventoryError(ValueError):
    """A known, non-private failure category."""


def mode_kind(mode: int) -> str:
    return FILE_TYPE_NAMES.get(stat.S_IFMT(mode), "OTHER")


class DirectoryDecoder:
    """Streaming parser for sync-v1 DENT (20-byte header)/DONE (20-byte)."""

    def __init__(self):
        self.buffer = bytearray()
        self.pending = None
        self.total = 0
        self.count = 0
        self.finished = False
        self.candidates = {}
        self.archive = None

    def feed(self, part: bytes, scope: str) -> None:
        if self.finished:
            raise InventoryError("UNEXPECTED_DATA_AFTER_DONE")
        self.total += len(part)
        if self.total > MAX_LIST_BYTES:
            raise InventoryError("LIST_SIZE_LIMIT_REACHED")
        self.buffer.extend(part)
        while True:
            if self.pending is None:
                if len(self.buffer) < 8:
                    return
                tag = bytes(self.buffer[:4])
                if tag == b"FAIL":
                    _, n = SYNC_HDR.unpack(self.buffer[:8])
                    if n > 512:
                        raise InventoryError("MALFORMED_SYNC_ERROR")
                    if len(self.buffer) < 8 + n:
                        return
                    # Do not leak returned path, filename, UID or error details.
                    raise InventoryError("DIRECTORY_LIST_DENIED_OR_UNSUPPORTED")
                if tag not in (b"DENT", b"DONE"):
                    raise InventoryError("UNEXPECTED_SYNC_REPLY")
                if len(self.buffer) < SYNC_DENT.size:
                    return
                _, mode, size, mtime, namelen = SYNC_DENT.unpack(self.buffer[:20])
                if tag == b"DONE":
                    if mode or size or mtime or namelen or len(self.buffer) != 20:
                        raise InventoryError("INVALID_SYNC_LIST_DONE")
                    self.buffer.clear()
                    self.finished = True
                    return
                if namelen == 0 or namelen > MAX_NAME_BYTES:
                    raise InventoryError("INVALID_DIRECTORY_NAME_LENGTH")
                del self.buffer[:20]
                self.pending = (mode, size, namelen)
            mode, size, namelen = self.pending
            if len(self.buffer) < namelen:
                return
            rawname = bytes(self.buffer[:namelen])
            del self.buffer[:namelen]
            self.pending = None
            self.count += 1
            if self.count > (MAX_PACKAGE_INDEX_DENTS
                             if scope in PACKAGE_INDEX_DIRECTORIES else
                             MAX_SYSTEMD_DENTS if scope in SYSTEMD_DIRECTORIES else
                             MAX_DENTS):
                raise InventoryError("DIRECTORY_ENTRY_LIMIT_REACHED")
            # Privacy gate: only small, plain-ASCII, non-hidden system names.
            # Never serialize unknown or private directory entries.
            try:
                name = rawname.decode("ascii")
            except UnicodeDecodeError:
                continue
            if (not name or name in (".", "..") or name.startswith(".") or
                    "/" in name or "\\" in name or
                    not name.isascii()):
                continue
            if scope == "consumer_binary_directory":
                if name in EXACT_BIN_NAMES or CANDIDATE_NAME.fullmatch(name):
                    self.candidates[name] = {
                        "kind": mode_kind(mode),
                        "executable_by_someone_dac": bool(mode & 0o111),
                        "bytes": size if size <= 8 * 1024 * 1024 else "OVER_8_MIB",
                    }
            elif scope in SYSTEMD_DIRECTORIES and SYSTEMD_FOTA_UNIT.fullmatch(name):
                if len(self.candidates) < MAX_REPORTED_FOTA_UNITS:
                    self.candidates[name] = {
                        "kind": mode_kind(mode),
                        "bytes": size if size <= 64 * 1024 else "OVER_64_KIB",
                    }
            elif scope == SAP_RESOURCE_SCOPE and name == SAP_RESOURCE_FILENAME:
                self.candidates[name] = {
                    "kind": mode_kind(mode),
                    "bytes": size if size <= 64 * 1024 else "OVER_64_KIB",
                }
            elif scope in PACKAGE_INDEX_DIRECTORIES and name == PACKAGE_INDEX_FILENAME:
                self.candidates[name] = {
                    "kind": mode_kind(mode),
                    "bytes": size if size <= 64 * 1024 else "OVER_64_KIB",
                    "readable_by_someone_dac": bool(mode & 0o444),
                }
            elif scope == PACKAGE_ROOT_SCOPE and name == PACKAGE_MANIFEST_FILENAME:
                self.candidates[name] = {
                    "kind": mode_kind(mode),
                    "bytes": size if size <= 64 * 1024 else "OVER_64_KIB",
                    "readable_by_someone_dac": bool(mode & 0o444),
                }
            elif scope in DBUS_DIRECTORIES and name == DBUS_ACTIVATION_FILENAME:
                self.candidates[name] = {
                    "kind": mode_kind(mode),
                    "bytes": size if size <= 64 * 1024 else "OVER_64_KIB",
                }
            elif scope == "fota_save_directory" and name == "delta.tar":
                self.archive = {
                    "kind": mode_kind(mode),
                    "owner_writable_dac": bool(mode & stat.S_IWUSR),
                    "group_writable_dac": bool(mode & stat.S_IWGRP),
                    "other_writable_dac": bool(mode & stat.S_IWOTH),
                    "bytes": size if size <= 8 * 1024 * 1024 else "OVER_8_MIB",
                }

    def report(self, scope: str) -> dict:
        if not self.finished:
            raise InventoryError("DIRECTORY_LIST_NOT_COMPLETED")
        if scope == "consumer_binary_directory":
            return {
                "status": "LIST_COMPLETE" if self.count else "EMPTY_OR_INACCESSIBLE",
                "matching_executable_candidates": self.candidates,
                "other_or_unreported_entries": max(0, self.count - len(self.candidates)),
                "meaning": ("Only names beginning fota/update are shown. "
                            "Missing candidate is not proof an updater is absent."),
            }
        if scope in SYSTEMD_DIRECTORIES:
            return {
                "status": "LIST_COMPLETE" if self.count else "EMPTY_OR_INACCESSIBLE",
                "matching_fota_unit_files": self.candidates,
                "matching_names_truncated": len(self.candidates) >= MAX_REPORTED_FOTA_UNITS,
                "other_or_unreported_entries": max(0, self.count - len(self.candidates)),
                "meaning": ("Only bounded FOTA/firmware/update systemd unit names "
                            "are exposed. Nonmatches, alternate names and dynamic "
                            "D-Bus ownership remain outside this evidence."),
            }
        if scope == SAP_RESOURCE_SCOPE:
            return {
                "status": "LIST_COMPLETE" if self.count else "EMPTY_OR_INACCESSIBLE",
                "declared_sap_profile_xml": self.candidates.get(
                    SAP_RESOURCE_FILENAME, "NOT_SEEN_IN_LIST"),
                "other_or_unreported_entries": max(0, self.count - len(self.candidates)),
                "meaning": ("Only the exact appcessoryservices.xml name declared by "
                            "Samsung's installed package XML is disclosed. The SAP "
                            "peer profile does not identify the D-Bus FOTA receiver."),
            }
        if scope in PACKAGE_INDEX_DIRECTORIES:
            return {
                "status": "LIST_COMPLETE" if self.count else "EMPTY_OR_INACCESSIBLE",
                "fota_package_xml": self.candidates.get(
                    PACKAGE_INDEX_FILENAME, "NOT_SEEN_IN_LIST"),
                "other_or_unreported_entries": max(0, self.count - len(self.candidates)),
                "meaning": ("Only exact com.samsung.fota-consumer.xml metadata is shown. "
                            "A complete negative listing applies to this directory only; "
                            "platform registration may use other locations or mechanisms. "
                            "DAC read bits are not proof of permission under Tizen SMACK."),
            }
        if scope == PACKAGE_ROOT_SCOPE:
            return {
                "status": "LIST_COMPLETE" if self.count else "EMPTY_OR_INACCESSIBLE",
                "tizen_manifest": self.candidates.get(
                    PACKAGE_MANIFEST_FILENAME, "NOT_SEEN_IN_LIST"),
                "other_or_unreported_entries": max(0, self.count - len(self.candidates)),
                "meaning": ("Only exact tizen-manifest.xml metadata is shown; "
                            "LIST_COMPLETE without it means the filename was not seen "
                            "at this one package root. An empty listing, failed LIST, "
                            "or missing filename is not proof of absent package metadata "
                            "elsewhere. DAC bits cannot prove access under Tizen SMACK."),
            }
        if scope in DBUS_DIRECTORIES:
            return {
                "status": "LIST_COMPLETE" if self.count else "EMPTY_OR_INACCESSIBLE",
                "fota_consumer_activation_file": (
                    self.candidates.get(DBUS_ACTIVATION_FILENAME, "NOT_SEEN_IN_LIST")
                ),
                "other_or_unreported_entries": max(0, self.count - len(self.candidates)),
                "meaning": ("Only the exact fota.consumer.service filename is reported. "
                            "Absent listing does not exclude dynamic D-Bus name ownership, "
                            "nonstandard activation paths, or restricted listings."),
            }
        return {
            "status": "LIST_COMPLETE" if self.count else "EMPTY_OR_INACCESSIBLE",
            "delta_tar": self.archive or "NOT_SEEN_IN_LIST",
            "meaning": ("POSIX DAC mode bits do not override Tizen SMACK, ACLs "
                        "or directory permissions; no modification attempted."),
        }


def list_one(sock, key_path: Path, scope: str) -> dict:
    """Issue exactly one fixed LIST on already-authorized SDB sync."""
    if scope == SAP_RESOURCE_SCOPE:
        path = SAP_RESOURCE_DIRECTORY
    elif scope == PACKAGE_ROOT_SCOPE:
        path = PACKAGE_ROOT_DIRECTORY
    elif scope in DIRECTORIES:
        path = DIRECTORIES[scope]
    elif scope in DBUS_DIRECTORIES:
        path = DBUS_DIRECTORIES[scope]
    elif scope in PACKAGE_INDEX_DIRECTORIES:
        path = PACKAGE_INDEX_DIRECTORIES[scope]
    elif scope in SYSTEMD_DIRECTORIES:
        path = SYSTEMD_DIRECTORIES[scope]
    else:
        raise InventoryError("SCOPE_NOT_ALLOWED")
    conn = Connection(sock, key_path)
    conn.handshake()
    conn.send(b"OPEN", LOCAL_STREAM, 0, b"sync:\x00")
    kind, remote, local, body = receive(sock)
    if kind == b"CLSE" and local == LOCAL_STREAM:
        raise InventoryError("SYNC_SERVICE_REFUSED")
    if kind != b"OKAY" or local != LOCAL_STREAM or remote == 0 or body:
        raise InventoryError("SYNC_OPEN_FAILED")
    conn.send(b"WRTE", LOCAL_STREAM, remote, SYNC_HDR.pack(b"LIST", len(path)) + path)
    decoder = DirectoryDecoder()
    for _ in range(MAX_FRAMES):
        kind, remote_id, local_id, body = receive(sock)
        if remote_id != remote or local_id != LOCAL_STREAM:
            raise InventoryError("SDB_STREAM_MISMATCH")
        if kind == b"OKAY":
            continue
        if kind == b"CLSE":
            raise InventoryError("SDB_CLOSED_BEFORE_LIST_DONE")
        if kind != b"WRTE":
            raise InventoryError("SDB_UNEXPECTED_FRAME")
        conn.send(b"OKAY", LOCAL_STREAM, remote)
        decoder.feed(body, scope)
        if decoder.finished:
            return decoder.report(scope)
    raise InventoryError("SDB_LIST_FRAME_LIMIT")


def inventory(ip: str, key_path: Path, timeout: int = 12,
              *, dbus_services_only: bool = False,
              fota_package_root_only: bool = False,
              fota_package_index_only: bool = False,
              fota_handoff_index_only: bool = False) -> dict:
    if sum((dbus_services_only, fota_package_root_only,
            fota_package_index_only, fota_handoff_index_only)) > 1:
        raise InventoryError("SCOPES_MUTUALLY_EXCLUSIVE")
    ip = private_watch_ip(ip)
    scopes = {}
    active_scopes = (list(SYSTEMD_DIRECTORIES) + [SAP_RESOURCE_SCOPE]
                     if fota_handoff_index_only else
                     PACKAGE_INDEX_DIRECTORIES if fota_package_index_only else
                     [PACKAGE_ROOT_SCOPE] if fota_package_root_only else
                     DBUS_DIRECTORIES if dbus_services_only else DIRECTORIES)
    for scope in active_scopes:
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                scopes[scope] = list_one(sock, key_path, scope)
        except InventoryError as exc:
            scopes[scope] = {"status": str(exc)}
        except (OSError, TimeoutError, ValueError):
            scopes[scope] = {"status": "SDB_UNAVAILABLE"}
    return {
        "schema": ("uglyos-r840x-fota-handoff-index-v1"
                   if fota_handoff_index_only else
                   "uglyos-r840x-fota-package-index-v1"
                   if fota_package_index_only else
                   "uglyos-r840x-fota-root-manifest-list-v1"
                   if fota_package_root_only else
                   "uglyos-r840x-fota-dbus-activation-v1" if dbus_services_only
                   else "uglyos-r840x-fota-consumer-inventory-v1"),
        "status": ("READ_ONLY_FOTA_HANDOFF_INDEX" if fota_handoff_index_only
                   else "READ_ONLY_FIXED_PACKAGE_INDEX_LIST" if fota_package_index_only
                   else "READ_ONLY_FIXED_PACKAGE_ROOT_LIST" if fota_package_root_only
                   else "READ_ONLY_FIXED_DBUS_DIRECTORY_INVENTORY" if dbus_services_only
                   else "READ_ONLY_FIXED_DIRECTORY_INVENTORY"),
        "directory_results": scopes,
        "known_fota_service_sha256":
            "008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757",
        "consumer_binary_retrieved": False,
        "root_obtained": False,
        "fota_cve_exploited": False,
        "unsigned_kernel_boot_proven": False,
        "stock_recovery_proven": False,
        "watch_write_performed": False,
        "interpretation": ("Directory listings are passive metadata, not proof of "
                           "consumer launch permissions, SMACK access or update validity."),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dbus-services-only", action="store_true",
                      help="List only fixed standard D-Bus activation directories")
    mode.add_argument("--fota-package-root-only", action="store_true",
                      help="LIST only the known FOTA package root for tizen-manifest.xml")
    mode.add_argument("--fota-package-index-only", action="store_true",
                      help="LIST two fixed Tizen package registry directories for exact FOTA XML")
    mode.add_argument("--fota-handoff-index-only", action="store_true",
                      help="LIST three Tizen daemon unit directories and one XML-declared SAP directory")
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--report", type=Path,
                        default=Path.home() / "watch3-r840x-fota-consumer-inventory.json")
    args = parser.parse_args()
    try:
        result = inventory(args.watch_ip, args.key_path,
                           dbus_services_only=args.dbus_services_only,
                           fota_package_root_only=args.fota_package_root_only,
                           fota_package_index_only=args.fota_package_index_only,
                           fota_handoff_index_only=args.fota_handoff_index_only)
        # Default report path remains unchanged for existing callers.
        default_report = Path.home() / "watch3-r840x-fota-consumer-inventory.json"
        path = (Path.home() / "watch3-r840x-fota-handoff-index.json"
                if args.fota_handoff_index_only and args.report == default_report else
                Path.home() / "watch3-r840x-fota-package-index.json"
                if args.fota_package_index_only and args.report == default_report else
                Path.home() / "watch3-r840x-fota-root-manifest-list.json"
                if args.fota_package_root_only and args.report == default_report else
                Path.home() / "watch3-r840x-fota-dbus-services.json"
                if args.dbus_services_only and args.report == default_report
                else args.report.expanduser())
        payload = (json.dumps(result, indent=2) + "\n").encode("utf-8")
        if not path.parent.is_dir():
            raise InventoryError("REPORT_DIRECTORY_MISSING")
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise InventoryError("REPORT_ALREADY_EXISTS") from None
        try:
            with os.fdopen(fd, "wb") as report:
                report.write(payload)
                report.flush()
                os.fsync(report.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    except (InventoryError, OSError) as exc:
        reason = str(exc) if isinstance(exc, InventoryError) else "LOCAL_FILE_ERROR"
        print("INVENTORY_ERROR: " + reason, file=sys.stderr)
        return 1
    print(("READ_ONLY_FOTA_HANDOFF_INDEX: " if args.fota_handoff_index_only
           else "READ_ONLY_FOTA_PACKAGE_INDEX_LIST: " if args.fota_package_index_only
           else "READ_ONLY_FOTA_PACKAGE_ROOT_LIST: " if args.fota_package_root_only
           else "READ_ONLY_DBUS_ACTIVATION_INVENTORY: " if args.dbus_services_only
           else "READ_ONLY_FOTA_DIRECTORY_INVENTORY: ") + str(path))
    print("NO firmware writes, FOTA calls, root, exploit or custom boot attempted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
