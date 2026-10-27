#!/usr/bin/env python3
"""Read one allowlisted Watch3 FOTA executable over authenticated SDB sync.

This is a bounded, host-local *read* of a normal Tizen application file.
No SDB push, shell, install, flash, bootloader mode, root or watch write exists.
The executable's path is a sibling-watch hypothesis, NOT proven on R840X.

The binary stays on the owner's phone for offline analysis. Do not upload it
to GitHub, and do not run it in Termux or on the watch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile

from watch3_r08_android_sdb import (
    Connection, SdbError, PORT, private_watch_ip, receive,
)

# Seen in a published Tizen wearable package inventory; exact R840X presence
# is to be observed, not assumed.
FOTA_EXECUTABLE = b"/usr/apps/com.samsung.fota-consumer/bin/fota-service"
LOCAL_STREAM = 17
MAX_BINARY_BYTES = 8 * 1024 * 1024
MAX_SYNC_CHUNK = 256 * 1024
MAX_STREAM_FRAMES = 1024
SYNC_HDR = struct.Struct("<4sI")


class ArtifactPullError(ValueError):
    """Categorical failure; never includes raw watch data or private addresses."""


class ReadOnlySyncDecoder:
    """Streaming decoder of adb/SDB sync RECV DATA/DONE or FAIL packets."""

    def __init__(self, out):
        self.out = out
        self.digest = hashlib.sha256()
        self.byte_count = 0
        self.head = bytearray()
        self.buf = bytearray()
        self.pending = None
        self.done = False

    def feed(self, piece: bytes) -> None:
        if self.done:
            raise ArtifactPullError("INVALID_SYNC_TRAILING_DATA")
        self.buf.extend(piece)
        while True:
            if self.pending is None:
                if len(self.buf) < SYNC_HDR.size:
                    return
                tag, size = SYNC_HDR.unpack(self.buf[:SYNC_HDR.size])
                del self.buf[:SYNC_HDR.size]
                if tag == b"DONE":
                    if size != 0 or self.buf or self.byte_count == 0:
                        raise ArtifactPullError("INVALID_SYNC_DONE")
                    self.done = True
                    return
                if tag not in (b"DATA", b"FAIL"):
                    raise ArtifactPullError("UNEXPECTED_SYNC_RESPONSE")
                if size > (MAX_SYNC_CHUNK if tag == b"DATA" else 512):
                    raise ArtifactPullError("UNBOUNDED_SYNC_MESSAGE")
                if tag == b"DATA" and self.byte_count + size > MAX_BINARY_BYTES:
                    raise ArtifactPullError("REMOTE_FILE_EXCEEDS_EIGHT_MIB")
                self.pending = (tag, size)
            tag, size = self.pending
            if len(self.buf) < size:
                return
            part = bytes(self.buf[:size])
            del self.buf[:size]
            self.pending = None
            if tag == b"FAIL":
                # The response might contain system paths or private data.
                raise ArtifactPullError("REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE")
            if self.byte_count + len(part) > MAX_BINARY_BYTES:
                raise ArtifactPullError("REMOTE_FILE_EXCEEDS_EIGHT_MIB")
            self.byte_count += len(part)
            self.digest.update(part)
            self.out.write(part)
            if len(self.head) < 20:
                self.head.extend(part[:20 - len(self.head)])

    def elf_kind(self) -> str:
        h = self.head
        if len(h) < 20 or h[:4] != b"\x7fELF" or h[5] != 1:
            raise ArtifactPullError("READ_BYTES_ARE_NOT_LITTLE_ENDIAN_ELF")
        machine = int.from_bytes(h[18:20], "little")
        if h[4] == 1 and machine == 40:
            return "ARM_ELF32"
        if h[4] == 2 and machine == 183:
            return "AARCH64_ELF64"
        raise ArtifactPullError("UNEXPECTED_ELF_ARCHITECTURE")


def pull_fota(sock, key_path: Path, outfile) -> dict[str, object]:
    """Use only SDB OPEN sync:, WRTE RECV exact allowlisted path, OKAY/CLSE."""
    channel = Connection(sock, key_path)
    channel.handshake()
    channel.send(b"OPEN", LOCAL_STREAM, 0, b"sync:\x00")
    kind, remote, local, body = receive(sock)
    if kind == b"CLSE" and local == LOCAL_STREAM:
        raise ArtifactPullError("SDB_SYNC_SERVICE_REFUSED")
    if (kind != b"OKAY" or local != LOCAL_STREAM or remote == 0 or body):
        raise ArtifactPullError("SDB_SYNC_OPEN_NOT_ACKNOWLEDGED")
    path = FOTA_EXECUTABLE
    # RECV is read-only by specification. SEND/STAT/DELETE are never sent.
    channel.send(b"WRTE", LOCAL_STREAM, remote,
                 SYNC_HDR.pack(b"RECV", len(path)) + path)
    decoder = ReadOnlySyncDecoder(outfile)
    for _ in range(MAX_STREAM_FRAMES):
        kind, arg0, arg1, body = receive(sock)
        if arg0 != remote or arg1 != LOCAL_STREAM:
            raise ArtifactPullError("SDB_SYNC_STREAM_ID_MISMATCH")
        if kind == b"OKAY":
            continue
        if kind == b"CLSE":
            raise ArtifactPullError("SDB_SYNC_CLOSED_BEFORE_DONE")
        if kind != b"WRTE":
            raise ArtifactPullError("UNEXPECTED_SDB_SYNC_FRAME")
        channel.send(b"OKAY", LOCAL_STREAM, remote)
        decoder.feed(body)
        if decoder.done:
            # Neither send a second request nor persist anything to the watch.
            break
    if not decoder.done:
        raise ArtifactPullError("SDB_SYNC_DID_NOT_COMPLETE")
    elf = decoder.elf_kind()
    return {
        "schema": "uglyos-r840x-sdb-fota-artifact-v1",
        "status": "READABLE_BINARY_COPIED_FROM_AUTHENTICATED_SDB",
        "candidate": "com.samsung.fota-consumer/fota-service",
        "bytes": decoder.byte_count,
        "sha256": decoder.digest.hexdigest(),
        "elf_kind": elf,
        "target_model_authenticated": False,
        "root_obtained": False,
        "custom_kernel_boot_proven": False,
        "stock_recovery_proven": False,
        "watch_write_performed": False,
        "notice": "A retrieved ELF is a research input, not a boot method or exploit.",
    }


def capture(ip: str, key_path: Path, destination: Path, timeout: int = 12) -> dict[str, object]:
    """Write output on the phone only, atomically, and never replace it."""
    ip = private_watch_ip(ip)
    destination = destination.expanduser()
    if destination.exists() or destination.is_symlink():
        raise ArtifactPullError("LOCAL_OUTPUT_ALREADY_EXISTS")
    if not destination.parent.is_dir():
        raise ArtifactPullError("LOCAL_OUTPUT_DIRECTORY_MISSING")
    fd, temporary = tempfile.mkstemp(prefix=".watch3-fota-readonly-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as outfile:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                result = pull_fota(sock, key_path, outfile)
            outfile.flush()
            os.fsync(outfile.fileno())
        # This check protects an existing local file. It does NOT update the watch.
        if destination.exists() or destination.is_symlink():
            raise ArtifactPullError("LOCAL_OUTPUT_ALREADY_EXISTS")
        os.rename(temporary, destination)
        return result
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True, help="Current local Watch3 Wi-Fi IP")
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--output", type=Path,
                        default=Path.home() / "watch3-r840x-fota-service-readonly.bin",
                        help="New private *phone* file; will not overwrite")
    args = parser.parse_args()
    try:
        report = capture(args.watch_ip, args.key_path, args.output)
    except (ArtifactPullError, SdbError, OSError, TimeoutError) as exc:
        # Never print a remote server error, watch IDs, addresses or binary data.
        reason = str(exc) if isinstance(exc, ArtifactPullError) else "SDB_UNAVAILABLE_OR_REJECTED"
        print("NO_ARTIFACT: " + reason, file=sys.stderr)
        return 1
    report_path = Path.home() / "watch3-r840x-fota-artifact-evidence.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    os.chmod(report_path, 0o600)
    print("READ_ONLY_ARTIFACT_RECEIVED: " + str(args.output.expanduser()))
    print("REPORT: " + str(report_path))
    print("NO root, exploit, bootloader access or stock recovery proven.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
