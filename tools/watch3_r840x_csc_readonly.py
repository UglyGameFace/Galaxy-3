#!/usr/bin/env python3
"""Read exactly one Tizen active-CSC file via existing read-only SDB sync RECV.

No arbitrary remote path, shell, Samsung CSC change code, FOTA, Odin,
partition access or watch writes. Referenced path was observed on an
SM-R805U Tizen Watch; may not exist / be readable on SM-R840X LDU.
This read reports one strictly bounded 3-character CSC candidate,
NOT a validated stock firmware region or flashing authorization.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import re
import socket
import sys

from watch3_r08_android_sdb import Connection, PORT, SdbError, private_watch_ip, receive
from watch3_r08_fota_artifact_pull import (
    ArtifactPullError, LOCAL_STREAM, MAX_STREAM_FRAMES, ReadOnlySyncDecoder, SYNC_HDR,
)

SOURCE_REPOSITORY = "sbose78/tizen-watch-internals"
SOURCE_COMMIT = "3dcd79ca586827ea2fde9a5a23170a79d1a8e2dd"
CSC_PATH = b"/opt/system/csc-default/output/csc-active-customer.log"
MAX_CSC_BYTES = 128
ACTIVE_CODE = re.compile(r"[A-Z0-9]{3}\Z")
SCHEMA = "uglyos-r840x-csc-fixed-sdb-read-v1"

class CscError(ValueError):
    """One of the sanitized, categorical read-only failure codes."""

class CscSink(io.BytesIO):
    """Hard limit applied before storing local file contents in memory."""

    def write(self, chunk: bytes) -> int:
        if self.tell() + len(chunk) > MAX_CSC_BYTES:
            raise CscError("CSC_LOG_BYTE_LIMIT_EXCEEDED")
        return super().write(chunk)


def parse_active_csc(raw: bytes) -> dict:
    """Use only an exact, single 3-character record. No serials/log dumps."""
    if not raw:
        return {"state": "CSC_LOG_EMPTY_OR_UNRECOGNIZED", "candidate_code": None}
    if len(raw) > MAX_CSC_BYTES:
        return {"state": "CSC_LOG_TOO_LARGE", "candidate_code": None}
    try:
        content = raw.decode("ascii")
    except UnicodeDecodeError:
        return {"state": "CSC_LOG_UNRECOGNIZED_CONTENT", "candidate_code": None}
    # Do not search for an arbitrary 3-letter substring in an unknown file:
    # it might be a person's name, device secret or misleading message.
    normalized = content.removesuffix("\n").removesuffix("\r")
    if not ACTIVE_CODE.fullmatch(normalized):
        return {"state": "CSC_LOG_UNRECOGNIZED_CONTENT", "candidate_code": None}
    if normalized == "XXX":
        return {"state": "CSC_PLACEHOLDER_NOT_REAL_REGION", "candidate_code": None}
    return {
        "state": "ACTIVE_CSC_CANDIDATE_READ_FROM_EXACT_TIZEN_PATH",
        "candidate_code": normalized,
    }


def fetch_fixed_csc(sock, key_path: Path) -> bytes:
    """Only SDB sync:RECV /opt/system/csc-default/output/csc-active-customer.log."""
    conn = Connection(sock, key_path)
    try:
        conn.handshake()
        conn.send(b"OPEN", LOCAL_STREAM, 0, b"sync:\x00")
        kind, remote, local, body = receive(sock)
    except (SdbError, OSError, TimeoutError):
        raise CscError("SDB_HANDSHAKE_OR_SYNC_OPEN_FAILED") from None
    if kind == b"CLSE" and local == LOCAL_STREAM:
        raise CscError("SDB_SYNC_SERVICE_REFUSED")
    if kind != b"OKAY" or local != LOCAL_STREAM or remote == 0 or body:
        raise CscError("SDB_SYNC_OPEN_INVALID")
    try:
        conn.send(b"WRTE", LOCAL_STREAM, remote,
                  SYNC_HDR.pack(b"RECV", len(CSC_PATH)) + CSC_PATH)
    except (SdbError, OSError, TimeoutError):
        raise CscError("SDB_FIXED_CSC_RECV_SEND_FAILED") from None
    sink = CscSink()
    decoder = ReadOnlySyncDecoder(sink)
    for _ in range(MAX_STREAM_FRAMES):
        try:
            kind, sender, receiver, body = receive(sock)
        except (SdbError, OSError, TimeoutError):
            raise CscError("SDB_FIXED_CSC_TRANSFER_INCOMPLETE") from None
        if sender != remote or receiver != LOCAL_STREAM:
            raise CscError("SDB_FIXED_CSC_STREAM_MISMATCH")
        if kind == b"OKAY":
            continue
        if kind == b"CLSE":
            raise CscError("SDB_CLOSED_BEFORE_CSC_RESULT")
        if kind != b"WRTE":
            raise CscError("SDB_UNEXPECTED_FRAME")
        try:
            conn.send(b"OKAY", LOCAL_STREAM, remote)
            decoder.feed(body)
        except ArtifactPullError as exc:
            if str(exc) == "REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE":
                raise CscError("CSC_FILE_MISSING_DENIED_OR_UNREADABLE") from None
            raise CscError("INVALID_CSC_SYNC_STREAM") from None
        except (SdbError, OSError, TimeoutError):
            raise CscError("SDB_FIXED_CSC_TRANSFER_INCOMPLETE") from None
        if decoder.done:
            return sink.getvalue()
    raise CscError("SDB_CSC_FRAME_LIMIT")


def report_base() -> dict:
    return {
        "schema": SCHEMA,
        "status": "CSC_NOT_YET_CONFIRMED",
        "model": "SM-R840X",
        "installed_build": "R840XXXU1AUA2",
        "source_watch_model": "SM-R805U",
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": SOURCE_COMMIT,
        "remote_path": CSC_PATH.decode("ascii"),
        "observed_active_csc_candidate": None,
        "state": "NOT_ATTEMPTED",
        "note": ("This same CSC path was physically observed on the owner's "
                 "SM-R840X on 2026-10-27, with active value PAP. This "
                 "single read reports the current three-character Tizen CSC "
                 "only; it does NOT establish original factory region, "
                 "signed firmware compatibility or stock rescue proof."),
        "watch_write_performed": False,
        "odin_session_started": False,
        "pit_requested": False,
        "firmware_written": False,
        "full_stock_recovery_proven": False,
        "flash_allowed": False,
    }


def collect(ip: str, key_path: Path, *, timeout: int = 12) -> dict:
    result = report_base()
    private_ip = private_watch_ip(ip)
    try:
        with socket.create_connection((private_ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = fetch_fixed_csc(sock, key_path)
        parsed = parse_active_csc(raw)
        result["state"] = parsed["state"]
        result["observed_active_csc_candidate"] = parsed["candidate_code"]
        if parsed["candidate_code"]:
            result["status"] = "CSC_CANDIDATE_FROM_OWNER_WATCH_FIXED_PATH"
    except CscError as exc:
        result["state"] = str(exc)
    except (SdbError, OSError, TimeoutError):
        result["state"] = "SDB_UNAVAILABLE_OR_NETWORK_ERROR"
    return result


def write_report(path: Path, report: dict) -> None:
    if not path.parent.is_dir():
        raise CscError("LOCAL_REPORT_PARENT_MISSING")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--watch-ip", help="Currently displayed private Tizen watch Wi-Fi IP")
    mode.add_argument("--offline-sample", type=Path,
                      help="LOCAL small CSC text fixture; ZERO watch/network interaction")
    p.add_argument("--key-path", type=Path,
                   default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    p.add_argument("--output", type=Path,
                   default=Path.home() / "watch3-r840x-csc-redacted.json")
    args = p.parse_args(argv)
    try:
        # A stale report must not cause even an unnecessary extra watch read.
        destination = args.output.expanduser()
        if destination.exists() or destination.is_symlink():
            raise CscError("LOCAL_REPORT_ALREADY_EXISTS")
        if not destination.parent.is_dir():
            raise CscError("LOCAL_REPORT_PARENT_MISSING")
        if args.offline_sample:
            sample = args.offline_sample.expanduser()
            if sample.is_symlink() or not sample.is_file() or sample.stat().st_size > MAX_CSC_BYTES:
                raise CscError("LOCAL_CSC_SAMPLE_NOT_REGULAR_OR_TOO_LARGE")
            raw = sample.read_bytes()
            parsed = parse_active_csc(raw)
            result = report_base()
            result["state"] = "OFFLINE_SAMPLE_" + parsed["state"]
            result["observed_active_csc_candidate"] = None
            result["note"] = "Offline sample only. No actual R840X CSC was observed."
        else:
            result = collect(args.watch_ip, args.key_path.expanduser())
        write_report(args.output.expanduser(), result)
    except (CscError, OSError, SdbError) as exc:
        reason = str(exc) if isinstance(exc, CscError) else "LOCAL_REPORT_OR_WATCH_IP_ERROR"
        print("CSC_PROBE_ERROR: " + reason, file=sys.stderr)
        return 1
    print("CSC_READONLY_RESULT: " + str(args.output.expanduser()))
    print("CSC_STATE: " + result["state"])
    if result["observed_active_csc_candidate"]:
        print("CSC_CANDIDATE: " + result["observed_active_csc_candidate"])
    print("NO CSC modification, Odin command, firmware write or flash authorization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
