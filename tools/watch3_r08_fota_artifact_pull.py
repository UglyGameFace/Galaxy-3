#!/usr/bin/env python3
"""Copy Watch3 update executables or the consumer's sync-agent dependency.

This is a bounded, host-local *read* of a normal Tizen application file.
Existing executable profiles use only sync RECV. The sync-agent profile uses
the existing sync LIST inventory to locate the library, then copies it.
No watch shell, install, flash, root or device write exists.
The updateclient path is from a public Tizen watch package inventory and
the R840X's earlier update-client directory observation. Its readability
and actual FOTA verification role are not yet proven.

The binary stays on the owner's phone for offline analysis. Do not upload it
to GitHub, and do not run it in Termux or on the watch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
import socket
import struct
import sys
import tempfile
import zipfile

from watch3_r08_android_sdb import (
    Connection, SdbError, PORT, private_watch_ip, receive,
)
from watch3_r08_fota_consumer_inventory import (
    FOTA_LIBRARY_DIRECTORIES, InventoryError, SYNC_AGENT_SONAME, list_one,
)

# Seen in a published Tizen wearable package inventory; exact R840X presence
# is to be observed, not assumed.
FOTA_EXECUTABLE = b"/usr/apps/com.samsung.fota-consumer/bin/fota-service"
# Fixed allowlist, not arbitrary watch paths. Preserve the existing default.
EXECUTABLES = {
    "fota-service": FOTA_EXECUTABLE,
    "updateclient": b"/usr/apps/com.samsung.tizen.update-client/bin/updateclient",
}
LOCAL_STREAM = 17
MAX_BINARY_BYTES = 8 * 1024 * 1024
MAX_SYNC_CHUNK = 256 * 1024
MAX_STREAM_FRAMES = 1024
SYNC_HDR = struct.Struct("<4sI")
SYNC_AGENT_INSTALL = "sync_agent_dm_fota_install"
SYNC_AGENT_BINARY = "libsync-agent.so.0.bin"
SYNC_AGENT_REPORT = "sync-agent-report.json"


class ArtifactPullError(ValueError):
    """Categorical failure; never includes raw watch data or private addresses."""


class RemoteFileReadError(ArtifactPullError):
    """Keep the legacy message while retaining only a redacted errno category."""

    def __init__(self, payload: bytes):
        lower = payload.lower()
        denied = any(x in lower for x in (b"permission denied", b"access denied",
                                          b"operation not permitted"))
        missing = b"no such file or directory" in lower
        self.category = ("REMOTE_REPORTED_ACCESS_DENIED" if denied and not missing else
                         "REMOTE_REPORTED_NO_SUCH_FILE" if missing and not denied else
                         "REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE")
        super().__init__("REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE")


def _sdb_stage_error(stage: str, exc: Exception) -> ArtifactPullError:
    """Redacted stage and error class, never a raw watch/socket message."""
    if isinstance(exc, TimeoutError):
        kind = "TIMEOUT"
    elif isinstance(exc, SdbError):
        kind = "PROTOCOL_OR_AUTH_FAILURE"
    else:
        kind = "IO_FAILURE"
    return ArtifactPullError(f"SDB_{stage}_{kind}")


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
                # Raw text is never retained, logged or serialized. Existing
                # callers keep their established exception message.
                raise RemoteFileReadError(part)
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


def pull_fota(sock, key_path: Path, outfile, *, component="fota-service") -> dict[str, object]:
    """Use only SDB OPEN sync:, WRTE RECV exact allowlisted path, OKAY/CLSE."""
    if component not in EXECUTABLES:
        raise ArtifactPullError("COMPONENT_NOT_ALLOWLISTED")
    data = _receive_arm_elf(sock, key_path, outfile, EXECUTABLES[component])
    return {
        "schema": "uglyos-r840x-sdb-fota-artifact-v1",
        "status": "READABLE_BINARY_COPIED_FROM_AUTHENTICATED_SDB",
        "candidate": ("com.samsung.fota-consumer/fota-service" if component == "fota-service"
                      else "com.samsung.tizen.update-client/updateclient"),
        **data,
        "target_model_authenticated": False,
        "root_obtained": False,
        "custom_kernel_boot_proven": False,
        "stock_recovery_proven": False,
        "watch_write_performed": False,
        "notice": "A retrieved ELF is a research input, not a boot method or exploit.",
    }


def vendor_executable_path(raw: str) -> bytes:
    """Validate a kernel proc-exe readout; not a new user-selected file interface."""
    if not isinstance(raw, str):
        raise ArtifactPullError("OWNER_EXECUTABLE_PATH_UNRECOGNIZED")
    value = raw.removesuffix("\n").removesuffix("\r")
    prefixes = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/apps/", "/opt/usr/apps/")
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]{1,239}", value) or
            not value.startswith(prefixes) or
            any(p in ("", ".", "..") for p in value.split("/")[1:]) or
            value.endswith("/")):
        raise ArtifactPullError("OWNER_EXECUTABLE_PATH_UNRECOGNIZED")
    return value.encode("ascii")


def sync_agent_library_path(raw: str) -> bytes:
    """Only the evidenced SONAME family in system library directories."""
    if (not isinstance(raw, str) or len(raw) > 240 or
            not re.fullmatch(r"/(?:usr/)?lib/(?:[A-Za-z0-9_+.-]+/)*"
                             r"libsync-agent[.]so[.]0(?:[.][0-9]+)*", raw) or
            any(p in ("", ".", "..") for p in raw.split("/")[1:])):
        raise ArtifactPullError("DEPENDENCY_LIBRARY_PATH_REJECTED")
    return raw.encode("ascii")


def _receive_arm_elf(sock, key_path: Path, outfile, path: bytes, *,
                     library: bool = False) -> dict[str, object]:
    """Authoritative bounded sync RECV reused for fixed and owner-observed files.

    The owner collector supplies only a path obtained from a stable bus/PID
    snapshot and proc-exe read. This helper never resolves user CLI paths.
    """
    if not isinstance(path, bytes):
        raise ArtifactPullError("OWNER_EXECUTABLE_PATH_UNRECOGNIZED")
    try:
        (sync_agent_library_path if library else vendor_executable_path)(path.decode("ascii"))
    except UnicodeDecodeError:
        raise ArtifactPullError("OWNER_EXECUTABLE_PATH_UNRECOGNIZED") from None
    channel = Connection(sock, key_path)
    try:
        channel.handshake()
    except (SdbError, OSError, TimeoutError) as exc:
        raise _sdb_stage_error("HANDSHAKE", exc) from None
    try:
        channel.send(b"OPEN", LOCAL_STREAM, 0, b"sync:\x00")
        kind, remote, local, body = receive(sock)
    except (SdbError, OSError, TimeoutError) as exc:
        raise _sdb_stage_error("SYNC_OPEN", exc) from None
    if kind == b"CLSE" and local == LOCAL_STREAM:
        raise ArtifactPullError("SDB_SYNC_SERVICE_REFUSED")
    if (kind != b"OKAY" or local != LOCAL_STREAM or remote == 0 or body):
        raise ArtifactPullError("SDB_SYNC_OPEN_NOT_ACKNOWLEDGED")
    # RECV is read-only by specification. SEND/STAT/DELETE are never sent.
    try:
        channel.send(b"WRTE", LOCAL_STREAM, remote,
                     SYNC_HDR.pack(b"RECV", len(path)) + path)
    except (SdbError, OSError, TimeoutError) as exc:
        raise _sdb_stage_error("SYNC_TRANSFER", exc) from None
    decoder = ReadOnlySyncDecoder(outfile)
    for _ in range(MAX_STREAM_FRAMES):
        try:
            kind, arg0, arg1, body = receive(sock)
        except (SdbError, OSError, TimeoutError) as exc:
            raise _sdb_stage_error("SYNC_TRANSFER", exc) from None
        if arg0 != remote or arg1 != LOCAL_STREAM:
            raise ArtifactPullError("SDB_SYNC_STREAM_ID_MISMATCH")
        if kind == b"OKAY":
            continue
        if kind == b"CLSE":
            raise ArtifactPullError("SDB_SYNC_CLOSED_BEFORE_DONE")
        if kind != b"WRTE":
            raise ArtifactPullError("UNEXPECTED_SDB_SYNC_FRAME")
        try:
            channel.send(b"OKAY", LOCAL_STREAM, remote)
        except (SdbError, OSError, TimeoutError) as exc:
            raise _sdb_stage_error("SYNC_TRANSFER", exc) from None
        try:
            decoder.feed(body)
        except OSError:
            raise ArtifactPullError("LOCAL_BINARY_WRITE_FAILED") from None
        if decoder.done:
            # Neither send a second request nor persist anything to the watch.
            break
    if not decoder.done:
        raise ArtifactPullError("SDB_SYNC_DID_NOT_COMPLETE")
    elf = decoder.elf_kind()
    return {
        "bytes": decoder.byte_count,
        "sha256": decoder.digest.hexdigest(),
        "elf_kind": elf,
    }



def _save_local_exclusive(temporary: str, destination: Path, expected_size: int) -> None:
    """Copy onto Android/Termux without os.link and without replacing a file.

    O_EXCL makes the no-overwrite check atomic, even when a different
    process creates the destination after capture()'s initial check.
    The temporary file is already fully received, ELF-checked and synced.
    A failed copy removes only the destination we exclusively created.
    """
    try:
        descriptor = os.open(str(destination),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ArtifactPullError("LOCAL_OUTPUT_ALREADY_EXISTS") from None
    try:
        with os.fdopen(descriptor, "wb") as target:
            with open(temporary, "rb") as source:
                shutil.copyfileobj(source, target, length=64 * 1024)
            target.flush()
            os.fsync(target.fileno())
        if destination.stat().st_size != expected_size:
            raise ArtifactPullError("LOCAL_COPY_SIZE_MISMATCH")
    except BaseException:
        # Only our freshly O_EXCL-created local destination is deleted.
        # Never delete an existing file belonging to the owner.
        destination.unlink(missing_ok=True)
        raise


def capture(ip: str, key_path: Path, destination: Path, timeout: int = 12,
            *, component="fota-service") -> dict[str, object]:
    """Write output on the phone only, atomically, and never replace it."""
    if component not in EXECUTABLES:
        raise ArtifactPullError("COMPONENT_NOT_ALLOWLISTED")
    ip = private_watch_ip(ip)
    destination = destination.expanduser()
    if destination.exists() or destination.is_symlink():
        raise ArtifactPullError("LOCAL_OUTPUT_ALREADY_EXISTS")
    if not destination.parent.is_dir():
        raise ArtifactPullError("LOCAL_OUTPUT_DIRECTORY_MISSING")
    fd, temporary = tempfile.mkstemp(prefix=".watch3-fota-readonly-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as outfile:
            try:
                sock = socket.create_connection((ip, PORT), timeout=timeout)
            except (OSError, TimeoutError) as exc:
                raise _sdb_stage_error("TCP_CONNECT", exc) from None
            with sock:
                try:
                    sock.settimeout(timeout)
                except (OSError, TimeoutError) as exc:
                    raise _sdb_stage_error("SOCKET_SETUP", exc) from None
                result = pull_fota(sock, key_path, outfile, component=component)
            outfile.flush()
            os.fsync(outfile.fileno())
        # Android's Termux Python may not expose os.link(). Use an atomic
        # O_CREAT|O_EXCL reservation and copy the validated local temporary.
        # Never clobber an existing phone file, even under a race.
        _save_local_exclusive(temporary, destination, result["bytes"])
        return result
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_agent_listing(ip: str, key_path: Path, scope: str, timeout: int) -> dict:
    """Reuse the authoritative LIST transport, with no on-watch helper."""
    with socket.create_connection((ip, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        return list_one(sock, key_path, scope)


def resolve_sync_agent(ip: str, key_path: Path, timeout: int, attempts: list) -> tuple:
    """Select an actually listed SONAME link or a unique versioned candidate."""
    for scope, directory in FOTA_LIBRARY_DIRECTORIES.items():
        record = {"directory": directory.decode("ascii")}
        attempts.append(record)
        try:
            listing = sync_agent_listing(ip, key_path, scope, timeout)
        except InventoryError as exc:
            record["status"] = str(exc)
            if str(exc) == "DIRECTORY_LIST_DENIED_OR_UNSUPPORTED":
                continue
            raise
        record.update(listing)
        if listing["matching_names_truncated"]:
            raise ArtifactPullError("DEPENDENCY_DIRECTORY_MATCHES_TRUNCATED")
        candidates = {name: info for name, info in listing["matching_sync_agent_libraries"].items()
                      if info["kind"] in ("REGULAR_FILE", "SYMLINK")}
        if not candidates:
            continue
        name = SYNC_AGENT_SONAME if SYNC_AGENT_SONAME in candidates else next(iter(candidates))
        if name != SYNC_AGENT_SONAME and len(candidates) != 1:
            raise ArtifactPullError("DEPENDENCY_DIRECTORY_ENTRY_AMBIGUOUS")
        if candidates[name]["bytes"] == "OVER_8_MIB":
            raise ArtifactPullError("DEPENDENCY_EXCEEDS_EIGHT_MIB")
        path = sync_agent_library_path(directory.decode("ascii") + "/" + name)
        return path, scope, candidates[name]
    raise ArtifactPullError("DEPENDENCY_NOT_OBSERVED_IN_LIBRARY_DIRECTORIES")


def _sync_agent_archive(folder: Path, archive: Path, binary_copied: bool) -> None:
    """Package only this capture's explicit files, including a failure report."""
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target:
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.write(folder / SYNC_AGENT_REPORT, SYNC_AGENT_REPORT)
                if binary_copied:
                    bundle.write(folder / SYNC_AGENT_BINARY, SYNC_AGENT_BINARY)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        archive.unlink(missing_ok=True)
        raise


def capture_sync_agent(ip: str, key_path: Path, folder: Path, *,
                       consumer_input: Path | None = None,
                       archive: Path | None = None, timeout: int = 12) -> dict:
    """Acquire the actual missing implementation in one phone-side operation.

    Verify the existing original consumer locally, resolve its evidenced
    dependency through existing SDB directory inventory, copy one ARM library
    with our existing RECV implementation, inspect it without loading it,
    and recheck the selected directory entry. No live provider is claimed.
    """
    from analyze_watch3_r08_fota_elf import (
        CONSUMER_BYTES, CONSUMER_SHA256, OfflineELFError, parse_elf32,
    )

    ip = private_watch_ip(ip)
    folder = folder.expanduser()
    if archive is not None:
        archive = archive.expanduser()
        if archive.exists() or archive.is_symlink():
            raise ArtifactPullError("LOCAL_ARCHIVE_ALREADY_EXISTS")
        if not archive.parent.is_dir():
            raise ArtifactPullError("LOCAL_ARCHIVE_DIRECTORY_MISSING")
    if not folder.parent.is_dir():
        raise ArtifactPullError("LOCAL_OUTPUT_DIRECTORY_MISSING")
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        raise ArtifactPullError("LOCAL_OUTPUT_ALREADY_EXISTS") from None
    source = (consumer_input.expanduser() if consumer_input is not None else
              Path.home() / "watch3-r840x-fota-unit-evidence/fota-configured-executable.bin")
    result = {
        "schema": "uglyos-r840x-sync-agent-dependency-v2",
        "state": "NOT_YET_CAPTURED", "stage": "local_consumer",
        "dependency_soname": SYNC_AGENT_SONAME,
        "source_consumer_verified": False, "source_consumer_sha256": None,
        "resolution_method": "SDB_SYNC_LIST", "resolution_attempts": [],
        "observed_path": None, "directory_entry_stable": False,
        "binary_copied": False, "binary": None, "elf": None,
        "runtime_provider_observed": False, "target_model_authenticated": False,
        "fota_method_called": False, "binary_executed": False,
        "watch_write_performed": False, "root_obtained": False,
        "bootloader_unlock_proven": False, "stock_recovery_proven": False,
        "result": "EVIDENCE_ONLY",
    }
    try:
        try:
            with source.open("rb") as stream:
                original = stream.read(CONSUMER_BYTES + 1)
        except FileNotFoundError:
            raise ArtifactPullError("LOCAL_ORIGINAL_CONSUMER_MISSING") from None
        if (len(original) != CONSUMER_BYTES or
                hashlib.sha256(original).hexdigest() != CONSUMER_SHA256):
            raise ArtifactPullError("LOCAL_ORIGINAL_CONSUMER_PIN_MISMATCH")
        if SYNC_AGENT_SONAME not in parse_elf32(original)["dependencies"]:
            raise ArtifactPullError("CONSUMER_DEPENDENCY_NOT_OBSERVED")
        result.update(source_consumer_verified=True, source_consumer_sha256=CONSUMER_SHA256,
                      stage="library_directory")
        path, scope, entry = resolve_sync_agent(ip, key_path, timeout, result["resolution_attempts"])
        result.update(observed_path=path.decode("ascii"), stage="library_copy")
        with tempfile.NamedTemporaryFile(dir=folder, prefix=".sync-agent-", suffix=".tmp") as temp:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                binary = _receive_arm_elf(sock, key_path, temp, path, library=True)
            temp.flush()
            os.fsync(temp.fileno())
            temp.seek(0)
            raw = temp.read(MAX_BINARY_BYTES + 1)
            result["stage"] = "library_identity"
            facts = parse_elf32(raw)
            result["elf"] = facts
            if facts["elf_type"] != "ET_DYN" or facts["soname"] != SYNC_AGENT_SONAME:
                raise ArtifactPullError("DEPENDENCY_ELF_IDENTITY_MISMATCH")
            if SYNC_AGENT_INSTALL not in {x["name"] for x in facts["allowlisted_function_exports"]}:
                raise ArtifactPullError("DEPENDENCY_INSTALL_FUNCTION_NOT_DEFINED")
            result["stage"] = "directory_recheck"
            recheck = sync_agent_listing(ip, key_path, scope, timeout)
            name = path.rsplit(b"/", 1)[1].decode("ascii")
            if (recheck["matching_names_truncated"] or
                    recheck["matching_sync_agent_libraries"].get(name) != entry):
                raise ArtifactPullError("DEPENDENCY_DIRECTORY_ENTRY_CHANGED_DURING_COPY")
            result["directory_entry_stable"] = True
            result["stage"] = "local_save"
            _save_local_exclusive(temp.name, folder / SYNC_AGENT_BINARY, binary["bytes"])
        result.update(binary_copied=True, binary=binary, stage="complete",
                      state="SYNC_AGENT_LIBRARY_COPIED")
    except RemoteFileReadError as exc:
        result["state"] = exc.category
    except (ArtifactPullError, OfflineELFError, InventoryError) as exc:
        result["state"] = str(exc)
    except SdbError:
        result["state"] = "DEPENDENCY_SDB_PROTOCOL_OR_CONFIGURATION_ERROR"
    except (OSError, TimeoutError):
        result["state"] = "DEPENDENCY_LOCAL_OR_NETWORK_IO_ERROR"
    payload = (json.dumps(result, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(folder / SYNC_AGENT_REPORT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(payload)
        target.flush()
        os.fsync(target.fileno())
    if archive is not None:
        _sync_agent_archive(folder, archive, result["binary_copied"])
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True, help="Current local Watch3 Wi-Fi IP")
    parser.add_argument("--component", choices=(*EXECUTABLES, "sync-agent"),
                        default="fota-service",
                        help="Fixed read-only source; default preserves original behavior")
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--output", type=Path,
                        default=None,
                        help="Private phone file, defaults to component-specific filename")
    parser.add_argument("--output-dir", type=Path,
                        help="sync-agent only: new private directory for binary and report")
    parser.add_argument("--consumer-input", type=Path,
                        help="sync-agent only: existing original configured-consumer capture")
    parser.add_argument("--archive", type=Path,
                        help="sync-agent only: new local ZIP for private analysis, also on failure")
    args = parser.parse_args(argv)
    if args.component == "sync-agent":
        if args.output is not None:
            parser.error("sync-agent uses --output-dir, not --output")
        folder = args.output_dir or Path.home() / "watch3-r840x-sync-agent-evidence"
        try:
            report = capture_sync_agent(args.watch_ip, args.key_path, folder,
                                        consumer_input=args.consumer_input, archive=args.archive)
        except (ArtifactPullError, SdbError, OSError) as exc:
            reason = str(exc) if isinstance(exc, ArtifactPullError) else "LOCAL_OR_SDB_CONFIGURATION_ERROR"
            print("DEPENDENCY_CAPTURE_ERROR: " + reason, file=sys.stderr)
            return 1
        print("DEPENDENCY_STATE: " + report["state"])
        print("DEPENDENCY_REPORT: " + str(folder.expanduser() / SYNC_AGENT_REPORT))
        if report["binary_copied"]:
            print("PRIVATE_OFFLINE_ELF: " + str(folder.expanduser() / SYNC_AGENT_BINARY))
        if args.archive is not None:
            print("PRIVATE_EVIDENCE_ZIP: " + str(args.archive.expanduser()))
        return 0 if report["binary_copied"] else 1
    if any(x is not None for x in (args.output_dir, args.consumer_input, args.archive)):
        parser.error("--output-dir, --consumer-input and --archive require --component sync-agent")
    output = (args.output if args.output is not None else
              Path.home() / f"watch3-r840x-{args.component}-readonly.bin")
    try:
        report = capture(args.watch_ip, args.key_path, output,
                         component=args.component)
    except (ArtifactPullError, SdbError, OSError, TimeoutError) as exc:
        # Never print a remote server error, watch IDs, addresses or binary data.
        reason = (str(exc) if isinstance(exc, ArtifactPullError) else
                  "WATCH_IP_OR_SDB_CONFIGURATION_ERROR" if isinstance(exc, SdbError)
                  else "LOCAL_IO_ERROR")
        print("NO_ARTIFACT: " + reason, file=sys.stderr)
        return 1
    report_path = (Path.home() / "watch3-r840x-fota-artifact-evidence.json"
                   if args.component == "fota-service" else
                   Path.home() / "watch3-r840x-updateclient-artifact-evidence.json")
    try:
        with os.fdopen(os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                               0o600), "w") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    except FileExistsError:
        print("REPORT_ALREADY_EXISTS: " + str(report_path), file=sys.stderr)
        return 1
    except OSError:
        print("REPORT_SAVE_FAILED", file=sys.stderr)
        return 1
    print("READ_ONLY_ARTIFACT_RECEIVED: " + str(output.expanduser()))
    print("REPORT: " + str(report_path))
    print("NO root, exploit, bootloader access or stock recovery proven.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
