#!/usr/bin/env python3
"""Build/run our ARM attribute reader in a temporary SDB SDK directory.

Requires clang/lld on the phone. Writes only our compiled program into a new
SDK subdirectory, executes it for fixed read-only metadata, then removes that
program/subdirectory. No root request, FOTA action, vendor-script execution,
partition access, firmware write or security-attribute modification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import uuid
import zipfile

from watch3_r08_android_sdb import Connection, PORT, SdbError, private_watch_ip, receive
from watch3_r08_fota_handoff_pull import private_write
from analyze_watch3_r08_fota_elf import parse_elf32, OfflineELFError

SOURCE = Path(__file__).parent / "native/watch3_security_metadata.c"
REPORT_NAME = "security-metadata-report.json"
MAX_BINARY = 64 * 1024
SYNC = struct.Struct("<4sI")
TARGETS = ("/usr/bin/fota-consumer", "/usr/bin/oma-dm-agent", "/usr/bin/launch_app",
           "/usr/bin/recovery-update.sh", "/usr/bin/rw-update-prepare.sh",
           "/usr/bin/rw-update-systemd.sh", "/opt/usr/data/fota/save", "/opt/data/recovery")
ATTRIBUTES = ("security.capability", "security.SMACK64", "security.SMACK64EXEC")
STAGE = re.compile(r"(?P<base>/(?:tmp|(?:opt/usr/)?home/(?:owner|developer|sdk))"
                   r"(?:/[A-Za-z0-9_.+-]+)*)/uglyos-metadata-[a-f0-9]{32}\Z")


class MetadataError(ValueError):
    pass


def build_probe(directory: Path, compiler=None, *, fixture=None, host_test=False) -> tuple[bytes, dict]:
    compiler = compiler or shutil.which("clang")
    if not compiler:
        raise MetadataError("CLANG_MISSING_RUN_PKG_INSTALL_CLANG")
    output = directory / "security-metadata-probe"
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-builtin"]
    if host_test:
        flags += ["-D_GNU_SOURCE", "-DPROBE_HOST_TEST"]
    else:
        flags += ["--target=armv7-linux-gnueabi", "-marm", "-mfloat-abi=soft", "-nostdlib",
                  "-ffreestanding", "-fno-stack-protector", "-fomit-frame-pointer",
                  "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-fno-pie",
                  "-static", "-fuse-ld=lld", "-Wl,-e,_start,--build-id=none,-z,noexecstack"]
    if fixture is not None:
        flags += ["-DPROBE_TEST", "-DPROBE_TEST_PREFIX=" + json.dumps(str(fixture))]
    try:
        result = subprocess.run([compiler, *flags, str(SOURCE), "-o", str(output)],
                                capture_output=True, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise MetadataError("PROBE_COMPILER_FAILED") from None
    if result.returncode:
        error = MetadataError("PROBE_COMPILER_FAILED")
        error.diagnostic = (result.stdout + result.stderr)[:65536]
        raise error
    raw = output.read_bytes()
    if not host_test:
        facts = parse_elf32(raw)
        if (len(raw) > MAX_BINARY or facts["elf_type"] != "ET_EXEC" or facts["dependencies"] or
                facts["executable_stack"] != "NONEXECUTABLE"):
            raise MetadataError("PROBE_ELF_PROFILE_INVALID")
    return raw, {"source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                 "elf_sha256": hashlib.sha256(raw).hexdigest(), "elf_bytes": len(raw)}


def validate_stage(path: str) -> str:
    match = STAGE.fullmatch(path) if isinstance(path, str) else None
    if not match or any(p in ("", ".", "..") for p in path.split("/")[1:]):
        raise MetadataError("SDK_STAGE_PATH_REJECTED")
    return path


def sdk_stage(raw: str, nonce: str) -> str:
    paths = re.findall(r"(?m)^sdk_toolpath:([^\r\n]+)\r?$", raw)
    if len(paths) != 1 or not re.fullmatch(r"[a-f0-9]{32}", nonce):
        raise MetadataError("SDK_TOOLPATH_UNAVAILABLE")
    return validate_stage(paths[0].rstrip("/") + "/uglyos-metadata-" + nonce)


def sdk_stages(raw: str, nonce: str) -> list[str]:
    """Bounded SDK/temp candidates; never create a missing parent directory."""
    advertised = sdk_stage(raw, nonce)
    parent, suffix = advertised.rsplit("/", 1)
    bases = [parent]
    if parent.endswith("/sdk_tools"):
        bases.append(parent.rsplit("/", 1)[0])
    bases.append("/tmp")
    return list(dict.fromkeys(validate_stage(base + "/" + suffix) for base in bases))


def stage_command(operation: str, stage: str) -> str:
    stage = validate_stage(stage)
    parent = stage.rsplit("/", 1)[0]
    return {
        "create": (f"if [ ! -d {parent} ]; then printf 'UGLYOS_STAGE_PARENT_MISSING\\n'; "
                   f"elif mkdir -m 700 {stage}; then printf 'UGLYOS_STAGE_CREATED\\n'; "
                   "else printf 'UGLYOS_STAGE_NOT_CREATED\\n'; fi"),
        "run": f"{stage}/probe",
        "cleanup": f"rm -f {stage}/probe && rmdir {stage} && printf 'UGLYOS_STAGE_REMOVED\\n'",
    }[operation]


def request(ip: str, key: Path, operation: str, *, stage=None, timeout=8):
    if operation not in ("capabilities", "create", "run", "cleanup", "stage_context"):
        raise MetadataError("OPERATION_NOT_ALLOWLISTED")
    if operation not in ("capabilities", "stage_context"):
        stage = validate_stage(stage)
    with socket.create_connection((ip, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        conn = Connection(sock, key)
        conn.handshake()
        if operation == "capabilities":
            return conn.capabilities()
        if operation == "stage_context":
            command = ("id; stat -c '%a %u %g %s %n' /tmp /home/owner "
                       "/home/owner/share /home/owner/share/tmp /home/owner/share/tmp/sdk_tools "
                       "/opt/usr/home/owner/share/tmp; cat /proc/mounts")
        else:
            command = stage_command(operation, stage)
        return conn._read_service(("shell:" + command).encode() + b"\0", raw=True)


def send_probe(ip: str, key: Path, stage: str, raw: bytes, *, timeout=8):
    """SEND only our compiled bounded ARM ELF, only into the new SDK stage."""
    stage = validate_stage(stage)
    facts = parse_elf32(raw)
    if not 1 <= len(raw) <= MAX_BINARY or facts["elf_type"] != "ET_EXEC" or facts["dependencies"]:
        raise MetadataError("PROBE_ELF_PROFILE_INVALID")
    with socket.create_connection((ip, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        conn = Connection(sock, key)
        conn.handshake()
        conn.send(b"OPEN", 2, 0, b"sync:\0")
        kind, remote, local, body = receive(sock)
        if kind != b"OKAY" or not remote or local != 2 or body:
            raise MetadataError("PROBE_UPLOAD_OPEN_FAILED")
        path = (stage + "/probe," + str(0o100700)).encode()
        payload = (SYNC.pack(b"SEND", len(path)) + path + SYNC.pack(b"DATA", len(raw)) + raw +
                   SYNC.pack(b"DONE", 0))
        conn.send(b"WRTE", 2, remote, payload)
        response = bytearray()
        for _ in range(32):
            kind, sender, receiver, part = receive(sock)
            if sender != remote or receiver != 2:
                raise MetadataError("PROBE_UPLOAD_STREAM_MISMATCH")
            if kind == b"OKAY":
                continue
            if kind != b"WRTE":
                raise MetadataError("PROBE_UPLOAD_INCOMPLETE")
            conn.send(b"OKAY", 2, remote)
            response.extend(part)
            if len(response) > 520:
                raise MetadataError("PROBE_UPLOAD_RESPONSE_INVALID")
            if len(response) >= 8:
                tag, size = SYNC.unpack(response[:8])
                if tag == b"FAIL":
                    if size > 512 or len(response) > 8 + size:
                        raise MetadataError("PROBE_UPLOAD_RESPONSE_INVALID")
                    if len(response) < 8 + size:
                        continue
                    error = MetadataError("PROBE_UPLOAD_DENIED")
                    error.upload_response = bytes(response)
                    raise error
                if tag != b"OKAY" or size or len(response) != 8:
                    raise MetadataError("PROBE_UPLOAD_RESPONSE_INVALID")
                return
        raise MetadataError("PROBE_UPLOAD_INCOMPLETE")


def parse_probe(raw: bytes) -> dict:
    if not raw or len(raw) > 32768:
        raise MetadataError("PROBE_OUTPUT_INVALID")
    try:
        value = json.loads(raw)
        if (value["schema"] != "uglyos-watch3-security-metadata-v1" or value["test_fixture"] is not False or
                [r["path"] for r in value["files"]] != list(TARGETS)):
            raise ValueError
        for field in ("uid", "euid"):
            if type(value[field]) is not int or not 0 <= value[field] <= 0xffffffff:
                raise ValueError
        if type(value["capget_rc"]) is not int or not -4095 <= value["capget_rc"] <= 0:
            raise ValueError
        for field in ("effective_caps_hex", "permitted_caps_hex", "inheritable_caps_hex"):
            if not re.fullmatch(r"[a-f0-9]{16}" if value["capget_rc"] == 0 else r"", value[field]):
                raise ValueError
        if (type(value["groups_rc"]) is not int or not -4095 <= value["groups_rc"] <= 128 or
                not isinstance(value["groups"], list) or len(value["groups"]) != max(value["groups_rc"], 0) or
                any(type(g) is not int or not 0 <= g <= 0xffffffff for g in value["groups"])):
            raise ValueError
        records = [(value["current_label_rc"], value["current_label_hex"])]
        for item in value["files"]:
            if type(item["write_access_rc"]) is not int or not -4095 <= item["write_access_rc"] <= 0:
                raise ValueError
            if [a["name"] for a in item["attrs"]] != list(ATTRIBUTES):
                raise ValueError
            records += [(a["rc"], a["hex"]) for a in item["attrs"]]
        for rc, encoded in records:
            if (type(rc) is not int or not -4095 <= rc <= 256 or not isinstance(encoded, str) or
                    not re.fullmatch(r"[a-f0-9]*", encoded) or len(encoded) != 2 * max(rc, 0)):
                raise ValueError
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise MetadataError("PROBE_OUTPUT_INVALID") from None
    return value


def capture(ip: str, key: Path, folder: Path, *, archive: Path | None = None,
            compiler=None, progress=None) -> dict:
    ip = private_watch_ip(ip)
    folder = folder.expanduser()
    archive = archive.expanduser() if archive is not None else None
    if archive is not None and (archive.exists() or archive.is_symlink()):
        raise MetadataError("LOCAL_ARCHIVE_ALREADY_EXISTS")
    if not folder.parent.is_dir() or archive is not None and not archive.parent.is_dir():
        raise MetadataError("LOCAL_PARENT_DIRECTORY_MISSING")
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        raise MetadataError("LOCAL_OUTPUT_ALREADY_EXISTS") from None
    report = {"schema": "uglyos-r840x-native-security-metadata-v1", "state": "NOT_CAPTURED",
              "probe": None, "temporary_sdk_write_requested": False, "probe_uploaded": False,
              "probe_execution_requested": False, "stage_cleanup_verified": False,
              "root_mode_requested": False, "vendor_script_executed": False,
              "existing_security_attributes_modified": False, "fota_method_called": False,
              "partition_reads_attempted": False, "firmware_written": False,
              "bootloader_unlock_proven": False, "stock_recovery_proven": False}
    saved = []
    report["stage_attempts"] = []

    def save(name, raw):
        private_write(folder / name, raw)
        saved.append(name)

    def cleanup(attempt, prefix):
        if progress: progress("Removing the temporary probe and its directory")
        try:
            raw = request(ip, key, "cleanup", stage=attempt["stage"])
            attempt["cleanup_verified"] = raw.strip() == b"UGLYOS_STAGE_REMOVED"
            save(prefix + "stage-cleanup.response", raw)
        except (OSError, SdbError, MetadataError):
            attempt["cleanup_verified"] = False
        report["stage_cleanup_verified"] = attempt["cleanup_verified"]
        if not attempt["cleanup_verified"]:
            report["remaining_sdk_stage"] = attempt["stage"]
            report["state"] = "SDK_STAGE_CLEANUP_UNVERIFIED"

    try:
        if progress: progress("Building our static ARM metadata reader")
        with tempfile.TemporaryDirectory(prefix="uglyos-metadata-build-") as tmp:
            binary, report["build"] = build_probe(Path(tmp), compiler)
        stages = sdk_stages(request(ip, key, "capabilities"), uuid.uuid4().hex)
        for number, stage in enumerate(stages, 1):
            prefix = "" if number == 1 else f"attempt-{number}-"
            attempt = {"stage": stage, "created": False, "uploaded": False,
                       "execution_requested": False, "cleanup_verified": False}
            report["stage_attempts"].append(attempt)
            report["temporary_sdk_write_requested"] = True
            report["unverified_sdk_stage"] = stage
            creation = request(ip, key, "create", stage=stage)
            attempt["created"] = creation.strip() == b"UGLYOS_STAGE_CREATED"
            if attempt["created"]:
                report.pop("unverified_sdk_stage", None)
            retry = False
            try:
                save(prefix + "stage-create.response", creation)
                marker = creation.strip().splitlines()[-1:]  # Diagnostics may precede a failure marker.
                if marker in ([b"UGLYOS_STAGE_PARENT_MISSING"], [b"UGLYOS_STAGE_NOT_CREATED"]):
                    attempt["creation_result"] = marker[0].decode()
                    report.pop("unverified_sdk_stage", None)
                    report["state"] = "SDK_STAGE_UNAVAILABLE"
                    if progress: progress("Temporary parent unavailable; trying the next fixed candidate")
                    continue
                if not attempt["created"]:
                    raise MetadataError("SDK_STAGE_CREATION_NOT_VERIFIED")
                if progress: progress("Uploading our reader into the new temporary directory")
                send_probe(ip, key, stage, binary)
                attempt["uploaded"] = report["probe_uploaded"] = True
                attempt["execution_requested"] = report["probe_execution_requested"] = True
                if progress: progress("Reading file capabilities, labels and access checks")
                raw = request(ip, key, "run", stage=stage)
                save(prefix + "probe-output.response", raw)
                report["probe"] = parse_probe(raw)
                report["state"] = "NATIVE_SECURITY_METADATA_CAPTURED"
            except MetadataError as exc:
                report["state"] = attempt["error"] = str(exc)
                if getattr(exc, "upload_response", None):
                    save(prefix + "probe-upload.response", exc.upload_response)
                retry = str(exc) in ("PROBE_UPLOAD_DENIED", "PROBE_OUTPUT_INVALID")
                if not retry: raise
            finally:
                if attempt["created"]:
                    cleanup(attempt, prefix)
            if not retry or not report["stage_cleanup_verified"]:
                break
    except (MetadataError, OfflineELFError) as exc:
        report["state"] = str(exc)
        if isinstance(exc, MetadataError) and getattr(exc, "diagnostic", None):
            private_write(folder / "compiler.response", exc.diagnostic)
            saved.append("compiler.response")
    except (OSError, SdbError):
        report["state"] = "LOCAL_OR_SDB_IO_ERROR"
    if report.get("remaining_sdk_stage"):
        report["state"] = "SDK_STAGE_CLEANUP_UNVERIFIED"
    if report["temporary_sdk_write_requested"] and report["state"] != "NATIVE_SECURITY_METADATA_CAPTURED":
        try:
            save("stage-context.response", request(ip, key, "stage_context"))
        except (OSError, SdbError, MetadataError):
            pass
    private_write(folder / REPORT_NAME, (json.dumps(report, indent=2) + "\n").encode())
    if archive is not None:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                    for name in [REPORT_NAME, *saved]: z.write(folder / name, name)
                out.flush(); os.fsync(out.fileno())
        except BaseException:
            archive.unlink(missing_ok=True); raise
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--watch-ip", required=True)
    p.add_argument("--key-path", type=Path, default=Path.home()/".config/galaxy3/watch3-sdbkey")
    p.add_argument("--output-dir", type=Path, default=Path.home()/"watch3-r840x-security-metadata-evidence")
    p.add_argument("--archive", type=Path)
    args = p.parse_args(argv)
    try:
        report = capture(args.watch_ip, args.key_path, args.output_dir, archive=args.archive,
                         progress=lambda text: print(text, flush=True))
    except (OSError, SdbError, MetadataError) as exc:
        print("SECURITY_METADATA_ERROR: " + (str(exc) if isinstance(exc, MetadataError) else "LOCAL_OR_SDB_IO_ERROR"), file=sys.stderr)
        return 1
    print("SECURITY_METADATA_STATE: " + report["state"])
    if args.archive: print("SECURITY_METADATA_ARCHIVE: " + str(args.archive.expanduser()))
    return 0 if report["state"] == "NATIVE_SECURITY_METADATA_CAPTURED" else 1


if __name__ == "__main__": raise SystemExit(main())
