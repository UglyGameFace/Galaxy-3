#!/usr/bin/env python3
"""Capture the original sync-agent's event configuration and declared code files.

Native SDB RECV only. No shell, service activation, event submission, execution,
root-mode change or firmware write. Original files remain private on the phone.
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
import zipfile

from analyze_watch3_r08_fota_elf import (
    OfflineELFError, parse_elf32, SYNC_AGENT_BYTES as LIBRARY_BYTES,
    SYNC_AGENT_SHA256 as LIBRARY_SHA256,
)
from watch3_r08_android_sdb import PORT, SdbError, private_watch_ip
from watch3_r08_fota_handoff_pull import HandoffError, _receive_bounded_file, private_write

# Original library: 0x483ac resolves this literal; 0x483ae passes it to sync_agent_init.
ROOT_CONFIG = b"/usr/share/oma-dm-cfg/fw-init/omadmfotaui_fw_config.xml"
MAX_XML_BYTES = 64 * 1024
MAX_XML_FILES = 16
MAX_ELF_FILES = 4
MAX_REFS = 64
MAX_XML_NODES = 4096
REPORT_NAME = "sync-agent-context-report.json"
XML_PATH = re.compile(r"/usr/share/oma-dm-cfg/[A-Za-z0-9_./+-]{1,180}[.]xml\Z")
ELF_PATH = re.compile(
    r"/(?:usr/)?lib/(?:[A-Za-z0-9_+.-]+/)*lib[A-Za-z0-9_+.-]+[.]so(?:[.][0-9]+)*\Z"
    r"|/usr/(?:s?bin)/[A-Za-z0-9_+.-]{1,100}\Z")


class ContextError(ValueError):
    """Categorical errors only; never serialize raw watch responses."""


def classify_reference(value: str) -> str | None:
    if (not isinstance(value, str) or len(value) > 240 or
            any(p in ("", ".", "..") for p in value.split("/")[1:])):
        return None
    if XML_PATH.fullmatch(value):
        return "xml"
    if ELF_PATH.fullmatch(value):
        return "elf"
    return None


def declared_references(raw: bytes) -> list[tuple[str, bytes]]:
    """Follow only complete absolute system paths actually present in XML fields.

    No guessed filenames, shell splitting, URLs, entities, relative-path
    interpretation or arbitrary metadata values appear in the public report.
    """
    if not raw or len(raw) > MAX_XML_BYTES:
        raise ContextError("CONTEXT_XML_SIZE_INVALID")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ContextError("CONTEXT_XML_ENCODING_UNSUPPORTED") from None
    if "\x00" in text:
        raise ContextError("CONTEXT_XML_ENCODING_UNSUPPORTED")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ContextError("CONTEXT_XML_DTD_OR_ENTITY_REJECTED")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ContextError("CONTEXT_XML_MALFORMED") from None
    refs = []
    for count, node in enumerate(root.iter(), 1):
        if count > MAX_XML_NODES:
            raise ContextError("CONTEXT_XML_NODE_LIMIT")
        for value in (node.text or "", *node.attrib.values()):
            value = value.strip()
            kind = classify_reference(value)
            if kind and (kind, value.encode("ascii")) not in refs:
                refs.append((kind, value.encode("ascii")))
                if len(refs) > MAX_REFS:
                    raise ContextError("CONTEXT_REFERENCE_LIMIT")
    return refs


def capture_context(ip: str, key_path: Path, folder: Path, *, library_input: Path,
                    archive: Path | None = None, timeout: int = 12, progress=None) -> dict:
    ip = private_watch_ip(ip)
    folder = folder.expanduser()
    archive = archive.expanduser() if archive is not None else None
    if archive is not None and (archive.exists() or archive.is_symlink()):
        raise ContextError("LOCAL_ARCHIVE_ALREADY_EXISTS")
    if not folder.parent.is_dir() or (archive is not None and not archive.parent.is_dir()):
        raise ContextError("LOCAL_PARENT_DIRECTORY_MISSING")
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        raise ContextError("LOCAL_OUTPUT_ALREADY_EXISTS") from None
    report = {
        "schema": "uglyos-r840x-sync-agent-context-v1",
        "state": "NOT_CAPTURED", "source_library_verified": False,
        "source_library_sha256": None, "root_config": ROOT_CONFIG.decode("ascii"),
        "files": [], "limits_reached": False,
        "runtime_receiver_observed": False, "fota_method_called": False,
        "binary_executed": False, "watch_write_performed": False,
        "root_obtained": False, "bootloader_unlock_proven": False,
        "stock_recovery_proven": False, "result": "EVIDENCE_ONLY",
    }
    saved = []
    try:
        with library_input.expanduser().open("rb") as stream:
            original = stream.read(LIBRARY_BYTES + 1)
        if (len(original) != LIBRARY_BYTES or
                hashlib.sha256(original).hexdigest() != LIBRARY_SHA256):
            raise ContextError("LOCAL_ORIGINAL_LIBRARY_PIN_MISMATCH")
        report.update(source_library_verified=True, source_library_sha256=LIBRARY_SHA256)
        queue = [("xml", ROOT_CONFIG)]
        seen = set()
        counts = {"xml": 0, "elf": 0}
        failures = 0
        while queue:
            kind, path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            limit = MAX_XML_FILES if kind == "xml" else MAX_ELF_FILES
            if counts[kind] >= limit:
                report["limits_reached"] = True
                continue
            counts[kind] += 1
            if progress is not None:
                progress(kind, counts[kind])
            record = {"remote_path": path.decode("ascii"), "kind": kind}
            report["files"].append(record)
            try:
                # Only ROOT_CONFIG and already parsed absolute declarations enter the queue.
                if classify_reference(path.decode("ascii")) != kind:
                    raise ContextError("CONTEXT_SOURCE_PATH_REJECTED")
                with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    raw = _receive_bounded_file(sock, key_path, path,
                                                MAX_XML_BYTES if kind == "xml" else 8 * 1024 * 1024)
                name = f"context-{len(report['files']):02d}.{'xml' if kind == 'xml' else 'bin'}"
                if kind == "elf":
                    record["elf"] = parse_elf32(raw)
                private_write(folder / name, raw)
                saved.append(name)
                record.update(status="COPIED", local_file=name, bytes=len(raw),
                              sha256=hashlib.sha256(raw).hexdigest())
                if kind == "xml":
                    for ref in declared_references(raw):
                        if ref[1] not in seen and ref not in queue:
                            queue.append(ref)
            except (ContextError, HandoffError, OfflineELFError) as exc:
                record["status"] = str(exc)
                failures += 1
            except (OSError, SdbError, TimeoutError):
                record["status"] = "CONTEXT_LOCAL_OR_SDB_IO_ERROR"
                failures += 1
        report["state"] = ("CONTEXT_CAPTURED" if not failures and not report["limits_reached"]
                           else "CONTEXT_PARTIAL_OR_UNAVAILABLE")
    except FileNotFoundError:
        report["state"] = "LOCAL_ORIGINAL_LIBRARY_MISSING"
    except ContextError as exc:
        report["state"] = str(exc)
    except OSError:
        report["state"] = "LOCAL_ORIGINAL_LIBRARY_IO_ERROR"
    private_write(folder / REPORT_NAME, (json.dumps(report, indent=2) + "\n").encode())
    if archive is not None:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as bundle:
                    for name in [REPORT_NAME, *saved]:
                        bundle.write(folder / name, name)
                target.flush()
                os.fsync(target.fileno())
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--library-input", type=Path, default=Path.home() /
                        "watch3-r840x-sync-agent-native-evidence/libsync-agent.so.0.bin")
    parser.add_argument("--output-dir", type=Path, default=Path.home() /
                        "watch3-r840x-sync-agent-context-evidence")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    try:
        report = capture_context(args.watch_ip, args.key_path, args.output_dir,
                                 library_input=args.library_input, archive=args.archive,
                                 progress=lambda kind, n: print(
                                     f"Reading {'configuration' if kind == 'xml' else 'declared code file'} {n}",
                                     flush=True))
    except (ContextError, HandoffError, OSError, SdbError) as exc:
        print("CONTEXT_ERROR: " + (str(exc) if isinstance(exc, ContextError)
                                  else "LOCAL_OR_SDB_IO_ERROR"), file=sys.stderr)
        return 1
    print("CONTEXT_STATE: " + report["state"])
    print("CONTEXT_REPORT: " + str(args.output_dir.expanduser() / REPORT_NAME))
    if args.archive is not None:
        print("CONTEXT_ARCHIVE: " + str(args.archive.expanduser()))
    return 0 if report["state"] == "CONTEXT_CAPTURED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
