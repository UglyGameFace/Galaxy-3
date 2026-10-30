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
    OMADM_AGENT_BYTES, OMADM_AGENT_SHA256,
)
from watch3_r08_android_sdb import PORT, SdbError, private_watch_ip
from watch3_r08_fota_handoff_pull import HandoffError, _receive_bounded_file, private_write, inspect_unit
from watch3_r08_fota_artifact_pull import ArtifactPullError, vendor_executable_path
from watch3_r08_fota_consumer_inventory import (
    FOTA_FRAMEWORK_DIRECTORIES, FRAMEWORK_FILE_NAME, InventoryError, list_one,
)

# Original library: 0x483ac resolves this literal; 0x483ae passes it to sync_agent_init.
ROOT_CONFIG = b"/usr/share/oma-dm-cfg/fw-init/omadmfotaui_fw_config.xml"
MAX_XML_BYTES = 64 * 1024
MAX_XML_FILES = 16
MAX_CONFIG_FILES = 8
MAX_UNIT_FILES = 8
MAX_ELF_FILES = 4
MAX_REFS = 64
MAX_XML_NODES = 4096
REPORT_NAME = "sync-agent-context-report.json"
BACKEND_CONFIG = "/usr/share/oma-dm-cfg/fw-init/omadm_fw_config.xml"
BACKEND_CONFIG_BYTES = 5296
BACKEND_CONFIG_SHA256 = "f8ba15dde1bca536e16ee08149206d428b605e839667151a3d55056c49a7500e"
# Literal referenced by the pinned daemon at 0x188e6 before verify_FOTA_image.
PUBLIC_CERTIFICATE = b"/usr/share/oma-dm-cfg/certi/FOTA_ROOT.cer"
XML_PATH = re.compile(r"/usr/share/oma-dm-cfg/[A-Za-z0-9_./+-]{1,180}[.]xml\Z")
CONFIG_PATH = re.compile(r"/usr/share/oma-dm-cfg/[A-Za-z0-9_./+-]{1,180}\Z")
UNIT_PATH = re.compile(r"/(?:usr/lib|etc)/systemd/system/([A-Za-z0-9_.@+-]{1,124})\Z")
ELF_PATH = re.compile(
    r"/(?:usr/)?lib/(?:[A-Za-z0-9_+.-]+/)*lib[A-Za-z0-9_+.-]+[.]so(?:[.][0-9]+)*\Z"
    r"|/usr/(?:s?bin)/[A-Za-z0-9_+.-]{1,100}\Z")


class ContextError(ValueError):
    """Categorical errors only; never serialize raw watch responses."""


def classify_reference(value: str) -> str | None:
    if (not isinstance(value, str) or len(value) > 240 or value != value.strip() or
            any(p in ("", ".", "..") for p in value.split("/")[1:])):
        return None
    if XML_PATH.fullmatch(value):
        return "xml"
    if CONFIG_PATH.fullmatch(value):
        return "config"
    unit = UNIT_PATH.fullmatch(value)
    if (unit and unit[1].endswith((".service", ".socket")) and
            FRAMEWORK_FILE_NAME.fullmatch(unit[1])):
        return "unit"
    if ELF_PATH.fullmatch(value):
        return "elf"
    try:
        # Reuse the established normal vendor executable validator, including
        # libexec and Tizen app code paths supplied by an observed unit/XML.
        vendor_executable_path(value)
    except ArtifactPullError:
        return None
    return "elf"


def parse_xml(raw: bytes):
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
    for count, node in enumerate(root.iter(), 1):
        if count > MAX_XML_NODES:
            raise ContextError("CONTEXT_XML_NODE_LIMIT")
    return root


def declared_references(raw: bytes) -> list[tuple[str, bytes]]:
    """Follow complete absolute declarations, including extensionless config.

    No guessed filenames, shell splitting, URLs, entities or relative paths.
    Extensionless Event-Config/Noti-Config files are not assumed to be XML.
    """
    refs = []
    for node in parse_xml(raw).iter():
        for value in (node.text or "", *node.attrib.values()):
            value = value.strip()
            kind = classify_reference(value)
            if kind and (kind, value.encode("ascii")) not in refs:
                refs.append((kind, value.encode("ascii")))
                if len(refs) > MAX_REFS:
                    raise ContextError("CONTEXT_REFERENCE_LIMIT")
    return refs


def configuration_fields(raw: bytes) -> dict:
    """Only the framework's bounded routing identifiers, never arbitrary values."""
    fields = {}
    names = {"Agent-Key": "agent_key", "Event-Key": "event_key", "Noti-Key": "noti_key"}
    for node in parse_xml(raw).iter():
        tag = node.tag.rsplit("}", 1)[-1]
        value = (node.text or "").strip()
        if tag in names and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value):
            fields[names[tag]] = value
        elif tag == "RunEventHandler" and value in ("0", "1"):
            fields["run_event_handler_declared"] = value == "1"
    if "event_key" in fields:
        fields["event_socket_from_config"] = "/tmp/agent_fw_event_" + fields["event_key"]
    return fields


def firmware_focus_sources(folder: Path) -> tuple[list, dict]:
    """Verify existing private capture before reading the FUMO declaration.

    The old capture report selects flat local filenames only. Both source files
    must match the reviewed originals, independently of the report's assertions.
    No paths or arbitrary configuration values from it are copied to output.
    """
    folder = folder.expanduser()
    try:
        with (folder / REPORT_NAME).open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ContextError("LOCAL_RECEIVER_REPORT_SIZE_INVALID")
        report = json.loads(raw)
        if not isinstance(report, dict) or not isinstance(report.get("files"), list):
            raise ContextError("LOCAL_RECEIVER_REPORT_INVALID")
        if len(report["files"]) > 128 or any(not isinstance(r, dict) for r in report["files"]):
            raise ContextError("LOCAL_RECEIVER_REPORT_INVALID")
        sources = {}
        for remote, size, digest, suffix in (
                ("/usr/bin/oma-dm-agent", OMADM_AGENT_BYTES, OMADM_AGENT_SHA256, "bin"),
                (BACKEND_CONFIG, BACKEND_CONFIG_BYTES, BACKEND_CONFIG_SHA256, "xml")):
            matches = [r for r in report["files"] if r.get("remote_path") == remote]
            if len(matches) != 1:
                raise ContextError("LOCAL_RECEIVER_SOURCE_RECORD_INVALID")
            record = matches[0]
            name = record.get("local_file")
            if (record.get("status") != "COPIED" or record.get("bytes") != size or
                    record.get("sha256") != digest or not isinstance(name, str) or
                    not re.fullmatch(r"context-[0-9]{2,3}[.]" + suffix, name)):
                raise ContextError("LOCAL_RECEIVER_SOURCE_RECORD_INVALID")
            path = folder / name
            if path.is_symlink():
                raise ContextError("LOCAL_RECEIVER_SOURCE_RECORD_INVALID")
            with path.open("rb") as stream:
                source = stream.read(size + 1)
            if len(source) != size or hashlib.sha256(source).hexdigest() != digest:
                raise ContextError("LOCAL_RECEIVER_SOURCE_PIN_MISMATCH")
            sources[remote] = source
    except FileNotFoundError:
        raise ContextError("LOCAL_RECEIVER_SOURCE_MISSING") from None
    except (ValueError, UnicodeDecodeError) as exc:
        if isinstance(exc, ContextError):
            raise
        raise ContextError("LOCAL_RECEIVER_REPORT_INVALID") from None
    except OSError:
        raise ContextError("LOCAL_RECEIVER_SOURCE_IO_ERROR") from None

    root = parse_xml(sources[BACKEND_CONFIG])
    plugins = []
    for manager in root.findall("./PlugIn-Mgr"):
        for domain in manager.findall("./Domain"):
            if domain.get("name") == "MO":
                for plugin in domain.findall("./Plug-In"):
                    if (plugin.findtext("Type") or "").strip() == "FUMO":
                        plugins.append((plugin.findtext("Path") or "").strip())
    if len(plugins) != 1 or classify_reference(plugins[0]) != "elf":
        raise ContextError("LOCAL_FUMO_DECLARATION_INVALID")
    if PUBLIC_CERTIFICATE + b"\0" not in sources["/usr/bin/oma-dm-agent"]:
        raise ContextError("LOCAL_CERTIFICATE_REFERENCE_MISSING")
    return [("elf", plugins[0].encode("ascii")), ("config", PUBLIC_CERTIFICATE)], {
        "daemon_sha256": OMADM_AGENT_SHA256,
        "backend_config_sha256": BACKEND_CONFIG_SHA256,
        "sources_verified": True,
        "plugin_selection": "MO_FUMO_DECLARATION",
    }


def discover_receiver_paths(ip: str, key_path: Path, timeout: int, discovery: list) -> list:
    """Find actual related entries; no guessed daemon or initializer filename."""
    paths = []
    for scope, directory in FOTA_FRAMEWORK_DIRECTORIES.items():
        record = {"directory": directory.decode("ascii")}
        discovery.append(record)
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                listing = list_one(sock, key_path, scope)
            record.update(listing)
            # Prefer observed daemon names over UI helper names within the cap.
            entries = sorted(listing["matching_framework_files"].items(),
                             key=lambda item: ("agent" not in item[0].lower(), item[0]))
            for name, info in entries:
                if info["kind"] not in ("REGULAR_FILE", "SYMLINK"):
                    continue
                path = directory.decode("ascii") + "/" + name
                kind = classify_reference(path)
                if kind:
                    paths.append((kind, path.encode("ascii")))
        except InventoryError as exc:
            record["status"] = str(exc)
        except (OSError, SdbError, TimeoutError):
            record["status"] = "CONTEXT_DIRECTORY_OR_SDB_IO_ERROR"
    return paths


def capture_context(ip: str, key_path: Path, folder: Path, *, library_input: Path,
                    archive: Path | None = None, timeout: int = 12, progress=None,
                    firmware_focus: bool = False, receiver_input_dir: Path | None = None) -> dict:
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
        "schema": "uglyos-r840x-sync-agent-context-v2",
        "state": "NOT_CAPTURED", "source_library_verified": False,
        "capture_scope": "FIRMWARE_FOCUS" if firmware_focus else "RECEIVER_CONTEXT",
        "source_library_sha256": None,
        "root_config": BACKEND_CONFIG if firmware_focus else ROOT_CONFIG.decode("ascii"),
        "files": [], "discovery": [], "limits_reached": False,
        "copied_by_kind": {}, "receiver_candidate_code_copied": False,
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
        if firmware_focus:
            if receiver_input_dir is None:
                receiver_input_dir = Path.home() / "watch3-r840x-sync-agent-receiver-evidence"
            queue, report["firmware_focus_source"] = firmware_focus_sources(receiver_input_dir)
        else:
            if progress is not None:
                progress("discovery", 0)
            queue = [("xml", ROOT_CONFIG),
                     *discover_receiver_paths(ip, key_path, timeout, report["discovery"])]
        report["limits_reached"] = any(r.get("matching_names_truncated", False)
                                       for r in report["discovery"])
        seen = set()
        limits = {"xml": MAX_XML_FILES, "config": MAX_CONFIG_FILES,
                  "unit": MAX_UNIT_FILES, "elf": MAX_ELF_FILES}
        counts = dict.fromkeys(limits, 0)
        failures = sum(r.get("status") not in ("LIST_COMPLETE", "EMPTY_OR_INACCESSIBLE")
                       for r in report["discovery"])
        while queue:
            kind, path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            limit = limits[kind]
            if counts[kind] >= limit:
                report["limits_reached"] = True
                continue
            counts[kind] += 1
            if progress is not None:
                progress(kind, counts[kind])
            record = {"remote_path": path.decode("ascii"), "kind": kind}
            report["files"].append(record)
            try:
                # Sources are fixed, XML/unit declared, or actually LIST-observed.
                if classify_reference(path.decode("ascii")) != kind:
                    raise ContextError("CONTEXT_SOURCE_PATH_REJECTED")
                with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    raw = _receive_bounded_file(sock, key_path, path,
                                                8 * 1024 * 1024 if kind == "elf" else MAX_XML_BYTES)
                suffix = {"xml": "xml", "config": "conf", "unit": "service", "elf": "bin"}[kind]
                name = f"context-{len(report['files']):02d}.{suffix}"
                if kind == "elf":
                    record["elf"] = parse_elf32(raw)
                private_write(folder / name, raw)
                saved.append(name)
                record.update(status="COPIED", local_file=name, bytes=len(raw),
                              sha256=hashlib.sha256(raw).hexdigest())
                if kind == "xml":
                    record["framework_fields"] = configuration_fields(raw)
                    for ref in declared_references(raw):
                        if ref[1] not in seen and ref not in queue:
                            queue.append(ref)
                elif kind == "unit":
                    record["configured_unit"] = inspect_unit(raw)
                    path = record["configured_unit"].get("exec_path", "")
                    if classify_reference(path) == "elf":
                        ref = ("elf", path.encode("ascii"))
                        if ref[1] not in seen and ref not in queue:
                            queue.append(ref)
            except (ContextError, HandoffError, OfflineELFError) as exc:
                record["status"] = str(exc)
                failures += 1
            except (OSError, SdbError, TimeoutError):
                record["status"] = "CONTEXT_LOCAL_OR_SDB_IO_ERROR"
                failures += 1
        report["copied_by_kind"] = {kind: sum(r["kind"] == kind and r["status"] == "COPIED"
                                             for r in report["files"]) for kind in limits}
        report["receiver_candidate_code_copied"] = bool(report["copied_by_kind"]["elf"])
        success = "FIRMWARE_FOCUS_CAPTURED" if firmware_focus else "CONTEXT_CAPTURED"
        report["state"] = (success if not failures and not report["limits_reached"]
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
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--firmware-focus", action="store_true",
                        help="Read only the pinned configuration's FUMO plugin and public certificate")
    parser.add_argument("--receiver-input-dir", type=Path, default=Path.home() /
                        "watch3-r840x-sync-agent-receiver-evidence")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    if args.output_dir is None:
        args.output_dir = Path.home() / ("watch3-r840x-firmware-focus-evidence" if args.firmware_focus
                                        else "watch3-r840x-sync-agent-receiver-evidence")
    try:
        report = capture_context(args.watch_ip, args.key_path, args.output_dir,
                                 library_input=args.library_input, archive=args.archive,
                                 firmware_focus=args.firmware_focus, receiver_input_dir=args.receiver_input_dir,
                                 progress=lambda kind, n: print(
                                     ("Finding related daemon/configuration entries" if kind == "discovery" else
                                      f"Reading {kind} file {n}"),
                                     flush=True))
    except (ContextError, HandoffError, OSError, SdbError) as exc:
        print("CONTEXT_ERROR: " + (str(exc) if isinstance(exc, ContextError)
                                  else "LOCAL_OR_SDB_IO_ERROR"), file=sys.stderr)
        return 1
    print("CONTEXT_STATE: " + report["state"])
    print("CONTEXT_REPORT: " + str(args.output_dir.expanduser() / REPORT_NAME))
    if args.archive is not None:
        print("CONTEXT_ARCHIVE: " + str(args.archive.expanduser()))
    return 0 if report["state"] in ("CONTEXT_CAPTURED", "FIRMWARE_FOCUS_CAPTURED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
