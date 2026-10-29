#!/usr/bin/env python3
"""Read existing FOTA ownership or the physically observed unit's metadata.

Default: query only org.freedesktop.DBus for an EXISTING fota.consumer
owner. Optional configured-unit mode reads systemd show properties for the
already observed fota-consumer.service and copies its configured ARM ELF.
Neither mode starts the consumer. Configured identity is not live ownership.
No FOTA method, privilege change, update, partition or Odin operation exists.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile

from watch3_r08_android_sdb import (
    Connection, FOTA_OWNER_REGISTRY_PROBES, FOTA_UNIT_METADATA_PROBES,
    PORT, SdbError, ShellCloseError,
    private_watch_ip,
)
from watch3_r08_fota_artifact_pull import (
    ArtifactPullError, _receive_arm_elf, _save_local_exclusive, vendor_executable_path,
)

SCHEMA = "uglyos-r840x-existing-fota-owner-v1"
REPORT = "fota-owner-report.json"
BINARY = "fota-owner-readonly.bin"
UNIT_REPORT = "fota-unit-report.json"
UNIT_BINARY = "fota-configured-executable.bin"
UNIT_ID = "fota-consumer.service"
UNIT_FRAGMENT = "/usr/lib/systemd/system/" + UNIT_ID
UNIT_FIELDS = {"Id", "LoadState", "ActiveState", "SubState", "Type", "BusName",
               "User", "Group", "FragmentPath", "ExecStart"}


class OwnerError(ValueError):
    """Only categorical errors; never expose raw bus replies or shell output."""


def parse_reply(raw: str, kind: str):
    if not isinstance(raw, str) or not 1 <= len(raw) <= 2048:
        raise OwnerError("REGISTRY_REPLY_UNRECOGNIZED")
    if "org.freedesktop.DBus.Error.NameHasNoOwner" in raw:
        raise OwnerError("NO_CURRENT_FOTA_OWNER")
    if "org.freedesktop.DBus.Error.AccessDenied" in raw:
        raise OwnerError("REGISTRY_QUERY_DENIED")
    if "not found" in raw.lower() or "no such file" in raw.lower():
        raise OwnerError("REGISTRY_TOOL_UNAVAILABLE")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 2 or not lines[0].startswith("method return "):
        raise OwnerError("REGISTRY_REPLY_UNRECOGNIZED")
    if kind in ("id", "owner"):
        pattern = r'string "([a-f0-9]{32})"' if kind == "id" else r'string "(:[0-9]{1,10}\.[0-9]{1,10})"'
        match = re.fullmatch(pattern, lines[1])
        if match:
            return match.group(1)
    elif kind in ("pid", "uid"):
        match = re.fullmatch(r"uint32 (0|[1-9][0-9]{0,9})", lines[1])
        if match:
            number = int(match.group(1))
            if 0 <= number <= 0xFFFFFFFF and (kind == "uid" or 1 <= number <= 4194304):
                return number
    raise OwnerError("REGISTRY_REPLY_UNRECOGNIZED")


def query(ip: str, key: Path, operation: str, *, pid=None, timeout=8) -> str:
    """Reuse existing SDB framing and the two supported shell service forms."""
    if (operation not in FOTA_OWNER_REGISTRY_PROBES and
            operation not in FOTA_UNIT_METADATA_PROBES and operation != "process_executable"):
        raise OwnerError("OWNER_OPERATION_NOT_ALLOWLISTED")
    if operation == "process_executable" and (type(pid) is not int or not 1 <= pid <= 4194304):
        raise OwnerError("REGISTRY_PROCESS_ID_INVALID")
    for style in ("standard", "tizen-command"):
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                channel = Connection(sock, key)
                channel.handshake()
                return (channel.process_executable(pid, style=style) if operation == "process_executable"
                        else channel.shell(operation, style=style))
        except ShellCloseError:
            if style == "tizen-command":
                raise OwnerError("OWNER_READONLY_SHELL_REFUSED_OR_TIMED_OUT") from None
        except SdbError:
            raise OwnerError("OWNER_SDB_AUTH_OR_PROTOCOL_FAILED") from None
        except (OSError, TimeoutError):
            raise OwnerError("OWNER_SDB_TRANSPORT_UNAVAILABLE") from None
    raise OwnerError("OWNER_READONLY_SHELL_REFUSED_OR_TIMED_OUT")


def process_link(raw: str) -> bytes:
    """Keep denied/missing proc links distinct from a binary-copy failure."""
    if isinstance(raw, str) and len(raw) <= 2048:
        lower = raw.lower()
        if "permission denied" in lower or "access denied" in lower:
            raise OwnerError("OWNER_PROCESS_LINK_ACCESS_DENIED")
        if "no such file" in lower or "not found" in lower:
            raise OwnerError("OWNER_PROCESS_LINK_UNAVAILABLE")
    try:
        return vendor_executable_path(raw)
    except ArtifactPullError:
        raise OwnerError("OWNER_PROCESS_LINK_UNRECOGNIZED") from None


def base_report(copy_binary: bool) -> dict:
    return {
        "schema": SCHEMA,
        "state": "OWNER_NOT_YET_OBSERVED",
        "target_name": "fota.consumer",
        "queried_destination": "org.freedesktop.DBus",
        "bus": "SYSTEM",
        "prior_model_record": "SM-R840X / R840XXXU1AUA2 / PAP",
        "device_identity_attested": False,
        "watch_contacted": False,
        "owner_snapshot_stable": False,
        "owner_uid": None,
        "observed_executable": None,
        "binary_copy_requested": copy_binary,
        "binary_copied": False,
        "binary": None,
        "service_activation_requested": False,
        "fota_method_called": False,
        "process_memory_read": False,
        "root_obtained": False,
        "signature_bypass_proven": False,
        "stock_recovery_proven": False,
        "custom_boot_proven": False,
        "firmware_written": False,
        "flash_allowed": False,
        "result": "NO_GO",
    }


def configured_unit(raw: str) -> dict:
    """Parse selected properties only; never retain argv, PIDs or timestamps.

    Both systemd v219 and current systemctl print ExecStart records beginning
    '{ path=... ; argv[]=...'. Only one record and one safe vendor path are
    accepted. The arguments are never interpreted or passed to a shell.
    """
    if not isinstance(raw, str) or not 1 <= len(raw) <= 8192:
        raise OwnerError("UNIT_PROPERTIES_UNRECOGNIZED")
    lower = raw.lower()
    if "permission denied" in lower or "access denied" in lower:
        raise OwnerError("UNIT_PROPERTIES_ACCESS_DENIED")
    if "systemctl:" in lower and ("not found" in lower or "no such file" in lower):
        raise OwnerError("UNIT_PROPERTIES_TOOL_UNAVAILABLE")
    fields = {}
    for line in raw.splitlines():
        if not line or "=" not in line:
            raise OwnerError("UNIT_PROPERTIES_UNRECOGNIZED")
        name, value = line.split("=", 1)
        if name not in UNIT_FIELDS or name in fields or len(value) > 4096:
            raise OwnerError("UNIT_PROPERTIES_UNRECOGNIZED")
        fields[name] = value
    if set(fields) != UNIT_FIELDS or fields["Id"] != UNIT_ID:
        raise OwnerError("UNIT_PROPERTIES_UNRECOGNIZED")
    if fields["LoadState"] != "loaded":
        raise OwnerError("UNIT_NOT_LOADED_OR_UNAVAILABLE")
    if fields["FragmentPath"] != UNIT_FRAGMENT:
        raise OwnerError("UNIT_FRAGMENT_DIFFERS_FROM_OBSERVED_PATH")
    for name in ("LoadState", "ActiveState", "SubState", "Type"):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", fields[name]):
            raise OwnerError("UNIT_PROPERTIES_UNRECOGNIZED")
    for name in ("BusName", "User", "Group"):
        if fields[name] and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", fields[name]):
            raise OwnerError("UNIT_PROPERTIES_UNRECOGNIZED")
    command = fields["ExecStart"]
    match = re.match(r"\{ path=([^\s;]+) ; argv\[\]=", command)
    if (not match or command.count("{ path=") != 1 or
            not command.endswith(" }")):
        raise OwnerError("UNIT_EXECUTABLE_NOT_SINGLE_SIMPLE_PATH")
    try:
        path = vendor_executable_path(match.group(1)).decode("ascii")
    except ArtifactPullError:
        raise OwnerError("UNIT_EXECUTABLE_PATH_REJECTED") from None
    return {
        "unit_id": fields["Id"], "fragment_path": fields["FragmentPath"],
        "load_state": fields["LoadState"], "active_state": fields["ActiveState"],
        "sub_state": fields["SubState"], "service_type": fields["Type"],
        "configured_bus_name": fields["BusName"] or None,
        "configured_user": fields["User"] or None,
        "configured_group": fields["Group"] or None,
        "configured_executable": path,
    }


def _write_report(destination: Path, name: str, result: dict) -> None:
    fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as target:
        target.write(json.dumps(result, indent=2) + "\n")


def capture_configured_unit(ip: str, key: Path, destination: Path, *, timeout=8) -> dict:
    """Inspect one known unit, then copy only its evidenced normal executable.

    This is separate from the live-owner route: no FOTA PID/UID or ownership
    is claimed. No service is started to make either kind of evidence exist.
    """
    ip = private_watch_ip(ip)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = base_report(True)
    result.update(schema="uglyos-r840x-configured-fota-unit-v1",
                  state="UNIT_NOT_YET_OBSERVED", evidence_kind="CONFIGURED_SYSTEMD_UNIT",
                  queried_destination="org.freedesktop.DBus / org.freedesktop.systemd1",
                  configured_unit=None, configured_fields_stable=False,
                  unit_configuration_may_be_loaded=True)

    def registry(operation, kind):
        raw = query(ip, key, operation, timeout=timeout)
        result["watch_contacted"] = True
        try:
            return parse_reply(raw, kind)
        except OwnerError as exc:
            if str(exc) == "NO_CURRENT_FOTA_OWNER":
                raise OwnerError("NO_CURRENT_SYSTEMD_MANAGER") from None
            raise

    def unit():
        raw = query(ip, key, "fota_unit_properties", timeout=timeout)
        result["watch_contacted"] = True
        return configured_unit(raw)

    def check_manager(bus_id, manager):
        if (registry("fota_unit_manager_owner", "owner") != manager or
                registry("fota_registry_id", "id") != bus_id):
            raise OwnerError("UNIT_MANAGER_CHANGED_DURING_OBSERVATION")

    try:
        bus_id = registry("fota_registry_id", "id")
        manager = registry("fota_unit_manager_owner", "owner")
        observed = unit()
        check_manager(bus_id, manager)
        result["configured_unit"] = observed
        # Never execute even a configured wrapper. The shared reader accepts
        # ARM ELF only; a shell script gets a categorical non-ELF result.
        executable = observed["configured_executable"].encode("ascii")
        with tempfile.NamedTemporaryFile(dir=destination, prefix=".unit-", suffix=".tmp") as temp:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                info = _receive_arm_elf(sock, key, temp, executable)
            temp.flush()
            os.fsync(temp.fileno())
            if unit() != observed:
                raise OwnerError("UNIT_FIELDS_CHANGED_DURING_COPY")
            check_manager(bus_id, manager)
            _save_local_exclusive(temp.name, destination / UNIT_BINARY, info["bytes"])
        result.update(binary_copied=True, binary=info, configured_fields_stable=True,
                      state="CONFIGURED_FOTA_UNIT_BINARY_COPIED_READONLY")
    except OwnerError as exc:
        result["state"] = str(exc)
        result["configured_unit"] = None
    except ArtifactPullError as exc:
        result.update(state="CONFIGURED_UNIT_ARTIFACT_READ_REJECTED", artifact_error=str(exc))
    except (SdbError, OSError, TimeoutError):
        result["state"] = "CONFIGURED_UNIT_SDB_OR_LOCAL_IO_FAILED"
    _write_report(destination, UNIT_REPORT, result)
    return result


def capture(ip: str, key: Path, destination: Path, *, copy_binary=False, timeout=8) -> dict:
    """One bounded observation; no polling or attempts to start an idle owner."""
    ip = private_watch_ip(ip)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = base_report(copy_binary)
    phase = "registry"

    def registry(kind):
        raw = query(ip, key, "fota_registry_" + kind, timeout=timeout)
        result["watch_contacted"] = True
        return parse_reply(raw, "id" if kind == "id" else "owner" if kind == "owner" else kind)

    def ensure_same_owner(bus_id, owner):
        if registry("owner") != owner or registry("id") != bus_id:
            raise OwnerError("FOTA_OWNER_CHANGED_DURING_OBSERVATION")

    try:
        bus_id = registry("id")
        owner = registry("owner")
        pid = registry("pid")
        uid = registry("uid")
        phase = "process_link"
        executable = process_link(query(
            ip, key, "process_executable", pid=pid, timeout=timeout))
        ensure_same_owner(bus_id, owner)
        result.update(owner_snapshot_stable=True, owner_uid=uid,
                      observed_executable=executable.decode("ascii"),
                      state="EXISTING_FOTA_OWNER_EXECUTABLE_OBSERVED")
        if copy_binary:
            phase = "binary_copy"
            # NamedTemporaryFile is private (0600) and is removed even if a
            # race, denied read or malformed ELF prevents publication.
            with tempfile.NamedTemporaryFile(dir=destination, prefix=".owner-", suffix=".tmp") as temp:
                with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    info = _receive_arm_elf(sock, key, temp, executable)
                temp.flush()
                os.fsync(temp.fileno())
                ensure_same_owner(bus_id, owner)
                if process_link(query(ip, key, "process_executable", pid=pid,
                                                timeout=timeout)) != executable:
                    raise OwnerError("FOTA_EXECUTABLE_CHANGED_DURING_COPY")
                ensure_same_owner(bus_id, owner)
                _save_local_exclusive(temp.name, destination / BINARY, info["bytes"])
            result.update(binary_copied=True, binary=info,
                          state="EXISTING_FOTA_OWNER_BINARY_COPIED_READONLY")
    except OwnerError as exc:
        result["state"] = str(exc)
        if phase != "registry":
            result.update(owner_snapshot_stable=False, owner_uid=None, observed_executable=None)
    except ArtifactPullError as exc:
        # ArtifactPullError messages are already categorical in the shared reader.
        result["state"] = "OWNER_ARTIFACT_READ_REJECTED"
        result["artifact_error"] = str(exc)
    except (SdbError, OSError, TimeoutError):
        result["state"] = "OWNER_SDB_OR_LOCAL_IO_FAILED"
    # Neither unique bus names, bus IDs, numeric PIDs nor raw replies persist.
    _write_report(destination, REPORT, result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--copy-existing-owner", action="store_true")
    mode.add_argument("--copy-configured-unit", action="store_true",
                      help="Read the known unit's systemd properties and copy its configured ELF; never start it")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    args = parser.parse_args(argv)
    if args.output_dir is None:
        args.output_dir = Path.home() / ("watch3-r840x-fota-unit-evidence" if args.copy_configured_unit
                                       else "watch3-r840x-fota-owner-evidence")
    report_name = UNIT_REPORT if args.copy_configured_unit else REPORT
    binary_name = UNIT_BINARY if args.copy_configured_unit else BINARY
    try:
        result = (capture_configured_unit(args.watch_ip, args.key_path, args.output_dir)
                  if args.copy_configured_unit else
                  capture(args.watch_ip, args.key_path, args.output_dir,
                          copy_binary=args.copy_existing_owner))
    except (SdbError, OSError):
        print("OWNER_PROBE_NOT_STARTED: use a local watch IP and a new private output directory.",
              file=sys.stderr)
        return 2
    label = "UNIT" if args.copy_configured_unit else "OWNER"
    print(label + "_STATE: " + result["state"])
    print(label + "_REPORT: " + str(args.output_dir / report_name))
    if result["binary_copied"]:
        print("PRIVATE_OFFLINE_ELF: " + str(args.output_dir / binary_name))
    print("NO_GO: No root, firmware change, recovery or custom boot proved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
