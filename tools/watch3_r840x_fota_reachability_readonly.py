#!/usr/bin/env python3
"""Read bounded FOTA reachability facts from an owned R840X.

Fixed SDB shell probes only: the shell's own UID class, metadata of
the FOTA archive directory (/opt/usr/data/fota/save), its parent,
and the recovery handoff directory, a listing classification of the
archive directory, the DELTA.PATH node's presence, and read-only
gets of the two consumer vconf state keys. These facts decide
whether the UID 5001 shell can even see the consumer's update
entry points. Never create a file, set a key, call a FOTA method,
attempt an exploit, request root, or write to the watch. A POSIX
write bit is reported as a class only; no write is ever attempted,
and POSIX bits do not override SMACK. Reports retain only
categories; raw probe output is discarded.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from watch3_r08_android_sdb import (
    PORT, SdbError, ShellCloseError, Connection, FOTA_REACHABILITY_PROBES,
    private_watch_ip,
)

REACH_ALLOWED_OPS = frozenset(FOTA_REACHABILITY_PROBES)
REACH_OPS_IN_ORDER = (
    "shell_uid", "fota_parent_dir_metadata", "fota_save_dir_metadata",
    "fota_save_dir_listing", "recovery_dir_metadata", "delta_path_node",
    "vconf_ui_state", "vconf_consumer_state",
)

# Established by earlier physical captures on this watch: the SDB
# shell runs as UID 5001 with primary GID 100 (User::Shell).
SHELL_UID = 5001
SHELL_GID = 100

SAVE_DIR = "/opt/usr/data/fota/save"
PARENT_DIR = "/opt/usr/data/fota"
RECOVERY_DIR = "/opt/data/recovery"
DELTA_PATH = "/opt/data/recovery/DELTA.PATH"

_VCONF_ANSWERED = {"STATE_60", "STATE_65", "STATE_OTHER_INT", "KEY_ABSENT"}


class ReachabilityError(ValueError):
    """Privacy-safe, categorical outcome."""


def reachability_query(ip: str, key: Path, operation: str, timeout=8) -> str:
    """Existing SDB allowlist; no file creation, key set or FOTA call."""
    if operation not in REACH_ALLOWED_OPS:
        raise ReachabilityError("REACHABILITY_OPERATION_NOT_ALLOWLISTED")
    for style in ("standard", "tizen-command"):
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                channel = Connection(sock, key)
                channel.handshake()
                return channel.shell(operation, style=style)
        except ShellCloseError:
            if style == "tizen-command":
                raise ReachabilityError(
                    "REACHABILITY_SDB_SHELL_UNAVAILABLE") from None
        except (SdbError, OSError, TimeoutError):
            raise ReachabilityError(
                "REACHABILITY_SDB_CONNECTION_FAILED") from None
    raise ReachabilityError("REACHABILITY_SDB_SHELL_UNAVAILABLE")


def _bounded_text(raw, label: str, limit: int) -> str:
    if not isinstance(raw, str) or len(raw) > limit:
        raise ReachabilityError(label)
    return raw


def parse_shell_uid(raw: str) -> dict:
    """Classify `id -u`; the expected shell UID is a known constant."""
    _bounded_text(raw, "SHELL_UID_OUTPUT_INVALID", 64)
    token = raw.strip()
    if not re.fullmatch(r"[0-9]{1,7}", token):
        raise ReachabilityError("SHELL_UID_OUTPUT_INVALID")
    return {"status": "SHELL_UID_CLASSIFIED",
            "uid_class": "SHELL_UID_5001" if int(token) == SHELL_UID
            else "OTHER_UID"}


def parse_dir_metadata(raw: str, path: str) -> dict:
    """Classify one `ls -ldn <dir>` line into relations and access.

    Only the permission class that applies to the shell (owner when
    the directory owner is UID 5001, group when its group is GID
    100, otherwise other) is reduced to READ/WRITE/TRAVERSE names.
    Numeric ids, sizes and dates are discarded.
    """
    _bounded_text(raw, "DIR_METADATA_OUTPUT_INVALID", 1024)
    lowered = raw.lower()
    if "permission denied" in lowered:
        return {"status": "DIR_METADATA_CLASSIFIED",
                "presence": "ACCESS_DENIED"}
    if "no such file" in lowered:
        return {"status": "DIR_METADATA_CLASSIFIED", "presence": "ABSENT"}
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ReachabilityError("DIR_METADATA_OUTPUT_INVALID")
    tokens = lines[0].split()
    if len(tokens) < 9 or tokens[-1] != path:
        raise ReachabilityError("DIR_METADATA_OUTPUT_INVALID")
    mode = tokens[0]
    if len(mode) != 10 or not re.fullmatch(r"[dl-][rwxstST-]{9}", mode):
        raise ReachabilityError("DIR_METADATA_OUTPUT_INVALID")
    if mode[0] == "l":
        return {"status": "DIR_METADATA_CLASSIFIED",
                "presence": "SYMLINK_UNRESOLVED"}
    if mode[0] != "d" or not tokens[2].isdigit() or not tokens[3].isdigit():
        raise ReachabilityError("DIR_METADATA_OUTPUT_INVALID")
    uid, gid = int(tokens[2]), int(tokens[3])
    owner_relation = "OWNER_IS_SHELL" if uid == SHELL_UID else "OWNER_OTHER"
    group_relation = ("GROUP_IS_SHELL_GID" if gid == SHELL_GID
                      else "GROUP_OTHER")
    if uid == SHELL_UID:
        bits = mode[1:4]
    elif gid == SHELL_GID:
        bits = mode[4:7]
    else:
        bits = mode[7:10]
    # The execute slot may carry set-id/sticky letters (s/S/t/T);
    # all of them except S/T imply traversal is granted.
    names = []
    if bits[0] == "r":
        names.append("READ")
    if bits[1] == "w":
        names.append("WRITE")
    if bits[2] in "xst":
        names.append("TRAVERSE")
    return {"status": "DIR_METADATA_CLASSIFIED", "presence": "PRESENT",
            "owner_relation": owner_relation,
            "group_relation": group_relation,
            "shell_access_class": "_".join(names) if names else "NO_ACCESS"}


def parse_dir_listing(raw: str) -> dict:
    """Classify `ls <dir>`: listable or not, entry-count class only.

    Entry names are counted and discarded; an empty directory is a
    valid listable result, not an error.
    """
    if not isinstance(raw, str) or len(raw) > 8192:
        raise ReachabilityError("DIR_LISTING_OUTPUT_INVALID")
    if raw == "":
        return {"status": "DIR_LISTING_CLASSIFIED", "listing": "LISTABLE",
                "entry_count_class": "ZERO"}
    lowered = raw.lower()
    if "permission denied" in lowered:
        return {"status": "DIR_LISTING_CLASSIFIED",
                "listing": "ACCESS_DENIED"}
    if "no such file" in lowered:
        return {"status": "DIR_LISTING_CLASSIFIED", "listing": "ABSENT"}
    if "cannot access" in lowered or "cannot open" in lowered:
        raise ReachabilityError("DIR_LISTING_OUTPUT_INVALID")
    count = len([line for line in raw.splitlines() if line.strip()])
    count_class = ("ZERO" if count == 0 else
                   "ONE_TO_FIVE" if count <= 5 else "SIX_OR_MORE")
    return {"status": "DIR_LISTING_CLASSIFIED", "listing": "LISTABLE",
            "entry_count_class": count_class}


def parse_delta_node(raw: str) -> dict:
    """Classify the DELTA.PATH node by presence only; never read it."""
    _bounded_text(raw, "DELTA_NODE_OUTPUT_INVALID", 1024)
    lowered = raw.lower()
    if "permission denied" in lowered:
        presence = "ACCESS_DENIED"
    elif "no such file" in lowered:
        presence = "ABSENT"
    elif raw.strip() == DELTA_PATH:
        presence = "PRESENT"
    else:
        presence = "UNRECOGNIZED"
    return {"status": "DELTA_NODE_CLASSIFIED", "presence": presence}


def parse_vconf_state(raw: str) -> dict:
    """Classify a read-only `vconftool get` answer; never retain it.

    States 60 and 65 are the consumer's documented update/result
    states; any other integer is only OTHER. A missing key means the
    get was answered, which is itself the reachability fact.
    """
    _bounded_text(raw, "VCONF_STATE_OUTPUT_INVALID", 1024)
    lowered = raw.lower()
    if "vconftool" in lowered and ("not found" in lowered
                                    or "no such file" in lowered):
        state_class = "TOOL_UNAVAILABLE"
    elif "permission denied" in lowered:
        state_class = "ACCESS_DENIED"
    elif any(marker in lowered for marker in
             ("no such key", "key not found", "does not exist",
              "no value", "invalid key", "cannot get")):
        state_class = "KEY_ABSENT"
    else:
        integers = re.findall(r"-?[0-9]+", raw)
        if not integers:
            state_class = "UNRECOGNIZED"
        else:
            value = int(integers[-1])
            state_class = {60: "STATE_60", 65: "STATE_65"}.get(
                value, "STATE_OTHER_INT")
    return {"status": "VCONF_STATE_CLASSIFIED", "state_class": state_class}


REACH_PARSERS = {
    "shell_uid": parse_shell_uid,
    "fota_parent_dir_metadata": lambda raw: parse_dir_metadata(raw, PARENT_DIR),
    "fota_save_dir_metadata": lambda raw: parse_dir_metadata(raw, SAVE_DIR),
    "fota_save_dir_listing": parse_dir_listing,
    "recovery_dir_metadata": lambda raw: parse_dir_metadata(raw, RECOVERY_DIR),
    "delta_path_node": parse_delta_node,
    "vconf_ui_state": parse_vconf_state,
    "vconf_consumer_state": parse_vconf_state,
}


def collect_reachability(ip: str, key: Path) -> dict:
    """Run the eight fixed reachability probes; failures stay categorical."""
    sources = {}
    for operation in REACH_OPS_IN_ORDER:
        try:
            sources[operation] = REACH_PARSERS[operation](
                reachability_query(ip, key, operation))
        except ReachabilityError as exc:
            sources[operation] = {"status": str(exc)}
    save_meta = sources["fota_save_dir_metadata"]
    if save_meta.get("presence") == "PRESENT":
        save_access = save_meta.get("shell_access_class", "UNDETERMINED")
    else:
        save_access = save_meta.get("presence", "UNDETERMINED")
    save_listing = sources["fota_save_dir_listing"].get(
        "listing", "UNDETERMINED")
    vconf_answered = any(
        sources[op].get("state_class") in _VCONF_ANSWERED
        for op in ("vconf_ui_state", "vconf_consumer_state"))
    return {
        "schema": "uglyos-r840x-fota-reachability-v1",
        "state": "READONLY_FOTA_REACHABILITY_ONLY",
        "sources": sources,
        "shell_uid_class": sources["shell_uid"].get(
            "uid_class", "UNDETERMINED"),
        "archive_dir_shell_access_class": save_access,
        "archive_dir_listing_class": save_listing,
        "vconf_get_answered": vconf_answered,
        "write_attempted": False,
        "vconf_write_performed": False,
        "fota_method_called": False,
        "exploit_attempted": False,
        "watch_write_performed": False,
        "root_proven": False,
        "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "Only reachability categories were retained; every raw "
            "probe output was discarded. Directory metadata reduces "
            "to the POSIX permission class that applies to the shell; "
            "a WRITE name there means the bit is set for the shell's "
            "class, not that a write would succeed (SMACK may still "
            "deny it) and no write was attempted. A vconf get being "
            "answered proves read reachability of the state keys "
            "only, not set permission. Neither outcome is an update "
            "trigger, a permission grant, or root."
        ),
    }


def save_reachability_report(path: Path, report: dict) -> None:
    """Create one new private report; an existing destination is kept."""
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(rendered)
    os.chmod(path, 0o600)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reachability-ip", required=True)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    ip = private_watch_ip(args.reachability_ip)
    if args.report.exists() or args.report.is_symlink():
        raise ReachabilityError("REACHABILITY_REPORT_ALREADY_EXISTS")
    report = collect_reachability(ip, args.key_path.expanduser())
    save_reachability_report(args.report.expanduser(), report)
    print(f"READ_ONLY_FOTA_REACHABILITY: {args.report.expanduser()}")
    print("Reachability facts only; no write, key set or FOTA call.")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
