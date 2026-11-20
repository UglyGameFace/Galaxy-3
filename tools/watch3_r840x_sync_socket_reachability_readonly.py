#!/usr/bin/env python3
"""Read bounded sync-agent event-socket reachability facts from an R840X.

Fixed SDB shell probes only: the shell's own UID class, metadata of
/tmp, metadata of the OMA-DM event socket node the sync-agent
library derives (/tmp/agent_fw_event_omadm), metadata of the
OMA-DM directory (/opt/usr/data/fota/oma-dm), and the presence of
its enabled-marker file. These facts decide whether the UID 5001
shell could even address the event channel the consumer's Install
method uses (event 4 to the receiving daemon), and whether the
marker that gates the consumer's OMA-DM launch is visible. Never
open a socket, send an event, create a file, set a key, call a
FOTA method, attempt an exploit, request root, or write to the
watch. A POSIX write bit on the socket node is reported as a
class only; for a socket that bit is the POSIX connect
permission, and POSIX bits do not override SMACK. Reports retain
only categories; raw probe output is discarded.
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
    PORT, SdbError, ShellCloseError, Connection,
    SYNC_SOCKET_REACHABILITY_PROBES, private_watch_ip,
)

SOCKET_ALLOWED_OPS = frozenset(SYNC_SOCKET_REACHABILITY_PROBES)
SOCKET_OPS_IN_ORDER = (
    "shell_uid", "tmp_dir_metadata", "event_socket_metadata",
    "omadm_dir_metadata", "omadm_marker_node",
)

# Established by earlier physical captures on this watch: the SDB
# shell runs as UID 5001 with primary GID 100 (User::Shell).
SHELL_UID = 5001
SHELL_GID = 100

TMP_DIR = "/tmp"
SOCKET_PATH = "/tmp/agent_fw_event_omadm"
OMADM_DIR = "/opt/usr/data/fota/oma-dm"
MARKER_PATH = "/opt/usr/data/fota/oma-dm/.oma-dm-agent-enabled"


class SocketReachabilityError(ValueError):
    """Privacy-safe, categorical outcome."""


def socket_reachability_query(ip: str, key: Path, operation: str,
                              timeout=8) -> str:
    """Existing SDB allowlist; no socket connect, event or write."""
    if operation not in SOCKET_ALLOWED_OPS:
        raise SocketReachabilityError(
            "SYNC_SOCKET_OPERATION_NOT_ALLOWLISTED")
    for style in ("standard", "tizen-command"):
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                channel = Connection(sock, key)
                channel.handshake()
                return channel.shell(operation, style=style)
        except ShellCloseError:
            if style == "tizen-command":
                raise SocketReachabilityError(
                    "SYNC_SOCKET_SDB_SHELL_UNAVAILABLE") from None
        except (SdbError, OSError, TimeoutError):
            raise SocketReachabilityError(
                "SYNC_SOCKET_SDB_CONNECTION_FAILED") from None
    raise SocketReachabilityError("SYNC_SOCKET_SDB_SHELL_UNAVAILABLE")


def _bounded_text(raw, label: str, limit: int) -> str:
    if not isinstance(raw, str) or len(raw) > limit:
        raise SocketReachabilityError(label)
    return raw


def parse_shell_uid(raw: str) -> dict:
    """Classify `id -u`; the expected shell UID is a known constant."""
    _bounded_text(raw, "SHELL_UID_OUTPUT_INVALID", 64)
    token = raw.strip()
    if not re.fullmatch(r"[0-9]{1,7}", token):
        raise SocketReachabilityError("SHELL_UID_OUTPUT_INVALID")
    return {"status": "SHELL_UID_CLASSIFIED",
            "uid_class": "SHELL_UID_5001" if int(token) == SHELL_UID
            else "OTHER_UID"}


def _shell_class_bits(mode: str, uid: int, gid: int) -> tuple:
    """Reduce an ls mode to the permission triple applying to the shell."""
    owner_relation = "OWNER_IS_SHELL" if uid == SHELL_UID else "OWNER_OTHER"
    group_relation = ("GROUP_IS_SHELL_GID" if gid == SHELL_GID
                      else "GROUP_OTHER")
    if uid == SHELL_UID:
        bits = mode[1:4]
    elif gid == SHELL_GID:
        bits = mode[4:7]
    else:
        bits = mode[7:10]
    return owner_relation, group_relation, bits


def _metadata_line(raw: str, path: str, label: str) -> tuple:
    """Validate one `ls -ldn` line; return (mode, uid, gid)."""
    _bounded_text(raw, label, 1024)
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        raise SocketReachabilityError(label)
    tokens = lines[0].split()
    if len(tokens) < 9 or tokens[-1] != path:
        raise SocketReachabilityError(label)
    mode = tokens[0]
    if len(mode) != 10 or not re.fullmatch(r"[a-zdl-][rwxstST-]{9}", mode):
        raise SocketReachabilityError(label)
    if not tokens[2].isdigit() or not tokens[3].isdigit():
        raise SocketReachabilityError(label)
    return mode, int(tokens[2]), int(tokens[3])


def parse_dir_metadata(raw: str, path: str) -> dict:
    """Classify one `ls -ldn <dir>` line into relations and access."""
    _bounded_text(raw, "DIR_METADATA_OUTPUT_INVALID", 1024)
    lowered = raw.lower()
    if "permission denied" in lowered:
        return {"status": "DIR_METADATA_CLASSIFIED",
                "presence": "ACCESS_DENIED"}
    if "no such file" in lowered:
        return {"status": "DIR_METADATA_CLASSIFIED", "presence": "ABSENT"}
    mode, uid, gid = _metadata_line(
        raw, path, "DIR_METADATA_OUTPUT_INVALID")
    if mode[0] == "l":
        return {"status": "DIR_METADATA_CLASSIFIED",
                "presence": "SYMLINK_UNRESOLVED"}
    if mode[0] != "d":
        raise SocketReachabilityError("DIR_METADATA_OUTPUT_INVALID")
    owner_relation, group_relation, bits = _shell_class_bits(mode, uid, gid)
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


def parse_socket_metadata(raw: str) -> dict:
    """Classify `ls -ldn` of the event socket node.

    The node kind is retained (a live listener's node is a socket;
    a stale regular file is a different fact). For the shell's
    permission class, the WRITE name is the POSIX connect
    permission for a socket node; it is reported, never exercised.
    """
    _bounded_text(raw, "SOCKET_METADATA_OUTPUT_INVALID", 1024)
    lowered = raw.lower()
    if "permission denied" in lowered:
        return {"status": "SOCKET_METADATA_CLASSIFIED",
                "presence": "ACCESS_DENIED"}
    if "no such file" in lowered:
        return {"status": "SOCKET_METADATA_CLASSIFIED",
                "presence": "ABSENT"}
    mode, uid, gid = _metadata_line(
        raw, SOCKET_PATH, "SOCKET_METADATA_OUTPUT_INVALID")
    if mode[0] == "l":
        return {"status": "SOCKET_METADATA_CLASSIFIED",
                "presence": "SYMLINK_UNRESOLVED"}
    node_kind = "SOCKET" if mode[0] == "s" else "OTHER_KIND"
    owner_relation, group_relation, bits = _shell_class_bits(mode, uid, gid)
    names = []
    if bits[0] == "r":
        names.append("READ")
    if bits[1] == "w":
        names.append("WRITE")
    if bits[2] in "xst":
        names.append("EXECUTE")
    return {"status": "SOCKET_METADATA_CLASSIFIED", "presence": "PRESENT",
            "node_kind": node_kind,
            "owner_relation": owner_relation,
            "group_relation": group_relation,
            "shell_access_class": "_".join(names) if names else "NO_ACCESS"}


def parse_marker_node(raw: str) -> dict:
    """Classify the OMA-DM enabled-marker node by presence only."""
    _bounded_text(raw, "MARKER_NODE_OUTPUT_INVALID", 1024)
    lowered = raw.lower()
    if "permission denied" in lowered:
        presence = "ACCESS_DENIED"
    elif "no such file" in lowered:
        presence = "ABSENT"
    elif raw.strip() == MARKER_PATH:
        presence = "PRESENT"
    else:
        presence = "UNRECOGNIZED"
    return {"status": "MARKER_NODE_CLASSIFIED", "presence": presence}


SOCKET_PARSERS = {
    "shell_uid": parse_shell_uid,
    "tmp_dir_metadata": lambda raw: parse_dir_metadata(raw, TMP_DIR),
    "event_socket_metadata": parse_socket_metadata,
    "omadm_dir_metadata": lambda raw: parse_dir_metadata(raw, OMADM_DIR),
    "omadm_marker_node": parse_marker_node,
}


def collect_socket_reachability(ip: str, key: Path) -> dict:
    """Run the five fixed socket-reachability probes; failures stay categorical."""
    sources = {}
    for operation in SOCKET_OPS_IN_ORDER:
        try:
            sources[operation] = SOCKET_PARSERS[operation](
                socket_reachability_query(ip, key, operation))
        except SocketReachabilityError as exc:
            sources[operation] = {"status": str(exc)}
    socket_meta = sources["event_socket_metadata"]
    if socket_meta.get("presence") == "PRESENT":
        socket_access = socket_meta.get("shell_access_class", "UNDETERMINED")
        socket_kind = socket_meta.get("node_kind", "UNDETERMINED")
    else:
        socket_access = socket_meta.get("presence", "UNDETERMINED")
        socket_kind = "UNDETERMINED"
    tmp_meta = sources["tmp_dir_metadata"]
    tmp_access = (tmp_meta.get("shell_access_class", "UNDETERMINED")
                  if tmp_meta.get("presence") == "PRESENT"
                  else tmp_meta.get("presence", "UNDETERMINED"))
    return {
        "schema": "uglyos-r840x-sync-socket-reachability-v1",
        "state": "READONLY_SYNC_SOCKET_REACHABILITY_ONLY",
        "sources": sources,
        "shell_uid_class": sources["shell_uid"].get(
            "uid_class", "UNDETERMINED"),
        "tmp_dir_shell_access_class": tmp_access,
        "event_socket_presence": socket_meta.get(
            "presence", "UNDETERMINED"),
        "event_socket_node_kind": socket_kind,
        "event_socket_shell_access_class": socket_access,
        "omadm_marker_presence": sources["omadm_marker_node"].get(
            "presence", "UNDETERMINED"),
        "socket_connect_attempted": False,
        "event_sent": False,
        "write_attempted": False,
        "exploit_attempted": False,
        "watch_write_performed": False,
        "root_proven": False,
        "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "Only reachability categories were retained; every raw "
            "probe output was discarded. For the event socket node, "
            "the WRITE name in the shell's permission class is the "
            "POSIX connect permission; it does not prove a "
            "connection would succeed (SMACK may still deny it) "
            "and none was attempted. Node presence proves a "
            "listener created the node at some point; it does not "
            "prove a receiver is currently accepting, which "
            "process owns it, or what its event-4 callback would "
            "do with a request. The consumer-side sync-agent "
            "library is configured client-only (RunEventHandler=0 "
            "in its captured initializer), so a present node would "
            "belong to another process. Neither outcome is an "
            "event submission, a permission grant, or root."
        ),
    }


def save_socket_report(path: Path, report: dict) -> None:
    """Create one new private report; an existing destination is kept."""
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(rendered)
    os.chmod(path, 0o600)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-ip", required=True)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    ip = private_watch_ip(args.socket_ip)
    if args.report.exists() or args.report.is_symlink():
        raise SocketReachabilityError("SYNC_SOCKET_REPORT_ALREADY_EXISTS")
    report = collect_socket_reachability(ip, args.key_path.expanduser())
    save_socket_report(args.report.expanduser(), report)
    print(f"READ_ONLY_SYNC_SOCKET_REACHABILITY: {args.report.expanduser()}")
    print("Socket reachability facts only; no connect, event send or write.")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
