#!/usr/bin/env python3
"""Read bounded standard D-Bus policy evidence from an owned R840X.

Fixed SDB sync LIST/RECV only. Never activate a service, send a D-Bus
message, execute vendor code, request root, change security state, or write
to the watch. Reports are evidence, NOT an effective-permission decision.
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

from watch3_r08_android_sdb import PORT, SdbError, private_watch_ip
from watch3_r08_fota_consumer_inventory import (
    DBUS_POLICY_DIRECTORIES, DBUS_FOTA_POLICY_NAME,
    InventoryError, list_one,
)
from watch3_r08_fota_handoff_pull import HandoffError, _receive_bounded_file

MAX_BYTES = 64 * 1024
MAX_POLICY_FILES = 8
MAX_RELEVANT_RULES = 128
# Only standard fixed configuration files, no directory walk or CLI paths.
CORE_FILES = (
    b"/usr/share/dbus-1/system.conf",
    b"/etc/dbus-1/system.conf",
    b"/etc/dbus-1/system-local.conf",
)
RULE_FIELDS = (
    "send_destination", "send_interface", "send_member", "send_type",
    "own", "receive_sender", "receive_type",
)
SAFE_FIELD = re.compile(r"[A-Za-z0-9_.:*+-]{1,128}\Z")
SAFE_POLICY = re.compile(r"[A-Za-z0-9_.+-]{1,64}\Z")


class PolicyError(ValueError):
    """Privacy-safe, categorical outcome."""


def allowed_path(path: bytes) -> bool:
    if path in CORE_FILES:
        return True
    return any(
        path.startswith(root + b"/") and
        DBUS_FOTA_POLICY_NAME.fullmatch(path[len(root) + 1:].decode("ascii", "strict"))
        for root in DBUS_POLICY_DIRECTORIES.values()
    )


def read_file(ip: str, key: Path, path: bytes, timeout: int = 10) -> bytes:
    # Never turn a filename or error returned by the watch into an arbitrary RECV.
    if type(path) is not bytes or not allowed_path(path):
        raise PolicyError("POLICY_PATH_NOT_ALLOWLISTED")
    try:
        with socket.create_connection((ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return _receive_bounded_file(sock, key, path, MAX_BYTES)
    except HandoffError as exc:
        raise PolicyError("POLICY_RECV_" + str(exc)) from None
    except (OSError, SdbError, TimeoutError):
        raise PolicyError("POLICY_SDB_UNAVAILABLE") from None


def list_policy_dir(ip: str, key: Path, scope: str, timeout: int = 10) -> dict:
    if scope not in DBUS_POLICY_DIRECTORIES:
        raise PolicyError("POLICY_SCOPE_NOT_ALLOWLISTED")
    try:
        with socket.create_connection((ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return list_one(sock, key, scope)
    except InventoryError as exc:
        return {"status": str(exc)}
    except (OSError, SdbError, TimeoutError):
        return {"status": "POLICY_SDB_UNAVAILABLE"}


def analyze_xml(raw: bytes) -> dict:
    """Extract only FOTA/structural policy evidence without declaring permission."""
    if not raw or len(raw) > MAX_BYTES:
        raise PolicyError("POLICY_XML_SIZE_INVALID")
    if b"<!ENTITY" in raw.upper() or b"<![" in raw.upper():
        raise PolicyError("POLICY_XML_ENTITY_OR_SECTION_REJECTED")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        raise PolicyError("POLICY_XML_MALFORMED") from None
    if root.tag != "busconfig":
        raise PolicyError("POLICY_XML_UNEXPECTED_ROOT")
    includes = 0
    includedirs = 0
    rules = []
    unmatched_policy_blocks = 0
    for child in root:
        if child.tag == "include":
            includes += 1
        elif child.tag == "includedir":
            includedirs += 1
        elif child.tag == "policy":
            if len(child) > 1024:
                raise PolicyError("POLICY_XML_RULE_COUNT_LIMIT")
            retained = 0
            for node in child:
                if node.tag not in ("allow", "deny"):
                    continue
                fields = {k: v for k, v in node.attrib.items() if k in RULE_FIELDS}
                if not fields or any(not SAFE_FIELD.fullmatch(v) for v in fields.values()):
                    continue
                relevant = (
                    any(fields.get(key) in ("fota.consumer", "*") for key in
                        ("send_destination", "own", "receive_sender")) or
                    fields.get("send_type") == "method_call" or
                    fields.get("send_type") == "*" or
                    fields.get("receive_type") == "method_call"
                )
                if not relevant:
                    continue
                scope = {k: v for k, v in child.attrib.items()
                         if k in ("user", "group", "context")
                         and isinstance(v, str) and SAFE_FIELD.fullmatch(v)}
                rules.append({"scope": scope, "action": node.tag, "fields": fields})
                retained += 1
                if len(rules) > MAX_RELEVANT_RULES:
                    raise PolicyError("POLICY_XML_RELEVANT_RULE_LIMIT")
            if not retained:
                unmatched_policy_blocks += 1
    return {
        "xml_valid": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "include_tags": includes,
        "includedir_tags": includedirs,
        "relevant_rules": rules,
        "other_policy_blocks": unmatched_policy_blocks,
        "actual_effective_policy_proven": False,
    }


def collect(ip: str, key: Path) -> dict:
    ip = private_watch_ip(ip)
    evidence = {}
    for path in CORE_FILES:
        label = path.decode("ascii")
        try:
            evidence[label] = analyze_xml(read_file(ip, key, path))
        except PolicyError as exc:
            evidence[label] = {"status": str(exc)}
    directory_results = {}
    for scope, base in DBUS_POLICY_DIRECTORIES.items():
        result = list_policy_dir(ip, key, scope)
        directory_results[scope] = result
        if result.get("status") != "LIST_COMPLETE" or result.get("matching_names_truncated"):
            continue
        candidates = result.get("matching_fota_policy_files", {})
        if type(candidates) is not dict or len(candidates) > MAX_POLICY_FILES:
            continue
        for name, facts in sorted(candidates.items()):
            if (not isinstance(name, str) or not DBUS_FOTA_POLICY_NAME.fullmatch(name)
                    or not isinstance(facts, dict)
                    or facts.get("kind") != "REGULAR_FILE"
                    or type(facts.get("bytes")) is not int
                    or not 0 < facts["bytes"] <= MAX_BYTES):
                continue
            path = base + b"/" + name.encode("ascii")
            label = path.decode("ascii")
            try:
                raw = read_file(ip, key, path)
                if len(raw) != facts["bytes"]:
                    raise PolicyError("POLICY_FILE_CHANGED_DURING_READ")
                evidence[label] = analyze_xml(raw)
            except PolicyError as exc:
                evidence[label] = {"status": str(exc)}
    return {
        "schema": "uglyos-r840x-dbus-policy-evidence-v1",
        "state": "PARTIAL_STANDARD_POLICY_EVIDENCE",
        "policy_files": evidence,
        "directory_results": directory_results,
        "bus_policy_complete": False,
        "user_shell_authorized_for_fota": "UNDETERMINED",
        "smack_cynara_authorization": "UNDETERMINED",
        "runtime_bus_identity_attested": False,
        "fota_method_called": False,
        "vendor_executable_executed": False,
        "watch_write_performed": False,
        "root_proven": False,
        "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "This is a bounded subset of standard policy files, not the merged "
            "effective D-Bus policy. Dynamic/nonstandard includes, policy order, "
            "SMACK/Cynara, running daemon settings and caller credentials remain "
            "unverified. Rules shown must not be evaluated as user authorization."
        ),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--watch-ip", required=True)
    p.add_argument("--key-path", type=Path, default=Path.home()/".config/galaxy3/watch3-sdbkey")
    p.add_argument("--report", type=Path, default=Path.home()/"watch3-r840x-dbus-policy-evidence.json")
    args = p.parse_args(argv)
    try:
        if args.report.exists() or args.report.is_symlink():
            raise PolicyError("POLICY_REPORT_ALREADY_EXISTS")
        if not args.report.parent.is_dir():
            raise PolicyError("POLICY_REPORT_PARENT_MISSING")
        result = collect(args.watch_ip, args.key_path)
        payload = (json.dumps(result, indent=2)+"\n").encode("utf-8")
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            args.report.unlink(missing_ok=True)
            raise
    except (PolicyError, OSError, ValueError) as exc:
        print("POLICY_EVIDENCE_ERROR: " + (str(exc) if isinstance(exc, PolicyError)
            else "LOCAL_OR_SDB_ERROR"), file=sys.stderr)
        return 1
    print("READ_ONLY_DBUS_POLICY_EVIDENCE: "+str(args.report))
    print("Partial config evidence only; no service call, execution or watch write.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
