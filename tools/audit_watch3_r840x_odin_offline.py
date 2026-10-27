#!/usr/bin/env python3
"""Offline-only Samsung Odin command risk audit for the owner's SM-R840X.

Reads this repository's existing Python magic-only client as *text* and
checks narrow AST invariants. Prints a source-anchored protocol risk catalog.
No sockets, packets, Odin sessions, subprocesses, watch files or firmware
are opened. This is a regression tripwire, NOT a formal security proof.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import sys

SCHEMA = "uglyos-r840x-odin-offline-command-audit-v1"
RAGNAROEK_REF = "f9164d2c227369ba711d89f12eef99186df61387"
SOURCE_ROOT = "https://github.com/AsteroidOS/ragnaroek/blob/" + RAGNAROEK_REF
MAGIC_SCRIPT = Path(__file__).resolve().parent / "watch3_r840x_netodin_magic_only.py"
LIVE_WATCH_COMMANDS_AUTHORIZED = False

# Grounded by Ragnarök's actual source at RAGNAROEK_REF. Every entry
# beyond the four-byte magic is NO-GO on the user's only working watch.
# "read_intent" means the protocol requests information; it does not mean
# a command is passive, reversible or safe on this untested bootloader.
COMMANDS = (
    {
        "name": "Magic greeting",
        "primary_opcode": None,
        "argument": None,
        "expected_wire_bytes": 4,
        "intent": "protocol_magic",
        "source": "ragnaroek/src/download_protocol/magic_handshake.rs",
        "hardware_evidence": "ODIN_LOKE_EXCHANGED_AND_WATCH_RETURNED_TO_STOCK",
        "watch_allowed_now": False,
        "risk": "Already verified once on this watch; repetition unnecessary.",
    },
    {
        "name": "Session start / protocol negotiation",
        "primary_opcode": "0x64",
        "argument": "0x00",
        "expected_wire_bytes": 1024,
        "intent": "changes_loader_session_state",
        "source": "ragnaroek/src/download_protocol/begin_session.rs",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "A Ragnarök detect/PIT command sends this after magic; not passive.",
    },
    {
        "name": "Set transfer part size",
        "primary_opcode": "0x64",
        "argument": "0x05",
        "expected_wire_bytes": 1024,
        "intent": "changes_loader_transfer_parameters",
        "source": "ragnaroek/src/download_protocol/begin_session.rs",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Can change session transfer behavior; protocol-version dependent.",
    },
    {
        "name": "Erase user data",
        "primary_opcode": "0x64",
        "argument": "0x07",
        "expected_wire_bytes": 1024,
        "intent": "destructive_factory_reset",
        "source": "ragnaroek/src/download_protocol/begin_session.rs",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Ragnarök implements this as factory_reset. Never test.",
    },
    {
        "name": "T-Flash mode",
        "primary_opcode": "0x64",
        "argument": "0x08",
        "expected_wire_bytes": 1024,
        "intent": "changes_storage_target",
        "source": "ragnaroek/src/download_protocol/types/session.rs",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Changes download target; irrelevant until verified recovery exists.",
    },
    {
        "name": "Request partition information",
        "primary_opcode": "0x65",
        "argument": "0x01",
        "expected_wire_bytes": 1024,
        "intent": "read_intent_but_session_state_required",
        "source": "ragnaroek/src/download_protocol/download_pit.rs",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Requires session start and additional requests; do not call passive.",
    },
    {
        "name": "Flash partition information",
        "primary_opcode": "0x65",
        "argument": "0x00",
        "expected_wire_bytes": 1024,
        "intent": "partition_table_write_intent",
        "source": "ragnaroek/src/download_protocol/flash_pit.rs",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Repartitioning can make stock rescue impossible.",
    },
    {
        "name": "Request partition data dump",
        "primary_opcode": "0x66",
        "argument": "0x01",
        "expected_wire_bytes": 1024,
        "intent": "read_intent_with_unverified_device_effects",
        "source": "PROTOCOL.md",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Read-like name is not a safe operation; may expose private data.",
    },
    {
        "name": "Flash partition data",
        "primary_opcode": "0x66",
        "argument": "0x00",
        "expected_wire_bytes": 1024,
        "intent": "firmware_write_intent",
        "source": "ragnaroek/src/download_protocol/flash",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Irreversible partition mutation possible. No-go.",
    },
    {
        "name": "Session end / reboot or shutdown",
        "primary_opcode": "0x67",
        "argument": "0x00..0x03",
        "expected_wire_bytes": 1024,
        "intent": "changes_loader_session_or_power_state",
        "source": "ragnaroek/src/download_protocol/end_session.rs",
        "hardware_evidence": "NOT_TESTED_ON_R840X",
        "watch_allowed_now": False,
        "risk": "Even no-reboot session end changes loader state; version dependent.",
    },
)

class OfflineAuditError(ValueError):
    """Fail-closed source integrity error; do not expose arbitrary input."""


def assignment_literal(tree: ast.Module, name: str):
    found = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                found.append(node.value)
    if len(found) != 1:
        raise OfflineAuditError("MISSING_OR_AMBIGUOUS_MAGIC_CONSTANT")
    try:
        return ast.literal_eval(found[0])
    except (ValueError, TypeError, MemoryError, RecursionError):
        raise OfflineAuditError("MAGIC_CONSTANT_NOT_LITERAL") from None


def audit_magic_source(source: str) -> dict:
    """Inspect syntax only. Never import or execute the magic-only client."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        raise OfflineAuditError("MAGIC_SCRIPT_SYNTAX_INVALID") from None
    if assignment_literal(tree, "MAGIC_OUT") != b"ODIN":
        raise OfflineAuditError("MAGIC_OUT_NOT_FOUR_BYTES_ODIN")
    if assignment_literal(tree, "MAGIC_IN") != b"LOKE":
        raise OfflineAuditError("MAGIC_IN_NOT_FOUR_BYTES_LOKE")
    if assignment_literal(tree, "PORT") != 13579:
        raise OfflineAuditError("MAGIC_LISTENER_PORT_CHANGED")

    prohibited_modules = {"subprocess", "ctypes", "struct", "serial", "requests"}
    unsafe_call_names = {"eval", "exec", "compile", "__import__", "getattr", "setattr"}
    unsafe_methods = {"send", "sendto", "sendmsg", "sendfile",
                      "write_all", "connect", "connect_ex"}
    sendalls = []
    receives = []
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in unsafe_call_names:
                raise OfflineAuditError("DYNAMIC_EXECUTION_OR_INTROSPECTION_PRESENT")
            if not isinstance(node.func, ast.Attribute):
                continue
            attr = node.func.attr
            if attr in unsafe_methods:
                raise OfflineAuditError("ADDITIONAL_NETWORK_SEND_OR_CONNECT_PRESENT")
            if attr == "sendall":
                sendalls.append(node)
            elif attr == "recv":
                receives.append(node)
    if prohibited_modules.intersection(imported):
        raise OfflineAuditError("UNEXPECTED_EXECUTION_OR_PACKET_MODULE_IMPORT")
    if len(sendalls) != 1:
        raise OfflineAuditError("MAGIC_SEND_COUNT_NOT_ONE")
    call = sendalls[0]
    if not (isinstance(call.func.value, ast.Name) and
            call.func.value.id == "peer" and len(call.args) == 1 and
            isinstance(call.args[0], ast.Name) and
            call.args[0].id == "MAGIC_OUT" and not call.keywords):
        raise OfflineAuditError("MAGIC_SEND_PAYLOAD_OR_PEER_CHANGED")
    if len(receives) != 1:
        raise OfflineAuditError("MAGIC_RECEIVE_COUNT_NOT_ONE")
    receive = receives[0]
    if not (isinstance(receive.func.value, ast.Name) and
            receive.func.value.id == "peer" and len(receive.args) == 1 and
            isinstance(receive.args[0], ast.BinOp) and
            isinstance(receive.args[0].op, ast.Sub) and
            isinstance(receive.args[0].left, ast.Constant) and
            receive.args[0].left.value == 4 and
            isinstance(receive.args[0].right, ast.Call) and
            isinstance(receive.args[0].right.func, ast.Name) and
            receive.args[0].right.func.id == "len" and
            len(receive.args[0].right.args) == 1 and
            isinstance(receive.args[0].right.args[0], ast.Name) and
            receive.args[0].right.args[0].id == "answer"):
        raise OfflineAuditError("MAGIC_RECEIVE_BOUND_CHANGED")
    return {
        "outbound_sendall_sites": 1,
        "exact_magic_out": "ODIN",
        "exact_magic_in": "LOKE",
        "expected_response_bytes": 4,
        "command_frame_send_sites": 0,
        "magic_only_static_regression_check": "PASSED_LIMITED_AST_CHECK",
        "limit": (
            "Only a narrow AST tripwire for this one source file. It cannot "
            "prove safety of imported code, runtime behavior or a bootloader."
        ),
    }


def build_report(script_path: Path = MAGIC_SCRIPT) -> dict:
    if script_path.is_symlink() or not script_path.is_file():
        raise OfflineAuditError("MAGIC_SCRIPT_UNAVAILABLE_OR_SYMLINK")
    if script_path.stat().st_size > 65536:
        raise OfflineAuditError("MAGIC_SCRIPT_OVERSIZED")
    try:
        source = script_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise OfflineAuditError("MAGIC_SCRIPT_NOT_READABLE") from None
    check = audit_magic_source(source)
    return {
        "schema": SCHEMA,
        "status": "OFFLINE_ODIN_RISK_CLASSIFICATION_ONLY",
        "device": "Samsung Galaxy Watch3 SM-R840X R08",
        "source_pin": RAGNAROEK_REF,
        "source_protocol": SOURCE_ROOT + "/PROTOCOL.md",
        "magic_source_regression": check,
        "commands": list(COMMANDS),
        "hardware_result": {
            "magic_handshake": "PHYSICALLY_OBSERVED_ODIN_LOKE",
            "stock_tizen_after_test": "OWNER_CONFIRMED_NORMAL_BOOT",
            "all_1024_byte_commands": "NOT_SENT_TO_WATCH",
        },
        "new_live_command_authorized": LIVE_WATCH_COMMANDS_AUTHORIZED,
        "watch_contacted": False,
        "socket_opened": False,
        "network_packets_sent": False,
        "firmware_written": False,
        "pit_requested": False,
        "root_obtained": False,
        "unsigned_boot_proven": False,
        "stock_restore_proven": False,
        "meaning": (
            "Offline source classification, not a real loader command probe. "
            "No 1024-byte Odin command is authorized without exact-model "
            "authentic restoration and independently validated recovery."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path,
                        help="Optional private JSON output, exclusive creation only")
    args = parser.parse_args()
    try:
        result = build_report()
        payload = (json.dumps(result, indent=2) + "\n").encode()
        if args.report:
            output = args.report.expanduser()
            fd = os.open(str(output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
            except BaseException:
                output.unlink(missing_ok=True)
                raise
            print("OFFLINE_ODIN_RISK_REPORT: " + str(output))
        else:
            print(payload.decode(), end="")
    except (OfflineAuditError, OSError) as exc:
        msg = str(exc) if isinstance(exc, OfflineAuditError) else "LOCAL_IO_ERROR"
        print("OFFLINE_ODIN_AUDIT_BLOCKED: " + msg, file=sys.stderr)
        return 1
    print("NO WATCH, NETWORK, ODIN COMMAND, PIT, SESSION OR FIRMWARE ACTION.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
