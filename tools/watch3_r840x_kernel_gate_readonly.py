#!/usr/bin/env python3
"""Read bounded kernel-route gate facts from an owned R840X.

Fixed SDB shell probes only: kernel machine class, Binder device-node
presence and the unprivileged-BPF switch. These facts decide whether
any public kernel privilege-escalation family is reachable from the
UID 5001 shell at all. Never open a device, load a module, submit an
event, attempt an exploit, request root, or write to the watch.
Reports retain only categories; raw probe output is discarded.
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
    PORT, SdbError, ShellCloseError, Connection, KERNEL_GATE_PROBES,
    private_watch_ip,
)

GATE_ALLOWED_OPS = frozenset(KERNEL_GATE_PROBES)
GATE_RAW_MAX = 64 * 1024
GATE_OPS_IN_ORDER = (
    "kernel_machine", "binder_node", "binderfs_control_node",
    "bpf_unprivileged_disabled",
)

MACHINE_CLASSES = {
    "armv7l": "ARMV7L_32BIT",
    "armv8l": "ARMV8L_32BIT_USERLAND",
    "aarch64": "AARCH64_64BIT",
    "arm64": "AARCH64_64BIT",
}
BPF_CLASSES = {
    "0": "UNPRIVILEGED_BPF_NOT_DISABLED",
    "1": "UNPRIVILEGED_BPF_RESTRICTED",
    "2": "UNPRIVILEGED_BPF_DISABLED",
}


class KernelGateError(ValueError):
    """Privacy-safe, categorical outcome."""


def kernel_gate_query(ip: str, key: Path, operation: str, timeout=8) -> str:
    """Existing SDB allowlist; no device open, activation or shell input."""
    if operation not in GATE_ALLOWED_OPS:
        raise KernelGateError("KERNEL_GATE_OPERATION_NOT_ALLOWLISTED")
    for style in ("standard", "tizen-command"):
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                channel = Connection(sock, key)
                channel.handshake()
                return channel.shell(operation, style=style)
        except ShellCloseError:
            if style == "tizen-command":
                raise KernelGateError("KERNEL_GATE_SDB_SHELL_UNAVAILABLE") from None
        except (SdbError, OSError, TimeoutError):
            raise KernelGateError("KERNEL_GATE_SDB_CONNECTION_FAILED") from None
    raise KernelGateError("KERNEL_GATE_SDB_SHELL_UNAVAILABLE")


def _bounded_text(raw, label: str, limit: int) -> str:
    if not isinstance(raw, str) or not 1 <= len(raw) <= limit:
        raise KernelGateError(label)
    return raw


def parse_kernel_machine(raw: str) -> dict:
    """Classify `uname -m` without retaining the raw token."""
    _bounded_text(raw, "KERNEL_MACHINE_OUTPUT_INVALID", 256)
    token = raw.strip()
    if "\n" in token or not re.fullmatch(r"[a-z0-9_]{2,32}", token):
        raise KernelGateError("KERNEL_MACHINE_OUTPUT_INVALID")
    return {"status": "KERNEL_MACHINE_CLASSIFIED",
            "machine_class": MACHINE_CLASSES.get(token, "OTHER_MACHINE_CLASS")}


def parse_node_presence(raw: str, node_path: str) -> dict:
    """Classify one fixed `ls /dev/...` probe; the listing is discarded."""
    _bounded_text(raw, "KERNEL_NODE_OUTPUT_INVALID", 4096)
    lowered = raw.lower()
    if "permission denied" in lowered:
        presence = "ACCESS_DENIED"
    elif "no such file" in lowered:
        presence = "ABSENT"
    elif raw.strip() == node_path:
        presence = "PRESENT"
    else:
        presence = "UNRECOGNIZED"
    return {"status": "KERNEL_NODE_CLASSIFIED", "presence": presence}


def parse_bpf_disabled(raw: str) -> dict:
    """Classify the unprivileged-BPF switch; a missing file is a class."""
    _bounded_text(raw, "KERNEL_BPF_OUTPUT_INVALID", 256)
    token = raw.strip()
    if token in BPF_CLASSES:
        return {"status": "KERNEL_BPF_CLASSIFIED",
                "bpf_class": BPF_CLASSES[token]}
    if "no such file" in token.lower():
        return {"status": "KERNEL_BPF_CLASSIFIED",
                "bpf_class": "SETTING_ABSENT"}
    raise KernelGateError("KERNEL_BPF_OUTPUT_INVALID")


GATE_PARSERS = {
    "kernel_machine": parse_kernel_machine,
    "binder_node": lambda raw: parse_node_presence(raw, "/dev/binder"),
    "binderfs_control_node": lambda raw: parse_node_presence(
        raw, "/dev/binderfs/binder-control"),
    "bpf_unprivileged_disabled": parse_bpf_disabled,
}


def _binder_gate(sources: dict) -> str:
    presences = [sources[op].get("presence") for op in
                 ("binder_node", "binderfs_control_node")
                 if isinstance(sources.get(op), dict)]
    if "PRESENT" in presences:
        return "BINDER_NODE_PRESENT_GATE_OPEN"
    if presences and all(p == "ABSENT" for p in presences):
        return "BINDER_NODE_ABSENT_GATE_CLOSED"
    return "UNDETERMINED"


def collect_kernel_gate(ip: str, key: Path) -> dict:
    """Run the four fixed gate probes; every failure stays categorical."""
    sources = {}
    for operation in GATE_OPS_IN_ORDER:
        try:
            sources[operation] = GATE_PARSERS[operation](
                kernel_gate_query(ip, key, operation))
        except KernelGateError as exc:
            sources[operation] = {"status": str(exc)}
    machine = sources["kernel_machine"].get("machine_class", "UNDETERMINED")
    return {
        "schema": "uglyos-r840x-kernel-gate-v1",
        "state": "READONLY_KERNEL_GATE_ONLY",
        "sources": sources,
        "kernel_machine_class": machine,
        "binder_gate": _binder_gate(sources),
        "binder_kernel_patch_state_verified": False,
        "exploit_attempted": False,
        "device_node_opened": False,
        "watch_write_performed": False,
        "root_proven": False,
        "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "Only gate categories were retained; every raw probe output "
            "was discarded. A present Binder node would only open "
            "research into one kernel bug family (CVE-2019-2215): its "
            "patch state in this vendor kernel would still be unknown. "
            "An absent node closes that family. Neither outcome is an "
            "exploit result, a permission, or root."
        ),
    }


def save_kernel_gate_report(path: Path, report: dict) -> None:
    """Create one new private report; an existing destination is kept."""
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(rendered)
    os.chmod(path, 0o600)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-gate-ip", required=True)
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    ip = private_watch_ip(args.kernel_gate_ip)
    if args.report.exists() or args.report.is_symlink():
        raise KernelGateError("KERNEL_GATE_REPORT_ALREADY_EXISTS")
    report = collect_kernel_gate(ip, args.key_path.expanduser())
    save_kernel_gate_report(args.report.expanduser(), report)
    print(f"READ_ONLY_KERNEL_GATE: {args.report.expanduser()}")
    print("Gate facts only; no device open, exploit attempt or watch write.")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
