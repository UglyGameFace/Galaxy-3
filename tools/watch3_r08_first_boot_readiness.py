#!/usr/bin/env python3
"""Offline, read-only first-boot readiness gate for Galaxy Watch3 SM-R840X.

Consumes privacy-filtered reports produced by the existing tools. It NEVER
communicates with a watch, installs images, enables an unlock or authorizes
flashing. Successful evidence collection is NOT bootloader acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

MODEL = "NOBLESSE-LARGE-BT"
TARGET = "Samsung Galaxy Watch3 SM-R840X / NOBLESSE-LARGE-BT R08"
KERNEL = "4.9.59"
PINNED_SOURCE = "ec258e12887d37362b59e3291c1d3e5363c24bff"
SMOKE_SHA256 = "2878bb3917eceec530f321acd61a21967fdb0f158370252866a21452b9f5060f"
MAX_REPORT_BYTES = 128 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
ARTIFACT_KINDS = {
    "kernel_image", "r08_dtb", "psplash_ipk", "initramfs_cpio",
    "asteroid_ext4",
}
KEYS = ("stock_image_exact_variant", "stock_restore_transport_verified",
        "stock_restore_tested", "signed_boot_acceptance_verified",
        "non_destructive_trial_boot_verified", "physical_display_verified")


class EvidenceError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise EvidenceError("Duplicate JSON keys are not valid evidence")
        out[key] = value
    return out


def report_file(path: Path | None, expected_status: str) -> dict[str, Any] | None:
    if path is None:
        return None
    if (path.is_symlink() or not path.is_file()
            or not 2 <= path.stat().st_size <= MAX_REPORT_BYTES):
        raise EvidenceError("Unsafe or oversized local redacted report")
    try:
        content = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise EvidenceError("Unreadable redacted JSON evidence") from exc
    if not isinstance(content, dict) or content.get("status") != expected_status:
        raise EvidenceError(f"Wrong redacted report schema: expected {expected_status}")
    flag = ("flashable" if expected_status == "PASS_HISTORICAL_SOURCE_AUDIT"
            else "flashing_authorized")
    if content.get(flag) is not False:
        raise EvidenceError("Untrusted evidence must explicitly disallow flashing")
    return content


def _str(value: Any, length: int = 120) -> str:
    return value if isinstance(value, str) and len(value) <= length else ""


def baseline(boot: dict[str, Any] | None) -> dict[str, Any]:
    if boot is None:
        return {"status": "NOT_SUPPLIED", "board_match": False, "kernel_match": False,
                "initramfs_root_observed": False, "partition_count": 0}
    facts = boot.get("facts")
    if not isinstance(facts, dict):
        raise EvidenceError("Boot report missing filtered facts")
    model = _str(facts.get("device_tree_model"))
    version = _str(facts.get("runtime_kernel_version"))
    count = facts.get("partitions", {})
    count = count.get("observed_count", 0) if isinstance(count, dict) else 0
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 128:
        raise EvidenceError("Invalid read-only block device count")
    board_ok = model == MODEL and facts.get("model_matches_reference") is True
    kernel_ok = version == KERNEL and facts.get("runtime_kernel_matches_historical") is True
    root_ok = (facts.get("runtime_root") == "/dev/ram0" and
               facts.get("root_matches_historical_dts") is True and
               facts.get("live_device_tree_root") == "/dev/ram0")
    return {"status": "OBSERVED" if board_ok and kernel_ok and root_ok else "INCOMPLETE",
            "board_match": board_ok, "kernel_match": kernel_ok,
            "initramfs_root_observed": root_ok, "partition_count": count}


def storage_summary(storage: dict[str, Any] | None) -> dict[str, Any]:
    if storage is None:
        return {"status": "NOT_SUPPLIED", "dm0_backing_observed": False,
                "boot_partition_identified": False}
    slaves = storage.get("dm0_slaves", [])
    if not isinstance(slaves, list) or len(slaves) > 32 or any(
        not isinstance(x, str) or not re.fullmatch(r"(?:mmcblk0p[1-9][0-9]?|dm-[0-9]+)", x)
        for x in slaves
    ):
        raise EvidenceError("Unrecognized redacted storage device list")
    if storage.get("boot_partition_identified") is not False:
        raise EvidenceError("SDB pseudo-files do not prove a boot partition layout")
    return {"status": "OBSERVED" if storage.get("dm0_backing_verified") is True
            else "INCOMPLETE",
            "dm0_backing_observed": storage.get("dm0_backing_verified") is True,
            "boot_partition_identified": False}


def reference_summary(reference: dict[str, Any] | None) -> dict[str, Any]:
    if reference is None:
        return {"status": "NOT_SUPPLIED", "historical_board_match": False}
    if reference.get("flashable") is not False:
        raise EvidenceError("Historical reference must never authorize flashing")
    result = (reference.get("status") == "PASS_HISTORICAL_SOURCE_AUDIT" and
              reference.get("source_commit") == PINNED_SOURCE and
              reference.get("board_model") == MODEL and
              reference.get("reference_chosen_root") == "/dev/ram0")
    return {"status": "REFERENCE_PASS" if result else "REFERENCE_MISMATCH",
            "historical_board_match": result}


def inspect_artifact(argument: str) -> dict[str, Any]:
    """Validate a local file hash without copying firmware bytes into reports."""
    fields = argument.split(":", 2)
    if len(fields) != 3:
        raise EvidenceError("--artifact requires kind:path:sha256")
    kind, filename, checksum = fields
    if kind not in ARTIFACT_KINDS or not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise EvidenceError("Unknown artifact kind or invalid SHA-256")
    path = Path(filename).expanduser()
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= MAX_ARTIFACT_BYTES:
        raise EvidenceError("Artifact missing, symlinked or larger than 1 GiB")
    total = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            piece = stream.read(1024 * 1024)
            if not piece:
                break
            total.update(piece)
    if total.hexdigest() != checksum:
        raise EvidenceError(f"Local {kind} checksum mismatch")
    # Even exact bytes of a known artifact do not establish signed acceptance.
    return {"kind": kind, "bytes": path.stat().st_size, "sha256_verified": True,
            "bootable": False, "flashable": False}


def analyze(boot: dict[str, Any] | None = None,
            storage: dict[str, Any] | None = None,
            reference: dict[str, Any] | None = None,
            artifacts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    observed = baseline(boot)
    topology = storage_summary(storage)
    historic = reference_summary(reference)
    artifacts = artifacts or []
    if len(artifacts) > len(ARTIFACT_KINDS):
        raise EvidenceError("Too many artifact proofs")
    kinds = [item.get("kind") for item in artifacts]
    if len(kinds) != len(set(kinds)) or any(x not in ARTIFACT_KINDS for x in kinds):
        raise EvidenceError("Duplicate or invalid artifact kind")
    blocks = []
    if not observed["board_match"]:
        blocks.append("Actual live R08 board identity not confirmed by filtered boot report")
    if not observed["kernel_match"] or not observed["initramfs_root_observed"]:
        blocks.append("Actual kernel and /dev/ram0 boot contract incomplete")
    if not historic["historical_board_match"]:
        blocks.append("Pinned historical R08 kernel/DTB reference audit unavailable")
    if not topology["dm0_backing_observed"]:
        blocks.append("Read-only dm-0 backing topology incomplete")
    blocks.extend([
        "Exact SM-R840X compatible FULL stock rescue firmware unverified",
        "Successful stock restoration route and download-mode recovery unverified",
        "Samsung bootloader acceptance of custom/signed kernel unverified",
        "Supported non-destructive trial boot method unverified",
        "Physical display and input operation under UgLy|OS unverified",
    ])
    return {
        "schema_version": 1, "device_target": TARGET,
        "decision": "NO_GO", "install_authorized": False, "flash_authorized": False,
        "watch_accessed": False, "watch_modified": False,
        "observation": observed, "storage": topology, "historical_reference": historic,
        "artifacts": artifacts, "unverified_recovery_and_boot_gates": list(KEYS),
        "blocking_reasons": blocks, "next_safe_action": (
            "Keep Tizen installed. Collect filtered read-only boot/storage reports "
            "using existing Termux SDB tools and independently establish exact "
            "R840X stock recovery and bootloader acceptance before installation."
        ),
        "notes": ("Source compilation, artifact SHA-256, dm-0 observation and "
                  "reboot/download menu access are NOT stock restore or signed boot proof.")
    }


def format_markdown(result: dict[str, Any]) -> str:
    obs = result["observation"]
    stor = result["storage"]
    ref = result["historical_reference"]
    lines = [
        "# UgLy|OS R08 first-boot readiness",
        "",
        "Decision: **NO-GO for installing/flashing**",
        "",
        "Evidence provided:",
        f"- Live R08 board match: {'yes' if obs['board_match'] else 'unverified'}",
        f"- Live reference kernel match: {'yes' if obs['kernel_match'] else 'unverified'}",
        f"- Live initramfs root: {'yes' if obs['initramfs_root_observed'] else 'unverified'}",
        f"- Read-only dm-0 dependency: {'observed' if stor['dm0_backing_observed'] else 'unverified'}",
        f"- Historical source audit: {ref['status']}",
        f"- Local artifacts checked: {len(result['artifacts'])}",
        "",
        "Remaining blockers:",
    ]
    lines.extend(f"- {reason}" for reason in result["blocking_reasons"])
    lines.extend(["", "No raw identifiers, addresses, partition data, or "
                  "firmware bytes are included. **Do not flash.**", ""])
    return "\n".join(lines)


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--boot-report", type=Path, help="Existing privacy-filtered boot JSON")
    cli.add_argument("--storage-report", type=Path, help="Existing privacy-filtered storage JSON")
    cli.add_argument("--reference-report", type=Path, help="Pinned source audit JSON")
    cli.add_argument("--artifact", action="append", default=[], metavar="kind:path:sha256",
                     help="Optional locally present and known-checksummed offline artifact")
    cli.add_argument("--output", type=Path, required=True, help="Local NO-GO JSON output")
    cli.add_argument("--markdown", type=Path, help="Optional human-readable NO-GO report")
    cli.add_argument("--enforce-install", action="store_true",
                     help="Fail the process for any operation requiring install authorization")
    args = cli.parse_args()
    try:
        if len(args.artifact) > len(ARTIFACT_KINDS):
            raise EvidenceError("Too many local artifacts")
        result = analyze(
            report_file(args.boot_report, "READ_ONLY_TIZEN_RUNTIME_OBSERVATION"),
            report_file(args.storage_report, "READ_ONLY_TIZEN_STORAGE_TOPOLOGY"),
            report_file(args.reference_report, "PASS_HISTORICAL_SOURCE_AUDIT"),
            [inspect_artifact(a) for a in args.artifact],
        )
        for destination in (args.output, args.markdown):
            if destination is not None and destination.is_symlink():
                raise EvidenceError("Refuse to overwrite a symbolic link")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        if args.markdown:
            args.markdown.parent.mkdir(parents=True, exist_ok=True)
            args.markdown.write_text(format_markdown(result))
    except (OSError, EvidenceError) as error:
        # Deliberately no user-supplied file path or private device value in errors.
        print(f"FAIL[firstboot-readiness]: {error}", file=sys.stderr)
        return 1
    print("PASS[readiness-report]: filtered OFF-DEVICE evidence report generated")
    print("DECISION: NO_GO. INSTALL/FLASH: NOT AUTHORIZED.")
    return 4 if args.enforce_install else 0


if __name__ == "__main__":
    raise SystemExit(main())
