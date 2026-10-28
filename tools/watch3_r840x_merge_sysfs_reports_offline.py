#!/usr/bin/env python3
"""Combine existing redacted R840X sysfs reports OFFLINE, never contact a watch.

Only accepts the versioned output of the existing fixed-path SDB parser.
Every supplied report is individually revalidated for exact index/mode/
command and safe NO_GO flags. A complete list of kernel-exported text
names is NOT a Samsung-signed PIT, a partition data backup or a restore path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SCHEMA = "uglyos-r840x-physical-sysfs-evidence-merge-v1"
INPUT_SCHEMA = "uglyos-r840x-sysfs-partition-names-v1"
MODEL = "SM-R840X"
BUILD = "R840XXXU1AUA2"
CSC = "PAP"
MAX_JSON_BYTES = 64 * 1024
ROLES = {
    "fixed": ("THREE_EXPLICIT_TEXT_PATHS_NO_WILDCARD", (1, 20, 21)),
    "batch1": ("SIX_EXPLICIT_TEXT_PATHS_BATCH_1_NO_WILDCARD", tuple(range(2, 8))),
    "batch2": ("SIX_EXPLICIT_TEXT_PATHS_BATCH_2_NO_WILDCARD", tuple(range(8, 14))),
    "batch3": ("SIX_EXPLICIT_TEXT_PATHS_BATCH_3_NO_WILDCARD", tuple(range(14, 20))),
}
LABELS = frozenset({
    "boot", "recovery", "param", "kernel", "rootfs", "system",
    "userdata", "user", "data", "cache", "csc", "efs",
    "misc", "vbmeta", "dtb", "dtbo", "vendor", "ramdisk",
    "sboot", "tzsw", "steady", "module", "wd-reserved",
    "loader", "updater", "modem", "up_param", "persist",
})
KNOWN_STATUS = frozenset({
    "PARTNAME_FIELD_OBSERVED", "UEVENT_READABLE_BUT_PARTNAME_ABSENT",
    "SDB_SHELL_TIMED_OUT", "SDB_SHELL_CLOSED_OR_REFUSED",
    "SDB_PROTOCOL_OR_READ_FAILURE", "SDB_TRANSPORT_UNREACHABLE",
    "SYSFS_EMPTY_SHELL_OUTPUT", "SYSFS_ACCESS_DENIED",
    "SYSFS_PATH_OR_COMMAND_NOT_FOUND", "NO_MATCHING_SINGLE_SYSFS_RECORD",
    "MALFORMED_OR_CONFLICTING_SYSFS_RECORD", "NOT_READ",
    "OTHER_UNAVAILABLE",
})
READABLE = frozenset({"PARTNAME_FIELD_OBSERVED", "UEVENT_READABLE_BUT_PARTNAME_ABSENT"})
NO_GO_FLAGS = (
    "raw_partition_bytes_read", "pit_requested", "odin_session_started",
    "watch_write_performed", "stock_recovery_proven",
    "bootloader_acceptance_proven", "flash_allowed",
)


class EvidenceError(ValueError):
    """Generic local input error without including potentially private bytes."""


def _no_duplicate_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise EvidenceError("DUPLICATE_JSON_KEY")
        data[key] = value
    return data


def read_json_file(path: Path) -> tuple[dict, str]:
    """Reject symlinks and large inputs; never echo file paths or raw content."""
    try:
        if path.is_symlink():
            raise EvidenceError("INPUT_UNREADABLE_OR_SYMLINK")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_size < 1 or meta.st_size > MAX_JSON_BYTES:
                raise EvidenceError("INPUT_NOT_REGULAR_OR_OUT_OF_BOUNDS")
            with os.fdopen(fd, "rb", closefd=False) as inp:
                raw = inp.read(MAX_JSON_BYTES + 1)
        finally:
            os.close(fd)
    except OSError:
        raise EvidenceError("INPUT_UNREADABLE_OR_SYMLINK") from None
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise EvidenceError("INPUT_OUT_OF_BOUNDS")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, ValueError, TypeError):
        raise EvidenceError("INVALID_REPORT_JSON") from None
    if not isinstance(data, dict):
        raise EvidenceError("REPORT_IS_NOT_OBJECT")
    return data, digest


def validate_report(data: dict, role: str) -> list[dict]:
    """Trust no supplied field; only accept exact reports from original probe."""
    if role not in ROLES:
        raise EvidenceError("UNKNOWN_EVIDENCE_ROLE")
    mode, indices = ROLES[role]
    if (data.get("schema") != INPUT_SCHEMA or
        data.get("device_target") != MODEL or
        data.get("installed_build_recorded") != BUILD or
        data.get("active_csc_recorded") != CSC):
        raise EvidenceError("WRONG_MODEL_BUILD_CSC_OR_SCHEMA")
    if (data.get("probe_mode") != mode or data.get("result") != "NO_GO" or
        any(data.get(flag) is not False for flag in NO_GO_FLAGS) or
        data.get("report") is not None):
        raise EvidenceError("WRONG_MODE_OR_MISSING_NO_GO_CONTRACT")
    if role != "fixed":
        batch = int(role[-1])
        if (type(data.get("remaining_batch_number")) is not int or
            data["remaining_batch_number"] != batch or
            data.get("prior_owner_observations_not_repeated") != [1, 20, 21] or
            data.get("prior_owner_rootfs_p20_and_user_p21_not_reverified") is not True):
            raise EvidenceError("BATCH_PROVENANCE_MISMATCH")
    expected_cmds = [f"cat /sys/class/block/mmcblk0p{i}/uevent" for i in indices]
    if data.get("source_path_expression") != expected_cmds:
        raise EvidenceError("SOURCE_PATHS_NOT_EXACT_ALLOWLIST")
    summary = data.get("probe_summary")
    if not isinstance(summary, dict) or summary.get("tested_partition_indices") != list(indices):
        raise EvidenceError("INDEX_SET_MISMATCH")
    if summary.get("full_partition_layout_proven") is not False:
        raise EvidenceError("INPUT_WRONGLY_CLAIMS_FULL_LAYOUT")
    # The batch's 'not tested' list is local to that one report.
    expected_rest = [i for i in range(1, 22) if i not in indices]
    if summary.get("remaining_partition_indices_not_tested") != expected_rest:
        raise EvidenceError("SINGLE_REPORT_SCOPE_MISMATCH")
    original = summary.get("probes")
    if not isinstance(original, list) or len(original) != len(indices):
        raise EvidenceError("WRONG_PROBE_ITEM_COUNT")
    outputs = []
    for i, item in zip(indices, original):
        if not isinstance(item, dict) or type(item.get("partition_index")) is not int or item["partition_index"] != i:
            raise EvidenceError("PROBE_INDEX_MISMATCH")
        status = item.get("status")
        if not isinstance(status, str) or status not in KNOWN_STATUS:
            raise EvidenceError("UNKNOWN_PROBE_STATUS")
        label = item.get("kernel_reported_label")
        if status == "PARTNAME_FIELD_OBSERVED":
            if not isinstance(label, str) or (label not in LABELS and label != "unclassified"):
                raise EvidenceError("PARTNAME_NOT_RECOGNIZED_OR_REDACTED")
        elif status == "UEVENT_READABLE_BUT_PARTNAME_ABSENT":
            if label != "not_exported":
                raise EvidenceError("MISSING_PARTNAME_STATE_MISMATCH")
        elif "kernel_reported_label" in item:
            raise EvidenceError("UNREADABLE_PROBE_CANNOT_CLAIM_PARTNAME")
        outputs.append({"index": i, "status": status, "kernel_reported_label": label})
    readable = sum(v["status"] in READABLE for v in outputs)
    named = sum(v["status"] == "PARTNAME_FIELD_OBSERVED" for v in outputs)
    if (type(summary.get("readable_uevent_files")) is not int or
        summary["readable_uevent_files"] != readable or
        type(summary.get("partname_fields_observed")) is not int or
        summary["partname_fields_observed"] != named or
        data.get("owner_watch_sysfs_observed") is not (readable > 0)):
        raise EvidenceError("COUNTS_OR_WATCH_OBSERVATION_MISMATCH")
    expected_state = ("FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED" if named else
                      "FIXED_SYSFS_UEVENT_READABLE_WITHOUT_NAMES" if readable else
                      "FIXED_SYSFS_NO_VALID_TEXT_OBSERVATIONS")
    if data.get("state") != expected_state:
        raise EvidenceError("SUMMARY_STATE_MISMATCH")
    return outputs


def reconcile(sources: dict[str, tuple[dict, str]]) -> dict:
    """Join disjoint fixed-role reports. Never infer missing partition values."""
    if "fixed" not in sources:
        raise EvidenceError("FIXED_BASELINE_REPORT_REQUIRED")
    records = {}
    metadata = []
    hashes = set()
    for role in ROLES:
        if role not in sources:
            continue
        data, digest = sources[role]
        if digest in hashes:
            raise EvidenceError("DUPLICATE_REPORT_BYTES")
        hashes.add(digest)
        fresh = validate_report(data, role)
        for item in fresh:
            if item["index"] in records:
                raise EvidenceError("DUPLICATE_INDEX_ACROSS_REPORTS")
            records[item["index"]] = item
        metadata.append({
            "role": role,
            "input_report_sha256_identity_only": digest,
            "requested_indices": list(ROLES[role][1]),
            "readable_indices": [r["index"] for r in fresh if r["status"] in READABLE],
        })
    if not records:
        raise EvidenceError("NO_REPORTS_SUPPLIED")
    combined = [records.get(i, {
        "index": i, "status": "NOT_IN_SUPPLIED_REPORTS",
        "kernel_reported_label": None,
    }) for i in range(1, 22)]
    readable = [x["index"] for x in combined if x["status"] in READABLE]
    named = [x["index"] for x in combined if x["status"] == "PARTNAME_FIELD_OBSERVED"]
    classified = [x["index"] for x in combined if x["kernel_reported_label"] in LABELS]
    redacted = [x["index"] for x in combined if x["kernel_reported_label"] == "unclassified"]
    absent = [x["index"] for x in combined if x["status"] == "NOT_IN_SUPPLIED_REPORTS"]
    return {
        "schema": SCHEMA,
        "target_model_recorded": MODEL,
        "installed_build_recorded": BUILD,
        "active_csc_previously_observed": CSC,
        "state": ("ALL_21_KERNEL_TEXT_PARTNAME_FIELDS_RECONCILED" if len(named) == 21 else
                  "PARTIAL_KERNEL_TEXT_METADATA_RECONCILED"),
        "source_kind": "OWNER_SUPPLIED_REDACTED_REPORTS_NOT_CRYPTOGRAPHICALLY_ATTESTED",
        "reports_used": metadata,
        "readable_uevent_indices": readable,
        "readable_uevent_count": len(readable),
        "partname_field_indices": named,
        "partname_field_count": len(named),
        "recognized_public_label_count": len(classified),
        "recognized_public_label_indices": classified,
        "redacted_unclassified_indices": redacted,
        "not_in_supplied_reports": absent,
        "positions": combined,
        "all_21_kernel_text_records_readable": len(readable) == 21,
        "all_21_kernel_partname_fields_seen": len(named) == 21,
        "unknown_partition_role_positions_still_exist": bool(redacted or absent or len(classified) != 21),
        "all_21_physical_partition_contents_read": False,
        "samsung_pit_authenticated": False,
        "signed_stock_image_verified": False,
        "partition_offsets_sizes_verified": False,
        "bootloader_accepted_custom_image": False,
        "stock_recovery_proven": False,
        "watch_contacted_by_merge": False,
        "odin_session_started": False,
        "firmware_written": False,
        "flash_allowed": False,
        "result": "NO_GO",
        "interpretation": ("Only already saved kernel sysfs PARTNAME text, with every "
                           "unknown or redacted role preserved. Filename hashes prove "
                           "local file identity, not original device or Samsung authenticity."),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed", type=Path, required=True,
                        help="Pre-existing owner report for p1,p20,p21, not raw sysfs")
    for num in (1, 2, 3):
        parser.add_argument(f"--batch{num}", type=Path,
                            help=f"Optional pre-existing owner report for fixed batch {num}")
    parser.add_argument("--output", type=Path, required=True,
                        help="New private JSON output file, refuse overwrite")
    args = parser.parse_args(argv)
    path = args.output.expanduser()
    try:
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            raise EvidenceError("OUTPUT_EXISTS_OR_PARENT_UNAVAILABLE")
        files = {"fixed": args.fixed}
        files.update({f"batch{i}": getattr(args, f"batch{i}") for i in (1, 2, 3)
                      if getattr(args, f"batch{i}") is not None})
        if any(p.expanduser() == path for p in files.values()):
            raise EvidenceError("OUTPUT_MUST_NOT_REPLACE_SOURCE")
        sources = {role: read_json_file(file.expanduser()) for role, file in files.items()}
        result = reconcile(sources)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(result, out, indent=2)
                out.write("\n")
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    except (EvidenceError, OSError, ValueError, UnicodeError) as exc:
        reason = str(exc) if isinstance(exc, EvidenceError) else "LOCAL_READ_OR_WRITE_ERROR"
        print("OFFLINE_PARTITION_MERGE_ERROR: " + reason, file=sys.stderr)
        return 1
    print("OFFLINE_PARTITION_MERGE_RESULT: " + str(path))
    print(f"READABLE_SYSFS_POSITIONS: {result['readable_uevent_count']}/21")
    print(f"VISIBLE_PARTNAME_FIELDS: {result['partname_field_count']}/21")
    print("NO device access, raw block reads, PIT request, Odin session, firmware writes or flash authorization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
