#!/usr/bin/env python3
"""Read-only Tizen Watch3 firmware-update service inventory.

Based on public sibling-watch evidence, not an R840X vulnerability proof.
Never trigger OTA, open service sockets, send SAP packets or write firmware.
"""
from __future__ import annotations

import re

FOTA_PATH_PROBES = {
    "fota_service_path": "ls -ld /usr/apps/com.samsung.fota-consumer/bin/fota-service",
    "update_client_path": "ls -ld /usr/apps/com.samsung.tizen.update-client",
    "oma_dm_socket_path": "ls -ld /tmp/agent_fw_event_omadm",
    "service_process_snapshot": "ps",
}
FOTA_FILE_PATHS = {
    "fota_service_path": "/usr/apps/com.samsung.fota-consumer/bin/fota-service",
    "update_client_path": "/usr/apps/com.samsung.tizen.update-client",
    "oma_dm_socket_path": "/tmp/agent_fw_event_omadm",
}
MAX_TEXT = 65536
# Report presence only, without copying raw shell output, PIDs, addresses, or arguments.
SERVICE_TOKENS = {
    "sapd": re.compile(r"(?<![a-z0-9_.-])sapd(?![a-z0-9_.-])", re.I),
    "fota_service": re.compile(r"(?<![a-z0-9_.-])fota-service(?![a-z0-9_.-])", re.I),
}
RECOGNIZED_STATUSES = {"PRESENT_AT_REFERENCE_PATH", "ABSENT_AT_REFERENCE_PATH", "UNAVAILABLE"}


def _path_observation(raw: str | None, path: str, error: str | None) -> str:
    """A missing reference path does not establish that the component is absent."""
    if error == "TARGET_PATH_NOT_FOUND":
        return "ABSENT_AT_REFERENCE_PATH"
    if error is not None or not isinstance(raw, str) or len(raw) > 2048:
        return "UNAVAILABLE"
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        return "UNAVAILABLE"
    columns = lines[0].split()
    # Accept ordinary file, directory, symlink or Unix socket. Reject
    # diagnostic/error text and unrelated paths.
    if (columns and columns[0][:1] in {"-", "d", "l", "s"}
            and path in columns[1:]):
        return "PRESENT_AT_REFERENCE_PATH"
    return "UNAVAILABLE"


def _process_observation(raw: str | None, error: str | None) -> dict[str, str]:
    statuses = {name: "UNAVAILABLE" for name in SERVICE_TOKENS}
    if error is not None or not isinstance(raw, str) or not raw or len(raw) > MAX_TEXT:
        return statuses
    lines = raw.splitlines()
    if len(lines) > 2000 or len(lines) < 2:
        return statuses
    # ps can include full command lines; never return them, only fixed booleans.
    for name, pattern in SERVICE_TOKENS.items():
        statuses[name] = ("NAME_SEEN_IN_PS" if any(
            pattern.search(line) for line in lines[1:])
            else "NAME_NOT_SEEN_IN_PS")
    return statuses


def summarize_fota_path(values: dict[str, str], errors: dict[str, str]) -> dict[str, object]:
    observations = values if isinstance(values, dict) else {}
    failures = errors if isinstance(errors, dict) else {}

    def observed(key: str) -> str | None:
        output = observations.get(key)
        return output if key not in failures and isinstance(output, str) else None

    locations = {
        key: _path_observation(observed(key), path, failures.get(key))
        for key, path in FOTA_FILE_PATHS.items()
    }
    processes = _process_observation(
        observed("service_process_snapshot"), failures.get("service_process_snapshot"))
    reference_found = any(v == "PRESENT_AT_REFERENCE_PATH" for v in locations.values())
    process_found = any(v == "NAME_SEEN_IN_PS" for v in processes.values())
    status = ("FOTA_COMPONENT_CANDIDATE_OBSERVED" if reference_found or process_found
              else "FOTA_SERVICE_EVIDENCE_INCONCLUSIVE")
    return {
        "schema": "uglyos-r840x-fota-service-inventory-v1",
        "status": status,
        "reference_paths": locations,
        "process_names": processes,
        "acquisition": {
            key: failures.get(key, "OUTPUT_RECEIVED" if key in observations
                              else "NO_RESPONSE_RECORDED")
            for key in FOTA_PATH_PROBES
        },
        "fota_vulnerability_proven": False,
        "cve_2021_25436_or_25437_exploited": False,
        "root_obtained": False,
        "custom_boot_verified": False,
        "stock_recovery_verified": False,
        "firmware_changed": False,
        "device_write_performed": False,
        "meaning": "Sibling-watch component observations only. Missing a candidate path "
                   "or process name is not proof that FOTA is absent or exploitable.",
    }
