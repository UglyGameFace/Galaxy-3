#!/usr/bin/env python3
"""Check a specific published Tizen archive-launcher root path, without exploiting it.

Sources: Bishop Fox SVE-2025-50109, and the Samsung TV archive-root implementation
at github.com/chris-ritsen/samsung-tv-root. TV behavior is NOT Watch3 evidence.

Only fixed read-only SDB observations are accepted. A positive report proves
prerequisites at most, never privilege escalation or an alternate OS boot.
"""
from __future__ import annotations

import re

# No shell interpolation, uploads, archive staging, package install or writes.
ROOT_PATH_PROBES = {
    "sdb_baseline_version": "cat /proc/version",
    "dotnet_caps": "getcap -v /usr/bin/dotnet",
    "launcher_caps": "getcap -v /usr/sbin/sdbd-tarlauncher",
    "dotnet_runtime": "/usr/bin/dotnet --list-runtimes",
    "tar_features": "/usr/bin/tar --help",
    # Probe actual file existence separately: getcap itself may be missing.
    "dotnet_file": "ls -ld /usr/bin/dotnet",
    "launcher_file": "ls -ld /usr/sbin/sdbd-tarlauncher",
    # Samsung Tizen may reject dotnet --list-runtimes but expose a symlink.
    "dotnet_runtime_link": "readlink -f /usr/share/dotnet.tizen/netcoreapp",
}
REQUIRED = {
    "dotnet_caps": frozenset(("cap_setgid", "cap_sys_admin")),
    "launcher_caps": frozenset(("cap_setgid", "cap_setuid")),
}
CAP_LINE = re.compile(r"^(cap_[a-z0-9_]+(?:,cap_[a-z0-9_]+)*)=([eip]+)$")
RUNTIME_LINE = re.compile(r"^Microsoft\.NETCore\.App (\d+)\.(\d+)\.\d+ \[[^\]\r\n]+\]$")
MAX_TEXT = 64 * 1024


def _caps(raw: str | None, path: str, required: frozenset[str]) -> str:
    if raw is None or not isinstance(raw, str) or len(raw) > MAX_TEXT:
        return "UNAVAILABLE"
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        return "UNAVAILABLE"
    line = lines[0]
    if line == path:
        return "REQUIRED_CAPABILITIES_ABSENT"
    if not line.startswith(path + " "):
        return "UNAVAILABLE"
    match = CAP_LINE.fullmatch(line[len(path) + 1:])
    if match is None:
        return "UNAVAILABLE"
    capabilities = {
        name for name in match.group(1).split(",")
        if "e" in match.group(2)
    }
    return ("REQUIRED_CAPABILITIES_PRESENT" if required.issubset(capabilities)
            else "REQUIRED_CAPABILITIES_ABSENT")


def _runtime(raw: str | None) -> str:
    if raw is None or not isinstance(raw, str) or len(raw) > MAX_TEXT:
        return "UNAVAILABLE"
    versions = []
    for line in raw.splitlines():
        if match := RUNTIME_LINE.fullmatch(line.strip()):
            versions.append((int(match.group(1)), int(match.group(2))))
    if not versions:
        return "UNAVAILABLE"
    return ("SUPPORTED_RUNTIME_PRESENT"
            if any(major >= 6 or (major, minor) == (3, 1)
                   for major, minor in versions)
            else "SUPPORTED_RUNTIME_ABSENT")


def _file(raw: str | None, path: str, error: str | None) -> str:
    """Conservative file existence from an ordinary ls -ld response."""
    if error == "TARGET_PATH_NOT_FOUND":
        return "FILE_ABSENT"
    if error is not None or not isinstance(raw, str) or len(raw) > 2048:
        return "UNAVAILABLE"
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if (len(lines) == 1 and lines[0].startswith(("-", "l"))
            and path in lines[0].split()):
        return "FILE_PRESENT"
    return "UNAVAILABLE"


def _tizen_runtime_link(raw: str | None) -> str:
    """Recognize only a versioned Tizen .NET runtime path, not arbitrary text."""
    if not isinstance(raw, str) or len(raw) > 1024:
        return "UNAVAILABLE"
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        return "UNAVAILABLE"
    match = re.fullmatch(
        r"/usr/share/dotnet\.tizen/netcoreapp/(\\d+)\.(\\d+)\.(\\d+)", lines[0])
    if not match:
        return "UNAVAILABLE"
    major, minor = int(match.group(1)), int(match.group(2))
    return ("SUPPORTED_RUNTIME_PRESENT"
            if major >= 6 or (major, minor) == (3, 1)
            else "SUPPORTED_RUNTIME_ABSENT")


def _tar(raw: str | None) -> str:
    if raw is None or not isinstance(raw, str) or len(raw) > MAX_TEXT:
        return "UNAVAILABLE"
    if not raw.strip() or "--help" in raw and "not supported" in raw.lower():
        return "UNAVAILABLE"
    return ("ARCHIVE_TO_COMMAND_PRESENT" if "--to-command" in raw
            else "ARCHIVE_TO_COMMAND_ABSENT")


def summarize_root_path(values: dict[str, str], errors: dict[str, str]) -> dict[str, object]:
    """Return fixed categories only. Never serialize raw watch output."""
    observations = values if isinstance(values, dict) else {}
    missing = errors if isinstance(errors, dict) else {}
    def observed(key: str) -> str | None:
        value = observations.get(key)
        return value if key not in missing and isinstance(value, str) else None
    # A known fixed read on the SAME authenticated SDB transport lets an
    # all-UNAVAILABLE report distinguish shell access from failing utilities.
    baseline = observed("sdb_baseline_version")
    baseline_ok = bool(
        baseline is not None and
        re.search(r"(?m)^Linux version [^\\s]{1,80}", baseline)
    )
    runtime = _runtime(observed("dotnet_runtime"))
    if runtime == "UNAVAILABLE":
        runtime = _tizen_runtime_link(observed("dotnet_runtime_link"))
    checks = {
        "dotnet_binary": _file(
            observed("dotnet_file"), "/usr/bin/dotnet", missing.get("dotnet_file")),
        "archive_launcher_binary": _file(
            observed("launcher_file"), "/usr/sbin/sdbd-tarlauncher",
            missing.get("launcher_file")),
        "dotnet_capabilities": _caps(
            observed("dotnet_caps"), "/usr/bin/dotnet", REQUIRED["dotnet_caps"]),
        "archive_launcher_capabilities": _caps(
            observed("launcher_caps"), "/usr/sbin/sdbd-tarlauncher",
            REQUIRED["launcher_caps"]),
        "dotnet_runtime": runtime,
        "archive_execution_option": _tar(observed("tar_features")),
    }
    good = {
        "dotnet_capabilities": "REQUIRED_CAPABILITIES_PRESENT",
        "archive_launcher_capabilities": "REQUIRED_CAPABILITIES_PRESENT",
        "dotnet_runtime": "SUPPORTED_RUNTIME_PRESENT",
        "archive_execution_option": "ARCHIVE_TO_COMMAND_PRESENT",
    }
    fail = {
        "REQUIRED_CAPABILITIES_ABSENT",
        "SUPPORTED_RUNTIME_ABSENT",
        "ARCHIVE_TO_COMMAND_ABSENT",
    }
    # A demonstrably absent required executable rules out this exact TV
    # route even if `getcap` is missing. Unknown ls output never does.
    required_file_missing = any(
        checks[name] == "FILE_ABSENT" for name in
        ("dotnet_binary", "archive_launcher_binary")
    )
    if (baseline_ok and
            all(checks[name] == good[name] for name in good) and
            checks["dotnet_binary"] == "FILE_PRESENT" and
            checks["archive_launcher_binary"] == "FILE_PRESENT"):
        status = "STATIC_PREREQUISITES_OBSERVED"
    elif required_file_missing or any(value in fail for value in checks.values()):
        status = "STATIC_PATH_NOT_SUPPORTED"
    else:
        status = "INCONCLUSIVE"
    return {
        "schema": "uglyos-r840x-archive-root-prerequisites-v1",
        "status": status,
        "sdb_shell_baseline": ("KERNEL_VERSION_READ" if baseline_ok
                               else "NOT_OBSERVED"),
        "checks": checks,
        # Categorical acquisition stage, distinct from the parsers above.
        # OUTPUT_RECEIVED + UNAVAILABLE means valid SDB data was obtained but
        # the current narrow parser did not recognize it.
        "acquisition": {
            key: missing.get(key, "OUTPUT_RECEIVED" if key in observations
                             else "NO_RESPONSE_RECORDED")
            for key in ROOT_PATH_PROBES
        },
        "sdb_command_injection_proven": False,
        "root_obtained": False,
        "unsigned_kernel_boot_proven": False,
        "stock_recovery_proven": False,
        "firmware_changed": False,
        "device_write_performed": False,
        "meaning": ("TV research prerequisites only; no Watch3 exploit, "
                    "root, bootloader unlock or stock recovery is proven."),
    }
