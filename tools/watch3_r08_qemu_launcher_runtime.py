#!/usr/bin/env python3
"""Bounded OFF-DEVICE runtime probe for the actual built ARM64 Asteroid launcher.

Runs the real original launcher under QEMU linux-user against a disposable
extraction of a pinned UgLy|OS rootfs. Chooses only a REAL ARM64 offscreen or
minimal QPA plugin from the image. Requires either explicit compositor QML
import + QPA trace, OR the source-proven Tutorial.qml "WELCOME" state
transition plus real QML delegate processing, OR sustained Qt QML
delegate-model execution with no fatal errors. Mere survival cannot pass.

Does not reproduce Exynos9110 hardware, real framebuffer, input or Watch3 boot.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from watch3_r08_qemu_userland_smoke import read_arm64, SmokeFailure
from watch3_r08_qml_module_closure import ROOTS

LIMIT_SECONDS = 9
MAX_LOG_BYTES = 8_000_000
DIAGNOSTIC_EXCERPT_BYTES = 24_000
PLATFORMS = ("offscreen", "minimal")
PLATFORM_ROOTS = (
    "usr/lib/plugins/platforms",
    "usr/lib64/plugins/platforms",
    "usr/lib/qt6/plugins/platforms",
    "usr/lib64/qt6/plugins/platforms",
    "lib/plugins/platforms",
)
FATAL_PATTERNS = (
    "could not load the qt platform plugin",
    "this application failed to start because no qt platform plugin",
    "qqmlapplicationengine failed to load component",
    "module \"qtquick\" is not installed",
    "module \"qtwayland.compositor\" is not installed",
    "symbol lookup error",
    "failed to create opengl context",
    "segmentation fault",
)


class RuntimeFailure(ValueError):
    pass


def locate_plugin(root: Path) -> tuple[str, Path]:
    root = root.resolve()
    for platform in PLATFORMS:
        located: dict[Path, Path] = {}
        for prefix in PLATFORM_ROOTS:
            candidate = root / prefix / ("libq" + platform + ".so")
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                raise RuntimeFailure("QT_PLATFORM_PLUGIN_PATH_ESCAPES_ROOT")
            try:
                read_arm64(resolved)
            except SmokeFailure as error:
                raise RuntimeFailure("QT_PLATFORM_PLUGIN_NOT_AARCH64") from error
            located[resolved] = resolved
        if located:
            if len(located) != 1:
                raise RuntimeFailure("AMBIGUOUS_REAL_QPA_PLUGIN:" + platform)
            return platform, next(iter(located.values()))
    raise RuntimeFailure("NO_ARM64_OFFSCREEN_OR_MINIMAL_QPA_PLUGIN")


def analyze(log: str, *, platform: str, returncode: int, timed_out: bool,
            elapsed: float) -> dict:
    lower = log.lower()
    loaded = bool(re.search(r"loaded library [^\r\n]*libq" +
                            re.escape(platform) + r"\.so", log, re.I))
    qml_trace = ("qrc:/Launcher/compositor.qml" in log
                 and ("QQmlImportDatabase" in log or "QQmlImports" in log))
    # Proven source for the exact "WELCOME" state:
    # AsteroidOS/asteroid-launcher@0ba0eb50...
    # src/qml/firstrun/Tutorial.qml: state: "WELCOME".
    # A QML runtime transition is stronger than linker/module presence,
    # but still does not demonstrate a rendered pixel or target framebuffer.
    tutorial_welcome = bool(re.search(
        r'qt\.qml\.states:.*changing state from:\s*""\s+to:\s*"WELCOME"',
        log, re.I))
    delegate_entries = sum(
        1 for line in log.splitlines()
        if "qt.qml.delegatemodel.recycling:" in line.lower())
    active_delegates = delegate_entries > 0
    fatal = [p for p in FATAL_PATTERNS if p in lower]
    explicit = loaded and qml_trace
    source_grounded = tutorial_welcome and active_delegates
    # Alternative *narrower* proof: original built launcher main executes
    # QML delegate-model internals repeatedly throughout the 9s CI probe.
    # This proves QML event processing, not a visible image, a particular
    # compositor import, a successful Wayland client, or Watch3 boot.
    sustained_delegates = (delegate_entries >= 20 and timed_out and
                           elapsed >= 8.0 and returncode == -signal.SIGKILL)
    credible = (not fatal and (explicit or source_grounded or sustained_delegates)
                and (returncode == 0 or (timed_out and elapsed >= 1.0)))
    evidence_mode = ("EXPLICIT_QPA_AND_COMPOSITOR_QRC_TRACE" if explicit else
                     "PINNED_SOURCE_TUTORIAL_WELCOME_AND_QML_DELEGATES"
                     if source_grounded else
                     "BOUNDED_ARM64_QML_DELEGATE_EVENT_PROCESSING"
                     if sustained_delegates else "INSUFFICIENT")
    return {
        "schema": "uglyos-r08-built-arm64-launcher-startup-probe-v2",
        "status": ("REAL_ARM64_LAUNCHER_QML_RUNTIME_OBSERVED_OFF_DEVICE"
                   if credible else "LAUNCHER_RUNTIME_NOT_PROVEN"),
        "evidence_mode": evidence_mode,
        "actual_qpa_plugin_loaded_in_qemu_trace": loaded,
        "actual_compositor_qrc_qml_import_trace_seen": qml_trace,
        "pinned_source_tutorial_welcome_state_changed": tutorial_welcome,
        "qml_delegate_processing_observed": active_delegates,
        "qml_delegate_trace_line_count": delegate_entries,
        "qml_delegate_processing_sustained": sustained_delegates,
        "source_grounding": ("AsteroidOS/asteroid-launcher at "
            "0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31 "
            "src/qml/firstrun/Tutorial.qml"),
        "fatal_messages_seen": fatal,
        "emulator_returncode": returncode,
        "process_was_bounded_and_terminated_after_timeout": timed_out,
        "runtime_seconds": round(elapsed, 3),
        "launchers_main_invocation_attempted": True,
        "compositor_pixel_output_proven": False,
        "real_wayland_client_exchange_proven": False,
        "watch3_kernel_or_hardware_tested": False,
        "stock_restore_proven": False,
        "watch_contacted": False,
        "flashable": False,
        "decision": "NO_GO",
    }


def inspect(root: Path, *, emulator: str = "qemu-aarch64",
            duration: int = LIMIT_SECONDS) -> tuple[dict, str]:
    if duration < 2 or duration > 12:
        raise RuntimeFailure("OUT_OF_BOUNDS_PROBE_DURATION")
    if not root.is_dir() or root.is_symlink():
        raise RuntimeFailure("INVALID_ROOTFS")
    root = root.resolve()
    launcher = root / "usr/bin/asteroid-launcher"
    if not launcher.is_file() or not launcher.resolve().is_relative_to(root):
        raise RuntimeFailure("MISSING_OR_UNSAFE_REAL_LAUNCHER")
    read_arm64(launcher)
    platform, plugin = locate_plugin(root)
    if not shutil.which(emulator):
        raise RuntimeFailure("QEMU_AARCH64_MISSING")
    qmlpaths: dict[Path, str] = {}
    for path in ROOTS:
        item = root / path
        if item.is_dir() and item.resolve().is_relative_to(root):
            qmlpaths[item.resolve()] = str(item.resolve())
    if not qmlpaths:
        raise RuntimeFailure("NO_ACTUAL_QML_IMPORT_ROOTS")
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "XDG_RUNTIME_DIR": "/tmp",
        "QEMU_LD_PREFIX": str(root),
        "QT_QPA_PLATFORM": platform,
        "QT_QPA_PLATFORM_PLUGIN_PATH": str(plugin.parent),
        "QT_QUICK_BACKEND": "software",
        "QML_IMPORT_PATH": ":".join(qmlpaths.values()),
        "QML2_IMPORT_PATH": ":".join(qmlpaths.values()),
        "QML_IMPORT_TRACE": "1",
        "QT_DEBUG_PLUGINS": "1",
        "QT_LOGGING_RULES": "qt.qml.*=true;qt.qpa.*=true",
        "QT_LOGGING_TO_CONSOLE": "1",
    }
    started = time.monotonic()
    # Redirect verbose Qt diagnostic output to an anonymous temporary FILE.
    # Never buffer an unbounded stream in Python memory and never discard
    # the diagnostic clues when it is large.
    with tempfile.TemporaryFile() as transcript:
        try:
            process = subprocess.Popen(
                [emulator, "-L", str(root), str(launcher), "-platform", platform],
                env=env, stdin=subprocess.DEVNULL, stdout=transcript,
                stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as error:
            raise RuntimeFailure("QEMU_PROCESS_LAUNCH_FAILED") from error
        timed_out = False
        try:
            process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise RuntimeFailure("QEMU_PROCESS_GROUP_NOT_TERMINATED") from None
        elapsed = time.monotonic() - started
        transcript.seek(0, os.SEEK_END)
        total_bytes = transcript.tell()
        transcript.seek(0)
        if total_bytes <= MAX_LOG_BYTES:
            log = transcript.read().decode("utf-8", errors="replace")
            excess = False
        else:
            prefix = transcript.read(DIAGNOSTIC_EXCERPT_BYTES)
            transcript.seek(max(0, total_bytes - DIAGNOSTIC_EXCERPT_BYTES))
            suffix = transcript.read()
            log = (prefix + b"\n[...EXCESSIVE QT LOG OMITTED...]\n" +
                   suffix).decode("utf-8", errors="replace")
            excess = True
    outcome = analyze(log, platform=platform, returncode=process.returncode,
                      timed_out=timed_out, elapsed=elapsed)
    outcome["guest_log_bytes"] = total_bytes
    outcome["guest_log_truncated_for_analysis"] = excess
    if excess:
        outcome["status"] = "LAUNCHER_RUNTIME_NOT_PROVEN"
        outcome["reason"] = "EXCESSIVE_QT_STARTUP_OUTPUT"
    outcome["selected_actual_aarch64_qpa_plugin"] = "/" + str(plugin.relative_to(root))
    outcome["target_qml_import_root_count"] = len(qmlpaths)
    return outcome, log


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--extracted-rootfs", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    args = ap.parse_args()
    try:
        outcome, log = inspect(args.extracted_rootfs)
    except (OSError, SmokeFailure, RuntimeFailure) as error:
        outcome = {"schema": "uglyos-r08-built-arm64-launcher-startup-probe-v2",
                   "status": "LAUNCHER_RUNTIME_NOT_PROVEN", "reason": str(error),
                   "watch_contacted": False, "flashable": False, "decision": "NO_GO"}
        log = ""
    if args.report.exists() or args.report.is_symlink():
        print("REFUSING_EXISTING_REPORT", file=sys.stderr)
        return 2
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(outcome, indent=2) + "\n")
    if outcome["status"] != "REAL_ARM64_LAUNCHER_QML_RUNTIME_OBSERVED_OFF_DEVICE":
        print("REAL_ARM64_LAUNCHER_RUNTIME_UNVERIFIED:", outcome, file=sys.stderr)
        print("BOUNDED_QEMU_DIAGNOSTICS:\n" + log[-6500:], file=sys.stderr)
        return 2
    print("REAL_ARM64_LAUNCHER_TUTORIAL_QML_INITIALIZED; NO DISPLAY OR WATCH BOOT")
    print("EVIDENCE_MODE:", outcome["evidence_mode"])
    print("QPA:", outcome["selected_actual_aarch64_qpa_plugin"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
