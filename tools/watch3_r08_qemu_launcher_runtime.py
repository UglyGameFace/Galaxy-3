#!/usr/bin/env python3
"""Bounded OFF-DEVICE runtime probe for the actual built ARM64 Asteroid launcher.

Runs the real original launcher under QEMU linux-user against a disposable
extraction of a pinned UgLy|OS rootfs. Chooses only a REAL ARM64 offscreen or
minimal QPA plugin from the image. Requires compositor QML import trace AND
successful QPA plugin load; mere process survival is not a pass.

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
import time

from watch3_r08_qemu_userland_smoke import read_arm64, SmokeFailure
from watch3_r08_qml_module_closure import ROOTS

LIMIT_SECONDS = 9
MAX_LOG_BYTES = 90_000
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
    fatal = [p for p in FATAL_PATTERNS if p in lower]
    # A clean bounded timeout can indicate a running event loop ONLY if Qt
    # logged both its actual platform load and compositor QML import.
    credible = (loaded and qml_trace and not fatal and
                (returncode == 0 or (timed_out and elapsed >= 1.0)))
    return {
        "schema": "uglyos-r08-built-arm64-launcher-startup-probe-v1",
        "status": ("QPA_AND_COMPOSITOR_QML_IMPORT_OBSERVED_OFF_DEVICE"
                   if credible else "LAUNCHER_RUNTIME_NOT_PROVEN"),
        "actual_qpa_plugin_loaded_in_qemu_trace": loaded,
        "actual_compositor_qrc_qml_import_trace_seen": qml_trace,
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
    try:
        process = subprocess.Popen(
            [emulator, "-L", str(root), str(launcher), "-platform", platform],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True)
    except OSError as error:
        raise RuntimeFailure("QEMU_PROCESS_LAUNCH_FAILED") from error
    timed_out = False
    try:
        output, _ = process.communicate(timeout=duration)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = process.communicate(timeout=5)
    elapsed = time.monotonic() - started
    if len(output) > MAX_LOG_BYTES:
        raise RuntimeFailure("UNBOUNDED_GUEST_STARTUP_LOG")
    log = output.decode("utf-8", errors="replace")
    outcome = analyze(log, platform=platform, returncode=process.returncode,
                      timed_out=timed_out, elapsed=elapsed)
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
        outcome = {"schema": "uglyos-r08-built-arm64-launcher-startup-probe-v1",
                   "status": "LAUNCHER_RUNTIME_NOT_PROVEN", "reason": str(error),
                   "watch_contacted": False, "flashable": False, "decision": "NO_GO"}
        log = ""
    if args.report.exists() or args.report.is_symlink():
        print("REFUSING_EXISTING_REPORT", file=sys.stderr)
        return 2
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(outcome, indent=2) + "\n")
    if outcome["status"] != "QPA_AND_COMPOSITOR_QML_IMPORT_OBSERVED_OFF_DEVICE":
        print("REAL_ARM64_LAUNCHER_RUNTIME_UNVERIFIED:", outcome, file=sys.stderr)
        print("BOUNDED_QEMU_DIAGNOSTICS:\n" + log[-6500:], file=sys.stderr)
        return 2
    print("REAL_ARM64_LAUNCHER_QPA_AND_QML_IMPORT_OBSERVED; NO DISPLAY OR WATCH BOOT")
    print("QPA:", outcome["selected_actual_aarch64_qpa_plugin"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
