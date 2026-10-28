#!/usr/bin/env python3
"""Capture actual ARM64 Qt backing-store pixels without Watch3 hardware.

Run the *compiled, hash-proven UgLy|OS rootfs* asteroid-launcher with its own
Qt6 ARM64 'minimal' QPA plugin, QT_DEBUG_BACKINGSTORE=1 and software Qt Quick.
Qt's real QMinimalBackingStore writes outputNNNN.png on flush. Verify an actual
PNG with meaningful pixel variation, recording SHA256 and dimensions.

A passing dump proves REAL GUEST QT BACKING-STORE OUTPUT, NOT necessarily that
the entire Wayland compositor, watch display, touch, or R840X boot works.
Fail closed if no frame is produced. No VNC listener, network, SDB or flash.
"""
from __future__ import annotations

import argparse
import hashlib
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

from PIL import Image, ImageStat, UnidentifiedImageError

from watch3_r08_qemu_userland_smoke import read_arm64, SmokeFailure
from watch3_r08_qemu_launcher_runtime import actual_qt_plugin_roots, PLATFORM_ROOTS
from watch3_r08_qml_module_closure import ROOTS as QML_ROOTS

MAX_SECONDS = 24
MAX_FRAMES = 200
MAX_FRAME_BYTES = 3_000_000
MAX_LOG_BYTES = 2_000_000
MAX_IMAGE_PIXELS = 1024 * 1024
FRAME_NAME = re.compile(r"^output\d{4}\.png$")
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


class VisualError(ValueError):
    pass


def find_minimal(root: Path) -> Path:
    root = root.resolve()
    matches: dict[Path, Path] = {}
    for prefix in PLATFORM_ROOTS:
        p = root / prefix / "libqminimal.so"
        if not p.is_file():
            continue
        full = p.resolve()
        if not full.is_relative_to(root):
            raise VisualError("MINIMAL_PLUGIN_ESCAPES_GUEST_ROOT")
        try:
            read_arm64(full)
        except SmokeFailure as exc:
            raise VisualError("MINIMAL_PLUGIN_WRONG_ARCH") from exc
        matches[full] = full
    if len(matches) != 1:
        raise VisualError("REQUIRE_EXACTLY_ONE_REAL_ARM64_MINIMAL_QPA_PLUGIN")
    return next(iter(matches.values()))


def inspect_png(frame: Path) -> dict:
    if not FRAME_NAME.fullmatch(frame.name) or not frame.is_file() or frame.is_symlink():
        raise VisualError("NOT_ORIGINAL_QT_BACKINGSTORE_FRAME")
    if not 80 <= frame.stat().st_size <= MAX_FRAME_BYTES:
        raise VisualError("QT_FRAME_INVALID_FILE_LENGTH")
    try:
        with Image.open(frame) as image:
            image.load()
            if image.format != "PNG":
                raise VisualError("QT_FRAME_NOT_PNG")
            if not 128 <= image.width <= 1024 or not 128 <= image.height <= 1024:
                raise VisualError("QT_FRAME_OUT_OF_BOUNDS")
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise VisualError("QT_FRAME_TOO_MANY_PIXELS")
            rgb = image.convert("RGB")
            extrema = rgb.getextrema()
            per_channel_range = [hi - lo for lo, hi in extrema]
            variation = max(per_channel_range)
            # Exclude both blank screens and accidental all-one-color images.
            # This is only an image-diversity check, NOT UI content recognition.
            unique = rgb.getcolors(maxcolors=8)
            significant = (unique is None or len(unique) >= 8) and variation >= 12
            stats = ImageStat.Stat(rgb)
            entropy = float(rgb.entropy())
            result = {
                "width": image.width, "height": image.height, "format": "PNG",
                "rgb_max_channel_range": variation,
                "rgb_stddev": [round(x, 2) for x in stats.stddev],
                "rgb_entropy_bits_per_pixel": round(entropy, 3),
                "nontrivial_pixel_variation": significant,
            }
    except (OSError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
        raise VisualError("QT_FRAME_INVALID_PNG_DECODING") from exc
    if not result["nontrivial_pixel_variation"]:
        raise VisualError("QT_FRAME_BLANK_OR_NEAR_UNIFORM")
    h = hashlib.sha256()
    with frame.open("rb") as src:
        for chunk in iter(lambda: src.read(1_048_576), b""):
            h.update(chunk)
    result["png_sha256"] = h.hexdigest()
    result["png_bytes"] = frame.stat().st_size
    return result


def run(root: Path, *, emulator: str = "qemu-aarch64", max_seconds: int = MAX_SECONDS) -> tuple[dict, bytes | None]:
    if not 6 <= max_seconds <= MAX_SECONDS:
        raise VisualError("CAPTURE_TIMEOUT_OUT_OF_RANGE")
    if not root.is_dir() or root.is_symlink():
        raise VisualError("INVALID_GUEST_ROOT")
    root = root.resolve()
    launcher = root / "usr/bin/asteroid-launcher"
    if not launcher.is_file() or not launcher.resolve().is_relative_to(root):
        raise VisualError("REAL_ARM64_LAUNCHER_MISSING")
    read_arm64(launcher)
    plugin = find_minimal(root)
    plugin_roots, svg = actual_qt_plugin_roots(root)
    if not plugin_roots:
        raise VisualError("TARGET_QT_PLUGIN_ROOTS_MISSING")
    qml_roots = sorted({
        str((root / prefix).resolve()) for prefix in QML_ROOTS
        if (root / prefix).is_dir() and (root / prefix).resolve().is_relative_to(root)
    })
    if not qml_roots:
        raise VisualError("TARGET_QML_ROOTS_MISSING")
    if not shutil.which(emulator):
        raise VisualError("HOST_ARM64_EMULATOR_UNAVAILABLE")
    with tempfile.TemporaryDirectory(prefix="uglyos-qt-minimal-proof-") as folder:
        out = Path(folder)
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "HOME": str(out),
            "TMPDIR": str(out),
            "XDG_RUNTIME_DIR": str(out),
            "QEMU_LD_PREFIX": str(root),
            "QT_QPA_PLATFORM": "minimal",
            "QT_QPA_PLATFORM_PLUGIN_PATH": str(plugin.parent),
            "QT_PLUGIN_PATH": ":".join(map(str, plugin_roots)),
            "QML_IMPORT_PATH": ":".join(qml_roots),
            "QML2_IMPORT_PATH": ":".join(qml_roots),
            "QT_QUICK_BACKEND": "software",
            "QT_DEBUG_BACKINGSTORE": "1",
            "QT_DEBUG_PLUGINS": "0",
            "QT_LOGGING_RULES": "qt.qml.states=true",
        }
        log_file = out / "minimal-launcher.log"
        began = time.monotonic()
        with log_file.open("wb") as transcript:
            try:
                process = subprocess.Popen(
                    [emulator, "-L", str(root), str(launcher), "-platform", "minimal"],
                    cwd=out, env=env, stdin=subprocess.DEVNULL,
                    stdout=transcript, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except OSError as exc:
                raise VisualError("QEMU_MINIMAL_LAUNCH_FAILED") from exc
            count_at_stop = 0
            try:
                while process.poll() is None and time.monotonic() - began < max_seconds:
                    count = len([x for x in out.iterdir() if FRAME_NAME.fullmatch(x.name)])
                    if count > MAX_FRAMES:
                        raise VisualError("TOO_MANY_GUEST_FRAME_FILES")
                    # Capture after a few redraws, if any, not just a single
                    # splash frame. If none, use the full time budget.
                    if count >= 3 and time.monotonic() - began >= 7:
                        count_at_stop = count
                        break
                    time.sleep(0.25)
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired as exc:
                    raise VisualError("GUEST_PROCESS_GROUP_NOT_TERMINATED") from exc
        elapsed = time.monotonic() - began
        size = log_file.stat().st_size
        with log_file.open("rb") as f:
            if size <= MAX_LOG_BYTES:
                log = f.read().decode("utf-8", errors="replace")
            else:
                head = f.read(10_000)
                f.seek(max(0, size - 10_000))
                tail = f.read()
                log = (head + b"\n[LOG_TRUNCATED]\n" + tail).decode("utf-8", errors="replace")
        frames = sorted([x for x in out.iterdir() if FRAME_NAME.fullmatch(x.name)])
        if len(frames) > MAX_FRAMES:
            raise VisualError("TOO_MANY_GUEST_FRAME_FILES")
        # Image is always original Qt process output from temporary working dir.
        selected = None
        analysis = None
        rejection_counts = {}
        for candidate in reversed(frames):
            try:
                details = inspect_png(candidate)
                selected, analysis = candidate, details
                break
            except VisualError as error:
                rejection_counts[str(error)] = rejection_counts.get(str(error), 0) + 1
        flush_logged = ("QMinimalBackingStore::flush() saving contents to" in log)
        errors = [
            x for x in ("Unsupported image format", "error while loading",
                        "could not load the qt platform plugin", "segmentation fault")
            if x.lower() in log.lower()
        ]
        base = {
            "schema": "uglyos-r08-real-arm64-minimal-backingstore-pixels-v1",
            "status": "REAL_QT_PIXEL_FRAME_UNVERIFIED",
            "actual_guest_aarch64_minimal_qpa": "/" + str(plugin.relative_to(root)),
            "source_compiled_guest_launcher": "/usr/bin/asteroid-launcher",
            "qt_minimal_backingstore_flush_logged": flush_logged,
            "qt_created_output_png_count": len(frames),
            "count_at_early_stop": count_at_stop,
            "render_runtime_seconds": round(elapsed, 2),
            "diagnostic_bytes": size,
            "image_decoding_rejection_reasons": rejection_counts,
            "qt_error_markers": errors,
            "guest_qsvg_aarch64_decoder_present": bool(svg),
            "real_watch3_framebuffer_tested": False,
            "wayland_compositor_pixels_proven": False,
            "watch_kernel_tested": False,
            "physical_watch_contacted": False,
            "firmware_changed": False,
            "flashable": False,
            "decision": "NO_GO",
        }
        if selected and flush_logged and not errors and analysis:
            base["status"] = "REAL_ARM64_QT_BACKINGSTORE_NONBLANK_PNG_CAPTURED"
            base["frame"] = analysis
            return base, selected.read_bytes()
        base["no_png_reason"] = (
            "NO_QT_BACKINGSTORE_FLUSH" if not flush_logged else
            "NO_NONBLANK_VERIFIABLE_PNG" if not selected else
            "FATAL_QT_ERROR_SEEN")
        return base, None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--extracted-rootfs", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--frame-output", type=Path, required=True)
    args = ap.parse_args()
    if args.report.exists() or args.frame_output.exists():
        print("REFUSING_TO_OVERWRITE_EXISTING_OUTPUT", file=sys.stderr)
        return 2
    try:
        report, image_bytes = run(args.extracted_rootfs)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        if not image_bytes:
            print("REAL_GUEST_PNG_NOT_PROVEN:", report, file=sys.stderr)
            return 2
        args.frame_output.parent.mkdir(parents=True, exist_ok=True)
        args.frame_output.write_bytes(image_bytes)
        if hashlib.sha256(image_bytes).hexdigest() != report["frame"]["png_sha256"]:
            raise VisualError("CAPTURED_IMAGE_CHANGED_BEFORE_PUBLISH")
    except (OSError, ValueError, SmokeFailure) as exc:
        print("REAL_GUEST_PNG_CAPTURE_FAILED:", str(exc), file=sys.stderr)
        return 2
    print("REAL_ARM64_QT_NONBLANK_PIXELS_CAPTURED_FROM_ORIGINAL_BUILT_LAUNCHER")
    print("FRAME_SHA256:", report["frame"]["png_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
