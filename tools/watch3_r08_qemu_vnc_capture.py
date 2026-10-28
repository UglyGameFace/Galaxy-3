#!/usr/bin/env python3
"""Capture RAW framebuffer pixels from the REAL ARM64 Qt vnc QPA, off-device.

SECURITY: Qt's built-in VNC server is UNAUTHENTICATED and binds all interfaces.
Run this program ONLY inside an isolated Docker --network none namespace.
Hard-stop if /sys/class/net lists anything besides loopback. The RFB client
connects to 127.0.0.1 *inside the same isolated namespace*. No host TCP,
watch connection, Samsung firmware execution, or flash.

The guest launcher and libqvnc.so are authenticated only as target AArch64 ELF
inside the checksum-proven archived October 24 UgLy|OS rootfs. The resulting
PNG is genuine framebuffer bytes, not an illustration. A uniform/blank
frame is NOT visual success. This does not emulate a physical Watch3.
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
import socket
import struct
import subprocess
import sys
import tempfile
import time

from PIL import Image, ImageStat
from watch3_r08_qemu_userland_smoke import read_arm64, SmokeFailure
from watch3_r08_qemu_launcher_runtime import actual_qt_plugin_roots, PLATFORM_ROOTS
from watch3_r08_qml_module_closure import ROOTS as QML_ROOTS
from watch3_r08_private_dbus_display import (
    private_system_bus, force_compositor_window_visible,
)

CAPTURE_SECONDS = 28
PORT = 5900
SIZE = (360, 360)
MAX_MESSAGE_BYTES = SIZE[0] * SIZE[1] * 4
MAX_LOG_BYTES = 200_000


class RfbError(ValueError):
    pass


def require_network_isolation(netdev_root: Path = Path("/sys/class/net")) -> list[str]:
    if not netdev_root.is_dir():
        raise RfbError("NETWORK_INTERFACE_PROOF_UNAVAILABLE")
    interfaces = sorted(item.name for item in netdev_root.iterdir())
    if interfaces != ["lo"]:
        raise RfbError("VNC_IS_UNAUTHENTICATED_REFUSING_NETWORKED_NAMESPACE:" +
                       ",".join(interfaces[:12]))
    return interfaces


def find_arm64_qvnc(root: Path) -> Path:
    root = root.resolve()
    unique: dict[Path, Path] = {}
    for prefix in PLATFORM_ROOTS:
        file = root / prefix / "libqvnc.so"
        if not file.is_file():
            continue
        candidate = file.resolve()
        if not candidate.is_relative_to(root):
            raise RfbError("VNC_PLUGIN_ESCAPES_TARGET_ROOT")
        try:
            read_arm64(candidate)
        except SmokeFailure as exc:
            raise RfbError("VNC_PLUGIN_NOT_AARCH64") from exc
        unique[candidate] = candidate
    if len(unique) != 1:
        raise RfbError("REAL_ARM64_QVNC_PLUGIN_ABSENT_OR_AMBIGUOUS")
    return next(iter(unique.values()))


def exactly(sock: socket.socket, size: int) -> bytes:
    if size < 0 or size > MAX_MESSAGE_BYTES:
        raise RfbError("RFB_LENGTH_OUT_OF_BOUNDS")
    result = bytearray()
    while len(result) < size:
        try:
            chunk = sock.recv(size - len(result))
        except socket.timeout as exc:
            raise RfbError("RFB_PEER_TIMED_OUT") from exc
        if not chunk:
            raise RfbError("RFB_PEER_CLOSED")
        result.extend(chunk)
    return bytes(result)


def handshake(sock: socket.socket) -> tuple[int,int]:
    greeting = exactly(sock, 12)
    if greeting != b"RFB 003.003\n":
        raise RfbError("UNSUPPORTED_QT_VNC_PROTOCOL")
    sock.sendall(greeting)
    auth, = struct.unpack(">I", exactly(sock, 4))
    if auth != 1:
        raise RfbError("RFB_UNEXPECTED_AUTHENTICATION")
    sock.sendall(b"\x01")  # Shared desktop, no destructive user interaction.
    # RFB ServerInit: width+height (4), pixel format (16), then name_len (4).
    # Read the fixed geometry+pixel format only, not name_len twice.
    data = exactly(sock, 20)
    width, height = struct.unpack(">HH", data[:4])
    if (width, height) != SIZE:
        raise RfbError("WRONG_GUEST_FB_DIMENSIONS:" + str((width,height)))
    name_length, = struct.unpack(">I", exactly(sock, 4))
    if name_length > 128:
        raise RfbError("RFB_SERVER_NAME_TOO_LONG")
    name = exactly(sock, name_length).decode("utf-8", errors="replace")
    if "Qt" not in name and "VNC" not in name:
        raise RfbError("RFB_SERVER_IDENTITY_UNEXPECTED")
    pixel_format = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    sock.sendall(b"\x00\x00\x00\x00" + pixel_format)
    # RAW pixel encoding only; NO cursor pseudo-encoding or compression.
    sock.sendall(b"\x02\x00" + struct.pack(">H", 1) + struct.pack(">i", 0))
    return width, height


def framebuffer_update(sock: socket.socket, width: int, height: int,
                       image: Image.Image) -> tuple[Image.Image, int]:
    sock.sendall(b"\x03\x00" + struct.pack(">HHHH", 0, 0, width, height))
    header = exactly(sock, 4)
    if header[0] != 0:
        raise RfbError("RFB_UNEXPECTED_SERVER_MESSAGE")
    rectangles, = struct.unpack(">H", header[2:4])
    if rectangles > 64:
        raise RfbError("RFB_EXCESS_RECTANGLES")
    for _ in range(rectangles):
        chunk = exactly(sock, 12)
        x, y, rw, rh, encoding = struct.unpack(">HHHHi", chunk)
        if encoding != 0 or rw <= 0 or rh <= 0:
            raise RfbError("RFB_NONRAW_OR_EMPTY_RECTANGLE")
        if rw > width or rh > height or x + rw > width or y + rh > height:
            raise RfbError("RFB_RECTANGLE_OUT_OF_SCREEN")
        raw = exactly(sock, rw * rh * 4)
        # Requested little-endian 32bpp with shifts 16/8/0 => B,G,R,X.
        tile = Image.frombytes("RGB", (rw, rh), raw, "raw", "BGRX")
        image.paste(tile, (x, y))
    return image, rectangles


def metrics(image: Image.Image) -> dict:
    if image.size != SIZE:
        raise RfbError("IMAGE_SIZE_MISMATCH")
    rgb = image.convert("RGB")
    extremes = rgb.getextrema()
    spread = max(high - low for low, high in extremes)
    ncolors = rgb.getcolors(maxcolors=16)
    varied = spread >= 12 and (ncolors is None or len(ncolors) >= 16)
    return {"pixel_width": rgb.width, "pixel_height": rgb.height,
            "maximum_rgb_channel_spread": spread,
            "rgb_stddev": [round(x,2) for x in ImageStat.Stat(rgb).stddev],
            "nonuniform_real_pixels": varied}


def capture(root: Path, *, max_seconds: int = CAPTURE_SECONDS) -> tuple[dict, bytes | None]:
    isolated = require_network_isolation()
    if not 8 <= max_seconds <= CAPTURE_SECONDS:
        raise RfbError("CAPTURE_DURATION_OUT_OF_RANGE")
    if not root.is_dir() or root.is_symlink():
        raise RfbError("INVALID_GUEST_ROOT")
    root = root.resolve()
    launcher = root / "usr/bin/asteroid-launcher"
    if not launcher.is_file() or not launcher.resolve().is_relative_to(root):
        raise RfbError("REAL_ARM64_LAUNCHER_MISSING")
    read_arm64(launcher)
    vnc = find_arm64_qvnc(root)
    plugin_roots, svg = actual_qt_plugin_roots(root)
    qml_roots = sorted({
        str((root / prefix).resolve()) for prefix in QML_ROOTS
        if (root / prefix).is_dir() and (root / prefix).resolve().is_relative_to(root)
    })
    if not plugin_roots or not qml_roots:
        raise RfbError("REAL_TARGET_QT_IMPORT_PATHS_MISSING")
    if not shutil.which("qemu-aarch64"):
        raise RfbError("AARCH64_QEMU_NOT_AVAILABLE")
    with tempfile.TemporaryDirectory(prefix="uglyos-rfb-isolated-") as tmp:
        run_dir = Path(tmp)
        logfile = run_dir / "launcher.stderr"
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": str(run_dir),
            "TMPDIR": str(run_dir), "XDG_RUNTIME_DIR": str(run_dir),
            "LANG": "C",
            "QEMU_LD_PREFIX": str(root),
            "QT_QPA_PLATFORM": "vnc:size=360x360:port=5900",
            "QT_QPA_PLATFORM_PLUGIN_PATH": str(vnc.parent),
            "QT_PLUGIN_PATH": ":".join(map(str, plugin_roots)),
            "QML_IMPORT_PATH": ":".join(qml_roots),
            "QML2_IMPORT_PATH": ":".join(qml_roots),
            "QT_QUICK_BACKEND": "software",
            "QT_DEBUG_PLUGINS": "0",
            "QT_LOGGING_RULES": "qt.qml.states=true",
        }
        with private_system_bus(run_dir) as dbus_address:
            environment["DBUS_SYSTEM_BUS_ADDRESS"] = dbus_address
            started = time.monotonic()
            with logfile.open("wb") as output:
                try:
                    proc = subprocess.Popen(
                        ["qemu-aarch64", "-L", str(root), str(launcher), "-platform",
                         "vnc:size=360x360:port=5900"],
                        cwd=run_dir, env=environment, stdin=subprocess.DEVNULL,
                        stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
                except OSError as exc:
                    raise RfbError("QEMU_GUEST_PROCESS_START_FAILED") from exc
                frames = 0
                unblank = None
                best_image = None
                best_metrics = None
                last_metrics = None
                handshake_proven = False
                problem = None
                wake = None
                try:
                    conn = None
                    # Qt ARM64 startup can take several seconds under emulation.
                    while time.monotonic() - started < min(17, max_seconds):
                        if proc.poll() is not None:
                            problem = "GUEST_EXITED_BEFORE_VNC_HANDSHAKE"
                            break
                        try:
                            conn = socket.create_connection(("127.0.0.1", PORT), timeout=1)
                            break
                        except (OSError, socket.timeout):
                            time.sleep(0.35)
                    if conn:
                        with conn:
                            conn.settimeout(3.0)
                            width, height = handshake(conn)
                            handshake_proven = True
                            # Exact pinned original compositor XML exposes this
                            # private D-Bus method. Toggle false then true to show
                            # the otherwise hidden QQuickWindow off-device.
                            wake = force_compositor_window_visible(
                                dbus_address, max_wait=7.0)
                            image = Image.new("RGB", (width, height), (0,0,0))
                            while time.monotonic() - started < max_seconds and frames < 96:
                                if proc.poll() is not None:
                                    problem = "GUEST_EXITED_DURING_VNC_CAPTURE"
                                    break
                                try:
                                    image, rectangles = framebuffer_update(conn, width, height, image)
                                except RfbError as exc:
                                    problem = str(exc)
                                    break
                                if rectangles:
                                    frames += 1
                                    state = metrics(image)
                                    last_metrics = state
                                    if state["nonuniform_real_pixels"]:
                                        unblank = image.copy()
                                        best_metrics = state
                                        break
                                    # Do not exhaust the capture budget on rapid
                                    # repeated black-frame responses before Qt has
                                    # initialized its scenegraph under emulation.
                                    time.sleep(0.55)
                            if unblank is None and problem is None:
                                problem = "NO_NONBLANK_RFB_FRAME_RECEIVED"
                    elif problem is None:
                        problem = "QT_VNC_SERVER_NOT_LISTENING"
                finally:
                    if proc.poll() is None:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired as exc:
                        raise RfbError("QEMU_PROCESS_GROUP_NOT_TERMINATED") from exc
            runtime = round(time.monotonic() - started, 2)
            with logfile.open("rb") as f:
                diag = f.read(MAX_LOG_BYTES + 1)
            log = diag.decode("utf-8", errors="replace")
            errors = [text for text in ("Unsupported image format", "error while loading",
                                       "could not load the qt platform plugin",
                                       "segmentation fault")
                      if text.lower() in log.lower()]
            report = {
                "schema": "uglyos-r08-real-arm64-qt-vnc-raw-frame-v1",
                "status": "REAL_ARM64_QT_VNC_FRAME_UNVERIFIED",
                "isolated_network_interfaces": isolated,
                "network_namespace": "docker --network none, no host or external VNC",
                "vnc_loopback_only_inside_namespace": True,
                "actual_target_aarch64_vnc_qpa": "/" + str(vnc.relative_to(root)),
                "source_compiled_arm64_launcher": "/usr/bin/asteroid-launcher",
                "rfb_protocol_3_3_handshake_verified": handshake_proven,
                "raw_fb_rect_updates_received": frames,
                "last_raw_frame_color_statistics": last_metrics,
                "private_compositor_display_wakeup": wake,
                "runtime_seconds": runtime,
                "qt_image_format_errors": errors,
                "guest_aarch64_qsvg_decoder_present": bool(svg),
                "png_created_by_host_rfb_client_from_actual_guest_framebuffer": bool(unblank),
                "original_watch3_display_tested": False,
                "exynos9110_hardware_emulated": False,
                "samsung_bootloader_accepted": False,
                "stock_r840x_rescue_proven": False,
                "watch_contacted": False,
                "flashable": False, "decision": "NO_GO",
            }
            if (unblank is not None and not errors and best_metrics and
                    wake and wake["compositor_show_fullscreen_command_sequence_proven"]):
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False, dir=run_dir) as temp:
                    pngfile = Path(temp.name)
                try:
                    unblank.save(pngfile, format="PNG")
                    data = pngfile.read_bytes()
                finally:
                    pngfile.unlink(missing_ok=True)
                if not 100 <= len(data) <= 2_000_000:
                    raise RfbError("CAPTURED_RFB_PNG_LENGTH_INVALID")
                report["frame"] = {
                    **best_metrics, "png_sha256": hashlib.sha256(data).hexdigest(),
                    "png_bytes": len(data),
                }
                report["status"] = "REAL_ARM64_QT_VNC_NONBLANK_PIXEL_FRAME_CAPTURED"
                return report, data
            report["reason"] = problem or ("QT_FATAL_RUNTIME_MESSAGES" if errors
                                         else "NO_VALID_NONBLANK_RAW_FRAMEBUFFER")
            report["guest_log_tail"] = log[-1700:]
            return report, None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--extracted-rootfs", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--frame-output", required=True, type=Path)
    args = p.parse_args()
    if args.report.exists() or args.frame_output.exists():
        print("OUTPUT_EXISTS_REFUSING_OVERWRITE", file=sys.stderr)
        return 2
    try:
        proof, png = capture(args.extracted_rootfs)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(proof, indent=2) + "\n")
        if png is None:
            print("REAL_ARM64_RFB_FRAME_NOT_PROVEN:", proof, file=sys.stderr)
            return 2
        args.frame_output.parent.mkdir(parents=True, exist_ok=True)
        args.frame_output.write_bytes(png)
        assert hashlib.sha256(png).hexdigest() == proof["frame"]["png_sha256"]
    except (OSError, ValueError, SmokeFailure) as exc:
        print("REAL_ARM64_RFB_VISUAL_PROBE_REJECTED:", str(exc), file=sys.stderr)
        return 2
    print("REAL_ARM64_QT_RFB_RAW_FRAMEBUFFER_PNG_PROVEN", proof["frame"]["png_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
