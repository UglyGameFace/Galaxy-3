#!/usr/bin/env python3
"""Isolated test-only system D-Bus for the ORIGINAL AArch64 Asteroid launcher.

The compiled Lipstick compositor exposes org.nemomobile.compositor on the
system bus and supports setUpdatesEnabled(boolean) on object path '/'.
Reference: AsteroidOS/asteroid-launcher at pinned source revision
0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31,
lipstick/src/compositor/compositor.xml and lipstickcompositor.cpp.

The compositor starts with m_updatesEnabled=True; to show its QQuickWindow,
it must first be set False and then True (showFullScreen). Without genuine
watch MCE, it can create QML and an all-black VNC frame indefinitely.

NEVER execute this outside the --network none container. Never contacts a
physical watch or connects to any host machine system D-Bus. Uses ephemeral
Unix socket strictly inside disposable Docker /tmp. Bus calls only affect
the emulated ARM64 launcher process.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import signal
import subprocess
import time

INTERFACE = "org.nemomobile.compositor"
OBJECT_PATH = "/"
MAX_BUS_WAIT = 4.0
MAX_COMPOSITOR_WAIT = 10.0


class PrivateBusError(ValueError):
    pass


def bus_environment(socket_path: Path) -> str:
    if not socket_path.is_absolute() or socket_path.name != "uglyos-private-system.sock":
        raise PrivateBusError("INVALID_PRIVATE_SYSTEM_BUS_SOCKET")
    if "/tmp/uglyos-" not in str(socket_path):
        raise PrivateBusError("PRIVATE_BUS_MUST_LIVE_IN_DISPOSABLE_TMP")
    return "unix:path=" + str(socket_path)


@contextmanager
def private_system_bus(run_dir: Path):
    """Start one bus limited to disposable container socket. Kill on exit."""
    from watch3_r08_qemu_vnc_capture import require_network_isolation
    require_network_isolation()
    if not run_dir.is_dir() or run_dir.is_symlink() or not run_dir.resolve().is_relative_to(Path("/tmp")):
        raise PrivateBusError("NONDISPOSABLE_DBUS_DIRECTORY")
    if not __import__("shutil").which("dbus-daemon"):
        raise PrivateBusError("DBUS_DAEMON_NOT_INSTALLED")
    target = run_dir / "uglyos-private-system.sock"
    if target.exists() or target.is_symlink():
        raise PrivateBusError("PRIVATE_SYSTEM_BUS_SOCKET_ALREADY_EXISTS")
    address = bus_environment(target)
    log = run_dir / "private-dbus.stderr"
    with log.open("wb") as stderr:
        process = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--nopidfile",
             "--address=" + address],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
            cwd=run_dir, start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "HOME": str(run_dir)},
        )
        try:
            deadline = time.monotonic() + MAX_BUS_WAIT
            while not target.is_socket() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise PrivateBusError("PRIVATE_DBUS_DAEMON_EXITED_EARLY:" + log.read_text(errors="replace")[-900:])
                time.sleep(0.05)
            if not target.is_socket():
                raise PrivateBusError("PRIVATE_SYSTEM_BUS_SOCKET_NOT_READY:" + log.read_text(errors="replace")[-900:])
            yield address
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    raise PrivateBusError("PRIVATE_DBUS_DAEMON_NOT_TERMINATED") from None


def send_display_update(address: str, value: bool) -> bool:
    """Only org.nemomobile.compositor.setUpdatesEnabled on local bus."""
    if not address.startswith("unix:path=/tmp/uglyos-") or "\n" in address:
        raise PrivateBusError("UNSAFE_OR_NONLOCAL_TEST_DBUS_ADDRESS")
    command = [
        "dbus-send", "--bus=" + address, "--type=method_call",
        "--print-reply", "--reply-timeout=1200",
        "--dest=" + INTERFACE, OBJECT_PATH,
        INTERFACE + ".setUpdatesEnabled",
        "boolean:" + ("true" if value else "false"),
    ]
    try:
        r = subprocess.run(
            command, capture_output=True, stdin=subprocess.DEVNULL,
            timeout=2.5, check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def force_compositor_window_visible(address: str,
                                    *, max_wait: float = MAX_COMPOSITOR_WAIT) -> dict:
    """Send false then true, proving real ARM64 compositor D-Bus methods reply."""
    if not 1 <= max_wait <= MAX_COMPOSITOR_WAIT:
        raise PrivateBusError("OUT_OF_BOUNDS_COMPOSITOR_BUS_WAIT")
    started = time.monotonic()
    off_confirmed = False
    on_confirmed = False
    attempts = 0
    while time.monotonic() - started < max_wait:
        attempts += 1
        if not off_confirmed:
            off_confirmed = send_display_update(address, False)
        elif not on_confirmed:
            on_confirmed = send_display_update(address, True)
        if off_confirmed and on_confirmed:
            break
        time.sleep(0.25)
    return {
        "private_system_bus_socket_in_container": address.split("unix:path=")[1],
        "compositor_dbus_owner_name": INTERFACE,
        "system_bus_display_off_method_replied": off_confirmed,
        "system_bus_display_on_method_replied": on_confirmed,
        "compositor_show_fullscreen_command_sequence_proven": off_confirmed and on_confirmed,
        "bus_requests_attempted": attempts,
        "bus_stage_seconds": round(time.monotonic() - started, 3),
        "physical_watch_contacted": False,
        "host_system_dbus_contacted": False,
        "flashable": False,
    }
