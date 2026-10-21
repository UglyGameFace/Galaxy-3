#!/usr/bin/env python3
"""Off-device QtWayland wl_shm round-trip under Xvfb; cleans every child."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    parser.add_argument("source", type=Path)
    opts = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="watch3-wl-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        root = Path(temp)
        runtime = root / "runtime"
        runtime.mkdir(mode=0o700)
        socket = "watch3-shm-0"
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = str(runtime)
        env["WAYLAND_DISPLAY"] = socket
        env["QT_QPA_PLATFORM"] = "xcb"
        env["QT_QUICK_BACKEND"] = "software"
        env["QT_WAYLAND_CLIENT_BUFFER_INTEGRATION"] = "shm"
        server_log = root / "compositor.log"
        client_log = root / "client.log"
        server_out = server_log.open("w")
        client_out = client_log.open("w")
        server = None
        client = None
        try:
            server = subprocess.Popen(
                [str(opts.build / "watch3_shm_compositor"), str(opts.source / "compositor.qml")],
                env=env, stdout=server_out, stderr=subprocess.STDOUT
            )
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if (runtime / socket).is_socket():
                    break
                if server.poll() is not None:
                    raise RuntimeError(f"compositor exited before socket creation ({server.returncode})")
                time.sleep(0.1)
            else:
                raise RuntimeError("Wayland compositor never created its socket")

            client_env = env.copy()
            client_env["QT_QPA_PLATFORM"] = "wayland"
            client_env["QT_WAYLAND_SHELL_INTEGRATION"] = "xdg-shell"
            client = subprocess.Popen(
                [str(opts.build / "watch3_shm_client")],
                env=client_env, stdout=client_out, stderr=subprocess.STDOUT
            )
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    break
                if client.poll() is not None:
                    raise RuntimeError(f"Wayland client exited early ({client.returncode})")
                time.sleep(0.1)
            else:
                raise RuntimeError("compositor round-trip exceeded 20 second deadline")

            if server.returncode != 0:
                raise RuntimeError(f"compositor failed with exit code {server.returncode}")
            server_out.flush()
            log = server_log.read_text(errors="replace")
            if "PASS[protocol]" not in log or "PASS[pixels]" not in log:
                raise RuntimeError("compositor never confirmed both wl_shm and output pixel checks")
            print(log, flush=True)
            print("PASS[roundtrip]: separate Wayland QWidget client -> real wl_shm -> software compositor pixels")
            return 0
        except RuntimeError as exc:
            print(f"FAIL[roundtrip]: {exc}", file=sys.stderr)
            return 1
        finally:
            for process in (client, server):
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            server_out.close()
            client_out.close()
            for label, log in (("compositor", server_log), ("client", client_log)):
                if log.exists():
                    print(f"--- {label} diagnostics ---", file=sys.stderr)
                    print(log.read_text(errors="replace")[-15000:], file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
