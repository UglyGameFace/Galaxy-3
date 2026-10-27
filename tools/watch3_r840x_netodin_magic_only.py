#!/usr/bin/env python3
"""Experimental Samsung Wireless Download *magic-only* handshake (Android/Termux).

STRICT LIMIT: one TCP accept, send exactly b'ODIN' (4 bytes), receive at
most 4 bytes b'LOKE', close. NO session-start (0x64), PIT (0x65), flash
(0x66), reboot (0x67), reset, partition write, or firmware upload.

A correct response indicates an Odin-compatible endpoint, NOT proof
of peer identity, SM-R840X, custom boot acceptance or a recovery path.
Manually entering/exiting Download mode can still be disruptive.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import sys
import time

PORT = 13579
MAGIC_OUT = b"ODIN"
MAGIC_IN = b"LOKE"
DEFAULT_WAIT = 60
PER_SOCKET_TIMEOUT = 5.0


def perform_magic_once(listener: socket.socket, seconds: int = DEFAULT_WAIT) -> dict:
    """Accept one connection and exchange magic only. Do not store client IP."""
    result = {
        "schema": "watch3-r840x-wireless-odin-magic-v1",
        "state": "NO_INBOUND_CONNECTION",
        "host_port": PORT,
        "watch_identity_verified": False,
        "received_loke": False,
        "firmware_written": False,
        "odin_session_started": False,
        "pit_requested": False,
        "custom_boot_verified": False,
        "stock_recovery_verified": False,
        "flash_allowed": False,
    }
    if seconds < 5 or seconds > 180:
        raise ValueError("listen timeout must be 5–180 seconds")
    listener.settimeout(float(seconds))
    try:
        peer, _ = listener.accept()
    except socket.timeout:
        return result
    except OSError:
        result["state"] = "LISTENER_ERROR"
        return result

    with peer:
        peer.settimeout(PER_SOCKET_TIMEOUT)
        try:
            # Exactly 4 bytes sent. No command frame or other protocol traffic.
            peer.sendall(MAGIC_OUT)
            answer = b""
            while len(answer) < 4:
                segment = peer.recv(4 - len(answer))
                if not segment:
                    break
                answer += segment
            if answer == MAGIC_IN:
                result["received_loke"] = True
                result["state"] = "ODIN_LOKE_MAGIC_VERIFIED_UNAUTHENTICATED_PEER"
            else:
                result["state"] = "INVALID_OR_INCOMPLETE_MAGIC"
        except (OSError, socket.timeout):
            result["state"] = "MAGIC_EXCHANGE_FAILED"
    return result


def run_live(seconds: int = DEFAULT_WAIT) -> dict:
    # Bind only when operator explicitly requests live mode.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", PORT))
        server.listen(1)
        print("Armed magic-only listener on port 13579; waiting for a watch-initiated TCP connection.", flush=True)
        print("Never sends Odin session, PIT, flash or reboot commands.", flush=True)
        return perform_magic_once(server, seconds)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--live-magic-only", action="store_true",
                    help="Explicitly listen for one download-mode peer; sends only ODIN magic")
    ap.add_argument("--watch-ap-confirmed", action="store_true",
                    help="I am using the watch's temporary Wireless Download AP, not public Wi-Fi")
    ap.add_argument("--listen-seconds", type=int, default=DEFAULT_WAIT)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args(argv)

    if not (args.live_magic_only and args.watch_ap_confirmed):
        ap.error("No network action by default. Live test requires BOTH --live-magic-only and --watch-ap-confirmed.")
    if not (5 <= args.listen_seconds <= 180):
        ap.error("--listen-seconds must be 5..180")

    try:
        result = run_live(args.listen_seconds)
    except OSError as exc:
        print("FAIL: cannot bind or accept port 13579: " + type(exc).__name__, file=sys.stderr)
        return 2
    body = json.dumps(result, indent=2) + "\n"
    if args.report:
        args.report.write_text(body)
        print("Wrote privacy-filtered handshake-only report: " + str(args.report))
    else:
        print(body, end="")
    print("NO_GO for firmware changes, custom boot, or presumed recovery.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
