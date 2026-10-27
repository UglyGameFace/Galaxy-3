#!/usr/bin/env python3
"""Termux-to-Tizen read-only SDB, without a computer or Samsung SDK.

Only fixed boot, storage or battery sysfs reads in explicit allowlists may run.
No root, reboot, device writes, partition reading, install or flashing.
The battery sysfs uevent response is not yet verified on physical SM-R840X.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import sys

from watch3_r08_live_boot_probe import PROBES, STORAGE_PROBES, summarize
from watch3_r08_storage_mapping import summarize_storage
from watch3_r08_power_baseline import summarize_power
from watch3_r08_bezel_capabilities import summarize_bezel
from watch3_r08_boot_memory import summarize_memory

# Read ONLY the pinned Samsung battery device's read-only sysfs uevent.
# No wildcard, arbitrary paths, raw blocks or writes; its exact identity
# is validated before reporting a battery percentage.
POWER_PROBES = {"battery_uevent": "cat /sys/class/power_supply/battery/uevent"}
# One fixed read-only text registry. It reports names, capability bitmaps
# and kernel handler tokens, NOT any actual bezel rotation or keypresses.
BEZEL_PROBES = {"input_devices": "cat /proc/bus/input/devices"}
# Safe kernel pseudo-text; no partition reads or binary device-tree nodes.
# /proc/iomem is optional: Linux may mask System RAM ranges for non-root users.
BOOT_MEMORY_PROBES = {
    "meminfo": "cat /proc/meminfo",
    "iomem": "cat /proc/iomem",
}

# Explicit, fixed, read-only operations; storage and battery probe sets run
# only when expressly requested. Normal boot collection stays unchanged.
ALLOWED_PROBES = {**PROBES, **STORAGE_PROBES, **POWER_PROBES, **BEZEL_PROBES, **BOOT_MEMORY_PROBES}

PORT = 26101
VERSION = 0x00100000
MAX_PAYLOAD = 256 * 1024
MAX_OUTPUT = 64 * 1024
HEADER = struct.Struct("<6I")
KNOWN = {b"CNXN", b"AUTH", b"OPEN", b"OKAY", b"WRTE", b"CLSE"}


class SdbError(ValueError):
    pass


class ShellCloseError(SdbError):
    """The watch closed a requested shell stream, possibly before acceptance.

    This is different from failure of the authenticated TCP/SDB transport.
    The frame's local/remote stream IDs, not watch identifiers, are logged.
    """


def frame(kind: bytes, arg0=0, arg1=0, body=b""):
    if kind not in KNOWN or len(body) > MAX_PAYLOAD:
        raise SdbError("Invalid SDB frame command or payload size")
    code = int.from_bytes(kind, "little")
    return HEADER.pack(code, arg0, arg1, len(body), sum(body) & 0xffffffff,
                       code ^ 0xffffffff) + body


def read_exact(sock, amount):
    data = bytearray()
    while len(data) < amount:
        chunk = sock.recv(amount - len(data))
        if not chunk:
            raise SdbError("Tizen SDB connection closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


def receive(sock):
    code, arg0, arg1, size, checksum, magic = HEADER.unpack(read_exact(sock, 24))
    if magic != (code ^ 0xffffffff) or size > MAX_PAYLOAD:
        raise SdbError("Invalid SDB frame header")
    kind = code.to_bytes(4, "little")
    if kind not in KNOWN:
        raise SdbError("Unsupported SDB frame type")
    body = read_exact(sock, size)
    if sum(body) & 0xffffffff != checksum:
        raise SdbError("SDB checksum mismatch")
    return kind, arg0, arg1, body


def crypto_modules():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
        return hashes, serialization, padding, rsa, utils
    except ImportError as exc:
        raise SdbError(
            "Watch requested SDB RSA authentication. In Termux install "
            "the optional package: pkg install python-cryptography"
        ) from exc


def local_private_key(path):
    _, serialization, _, rsa, _ = crypto_modules()
    if not path.exists():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        try:
            with os.fdopen(
                os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
            ) as dest:
                dest.write(private)
        except FileExistsError:
            pass
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_mode & 0o077):
        raise SdbError("SDB private key must be a regular private file (0600)")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise SdbError("Local SDB private key cannot be parsed") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
        raise SdbError("SDB private key must be RSA 2048")
    return key


def sign_auth_token(path, token):
    if len(token) != 20:
        raise SdbError("Unsupported Tizen SDB authorization token")
    hashes, _, padding, _, utils = crypto_modules()
    return local_private_key(path).sign(
        token, padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))


def adb_public_key(path):
    numbers = local_private_key(path).public_key().public_numbers()
    modulus = numbers.n
    inv = (-pow(modulus, -1, 1 << 32)) & 0xffffffff
    rr = pow(2, 4096, modulus)
    data = (struct.pack("<II", 64, inv) +
            modulus.to_bytes(256, "little") +
            rr.to_bytes(256, "little") +
            struct.pack("<I", numbers.e))
    if len(data) != 524:
        raise SdbError("Invalid SDB public key")
    return base64.b64encode(data) + b" watch3-termux\x00"


class Connection:
    def __init__(self, sock, key_path):
        self.sock = sock
        self.key_path = key_path

    def send(self, kind, arg0=0, arg1=0, body=b""):
        self.sock.sendall(frame(kind, arg0, arg1, body))

    def handshake(self):
        self.send(b"CNXN", VERSION, MAX_PAYLOAD, b"host::\x00")
        auth_count = 0
        for _ in range(5):
            kind, arg0, _arg1, body = receive(self.sock)
            if kind == b"CNXN":
                if not body.startswith(b"device:"):
                    raise SdbError("Endpoint did not identify as SDB device")
                return
            if kind != b"AUTH" or arg0 != 1:
                raise SdbError("Unexpected SDB authorization response")
            auth_count += 1
            if auth_count == 1:
                self.send(b"AUTH", 2, 0, sign_auth_token(self.key_path, body))
            elif auth_count == 2:
                self.send(b"AUTH", 3, 0, adb_public_key(self.key_path))
            else:
                raise SdbError("Watch authorization failed; approve prompt on watch")
        raise SdbError("Watch SDB handshake could not complete")

    def shell(self, operation, style="standard"):
        if operation not in ALLOWED_PROBES:
            raise SdbError("Operation not in the fixed read-only allowlist")
        if style not in {"standard", "tizen-command"}:
            raise SdbError("Unknown read-only SDB shell service style")
        # Classic watch SDB uses "shell:cat ..."; Samsung's Tizen service
        # dispatcher on some models uses "shell:0 cat ..." instead.
        # Both variants only contain our literal read-only allowlist.
        destination = ("shell:" if style == "standard" else "shell:0 ")
        local = 2
        self.send(b"OPEN", local, 0,
                  (destination + ALLOWED_PROBES[operation]).encode() + b"\x00")
        remote = None
        output = bytearray()
        payload_frames = 0
        for _ in range(128):
            try:
                kind, arg0, arg1, body = receive(self.sock)
            except (OSError, TimeoutError) as exc:
                # Show protocol phase, not raw output, network identifiers or
                # authorization material. A refused shell is not a kernel read.
                phase = ("before OKAY" if remote is None
                         else f"after OKAY remote_id={remote}")
                raise ShellCloseError(
                    "SDB shell timed out " + phase +
                    f"; WRTE frames={payload_frames}, bytes={len(output)}"
                ) from None
            if kind == b"OKAY":
                if arg1 != local or (remote is not None and remote != arg0):
                    raise SdbError("Invalid SDB stream identifiers")
                if arg0 == 0:
                    raise SdbError("Device acknowledged shell with zero stream ID")
                remote = arg0
            elif kind == b"WRTE":
                if remote is None or arg0 != remote or arg1 != local:
                    raise SdbError("Unexpected SDB stream data")
                if len(body) + len(output) > MAX_OUTPUT:
                    raise SdbError("SDB response exceeded allowed size")
                output.extend(body)
                payload_frames += 1
                self.send(b"OKAY", local, remote)
            elif kind == b"CLSE":
                # A valid refused OPEN has sender_id=0, receiver_id=local;
                # it must NEVER be treated as successful empty output.
                # Record only stream IDs, not frame content or secrets.
                if remote is None:
                    if arg0 == 0 and arg1 == local:
                        raise ShellCloseError(
                            "Read-only shell OPEN refused by SDB (CLSE 0/local)")
                    raise ShellCloseError(
                        "SDB closed read-only shell before opening it "
                        f"(CLSE sender_id={arg0}, receiver_id={arg1}, "
                        f"expected_receiver_id={local})")
                if arg1 != local:
                    raise ShellCloseError(
                        "SDB closed an established shell for the wrong local "
                        f"stream (CLSE sender_id={arg0}, receiver_id={arg1}, "
                        f"expected_receiver_id={local})")
                if arg0 == 0:
                    # Some *older* ADB-family daemons use CLSE(0, local)
                    # even AFTER acknowledging OPEN, although modern ADB
                    # documentation reserves zero for failed OPEN. Real
                    # Watch3 screenshot shows OKAY(9,2), then CLSE(0,2).
                    # No payload: NOT success. Actual WRTE: may finish.
                    if not output:
                        raise ShellCloseError(
                            "SDB acknowledged shell then closed it with "
                            f"CLSE(0,{local}) without any WRTE data "
                            "(legacy zero-sender close or service refusal)")
                    return output.decode("utf-8", "replace")
                if arg0 != remote:
                    raise ShellCloseError(
                        "SDB closed an established shell with unexpected "
                        f"sender_id={arg0}, expected_sender_id={remote}, "
                        f"receiver_id={arg1}")
                # Existing Samsung SDB behavior echoes a normal nonzero close.
                self.send(b"CLSE", local, remote)
                if not output:
                    raise ShellCloseError(
                        "SDB acknowledged shell but closed without WRTE data "
                        f"(remote_id={remote})")
                return output.decode("utf-8", "replace")
            else:
                raise SdbError("Unexpected SDB frame during read-only shell")
        raise SdbError("SDB response exceeded frame limit")


def private_watch_ip(raw):
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise SdbError("Use the watch's numeric Wi-Fi IP address, not a hostname") from exc
    if not (address.is_private or address.is_link_local or address.is_loopback):
        raise SdbError("Only local-network watch IP addresses are accepted")
    return str(address)


def diagnose(ip, key_path, timeout=4, output=print):
    """Report the FIRST failing layer, not raw device output or identifiers.

    TCP connect, SDB authentication and one allowlisted read of /proc/version
    are separate steps. This method never changes the device.
    """
    ip = private_watch_ip(ip)
    try:
        with socket.create_connection((ip, PORT), timeout=timeout) as sock:
            sock.settimeout(8)
            output("PASS[tcp]: Watch debugging port 26101 is reachable.")
            channel = Connection(sock, key_path)
            try:
                channel.handshake()
            except (SdbError, OSError, TimeoutError) as exc:
                if isinstance(exc, (OSError, TimeoutError)):
                    raise SdbError(
                        "FAIL[sdb]: TCP connected but watch did not complete "
                        "SDB handshake. Check Tizen Debugging and authorization."
                    ) from None
                raise SdbError(
                    "FAIL[sdb]: TCP connected, SDB protocol/authentication "
                    "failed: " + str(exc)
                ) from None
            output("PASS[sdb]: Watch accepted experimental SDB handshake.")
            try:
                result = channel.shell("version")
                style = "standard"
                if "Linux version " not in result:
                    raise ShellCloseError(
                        "Standard SDB shell response was not a kernel version")
            except ShellCloseError as first:
                output("NOTE[shell]: Standard read-only shell was closed or "
                       "returned no valid kernel version; checking documented "
                       "Tizen command-prefixed format.")
                try:
                    # Independent connection, not an unverified reuse of a
                    # closed SDB stream. Never send arbitrary commands.
                    with socket.create_connection((ip, PORT),
                                                  timeout=timeout) as second:
                        second.settimeout(8)
                        other = Connection(second, key_path)
                        other.handshake()
                        result = other.shell("version", style="tizen-command")
                    style = "tizen-command"
                except (SdbError, OSError, TimeoutError) as second_error:
                    # All messages describe protocol state, not raw output.
                    if isinstance(second_error, ShellCloseError):
                        reason = str(second_error)
                    elif isinstance(second_error, SdbError):
                        reason = str(second_error)
                    else:
                        reason = "second read-only shell did not respond"
                    raise SdbError(
                        "FAIL[shell]: Both allowed read-only SDB shell forms "
                        "failed. Standard: " + str(first) + "; Tizen command: "
                        + reason
                    ) from None
            except (SdbError, OSError, TimeoutError) as exc:
                if isinstance(exc, (OSError, TimeoutError)):
                    raise SdbError(
                        "FAIL[shell]: SDB connected but read-only shell "
                        "did not respond."
                    ) from None
                raise SdbError(
                    "FAIL[shell]: SDB connected but read-only shell failed: "
                    + str(exc)
                ) from None
            if "Linux version " not in result:
                raise SdbError(
                    "FAIL[shell]: SDB responded but did not provide a "
                    "recognizable /proc/version. No raw output displayed."
                )
            output("PASS[shell]: Read-only watch kernel version is accessible "
                   f"(format={style}).")
            output("NEXT: Run without --diagnose-only to collect redacted boot facts.")
    except ConnectionRefusedError:
        raise SdbError(
            "FAIL[tcp-refused]: Device refused TCP port 26101. On Tizen "
            "Watch3 enable Settings > About watch > Debugging, set Wi-Fi "
            "Always on, and normally restart the watch."
        ) from None
    except (TimeoutError, socket.timeout):
        raise SdbError(
            "FAIL[tcp-timeout]: No reply on TCP port 26101. Confirm the "
            "watch's currently displayed hotspot IP, debugging and Wi-Fi "
            "connection. Your phone's hotspot may isolate clients."
        ) from None
    except OSError:
        raise SdbError(
            "FAIL[tcp-network]: Watch SDB port could not be reached on "
            "the current network. Check the watch's IP, hotspot and Wi-Fi."
        ) from None


def collect(ip, key_path, timeout=8, probes=PROBES):
    ip = private_watch_ip(ip)
    observations, problems = {}, {}
    if (probes is not PROBES and probes is not STORAGE_PROBES and
            probes is not POWER_PROBES and probes is not BEZEL_PROBES and
            probes is not BOOT_MEMORY_PROBES):
        raise SdbError("Only predefined boot, storage, battery, bezel or boot-memory probe sets are allowed")
    for name in probes:
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(max(timeout, 25))
                channel = Connection(sock, key_path)
                channel.handshake()
                try:
                    value = channel.shell(name)
                except ShellCloseError:
                    # A Tizen command-dispatcher variant is observed on some
                    # Samsung devices. Only try the SAME fixed read-only
                    # operation, in a fresh authorized connection.
                    with socket.create_connection((ip, PORT),
                                                  timeout=timeout) as second:
                        second.settimeout(max(timeout, 25))
                        alt = Connection(second, key_path)
                        alt.handshake()
                        value = alt.shell(name, style="tizen-command")
            if (not value.strip() or any(
                warning in value.lower() for warning in (
                    "permission denied", "no such file", "not found", "access denied"
                ))):
                problems[name] = "Read-only property unavailable"
            else:
                observations[name] = value
        except SdbError as exc:
            if any(key in str(exc).lower() for key in (
                "authorization", "authentication", "private key", "crypto", "rsa"
            )):
                raise
            problems[name] = "Read-only property unavailable over SDB"
        except (OSError, TimeoutError):
            problems[name] = "Watch did not answer this SDB read"
    return observations, problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-ip", required=True,
                        help="Exact watch address on your trusted Wi-Fi")
    parser.add_argument("--diagnose-only", action="store_true",
                        help="Check hotspot port, SDB handshake and one "
                             "read-only version command; never collect raw "
                             "boot data or flash anything")
    parser.add_argument("--storage-only", action="store_true",
                        help="Read only fixed /proc/mounts and /sys eMMC "
                             "device mapper dependencies; redacted report")
    parser.add_argument("--power-only", action="store_true",
                        help="Collect one redacted, read-only Tizen battery gauge "
                             "snapshot; never writes to the watch")
    parser.add_argument("--bezel-only", action="store_true",
                        help="Read Tizen input capability names and bitmaps, "
                             "save only a privacy-filtered bezel report; "
                             "never capture live rotation or button events")
    parser.add_argument("--boot-memory-only", action="store_true",
                        help="Read only Tizen /proc/meminfo and /proc/iomem; "
                             "save privacy-filtered RAM ranges; no bootloader commands")
    parser.add_argument("--report", type=Path,
                        help="Optional local privacy-filtered JSON destination")
    parser.add_argument("--key-path", type=Path,
                        default=Path.home() / ".config/galaxy3/watch3-sdbkey")
    args = parser.parse_args()
    if sum((args.diagnose_only, args.storage_only,
            args.power_only, args.bezel_only, args.boot_memory_only)) > 1:
        parser.error("Choose at most one of --diagnose-only, --storage-only, "
                     "--power-only, --bezel-only or --boot-memory-only")
    if args.diagnose_only:
        try:
            diagnose(args.watch_ip, args.key_path)
        except (SdbError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    try:
        if args.power_only:
            values, errors = collect(args.watch_ip, args.key_path,
                                     probes=POWER_PROBES)
            report = summarize_power(values, errors)
            dest = args.report or (Path.home() /
                                   "watch3-r08-battery-redacted.json")
        elif args.bezel_only:
            values, errors = collect(args.watch_ip, args.key_path,
                                     probes=BEZEL_PROBES)
            report = summarize_bezel(values, errors)
            dest = args.report or (Path.home() /
                                   "watch3-r08-bezel-redacted.json")
        elif args.boot_memory_only:
            values, errors = collect(args.watch_ip, args.key_path,
                                     probes=BOOT_MEMORY_PROBES)
            report = summarize_memory(values, errors)
            dest = args.report or (Path.home() /
                                   "watch3-r08-boot-memory-redacted.json")
        elif args.storage_only:
            values, errors = collect(args.watch_ip, args.key_path,
                                     probes=STORAGE_PROBES)
            report = summarize_storage(values, errors)
            dest = args.report or (Path.home() /
                                   "watch3-r08-storage-redacted.json")
        else:
            values, errors = collect(args.watch_ip, args.key_path)
            report = summarize(values, errors)
            dest = args.report or (Path.home() /
                                   "watch3-r08-boot-redacted.json")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(report, indent=2) + "\n")
    except (SdbError, ValueError, OSError) as exc:
        print("FAIL[read-only-sdb]: " + str(exc), file=sys.stderr)
        print("DIAGNOSE: Run again with --diagnose-only to distinguish "
              "hotspot/TCP, SDB handshake and read-only shell problems.",
              file=sys.stderr)
        return 1
    if args.power_only and report["status"] != "OBSERVED_TIZEN_BATTERY":
        print("UNAVAILABLE: Watch battery gauge not confirmed; no battery "
              "percentage or drain inferred. Redacted report saved locally.")
    elif args.bezel_only and report["status"] != "BEZEL_REL_WHEEL_ADVERTISED":
        print("UNAVAILABLE: Physical REL_WHEEL capability not confirmed; "
              "no rotation events or Qt navigation inferred. Redacted report saved.")
    elif args.boot_memory_only and report["status"] == "LIVE_MEMORY_UNAVAILABLE":
        print("UNAVAILABLE: Watch kernel RAM evidence masked or unavailable; "
              "no layout or boot addresses inferred.")
    else:
        print("PASS: privacy-filtered Watch3 " +
              ("power" if args.power_only else "bezel capability" if args.bezel_only else
               "boot memory" if args.boot_memory_only else
               "storage" if args.storage_only else "boot") +
              " report saved locally.")
    print("Report path:", dest)
    print("NO bootloader acceptance or stock recovery proven. NOT FLASHABLE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
