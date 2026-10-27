#!/usr/bin/env python3
"""Observe Android/Termux WLAN IPv4 assignments with NO watch contact.

Uses Linux SIOCGIFADDR/SIOCGIFNETMASK on locally enumerated WLAN devices.
Never reads SSIDs, scans APs, connects to a peer, starts a server, invokes
shell commands or changes networking. Output is local-only and optional.
"""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891b
WLAN_NAME = re.compile(r"(?:wlan|wifi|swlan)[0-9]{1,2}\Z")
PRIVATE_SUBNETS = tuple(ipaddress.IPv4Network(x) for x in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
))
SCHEMA = "uglyos-r840x-android-local-wlan-preflight-v1"


def is_rfc1918(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in PRIVATE_SUBNETS)


def read_ipv4_ioctl(sock, ifname: str, operation: int) -> str:
    if not WLAN_NAME.fullmatch(ifname):
        raise ValueError("NOT_ALLOWLISTED_WLAN_INTERFACE")
    request = struct.pack("256s", ifname.encode("ascii"))
    reply = fcntl.ioctl(sock.fileno(), operation, request)
    if len(reply) < 24:
        raise OSError("short interface reply")
    return socket.inet_ntoa(reply[20:24])


def observe_wlan_ipv4() -> list[dict]:
    """Local interface metadata only. Unavailable Android IOCTL is inconclusive."""
    try:
        ifaces = sorted(name for _, name in socket.if_nameindex()
                        if WLAN_NAME.fullmatch(name))
    except (OSError, ValueError):
        return []
    result = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for name in ifaces[:8]:
                try:
                    addr_text = read_ipv4_ioctl(sock, name, SIOCGIFADDR)
                    mask_text = read_ipv4_ioctl(sock, name, SIOCGIFNETMASK)
                    address = ipaddress.IPv4Address(addr_text)
                    network = ipaddress.IPv4Network(
                        (addr_text, mask_text), strict=False)
                except (OSError, ValueError, ipaddress.AddressValueError):
                    continue
                result.append({
                    "interface": name,
                    "ipv4": str(address),
                    "subnet": str(network),
                    "rfc1918_address": is_rfc1918(address),
                })
    except OSError:
        return []
    return result


def subnet_for_bind_ip(bind_ip: str) -> ipaddress.IPv4Network:
    """Only a private IPv4 actually assigned to a local WLAN is permitted."""
    try:
        addr = ipaddress.IPv4Address(bind_ip)
    except ipaddress.AddressValueError:
        raise ValueError("BIND_IP_NOT_VALID_IPV4") from None
    if not is_rfc1918(addr):
        raise ValueError("BIND_IP_NOT_RFC1918")
    for observed in observe_wlan_ipv4():
        if observed["ipv4"] == str(addr) and observed["rfc1918_address"]:
            return ipaddress.IPv4Network(observed["subnet"], strict=False)
    raise ValueError("BIND_IP_NOT_OBSERVED_ON_WLAN")


def preflight_report() -> dict:
    addresses = observe_wlan_ipv4()
    return {
        "schema": SCHEMA,
        "status": ("WLAN_IPV4_OBSERVED" if addresses else
                   "WLAN_IPV4_UNAVAILABLE_OR_ANDROID_RESTRICTED"),
        "wlan_ipv4": addresses,
        "wifi_ssid_verified": False,
        "watch_download_ap_verified": False,
        "odin_peer_verified": False,
        "tcp_listener_started": False,
        "network_packets_sent": False,
        "watch_contacted": False,
        "watch_write_performed": False,
        "bootloader_acceptance_proven": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "Phone-assigned WLAN IPv4/subnet only. The user must separately "
            "confirm their Wi-Fi SSID is the watch's temporary Download AP "
            "using Android Settings. An unlisted interface is inconclusive "
            "on newer Android releases. This never contacts the watch."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Optional private local JSON; no overwrite")
    args = parser.parse_args(argv)
    report = preflight_report()
    body = (json.dumps(report, indent=2) + "\n").encode()
    if args.report is not None:
        target = args.report.expanduser()
        try:
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(body)
            except BaseException:
                target.unlink(missing_ok=True)
                raise
        except OSError:
            print("LOCAL_REPORT_UNAVAILABLE_OR_ALREADY_EXISTS", file=sys.stderr)
            return 1
        print("LOCAL_WLAN_PREFLIGHT: " + str(target))
    else:
        print(body.decode(), end="")
    print("NO watch access, TCP connection, listener, firmware action or reboot.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
