#!/usr/bin/env python3
"""Observe Android/Termux WLAN IPv4 assignments with NO watch contact.

Uses Linux SIOCGIFADDR/SIOCGIFNETMASK on local WLAN devices, including\na fixed wlan0/wlan1 fallback when Android blocks interface enumeration.
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
    """Local-only WLAN IOCTLs, even if Android blocks netlink enumeration.

    socket.if_nameindex() may itself require NETLINK_ROUTE, denied to
    third-party apps on Android 13+. Use the fixed conventional WLAN
    interface labels as a fallback. SIOCGIFADDR and SIOCGIFNETMASK only
    read local kernel interface metadata; no network packets are sent.
    An absent interface or denied IOCTL stays INCONCLUSIVE, not a
    fabricated /24 or guessed subnet.
    """
    try:
        discovered = [name for _, name in socket.if_nameindex()
                      if WLAN_NAME.fullmatch(name)]
    except (OSError, ValueError):
        discovered = []

    # Literal, bounded names: no user-selected paths, netlink dump,
    # network scanning, command execution, or guessed IP/netmask.
    ifaces = list(dict.fromkeys(discovered[:6] + ["wlan0", "wlan1"]))
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
                if not is_rfc1918(address) or address in (
                        network.network_address, network.broadcast_address):
                    continue
                result.append({
                    "interface": name,
                    "ipv4": str(address),
                    "subnet": str(network),
                    "rfc1918_address": True,
                    "source": "DIRECT_WLAN_IOCTL_NO_NETWORK_PACKETS",
                })
    except OSError:
        return []
    return result


def validate_manual_wifi_details(
    wifi_ip: str, wifi_netmask: str, *, settings_confirmed: bool,
) -> ipaddress.IPv4Network:
    """Check user-entered Android Wi-Fi details using LOCAL bind only.

    Binding to an ephemeral IPv4 port without listen()/connect()/send()
    verifies local assignment, NOT the adapter type or the watch identity.
    The human must inspect the Wi-Fi settings screen and confirm the two
    fields came from the same CURRENTLY CONNECTED Wi-Fi network.
    """
    if not settings_confirmed:
        raise ValueError("ANDROID_WIFI_SETTINGS_CONFIRMATION_REQUIRED")
    try:
        addr = ipaddress.IPv4Address(wifi_ip)
        network = ipaddress.IPv4Network((str(addr), wifi_netmask), strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        raise ValueError("MANUAL_WIFI_ADDRESS_OR_MASK_INVALID") from None
    if not is_rfc1918(addr):
        raise ValueError("MANUAL_WIFI_IP_NOT_RFC1918")
    # Only reasonably scoped WLAN subnets; never approve /8 or /16
    # just because the IP looks private (would admit unrelated peers).
    if not 20 <= network.prefixlen <= 30:
        raise ValueError("MANUAL_WIFI_SUBNET_TOO_BROAD_OR_NARROW")
    if addr in (network.network_address, network.broadcast_address):
        raise ValueError("MANUAL_WIFI_IP_NOT_HOST_ADDRESS")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((str(addr), 0))
            # Never call listen(), accept(), connect() or send().
    except OSError:
        raise ValueError("MANUAL_WIFI_IP_NOT_LOCALLY_BINDABLE") from None
    return network


def subnet_for_bind_ip(
    bind_ip: str, *, manual_wifi_netmask: str | None = None,
    manual_wifi_settings_confirmed: bool = False,
) -> ipaddress.IPv4Network:
    """Require either readable WLAN IOCTL, or locally-bound manual Wi-Fi details."""
    try:
        addr = ipaddress.IPv4Address(bind_ip)
    except ipaddress.AddressValueError:
        raise ValueError("BIND_IP_NOT_VALID_IPV4") from None
    if not is_rfc1918(addr):
        raise ValueError("BIND_IP_NOT_RFC1918")
    if manual_wifi_netmask is not None:
        return validate_manual_wifi_details(
            bind_ip, manual_wifi_netmask,
            settings_confirmed=manual_wifi_settings_confirmed)
    for observed in observe_wlan_ipv4():
        if observed["ipv4"] == str(addr) and observed["rfc1918_address"]:
            return ipaddress.IPv4Network(observed["subnet"], strict=False)
    raise ValueError("BIND_IP_NOT_OBSERVED_ON_WLAN")


def preflight_report(
    *, manual_wifi_ip: str | None = None,
    manual_wifi_netmask: str | None = None,
    manual_wifi_settings_confirmed: bool = False,
) -> dict:
    # Manual mode is opt-in. There is no implicit guessed /24 prefix.
    if manual_wifi_ip is not None or manual_wifi_netmask is not None:
        if not manual_wifi_ip or not manual_wifi_netmask:
            raise ValueError("MANUAL_WIFI_REQUIRES_IP_AND_NETMASK")
        subnet = validate_manual_wifi_details(
            manual_wifi_ip, manual_wifi_netmask,
            settings_confirmed=manual_wifi_settings_confirmed)
        addresses = [{
            "interface": "ANDROID_WIFI_SETTINGS_MANUAL",
            "ipv4": str(ipaddress.IPv4Address(manual_wifi_ip)),
            "subnet": str(subnet),
            "rfc1918_address": True,
            "local_bind_verified": True,
            "source": "ANDROID_WIFI_SETTINGS_USER_ENTERED",
        }]
        status = "MANUAL_WIFI_ADDRESS_LOCALLY_BINDABLE_NOT_SSID_VERIFIED"
    else:
        addresses = observe_wlan_ipv4()
        status = ("WLAN_IPV4_OBSERVED" if addresses else
                  "WLAN_IPV4_UNAVAILABLE_OR_ANDROID_RESTRICTED")
    return {
        "schema": SCHEMA,
        "status": status,
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
            "Phone-local Wi-Fi IPv4/subnet only. Manual mode proves ONLY that "
            "the user-entered address is bindable locally; it does not "
            "technically prove which interface owns the IP or verify SSID. "
            "The user must separately confirm Android's current Wi-Fi "
            "network is the watch's temporary Download AP before any "
            "live experiment. No network packets are transmitted."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Optional private local JSON; no overwrite")
    parser.add_argument("--manual-wifi-ip",
                        help="Current IPv4 read in Android Settings > Connections > Wi-Fi")
    parser.add_argument("--manual-wifi-netmask",
                        help="Exact mask or prefix shown by Android Wi-Fi details, e.g. 255.255.255.0")
    parser.add_argument("--manual-wifi-settings-confirmed", action="store_true",
                        help="I checked BOTH values on the current Wi-Fi network details screen")
    args = parser.parse_args(argv)
    if args.manual_wifi_settings_confirmed and not args.manual_wifi_ip:
        parser.error("Manual confirmation requires --manual-wifi-ip and --manual-wifi-netmask")
    try:
        report = preflight_report(
            manual_wifi_ip=args.manual_wifi_ip,
            manual_wifi_netmask=args.manual_wifi_netmask,
            manual_wifi_settings_confirmed=args.manual_wifi_settings_confirmed,
        )
    except ValueError as exc:
        print("LOCAL_WIFI_PREFLIGHT_FAILED: " + str(exc), file=sys.stderr)
        return 2
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
