# SM-R840X: limited phone ↔ wireless-download protocol experiment

**Research status:** experimental; NO stock recovery, loader unlock, custom
kernel boot or damaged-partition restoration is proven. This document
describes the least-privileged *protocol* experiment, not a way to flash
or repair the watch. Use only on a watch you own and can physically access.

## Proposed bootloader transport measurement

The existing Termux SDB port 26101 runs against Tizen. It tells us nothing
about the earlier Samsung wireless-download bootloader. Reading the source
of [AsteroidOS Ragnarök's TCP listener](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/comms/net_bind.rs)
and [actual magic handler](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/magic_handshake.rs)
shows a **different channel**:

- A watch in wireless-download mode connects **to the host** TCP 13579
  (host is the listening phone). Host port 13579 is not an outbound scan.
- Host sends exactly four ASCII bytes `ODIN`, and expects exactly
  four ASCII bytes `LOKE`.
- Session begin, PIT, flash, end/reboot and all 1024-byte Odin command
  packets happen **later**. This tool DOES NOT send any of them.
- A LOKE response is evidence of an **Odin-compatible peer** only, not
  authenticated proof of model/firmware or recovery success.

The pinned [PROTOCOL.md](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/PROTOCOL.md)
describes a historical AP topology: watch `192.168.1.1` connects to host
`192.168.1.20:13579`. Those addresses have **not** been observed on this
R840X. The CLI's `192.168.49.1` upload/shell default belongs to a separate
transport; it is not contradictory evidence for Wireless Download AP.

The tool binds IPv4 `0.0.0.0:13579` and accepts one inbound connection.
That listens on addresses the phone already owns; it **does not assign
an IP, change routing, or make the phone reachable at an address the
watch expects**. The actual AP address/subnet, assigned phone address,
and watch's connection target must be established before a live trial.
Android Wi-Fi connection alone does not prove these prerequisites.
Do not copy historical static IPs or add automatic address workarounds.
The tool never records the peer IP. Nothing is attempted unless the
operator supplies **both** explicit live-mode flags.

## Hardware and operator precautions

Before any experiment, watch must reliably boot normal stock Tizen
and have adequate battery. Official [Samsung Watch3 forced restart](https://www.samsung.com/us/support/troubleshoot/TSG10007068/)
uses **both Home/Power and Back** held until `Rebooting...`. This
is a means to restart a responsive, unmodified watch, **not** complete
stock restoration if firmware/bootloader partitions fail.

Entering Download (Wireless) is a temporary change of boot mode. Never
select **Recovery / Factory reset**, do not accept firmware offers,
do not press `Start` in Odin, and do not send a PIT, boot image,
hand-built packet, exploit, signed or unsigned firmware. Be prepared
to force restart the watch to exit if the Odin screen remains. If it
cannot return to Tizen, stop; do not try destructive retries.

Third-party Watch3-family descriptions mention `Download (Wireless)`,
then toggling its WPS mode to AP mode with two Home presses. **Screen
labels and behavior must be checked on the actual SM-R840X**; do not
guess if its menus differ.

## Android-only Termux procedure (only after merging PR)

1. Enter the watch's Wireless Download menu manually if and only if
   you are comfortable with the temporary reboot and can use its
   documented force-restart. In wireless AP mode, connect your phone's
   Wi-Fi to the watch's temporary network, **not** a public hotspot.
   Android may warn that there is no internet; remain on that Wi-Fi.
   Check its IP/subnet and gateway in Android's Wi-Fi details against
   the watch's observed network information. If the expected host
   address cannot be established, the routing prerequisite is still
   unverified; a timeout cannot diagnose bootloader capability.
2. Run this on your Android S25 Ultra Termux; no root or desktop needed.
   The tool exits after one connection or a 60-second default timeout:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_netodin_magic_only.py \
  --live-magic-only \
  --watch-ap-confirmed \
  --listen-seconds 60 \
  --report ~/watch3-r840x-odin-magic-redacted.json
cat ~/watch3-r840x-odin-magic-redacted.json
```

If no connection is seen, **do not infer the bootloader lacks Odin**:
phone Wi-Fi routing, AP/WPS mode, unexpected listen IP, timeouts or
Android restrictions can prevent the TCP connection. Report
`NO_INBOUND_CONNECTION`, which is a genuine measurement.

If `ODIN_LOKE_MAGIC_VERIFIED_UNAUTHENTICATED_PEER`, the phone and
wireless download loader completed the **four-byte exchange**, but
*device identity, PIT, signatures, partition rescue and custom boot
remain UNPROVEN*. The tool sends no firmware or partition-write commands.

3. Restart the watch using **both physical Watch3 buttons**, wait for
   ordinary Tizen to return, reconnect the phone's usual Wi-Fi.
   Do not confuse a normal reboot with recovery from corruption.

No serials, bootloader data, Wi-Fi keys, network identifiers or IPs are
saved to the redacted JSON. GitHub CI only runs synthetic local TCP
tests. No claim is made that this experiment has happened on hardware.

## Follow-on gate, NOT included

If and only if the actual peer handshake succeeds and the watch
returns to normal stock Tizen, the next **separately scoped** study
would inspect PIT *read-only* on a sacrificial R840X and verify
bootloader signature/rollback checks against lawful OEM binaries.
A live Odin write, partition exploit, custom image boot or
restoration trial on the only working watch is not authorized.

## Separate read-only code-first root-path prerequisite check

The 2026 [Bishop Fox SDB injection advisory](https://bishopfox.com/blog/samsung-tizen-os-version-through-9-0) and [open-source TV archive-launcher root research](https://github.com/chris-ritsen/samsung-tv-root/blob/master/src/samsung_tv_root/archive_root.py) identify a **specific** possible elevation chain. It was demonstrated on Tizen TVs, **not the SM-R840X Watch3**. The Watch3 already provides an unprivileged SDB shell, so SDB command execution alone would not grant root.

The existing authenticated, read-only SDB client can check its *static* Watch3 prerequisites without running an exploit, installing an app, uploading an archive or modifying the watch:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_android_sdb.py --watch-ip WATCH_CURRENT_IP --root-path-only
cat ~/watch3-r08-root-path-redacted.json
```

The four literal requests check file capabilities of `/usr/bin/dotnet` and `/usr/sbin/sdbd-tarlauncher`, installed .NET runtime versions, and whether the existing `/usr/bin/tar --help` advertises `--to-command`. The JSON output contains only categorical results; no raw process or network information. **STATIC_PREREQUISITES_OBSERVED** indicates this narrow route merits further engineering; it does not prove injected SDB commands are accepted, privilege elevation, unsigned code acceptance or recovery. **STATIC_PATH_NOT_SUPPORTED** requires an actual negative prerequisite observation. Failed/blocked reads yield **INCONCLUSIVE**, not a fabricated incompatibility. Tests use an in-memory fake SDB peer only. No device experimentation has happened.

Do not use the TV-specific exploit binary, package-name payloads or kernel address assumptions on the only working watch.

## R840X field result: all four checks unavailable

An actual SM-R840X report showed `INCONCLUSIVE` with four `UNAVAILABLE`
checks. The original shared SDB collector discarded shell-command rejections,
missing utility/path errors and parser mismatches into the same vague result.
That report **does not** show that the TV-derived archive-root prerequisites
are missing, nor that SDB elevation is supported.

Re-run the existing `--root-path-only` mode after updating main. The same
four fixed read-only requests now report per-check `acquisition` categories:
`SDB_SHELL_CLOSED_OR_REFUSED`, `SDB_SHELL_TIMEOUT`,
`SDB_PROTOCOL_OR_READ_FAILURE`, `SDB_TRANSPORT_UNREACHABLE`,
`WATCH_REPORTED_COMMAND_OR_PATH_MISSING`, `WATCH_REPORTED_ACCESS_DENIED`,
`EMPTY_SHELL_OUTPUT`, or `OUTPUT_RECEIVED`. None include raw private
watch details. An `OUTPUT_RECEIVED` with an `UNAVAILABLE` parsed check
is a **parser mismatch**, not a proven negative prerequisite. A shell
refusal suggests the restricted Tizen SDB dispatcher blocked the command;
a missing path requires differentiating absent tool and absent target in
later analysis. No exploit, archive launch or firmware write occurs.
