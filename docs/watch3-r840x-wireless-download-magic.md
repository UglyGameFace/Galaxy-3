# SM-R840X: limited phone ↔ wireless-download protocol experiment

**Research status:** experimental; NO stock recovery, loader unlock, custom
kernel boot or damaged-partition restoration is proven. This document
describes the least-privileged *protocol* experiment, not a way to flash
or repair the watch. Use only on a watch you own and can physically access.

## Why this is the first useful live bootloader measurement

The existing Termux SDB port 26101 runs against Tizen. It tells us nothing
about the earlier Samsung wireless-download bootloader. Reading the source
of [AsteroidOS Ragnarök's TCP listener](https://github.com/AsteroidOS/ragnaroek/blob/master/ragnaroek/src/comms/net_bind.rs)
and [actual magic handler](https://github.com/AsteroidOS/ragnaroek/blob/master/ragnaroek/src/download_protocol/magic_handshake.rs)
shows a **different channel**:

- A watch in wireless-download mode connects **to the host** TCP 13579
  (host is the listening phone). Host port 13579 is not an outbound scan.
- Host sends exactly four ASCII bytes `ODIN`, and expects exactly
  four ASCII bytes `LOKE`.
- Session begin, PIT, flash, end/reboot and all 1024-byte Odin command
  packets happen **later**. This tool DOES NOT send any of them.
- A LOKE response is evidence of an **Odin-compatible peer** only, not
  authenticated proof of model/firmware or recovery success.

The source [PROTOCOL.md](https://github.com/AsteroidOS/ragnaroek/blob/master/PROTOCOL.md)
and Ragnarök CLI contain contradictory/static IP examples. The tool
avoids all IP assumptions: it binds IPv4 `0.0.0.0:13579`, accepts one
inbound connection and never records the peer IP. Nothing is attempted
unless the operator supplies **both** explicit live-mode flags.

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
remain UNPROVEN*. In all outcomes, the watch firmware is untouched.

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
