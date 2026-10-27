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

**2026-10-27 safety correction:** The original proof-of-concept bound
`0.0.0.0:13579`, allowing a connection on any phone interface. This is
not a suitable default for live R840X research. The revised program
requires `--bind-ip` equal to a private IPv4 address **actually assigned
to the phone's local Wi-Fi interface**. It binds only that exact IP and
refuses incoming peers outside its observed local subnet **before sending
any bytes**. Same-subnet membership is still NOT authentication of a
Samsung watch or proof of an Odin bootloader. The tool does **not**
assign an IP, change routing, or make the phone reachable at an
address the watch expects.

An independent **phone-only** Termux preflight
`tools/watch3_r840x_ap_network_preflight.py` uses only local WLAN
interface IOCTLs to report current private IPv4 and subnet. It does
not connect to the watch, send packets, start a listener, obtain an
SSID, enter Download mode, or run any phone shell. Some newer Android
versions may restrict interface IOCTLs; that must be marked
`WLAN_IPV4_UNAVAILABLE_OR_ANDROID_RESTRICTED`, not guessed or
worked around by using `0.0.0.0`. The **owner must manually verify**
the connected SSID is the Watch3's temporary Wireless Download AP,
not their home/public Wi-Fi. AP/WPS mode and routing remain
unproven on this R840X.

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

## Android-only Termux procedure (after tests and merge)

### Step A: PHONE-ONLY preflight; no watch reboot or connection

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_ap_network_preflight.py \
  --report ~/watch3-r840x-phone-wlan-preflight.json
cat ~/watch3-r840x-phone-wlan-preflight.json
```

The result lists the current **phone-local** WLAN IPv4 and subnet
only if Android makes them readable. It **cannot** identify a Wi-Fi
SSID or verify a Watch3 AP. It is not a bootloader handshake; no
watch request occurs. The report contains local addresses, so keep
it private.

**Actual R840X owner's Android result, 2026-10-27:** the above program
returned `WLAN_IPV4_UNAVAILABLE_OR_ANDROID_RESTRICTED` with empty
`wlan_ipv4`. That is a local discovery limitation and **does not
indicate any failed Watch3/Odin handshake**. No watch request was made.
Termux on Android 13+ has documented network interface restrictions
(see https://github.com/termux/termux-app/issues/2993), although this
result does not distinguish an unavailable WLAN adapter, interface
enumeration restriction, or an IOCTL failure.

#### Android netlink-permission fix: direct fixed-interface IOCTL

The owner then ran `ip -4 route show` on their Galaxy S25 Ultra and
observed exactly `Cannot bind netlink socket: Permission denied`.
Termux's own [Android 13+ bug report](https://github.com/termux/termux-app/issues/2993)
documents this class of sandbox restriction. That error is **from the
phone** and is unrelated to Watch3 firmware access.

The original Python probe first called `socket.if_nameindex()`, which
can use the same denied netlink route and return no interfaces *before*
attempting the already implemented local `SIOCGIFADDR` and
`SIOCGIFNETMASK` calls. Other users have observed `ifconfig` show
`wlan0` addresses and mask even when `ip` netlink fails. PR #77
therefore always attempts read-only IOCTLs on exact **literal**
`wlan0` and `wlan1`, with bounded, deduplicated discovered names
when enumeration succeeds. It does **not** assume any IP, subnet,
interface visibility or Android permission. Unavailable IOCTLs remain
`WLAN_IPV4_UNAVAILABLE_OR_ANDROID_RESTRICTED`. No root, shell,
network packets, socket listener, Wi-Fi changes or watch operations.

The actual Samsung Settings screenshot already confirmed the
**phone's** IPv4 address `10.0.0.98` on its currently connected
2.4 GHz Wi-Fi. That screenshot did **not** show a netmask/prefix.
A successful direct IOCTL report must derive the **actual prefix**
from the returned mask and is *not* allowed to fill in guessed `/24`.

**After merging, run the automatic preflight again without reusing
its existing output path** (default prints JSON without writing):

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_ap_network_preflight.py
```

If it returns `WLAN_IPV4_OBSERVED`, check that
`wlan_ipv4[].ipv4` equals `10.0.0.98` **only while still connected
to the same ordinary Wi-Fi**. A mismatch requires investigating
network switch before using it. When the phone later connects to
a separate Watch3 Download AP, it must derive/confirm an entirely
**new** current local WLAN address and subnet before any optional
live handshake. No new live watch experiment has been authorized.

#### Phone-only manual fallback, no IP guesses

While still on ordinary Wi-Fi with the watch in **normal Tizen**, open
your Galaxy phone's **Settings > Connections > Wi-Fi**, tap the gear
beside your **currently connected** network and scroll to the IP
details (some One UI versions need `View more`). Record exactly the
**phone's IPv4 address** and either the **subnet mask** or its CIDR
prefix length shown for the same network. Do not use the external/public
IP, router gateway, the watch's Tizen SDB address, or a remembered
`192.168.1.20`. Do **not** change Wi-Fi to Static.

If both values are shown in Settings, copy them into:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_ap_network_preflight.py \
  --manual-wifi-ip EXACT_PHONE_WIFI_IPV4 \
  --manual-wifi-netmask EXACT_VISIBLE_NETMASK_OR_PREFIX \
  --manual-wifi-settings-confirmed \
  --report ~/watch3-r840x-phone-manual-wlan.json
cat ~/watch3-r840x-phone-manual-wlan.json
```

Replace **both** placeholders with **actual currently displayed**
values. The subnet mask can be dotted IPv4 such as
`255.255.255.0` or the exact visible prefix such as `24`; those
are format examples **not suggested actual values**. If the mask or
prefix is not displayed, stop; do not assume `/24`. If the phone
rejects local `bind(ip, 0)`, or mask is malformed, or subnet is
too broad, the program fails safely. Binding ephemeral port 0 does
**not** send packets, listen, contact the watch or authenticate an
interface. Even a successful result means only that a private
user-entered IP is locally bindable and the user claims it came from
Android Wi-Fi settings. It **cannot independently prove that Wi-Fi
owns that IP, confirm SSID, or identify a Samsung bootloader**.

### Step B: separate opt-in manual Watch3 Wireless Download observation

Only if the owner explicitly chooses the temporary Watch3 reboot and
is comfortable with the risk of a boot-mode transition:

1. Confirm the watch normally boots Tizen and has enough charge. Know
   how to perform the Watch3's documented force restart.
2. On the watch, enter `Download (Wireless)` only when the actual
   physical menu matches the documented labels. If AP mode is
   available, connect Android Wi-Fi to that watch AP **not to a home,
   public or ordinary phone hotspot**. Android may report no internet.
   Do not choose Recovery / factory reset or start any update.
3. Inspect the Android Wi-Fi screen and confirm the SSID
   matches the temporary **watch** AP. Termux cannot verify that
   identity. Run the phone-only preflight again with a **NEW report
   filename**. If IOCTL discovery is still blocked, manually enter
   the **new actual connected-watch-AP Wi-Fi IPv4 AND the actual mask
   shown in Android Settings**, with
   `--manual-wifi-settings-confirmed`, as above. Do not reuse the
   address from ordinary home Wi-Fi; Wi-Fi networks can change the
   assigned address. If Android does not show both values or if
   the ephemeral local bind fails, STOP. Never guess historical
   `192.168.1.20` or fall back to `0.0.0.0`.
4. Only after manual AP confirmation, run one four-byte test using
   the freshly observed local Wi-Fi address as `PHONE_WLAN_IPV4`
   (replace that token with the literal preflight result). If
   **manual mode** was required, include the two additional
   confirmed-mask flags shown below:

```sh
python tools/watch3_r840x_netodin_magic_only.py \
  --live-magic-only \
  --watch-ap-confirmed \
  --bind-ip PHONE_WLAN_IPV4 \
  --listen-seconds 60 \
  --report ~/watch3-r840x-odin-magic-redacted.json
cat ~/watch3-r840x-odin-magic-redacted.json
```

If Termux could not read WLAN metadata and you used the **manual
Settings fallback**, the optional live test would instead require:

```sh
python tools/watch3_r840x_netodin_magic_only.py \
  --live-magic-only \
  --watch-ap-confirmed \
  --bind-ip PHONE_IPV4_FROM_CURRENT_WATCH_AP_SETTINGS \
  --manual-wifi-netmask NETMASK_FROM_SAME_WATCH_AP_SETTINGS \
  --manual-wifi-settings-confirmed \
  --listen-seconds 60 \
  --report ~/watch3-r840x-odin-magic-redacted.json
```

That command is **NOT** the immediate next task; run the
phone-only preflight on normal Wi-Fi first. The live command requires
a voluntary physical Watch3 boot-mode change. IPs and netmasks are
NOT automatically detected or inherited from an earlier network.

The listener binds only `PHONE_WLAN_IPV4:13579` and replies with
exactly `ODIN` to one inbound same-subnet peer, expecting at most
four bytes `LOKE`. It never sends Odin session-start, PIT, flashing,
reboot or exploit commands. It does NOT authenticate the endpoint as
Samsung hardware; `LOKE` is only magic exchange evidence.

5. Exit Download mode using the model-appropriate documented force
   restart, return to ordinary Tizen, and restore normal phone Wi-Fi.
   Do not treat a forced reboot as proof you can repair corrupt flash.

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

The five literal read-only requests first test the same authenticated SDB shell with `cat /proc/version`, then check file capabilities of `/usr/bin/dotnet` and `/usr/sbin/sdbd-tarlauncher`, installed .NET runtime versions, and whether the existing `/usr/bin/tar --help` advertises `--to-command`. The JSON output contains only categorical results; no raw process or network information. **STATIC_PREREQUISITES_OBSERVED** indicates this narrow route merits further engineering; it does not prove injected SDB commands are accepted, privilege elevation, unsigned code acceptance or recovery. **STATIC_PATH_NOT_SUPPORTED** requires an actual negative prerequisite observation. Failed/blocked reads yield **INCONCLUSIVE**, not a fabricated incompatibility. Tests use an in-memory fake SDB peer only. No device experimentation has happened.

Do not use the TV-specific exploit binary, package-name payloads or kernel address assumptions on the only working watch.

## R840X field result: all four checks unavailable

An actual SM-R840X report showed `INCONCLUSIVE` with four `UNAVAILABLE`
checks. The original shared SDB collector discarded shell-command rejections,
missing utility/path errors and parser mismatches into the same vague result.
That report **does not** show that the TV-derived archive-root prerequisites
are missing, nor that SDB elevation is supported.

Re-run the existing `--root-path-only` mode after updating main. The five
fixed read-only requests now begin with a kernel-version baseline and report
`sdb_shell_baseline` as `KERNEL_VERSION_READ` or `NOT_OBSERVED`.
The four original checks still report the existing per-check `acquisition` categories:
`SDB_SHELL_CLOSED_OR_REFUSED`, `SDB_SHELL_TIMEOUT`,
`SDB_PROTOCOL_OR_READ_FAILURE`, `SDB_TRANSPORT_UNREACHABLE`,
`WATCH_REPORTED_COMMAND_OR_PATH_MISSING`, `WATCH_REPORTED_ACCESS_DENIED`,
`EMPTY_SHELL_OUTPUT`, or `OUTPUT_RECEIVED`. None include raw private
watch details. An `OUTPUT_RECEIVED` with an `UNAVAILABLE` parsed check
is a **parser mismatch**, not a proven negative prerequisite. A shell
refusal suggests the restricted Tizen SDB dispatcher blocked the command;
a missing path requires differentiating absent tool and absent target in
later analysis. No exploit, archive launch or firmware write occurs.

## R840X real SDB root-path observation: 2026-10-27 (working IP 10.0.0.65)

Owner's authenticated read-only SDB observation on the live R840X:
`sdb_shell_baseline=KERNEL_VERSION_READ`; `tar --to-command` advertised;
both capability probes reported `WATCH_REPORTED_COMMAND_OR_PATH_MISSING`;
the .NET list-runtimes request returned bytes, but the original narrow parser
did not recognize them. This **does not** prove the capability-bearing
binaries are missing because the watch may lack `getcap` itself.

A follow-up, still read-only, checks `ls -ld` on each exact required
binary and tries `readlink -f /usr/share/dotnet.tizen/netcoreapp` as a
Tizen-specific fallback if the desktop-style runtime listing is unknown.
All values are categorized without saving raw paths, firmware secrets or
watch IPs. A target-absent result is reported only if `ls` names the
exact missing path; a missing `ls` command is not misclassified as an
absent target. This is not the TV SDB injection payload or a root attempt.

Run after the branch is merged:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_android_sdb.py --watch-ip 10.0.0.65 --root-path-only
cat ~/watch3-r08-root-path-redacted.json
```

If a required file is **proven absent**, this *specific TV archive-launcher
chain* is unavailable in its published form. If files are present but
capability tools are unavailable, the result correctly remains inconclusive.
Do not install tools onto Tizen, attempt firmware writes or assume another
model's kernel exploit applies.
