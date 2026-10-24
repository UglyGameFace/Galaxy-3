# Galaxy Watch3 SM-R840X R08: compare live Tizen boot facts (READ ONLY)

**Purpose:** replace assumptions from historical Samsung source with facts from
the **running** Watch3 before planning a first custom boot. No device changes,
firmware flashing, reboot, privilege escalation or root access.

The historical reference [CI #40112813921](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40112813921)
found KEXEC disabled and historical initramfs root=/dev/ram0, but did not
prove the installed R840X uses those settings.

## Phone hotspot setup and connection diagnosis

**Samsung explicitly supports using a mobile hotspot** for Tizen Galaxy Watch
development. A hotspot-generated address (often 10.x.x.x instead of 192.168.x.x)
is valid as long as it is the currently displayed **WATCH** Wi-Fi IP. Do not use
your phone's hotspot gateway address or the example IP from this document.

Before trying again:
1. Watch: **Settings > About watch > Debugging = ON** (Tizen; not Wear OS ADB).
2. Watch: **Settings > Connections > Wi-Fi > Always on**, connected directly
   to your phone's active hotspot. Samsung recommends this only for debugging;
   change back to Auto later to save battery.
3. **Normally restart the watch once after enabling debugging**, as Samsung's
   Tizen developer instructions recommend, then reconnect watch to hotspot.
   Confirm the current watch IP again because it can change on reconnect.
4. Keep the phone's hotspot enabled and Termux in the foreground.

On Android/Termux with the latest Galaxy-3 code:

```sh
cd ~/Galaxy-3
git pull --ff-only
python tools/watch3_r08_android_sdb.py --watch-ip WATCH_IP --diagnose-only
```

Replace WATCH_IP with the actual numeric address shown on the watch.
The diagnosis checks three phases individually: **TCP 26101**, **SDB protocol
and authorization**, and a read-only /proc/version shell. It never prints the
raw response, device IP, serial, RSA secret or unfiltered kernel command line.

- **FAIL[tcp-refused]:** A watch or another endpoint actively refused port
  26101. Check enabled Tizen debugging and normal restart.
- **FAIL[tcp-timeout]:** No TCP reply. Verify the watch's current hotspot IP,
  Wi-Fi connection, and whether the phone hotspot permits phone-to-client
  connections. A hotspot does not guarantee client reachability.
- **PASS[tcp] + FAIL[sdb]:** The port is open; investigate the experimental
  SDB protocol or watch authorization rather than changing IP addresses.
- **PASS[sdb] + FAIL[shell]:** SDB handshake worked but the read-only shell
  was rejected, unavailable or returned unrecognized output.
- **All PASS:** Run the same command *without* --diagnose-only to generate
  ~/watch3-r08-boot-redacted.json (redacted report). Do not paste raw SDB
  packets or secret outputs into a GitHub issue.

If hotspot routing remains blocked, an ordinary shared Wi-Fi router is a
possible alternative. No PC, root or firmware modification is needed for
these read-only checks.

Official sources:
- https://developer.samsung.com/sdp/blog/en/2021/04/12/remote-device-manager-an-easy-way-to-launch-your-application-with-tizen-studio
- https://developer.samsung.com/galaxy-watch-tizen/testing-your-app-on-galaxy-watch.html

## Method 0: Android-only direct SDB without a computer (experimental)

We now have a **pure-Python SDB protocol client** in
[watch3_r08_android_sdb.py](../tools/watch3_r08_android_sdb.py).
It uses a manually supplied private-network watch IP, Samsung SDB
TCP port 26101, Samsung's 24-byte message framing, read-only shell
services, and an optional locally generated RSA authentication key
if the watch challenges the phone. Unlike running the official
Samsung SDB binary, **the actual R840X connection has not been tested**
and the watch might reject the client. All protocol tests use fake
devices in GitHub Actions, not your watch.

On an Android phone with Termux, on the same trusted Wi-Fi as the watch:

1. On the watch, enable developer/debugging options and find its Wi-Fi IP.
   Samsung's official procedure is linked at the end of this guide.
2. In Termux, use the already installed Galaxy-3 checkout, or clone it:
   `pkg install python git` and
   `git clone https://github.com/UglyGameFace/Galaxy-3.git`.
3. From the Galaxy-3 directory run, replacing the example IP with
   the actual IP shown on **your watch**:

   ```sh
   cd ~/Galaxy-3
   python tools/watch3_r08_android_sdb.py --watch-ip 192.168.1.40
   ```

4. If the watch asks for RSA approval, accept **only** if you initiated
   this connection. If Termux reports a missing library, install the
   local package with `pkg install python-cryptography` and run again.
   The RSA private key stays in Termux's private app directory under
   `~/.config/galaxy3/watch3-sdbkey`. **Never share or commit it.**
5. When successful, inspect the local privacy-filtered file:
   `~/watch3-r08-boot-redacted.json`. The script never saves raw SDB
   shell output, serial numbers, IP addresses or unfiltered command lines.

**The direct client is not an installation tool.** Its ONLY allowed
remote commands are the seven specific read-only commands listed in
Method A. It cannot write firmware, read hidden partitions, change
permissions, restart the watch or authorize an AsteroidOS boot.

If it cannot connect, don't try root/unlock/download-mode shortcuts.
Report the brief sanitized failure message so the protocol mismatch
can be fixed without putting the watch at risk.

## Method A: existing authorized SDB client

Samsung documents **Smart Development Bridge (SDB)** over Wi-Fi, typically
TCP port 26101, with approval on the Tizen Galaxy Watch. This is **not ADB**.
The Wear OS Android ADB-pairing instructions do not apply to the R840X.

1. Enable the watch's official Tizen debugging setting and connect the watch
   and SDB host to the same trusted Wi-Fi.
2. On a terminal that already has an authorized SDB client, verify
   'sdb devices'. If needed, standard Tizen syntax is
   'sdb connect <watch-ip>:26101'. Approve access on the watch.
3. On that terminal, with Python 3, run:

    python3 tools/watch3_r08_live_boot_probe.py \
      --collect-sdb \
      --report "$HOME/watch3-r08-boot-redacted.json"

If multiple authorized devices appear, specify an exact identifier from
'sdb devices' with --target. The script never guesses which device to use.

The only remote commands issued are:
- cat /proc/cmdline
- cat /proc/version
- cat /proc/partitions
- cat /proc/device-tree/model
- cat /proc/device-tree/chosen/bootargs
- ls -l /dev/block/by-name
- ls -l /dev/disk/by-name

Some paths may be missing or permission-restricted. Unavailable paths
are marked as such, not accessed through root or brute force.

### Android-only limitation

The probe is Python and compatible with Termux's Python, **but Termux
does not automatically include a verified Samsung SDB client**. No
Android SDB shell app has yet been tested on this *exact* R840X.
Do not substitute ADB, sideload an untrusted installer, or run guessed
bootloader commands. If the phone cannot run an authorized SDB client,
use Method B if you have previous output from an authorized SDB session.

## Method B: parse existing captures, completely offline

Create a private local directory, for example ~/watch3-capture, containing:

| Filename | Read-only source |
|---|---|
| cmdline.txt | cat /proc/cmdline |
| version.txt | cat /proc/version |
| partitions.txt | cat /proc/partitions |

Optional: model.txt from cat /proc/device-tree/model, bootargs.txt from
cat /proc/device-tree/chosen/bootargs, block_links.txt from
ls -l /dev/block/by-name and disk_links.txt from ls -l /dev/disk/by-name.

On Android with Termux, Python can be installed with 'pkg install python'.
When the Galaxy-3 repository is checked out locally:

    python tools/watch3_r08_live_boot_probe.py \
      --from-dir "$HOME/watch3-capture" \
      --report "$HOME/watch3-r08-boot-redacted.json"

The offline mode makes **no watch or network connection**.

## Report meaning and privacy

The JSON contains running kernel version and only a short allowlist of
boot arguments such as root=, console= and init=. It compares root=
to the historical /dev/ram0 reference and reports partitions and only
selected boot-related symlink labels where visible. It never guesses
missing partition numbers.

Raw /proc/cmdline can contain private OEM identifiers, network secrets,
serials and developer details. The script does **not** save raw stdout,
stderr, network addresses, SDB serial, or arbitrary kernel parameters.
Raw captures must remain private. Review the redacted JSON before sharing.
Never upload raw boot dumps to public GitHub CI, issues or PRs.

This report always states that custom-boot acceptance, recoverable
matching stock firmware and flashing authorization are **NOT PROVEN**.
Even matching live kernel arguments are insufficient to establish a
bootable AsteroidOS kernel or safe installer.

Next: use real values to establish the exact running kernel boot context,
then resolve the *independent* bootloader signature and stock recovery
barriers before any trial boot or firmware write.

Official sources:
- https://developer.samsung.com/galaxy-watch-tizen/testing-your-app-on-galaxy-watch.html
- https://docs.tizen.org/application/tizen-studio/common-tools/smart-development-bridge/
