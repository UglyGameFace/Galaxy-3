# Galaxy Watch3 SM-R840X R08: compare live Tizen boot facts (READ ONLY)

**Purpose:** replace assumptions from historical Samsung source with facts from
the **running** Watch3 before planning a first custom boot. No device changes,
firmware flashing, reboot, privilege escalation or root access.

The historical reference [CI #40112813921](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40112813921)
found KEXEC disabled and historical initramfs root=/dev/ram0, but did not
prove the installed R840X uses those settings.

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
