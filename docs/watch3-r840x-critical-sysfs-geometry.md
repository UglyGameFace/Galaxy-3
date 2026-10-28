# Galaxy Watch3 SM-R840X: critical partition start/size as READ-ONLY sysfs text

**Issue #47. Status: NO-GO FOR FLASHING OR CUSTOM BOOT.**
Installed Tizen: `SM-R840X`, `NOBLESSE-LARGE-BT R08`,
`R840XXXU1AUA2`, observed active CSC `PAP`.

## Why this is the next *small* question

The owner already physically read and, on October 27, reconciled **21/21**
kernel `uevent` `PARTNAME` text fields using the existing
`watch3_r840x_merge_sysfs_reports_offline.py` tool. These included
**`mmcblk0p10=param`**, **`mmcblk0p13=boot`**, and
**`mmcblk0p14=recovery`**. See the
[actual completed four-report merge](watch3-r840x-sysfs-partition-labels.md#completed-owner-run-offline-2121-merge-october-27-2026).

The old blockers **have changed**: numbered labels are no longer
unknown for these three roles. But we still have **no authentic Samsung
PIT with sectors/offsets**, no signed full R840X recovery package,
no demonstrated recovery after failed boot, and no accepted custom
kernel. A source-authenticated PIT comparison, if one becomes
available, benefits from a separate observation of what the running
**Linux kernel** considers those partition start/size sector fields.

The new `tools/watch3_r840x_critical_sysfs_geometry.py` uses **only**
Galaxy-3's already existing, authenticated SDB and exact-allowlist
`collect` transport. Its **seven** hardcoded normal Tizen commands are:

```text
cat /sys/class/block/mmcblk0/size
cat /sys/class/block/mmcblk0p10/start
cat /sys/class/block/mmcblk0p10/size
cat /sys/class/block/mmcblk0p13/start
cat /sys/class/block/mmcblk0p13/size
cat /sys/class/block/mmcblk0p14/start
cat /sys/class/block/mmcblk0p14/size
```

These are **Linux sysfs scalar pseudo-files**, **not** reads of
`/dev/mmcblk0` or actual block partitions. No whole-partition data,
key material, signed boot image, recovery payload, PIT, CSC update,
NetOdin command, privilege escalation, dynamic shell input,
file writes to watch storage or firmware operation is attempted.
Nothing runs without an explicit owner command. GitHub Actions tests
use **fake responses only**.

## Parsing and actual meaning

The tool expects one strictly numeric text scalar per file and
rejects mixed text, negatives, leading zeros, oversized numbers,
missing fields, or ranges past the separately obtained disk sector
count. It checks the three ranges do not overlap within this
**kernel-reported** snapshot and reports the count and half-open
end sector, **not any command to read/write at those offsets**.

The Linux `size` and `start` sysfs fields conventionally use
**512-byte sector units**, independently of a physical device's
larger hardware block size. The report uses that precise description,
but **does not equate this with an independently authenticated
Samsung PIT** or extrapolate to remaining 18 partitions or eMMC boot
areas. See Linux [block device sysfs ABI documentation](
https://www.kernel.org/doc/html/latest/admin-guide/abi-stable-files.html).
Even a complete snapshot can be stale after firmware replacement,
cannot attest device identity, and does not establish stock
image signing, bootloader layout or the ability to restore after
failed boot.

## One optional Android/Termux read after merge + CI

Run **only if** you still have a normally booted and working Tizen
Watch3, and its authorized SDB is already accessible over the same
trusted Wi-Fi/hotspot. Confirm the current **watch-side private IP**
on the watch; never blindly reuse a previous 10.x address.

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_critical_sysfs_geometry.py \
  --watch-ip WATCH_CURRENT_WIFI_IP
cat ~/watch3-r840x-critical-geometry-redacted.json
```

Replace the placeholder with the watch's currently displayed IP. The
script reports only selected numeric geometry and fixed categorical
states, no network IP, serial, PARTUUID, raw system output, phone
credentials or raw partition data. Its private local JSON file is
created mode 0600 and refuses to overwrite existing evidence
**before** attempting another SDB request.

If the target is unreachable or metadata inaccessible, the answer is
**unknown**. Do not try root, reset, `/dev` raw reads, or NetOdin to
fill that gap. Preserved outputs are better than repeating a failed
batch.

The tool's safety flags remain
`authentic_samsung_pit_obtained=false`,
`signed_stock_images_obtained=false`,
`all_21_partition_geometry_established=false`,
`stock_recovery_proven=false`,
`custom_boot_accepted=false`,
`firmware_written=false`, `flash_allowed=false`,
`result=NO_GO`.

**Next true blocker after this optional read:** a lawfully and freely
obtainable **authenticated full SM-R840X** OEM stock rescue package
for the installed `R840XXXU1AUA2` or a demonstrably compatible,
signed successor; a trustworthy PIT/partition image comparison,
bootloader signing/rollback evidence; and verified restore on
sacrificial matching hardware. The measured numeric sectors, even
if complete, are *not* enough to justify a flash or retail cross-flash.
