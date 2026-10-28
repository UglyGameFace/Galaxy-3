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


## Owner's physical seven-scalar result and p10-only follow-up (October 27, 2026)

The owner ran the original tool on a normally booted **SM-R840X** and
provided the redacted JSON, saved **locally** as
`~/watch3-r840x-critical-geometry-redacted.json`:

- The whole `mmcblk0` device reported **15,269,888** Linux 512-byte
  sectors. This is kernel metadata, not an authenticated Samsung PIT.
- `mmcblk0p13` (`boot`): start **169,984**, size **36,864** sectors,
  exclusive end **206,848** (18 MiB).
- `mmcblk0p14` (`recovery`): start **206,848**, size **36,864**
  sectors, exclusive end **243,712** (18 MiB). These two observed
  ranges are adjacent, not overlapping.
- `mmcblk0p10` (`param`): **REPORTED_FIELD_UNAVAILABLE**. This
  original summary collapses the two input keys and discards their
  categorical transport/sysfs errors. It cannot establish whether
  `start`, `size`, or both failed. It does **not** mean the partition
  is absent: the earlier actual 21/21 `uevent` report observed
  `p10=param`.
- Original report: `PARTIAL_OR_UNAVAILABLE_KERNEL_SECTOR_FIELDS`,
  `result=NO_GO`; no PIT/Odin/raw block/write. A partial report
  deliberately cannot assert the three-partition non-overlap result
  because the p10 sector range is unknown.

The existing shared `collect()` already maps SDB and sysfs failures
into **private-safe categorical errors**, but the original geometry
report didn't retain those categories. The small **`--param-only`**
mode reuses that collector and asks for **exactly two** existing
hardcoded `cat /sys/class/block/mmcblk0p10/{start,size}` commands.
It does not reread the disk, boot or recovery fields, request PIT,
try root, or run a shell command supplied by the user.

After its GitHub CI passes **and the change is merged**, the optional
owner-operated Android/Termux diagnostic is:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_critical_sysfs_geometry.py \
  --watch-ip WATCH_CURRENT_WIFI_IP --param-only
cat ~/watch3-r840x-param-geometry-diagnostic-redacted.json
```

Use the **currently displayed** watch Wi-Fi IP on the same trusted
network, with existing authorized SDB. The tool will fail safely if
the separate diagnostic report already exists, before contacting
the watch. Never delete or overwrite the original seven-scalar JSON
just to rerun it. If SDB is unavailable, stop; no fallback to Odin,
`dd`, privilege escalation, alternate paths or repeated retries.

The follow-up JSON contains a bounded category **per p10 field**
(e.g. `SYSFS_ACCESS_DENIED`, `SYSFS_PATH_OR_COMMAND_NOT_FOUND`,
`SDB_TRANSPORT_UNREACHABLE`, `SDB_PROTOCOL_OR_READ_FAILURE`,
`SDB_SHELL_CLOSED_OR_REFUSED`, or an observed numeric value).
It never saves raw shell output or a private IP. If both numbers are
obtained it reports a **p10 kernel sector candidate** from a
*different snapshot*: do not silently combine it with the earlier
disk/boot/recovery readings as one atomic measurement. No authentic
PIT/signing/stock rescue/custom boot is established, so `NO_GO` remains.
