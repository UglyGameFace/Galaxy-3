# SM-R840X R08: identify numbered partition LABELS without Odin/PIT

**Issue #47.** Installed `R840XXXU1AUA2`, observed active CSC
`PAP`. The owner's one physical SM-R840X is still working on
normal Tizen. No stock restore set or custom signed boot exists in
our evidence. **NO FLASHING.**

## New hypothesis after eliminating full-watch FUS, generic Recovery, and untrusted retail ZIPs

The actual physical watch reported **21 numbered eMMC partitions**
(`mmcblk0p1` through `mmcblk0p21`), but the ordinary unprivileged
SDB shell couldn't enumerate its by-name symlinks. Our existing
`--storage-only` collector reads `/sys/class/block/mmcblk0p20/uevent`
and `p21/uevent` only and may expose `PARTNAME=` fields on those
two partitions. **That does not establish the other 19 labels.**

Linux publishes partition *metadata* through sysfs `uevent` pseudo-files.
If a GPT-style `PARTNAME` is exported and allowed by the Tizen
shell, one fixed globbed **read-only** command could obtain labels for
the *already enumerated numbered eMMC partitions* without:
- requesting PIT through stateful 1024-byte NetOdin commands;
- opening any `/dev/mmcblk0*` block device or partition image;
- root, kexec, Samsung FOTA install, recovery/factory reset;
- changing original watch data, software, permissions or reboot mode.

This is a **hypothesis**, not yet verified on this SM-R840X. Samsung
could hide the `PARTNAME` fields or restrict this sysfs path;
the SDB shell may also reject glob expansion. An empty or blocked
response is a proper negative/unknown result and **not** permission
to escalate privileges or brute-force more paths.

## Exactly one new fixed operation

The opt-in script `tools/watch3_r840x_partition_sysfs_readonly.py`
uses the existing tested Android/Tizen SDB transport. The single
fixed command is:

```sh
cat /sys/class/block/mmcblk0p[0-9]*/uevent
```

The command is hardcoded in the SDB operation allowlist. It is
**never accepted as arbitrary user text**. A Tizen-specific
shell-style retry, if a stream is refused, repeats the **same
read-only command** on a fresh connection. The SDB collector's
existing 64KiB upper bound still applies, while the new parser
caps its data at **16 KiB**. It admits 21 partition indices at
most, rejects duplicates, conflicting `PARTN`/`DEVNAME`
fields, embedded binary/NUL, oversized or malformed records.
If shell globbing is unsupported, it reports inconclusive.

The privacy-filtered JSON emits only fixed `mmcblk0p1..p21`
**numbers** and a small allowlist of common public partition
role labels; all other labels become `unclassified`. It never
emits `PARTUUID`, serial numbers, MAC, IP, mount commands,
full raw sysfs content or signed kernel data. The local report
is created private (0600) and never overwritten. A prior
report is checked **before any network connection**.

## Run only after PR merge and green CI

On Android/Termux, watch in **normal Tizen** on an authorized trusted
Wi-Fi/hotspot with its actual currently displayed **watch IP**:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_partition_sysfs_readonly.py \
  --watch-ip WATCH_CURRENT_WIFI_IP
cat ~/watch3-r840x-sysfs-partition-names.json
```

**Replace** `WATCH_CURRENT_WIFI_IP` with the actual watch-side address.
No PC, paid firmware, root, USB cable or Wireless Download mode is used.
The report's contents are already sanitized for sharing. Do not
share any raw `/sys` files or unexpected private identifiers.

The same script has a strictly local synthetic test mode:
`--offline-sample local-fixture.txt`. It marks any such result as
`OFFLINE_SAMPLE_ONLY_NOT_A_REAL_WATCH_OBSERVATION` so fake CI
bytes can never be misrepresented as an owner-watch partition table.

## Interpreting results without inventing recovery

- `SYSFS_PARTITION_LABELS_OBSERVED`: a consistent subset of
  kernel-exported numbered partition labels was obtained. This
  is **useful physical partition-label evidence** but is not
  Samsung's authenticated PIT, signed firmware, rollback acceptance,
  backup or repair capability.
- `all_21_numbered_partitions_observed=false`: missing metadata
  must not be filled in by numbering guesses. The `missing` list
  is diagnostic, not evidence a partition is physically absent.
- `SYSFS_READ_UNAVAILABLE_OR_UNSUPPORTED_GLOB`:
  firmware or the SDB shell didn't expose this information.
  Do not try reading raw devices or live Odin as a workaround.
- All reports retain `NO_GO`, `stock_recovery_proven=false`,
  `flash_allowed=false`, `bootloader_acceptance_proven=false`.

**Precise engineering value:** an observed label like `param`,
`recovery`, `kernel` or `boot` could help map known
public Samsung bootloader vulnerabilities to an actual partition
**name**, rather than inventing `mmcblk0pN` roles. This must
**never** become an instruction to overwrite it. An authentic
full model-matching OEM recovery archive and verified reversible
return-to-stock are still mandatory before any boot experiment.
