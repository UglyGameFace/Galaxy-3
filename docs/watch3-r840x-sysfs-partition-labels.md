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

## Physical result: October 27 wildcard SDB read was inconclusive

On the real working SM-R840X, the owner already ran the original
wildcard probe and received **`SYSFS_READ_UNAVAILABLE_OR_UNSUPPORTED_GLOB`**;
`owner_watch_sysfs_observed=false`, `report=null`. The existing
collector merged shell refusal, timeout, denied path and missing
glob matches into that same generic result. **The output does not
prove the shell failed to expand `*`, that sysfs lacks a partition
label, or that the actual kernel has no partition metadata.**

### Non-wildcard follow-up for Android/Termux

After the corresponding PR passes CI and is merged to `main`,
use **only** the new opt-in `--fixed-paths` mode. It makes three
explicit, bounded SDB shell text-only requests:

```text
cat /sys/class/block/mmcblk0p1/uevent
cat /sys/class/block/mmcblk0p20/uevent
cat /sys/class/block/mmcblk0p21/uevent
```

There are **no wildcards**, no arbitrary paths, and no
`/dev/mmcblk0p*` file reads. This is deliberately **three
probes, not an enumeration of all 21 partitions**. Numbers 1, 20
and 21 are chosen as a minimal test of whether direct sysfs
access works. Their roles are **not assumed**.

From normal Tizen on your existing trusted LAN/hotspot (not
Wireless Download), use the **currently displayed watch IP**.
The address `10.0.0.65` from previous runs must not be assumed
still correct.

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_partition_sysfs_readonly.py \\
  --watch-ip WATCH_CURRENT_WIFI_IP --fixed-paths
cat ~/watch3-r840x-sysfs-fixed-three.json
```

The original `~/watch3-r840x-sysfs-partition-names.json`
is retained unchanged for provenance. The new fixed-only
report is `~/watch3-r840x-sysfs-fixed-three.json` and is
created in private mode `0600` without overwriting any
prior report. It never outputs raw sysfs strings or PARTUUIDs.

What the NEW report can discriminate:

- `SDB_SHELL_CLOSED_OR_REFUSED`,
  `SDB_SHELL_TIMED_OUT` and `SDB_TRANSPORT_UNREACHABLE`
  mean shell/service/transport limitations, **not**
  unavailability of physical partition names.
- `SYSFS_PATH_OR_COMMAND_NOT_FOUND`, `SYSFS_ACCESS_DENIED`
  and `SYSFS_EMPTY_SHELL_OUTPUT` mean the specific text
  request was denied, absent or returned no content. Do
  **not** escalate privileges.
- `UEVENT_READABLE_BUT_PARTNAME_ABSENT` is a meaningful
  kernel metadata result: sysfs may expose the partition
  number without a GPT volume label.
- `PARTNAME_FIELD_OBSERVED` means **only the specified
  index** returned a correctly matching, bounded uevent
  containing a `PARTNAME` key. The field is
  privacy-filtered against a small set of recognized labels.
  It does **not** authenticate Samsung PIT or any
  recovery/flash compatibility.

Linux's partition `uevent` exporter adds `PARTN`, and
**only adds `PARTNAME` when volume-name metadata exists**.
See upstream [Linux block/partitions/core.c](
https://github.com/torvalds/linux/blob/master/block/partitions/core.c).
Therefore, even a successful `uevent` read without `PARTNAME`
must not be reported as a confirmed partition role.

The read-only safety result remains **`NO_GO`** for any
firmware action, root, Odin session, PIT request, stock rescue,
retail cross-flash or alternate UgLy|OS boot.

## Physical follow-up: October 27 fixed-path SDB transport failures

The owner ran the three exact sysfs `uevent` reads in normal Tizen:

- `mmcblk0p1/uevent`: `SDB_TRANSPORT_UNREACHABLE`.
- `mmcblk0p20/uevent`: `SDB_TRANSPORT_UNREACHABLE`.
- `mmcblk0p21/uevent`: `SDB_TRANSPORT_UNREACHABLE`.

The preserved output file was
`~/watch3-r840x-sysfs-fixed-three.json`. It recorded
`readable_uevent_files=0`, `partname_fields_observed=0`,
`owner_watch_sysfs_observed=false` and
`FIXED_SYSFS_NO_VALID_TEXT_OBSERVATIONS`.

**Do not conclude any of those three partitions are absent or have
no `PARTNAME`.** The existing SDB collector maps multiple
`OSError`/timeout failures, including a socket connect failure
and failures during later SDB activity, into that single
`SDB_TRANSPORT_UNREACHABLE` category. It does **not** establish
which connection stage failed. Repeating three fixed file probes
while disconnected would not improve the evidence.

### Next smallest diagnosis: one TCP/SDB handshake, no shell at all

A new opt-in `--connection-only` mode uses the existing exact
watch-side private IP, sends only the ordinary SDB connection hello
on TCP **26101**, and **does not open a Tizen shell, request any
sysfs file, inspect raw partition bytes, interact with NetOdin,
reboot the watch or change its settings**.

It produces a fresh private JSON report
`~/watch3-r840x-sdb-connection-redacted.json`, without the watch IP
or raw SDB response. It refuses to overwrite an existing file
*before* opening the network connection.

After merging the corresponding PR and confirming the watch is in
**normal Tizen** with Wi-Fi debugging enabled and joined to your
phone hotspot/trusted local network, read the watch's **currently
displayed IP** and run once:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only origin main
python tools/watch3_r840x_partition_sysfs_readonly.py \\
  --watch-ip WATCH_CURRENT_WIFI_IP --connection-only
cat ~/watch3-r840x-sdb-connection-redacted.json
```

Do **not** use a prior `10.0.0.x` address from logs by assumption.
If you run a VPN on the phone, make sure ordinary phone-to-watch
private-network traffic is permitted. We already know the watch
previously returned CSC `PAP` over SDB at a different time;
that success **does not prove current Wi-Fi reachability**.

The categorical states mean:

| Result | What it really establishes |
| --- | --- |
| `TCP_PORT_REFUSED` | The supplied host refused port 26101. Debugging may be off, service absent, stale IP or wrong host. |
| `TCP_CONNECT_TIMED_OUT` | No completed TCP connection in 4 seconds; check currently shown watch IP, Wi-Fi/hotspot/VPN/firewall. |
| `TCP_NETWORK_UNREACHABLE_OR_BLOCKED` | Local TCP connection failed for a different network reason, but no watch identity or sysfs state was established. |
| `SDB_HANDSHAKE_TIMED_OUT` | TCP worked, but normal SDB handshake timed out. |
| `SDB_HANDSHAKE_IO_FAILURE` | TCP connected but dropped or failed during SDB handshake. |
| `SDB_AUTHORIZATION_OR_LOCAL_KEY_UNAVAILABLE` | Watch may request authorization or local RSA key material may be unavailable; do not share keys or tokens. |
| `SDB_HANDSHAKE_PROTOCOL_FAILED` | TCP connected but expected SDB handshake did not complete. |
| `SDB_HANDSHAKE_COMPLETE_NO_SYSFS_READ` | A host at that IP responded to SDB. **No Tizen shell, sysfs label or partition was tested**; not a guarantee of the device's full identity. |

If this proves the network/SDB is healthy, the **separate**
`--fixed-paths` text-only test can be considered with a **new**
`--report` filename, never by deleting or overwriting the original.
If the handshake fails, do not run any more sysfs probes or escalate
to privileged SDB/Odin; resolve ordinary IP, Wi-Fi and debugging
first. The absence of labels remains **unresolved**, not negative.

All statuses preserve `NO_GO` for flashing, stock recovery,
custom kernel acceptance, or partition modification.

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
  old report was **inconclusive across several shell and path
  failure types**, not proof that wildcard expansion specifically
  failed. Prefer the bounded explicit-path read-only diagnostic
  described above; never fall back to raw devices or Odin.
- All reports retain `NO_GO`, `stock_recovery_proven=false`,
  `flash_allowed=false`, `bootloader_acceptance_proven=false`.

**Precise engineering value:** an observed label like `param`,
`recovery`, `kernel` or `boot` could help map known
public Samsung bootloader vulnerabilities to an actual partition
**name**, rather than inventing `mmcblk0pN` roles. This must
**never** become an instruction to overwrite it. An authentic
full model-matching OEM recovery archive and verified reversible
return-to-stock are still mandatory before any boot experiment.
