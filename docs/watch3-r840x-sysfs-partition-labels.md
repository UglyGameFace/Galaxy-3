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

## Physical connection-only result: TCP failed before SDB (October 27)

The owner ran `--connection-only` from Android/Termux with a previously
used private hotspot IP and provided the complete sanitized report:

- `state=TCP_NETWORK_UNREACHABLE_OR_BLOCKED`
- `tcp_connected=false`
- `sdb_handshake_completed=false`
- `remote_device_identity_verified=false`
- `owner_watch_sysfs_observed=false`
- `source_path_expression=[]`, and `report=null`
- `pit_requested=false`, `watch_write_performed=false`,
  `firmware_written=false`, `flash_allowed=false`

**Meaning:** the code reached the phone's TCP connect attempt and received
a general OS-level `OSError` before a socket connected. Neither
SDB authorization, sysfs files, partition names nor the watch's
actual presence at that IP was tested. **Do not confuse this with a
locked CSC, absent partition label or a bootloader issue.** The
earlier genuinely observed active CSC `PAP` from a different
working SDB session remains valid historical evidence.

### Non-invasive network recovery checklist, in order

1. On the **watch** in normal Tizen, look at current Wi-Fi network,
   connection state and its **currently displayed device IP**.
   A previously working hotspot IP is *not* permanent. Check
   Tizen Debugging remains enabled; do not enter Wireless Download,
   reset or flash.
2. On the **phone**, confirm the **same trusted local network**
   and that the watch currently appears as a client under
   Mobile Hotspot's connected-device view, if using your phone
   as the hotspot. If connected to a normal router, both
   devices must use the same LAN with client-to-client routing
   permitted. Hotspot client association alone does not prove
   phone-to-client socket reachability.
3. If using a phone **VPN**, allow local-network traffic or
   temporarily disable that VPN only for this ordinary
   local diagnostic, then restore it afterwards. Avoid guessing
   a new `10.0.0.x` IP or scanning other clients.
4. **Only after the current watch IP is confirmed**, run
   **one** normal SDB handshake check with a **new local report**
   filename, preserving the original failure report:

   ```sh
   cd ~/Galaxy-3 && git switch main && git pull --ff-only
   python tools/watch3_r840x_partition_sysfs_readonly.py \\
     --watch-ip WATCH_CURRENT_WIFI_IP --connection-only \\
     --report ~/watch3-r840x-sdb-connect-after-network-check.json
   cat ~/watch3-r840x-sdb-connect-after-network-check.json
   ```

5. If you cannot route to the watch from a **phone hotspot**,
   use a shared trusted Wi-Fi router for phone and watch when
   convenient. Do not replace Tizen or experiment with NetOdin
   to fix an ordinary routing problem.

### Improved categorization for a follow-up connection check

The new script preserves the original `state` field and adds a
fixed non-sensitive `tcp_error_category` to distinguish
local errors. The **original** failure JSON cannot retroactively
tell us its OS errno; no raw exception, watch IP, port scan,
serial, private keys or networking identifiers are saved.

| `tcp_error_category` | What the phone OS reported, not what happened inside the watch |
| --- | --- |
| `PHONE_HAS_NO_ROUTE_TO_TARGET` | No phone route for the selected target; check local Wi-Fi/hotspot routing and VPN |
| `TARGET_HOST_UNREACHABLE_ON_CURRENT_NETWORK` | Current network could not reach target; check watch connection and **current IP** |
| `PHONE_NETWORK_INTERFACE_DOWN` | Local network interface unavailable |
| `ANDROID_OS_OR_VPN_SOCKET_POLICY_BLOCKED` | OS refused creating/using the socket; local network policy may be involved |
| `LOCAL_SOURCE_ADDRESS_NOT_AVAILABLE` | Local source address unavailable |
| `TARGET_OR_INTERMEDIARY_REFUSED_PORT` | A peer actively refused SDB port 26101; debugging or IP still needs verification |
| `TCP_CONNECT_TIMEOUT_NO_REPLY` | TCP connection never completed before application timeout |
| `OTHER_PHONE_SIDE_CONNECT_ERROR` | No reliable subtype; do not infer a specific root cause |
| `NOT_APPLICABLE` | No additional phone-level connect error was present |

**No automatic retry, scanning, other port access or watch writes** are
added. The report remains private and exclusive. If a TCP/SDB
handshake eventually succeeds, consider only the previously
documented *separate* text-only `--fixed-paths` sysfs probe,
with a new output path. Stock recovery and bootloader GO
remain **UNPROVEN** regardless of network outcome.

## Physical recheck: TCP and SDB handshake recovered (October 27)

The owner ran a separate **connection-only** diagnostic from Android/Termux
against the watch-side hotspot address `10.54.86.131`, while in normal Tizen.
The sanitized owner-provided file

`~/watch3-r840x-sdb-connect-after-network-check.json`

establishes:

- `state=SDB_HANDSHAKE_COMPLETE_NO_SYSFS_READ`
- `tcp_connected=true` and `sdb_handshake_completed=true`
- `transport_diagnosis_only=true`,
  `probe_mode=SINGLE_SDB_TCP_HANDSHAKE_NO_SHELL_OR_SYSFS`
- `remote_device_identity_verified=false`,
  `owner_watch_sysfs_observed=false`,
  `source_path_expression=[]`, `report=null`
- `raw_partition_bytes_read=false`, `pit_requested=false`,
  `odin_session_started=false`, `watch_write_performed=false`,
  `stock_recovery_proven=false`, `flash_allowed=false`.

**Critical sequencing detail:** the user then tried to run that **same
connection-only check with the same `--report` path** and received
`PARTITION_PROBE_ERROR: REPORT_ALREADY_EXISTS`. The subsequent
`cat` printed the pre-existing **successful** JSON. The error came
from the tool's *local exclusive-output preflight*, **before any new
SDB connection**. It is **not** a watch failure, new handshake failure,
or proof that partition labels were collected by that second command.

The prior `TCP_NETWORK_UNREACHABLE_OR_BLOCKED` diagnostic described an
**earlier network state**. That failure and the newly proven successful
SDB handshake are separate dated observations, **not conflicting
outcomes of the same attempt**. The IP still does not cryptographically
establish the remote watch's identity, although the owner's normal
Tizen/hotspot observation makes it the intended target.

### Only meaningful next observation: the existing three literal sysfs reads

There is **no reason to repeat the handshake-only probe**, debug
the old network failure, delete an existing report, add new protocol
variants or send Odin commands. The already merged
`--fixed-paths` implementation can now be exercised exactly once:

```sh
cd ~/Galaxy-3 && git pull --ff-only
out="$HOME/watch3-r840x-sysfs-fixed-$(date +%Y%m%d-%H%M%S)-$.json"
python tools/watch3_r840x_partition_sysfs_readonly.py \\
  --watch-ip 10.54.86.131 --fixed-paths --report "$out"
cat "$out"
```

**Only use `10.54.86.131` if it is still the current watch-side
IP** on the trusted network. Use a distinct local file name for each
observation. The script reads exactly three ordinary kernel sysfs
`uevent` text pseudo-files for **p1, p20, p21**; no PIT dump,
partition contents, stock image or flashing. It can still fail at the
*shell service* stage even after a successful SDB handshake.
This probe **later succeeded** on the owner's watch; see the new dated observation below.

A useful result will be a categorical per-path status:
`PARTNAME_FIELD_OBSERVED`, `UEVENT_READABLE_BUT_PARTNAME_ABSENT`,
`SDB_SHELL_CLOSED_OR_REFUSED`, `SDB_SHELL_TIMED_OUT`,
`SYSFS_PATH_OR_COMMAND_NOT_FOUND`, or other fail-closed status.
**Do not infer physical roles for p1/p20/p21**, or declare the
remaining 18 partition names known from a three-file sample.
A successful sysfs metadata sample remains `NO_GO` for all
firmware modifications and alternate boot.

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

## Verified October 27 physical result: three literal sysfs paths SUCCEEDED

Owner used the normal Tizen Wi-Fi debugging connection and the existing
`--fixed-paths` mode on physical **SM-R840X**, installed
`R840XXXU1AUA2`, with independently observed active CSC `PAP`.

Sanitized private Termux report:
`~/watch3-r840x-sysfs-fixed-20261027-195942-30781.json`.

Actual JSON evidence:
- `state=FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED`
- `owner_watch_sysfs_observed=true`
- `probe_mode=THREE_EXPLICIT_TEXT_PATHS_NO_WILDCARD`
- `tested_partition_indices=[1,20,21]`
- `readable_uevent_files=3`, `partname_fields_observed=3`
- `mmcblk0p1`: `PARTNAME_FIELD_OBSERVED`, **`unclassified`**
  according to our privacy-safe allowlist. This means an actual
  `PARTNAME` *was* present but its raw value was intentionally not
  reported. It does NOT mean the kernel named it literally
  `unclassified` or that the partition has no purpose.
- `mmcblk0p20`: `PARTNAME_FIELD_OBSERVED`, **`rootfs`**
- `mmcblk0p21`: `PARTNAME_FIELD_OBSERVED`, **`user`**
- `remaining_partition_indices_not_tested=[2..19]` and
  `full_partition_layout_proven=false`.

This is independent physical label metadata. In particular,
`mmcblk0p20=rootfs` is no longer merely a block-size-matching
hypothesis. However, `PARTNAME` is not proof of exactly which
filesystem is mounted from a partition, the signed R840X PIT, kernel
and bootloader locations, rollback compatibility, or a stock rescue.

The report also explicitly confirms
`raw_partition_bytes_read=false`, `pit_requested=false`,
`odin_session_started=false`, `watch_write_performed=false`,
`stock_recovery_proven=false`,
`bootloader_acceptance_proven=false`, `flash_allowed=false` and
`result=NO_GO`.

### New bounded follow-up: three *opt-in* batches for remaining p2–p19

**Only after the corresponding pull request's mock-SDB CI passes and
its changes are merged to main**, use `--remaining-batch` to
request six literal, distinct sysfs `uevent` text paths at a time:

| Batch | Exact indices | Total paths |
| --- | --- | --- |
| 1 | `mmcblk0p2` through `mmcblk0p7` | 6 |
| 2 | `mmcblk0p8` through `mmcblk0p13` | 6 |
| 3 | `mmcblk0p14` through `mmcblk0p19` | 6 |

The original **p1/p20/p21 are not reread**, and the older
wildcard/glob command is **not attempted**. All 18 commands are
hardcoded in the SDB operation allowlist. They contain only a
literal `cat /sys/class/block/mmcblk0pN/uevent`. No
`/dev/mmcblk0*` block-device accesses, root, arbitrary shell
commands, SSH, update, PIT request, bootloader session, CSC change
or partition writes are possible through this mode.

On your Android phone, with the watch booted normally into Tizen
and its **currently displayed watch Wi-Fi IP** (not an old/stale
address), run the first batch:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
out="$HOME/watch3-r840x-sysfs-p2-p7-$(date +%Y%m%d-%H%M%S)-$$.json"
python tools/watch3_r840x_partition_sysfs_readonly.py \
  --watch-ip WATCH_CURRENT_WIFI_IP \
  --remaining-batch 1 --report "$out"
cat "$out"
```

Then run **batch 2** with `--remaining-batch 2` and a
**different report name** if batch 1 actually returned useful
`PARTNAME_FIELD_OBSERVED` entries. Run **batch 3** similarly
only if connection and transport remain reliable. Do not
blindly rerun multiple batches when the first gives
`SDB_TRANSPORT_UNREACHABLE`, `SYSFS_ACCESS_DENIED`,
shell refusal or timeouts.

This is normal Tizen SDB read-only work, **not an Odin session**.
No raw unknown partition labels, UUID, IP, serial, or privileged
image contents are saved. Known public partition names pass a
fixed allowlist; unknown labels are `unclassified` and may
require separate future source-grounded research. Any single
batch report still states `full_partition_layout_proven=false`,
even if all six requested text files are readable. Absent/missing
`PARTNAME` means an unknown role, not a missing partition.

### Explicit next gate after three physical batches

If all three owner reports succeed, a future **offline-only**
cross-report reconciliation can combine and check *observed*
indices **1–21** with the original three-file report. That
must preserve each file's provenance, reject duplicates and
conflicting labels, and distinguish any `unclassified` and
`not_exported` entries. It must never claim this text mapping
is an authenticated Samsung PIT, complete recovery image, verified
bootloader unlock, or safe alternate UgLy|OS boot.

**Status: NO-GO for all watch modification and flashing.**


## Physical owner result: batches 2 and 3 both succeeded (October 27, 2026)

After the proven `p1/p20/p21` read, the owner ran the preexisting
`--remaining-batch 2` and `--remaining-batch 3` with their current
watch-side private IP from Android/Termux. The owner shared both
complete **privacy-filtered JSON summaries** in chat. No private
network address or unsanitized sysfs records are committed here.

Both batches report:
- `FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED`, `owner_watch_sysfs_observed=true`
- **6/6** readable explicitly selected `uevent` text files and **6/6**
  kernel `PARTNAME` fields per batch
- `raw_partition_bytes_read=false`, `pit_requested=false`,
  `odin_session_started=false`, `watch_write_performed=false`,
  `stock_recovery_proven=false`, `bootloader_acceptance_proven=false`,
  `flash_allowed=false`, `result=NO_GO`.

| Numbered eMMC partition | Sanitized kernel label | Direct source |
| --- | --- | --- |
| `mmcblk0p1` | `unclassified` | earlier original fixed group |
| `mmcblk0p2`–`p7` | **No report supplied in this evidence** | batch 1 not yet reconciled |
| `mmcblk0p8` | `unclassified` | batch 2 |
| `mmcblk0p9` | `unclassified` | batch 2 |
| `mmcblk0p10` | **`param`** | batch 2 |
| `mmcblk0p11` | **`up_param`** | batch 2 |
| `mmcblk0p12` | `unclassified` | batch 2 |
| `mmcblk0p13` | **`boot`** | batch 2 |
| `mmcblk0p14` | **`recovery`** | batch 3 |
| `mmcblk0p15` | `unclassified` | batch 3 |
| `mmcblk0p16` | `unclassified` | batch 3 |
| `mmcblk0p17` | `unclassified` | batch 3 |
| `mmcblk0p18` | **`csc`** | batch 3 |
| `mmcblk0p19` | `unclassified` | batch 3 |
| `mmcblk0p20` | **`rootfs`** | earlier original fixed group |
| `mmcblk0p21` | **`user`** | earlier original fixed group |

**Combined available owner-reported evidence: 15 distinct readable
positions**, seven clear public labels
(`param`, `up_param`, `boot`, `recovery`, `csc`, `rootfs`,
`user`), eight `unclassified` positions, and **six positions p2–p7
not established by the reports shared so far**. The word
`unclassified` is **our privacy filter**, not the literal kernel
PARTNAME or evidence a partition lacks a name. The original
`remaining_partition_indices_not_tested` list is *relative to a
single report's selected six indices*; it is not a global running
coverage result.

This is especially helpful for the original Samsung Watch3
July-2021 `param`/`recovery` bootloader CVE investigation:
these names now map to **actual kernel-exported owner-watch labels**
at p10 and p14 respectively. **It does not prove CVE exploitability**,
raw partition contents, Samsung PIT correspondence, Samsung signing
rules, custom kernel acceptance, or safe recovery. Neither name
justifies reading/writing raw `/dev/mmcblk0p10` or
`/dev/mmcblk0p14`, and the watch's stock system must remain intact.

### Reconcile existing reports OFFLINE, without contacting the watch

To avoid double-counting or treating each batch's local `not_tested`
array as a global list, the new
`tools/watch3_r840x_merge_sysfs_reports_offline.py` accepts only
**already-saved redacted JSON reports** from the original fixed
group and optional numbered batches. It revalidates version, model,
build, CSC, exact six or three source paths, mode, indices, per-file
counts, labels and fixed `NO_GO` flags. It refuses duplicate input
bytes or unrecognized values. It makes **zero SDB, Odin or network
requests** and never opens any block devices. Its JSON report
contains only the sanitized role labels and SHA256s of its input
JSON files (local identity, **not** watch attestation).

On the Android phone, if the same earlier reports still exist in
Termux `$HOME`, combine them with:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_merge_sysfs_reports_offline.py \
  --fixed "$HOME/watch3-r840x-sysfs-fixed-20261027-195942-30781.json" \
  --batch2 "$HOME/watch3-r840x-batch2-1793148619-7379.json" \
  --batch3 "$HOME/watch3-r840x-batch3-1793148623-7379.json" \
  --output "$HOME/watch3-r840x-partition-coverage-15-of-21.json"
cat "$HOME/watch3-r840x-partition-coverage-15-of-21.json"
```

These filenames come from the earlier owner reports, **not from
files accessible to the research environment**; if one is absent,
do not invent it. The offline command will refuse absent input.
An existing output is never overwritten; use a new filename for
subsequent evidence.

Once an independently observed **batch 1, p2–p7** sanitized report
is available, add `--batch1 /actual/saved/batch1-report.json`
and change the output filename. If those six sysfs text reads are
available, the reconciler can record **21/21 readable partition text
records**. It will *still* report
`samsung_pit_authenticated=false`,
`partition_offsets_sizes_verified=false`,
`stock_recovery_proven=false`,
`flash_allowed=false`, and `NO_GO`.
It does not have access to a signed Samsung PIT, any raw partition
bytes, or a recovery method.

**Next low-risk hardware question, only if batch 1 does not already
have a preserved report:** the six existing explicitly allowlisted
read-only sysfs `uevent` paths for p2–p7. Do not repeat batches
2 or 3, use the old wildcard probe, or experiment with
NetOdin, modified CSC, boot/recovery/param partitions or retail firmware.

## Physical Batch 1 received: all 21 sysfs text positions now have reported observations (October 27)

The owner has now supplied the previously missing full sanitized **batch 1**
JSON directly from their **physical SM-R840X**, in normal Tizen over
authenticated read-only SDB. Its local private report filename is:

`~/watch3-r840x-batch1-1793149368-7379.json`

This is a path reported by the owner, **not a file in this repository or
a file downloaded by CI**. The owner ran the existing
`tools/watch3_r840x_partition_sysfs_readonly.py --remaining-batch 1`
with a time-stamped, exclusive local output. Its **verbatim report
contract**, transcribed without claiming independently obtained raw
kernel bytes:

- `schema=uglyos-r840x-sysfs-partition-names-v1`
- `device_target=SM-R840X`,
  `installed_build_recorded=R840XXXU1AUA2`,
  `active_csc_recorded=PAP`
- `state=FIXED_SYSFS_PARTNAME_FIELDS_OBSERVED`,
  `owner_watch_sysfs_observed=true`
- `probe_mode=SIX_EXPLICIT_TEXT_PATHS_BATCH_1_NO_WILDCARD`,
  `remaining_batch_number=1`
- `tested_partition_indices=[2,3,4,5,6,7]`
- `readable_uevent_files=6`, `partname_fields_observed=6`
- all six entries `status=PARTNAME_FIELD_OBSERVED`
- `p2=unclassified`, `p3=unclassified`, `p4=unclassified`,
  **`p5=module`**, `p6=unclassified`, **`p7=steady`**
- `prior_owner_observations_not_repeated=[1,20,21]`;
  the established original fixed group was not run again
- `raw_partition_bytes_read=false`, `pit_requested=false`,
  `odin_session_started=false`, `watch_write_performed=false`,
  `stock_recovery_proven=false`,
  `bootloader_acceptance_proven=false`, `flash_allowed=false`,
  `result=NO_GO`.

**Important correction to shorthand:** `unclassified` is the
*probe's privacy-preserving replacement* for an observed but
unknown/unapproved `PARTNAME` string. It does **not** mean the
kernel literally emitted `PARTNAME=unclassified`, that the
partition lacks a name, or that the partition has no role. The
tool intentionally does not expose the original unknown label.

### Evidence from all four physically read groups

These entries are transcribed from **four separately owner-supplied**
redacted reports: the original p1/p20/p21 fixed group and the
already-documented physical batches 2 and 3, plus the new batch 1.
They have not yet been individually loaded together and checked by
the offline reconciliation CLI on the owner's phone.

| Position | Privacy-filtered `PARTNAME` | Owner report |
| --- | --- | --- |
| `mmcblk0p1` | `unclassified` | original fixed |
| `mmcblk0p2` | `unclassified` | batch 1 |
| `mmcblk0p3` | `unclassified` | batch 1 |
| `mmcblk0p4` | `unclassified` | batch 1 |
| `mmcblk0p5` | **`module`** | batch 1 |
| `mmcblk0p6` | `unclassified` | batch 1 |
| `mmcblk0p7` | **`steady`** | batch 1 |
| `mmcblk0p8` | `unclassified` | batch 2 |
| `mmcblk0p9` | `unclassified` | batch 2 |
| `mmcblk0p10` | **`param`** | batch 2 |
| `mmcblk0p11` | **`up_param`** | batch 2 |
| `mmcblk0p12` | `unclassified` | batch 2 |
| `mmcblk0p13` | **`boot`** | batch 2 |
| `mmcblk0p14` | **`recovery`** | batch 3 |
| `mmcblk0p15` | `unclassified` | batch 3 |
| `mmcblk0p16` | `unclassified` | batch 3 |
| `mmcblk0p17` | `unclassified` | batch 3 |
| `mmcblk0p18` | **`csc`** | batch 3 |
| `mmcblk0p19` | `unclassified` | batch 3 |
| `mmcblk0p20` | **`rootfs`** | original fixed |
| `mmcblk0p21` | **`user`** | original fixed |

This yields **21/21 distinct physically observed readable kernel
`uevent` files**, with **21/21 `PARTNAME` fields present** across
four separate owner sessions, **9 recognized public names**
(`module`, `steady`, `param`, `up_param`, `boot`,
`recovery`, `csc`, `rootfs`, `user`) and **12 redacted
`unclassified` names**. These counts are derived by taking the
union of the four owner-reported disjoint index ranges, not from
the original per-batch `remaining_partition_indices_not_tested`
lists. The signed Samsung PIT, raw contents, secure boot chain,
partition geometry, restoration and model-specific retail
cross-flash compatibility are **NOT** established.

### Next step: reconcile already-existing JSON files OFFLINE

The independently implemented `watch3_r840x_merge_sysfs_reports_offline.py`
tool is **already on `main`**. Use it with all **four preserved
Termux report files**. It performs **zero network/SDB/Watch3
communication**. It validates per-report schema, exact fixed
source paths and mode, all expected indices, fail-closed
NO-GO flags, counts and SHA-256 local-file identity:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_merge_sysfs_reports_offline.py \
  --fixed "$HOME/watch3-r840x-sysfs-fixed-20261027-195942-30781.json" \
  --batch1 "$HOME/watch3-r840x-batch1-1793149368-7379.json" \
  --batch2 "$HOME/watch3-r840x-batch2-1793148619-7379.json" \
  --batch3 "$HOME/watch3-r840x-batch3-1793148623-7379.json" \
  --output "$HOME/watch3-r840x-all21-sysfs-evidence.json"
cat "$HOME/watch3-r840x-all21-sysfs-evidence.json"
```

All source filenames are from owner-supplied prior reports, **not
independently available in the assistant's current environment**.
If an input is missing or a local output already exists, the
offline script will safely refuse; do not delete the original
evidence. Choose a fresh `--output` filename if necessary.

**Historical note (superseded by physical owner-run merge below):**
At this stage, all four local files had not yet been reconciled.
The owner has **now run** the actual merge on the Android phone and supplied
its sanitized result. Synthetic CI alone never verified the actual files.
The recorded file digests are **local identity only**, not a signed
hardware attestation.

**Hardware gates unchanged:** `NO_GO` for Odin session-start,
PIT transfer, boot/recovery/param writes, unsigned kernel boot
and retail firmware conversion. Kernel `PARTNAME` metadata
is neither an authentic Samsung-signed PIT nor a full OEM
stock recovery pathway. Do **not** rerun batches 1/2/3
or perform extra physical probes for this task.



## Completed owner-run offline 21/21 merge (October 27, 2026)

**This is no longer a pending command.** The owner ran the existing
`tools/watch3_r840x_merge_sysfs_reports_offline.py` in Android Termux
with all **four preserved** local reports after updating to
`main=e39c2807f8eaca806561f3a27eedbaf2ee989192`. It produced
`~/watch3-r840x-all21-sysfs-evidence.json` with:

- `schema=uglyos-r840x-physical-sysfs-evidence-merge-v1`
- `state=ALL_21_KERNEL_TEXT_PARTNAME_FIELDS_RECONCILED`
- `readable_uevent_count=21` and `partname_field_count=21`
- `recognized_public_label_count=9`, `redacted_unclassified_indices`
  `[1,2,3,4,6,8,9,12,15,16,17,19]`
- `not_in_supplied_reports=[]`
- `source_kind=OWNER_SUPPLIED_REDACTED_REPORTS_NOT_CRYPTOGRAPHICALLY_ATTESTED`
- `watch_contacted_by_merge=false`, `samsung_pit_authenticated=false`,
  `partition_offsets_sizes_verified=false`,
  `all_21_physical_partition_contents_read=false`,
  `signed_stock_image_verified=false`,
  `stock_recovery_proven=false`,
  `bootloader_accepted_custom_image=false`, `flash_allowed=false`,
  `result=NO_GO`.

The merge tool confirmed **all 21 indices** and their presence in the
four **distinct, already-saved** read-only SDB reports. It did not
contact the physical watch, use Odin, read raw partition bytes, or
calculate partition start/end sectors.

### Verified by the owner's on-phone schema checks, not Samsung signatures

The owner-supplied report contained these SHA-256s **for the original
local redacted JSON inputs** (not for raw sysfs files or firmware images):

| Report role | Recorded source indices | SHA-256 of local redacted input report |
| --- | --- | --- |
| fixed | 1, 20, 21 | `cdf428b879f43ddce0fbe7b323c6ea5852744b0e55591d30b9f60d3aa5f1e517` |
| batch1 | 2–7 | `6a719892c664fbbb5fccf7e31b9b81349cff4902dfe4abb71b48ff30bd5101a0` |
| batch2 | 8–13 | `d1bc08ef4d35a23c40eeeb5c49b716264ea3fd44e9d4a2988503599074a89c54` |
| batch3 | 14–19 | `2267efafa804c0676ccfe71687be8f7f783bcc86593e27874d81ff114aa46ca7` |

The merger checks the expected indices, recognized labels,
schema, `PAP` owner-CSC reference, recorded build, source paths and
`NO_GO` flags. These hashes make it possible to identify the four
source files again on the **owner's phone**, but cannot independently
attest the physical eMMC contents.

### Concrete kernel-reported partition-label evidence

| Numbered eMMC partition | Sanitized recognized `PARTNAME` | Interpretation limit |
| --- | --- | --- |
| `mmcblk0p5` | `module` | Kernel text label only |
| `mmcblk0p7` | `steady` | Kernel text label only |
| `mmcblk0p10` | `param` | Corresponds *by name* to the partition class in Samsung's 2021 bootloader advisory; not proof of vulnerability on this build |
| `mmcblk0p11` | `up_param` | No known verified boot behavior or image format |
| `mmcblk0p13` | `boot` | Named normal boot partition; **no contents, signing envelope or boot image packaging inspected** |
| `mmcblk0p14` | `recovery` | Recovery-labeled partition; **not verified to repair an unbootable watch** |
| `mmcblk0p18` | `csc` | Partition named CSC, distinct from the separately read active `PAP` text configuration |
| `mmcblk0p20` | `rootfs` | Kernel label confirms a rootfs-named partition, not a proven filesystem mount/dependency or restorable signed system image |
| `mmcblk0p21` | `user` | Kernel label only; no raw user data accessed |

The remaining **12** positions are `unclassified` **by our
privacy filter**, not by the kernel itself; the underlying `PARTNAME`
values were intentionally omitted from the saved reports.
Do **not** interpret these as empty, unused or unallocated partitions.
Other bootloader components may live in unclassified partitions,
eMMC hardware boot areas or RPMB; these were **not inspected**.

### What changes for Issue #47, and what does not

This new physical evidence **does resolve the old unknown index-to-name
relationship for nine common labels** and removes the need to repeat
any of the three read-only batches. We can now distinguish
`param`, `boot`, `recovery`, `csc` and `rootfs` in the
running kernel's text namespace, rather than guessing their positions.

However, `21/21` is the **coverage of privacy-filtered kernel
metadata**, **not** a complete authenticated Samsung PIT or a complete
partition-role map. It does not supply partition geometry (offsets
or block sizes), authentic BL/AP/CSC recovery package contents,
signature/anti-rollback acceptance or the ability to boot a custom
kernel safely.

**Next real research gate:** independently corroborated R840X
OEM stock restoration (firmware/provenance/PIT/rollback) and
Samsung boot-chain behavior **off-device**. Do not run NetOdin
`print-pit`/session start, read `/dev/mmcblk0pN`, flash retail
SM-R840 firmware, or change the active `PAP` CSC simply because
the labels are now known.

**NO-GO remains unchanged for all watch writes and installation.**
