# SM-R840X R08: read-only active CSC check from Tizen

**Issue:** [#47](https://github.com/UglyGameFace/Galaxy-3/issues/47)
**Installed build:** `R840XXXU1AUA2`.
**Owner-observed active CSC (2026-10-27): `PAP`, read from the physical watch via fixed-path read-only SDB.**
**Factory sales region / signed rescue firmware identity: still UNKNOWN.**

## Owner's physical SM-R840X result, October 27, 2026

**Evidence level: directly observed active CSC candidate on the actual
working demo watch.** After PR #84 merged and both Ubuntu fake-SDB CI
jobs passed, the owner ran the one-path Termux reader and supplied its
privacy-filtered JSON and console output:

- `CSC_STATE: ACTIVE_CSC_CANDIDATE_READ_FROM_EXACT_TIZEN_PATH`
- `CSC_CANDIDATE: PAP`
- `schema: uglyos-r840x-csc-fixed-sdb-read-v1`
- `status: CSC_CANDIDATE_FROM_OWNER_WATCH_FIXED_PATH`
- `model: SM-R840X`; `installed_build: R840XXXU1AUA2`
- `remote_path: /opt/system/csc-default/output/csc-active-customer.log`
- `observed_active_csc_candidate: PAP`
- `watch_write_performed=false`; `odin_session_started=false`;
  `pit_requested=false`; `firmware_written=false`;
  `full_stock_recovery_proven=false`; `flash_allowed=false`.

This confirms that **the actual SM-R840X exposes this same CSC file** and
that it contained exactly **`PAP`** at the moment of observation.
Our SDB tool called only `sync:RECV` (authenticated ordinary Tizen
debugging), not FOTA launch, Odin, partition write or reboot. The saved
report is on the owner's private Termux filesystem; **no original raw
file, account identifiers, watch IP or auth key were uploaded to GitHub**.

**External interpretation: suggestive, NOT same-model proof:**

- A [2016 Android developer's firsthand report](
  https://stackoverflow.com/questions/36836024/same-android-version-and-same-device-model-but-only-one-cannot-download-app)
  records `PAP` on Samsung in-store demo Galaxy phones and explicitly
  investigates whether the demonstration configuration affected app
  availability. This supports the possibility of a Samsung **demo
  configuration association**, not the semantics of the R840X
  bootloader or watch CSC package.
- A [2017 community Galaxy S8 LDU report](
  https://4pda.to/forum/index.php?showtopic=824699&st=300)
  identifies Live Demo Unit `G955XU` with `CARRIER: MDL` and
  `CSC: PAP`. This is independently consistent with the owner's
  R840X LDU observation, but is **another product generation**.
- Multiple generic public [CSC mappings](
  https://github.com/zerotet/samsung-csc-codes)
  and [regional code lists](
  https://technastic.com/samsung-csc-codes-list) call `PAP`
  **"Europe (PAP)"**. This generic label is **NOT** authoritative
  proof of the watch's country of manufacture, sales region or
  which signed model-specific Samsung files it accepts.

**Interpretation:** Record **active CSC: PAP** as measured.
Record **CSC association with older Samsung demo configurations:
plausible, independently corroborated**. Record **exact R840X-specific
PAP meaning, factory region, firmware eligibility, bootloader
signatures/rollback and physical restoration: UNKNOWN**. Never assume
`PAP` means a retail European flash package is suitable. The older
`R840XXXU1ATFA-(OXA)` third-party ZIP title is not evidence that this
unit has `OXA` installed. The previously public FOTA probes for
`SM-R840X/XAR` and `SM-R840X/KOO` returned HTTP 403, but those were
hypothetical regions and did not establish the active CSC.

**Next genuinely useful evidence:** If an authentic *free* and legally
sourced **exact SM-R840X**, appropriate `PAP`/LDU firmware package
exists, inspect its signatures, exact build and PIT **offline**, and
validate stock rescue on an independent/sacrificial R840X before any
owner-unit flashing. The active CSC measurement does not remove the
hard `NO_GO` on loader commands, firmware changes or UgLy|OS
custom boot.

## Why this test instead of assuming `OXA`, `XAR` or `KOO`

The firmware's `XXX` substring does not resolve a three-letter
sales/region code. The older `R840XXXU1ATFA-(OXA)` file name is a
third-party **multi-CSC package label**, not proof of this watch's
active software customization.

Original source lead: the public [SM-R805U Tizen Watch internals
research](https://github.com/sbose78/tizen-watch-internals/blob/3dcd79ca586827ea2fde9a5a23170a79d1a8e2dd/README.md)
reports **that watch's** active CSC in exactly:

`/opt/system/csc-default/output/csc-active-customer.log`

**Important distinction:** The path was originally learned on LTE
`SM-R805U`, but the owner's later **physical SM-R840X** observation
above now independently confirms that this exact text record also
exists and reports `PAP` on their Bluetooth LDU. That is an active
code observation, **not** authenticated OEM rescue image or permission
to flash another CSC.

This is **not** the Android phone path `Settings > About phone >
Service provider software version`. Nor is it the `*#1234#`
phone dialer code. Don't blindly use phone-specific shortcuts
or reset/change-CSC menus on a watch.

## Safest test order

1. Leave the watch in **normal Tizen**, not Wireless Download,
   Recovery or AP mode. No reboot or re-pairing is needed.
2. If an authorized SDB debugging connection is *already active*
   on a trusted LAN or phone hotspot, confirm the **current
   watch-side IP address**. Do not reuse stale addresses from
   previous test logs or share Wi-Fi keys, serials or IPs publicly.
3. Run the already-integrated fixed-path SDB reader from
   Android/Termux (after PR checks pass and merge):

   ```sh
   cd ~/Galaxy-3 && git pull --ff-only
   python tools/watch3_r840x_csc_readonly.py \
     --watch-ip WATCH_CURRENT_WIFI_IP
   cat ~/watch3-r840x-csc-redacted.json
   ```

   Replace `WATCH_CURRENT_WIFI_IP` with the actual private IP shown
   by **your watch**, not the phone hotspot address. The output
   prints only a three-character candidate CSC if found.
   The JSON contains no raw system log, SDB auth key, network IP
   or other file contents. The report is created mode 0600 and
   refuses to overwrite an existing report. If you intentionally
   take a second observation, use a distinct `--output` filename
   rather than deleting original evidence. The script checks this
   *before* attempting a network connection.

   If a prior result exists, preserve it and use for example:

   ```sh
   python tools/watch3_r840x_csc_readonly.py \\
     --watch-ip WATCH_CURRENT_WIFI_IP \\
     --output ~/watch3-r840x-csc-second-observation.json
   ```

4. Possible responses:
   - `ACTIVE_CSC_CANDIDATE_READ_FROM_EXACT_TIZEN_PATH` and
     `CSC_CANDIDATE: ABC`: that exact 3-character string was read
     from this watch's file, **not** proven Samsung signed
     stock-restoration regional compatibility.
   - `CSC_FILE_MISSING_DENIED_OR_UNREADABLE`: the path was absent,
     restricted or unreadable over normal SDB; **CSC remains
     UNKNOWN**, not `XXX`.
   - `CSC_PLACEHOLDER_NOT_REAL_REGION`: the file contains
     `XXX`, a placeholder; don't infer a valid region.
   - `CSC_LOG_UNRECOGNIZED_CONTENT`: the log wasn't exactly a
     three-character alphanumeric token. Tool will **not**
     extract a tempting substring from private/unrecognized text.
   - `SDB_UNAVAILABLE_OR_NETWORK_ERROR`: connection couldn't be
     completed. This is neither a CSC result nor a request to
     enter Wireless Download.

The CLI has **no arbitrary path flag**. On the watch, its
only requested operation is a single, bounded SDB
`sync:RECV` to the path above. It uses the same existing
SDB read-only transport as Galaxy-3's successfully tested
FOTA manifest reader; transfers at most **128 bytes** and
saves a filtered categorical report, never the raw log.

CI tests **mock** the watch on Ubuntu 22.04 and 24.04,
including exact path, single RECV, denied access, invalid
content, size cap, no additional packet, private report and
offline sample mode. Neither CI nor the code makes Odin
session/PIT/flash calls, reboots the watch, installs anything,
changes CSC or modifies partitions.

## What this will and won't resolve

**Resolved for the current installed Tizen configuration:** The
actual active CSC file on this R840X reported `PAP` on October 27.
No reason to repeat the same one-file read unless the owner has a
specific new configuration question; preserve the original report.

**Cannot resolve alone:** The original factory CSC, the full
regional firmware package identity, whether this LDU bootloader
accepts another CSC/region, authentic OEM rescue signatures,
recovery from a failed boot, or UgLy|OS custom kernel acceptance.

Regardless of this result, Issue #47's **full-stock recovery
and bootloader acceptance NO-GO stays in place**. Do not use a
candidate CSC to flash `SM-R840` retail firmware.
