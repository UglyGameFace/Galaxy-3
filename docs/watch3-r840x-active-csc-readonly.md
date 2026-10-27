# SM-R840X R08: read-only active CSC check from Tizen

**Issue:** [#47](https://github.com/UglyGameFace/Galaxy-3/issues/47)
**Installed build:** `R840XXXU1AUA2`.
**Actual CSC:** **UNKNOWN** until owner-derived evidence is obtained.

## Why this test instead of assuming `OXA`, `XAR` or `KOO`

The firmware's `XXX` substring does not resolve a three-letter
sales/region code. The older `R840XXXU1ATFA-(OXA)` file name is a
third-party **multi-CSC package label**, not proof of this watch's
active software customization.

Original source lead: the public [SM-R805U Tizen Watch internals
research](https://github.com/sbose78/tizen-watch-internals/blob/3dcd79ca586827ea2fde9a5a23170a79d1a8e2dd/README.md)
reports **that watch's** active CSC in exactly:

`/opt/system/csc-default/output/csc-active-customer.log`

**Important difference:** The researched device is LTE
`SM-R805U`, while ours is a Bluetooth LDU `SM-R840X`.
An LDU could have a different customization layout, an empty
placeholder, absent CSC, or permission restrictions. None has
been proven on our watch. A read result from the exact file
would be *direct, relevant evidence* of an active code but
still would **not** authenticate a full stock repair image or
authorize a firmware-region change.

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

**Can resolve:** A plausible active CSC value from a real
system log on this exact R840X, if the file exists and is readable.

**Cannot resolve alone:** The original factory CSC, the full
regional firmware package identity, whether this LDU bootloader
accepts another CSC/region, authentic OEM rescue signatures,
recovery from a failed boot, or UgLy|OS custom kernel acceptance.

Regardless of this result, Issue #47's **full-stock recovery
and bootloader acceptance NO-GO stays in place**. Do not use a
candidate CSC to flash `SM-R840` retail firmware.
