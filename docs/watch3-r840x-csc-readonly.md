# Read the Galaxy Watch3 SM-R840X active CSC without modifying anything

**Active project:** [Watch3 safe boot and restoration, Issue #47](https://github.com/UglyGameFace/Galaxy-3/issues/47).
**Physical watch:** SM-R840X, Live Demo Unit, NOBLESSE-LARGE-BT R08,
installed `R840XXXU1AUA2` Tizen 5.5.

**Existing evidence:** The actual CSC is **UNKNOWN**. We did **not** establish
XAR, KOO or OXA from the public FOTA checks or older third-party `(OXA)`
repair-package label. `OXA` is a multi-CSC family label, not necessarily
the running active 3-character CSC. Firmware `XXX` does not prove CSC.

## Why this exact path is worth checking

[Public SM-R805U Tizen watch reverse-engineering notes, pinned
`3dcd79ca586827ea2fde9a5a23170a79d1a8e2dd`](
https://github.com/sbose78/tizen-watch-internals/blob/3dcd79ca586827ea2fde9a5a23170a79d1a8e2dd/README.md)
document the **active CSC text file**:

`/opt/system/csc-default/output/csc-active-customer.log`

The researcher physically inspected this path on a **different Samsung
Tizen watch (SM-R805U)**. It has **not** yet been verified present or
readable on the owner's SM-R840X demo unit. LTE carrier CSC behavior
does not necessarily apply to a Bluetooth-only LDU watch.

The new `tools/watch3_r840x_csc_readonly.py` reuses Galaxy-3's existing
authenticated standard Tizen Smart Development Bridge (SDB) transport and
the already tested `ReadOnlySyncDecoder`. It requests **one exact
allowlisted path** over SDB `sync:RECV`, capped to **128 bytes**, then
immediately closes the connection. It uses **neither** Tizen shell
execution nor `root`, `sync:SEND`, watch reboot, update configuration,
FOTA `Launch`, NetOdin, partition data, CSC change or firmware flashing.
It needs the watch's normal Wi-Fi debugging access; **never** enter
Wireless Download mode for this task.

Only a file containing exactly **three ASCII uppercase alphanumeric
characters** (optional final LF or CRLF) qualifies for a provisional
CSC candidate. Placeholder `XXX`, unexpected text, access denied,
unavailable path or empty response must be reported as **unknown**.
That protects against mistaking unrelated log text, device identifiers
or phone secrets for a region code. No raw file contents, watch IP,
serial, MAC address or device identity are recorded. Result is written
mode `0600` and refuses to overwrite an existing report.

## How to run from Android Termux (after CI passes and PR merges)

Your watch should be **normally booted into Tizen**, with Wi-Fi
debugging enabled and connected to your trusted Wi-Fi/hotspot.
Use only the private IP address **currently shown by the watch**;
past IPs may not be valid:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_csc_readonly.py \
  --watch-ip YOUR_WATCH_CURRENT_IP
cat ~/watch3-r840x-csc-redacted.json
```

This is a **networked read-only query**, not a fully offline operation.
The phone opens an authenticated SDB connection to the address you
provide (standard Tizen port 26101) and asks for one regular text file.
If Samsung Tizen security policy refuses it, do not retry with root,
alternate hidden paths, engineering firmware, or Odin. Share only the
sanitized report contents; it includes a three-character code **if**
the probe succeeds.

The default report filename must not already exist. That is
intentional evidence preservation. For a future new observation,
use a different path, for example:

```sh
python tools/watch3_r840x_csc_readonly.py \
  --watch-ip YOUR_WATCH_CURRENT_IP \
  --output ~/watch3-r840x-csc-followup-redacted.json
```

An offline-only parser fixture mode is also available for tests:

```sh
printf '%s\\n' XAR > ~/synthetic-csc.txt
python tools/watch3_r840x_csc_readonly.py \
  --offline-sample ~/synthetic-csc.txt \
  --output ~/synthetic-csc-offline-report.json
```

The example `XAR` is **fake test data** and will never be described
as a physical watch observation by the script.

## How to interpret evidence

- `CSC_CANDIDATE_FROM_OWNER_WATCH_FIXED_PATH` indicates that one
  fixed candidate was read from the physical watch's standard Tizen
  path. **It still does not independently establish a firmware
  distribution/region package, CSC sales history, original country,
  bootloader compatibility or exact stock image signing.**
- `CSC_NOT_YET_CONFIRMED` with a categorical `state` is not an
  error requiring escalating privileges; it means the path didn't
  furnish trustworthy active CSC data on this particular watch.
- The previous Samsung public FOTA checks returned 403 for
  `SM-R840X/XAR` and `SM-R840X/KOO` and positive metadata only
  for different **retail** `SM-R840/XAR`. Do not use that to infer
  the owner's active CSC.
- All output says `flash_allowed=false`,
  `full_stock_recovery_proven=false`. CSC data alone cannot unlock
  or convert the LDU, authenticate an `R840` retail image,
  override rollback restrictions or make UgLy|OS bootable.

## CI and scope

GitHub Actions runs fake watch packets on Ubuntu 22.04/24.04
without watch access. Tests assert exactly one SDB `sync:RECV`,
no `SEND`/shell/Odin, exact source path, small reply bound,
private redacted no-overwrite report, unknown state for
unreadable/invalid file and no boot/restore authorization.

**Do not start installing combination or retail firmware.**
This one safe question is only: *does the R840X expose a readable
active CSC text record, and if so what precise three-character
value does it currently contain?*
