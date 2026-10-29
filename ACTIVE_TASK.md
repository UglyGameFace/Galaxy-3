# UgLy|OS R840X bootloader and recovery

Updated October 29, 2026. Active scope: Issue #47, boot/recovery only.

## Objective and current state

Reproducibly restore stock firmware and boot UgLy|OS on the owner's
SM-R840X / NOBLESSE-LARGE-BT R08, installed R840XXXU1AUA2, CSC candidate PAP.
**Blocked for physical unlocking and recovery; neither is demonstrated.**

Preserved physical evidence: authenticated non-root Tizen SDB, 21 partition
names and critical sysfs geometry, original FOTA userspace artifacts, and the
owner's completed four-byte ODIN/LOKE exchange. Physical boot/recovery bytes,
unsigned-kernel acceptance and a return-to-stock test are absent.

## Current continuation

- Base: main `342eaa3`; PR #120 integrated and physically validated for a
  read-only configured-consumer capture, not root or firmware operations.
- Branch: `issue-47-original-consumer-trust-map`.
- Owner attached the original consumer ELF and unit report in
  `watch3-fota-consumer-evidence.zip`. Independently verified 89,980 bytes,
  ARM ELF32 PIE, SHA-256
  `19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a`.
  Build ID `bb62b3fe4f1f2ae02cd58c18dd39bff093a2a9cd`.
- Original `/usr/bin/fota-consumer` registers the expected system-bus name
  and object, callback code `0xba04`. Configured user/group `fota:fota`,
  inactive/dead; no live UID or root access established.
- The handler accepts a claimed PID, frees the supplied cookie, and uses
  that PID's proc label to classify LaunchIp callers. It discards callback
  sender/connection arguments. Bus policy and runtime access are unresolved;
  no method was called and no exploitable authorization bypass is claimed.
- Actual update entry is a vconf ui_state callback into do_device_control.
  The original update wrapper extracts delta.ua, writes recovery DELTA.PATH,
  extracts nested pre_update.tar and executes its pre_update_client_2 through
  a shell-command helper, then calls rw-update-prepare.sh FOTA. No explicit
  signature gate was observed inside this wrapper; earlier/later and library
  checks remain unresolved. No target binary or script was run.
- Extend the authoritative offline analyzer with a separate exact consumer
  profile: 28 decoded calls, 15 relocation resolutions, 10 literal references,
  eight control instructions, callback pointer and interface definitions.
  Default accessory profile remains compatible; standard library only.
- Extend the original bounded script reader for the newly code-evidenced
  /usr/bin/rw-update-prepare.sh path, optional update-prepare component.
  One read-only RECV, 8 KiB cap, separate private output; no script invocation.
- Full evidence: `docs/watch3-r840x-consumer-trust-boundaries.md`.
- Earlier no-current-owner query is preserved. Do not repeat it or start an
  idle consumer. Prior TV tar route is ruled out by missing sdbd-tarlauncher.
  Previously inaccessible recovery-update/rw-update-systemd scripts stay retired.

## Validation and integration

The exact uploaded original ELF passed the new semantic review locally;
Capstone 5.0.6 independently matched all 28 selected call targets. All 180
focused local regressions passed without skips. Mock tests
cover decoder alignment/invalid inputs, strict profile pins, private output,
fixed new RECV bytes, unknown component rejection, denial and byte cap.
Five older collision fixtures had escaped their socket mock scopes; corrected
those scopes. All 180 fixtures also passed with unmocked create_connection
calls explicitly rejected, and CI now enforces that condition.
Existing SDB/FOTA regression and real host integration checks remain required
in CI. A green host test is not physical unlocking or restoration.
The new update-prepare read has not run on the physical watch yet.
Issue #47 stays open until stock restoration/custom boot are demonstrated.

## Decisive blockers and next step

1. Authentic exact-R840X original S-BOOT and complete signed stock rescue set,
   or independently verified compatible signed replacement, remain missing.
2. This host has no direct authenticated connection to the physical watch.
3. Bus/MAC policy, archive writability, runtime privileges, upstream verification
   and later recovery/bootloader acceptance remain unverified.

Next normal-Tizen Termux read after validated integration:
`python tools/watch3_r08_recovery_script_pull.py --watch-ip <current local IP>
--component update-prepare`. Inspect the private script/report offline if
acquired; if denied/unavailable, analyze that outcome before any new request.
No default-mode rerun of recovery-update.sh and no FOTA/archive submission.
Continue exact-model restoration sourcing when a concrete new lead exists.

Do not repeat sibling scans or GUI builds as substitutes. Preserve the
user's no-experimental-flashing constraint: no reset, repartition, image
write, update activation or exploit traffic on the only working watch.
No additional hardware/purchases are assumed. Older source branches remain
retained because direct Git branch deletion lacks authentication.
