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

- Base: main `656f8a5`, PR #120 integrated, all seven workflows green.
- Current work: record the successful physical configured-consumer capture;
  offline analysis is waiting for the original captured bytes.
- Owner supplied the physical PR #119 JSON: `NO_CURRENT_FOTA_OWNER`,
  `watch_contacted=true`, no UID/executable/binary, no service activation.
  This is an unowned name at that instant, not a transport failure or proof
  of an absent consumer. Do not repeat that probe or start the consumer.
- Owner ran PR #120's configured-unit mode successfully. The unit is
  `Type=dbus`, `BusName=fota.consumer`, configured user/group `fota:fota`,
  `ExecStart=/usr/bin/fota-consumer`, inactive/dead. Selected fields were
  stable and the original ARM ELF reader copied 89,980 bytes to the phone.
  Reported SHA-256:
  `19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a`.
  No service activation, FOTA method or firmware write occurred.
- This session has the report, not the copied ELF bytes. Verify size/hash
  independently when the owner attaches the capture; do not claim to have
  inspected its machine code or linked it to a vulnerability yet.
- Configuration is distinct from live ownership/process UID. Manager/bus
  and selected unit fields are rechecked before publishing a copy. No raw
  responses, arguments, PIDs, timestamps or bus identities are saved.
- Procedure and actual no-owner result:
  `docs/watch3-r840x-existing-fota-owner.md`.
- Samsung's exact R840X Korea detail page had no downloadable content;
  unauthenticated detail API returned 401. No new signed rescue bytes.
- Prior TV archive-root route was physically ruled out by missing
  `sdbd-tarlauncher`; do not repeat it. Inaccessible scripts stay retired.

## Validation and integration

Focused tests cover existing ownership, configured metadata, unsafe or
multiple ExecStart records, private output, manager/bus changes, unit
changes and denied copies. Real private D-Bus tests remain required.
A separate required real systemd test passed against an inactive trap unit
on disposable Ubuntu 22.04/24.04 runners, alongside the required real private
D-Bus tests, without skips. PR #120's actual watch execution now confirms
configured metadata and read-only ELF acquisition; no firmware acceptance,
root or recovery behavior was tested. The uploaded bytes remain pending.
Issue #47 stays open until physical restoration/custom boot are demonstrated.

## Decisive blockers and next step

1. Authentic exact-R840X original S-BOOT and complete signed stock rescue set,
   or an independently verified compatible signed replacement, remain missing.
2. This host has no direct authenticated connection to the physical watch.
3. Firmware-specific bootloader behavior, recovery after boot failure and
   custom-kernel acceptance remain unverified.

Next step: owner attaches the existing
`~/watch3-r840x-fota-unit-evidence/fota-configured-executable.bin`, preferably
packaged with `fota-unit-report.json`. No further watch query is needed.
Verify 89,980 bytes and the reported hash, then inspect the original ELF
offline for D-Bus registration/authorization, update-file validation,
privilege transitions and recovery handoff. Never execute the vendor file
or infer a signature bypass from strings/imports alone.
Continue exact-model restoration sourcing when a concrete new lead exists.

Do not repeat sibling scans or GUI builds as substitutes. Preserve the
user's no-experimental-flashing constraint: no reset, repartition, image
write, update activation or exploit traffic on the only working watch.
No additional hardware/purchases are assumed. Older source branches remain
retained because direct Git branch deletion lacks authentication.
