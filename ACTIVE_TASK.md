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

- Base: main `0f7d2ed`, PR #119 integrated, all seven workflows green.
- Branch: `issue-47-configured-fota-unit`.
- Owner supplied the physical PR #119 JSON: `NO_CURRENT_FOTA_OWNER`,
  `watch_contacted=true`, no UID/executable/binary, no service activation.
  This is an unowned name at that instant, not a transport failure or proof
  of an absent consumer. Do not repeat that probe or start the consumer.
- Earlier physical inventory listed the exact 386-byte
  `/usr/lib/systemd/system/fota-consumer.service`; its RECV was unavailable
  or denied. The new optional mode asks the existing systemd manager for
  this known unit's configured properties, then uses the original bounded
  ARM ELF reader for its observed ExecStart path. Never executes that path.
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
A separate required real systemd test checks the exact show command
against an inactive trap unit on disposable Ubuntu 22.04/24.04 runners.
Local PID 1 is not systemd and sockets are denied; real tests must pass
without skipping in CI before integration. Watch execution remains pending.
Issue #47 stays open until physical restoration/custom boot are demonstrated.

## Decisive blockers and next step

1. Authentic exact-R840X original S-BOOT and complete signed stock rescue set,
   or an independently verified compatible signed replacement, remain missing.
2. This host has no direct authenticated connection to the physical watch.
3. Firmware-specific bootloader behavior, recovery after boot failure and
   custom-kernel acceptance remain unverified.

Next normal-Tizen Termux command after green CI and merge:
`python tools/watch3_r840x_fota_owner_readonly.py --watch-ip <current local IP>
--copy-configured-unit`, then inspect
`~/watch3-r840x-fota-unit-evidence/fota-unit-report.json` and privately acquired
ELF offline, if any. If denied/unavailable, analyze that outcome first.
Continue exact-model restoration sourcing when a concrete new lead exists.

Do not repeat sibling scans or GUI builds as substitutes. Preserve the
user's no-experimental-flashing constraint: no reset, repartition, image
write, update activation or exploit traffic on the only working watch.
No additional hardware/purchases are assumed. Older source branches remain
retained because direct Git branch deletion lacks authentication.
