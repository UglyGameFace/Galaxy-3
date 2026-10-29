# UgLy|OS R840X bootloader and recovery

Updated October 28, 2026. Active scope: Issue #47, boot/recovery only.

## Objective and current state

Reproducibly restore stock firmware and boot UgLy|OS on the owner's
SM-R840X / NOBLESSE-LARGE-BT R08, installed R840XXXU1AUA2, CSC candidate PAP.
**Blocked for physical unlocking and recovery; neither is demonstrated.**

Preserved physical evidence: authenticated non-root Tizen SDB, 21 partition
names and critical sysfs geometry, original FOTA userspace artifacts, and the
owner's completed four-byte ODIN/LOKE exchange. Physical boot/recovery bytes,
unsigned-kernel acceptance and a return-to-stock test are absent.

## Current continuation

- Base: main `7bb7084`, PR #118 integrated and real-binary CI green.
  No open PRs or conflicting changes at start of this continuation.
- Branch: `issue-47-live-fota-owner-evidence`.
- Samsung's exact R840X Korea download detail page explicitly has no
  downloadable content. The separate unauthenticated detail API returned 401.
  No new bootloader or signed rescue bytes acquired.
- Prior TV archive-root route was physically ruled out by missing
  `sdbd-tarlauncher`; do not repeat it.
- The original R840X FOTA ELF already proves system-bus client use of the
  name `fota.consumer`, but not its actual owner/executable. Existing searches
  for static activation files were inconclusive.
- New collector queries only the bus daemon's existing-owner registry,
  obtains the observed process's proc-exe link, and can privately copy that
  ARM ELF through the existing bounded SDB RECV reader. Bus/owner/path changes
  withhold the copy. No firmware-service call or activation is requested.
- Reuses original authenticated SDB framing/key and authoritative ELF reader;
  no duplicate protocol implementation, guessed binary path or watch write.
- Procedure and sources: `docs/watch3-r840x-existing-fota-owner.md`.

## Validation and integration

Local regression evidence and required real private host D-Bus integration
are recorded in the PR. The local environment forbids socket binding; CI must
run the real bus test without skipping it before integration is accepted.
Issue #47 must stay open until the physical objective is demonstrated.
No production/watch validation has been performed in this continuation.

## Decisive blockers and next step

1. Authentic exact-R840X original S-BOOT and complete signed stock rescue set,
   or an independently verified compatible signed replacement, remain missing.
2. This session has no direct authenticated connection to the physical watch;
   prior local Termux/SDB access is evidence, not remote access from this host.
3. The owner's firmware-specific bootloader behavior, recoverable transport
   after boot failure, and custom-kernel acceptance remain unverified.

Next physical evidence is one optional, read-only normal-Tizen run of
`watch3_r840x_fota_owner_readonly.py --watch-ip <current local IP>
--copy-existing-owner`; inspect its redacted report and any captured original
consumer ELF offline. Do not start an idle consumer or repeat blocked paths
to make the query succeed. Continue exact-model restoration sourcing.

Do not repeat sibling scans or large GUI builds as substitutes. Retain the
user's prior no-experimental-flashing constraint; no factory reset,
repartition, image write or exploit traffic on the only working watch.
No additional hardware/purchases are assumed. PR #118 source branch remains
retained because direct Git branch deletion lacked authentication.
