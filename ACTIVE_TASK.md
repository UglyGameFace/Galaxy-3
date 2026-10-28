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

## This continuation

- Base: main `8827c89` (PR #117). No open PRs or conflicting changes at start.
- Branch: `issue-47-pit-dispatch-provenance`.
- Original archived R500 reference files were obtained off-device and checked
  against the existing archive and raw S-BOOT hash pins.
- Root cause of an ambiguous report: the broad PIT-vicinity window includes
  two separate function frames. Only one reported `BL` reaches the validator
  candidate; the following `BL` reaches the adjacent routine.
- Traced the donor dispatcher: command 0x65 / subcommand 3 / state 0,
  buffer from object +0x30, length from +0x58, negative-return branch before
  the adjacent call. Receive-side direct call also observed in both originals.
- Extended the authoritative existing analyzer and existing real-binary CI;
  no duplicate inspector, payload, on-watch operation or firmware committed.
- Detailed evidence and limits: `docs/watch3-r500-sboot-reference-differential.md`.

## Validation and integration

Local focused validation and original-binary checks are recorded in the PR.
GitHub CI and merge must be verified before calling this change integrated.
Issue #47 must stay open until the physical objective is demonstrated.
No production/watch validation has been performed in this continuation.

## Decisive blockers and next step

1. Authentic exact-R840X original S-BOOT and complete signed stock rescue set,
   or an independently verified compatible signed replacement, remain missing.
2. This session has no direct authenticated connection to the physical watch;
   prior local Termux/SDB access is evidence, not remote access from this host.
3. The owner's firmware-specific bootloader behavior, recoverable transport
   after boot failure, and custom-kernel acceptance remain unverified.

Prioritize exact-model binary/restoration evidence. Apply the existing pipeline
to that evidence offline when available. Do not repeat sibling scans or large
GUI builds as substitutes. Retain the user's prior no-experimental-flashing
constraint; no factory reset, repartition, image write or exploit traffic on the
only working watch. No additional hardware/purchases are assumed.
