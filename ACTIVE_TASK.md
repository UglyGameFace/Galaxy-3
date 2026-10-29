# UgLy|OS R840X bootloader and recovery

Updated October 29, 2026. Active scope: Issue #47, boot/recovery only.

## Objective and current state

Reproducibly restore stock firmware and boot UgLy|OS on the owner's
SM-R840X / NOBLESSE-LARGE-BT R08, installed R840XXXU1AUA2, CSC candidate PAP.
**Physical unlocking and recovery remain unverified; neither is demonstrated.**
The owner has authorized this work. Lack of a demonstrated technique is a
technical unknown, not a permission refusal or a reason to end investigation.

Preserved physical evidence: authenticated non-root Tizen SDB, 21 partition
names and critical sysfs geometry, original FOTA userspace artifacts, and the
owner's completed four-byte ODIN/LOKE exchange. Physical boot/recovery bytes,
unsigned-kernel acceptance and a return-to-stock test are absent.

## Current continuation

- Base main `6b6a8b5`, PR #121 integrated. This continuation corrects misleading
  collector output and records further analysis of the original artifacts.
- The owner collector's version-1 `flash_allowed=false` and `NO_GO` were
  hard-coded, not watch/bootloader findings. Remove the permission-like field;
  version 2 reports EVIDENCE_ONLY and retains all actual observation states.
  Existing evidence does not need to be acquired again for this output fix.
- Owner ran the exact update-prepare reader on normal Tizen. Result:
  `RECOVERY_SCRIPT_ERROR: REMOTE_MISSING_DENIED_OR_UNREADABLE`.
  Remote sync FAIL does not distinguish missing from denied content.
  No script/JSON acquired; the && chain stopped before packaging a ZIP.
  Do not rerun the unchanged sync read expecting a different diagnosis. The
  decoder discarded the remote error text; the result cannot establish
  permanent inaccessibility. No transport failure was demonstrated.
- Recovered the earlier private original accessory service upload without a
  watch read; independently verified 87,036 bytes, SHA-256
  `008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757`.
- Crosschecked the actual accessory-to-consumer state handoff: file completion
  in state 30 with status 0 sets state 50. A separate parsed request's case 8
  sets state 60. On response success its control routine writes
  db/fotaconsumer/ui_state, matching the original consumer's registered key.
  File receipt is not by itself proof of installation or a validation bypass.
- Verified 14 selected accessory calls with the existing decoder and Capstone,
  six PLT/GOT resolutions, seven control assertions and two key literals.
  The completion callback calls chmod(0666) before status/state handling;
  actual caller privilege, MAC policy and writable attack surface are unknown.
- Original consumer remains verified: 89,980-byte ARM ELF32 PIE, SHA-256
  `19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a`,
  build ID bb62b3fe4f1f2ae02cd58c18dd39bff093a2a9cd. Configured fota:fota,
  inactive/dead; no observed live UID or phone root access.
- Its reviewed wrapper executes archive-supplied pre_update_client_2 through
  a shell helper before recovery preparation. No explicit signature gate was
  observed inside that wrapper; earlier/later and library checks remain open.
- Independently traced Install's separate path: 0xbf62 compares the method;
  0xc062 enters the installation helper, which calls _IPC_interfaces(4,1,0)
  at 0xb2d2. The actual TBB table maps event 4 to 0x7e30, where 0x7e32
  calls the imported sync_agent_dm_fota_install. libsync-agent.so.0 is an
  actual DT_NEEDED dependency; its installed path and implementation are
  not captured. Verified six additional calls and three PLT/GOT resolutions.
- Original vendor files remain private and were never executed or modified.
  Details: docs/watch3-r840x-consumer-trust-boundaries.md.

## Validation and integration

PR #121 passed 180 guarded fake-SDB fixtures plus two required real private
D-Bus and one required real systemd test on both Ubuntu 22.04/24.04 without
skips (run 40927170402). The consumer's 28 selected instruction targets were
independently matched locally on the actual original ELF.
This continuation independently verified the older original ELF, selected
cross-artifact edges and the consumer's imported installation boundary.
The collector's report wording changes; its outgoing requests and device
behavior do not change. No target binary/script, update RPC or firmware write
was run.
Issue #47 stays open: the physical unlock/restoration objective is unfulfilled.

## Decisive blockers and next step

1. Authentic exact-R840X original S-BOOT and a complete signed stock rescue set,
   or independently verified compatible signed replacement, remain missing.
2. This host has no direct authenticated connection to the physical watch.
3. Runtime bus/MAC permissions, archive control, upstream verification and
   recovery/bootloader acceptance remain unverified. Intended code paths do
   not establish an exploitable route or usable recovery on this device.

The next missing implementation is the imported sync-agent installation code,
not another guessed preparation-script name. Its SONAME is observed in the
original ELF; its actual installed path must be established before acquisition.
Continue original-code and exact-model firmware research. No working
unlock/recovery procedure is verified, and no new permission question is needed
to continue work already authorized by the owner.
A fresh public exact-build/model lookup yielded no new verified rescue bytes;
retail or combination image listings are not compatibility evidence.

Previously closed routes remain closed: idle fota.consumer owner query,
TV tar route (missing sdbd-tarlauncher), inaccessible recovery-update.sh,
rw-update-systemd.sh, and now rw-update-prepare.sh. Do not repeat sibling
scans or GUI builds as substitutes. Preserve the no-experimental-flashing
constraint: no reset, repartition, archive/image write, update activation
or exploit traffic on the only working watch. No hardware purchases.
Older merged source branches remain retained because direct Git branch
retirement lacks authentication and no delete-ref connector is available.
