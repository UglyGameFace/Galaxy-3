# UgLy|OS R840X bootloader and recovery

Updated October 29, 2026. Active objective: Issue #47, restore stock reliably
and boot UgLy|OS on the owner's SM-R840X / NOBLESSE-LARGE-BT R08,
installed R840XXXU1AUA2, CSC candidate PAP.
Root, bootloader unlock, custom boot and tested stock restoration remain
unverified. The owner has authorized this work; unverified capability is
not an owner-permission decision.

## Current implementation

Base main `518d9eb` includes PR #122. No overlapping open PR was present at
the start. Current branch: `issue-47-sync-agent-install-implementation`.

The original consumer's separate Install path reaches imported
`sync_agent_dm_fota_install`. Its actual ELF lists `libsync-agent.so.0`.
The missing implementation is now the target of one complete acquisition
mode in the existing `tools/watch3_r08_fota_artifact_pull.py`:

- Verify the existing 89,980-byte original consumer/hash locally.
- Resolve the evidenced SONAME from the watch's existing linker cache using
  one fixed `ldconfig -p` query; no guessed remote path or library loading.
- Copy exactly one resolved system-library path with the existing bounded
  SDB RECV reader, check ARM ELF32/ET_DYN/DT_SONAME and an exported install
  function in mapped executable bytes, then recheck the cache.
- Save a private binary/report and optional ZIP in one run. A denied or
  missing read also produces a report-only ZIP; raw error text stays private.
- Keep earlier executable profiles, path validation and error strings
  compatible. New ELF facts are additive. No duplicate transport exists.

Phone instructions and failure states:
[artifact capture](docs/watch3-r08-fota-artifact-readonly.md).
Physical sync-agent acquisition and implementation analysis are still pending.
A stable cache entry is a candidate, not proof of an observed runtime provider.

## Preserved original evidence

- Authenticated non-root Tizen Wi-Fi SDB; ARMv7 userspace, Linux 4.9.59.
- 21 partition names and critical sysfs geometry; physical original
  S-BOOT/boot/recovery bytes have not been acquired.
- Owner's four-byte ODIN/LOKE exchange; no subsequent Odin operation.
- Actual 87,036-byte accessory fota-service and 89,980-byte configured
  consumer were privately captured and independently hash-verified.
- Consumer configured fota:fota, inactive/dead; live-owner query returned
  NO_CURRENT_FOTA_OWNER at that snapshot.
- Accessory success in state 30 sets 50; a separate parsed request sets 60
  and signals db/fotaconsumer/ui_state, matching the consumer callback.
- Consumer wrappers execute archive-supplied pre_update_client_2 before
  preparation. Earlier/library/later validation and runtime access are open.
- Update-prepare SDB RECV returned an ambiguous remote FAIL. No script,
  JSON or ZIP resulted. Repeating that unchanged read is not the next step.
  The consumer literal does not prove that the script exists/read access.
- Earlier TV tar route lacks sdbd-tarlauncher. R500 donor observations and
  retail/combination listings are not exact-R840X compatibility evidence.

Detailed original-byte findings:
[consumer trust boundaries](docs/watch3-r840x-consumer-trust-boundaries.md).
PR #122 removed the hard-coded flash_allowed=false/NO_GO permission-like
output; existing captures remain valid and do not need recapture.

## Validation and integration

Local focused suite: 193 passing cases; one ARM cross-compiler fixture skipped
because clang/lld are absent here. CI requires that compiled ARM fixture to
run, alongside the complete 194-case guarded suite, two real private D-Bus
tests and one real systemd test on both Ubuntu 22.04 and 24.04. The compiled
fixture is original tiny test code and is never executed.

Both private original Samsung ELFs still pass their pinned offline analyses;
the consumer's reviewed 28-call profile is unchanged. No original vendor
binary is committed or uploaded to CI. Current production validation is
pending the owner's phone run; host/fake-peer tests do not establish watch
tool availability, library readability or unlocking.

## Remaining work and cleanup

Obtain the original sync-agent implementation, trace its actual installation
and validation boundary, and establish a real privilege/boot route. Exact
R840X S-BOOT, a complete signed rescue set (or verified compatible signed
replacement), unsigned-kernel acceptance and a tested return path remain
missing. Issue #47 stays open.

Android/Termux only, free only, no hardware purchases. Protect the only
functional watch: the current operation copies ordinary userspace files and
does not run an update, write a partition, reset, repartition or flash.
This host has no authenticated direct connection to the watch; collection
runs through the owner's already-authorized phone SDB connection.

Older merged source branches remain preserved: direct Git branch deletion
has no authentication and the connector exposes no delete-ref capability.
Do not retry failed deletion or discard unpreserved owner work.
