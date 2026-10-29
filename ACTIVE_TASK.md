# UgLy|OS R840X bootloader and recovery

Updated October 29, 2026. Issue #47: restore stock reliably and boot UgLy|OS
on the owner's SM-R840X / NOBLESSE-LARGE-BT R08, R840XXXU1AUA2, CSC PAP candidate.
Root, bootloader unlock, custom boot and tested restoration remain unverified.
Owner authorization is established.

## Current physical result and root cause

Base main `719625f` includes PR #123. No overlapping open PR was present.
Owner uploaded `watch3-sync-agent-evidence.zip`. Verified ZIP SHA-256:
`b13d005fb5432e3cbe0c4ca41de682c9901ac276fa9eecc504b6f51f4a8161f4`.
It contains only `sync-agent-report.json` (782 bytes), SHA-256:
`5885d6a9a42f9e0e7bd9db91f37f68d04c624a7d93edcb6b38118f2a9042584d`.

Actual result: DEPENDENCY_CACHE_TOOL_UNAVAILABLE, stage linker_cache.
The original consumer was verified, and the watch replied; no path or
library bytes were acquired. This is a failed shell-helper dependency
in the lookup method, not evidence that the library is absent or unreadable.
Do not repeat the original cache-command capture.

## Current implementation and next phone action

Source branch: `issue-47-native-sync-agent-discovery`.
The existing artifact reader's sync-agent mode now uses existing native
SDB LIST/RECV exclusively. The obsolete cache query/probe/parser and
shell fixtures are removed after checking their references.

- Verify the already captured original consumer locally.
- List /usr/lib, then /lib only if needed; report the exact evidenced
  SONAME/version family and copy only an actually observed candidate.
- Reuse the existing bounded RECV reader; check ARM32/ET_DYN/DT_SONAME and
  a defined public install function in executable file-backed memory.
- Recheck selected directory metadata and preserve binary/report/ZIP.
  Directory identity is not an observation of an active runtime provider.
- Use a new output folder and ZIP so the owner's first failure evidence
  is preserved. New report schema v2 records native directory resolution.

[Current one-run instructions](docs/watch3-r08-fota-artifact-readonly.md).
Physical native acquisition remains pending the owner's phone run. This
workspace has no authenticated direct connection to the watch.

## Preserved evidence

- Authenticated non-root Tizen Wi-Fi SDB, ARMv7 userspace, Linux 4.9.59.
- 21 partition names and critical sysfs geometry; no original physical
  S-BOOT/boot/recovery bytes or tested restore.
- Owner completed only ODIN/LOKE exchange, then returned to stock.
- Private originals: accessory fota-service 87,036 bytes and configured
  fota-consumer 89,980 bytes; exact hashes remain pinned in the tools/docs.
- Consumer configuration fota:fota, inactive/dead; no current live owner
  in the earlier snapshot.
- Original-byte analysis connects the accessory's separate receipt/install
  states (50/60), vconf notification and consumer update callback.
- The consumer executes archive-supplied pre_update_client_2 in reviewed
  wrappers; earlier/library/later validation and actual privileges are open.
- Separate Install reaches imported sync_agent_dm_fota_install; the original
  ELF's libsync-agent.so.0 dependency is the current missing implementation.
- Failed preparation/recovery-script sync reads remain ambiguous. The TV
  tar route lacks sdbd-tarlauncher; R500/retail firmware observations do not
  establish exact-R840X compatibility.

[Detailed original-code findings](docs/watch3-r840x-consumer-trust-boundaries.md).
PR #122 removed hard-coded flash_allowed/NO_GO permission-like output;
existing evidence remains valid.

## Validation and remaining work

Local focused suite: 195 passing cases, one compiler-only fixture skipped
because clang/lld are absent locally. CI requires all 196 cases including
the cross-compiled ARM/readelf fixture, plus two real private D-Bus tests
and one real systemd test on Ubuntu 22.04 and 24.04 without skips.
Fake-SDB assertions verify only sync LIST/RECV, no watch shell/helper requests.
Samsung originals are not committed, executed or uploaded to CI.

The missing original library must be acquired and examined before its
installation/validation behavior can be determined. Exact R840X S-BOOT,
complete signed rescue firmware or verified compatible replacement,
unsigned-kernel acceptance and tested return to stock remain missing.
Issue #47 stays open. This collector changes no firmware or service state.

Android/Termux only, free only, no PC or hardware purchases.
Earlier merged remote branches remain retained: direct Git deletion has no
authentication and the connector exposes no delete-ref operation.
Do not discard unpreserved owner work.
