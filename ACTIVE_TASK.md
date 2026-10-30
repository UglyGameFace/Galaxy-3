# UgLy|OS R840X bootloader and recovery

Updated October 29, 2026. Issue #47: restore stock reliably and boot UgLy|OS
on the owner's SM-R840X / NOBLESSE-LARGE-BT R08, R840XXXU1AUA2, CSC PAP candidate.
Root, bootloader unlock, custom boot and tested restoration remain unverified.
Owner authorization is established.

## Current physical result and original-code review

Base main `25dc9c0` includes PR #124. The corrected native library capture
succeeded. No overlapping open PR was present. Uploaded
`watch3-sync-agent-native-evidence.zip` SHA-256:
`331b97505a06dc0a3c8dd45cf08b3e42d269151f9e1dd1f756818eb5c8ba374e`.
It contains the 4,211-byte report and 647,076-byte ARM ELF32 library copied
from `/usr/lib/libsync-agent.so.0`, SHA-256:
`3fbebb3d55a7e6a132f3516af88280e63278a4b3bf51cb61cca194614b605a97`.
GNU build ID: `07783d299457ad74f7c232f1941446060aa6a1a9`.

Actual-byte review matched 30 immediate calls with independent decoders,
20 PLT/GOT relocations, 10 control/argument instructions and 2 literals.
The public Install wrapper creates event 4 and sends a configuration-selected
Unix socket request. The library's generic listener dispatches a registered
callback; the actual receiver/callback has not yet been identified.
A separate MD5 file-comparison routine exists. Do not conflate it with the
Install wrapper or assert that the backend omits signature verification.

## Current implementation and next phone action

Source branch: `issue-47-sync-agent-receiver-context`.
`watch3_r08_fota_framework_context.py` verifies the existing original library
locally, reads its exact initialization XML, follows declared absolute XML
references under the OMA config root, and captures any explicitly declared
system ELF candidates. It uses the existing native bounded RECV transport,
prints progress and preserves private originals/report/diagnostic ZIP.
16 XML / 4 ELF limits, no entities/relative-path guesses/command execution.

The exact root XML is referenced by original code at `0x483ac` and passed
to initialization at `0x483ae`; its files are not yet acquired. This bundles
the declared context into one owner run instead of requesting each path
separately. The existing five-file handoff mode and 8 KiB limit are preserved.
The generic analyzer also gains the pinned sync-agent profile and explicitly
reports libgcrypt digest/HMAC imports apart from signature checks.

[Original review and next one-run command](docs/watch3-r840x-sync-agent-install-path.md).
Physical context acquisition remains pending the owner's phone run. This
workspace has no authenticated direct connection to the watch. Do not repeat
the completed library capture or the earlier unavailable cache-helper query.

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
- Separate Install reaches sync_agent_dm_fota_install, now acquired and traced
  to an IPC request. The receiving callback/configuration is the missing boundary.
- Failed preparation/recovery-script sync reads remain ambiguous. The TV
  tar route lacks sdbd-tarlauncher; R500/retail firmware observations do not
  establish exact-R840X compatibility.

[Detailed original-code findings](docs/watch3-r840x-consumer-trust-boundaries.md).
PR #122 removed hard-coded flash_allowed/NO_GO permission-like output;
existing evidence remains valid.

## Validation and remaining work

Local focused suite: 205 passing cases, one compiler-only fixture skipped
because clang/lld are absent locally. CI requires all 206 cases including
the cross-compiled ARM/readelf fixture, plus two real private D-Bus tests
and one real systemd test on Ubuntu 22.04 and 24.04 without skips.
Fake-SDB context tests verify complete chained RECV, source pinning, diagnostic
ZIPs, read/encoding/ELF errors, private values, cycles and file/byte limits.
Those fixtures do not establish a physical receiver or a working unlock.
Samsung originals are not committed, executed or uploaded to CI.

The original library has been acquired and examined. Its receiving updater
and full validation behavior remain open. Exact R840X S-BOOT,
complete signed rescue firmware or verified compatible replacement,
unsigned-kernel acceptance and tested return to stock remain missing.
Issue #47 stays open. This context reader changes no firmware or service state.

Android/Termux only, free only, no PC or hardware purchases.
Earlier merged remote branches remain retained: direct Git deletion has no
authentication and the connector exposes no delete-ref operation.
Do not discard unpreserved owner work.
