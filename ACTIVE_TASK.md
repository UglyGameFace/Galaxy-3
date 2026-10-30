# UgLy|OS R840X bootloader and recovery

Updated October 29, 2026. Issue #47: restore stock reliably and boot UgLy|OS
on the owner's SM-R840X / NOBLESSE-LARGE-BT R08, R840XXXU1AUA2, CSC PAP candidate.
Root, bootloader unlock, custom boot and tested restoration remain unverified.
Owner authorization is established.

## Current physical result and original-code review

Base main `40cdf13` includes PR #125. Library and root initializer capture
succeeded. No overlapping open PR was present. Original library upload:
`watch3-sync-agent-native-evidence.zip` SHA-256:
`331b97505a06dc0a3c8dd45cf08b3e42d269151f9e1dd1f756818eb5c8ba374e`.
It contains the 4,211-byte report and 647,076-byte ARM ELF32 library copied
from `/usr/lib/libsync-agent.so.0`, SHA-256:
`3fbebb3d55a7e6a132f3516af88280e63278a4b3bf51cb61cca194614b605a97`.
GNU build ID: `07783d299457ad74f7c232f1941446060aa6a1a9`.

New upload `watch3-sync-agent-context-evidence.zip`, SHA-256:
`6ce5c08e884046ea257082ceb09bb6222061f8889c763c1ecb47db66ccff873b`.
It contains only the 872-byte report and 384-byte initializer, SHA-256:
`29ab3dea6bfa21a28d7d148f943485fca7779df54c3ca9df276aea01c4939b92`.
The XML selects Event-Key=omadm and RunEventHandler=0. Event-Config and
Noti-Config point to extensionless files under /usr/share/oma-dm-cfg/ipc.
V1's .xml-only assumption skipped both. Its CONTEXT_CAPTURED state proves
only the root XML copy, not complete receiver context. Preserve that upload.

Actual-byte review now matches 36 immediate calls with independent decoders,
26 PLT/GOT relocations, 11 control/argument instructions and 5 literals.
The public Install wrapper creates event 4 and sends a configuration-selected
Unix socket request. The library's generic listener dispatches a registered
callback; the configured endpoint derives to /tmp/agent_fw_event_omadm.
The library checks RunEventHandler against 1 and does not start its generic
listener for this initializer's 0 value. The extensionless event definition
is loaded through fopen/fscanf, not an XML parser. Actual live receiver,
callback, privileges and validation behavior have not yet been identified.
A separate MD5 file-comparison routine exists. Do not conflate it with the
Install wrapper or assert that the backend omits signature verification.

## Current implementation and next phone action

Source branch: `issue-47-omadm-receiver-capture`.
`watch3_r08_fota_framework_context.py` verifies the existing original library
locally, reads its exact initialization XML, follows declared absolute config
references including the extensionless event/notification files, and stores
those text definitions as opaque bytes. Native LIST now discovers actual
OMA-DM/sync-agent-family units, /usr/bin entries and fw-init files. Captures
observed code candidates plus normal executables declared by unit ExecStart
or XML, using established validators/RECV. No service or event is invoked.
Schema v2 reports discovery, copied-by-kind counts and candidate-code status;
runtime_receiver_observed remains false. Fresh receiver output folder/ZIP
preserve the successful root XML and earlier original library.
Bounds: 16 XML / 8 config / 8 unit / 4 ELF; no entities or path/command guessing.

The exact root XML is referenced by original code at `0x483ac` and passed
to initialization at `0x483ae`; the exact initializer is now acquired. Both
declared extensionless paths were confirmed by running the corrected parser
on those actual 384 bytes. The existing five-file handoff mode, its 8 KiB
limit and default directory inventory scopes are preserved. Only the explicit
context capture uses receiver-family discovery.

[Original review and next one-run command](docs/watch3-r840x-sync-agent-install-path.md).
Expanded receiver acquisition remains pending the owner's phone run. This
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

Local focused suite: 210 passing cases, one compiler-only fixture skipped
because clang/lld are absent locally. CI requires all 211 cases including
the cross-compiled ARM/readelf fixture, plus two real private D-Bus tests
and one real systemd test on Ubuntu 22.04 and 24.04 without skips.
Fake-SDB context tests verify the real initializer's extensionless shape,
complete native LIST/RECV discovery and unit-declared libexec capture, source
pinning, diagnostic ZIPs, read/encoding/ELF errors, privacy and bounded cycles.
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
