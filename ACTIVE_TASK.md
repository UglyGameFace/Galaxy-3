# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Issue #47: restore stock reliably and boot UgLy|OS
on the owner's SM-R840X / NOBLESSE-LARGE-BT R08, R840XXXU1AUA2, CSC PAP candidate.
Root, bootloader unlock, custom boot and tested restoration remain unverified.
Owner authorization is established. Android/Termux only, free only, no PC or
hardware purchases. Preserve the single working watch and existing evidence.

## Current original capture and findings

Base main `c84e40a` contains PR #126. The owner supplied
`watch3-sync-agent-receiver-evidence.zip`, SHA-256
`b07635c319f89c64daef262e6fac700af785cb3c852a342e6f3bd310e77ccdc9`.
Its 14 members contain a 16,247-byte report and 13 original copied files:
seven XML, two opaque config and four ARM ELF32 binaries. All member paths,
lengths and hashes were verified. Originals remain private and unexecuted.

The captured daemon `/usr/bin/oma-dm-agent` is 525,584 bytes, SHA-256
`32057c3ba2537b2632a5d73dc1397b919ad3bf9c58c446b11e48e3837ab99a05`.
The DM device plugin is 36,184 bytes, SHA-256
`98c21b99b0c443e75f42e00cc990f6e4374fa8c398f8d3e8c82a4585d9f2f357`.
The backend initializer is 5,296 bytes, SHA-256
`f8ba15dde1bca536e16ee08149206d428b605e839667151a3d55056c49a7500e`.

The event file labels event 4 EVENT_INSTALL. The daemon's bounded TBB entry
and callback setter register Thumb pointer 0x23749 / code 0x23748 for event 4.
The callback opens a management object and requests an asynchronous FUMO task.
The backend initializer selects Event-Key=omadm, RunEventHandler=1; main
references that exact XML. This identifies a static registration, not a live
receiver or UID. The complete async dispatch remains open.

Daemon _pre_update_client at 0x187e8 calls verify_FOTA_image at 0x188ea,
using /usr/share/oma-dm-cfg/certi/FOTA_ROOT.cer. Actual calls and branches
check X509_verify_cert and EVP_PKEY_verify before extracting/executing the
inner pre_update_client_2. Outer archive parsing occurs before that check.
This daemon implementation differs from the standalone fota-consumer helper.
The device plugin's nonzero-helper-return path rejoins later update preparation;
the helper signature check alone does not establish whole-update abortion.
This continuation is also not proof of unsigned-firmware acceptance.

Private independent review: 25 immediate calls match standard-library decoding
and Capstone; 18 PLT/GOT bindings, seven branches, eight literals and the event-4
TBB entry match original bytes. readelf confirms metadata/build IDs/symbols.
The analyzer now pins both originals and reports the formerly omitted
EVP_PKEY_verify / X509_verify_cert imports. No absence inference is valid from
the earlier narrow allowlist.

[Detailed review and next command](docs/watch3-r840x-omadm-install-verification.md).

## Next physical input: firmware focus

Source branch: `issue-47-fumo-signature-boundary`.
The four-ELF limit consumed the daemon, HTTP and two device plugins. It did
not attempt the backend-declared MO/FUMO plugin:
`/usr/lib/sync-agent/dm-private/libplugin-mo-fumo.so`.
Native LIST observed the 453-byte oma-dm-agent.service, but its RECV returned
REMOTE_MISSING_DENIED_OR_UNREADABLE; the failure reason is not resolved.

The existing context reader's --firmware-focus option verifies the existing
library, daemon and backend config before connecting, derives the unique FUMO
plugin from that exact XML, and copies only that plugin plus the daemon's
referenced public certificate. Two bounded RECV operations, no rediscovery.
Fresh default folder watch3-r840x-firmware-focus-evidence; explicit ZIP in
Downloads. Failures retain partial files and a diagnostic report/ZIP.
No watch shell, helper execution, service/event invocation or firmware write.
Original captures and the phone's SDB key remain untouched.

The phone run/upload remains necessary: this workspace has no authenticated
watch connection. Do not repeat the completed broad capture, old library
capture, unavailable cache-helper query or ambiguous preparation-script read.

## Validation and unresolved project goals

Local focused suite: 219 passing cases plus one compiler-only fixture skipped
because clang/lld are absent locally. CI requires all 220 cases including
the compiled ARM/readelf fixture, plus two real private D-Bus and one real
systemd test per Ubuntu 22.04/24.04, with no skips. New fake-SDB cases verify
two-file selection, source pins, bounded diagnostics, private ZIPs, no discovery,
unchanged prior captures, and invalid/deceptive local manifests. Fixtures do
not establish a physical receiver, exploit, bootloader unlock or recovery.

Preserved earlier evidence: authenticated non-root ARMv7 Tizen Wi-Fi SDB,
Linux 4.9.59, 21 partition names and critical sysfs geometry; original
fota-service, fota-consumer and libsync-agent; consumer configured fota:fota,
inactive/dead, no current D-Bus owner in the earlier snapshot. The owner
completed only ODIN/LOKE handshake, then returned to stock. Historical R500
and retail firmware findings do not establish exact-R840X compatibility.

Remaining: full FUMO/firmware verification chain and runtime privilege,
exact R840X physical S-BOOT/boot/recovery bytes, complete signed rescue or
verified compatible replacement, custom-kernel acceptance and tested stock
restoration. Issue #47 stays open. PR #122 removed hard-coded NO_GO permission-like
output; evidence flags describe observations, not authorization.

Earlier remote branches remain retained because direct Git deletion has no
authentication and the connector lacks delete-ref. Do not discard owner work.
