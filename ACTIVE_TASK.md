# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Issue #47: restore stock reliably and boot UgLy|OS
on the owner's SM-R840X / NOBLESSE-LARGE-BT R08, R840XXXU1AUA2, CSC PAP candidate.
Root, bootloader unlock, custom boot and tested restoration remain unverified.
Owner authorization is established. Android/Termux only, free only, no PC or
hardware purchases. Preserve the single working watch and existing evidence.

## Current evidence and actual-code review

Base main `d0843c6` contains PR #127. No overlapping open PR was present.
The owner supplied `watch3-firmware-focus-evidence.zip`, SHA-256
`461b424a40ef512b4bdca83fcfa6ab8682a7202226a5b643e8e6eb98c10cdabb`.
All three members match the report: FIRMWARE_FOCUS_CAPTURED, 5,032-byte FUMO
plugin and 1,058-byte DER public certificate. Originals stay private.

FUMO SHA-256 `e3993a58bfc904730a0e753de188e5ab61cef7fb9e52de75899270477ed99458`;
build ID `06d04977f8e458215a73fa1153ff9795896b3bf6`. Four exports implement
server-list/MO metadata and logging stubs. All 17 selected immediate calls
match independent Thumb/Capstone decoding and original PLT/GOT: only logging,
malloc, calloc and strcmp. State uses the literal 10 plus NUL, not live status.
The pinned fumo-plugin analyzer exposes these exact exports. No code executed.

Certificate SHA-256 `196a09eb31f957fcca49bae20c427070c38cca59cddefaf1874ab2173c20a70c`;
RSA-2048 public CA, self-issued, self-signature verified with SHA-512/RSA.
Encoded validity 2013-11-21 through 2068-08-24. No private signing key and no
package-acceptance or watch-clock observation. Do not confuse the certificate's
own signature algorithm with the update archive's digest algorithm.

Earlier receiver ZIP `b07635c3...` remains preserved. Pinned daemon
`32057c3b...` registers event 4 at callback code 0x23748. Further original-byte
checks map task ID 8 registration/request to callback 0x1feac, then selected
state-dependent segments through service_engine_start, fumo_exec and firmware
update/state operations. Eight more calls, two PLT/GOT bindings, one callback
literal and both task-ID instructions match. Complete live dispatch is open.

Daemon _pre_update_client verifies its pre_update.tar through certificate and
EVP_PKEY verification before executing the inner helper; outer parsing precedes
that check. The device plugin's failure branch rejoins later preparation.
The standalone consumer helper is a separate implementation. Neither the check
nor continuation proves whole-firmware acceptance or a bypass.

[Original-code review](docs/watch3-r840x-omadm-install-verification.md).

## Current implementation and next physical run

Source branch: `issue-47-native-root-recovery`.
The new native-root entry point explicitly requests Tizen's normal root:on
service at most once; this is an account-mode change request, not a read-only
claim. Existing metadata/context collectors never invoke it. Fresh authenticated
id -u and /proc/self/status UID/EUID reads establish actual root, independently
of the service message/capability flags. No root or unlock has yet been observed
on the owner's watch through this mode.

If root is verified, it automatically rechecks p13 boot/p14 recovery labels and
geometry against earlier kernel observations, then requests read-only full
18 MiB copies of each. Truncated/oversized copies are not published. It then
copies recovery-update.sh, rw-update-prepare.sh and the LIST-observed OMA-DM unit.
The shared bounded decoder supports this explicit larger cap; previous ELF/
metadata limits remain. No payload, SDB SEND, service activation, reboot or
firmware write. Root-mode persistence and stock restoration are not assumed.

The phone run/upload remains necessary: this workspace has no authenticated
watch connection. Use the one command in the
[native root/backup guide](docs/watch3-r840x-native-root-and-backup.md).
Fresh output folder/ZIP preserve all previous captures, including diagnostics
if root is refused. Do not repeat completed FUMO/library/context acquisitions.
Old preparation-script failures were ambiguous; retry is now conditional on
new, verified root access, rather than an identical unprivileged request.

## Validation and unresolved project goals

Local focused suite: 234 passing cases plus one compiler-only fixture skipped
because clang/lld are absent locally. CI requires all 235 cases including
the compiled ARM/readelf fixture, plus two real private D-Bus and one real
systemd test per Ubuntu 22.04/24.04, with no skips. New fake-SDB cases verify
root-message/UID disagreements, control-stream close, already-root behavior,
identity fallback, diagnostics, geometry rejection, complete conditional copies,
incomplete images and larger bounded transfer with legacy limits intact. Fixtures do
not establish a physical receiver, exploit, bootloader unlock or recovery.

Preserved earlier evidence: authenticated non-root ARMv7 Tizen Wi-Fi SDB,
Linux 4.9.59, 21 partition names and critical sysfs geometry; original
fota-service, fota-consumer and libsync-agent; consumer configured fota:fota,
inactive/dead, no current D-Bus owner in the earlier snapshot. The owner
completed only ODIN/LOKE handshake, then returned to stock. Historical R500
and retail firmware findings do not establish exact-R840X compatibility.

Remaining: physical native-root result, full firmware verification and runtime privilege,
exact R840X physical S-BOOT/boot/recovery bytes, complete signed rescue or
verified compatible replacement, custom-kernel acceptance and tested stock
restoration. Issue #47 stays open. PR #122 removed hard-coded NO_GO permission-like
output; evidence flags describe observations, not authorization.

Earlier remote branches remain retained because direct Git deletion has no
authentication and the connector lacks delete-ref. Do not discard owner work.
