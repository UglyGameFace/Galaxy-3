# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Objective: verified recovery/stock restoration and
UgLy|OS custom boot on the owner's SM-R840X, NOBLESSE-LARGE-BT R08,
R840XXXU1AUA2, CSC PAP candidate. Root, bootloader unlock, custom boot and
restoration remain unverified. Owner authorization is established. Termux/
Android only, free only, no PC/hardware purchases. Preserve the working watch.

## Current physical result

Base main inspected at start: `2ee0f74`, merged PR #128. No overlapping open
PR was present. New owner upload `watch3-native-root-evidence.zip`: 666 bytes,
SHA-256 `aa0ab67fd0d941ceb955e63fb745b40a1e929194fdf3cd7dd570451b0360db70`.
Its sole 1,560-byte report has SHA-256
`f2f6cee9639a909acb053fe2aa47c81d93f0474d02d4ea067354234bc0d747bf`.
Inventory/hash verified and preserved privately.

Result NATIVE_ROOT_NOT_GRANTED. Board matched; advertised sdbd_rootperm and
rootonoff_support disabled. One root:on request explicitly denied. Before and
after: UID 5001, UID tuple [5001,5001,5001,5001], GIDs [100,100,100,100],
CapEff 0000000000000000, standard shell. No partition read, script acquisition,
service activation, FOTA call or firmware write. Do not repeat the closed native
root switch without a relevant change/different evidenced route. This is an
actual device denial, not an owner-permission policy or collector failure.

## Current implementation and next physical input

Source branch: `issue-47-recovery-shell-access`.
Earlier recovery-script failures came only through sync RECV and combined
missing/denied/unreadable into one result. Ordinary shell access is now proven
by the native-root identity reads. That does not prove ordinary cat can read
the scripts; it is the next distinct access boundary to test.

Extend the authoritative recovery-script reader with --shell-context rather
than creating another collector. Eight fixed reads cover the three original-
unit/binary referenced scripts, the observed OMA-DM unit, file/directory stat,
getcap, current SMACK label and updater systemctl show settings. Shared native
stream code can return bytes without UTF-8 replacement; prior string callers
and default sync-RECV behavior remain. Script paths are centralized. No root
request, recovered-script execution, unit start or partition access. Payload
hashes describe shell output, not independent disk hashes/completeness.

Private raw diagnostics remain distinct from script/unit-looking payloads.
The fresh recovery-shell folder/ZIP is created even for failed/partial reads,
without overwriting prior captures. Existing output/private-key behavior stays.
The one phone command is in the
[current recovery guide](docs/watch3-r840x-native-root-and-backup.md#current-next-command-ordinary-shell-recovery-context).
This cloud workspace cannot authenticate directly to the watch. Capture/upload
is the physical dependency. Do not repeat completed native-root/FUMO/library/
receiver capture or identical unprivileged sync-RECV failures.

## Preserved original-code findings

FUMO ZIP `461b424a...` captured the original 5,032-byte metadata plugin and
1,058-byte DER public CA. Seventeen original plugin calls resolve only to
allocation/logging/comparison; State literal 10 is not live status. Certificate
contains an RSA-2048 public key; verified self-signature is SHA-512/RSA, not
proof of update-archive algorithm/acceptance or availability of a private key.

Receiver ZIP `b07635c3...`: original daemon registers Install event 4 at code
0x23748, task ID 8 spec/request callback 0x1feac. Selected state-dependent
segments reach service_engine_start/fumo_exec/update operations. Full live
execution is unobserved. Daemon pre-update helper verifies its nested archive;
outer parsing precedes that check. Device-plugin helper failure rejoins later
preparation. Standalone consumer has a separate helper implementation. Neither
continuation nor a missing local check proves complete firmware acceptance.
[Detailed original review](docs/watch3-r840x-omadm-install-verification.md).

Earlier evidence: non-root ARMv7 Tizen SDB, Linux 4.9.59, 21 partition labels
and critical kernel geometry; original accessory service, consumer and sync
library. Fota-consumer configured fota:fota/inactive with no live owner in the
earlier snapshot. Owner completed only ODIN/LOKE handshake, returned to stock.
Historical R500/retail firmware does not establish exact R840X compatibility.

## Validation, issues and cleanup

Local focused suite: 240 passing cases, one compiler-only fixture unavailable
locally. CI requires all 241 plus two private D-Bus and one real systemd case
per Ubuntu 22.04/24.04, no skips. New fake-SDB cases cover fixed shell-only
requests, byte preservation, cat-error diagnostics, refused/oversized output,
private/exclusive ZIPs and default-mode compatibility. Fixtures do not prove
physical script access or exploitation. Vendor originals stay private and are
not executed, committed or uploaded to CI.

Remaining: physical shell-context result, actual writable archive/caller/MAC
boundaries and complete verification chain, exact R840X S-BOOT/boot/recovery
bytes, a verified rescue route, accepted custom boot and tested restoration.
Issue #47 stays open. No unlock/root/recovery success claim is supported.

Merged remote branches remain retained: direct Git deletion lacks credentials
and the connector has no delete-ref operation. Retire local merged branches
without discarding owner work. Task records do not lock other conversations.
