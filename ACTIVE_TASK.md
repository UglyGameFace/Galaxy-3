# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Objective: verified stock recovery/restoration and
UgLy|OS custom boot on the owner's SM-R840X, NOBLESSE-LARGE-BT R08,
R840XXXU1AUA2, CSC PAP candidate. Root, bootloader unlock, custom boot and
restoration remain unverified. Owner authorization is established. Termux/
Android only, free only, no PC/hardware purchases. Preserve the working watch.

## Current device result

Base main inspected: `6a0e29b`, PR #131 merged. No overlapping open PR.
New owner watch3-security-metadata-retry.zip: 2,730 bytes, SHA-256
57510e26112229cda3b02a194fc964801f57040047cbda5fdc6849bdcad31959.
All seven members checked/preserved privately. Report 1,573 bytes, SHA-256
9b01a142c1c500502a890399a4dd80ad981a482a2574e39490e1d71b3f37e8bb.

Phone compiled same 7,444-byte ARM ELF. SDK directory and immediate parent
absent. /tmp stage creation, SDB upload and exact cleanup succeeded. Execution
returned Permission denied (89 bytes); current mount table explicitly marks
/tmp rw,nosuid,nodev,noexec. That is sufficient to prevent execve regardless
of 0700 mode; it does not prove an additional MAC restriction or bad binary.
No probe metadata, root, FOTA call, vendor-script execution or firmware write.

The 3,387-byte context independently supplies UID5001(owner), primary GID100,
25 supplementary groups, none 1051, and User::Shell. Combined with earlier
0550 uid200:gid1051 recovery/prepare script modes, DAC explains cat denials.
UID200 account mapping and executable capability attributes remain unknown.
Owner home exists 0750 5001:1051, share exists 0775 5001:100. /opt and /opt/usr
are rw ext4 without noexec; / is ro. Home/share's canonical path was not read,
so select a stage from fresh resolved-path and mount evidence, not assumptions.

Earlier native root:on explicitly denied, UID/EUID5001 and CapEff0 before/
after, root flags disabled. All queried updater services inactive/dead. Keep
completed root/cat/RECV/FUMO/receiver/shell captures; do not repeat without new
evidence. No exact R840X rescue, raw bootloader/boot/recovery originals or
custom kernel acceptance is yet established.

## Implementation and next physical input

Source branch: issue-47-mount-aware-metadata-stage.
Replace the three-location upload fallback with one evidence-selected stage.
Fixed read-only preflight checks SDK path plus existing owner/share spellings,
readlink canonical resolution, directory write/search tests and current
/proc/self/mountinfo. Reject noexec/ro/denied/missing/out-of-root/ambiguous
parents before any mkdir or upload. Canonical roots include /home, /opt/home
and /opt/usr/home owner/SDK names. No ancestor walk or parent creation.

One eligible canonical parent, one random mode0700 child, one upload/run.
No automatic retry after failure. Native fixed metadata reader unchanged.
Keep raw preflight and precise selection reasons privately. An execution
refusal also records staged-file mode/owner and ls label diagnostics before
cleanup. Remove only our known-created file/child; uncertain creation is
never deleted, cleanup failure retains exact path and overrides success.
Compiler failure still makes no watch contact. No remount, root, label/cap
change, FOTA method, partition access or firmware modification.

[Current evidence and fresh-name phone command](docs/watch3-r840x-security-metadata.md).
Phone clang already compiled successfully. Preserve both previous evidence
folders/ZIPs. New home-evidence folder/ZIP avoids collisions. The cloud cannot
authenticate to the watch; phone execution/upload is the physical dependency.
Mount eligibility is not proof of MAC-approved execution or root/unlock.

## Preserved reverse engineering

Original FUMO plugin supplies metadata/logging (17 verified immediate calls),
not install logic. Original public CA has RSA-2048 key and verified self-
signature, no signing private key. Original daemon registers Install event4,
task8 callback0x1feac with selected state-dependent update segments reviewed.
Daemon pre-update helper verifies nested archive before inner execution; outer
parsing precedes check. Standalone consumer helper differs. Device-plugin
helper failure rejoins preparation. No whole-firmware bypass proven.
[Detailed original review](docs/watch3-r840x-omadm-install-verification.md).

Earlier: non-root ARMv7 Tizen SDB, Linux4.9.59, 21 partition labels and critical
kernel geometry. Owner completed only ODIN/LOKE handshake and returned stock.
Historical R500/retail findings do not establish R840X compatibility. No exact
original bootloader/boot/recovery bytes or tested return-to-stock route yet.

## Validation and remaining work

Regression checks cover deepest mount selection/bind flags, canonical paths,
noexec/ro/denied/missing/unsafe/ambiguous cases, malformed preflight without
writes, one selected upload, refusal diagnostics, cleanup/error paths and
exclusive private evidence. Host shell tests use actual symlinks/directories.
Required CI mounts a disposable noexec tmpfs, demonstrates execve EACCES on
our own mode0700 host probe, and removes it. Existing ARM/QEMU and real xattr
checks remain required. No Samsung binary runs or goes to CI.

Pending: phone native metadata capture, archive/caller/MAC boundary evidence,
full validation chain, exact R840X S-BOOT/boot/recovery originals, verified
rescue, custom boot acceptance and restoration. Issue #47 stays open. No
unlock/root/recovery success claim is supported. Remote merged-branch deletion
is unavailable through the current connector/Git credentials; preserve owner
work and keep unrelated projects free to proceed.
