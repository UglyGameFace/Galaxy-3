# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Objective: verified stock recovery/restoration and
UgLy|OS custom boot on the owner's SM-R840X, NOBLESSE-LARGE-BT R08,
R840XXXU1AUA2, CSC PAP candidate. Root, bootloader unlock, custom boot and
restoration remain unverified. Owner authorization is established. Termux/
Android only, free only, no PC/hardware purchases. Preserve the working watch.

## Current device result

Base main inspected: `e76a94d`, PR #129 merged. No overlapping open PR.
New owner upload watch3-recovery-shell-evidence.zip: 3,325 bytes, SHA-256
cde1834a01caba62970d6ac6946027908386af98ad82d292a1454bd86a4fa33e.
All nine members match the 3,637-byte report/hash; preserved privately.

Three scripts exist but cat explicitly denied access: recovery-update.sh
0550 uid200:gid1051 / 8,339 bytes; rw-update-prepare.sh 0550 200:1051 /
664 bytes; rw-update-systemd.sh 0700 0:0 / 7,706 bytes. OMA-DM unit also
permission-denied, 0700 200:200 / 453 bytes. Consumer and daemon ELF paths
are 0755 200:200, lengths agree with pinned originals. Archive save directory
0777 2201:1051; recovery directory 0770 200:1051. DAC mode is not effective
SMACK writability. No archive write occurred. Shell label User::Shell.
getcap is missing, not proof of absent capability attributes.

All five queried units loaded/inactive/dead, MainPID=0. Both updater daemons
configured fota:fota; rw-update root:root, recovery-update empty/default,
update-service app_fw:app_fw via launch_app. Bounding mask all bits is only a
ceiling, not granted capabilities. NoNewPrivileges=no grants nothing. Prior
recovery-update exit0 does not prove recovery boot/restoration. fota last
exit44 cause unestablished. Account mappings for numerical owners not attested.

Prior normal root:on was explicitly denied: UID/EUID5001, GIDs100, CapEff0
before/after, both root flags disabled. No partition read. Do not repeat the
normal switch or identical cat/RECV acquisitions without changed evidence.

## Implementation and next physical input

Source branch: issue-47-native-privilege-metadata.
Add our static ARM EABI metadata reader to replace unavailable getcap. Fixed
read/query calls: UID/EUID, groups, capget, getxattr, current label and access.
Fixed targets: six updater executables/scripts and two directories. Bounded
security.capability/SMACK64/SMACK64EXEC values preserve bytes/errno. No capset,
setuid, setxattr, ioctl, mount, FOTA action or vendor-script execution.

The phone controller builds from our source using Termux clang/lld, validates
static ARM ELF, derives/validates the advertised SDK home/tmp directory,
creates one random private child, SENDs/runs only our small metadata reader,
then removes only that file and empty child. This is an explicit temporary
SDK write/execute operation, not entirely read-only. No firmware/partition
write or attribute modification. No unverified pre-existing directory removal.
Failures preserve private responses, exact uncertain stage and diagnostic ZIP.
Cleanup is separately verified; no silent success if cleanup fails.

[Actual evidence, native probe and one command](docs/watch3-r840x-security-metadata.md).
This workspace cannot authenticate directly to the watch; phone build/run/
upload is the physical dependency. Do not repeat completed root/FUMO/receiver/
shell captures. Determine real capabilities, exec labels, supplementary groups
and non-mutating directory access before proposing an active updater path.

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

Host C tests exercise real positive/oversized xattrs; fake-SDB cases exercise
bounded SEND, validated stage roots, acquisition/cleanup, upload/run errors,
uncertain creation and cleanup failure, private/exclusive failure archives.
Required CI compiles/runs the ARM ABI under QEMU with real xattr fixtures;
fixture output is marked synthetic and rejected by production parsing.
Original Samsung code is never executed/committed or sent to CI. This proves
probe/protocol behavior only, not physical root or recovery.

Pending: phone build/native metadata result, writable archive/caller/MAC
boundaries, full validation chain, exact R840X S-BOOT/boot/recovery originals,
verified rescue, custom boot acceptance and restoration. Issue #47 stays open.
No unlock/root/recovery success claim is supported. Retire merged local
branches safely; remote deletion unavailable through current connector/Git
credentials. Preserve owner work and do not lock unrelated conversations.
