# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Objective: verified stock recovery/restoration and
UgLy|OS custom boot on the owner's SM-R840X, NOBLESSE-LARGE-BT R08,
R840XXXU1AUA2, CSC PAP candidate. Root, bootloader unlock, custom boot and
restoration remain unverified. Owner authorization is established. Termux/
Android only, free only, no PC/hardware purchases. Preserve the working watch.

## Current device result

Base main inspected: `b86ebb5`, PR #132 merged. No overlapping open PR.
New owner watch3-security-metadata-home.zip: 3,464 bytes, SHA-256
83c297b4743a3d56a9f40f5ae80c4932171385a9654d96becf1d1d8c19bd25ec.
Five members independently checked/preserved privately. Report SHA-256
ce5d5508bb8d73b17b847e8c276d2c7e47fe6f341febaf40d719a29314f26726;
native 2,226-byte response 45bf249e8ccc0a9c631ac5548bd75232060a2fd5c888cafc7e744a181168f6bd.
Production parsers reproduce preflight/probe objects; cleanup marker matches.

NATIVE_SECURITY_METADATA_CAPTURED on actual watch. Canonical share directory
/opt/usr/home/owner/share, /opt/usr rw,nosuid without noexec. Our 7,444-byte ARM
program ran as UID/EUID5001, User::Shell, 25 groups with no1051. Effective and
permitted caps0, inheritable00000000002000c2 (bits1 DAC_OVERRIDE,6 SETGID,
7 SETUID,21 SYS_ADMIN). Inheritable bits are not usable permission by themselves.

All eight target security.capability attributes return ENODATA(-61). Consumer,
OMA-DM and scripts label _, no exec label; launch_app label User::Shell and
exec label User (MAC attribute, not root). Fixed executable/script write checks
EROFS(-30); FOTA/save label User::App::Shared returns write-check0; recovery
label _ returns EACCES(-13). No archive/file created in FOTA or recovery dirs.
No vendor execution, FOTA action, root switch, partition read or firmware write.

Completed native root:on denied; do not retry. Completed cat/RECV denials,
FUMO/receiver captures and metadata runs remain preserved. Missing SDK paths
and /tmp noexec diagnosed; stop repeating them. Native execution/cleanup now
physically works. Root, kernel acceptance, recovery/restoration still unproved.

## Implementation and next physical input

Source branch: issue-47-physical-privilege-inventory.
Implementation PR: #133. Physical inventory/original-input execution pending.
Extend the existing controller with --privilege-inventory, reusing proven
canonical preflight/upload/cleanup. Native profile adds only read/query
getdents64/lstat64/prctl GETs to enumerate six fixed system-helper directories,
nonrecursively. Report setuid/setgid and capability-bearing regular files,
mode/owners/64-bit sizes, access checks, label/exec-label values and process
no-new-privileges/securebits/bounding queries. Do not execute discovered helpers.

Limits/errors/truncation explicit, synthetic fixtures rejected. Same command,
after verified probe cleanup, copies launch_app plus selected bounded original
helpers (up to8, 2MiB each) via RECV only. Validate observed paths, ARM ELF32,
known size/hash; retain denied/invalid copies. Fixed systemctl show privilege
settings and fota-consumer unit cat supply service context without activation.
No remount, identity/cap/label changes, update archive or firmware access.

[Physical evidence and current phone command](docs/watch3-r840x-privilege-inventory.md).
Fresh inventory output names preserve older ZIPs. Phone clang already works.
Cloud cannot authenticate to the watch; this inventory/original-input upload
is the physical dependency. Static matches are candidates, not privilege proof.

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

Host and required ARM/QEMU tests use real directories, mode/owner/stat64,
positive user xattrs, symlink rejection, >4GiB sparse-file sizes, record limits
and synthetic markers. Exact production inventory profile also runs in QEMU.
Capability decoding covers revisions1/2/3, error-vs-absence and rootid retention.
Protocol checks cover bounded input copies/private ZIP, unsafe records, denied
ELF reads, copy budget, cleanup and no follow-up after cleanup failure. Existing
metadata/ARM/noexec regressions remain. No Samsung binary runs or goes to CI.
Local focused suite: 271 tests, passing with four unavailable ARM/noexec checks
skipped locally. The updated host inventory/bounds fixtures also pass. Required
ARM/QEMU CI also passed: run41071961281, code head5423b9d, all271 focused +
2 private D-Bus +1 real systemd tests on both Ubuntu versions (274 per OS,
no skips). Logs confirm exact ARM inventory/profile ABI, real >4GiB stat64,
xattr/output bounds and original-copy/cleanup regressions. Integration and the
owner's new inventory command remain to be verified.

Pending: physical privilege inventory and selected helper originals, actual
privilege-gain path, archive/caller/MAC validation, exact R840X S-BOOT/boot/
recovery originals, verified rescue, custom boot acceptance and restoration.
Issue #47 stays open. No unlock/root/recovery success claim is supported.
Remote merged-branch deletion unavailable through current connector/Git
credentials. Preserve owner work and unrelated-project independence.
