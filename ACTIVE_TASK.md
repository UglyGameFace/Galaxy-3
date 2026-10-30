# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Objective: verified stock recovery/restoration and
UgLy|OS custom boot on the owner's SM-R840X, NOBLESSE-LARGE-BT R08,
R840XXXU1AUA2, CSC PAP candidate. Root, bootloader unlock, custom boot and
restoration remain unverified. Owner authorization is established. Termux/
Android only, free only, no PC/hardware purchases. Preserve the working watch.

## Current device result

Base main inspected: `4b5b2e9`, PR #130 merged. No overlapping open PR.
The new watch3-security-metadata-evidence.zip is 884 bytes, SHA-256
be7b2b5349c39ab81c4d6c40a96d2050976aa9ca69e382c1ebd5667d998f238b.
Both original members are preserved privately. Report 874 bytes, SHA-256
447d90baf5c5402d6c0e23bf0e7d75b262d648fc97732341ac313d75221cb131.

The phone successfully built the unchanged ARM reader: 7,444 bytes, SHA-256
76f8f1df022a7dc3e4d0b7864dae2c7434850c8175006c40bf99b9c92e4e82e8.
The advertised /home/owner/share/tmp/sdk_tools path could not host the random
child: mkdir explicitly returned No such file or directory (142-byte response,
SHA-256 14df1545ac823d62661ca68f27a7f3a317d4d8f81cfb1d912a4dc0b0d4541039).
This is a missing parent/path component, not a probe execution denial. No
program uploaded/executed, no native attribute result, no created child to
remove from that attempt. No root/partition/firmware operation occurred.

Earlier shell capture: all three recovery scripts and OMA-DM unit exist but
cat is permission-denied. Scripts 0550 200:1051 / 8,339 and 664 bytes, and
0700 0:0 / 7,706 bytes. Consumer/daemon 0755 200:200. Archive directory
0777 2201:1051; recovery directory 0770 200:1051. DAC mode is not effective
SMACK writability. Shell label User::Shell. getcap is missing, not absent
capabilities. All five queried updater units inactive/dead, MainPID0. fota
units configured fota:fota; rw-update root:root; recovery-update default;
update-service app_fw:app_fw. Configured capability ceiling is not a grant.

Prior root:on explicitly denied, UID/EUID5001 and CapEff0 before/after,
root flags disabled. Do not repeat that switch, cat/RECV, or completed FUMO/
receiver/shell captures without changed evidence. Numerical file owners have
not been independently mapped to accounts. No exact stock rescue is verified.

## Implementation and next physical input

Source branch: issue-47-metadata-stage-fallback.
Fix the real staging failure in the existing controller. Try at most three
validated locations: advertised SDK directory; immediate parent only for an
sdk_tools final segment; /tmp. Create only a new random mode0700 child under
an existing parent. No mkdir -p, parent creation, traversal or permission/
attribute changes. Explicit missing-parent/failed-mkdir markers allow fallback.
Unknown creation/transport results stop fallback without deleting unknown dirs.

Only our compiled fixed ARM metadata program is uploaded. A refused upload or
invalid/denied execution response can retry only after verified cleanup of
that known-created child. Cleanup failure stops fallback. Separate private
responses/report fields retain every attempted stage and exact residual paths.
Unsuccessful staging also collects fixed read-only id/directory/mount context.
The ARM reader and its syscall/target allowlists are unchanged. Compiler errors
still make no watch contact. No root/FOTA/vendor-script/partition/firmware action.

[Evidence, implementation and fresh-name retry command](docs/watch3-r840x-security-metadata.md).
Phone clang already worked; do not ask to reinstall it. Preserve original
local evidence; retry uses a distinct output folder and Downloads ZIP. Cloud
cannot authenticate to this watch; the phone run/upload is the physical input.
Determine real caps, exec labels, groups and permission checks before choosing
an active updater path. Metadata capture alone is not root or an unlock.

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

Regression checks exercise real shell/filesystem missing-parent/existing-child
behavior, actual advertised-path fallback through fake SDB, denied execution
cleanup before retry, bounded/deduplicated candidates, private failure context,
transport/cleanup failures stopping fallback, and cleanup despite local write
failure. Existing host xattr tests and required ARM/QEMU CI remain in place.
No Samsung binary is executed/committed or sent to CI. Tests establish the
controller/probe behavior, not physical root or bootloader acceptance.

Pending: phone metadata retry, writable archive/caller/MAC boundaries, full
validation chain, exact R840X S-BOOT/boot/recovery originals, verified rescue,
custom boot acceptance and restoration. Issue #47 stays open. No unlock/root/
recovery success claim is supported. Remote merged-branch deletion unavailable
through current connector/Git credentials; preserve owner work.
