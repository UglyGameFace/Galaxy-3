# R840X recovery access and native security metadata

Issue #47, October 30, 2026. The ordinary shell capture now confirms that all
three recovery scripts exist and are permission-denied. The native root switch
was also denied. A missing getcap utility leaves actual executable capability
attributes unknown. The next operation replaces that missing utility with our
small ARM metadata reader, compiled on the phone and run in a checked temporary
owner directory. Two original captures now establish why earlier staging did
not execute. This is diagnostic code, not a demonstrated root/unlock procedure.

## Verified original shell capture

`watch3-recovery-shell-evidence.zip`: 3,325 bytes, SHA-256
`cde1834a01caba62970d6ac6946027908386af98ad82d292a1454bd86a4fa33e`.
All nine member names, lengths and payload hashes match the 3,637-byte report,
SHA-256 `329cdd4e1086ab2be35c56c288f023c98ce34f614c6a6ed70005a931892e4976`.
The originals and responses remain private. No script body was recovered.

| Observed path | Mode | UID:GID | Bytes |
| --- | --- | --- | ---: |
| `/usr/bin/recovery-update.sh` | 0550 | 200:1051 | 8,339 |
| `/usr/bin/rw-update-prepare.sh` | 0550 | 200:1051 | 664 |
| `/usr/bin/rw-update-systemd.sh` | 0700 | 0:0 | 7,706 |
| `/usr/lib/systemd/system/oma-dm-agent.service` | 0700 | 200:200 | 453 |
| `/usr/bin/fota-consumer` | 0755 | 200:200 | 89,980 |
| `/usr/bin/oma-dm-agent` | 0755 | 200:200 | 525,584 |
| `/opt/usr/data/fota/save` | 0777 | 2201:1051 | directory |
| `/opt/data/recovery` | 0770 | 200:1051 | directory |

Each script and the OMA-DM unit returned an explicit cat permission denial.
The shell label is `User::Shell`. The directory's DAC mode 0777 does not
establish effective writability under SMACK; no archive was written to test it.
The numerical file owners above have not independently been mapped to account
names. The getcap response is `command not found`, not absent file capabilities.

All five queried units were loaded, inactive/dead with MainPID=0:

| Unit | Configured user/group | Observed executable |
| --- | --- | --- |
| oma-dm-agent | fota:fota | `/usr/bin/oma-dm-agent` |
| fota-consumer | fota:fota | `/usr/bin/fota-consumer` |
| recovery-update | empty/default | `/usr/bin/recovery-update.sh` |
| rw-update | root:root | `/usr/bin/rw-update-systemd.sh` |
| update-service | app_fw:app_fw | `/usr/bin/launch_app` |

These are manager configuration/snapshot observations, not active process
UIDs. Both fota units' last exits reported status 44; this alone does not
explain why they exited. The recovery-update service's earlier exit status 0
does not prove that a recovery image booted or restored the watch. A full
CapabilityBoundingSet is a ceiling, not a grant of effective capabilities;
NoNewPrivileges=no also does not establish privilege escalation.

## First native-reader attempt: advertised directory missing

The owner's `watch3-security-metadata-evidence.zip` is 884 bytes, SHA-256
`be7b2b5349c39ab81c4d6c40a96d2050976aa9ca69e382c1ebd5667d998f238b`.
Its 874-byte report, SHA-256
`447d90baf5c5402d6c0e23bf0e7d75b262d648fc97732341ac313d75221cb131`,
records a successful phone build: 7,444-byte ARM ELF, SHA-256
`76f8f1df022a7dc3e4d0b7864dae2c7434850c8175006c40bf99b9c92e4e82e8`.
The unchanged C source hash is
`a157c47b16c5a30dafeca8d826811812cca02f72227df85335f5861b0706f962`.

The 142-byte `stage-create.response`, SHA-256
`14df1545ac823d62661ca68f27a7f3a317d4d8f81cfb1d912a4dc0b0d4541039`,
explicitly reports `No such file or directory` when creating the random child
under advertised `/home/owner/share/tmp/sdk_tools`. This establishes a missing
parent/path component for that mkdir, not a denied probe execution. No probe
was uploaded or executed; no metadata was captured. That mkdir did not create
the requested child, so no cleanup of that old path is needed. Preserve the
old local evidence; the retry below uses new output names.

## Retry capture: upload worked, /tmp forbids execution

The owner's `watch3-security-metadata-retry.zip` is 2,730 bytes, SHA-256
`57510e26112229cda3b02a194fc964801f57040047cbda5fdc6849bdcad31959`.
All seven members were checked and preserved privately. Its 1,573-byte report,
SHA-256 `9b01a142c1c500502a890399a4dd80ad981a482a2574e39490e1d71b3f37e8bb`,
records the same compiled program, successful creation/upload in `/tmp`, an
execution request, and verified removal of that program and its child directory.
The advertised SDK directory and its immediate parent both remain absent.

The 89-byte execution response explicitly says `Permission denied`; the
3,387-byte context response shows `/tmp` is `rw,nosuid,nodev,noexec`. Linux
[execve](https://man7.org/linux/man-pages/man2/execve.2.html) reports EACCES
for a program on a noexec filesystem. This explains the failure even with
executable mode bits; it does not establish an additional SMACK denial or a
malformed program. The probe did not produce metadata. No root, FOTA action,
partition access, firmware write or security attribute modification occurred.

The context also supplies the previously missing supplementary groups:
UID 5001(owner), primary GID 100(users), 25 listed groups, none equal to 1051.
Together with the earlier 0550 uid200:gid1051 script modes, that explains the
ordinary shell's read denials under DAC. It does not map UID200 to an account
or prove a bypass. The context still reports `User::Shell`.

Existing `/home/owner` is 0750 uid5001:gid1051; its `share` directory is 0775
uid5001:gid100. `/opt` and `/opt/usr` are writable ext4 mounts without noexec;
`/` is read-only. The canonical target of `/home/owner/share` was not captured,
so the next controller resolves that path and reads current mountinfo before
creating/uploading anything. It never remounts or changes labels/permissions.

## Own ARM reader: fixed metadata, reversible staging

`tools/native/watch3_security_metadata.c` has no libc dependency. It uses the
Linux ARM EABI read/query calls for UID/EUID, supplementary groups, capget,
getxattr, access and the current process label. Its only data writes are to
stdout. Fixed targets are the six original/observed updater executables and
the FOTA/recovery directories above. It reads security.capability, SMACK64 and
SMACK64EXEC into bounded buffers, returning raw hex and syscall results. An
error such as EACCES/ENODATA/ERANGE remains distinct; there is no blind absence
inference. access(W_OK) is a non-mutating permission check, not proof that an
archive was successfully created or an update could be triggered.

ABI references: Linux v4.9's
[ARM syscall definitions](https://github.com/torvalds/linux/blob/v4.9/arch/arm/include/uapi/asm/unistd.h)
and [capability structures](https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/capability.h).
The reader does not call setuid, capset, setxattr, ioctl, mount or reboot.

The controller builds a static, bounded ARM ELF from this source with clang/
lld on the phone. The old upload fallback loop is removed. A fixed read-only
preflight checks the advertised sdk_toolpath plus `/home/owner/share` and its
two standard `/opt` home spellings. Shell tests check directory existence,
write/search access; readlink resolves canonical paths. The controller parses
current `/proc/self/mountinfo` and checks the deepest containing mount, including
per-mount and superblock flags. Missing, denied, read-only, noexec, ambiguous or
out-of-scope paths are ineligible. A resolved path must stay within the fixed
owner/SDK home roots; no traversal, arbitrary destination or ancestor walk.

The controller selects one eligible canonical parent and makes one staging
attempt. It creates only a new random mode-0700 child. Missing parents are never
created. Only our program is sent into that new child with mode 0700. It runs the reader,
then removes only that program and its now-empty directory. No generic remote
path/binary argument is exposed. No FOTA service, vendor recovery script,
firmware file or partition is modified. This mode does write and execute our
own temporary program in owner data storage, then deletes it; it is not an
entirely read-only transport mode. Preflight mount eligibility is not proof
that SMACK permits execution; only actual valid probe output can establish that.

If no parent qualifies, it saves preflight diagnostics without mkdir or upload.
Unverified creation never causes deletion of a potentially pre-existing
directory. Upload/execution failure does not retry another location. After
verified creation, cleanup runs even on upload/transport or local-save failure.
Refused/invalid execution also captures the staged program's mode/owner and
available ls security-label output before cleanup. Cleanup failure retains the
exact residual path and overrides the final state; successful metadata remains
available. Raw preflight/create/upload/run/cleanup responses stay private and
existing evidence is never overwritten. A failure still creates the report/ZIP.
Compiler failures make no watch contact.

## One phone command

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r840x_security_metadata.py \
  --watch-ip 10.115.12.131 \
  --output-dir ~/watch3-r840x-security-metadata-home-evidence \
  --archive ~/storage/downloads/watch3-security-metadata-home.zip
```

Termux's [clang package](https://github.com/termux/termux-packages/blob/master/packages/libllvm/clang.subpackage.sh)
depends on lld; its [LLVM recipe](https://github.com/termux/termux-packages/blob/master/packages/libllvm/build.sh)
builds all target backends. Clang is already installed and the owner's first
phone build succeeded. No PC, paid tooling or Tizen SDK is needed. Execution
of the reader on the watch still requires physical validation.

Attach `watch3-security-metadata-home.zip` from Downloads, including if
the state is partial/failed. A successful metadata capture does not prove root,
a signature bypass, bootloader unlock, custom boot or tested recovery.

## Validation

Local tests compile/run our own host-test reader against real positive user
xattrs and an oversized attribute, checking exact bytes and ERANGE. Required
CI additionally cross-compiles the ARM program and runs it under qemu-arm
against that same real fixture. The fixture is explicitly marked synthetic
and rejected by the production metadata parser. It is not a watch/root proof.

Fake-SDB tests check the exact bounded SEND destination/mode, forbidden stage
paths, root/firmware separation, complete acquisition and cleanup, upload/run
failures, uncertain creation without deletion, explicit cleanup failure and
private/exclusive diagnostic ZIPs. Preflight regressions cover missing SDK paths,
canonical home resolution, deepest bind mounts, ambiguous stacks, escaped mount
points, noexec/read-only/access denial, invalid/truncated output and no remote
write when no eligible stage exists. Real host shell tests exercise symlink
resolution and missing/existing directory behavior. CI supplies a disposable
noexec tmpfs and verifies Linux refuses our own compiled host probe despite
mode 0700, then removes the fixture. No existing host mount flags are changed.
The format follows the Linux
[mountinfo documentation](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html).
Older metadata readers remain unchanged.
