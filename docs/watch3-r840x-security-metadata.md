# R840X recovery access and native security metadata

Issue #47, October 30, 2026. The ordinary shell capture now confirms that all
three recovery scripts exist and are permission-denied. The native root switch
was also denied. A missing getcap utility leaves actual executable capability
attributes unknown. The next operation replaces that missing utility with our
small ARM metadata reader, compiled on the phone and run in a temporary SDK
directory. This is diagnostic code, not a demonstrated root/unlock procedure.

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
lld on the phone. It uses the authenticated device's sdk_toolpath, validates
the home/tmp root and normal path segments, creates one random private child
directory, and sends only our program there with mode 0700. It runs the reader,
then removes only that program and its now-empty directory. No generic remote
path/binary argument is exposed. No FOTA service, vendor recovery script,
firmware file or partition is modified. This mode does write and execute our
own temporary SDK program; it is not an entirely read-only transport mode.

Unverified creation never causes deletion of a potentially pre-existing
directory. Upload/run failures still attempt cleanup after verified creation.
Cleanup failure is explicit, retaining the exact stage path and diagnostics.
Raw create/run/cleanup responses and parsed metadata are stored privately;
existing evidence is never overwritten. A failure still creates the report/ZIP.

## One phone command

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
pkg install -y clang &&
python tools/watch3_r840x_security_metadata.py \
  --watch-ip 10.115.12.131 \
  --archive ~/storage/downloads/watch3-security-metadata-evidence.zip
```

Termux's [clang package](https://github.com/termux/termux-packages/blob/master/packages/libllvm/clang.subpackage.sh)
depends on lld; its [LLVM recipe](https://github.com/termux/termux-packages/blob/master/packages/libllvm/build.sh)
builds all target backends. No PC, paid tooling or Tizen SDK is needed. The
actual phone build and watch execution still require physical validation.

Attach `watch3-security-metadata-evidence.zip` from Downloads, including if
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
private/exclusive diagnostic ZIPs. Older metadata readers remain unchanged.
