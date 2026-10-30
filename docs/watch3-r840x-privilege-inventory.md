# R840X: native execution confirmed, privilege boundary next

Issue #47, October 30, 2026. The owner's metadata reader ran on the actual
watch and returned valid output. The temporary program and directory were
removed. This establishes ordinary native execution as UID5001, not root,
bootloader unlock or functioning recovery. The next command inventories the
installed privilege-bearing helpers and copies bounded originals for analysis.

## Verified physical result

`watch3-security-metadata-home.zip`: 3,464 bytes, SHA-256
`83c297b4743a3d56a9f40f5ae80c4932171385a9654d96becf1d1d8c19bd25ec`.
All five members are preserved privately. The 6,947-byte report has SHA-256
`ce5d5508bb8d73b17b847e8c276d2c7e47fe6f341febaf40d719a29314f26726`.
The 2,226-byte native response has SHA-256
`45bf249e8ccc0a9c631ac5548bd75232060a2fd5c888cafc7e744a181168f6bd`.
Independent production parsers reproduced both report objects from the raw
preflight/probe responses; the cleanup marker also matched.

The real canonical share path is `/opt/usr/home/owner/share`, on writable
`/opt/usr` with nosuid and without noexec. Our 7,444-byte program ran there,
UID/EUID5001, label `User::Shell`, 25 supplementary groups, none 1051.
Effective and permitted capabilities are both zero. Inheritable mask is
`00000000002000c2`: DAC_OVERRIDE, SETGID, SETUID, SYS_ADMIN (bits 1,6,7,21).
Inheritable bits are not effective permission. Linux's
[capability transformation rules](https://man7.org/linux/man-pages/man7/capabilities.7.html)
require additional executable/runtime conditions before any can become usable.

All eight queried paths returned ENODATA (-61) for security.capability.
That is actual absent-attribute evidence, unlike the earlier missing getcap.

| Path/group | SMACK64 | SMACK64EXEC | access(W_OK) |
| --- | --- | --- | --- |
| consumer, OMA-DM daemon, three recovery scripts | `_` | ENODATA | EROFS (-30) |
| `/usr/bin/launch_app` | `User::Shell` | `User` | EROFS (-30) |
| `/opt/usr/data/fota/save` | `User::App::Shared` | ENODATA | 0 |
| `/opt/data/recovery` | `_` | ENODATA | EACCES (-13) |

The launcher's exec label is an observed MAC transition attribute, not a UID
change or root grant. Smack's
[original kernel documentation](https://github.com/torvalds/linux/blob/v4.9/Documentation/security/Smack.txt)
defines that attribute. The archive directory passed a permission query; no
file/archive was created there and no update handler was invoked. The recovery
directory remains inaccessible for writing. No image/partition was read or
written. Native root mode was not retried.

## One bounded privilege inventory

The existing controller adds an explicit `--privilege-inventory` profile. It
reuses the now physically validated build, canonical preflight, upload and
cleanup path. The original eight metadata targets remain in the response.
The inventory adds only read/query syscalls: getdents64, lstat64, and prctl
GET_NO_NEW_PRIVS, GET_SECUREBITS, CAPBSET_READ. No helper executes, no identity
is changed, and no capability/security attribute is set.

It enumerates only the immediate entries in `/bin`, `/sbin`, `/usr/bin`,
`/usr/sbin`, `/usr/libexec`, `/usr/lib`; it does not recurse or search user
data. It inspects regular files with lstat (ignoring symlink entries), and
reports setuid/setgid modes or present capability attributes, owner IDs,
64-bit size, read/execute permission queries and SMACK labels. Errors remain
distinct from absent attributes. The response also retains process bounding
capability queries and no-new-privileges/securebits results.

Limits: 256 directory reads and 4,096 normal entries per directory, 64 retained
candidate records, 256 bytes per xattr, 64 KiB total native output. Invalid or
unsafe names are counted and omitted. Limits, inaccessible paths, stat/xattr
errors and dropped records prevent a complete-scope claim. This is a bounded
nonrecursive inventory, not proof that no other privileged executable exists.

The phone validates all records, decodes VFS capability revisions 1/2/3 and
computes intersections with the observed inheritable mask. Unknown formats,
nonzero namespace root IDs, mount flags, no-new-privileges and other runtime
conditions still need review; a static candidate is not proven privilege gain.

After verified cleanup, the same command copies `/usr/bin/launch_app` and up
to seven readable executable candidates, prioritizing inheritable matches,
root setuid and updater-group setgid. Every candidate must come from the
validated directory inventory. Only sync RECV is used for these copies; each
is capped at 2 MiB, checked as ARM ELF32, size-checked against its inventory
record where available, and hashed. Missing/denied/invalid copies remain
explicit in the report. Unselected inputs are counted. Files stay private;
no Samsung executable is run or committed to the repository/CI.

The final fixed context read uses systemctl show for the two observed updater
units' user/group, capability, securebits and SMACK properties, then reads the
known fota-consumer unit file. Unsupported properties or denied file reads
remain raw diagnostics. It does not start a unit, request a D-Bus FOTA action,
launch an application, stage an update archive or touch firmware.

## Current phone command

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r840x_security_metadata.py \
  --watch-ip 10.115.12.131 --privilege-inventory \
  --output-dir ~/watch3-r840x-privilege-inventory-evidence \
  --archive ~/storage/downloads/watch3-privilege-inventory.zip
```

Attach `watch3-privilege-inventory.zip`, including on a partial/failure state.
Existing metadata evidence is retained. No tool reinstall or root-switch
retry is needed. A captured inventory remains distinct from a working root,
unlock, custom boot or tested stock-restoration route.

## Verification

The native layout uses the original Linux v4.9
[ARM stat64](https://github.com/torvalds/linux/blob/v4.9/arch/arm/include/uapi/asm/stat.h),
[ARM syscall numbers](https://github.com/torvalds/linux/blob/v4.9/arch/arm/include/uapi/asm/unistd.h),
[dirent64](https://github.com/torvalds/linux/blob/v4.9/include/linux/dirent.h), and
[read-only prctl numbers](https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/prctl.h).
Host and required ARM/QEMU fixtures exercise real directory enumeration,
modes/owners, positive user xattrs, symlink rejection, unsafe names, a sparse
file above 4 GiB and explicit record truncation. Fixture attributes are marked
synthetic and rejected by production parsing. The exact production ARM profile
also runs under QEMU. Protocol regressions cover one checked upload, bounded
original copies, invalid inputs, exclusive private archives, and no follow-up
copy after unverified cleanup. Physical inventory execution is still pending.
