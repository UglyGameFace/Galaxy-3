# Standard SDB root mode and conditional original backups

Issue #47, October 30, 2026. The FUMO plugin and public certificate are now
[captured and reviewed](watch3-r840x-omadm-install-verification.md#completed-firmware-focused-capture).
They do not supply a demonstrated unlock. The next phone operation attempts
Tizen's normal root-mode service once, verifies the actual shell identity,
then acquires original boot/recovery and recovery-script inputs if permitted.
The owner has now run this mode: the watch explicitly denied the request.
The shell-context read below is also completed. Its observed permission
denials and the [current native metadata command](watch3-r840x-security-metadata.md)
are recorded in the follow-up; do not repeat the completed reads. Native
metadata has since succeeded; use the [current privilege-inventory guide](watch3-r840x-privilege-inventory.md).

## Actual root attempt: denied

The owner supplied `watch3-native-root-evidence.zip`, 666 bytes, SHA-256
`aa0ab67fd0d941ceb955e63fb745b40a1e929194fdf3cd7dd570451b0360db70`.
Its only member is the 1,560-byte `native-root-report.json`, SHA-256
`f2f6cee9639a909acb053fe2aa47c81d93f0474d02d4ea067354234bc0d747bf`.
Both the ZIP member inventory and report hash were verified and preserved.

The board matched. `sdbd_rootperm` and `rootonoff_support` both advertised
disabled; the root service explicitly reported denial. Before and after the
request, `id -u` returned 5001 and the status UID tuple was
`[5001,5001,5001,5001]`, GID tuple `[100,100,100,100]`, effective capabilities
`0000000000000000`. The result is `NATIVE_ROOT_NOT_GRANTED`. No partition
reads, script copies, FOTA calls, service activation or firmware writes ran.
This closes the normal SDB root-switch route for this observed build/state.
Do not repeat it without a relevant change or a different evidenced route.

## Completed command: ordinary-shell recovery context

The earlier script acquisition failures came from native sync RECV, which
does not distinguish a missing file, denied access or another unreadable
condition. They did not establish what a fixed `cat` through the already
working ordinary shell returns. Root denial is not proof that those files
are unreadable through this separate service.

The existing recovery reader now has `--shell-context`. It reads exactly:

- `recovery-update.sh`, `rw-update-prepare.sh`, `rw-update-systemd.sh`, whose
  paths came from the original updater units/binaries;
- the LIST-observed `oma-dm-agent.service`;
- fixed `stat` metadata for these updater files and the FOTA/recovery directories;
- fixed `getcap -v`, the current SMACK label and `systemctl show` settings for
  the five known updater units.

These are eight fixed shell requests, using cat/stat/getcap/systemctl show.
No recovered script is executed, no root switch is retried, no unit is started
and no partition or firmware is written. A missing utility or access error
is kept privately as diagnostic output rather than treated as proof of absence.
Script-looking payloads and diagnostic responses have separate statuses/names.
Payloads remain byte-preserved within the shared bounded SDB stream reader.
Their hashes describe captured shell output; on-disk completeness and an
independent disk hash are not established by this transport alone.

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r08_recovery_script_pull.py \
  --watch-ip 10.115.12.131 --shell-context \
  --archive ~/storage/downloads/watch3-recovery-shell-evidence.zip
```

Attach `watch3-recovery-shell-evidence.zip` from Downloads, even for a partial
state. The new 0700 folder/0600 files preserve all earlier evidence. A diagnostic
ZIP is created even when every read fails; existing destinations are never
overwritten. `RECOVERY_SCRIPTS_CAPTURED_VIA_SHELL` means three script-looking
payloads were acquired, not that recovery or an exploit worked. Further analysis
will use the captured contents and privilege metadata; root, custom boot,
bootloader unlock and tested restoration remain unproven.

The owner supplied that archive: all three scripts and the OMA-DM unit
explicitly denied access; no script body was acquired. stat confirmed the
files and modes, getcap was unavailable, and the unit snapshot showed both
updater daemons configured as fota and currently inactive. The follow-up
above replaces the missing getcap utility and tests metadata/access without
invoking the update flow. This command is retained as acquisition history.

## Protocol and observed success requirements

[Samsung's SDB documentation](https://github.com/Samsung/tizen-docs/blob/master/docs/sdk-tools/baseline-sdk/common-tools/smart-development-bridge.md)
defines `sdb root on` as the standard root-account switch. The native service
form `OPEN root:on` also appears in the original author's
[published SDB client](https://forum.samygo.tv/viewtopic.php?t=9803).
Those are protocol references, not evidence that this watch grants root.

The phone-native implementation reuses the existing authenticated SDB framing.
It checks the connected NOBLESSE-LARGE-BT board, records only allowlisted root
capability flags and reads `id -u` plus the UID fields of `/proc/self/status`.
It requests native root mode at most once, then repeats both identity reads
on fresh authenticated connections. A positive root response without UID 0
and effective UID 0 is not success. A closed control connection is also not
success; subsequent identity reads determine whether access changed.

If root already exists, the switch is skipped. A denied/unavailable switch
does not invoke FOTA, install a payload, activate a daemon, reboot or retry an
exploit. Root flags advertised by SDB are observations; the independent identity
readback determines whether root is available. Root mode's persistence has not
been established. The root-mode request itself asks to change account mode;
this tool must not be described as entirely read-only.

## Automatic original-image and script acquisition

After root is verified, each partition's DEVNAME/PARTNAME, start and size
are read again and must match the owner's earlier kernel observations:

| Original role | Read-only block source | Start sectors | Size sectors / bytes |
| --- | --- | ---: | ---: |
| boot | `/dev/mmcblk0p13` | 169,984 | 36,864 / 18,874,368 |
| recovery | `/dev/mmcblk0p14` | 206,848 | 36,864 / 18,874,368 |

These values identify two backup candidates; they are not a Samsung PIT or
instructions for writing an image. Native sync RECV reads each whole candidate
to `boot-original.bin` / `recovery-original.bin` on the phone. A missing or
changed label/geometry prevents that read. A truncated or oversized transfer
is not saved as a completed image. Hash and exact length accompany each copy.
The server might still refuse block-device RECV even when shell UID is zero;
that is a partial acquisition, not a tested restoration route.

The same run then copies the two earlier unreadable files
`/usr/bin/recovery-update.sh`, `/usr/bin/rw-update-prepare.sh` and the observed
`/usr/lib/systemd/system/oma-dm-agent.service`. Files are retained for offline
inspection and never executed. No bootloader device is guessed, no partition
is written, and no firmware installation or custom boot is attempted.

The shared RECV decoder accepts an explicit cap up to 32 MiB for this path;
earlier ELF captures retain their 8 MiB default and metadata retains its smaller
caller limit. Frame count is bounded for larger transfers. Files publish only
after DONE and successful size checks. The output directory is 0700, files and
the ZIP are 0600, and existing destinations are never overwritten. Denied root
or partial acquisition still saves the categorical report/ZIP. Raw status,
capability private paths, device names and control replies are not reported.

## Completed native-root command (retained as history)

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r840x_native_root.py \
  --watch-ip 10.115.12.131 \
  --archive ~/storage/downloads/watch3-native-root-evidence.zip
```

The owner supplied `watch3-native-root-evidence.zip`; do not repeat this
completed command. It used a new `~/watch3-r840x-native-root-evidence`
folder and preserves the earlier firmware-focused capture. It returns zero
when root is independently observed, even if a later file read is partial.

`ROOT_VERIFIED_RECOVERY_INPUTS_COPIED` means identity was verified and requested
copies completed. `ROOT_VERIFIED_RECOVERY_INPUTS_PARTIAL` preserves the same
identity result with per-file failures. `NATIVE_ROOT_NOT_GRANTED` means the
post-request shell still has a non-root identity. `ROOT_IDENTITY_UNAVAILABLE`
means the identity could not be verified. None means an unlocked bootloader,
accepted unsigned kernel or recovery successfully booted/restored.
`ROOT_IDENTITY_INCONSISTENT` records disagreement between UID/EUID readbacks
and prevents conditional acquisition.

## Verification

The fake-SDB regression suite exercises both root-message/UID disagreement
and real UID/EUID checks, a root-control stream close, already-root behavior,
denials, wrong-board rejection, fresh-connection shell fallback, private
diagnostics, complete conditional acquisition and exact RECV-only requests.
Backup cases reject changed/duplicate metadata and incomplete copies. A
synthetic transfer crosses the previous 8 MiB boundary while a legacy decoder
still rejects it. No original firmware, physical watch or real host root switch
is part of those fixtures. The native-root phone run was denied as recorded
above. Shell-context and native metadata captures are now completed; their
findings and remaining physical dependency are in the current guide above.
