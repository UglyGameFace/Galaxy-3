# Standard SDB root mode and conditional original backups

Issue #47, October 30, 2026. The FUMO plugin and public certificate are now
[captured and reviewed](watch3-r840x-omadm-install-verification.md#completed-firmware-focused-capture).
They do not supply a demonstrated unlock. The next phone operation attempts
Tizen's normal root-mode service once, verifies the actual shell identity,
then acquires original boot/recovery and recovery-script inputs if permitted.
This mode has not yet been tested on the physical owner's R840X.

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

## One phone command

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r840x_native_root.py \
  --watch-ip 10.115.12.131 \
  --archive ~/storage/downloads/watch3-native-root-evidence.zip
```

Attach `watch3-native-root-evidence.zip` from Downloads, including after a
failure state. The command uses a new `~/watch3-r840x-native-root-evidence`
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
is part of those fixtures. Physical validation remains the owner's phone run.
