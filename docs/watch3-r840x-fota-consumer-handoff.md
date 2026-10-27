# Watch3 R840X: consumer handoff / fixed SDB directory inventory

**Issue #47:** Software-only UgLy|OS boot and safe recovery. User works
entirely in Android/Termux, has one physical SM-R840X watch, and does not
authorize watch writes, risky flashing, or purchasing tools.

## Verified evidence from the actual extracted FOTA service

Owner provided the SDB sync RECV result on their watch and privately
uploaded the ELF. The binary's size/hash are exactly:

- 87,036 bytes, ARM ELF32 little-endian, PIE
- SHA-256: 008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757
- Build ID: d6e175a0495c710e90282f758ef782d80a6cf4cd
- Source build path includes com.samsung.fota-consumer-1.1.3

Offline Thumb-2 disassembly identified:

- The FOTA file-transfer callback on_receive_complete calls chmod at
  ELF-relative 0x6732 with mode 0o666 on the filename callback argument.
- The service uses /opt/usr/data/fota/save/delta.tar for receiving updates.
- The launch_fota_consumer wrapper at 0xa764 uses g_dbus_proxy_call_sync
  at 0xa7f8; strings adjacent to the wrapper include bus fota.consumer,
  object /fota/consumer and operation Launch. This is a distinct process
  boundary, NOT proof that file reception automatically runs a payload.
- Service process imports fork/exec, but their callability via an
  untrusted SAP message or any escalation remains unverified.

Samsung's July 2021 Wearable Security Bulletin identifies Watch3 FOTA
CVE-2021-25436 (input validation) and CVE-2021-25437 (update-file
replacement). Source:
https://security.samsungmobile.com/serviceWeb.smsb?year=2021&month=7

The binary alone does NOT establish the exact CVE code path, caller UID,
SMACK labels, writable attack surface, cryptographic acceptance, unsigned
kernel acceptance or restoration. It remains incorrect to assume the
delta archive is accepted without signature verification.

## Next evidence gate: identify actual consumer executable

The service's package path is known from the authentic ELF:
 /usr/apps/com.samsung.fota-consumer/bin/fota-service

The consumer's filename is not proven. Avoid guessing a source path.
The new Termux-only tool issues exactly one read-only SDB sync-v1 LIST
request for EACH of two fixed paths:

  /usr/apps/com.samsung.fota-consumer/bin
  /opt/usr/data/fota/save

Protocol source: Android AOSP sync-v1 documentation
https://android.googlesource.com/platform/system/core/+/refs/tags/android-11.0.0_r20/adb/SYNC.TXT

Run after this PR is merged and the synthetic CI is green:

    cd ~/Galaxy-3 && git pull --ff-only
    python tools/watch3_r08_fota_consumer_inventory.py --watch-ip 10.0.0.65
    cat ~/watch3-r840x-fota-consumer-inventory.json

Use the watch's current Wi-Fi IP if it changes.

The tool reports ONLY plain-ASCII names beginning fota/update in the
package bin directory. In the archive directory it reports ONLY whether
delta.tar appears and its ordinary Unix read/write mode bits and size;
no other filenames, timestamps, phone addresses, raw process output or
tokens are saved. If directory listing returns an empty DONE it is
classified EMPTY_OR_INACCESSIBLE: in sync-v1 an empty response can also
mean opendir was denied. A missing listed filename does NOT prove its
binary is absent. Ordinary Unix permission bits do NOT reveal whether
Tizen SMACK policies prevent another process from opening a file.

**Zero remote modification**: No SDB shell, SEND, firmware update command,
file substitution, socket interaction with SAP or fota.consumer, root,
bootloader or recovery operation. Only local Termux JSON output is created,
with exclusive 0600 mode and no overwrite. Fake-watch protocol tests
cover fragmented DENT, FAIL, DONE, privacy and malformed frames.

## After the real inventory

If a candidate *consumer* executable is shown, design one additional
strictly allowlisted RECV for that exact observed filename and inspect
its ARM machine code OFFLINE, just as we did for fota-service. That is
the missing component required to investigate what verifies delta.tar
and in which principal it executes. Do not send malicious requests or
replace update archives on the only watch. Stock recovery and signing
limits must be demonstrated separately before any alternate-OS attempt.


## October 27: physical consumer-directory results and targeted next file

Owner's actual SM-R840X read-only SDB LIST completed. Package binary
directory exposed `fota-service` (87,036 bytes, matching the extracted
ELF) and `fota-syspopup` (40,812 bytes) with two filtered entries.
FOTA save directory LIST did not show `delta.tar`. That is an observation
at one moment, not proof that the update path is forever empty or writable.

A public Tizen wearable package inventory separately labels
`fota-syspopup` a UI app and identifies the service application
`com.samsung.tizen.update-client`, executable
`/usr/apps/com.samsung.tizen.update-client/bin/updateclient`:
https://gist.github.com/avipars/bf4ebf3efa1bcceb77025b8b9159a6df

The owner's earlier R840X FOTA-path probe saw the `update-client`
*directory*; the precise executable, D-Bus ownership, privilege context,
and signature-check code are still NOT verified. The updated original
RECV tool (no duplicate transport implementation) now supports only
two literal source choices: default `fota-service` and optional
`updateclient`. On Android/Termux, after this PR is merged and its
NO-WATCH synthetic CI passes:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_artifact_pull.py --watch-ip 10.0.0.65 --component updateclient
cat ~/watch3-r840x-updateclient-artifact-evidence.json
```

Use the watch's current local Wi-Fi address if different. The new
binary and report stay on the owner's phone in separate private filenames,
created exclusively without overwriting existing files. It sends only
an authenticated read-only SDB `sync:RECV`, bounded to 8 MiB, and checks
that returned bytes are ARM/AArch64 ELF; no watch write, shell, SAP packet,
D-Bus launch, bootloader transition, update request, or exploit.

**Interpretation:** A successful read establishes real binary bytes for
offline analysis of the consumer/verification architecture, not a root
exploit or unsigned-boot permission. An SDB `FAIL` means
missing/denied/unreadable cannot be distinguished. If the exact
`updateclient` can be recovered, inspect it OFFLINE before pursuing
any other FOTA surface. Stock restore and bootloader acceptance remain
independent mandatory proof gates.
