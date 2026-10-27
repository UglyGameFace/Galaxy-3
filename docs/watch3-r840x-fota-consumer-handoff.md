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

## Follow-up: actual updateclient RECV failure and diagnostic correction

Owner's first actual R840X `--component updateclient` run returned
`NO_ARTIFACT: SDB_UNAVAILABLE_OR_REJECTED`; no evidence JSON was created.
The extractor's prior `main()` combined `SdbError`, local `OSError`,
and timeouts into one catch-all string. Thus this output **does not**
prove file absence, denial, or successful binary access. In particular,
a normal sync `FAIL` would have reported
`REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE`, which was **not** observed.

The narrow fix preserves the two literal executable paths, byte cap,
private no-overwrite semantics, and pure SDB `sync:RECV` behavior. It
categorizes connect, handshake, sync-open, and sync-transfer failures,
separating timeouts, protocol/auth failures, and I/O failures without
printing raw network, token or system error text. Read-only mock-watch
regressions run in the existing workflow. A stage result is evidence of
**where** acquisition failed, not necessarily why the watch rejected it.

After merging a green CI result, retry only the same bounded read once.
No firmware update, mode transition, root attempt or watch write is needed.


## Real updateclient ELF narrows the next firmware consumer target (October 27)

The owner privately uploaded the 445,524-byte ARM32 `updateclient`
from physical R840X SDB `sync:RECV`. Verified SHA-256:
`95ca44a06e3dd95ae78d09443f2a8cb22d34fda1648fa0ba7e1a25472feb8728`.
Offline disassembly mapped SES updater network/cert and Tizen package-manager
calls, not the earlier `fota.consumer` D-Bus `Launch` endpoint. This
does not demonstrate any firmware-signature bypass or root path. Keep the
private extracted ELF out of GitHub.

### Fixed D-Bus service activation inventory

Standard Linux D-Bus service activation locators (authoritative spec:
https://dbus.freedesktop.org/doc/dbus-specification.html ) include:
`/usr/share/dbus-1/system-services`, `/etc/dbus-1/system-services`,
and session-bus `/usr/share/dbus-1/services`. Neither the exact
Samsung registry location nor activation mechanism is proven on R840X.

Reuse the previously validated SDB sync `LIST` implementation with
`--dbus-services-only`. It performs at most three independent fixed,
bounded read-only directory listings and reveals **only**
`fota.consumer.service` (type and size), not unrelated filenames,
user data, D-Bus messages, service activation, arbitrary search paths,
device writes or file contents. Empty/denied listings and missing
filename are explicitly inconclusive: the bus name could be acquired
dynamically or from a nonstandard directory.

After passing fake-watch CI and merging to main:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_consumer_inventory.py \
  --watch-ip 10.0.0.65 --dbus-services-only
cat ~/watch3-r840x-fota-dbus-services.json
```

If the target is listed in one of those locations, the next change
will be an equally fixed, bounded read-only `sync:RECV` of that
**observed** text registration, with privacy-filtered reporting of
`Name` and `Exec` only. Do not call the `Launch` method or
invoke firmware updates. If it is not listed, do not claim the service
is absent; pivot to passive package/systemd/daemon registration evidence
instead. Root, safe stock rescue and custom unsigned boot remain NO-GO.


## Physical D-Bus directory observation (October 27): target not listed

Owner ran PR #64's read-only fixed directory inventory on the physical
SM-R840X and got:
- `/usr/share/dbus-1/system-services`: LIST_COMPLETE, 85 other entries;
  exact `fota.consumer.service` **not listed**.
- `/etc/dbus-1/system-services`: EMPTY_OR_INACCESSIBLE.
- `/usr/share/dbus-1/services`: LIST_COMPLETE, 16 other entries;
  exact target **not listed**.
No firmware write, root attempt, update RPC, or privileged interaction.
These observations **do not establish an absent D-Bus owner**. The current
D-Bus specification requires system-bus .service filenames to match
the well-known name; session-bus activation files can have a differing
filename for historical compatibility, and the prior probe did not
cover every standard system directory. Source:
https://dbus.freedesktop.org/doc/dbus-specification.html

## Next stronger source: installed FOTA package manifest

Samsung's Tizen package installation layout places
`tizen-manifest.xml` in the native application's package root. It
contains `<service-application>` declarations and `exec` paths.
Source: https://github.com/Samsung/tizen-docs/blob/master/docs/application/native/index.md
and https://github.com/Samsung/tizen-docs/blob/master/docs/application/native/guides/applications/service-app.md .

Known actual package root from the already extracted
`/usr/apps/com.samsung.fota-consumer/bin/fota-service` gives the
**one fixed target**
`/usr/apps/com.samsung.fota-consumer/tizen-manifest.xml`.
The small `watch3_r08_fota_manifest_probe.py` performs one
bounded, authenticated, read-only `sync:RECV` of **that exact path**,
without execution. It reuses the existing SDB transport and sync decoder,
validates an XML package root without DTD/entities, and reports only
application type and within-package executable basename plus safe
application ID. It does not persist the raw XML, read any other paths,
start services, invoke `Launch`, write to the watch or access partitions.

After passing synthetic no-watch CI and merging:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_manifest_probe.py --watch-ip 10.0.0.65
cat ~/watch3-r840x-fota-manifest.json
```

The JSON is private mode 0600 and no-clobber. If the manifest is not
readable, that is a precise access result, not evidence of absent
firmware machinery. If present, compare declared executables with the
previous FOTA bin inventory. This is still static package metadata,
**not proof of D-Bus ownership, unsigned custom kernel acceptance or
stock recovery**. Record findings under Issue #47 only.
