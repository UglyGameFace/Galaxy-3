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


## Physical manifest RECV failed: parent-directory evidence gate (October 27)

After #65 merged (`ca11734`), the owner actually ran the fixed
`/usr/apps/com.samsung.fota-consumer/tizen-manifest.xml` SDB RECV.
The watch responded with a sync FAIL, redacted locally as
`MANIFEST_MISSING_DENIED_OR_UNREADABLE`. **No JSON was created because
the command did not acquire XML.** This is *not* a network transport error,
proof of a permissions bypass, or demonstration that Tizen manifests
do not exist. The current decoder purposely does not reveal raw error
messages, so missing vs denied is not yet established.

Samsung's Tizen documentation grounds that normal installed native
packages have their manifest in the package root, but proprietary
system packages and SMACK policy can differ. Primary reference:
https://github.com/Samsung/tizen-docs/blob/master/docs/application/native/index.md .

The previously acquired FOTA service executable proves the binary
exists in `/usr/apps/com.samsung.fota-consumer/bin`. Before speculating
about another file path, perform ONE fixed read-only SDB sync `LIST`
on its literal parent `/usr/apps/com.samsung.fota-consumer`.
The existing inventory now has `--fota-package-root-only`; this sends
exactly one bounded LIST, reporting the existence, file kind,
bounded size, and ordinary DAC read bits of only the **exact name**
`tizen-manifest.xml`. All other directory names are filtered to a count.
The parent metadata query cannot override a denied file RECV, Tizen
SMACK, or establish where the D-Bus consumer runs.

After PR CI passes and merges:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_consumer_inventory.py \
  --watch-ip 10.0.0.65 --fota-package-root-only
cat ~/watch3-r840x-fota-root-manifest-list.json
```

Interpret `LIST_COMPLETE` + `NOT_SEEN_IN_LIST` as **specific
manifest filename not listed in that one directory**; if it is listed,
record DAC file metadata but retain the prior RECV failure as an open
SMACK/access/transport question. No shell, file download, service
launch, D-Bus invocation, firmware update, root or watch write.


## Physical result: no tizen-manifest.xml in FOTA package root

Owner's read-only `--fota-package-root-only` run on main
`be6662f` returned `LIST_COMPLETE`, six filtered entries, and
`tizen_manifest=NOT_SEEN_IN_LIST` for the exact directory
`/usr/apps/com.samsung.fota-consumer`. Earlier `sync:RECV` of
`/usr/apps/com.samsung.fota-consumer/tizen-manifest.xml` was refused
with `MANIFEST_MISSING_DENIED_OR_UNREADABLE`. In combination these
indicate **that specific manifest path is not seen**. Stop retrying it.

### Better Tizen package registry locations, grounded in install artifacts

A published Tizen native RPM packaging spec for the Cobalt application
explicitly installs the executable under `/usr/apps/<package>/bin`
and the XML manifest under `/usr/share/packages/<package>.xml`:
https://cobalt.googlesource.com/cobalt/+/refs/heads/release_11/src/starboard/tizen/packaging/com.youtube.cobalt.spec
Samsung Tizen web/hybrid package documentation independently identifies
`/opt/share/packages/<package>.xml` for those package types:
https://github.com/Samsung/tizen-docs/blob/master/docs/application/web/index.md

The actual R840X FOTA package identity is evidenced by the successfully
pulled service at
`/usr/apps/com.samsung.fota-consumer/bin/fota-service`.
Therefore use only exact name `com.samsung.fota-consumer.xml`
in two fixed directories: `/usr/share/packages` and
`/opt/share/packages`. These are **layout hypotheses, not** a claim
that the user's watch has that registration or that these are exhaustive.

Extending the original SDB `LIST` inventory with
`--fota-package-index-only` performs precisely two independent,
read-only directory queries. It reports only the exact package XML
filename's kind, bounded size, and ordinary DAC read bit, plus counts
of other entries; no other filenames or raw contents are exposed.
The entry limit for these two directories alone increases from 256
to 2,048 to avoid truncating typical larger registries. The existing
512 KiB total LIST limit, frame limit, default original two scopes,
D-Bus mode, one-package-root mode, no remote writes and private
0600 no-overwrite report remain intact.

After mock-watch CI passes and the PR merges:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_consumer_inventory.py \
  --watch-ip 10.0.0.65 --fota-package-index-only
cat ~/watch3-r840x-fota-package-index.json
```

If a registered manifest appears, the evidence-gated next step is a
separate limited `RECV` of only that exact file followed by local,
privacy-filtered parsing of `service-application` and `exec`
attributes. If not, **do not invent** a different path or infer no
daemon; use passive public/vendor package evidence and the already
extracted binary to investigate owner code instead. No update
triggering, exploit payload, unsigned boot or stock recovery proved.


## October 27: actual installed FOTA package XML found (physical evidence)

After merged #67, the owner's authenticated read-only SDB `LIST` on
`/usr/share/packages` completed with **146 other entries**, and found
the exact file `com.samsung.fota-consumer.xml` as a **2,215-byte
REGULAR_FILE**, with at least one POSIX DAC read bit. The separate
`/opt/share/packages` LIST completed with 10 unrelated entries and
**no matching file**. This resolves why the earlier incorrectly assumed
package-root `tizen-manifest.xml` could not be read: it was not listed
there on this particular watch. The published native Tizen RPM layout
explicitly registers `<package>.xml` under `/usr/share/packages`;
the physical watch now confirms that exact location. This file's
contents are not yet known. DAC read bits do not prove SDB access due
to Tizen SMACK restrictions.

The next evidence gate is a **single exact-path, fixed, read-only RECV**
of the file actually listed, not another guessed path. To avoid a
duplicate transport stack, `watch3_r08_fota_manifest_probe.py`'s
existing sync implementation is reused by a new
`watch3_r08_fota_package_registration_pull.py`; the former's default
package-root mode remains intact.

The new program:
- Reads only `/usr/share/packages/com.samsung.fota-consumer.xml`,
  limited to 16 KiB by the streaming decoder;
- Parses well-formed XML offline, refusing DTD/entities, without
  interpreting package records as D-Bus execution evidence;
- Saves raw XML only in Termux as **mode-0600 exclusive local file**
  `~/watch3-r840x-fota-package-registration.xml`, not on GitHub;
- Saves separate privacy-filtered JSON, with source hash, byte count,
  root tag, safe executable basenames and limited app IDs;
- Never issues SDB `SEND`, shell, FOTA `Launch`, firmware install,
  privileged operations, or writes to the watch.

After mock-watch CI succeeds and merge completes:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_package_registration_pull.py --watch-ip 10.0.0.65
cat ~/watch3-r840x-fota-package-registration.json
```

If it succeeds, `cp -n ~/watch3-r840x-fota-package-registration.xml
~/storage/downloads/watch3-fota-package-registration.xml` copies it
into Android Downloads for private upload to this conversation.
**Do not add the raw XML to the repository.** If the RECV fails,
capture the exact redacted failure and do not infer root or absent
FOTA. No code execution or image flashing occurs. Root, ownership of
`fota.consumer`, unsigned kernel boot, and full stock rescue remain
unproven and separate.


## October 27: Authentic 2,215-byte installed XML resolves FOTA package service role

Owner personally attached the complete `/usr/share/packages/com.samsung.fota-consumer.xml`
previously listed on their physical SM-R840X. Verified locally:
**2,215 bytes** and SHA-256
`723eb10e8c090b51b0bc9bcf28f17e4bcb099bdf126e591e77052b8f209b863c`.
XML namespace: `http://tizen.org/ns/packages`, package
`com.samsung.fota-consumer`, `version=1.1.3`, `type=rpm`, `readonly=true`,
`preload=true`, `removable=false`. Do **not** commit the original XML or
its author information.

Actual two application registrations: `com.samsung.fota-syspopup`
runs `/usr/apps/com.samsung.fota-consumer/bin/fota-syspopup` and
`com.samsung.fota-service` runs
`/usr/apps/com.samsung.fota-consumer/bin/fota-service`. Both appear under
`ui-application`, but the latter declares `component-type=svcapp`,
`on-boot=false`, `auto-restart=false`, `nodisplay=true`,
`launch-on-attach=true`, and download/network/IoT background categories.
It also declares the exact metadata
`accessory-services-location=/res/xml/appcessoryservices.xml`. **Preserve
the vendor spelling `appcessoryservices.xml`, not the conventional
`accessoryservices.xml`.**

Samsung's official Tizen SAP API documentation confirms
`accessory-services-location` points to a peer-service profile stored
under `/res/xml` of the app, not a D-Bus service registration:
https://developer.samsung.com/galaxy-watch-tizen/creating-your-first-app/native-companion/use-sap.html .
The Tizen platform white paper states systemd launches platform daemons,
with vendor unit directories `/usr/lib/systemd/system` and
`/usr/lib/systemd/user`, while standard systemd override units may
appear in `/etc/systemd/system`:
https://www.tizen.org/sites/default/files/page/tizen_for_platform_developers_and_manufacturers.pdf
https://www.freedesktop.org/software/systemd/man/systemd.unit.html .

### Evidence-guided dual registry check

Existing `watch3_r08_fota_consumer_inventory.py` opt-in
`--fota-handoff-index-only` performs only FOUR fixed read-only sync-v1
`LIST` operations: the three systemd directories above and
`/usr/apps/com.samsung.fota-consumer/res/xml` (derived from the exact
registered package root and declared metadata). The last scope emits
only presence/type/bounded size of **`appcessoryservices.xml`**; the
systemd scopes emit only bounded `fota`, `firmware`, or `update`
`.service/.socket/.target/.timer` filenames and basic metadata.
No other filenames; other entries become counts. The systemd-only
DENT cap is 1,024 per folder, total input 512 KiB per folder; original
scopes retain old limits. Empty, unlisted, or inaccessible directories
are explicitly inconclusive. Four individually authenticated normal
SDB connections, with no process introspection, shell, firmware calls,
service activation, file contents, root or watch write.

After CI and merge:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_consumer_inventory.py \
  --watch-ip 10.0.0.65 --fota-handoff-index-only
cat ~/watch3-r840x-fota-handoff-index.json
```

If a FOTA-related systemd unit is listed, retrieve **only that confirmed
unit** on a subsequent separate, reviewed read-only slice and inspect its
`ExecStart` and optional `BusName`. The SAP resource can clarify the
watch/phone protocol but will not by itself establish who owns the
`fota.consumer` D-Bus name. Never send `Launch` or initiate a FOTA
update. Unsigned boot, stock rescue and privilege boundaries still
require independent proof.


## October 27: physical FOTA systemd units and SAP resource confirmed

The owner executed merged #70 `--fota-handoff-index-only` against their
actual SM-R840X and returned four complete read-only SDB LIST results:

- `/usr/lib/systemd/system` listed **11** FOTA/update-like unit names
  (401 other items). The most relevant *actual regular files*:
  `fota-consumer.service` (**386 bytes**),
  `recovery-update.service` (**238 bytes**),
  `update-service.service` (**245 bytes**),
  `rw-update.service` (**215 bytes**).
  Other matches include ordinary systemd bookkeeping units and
  `system-update.target`; names alone cannot identify a boot mechanism.
- `/usr/lib/systemd/user` LIST_COMPLETE, 67 other entries and zero
  matched FOTA-related units.
- `/etc/systemd/system` LIST_COMPLETE, four unrelated entries and zero
  matched units.
- Exact `/usr/apps/com.samsung.fota-consumer/res/xml/appcessoryservices.xml`
  is a **2,036-byte REGULAR_FILE**, with two other entries in its
  directory. The vendor spelling `appcessory` was verified in the
  authentically retrieved 2,215-byte installed package XML.

This is the first positive on-device presence evidence for the named
`fota-consumer.service` **systemd** unit, distinct from missing D-Bus
activation service files. It is plausible that systemd starts the FOTA
receiver, but actual `ExecStart`, `BusName`, signature checks and
mode of recovery have NOT been read or established.

### Next exact five-file read-only evidence gate

`tools/watch3_r08_fota_handoff_pull.py` uses the proven authenticated SDB
sync-v1 transport to read exactly these five **owner-observed** files,
each on its own bounded SDB connection. The remote allowlist is literal,
not a path supplied by the user. The per-file read is capped at 8 KiB
and the normal SDB frame count and read timeout limits apply.

The original service-unit files and XML stay **only on the owner's
phone**, as mode-0600 files inside exclusive mode-0700
`~/watch3-r840x-fota-handoff-evidence` (never in GitHub). A redacted
`fota-handoff-report.json` inside that directory records per-file
`FETCHED` or explicit redacted failure, size, SHA-256, and only bounded
unit fields: `Type`, `BusName`, safe simple absolute executable
path from `ExecStart` (no args), `After`, `Wants`, `Requires`. For
SAP XML only root tag is shown; the full XML is private. Missing or
denied files are recorded independently and do not prevent other fixed
reads. No guessed sixth file, shell, `systemctl`, update call, D-Bus
message, write, device flash or root action exists.

After CI and merge, owner can execute this from Android Termux:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_fota_handoff_pull.py --watch-ip 10.0.0.65
cat ~/watch3-r840x-fota-handoff-evidence/fota-handoff-report.json
```

For more thorough offline inspection, copy the private `.service`
files to Android Downloads for chat attachment (not GitHub). A
successfully read FOTA `BusName` and `ExecStart` would tie the D-Bus
name to a specific executable/service startup **configuration**, not
prove an active owner or that any FOTA payload is accepted. Recovery
service content may establish a recovery *procedure or helper*, but
a safe stock restore and custom unsigned kernel boot still require
independent hardware/firmware verification.
