# Identify the existing firmware consumer without launching it

Issue #47. Software-only research on the owner's original SM-R840X,
R840XXXU1AUA2 / PAP. This is **not an unlock or recovery procedure**.

## Why this evidence path is different

The exact owner-extracted `fota-service` ELF (87,036 bytes, SHA-256
`008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757`)
was already proven to create a **system-bus** client for `fota.consumer`.
See the [original ELF bus proof](watch3-r840x-fota-consumer-handoff.md).
The consumer's executable and actual process credentials remain unknown.
Earlier static activation-file searches and inaccessible systemd scripts
did not establish that identity; repeating those reads is unnecessary.

The [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html)
provides `GetNameOwner`, `GetConnectionUnixProcessID`, `GetConnectionUnixUser`
and `GetId` on the **bus daemon**. The collector addresses only
`org.freedesktop.DBus` at `/org/freedesktop/DBus`; `fota.consumer` appears
only as a query argument. It never calls the firmware service's `Launch`,
`DeleteTempFile`, introspection or properties, nor `StartServiceByName`.
An absent owner stays absent. All commands have a bounded reply timeout.

## One normal-Tizen, read-only run in Termux

Keep the watch running normally with its already-authorized Wi-Fi SDB.
Use its current local IP if the previous `10.115.12.131` has changed.

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_fota_owner_readonly.py \
  --watch-ip 10.115.12.131 --copy-existing-owner
cat ~/watch3-r840x-fota-owner-evidence/fota-owner-report.json
```

The tool reuses the original SDB key at
`~/.config/galaxy3/watch3-sdbkey` and both existing SDB shell encodings.
No extra Python package, PC, purchase, privileged command or firmware mode
is required by the new collector. Watch-side `dbus-send`, registry policy
and proc-link readability remain **unverified until this physical run**.

1. Read the system bus ID and existing owner, then its PID and UID.
2. Read only `/proc/<observed PID>/exe` with `readlink`. The PID must be a
   bounded integer; neither an arbitrary command nor remote path is accepted.
3. Recheck owner and bus ID before accepting the identity. Unique names are
   not reused on the same bus; checking its ID also detects a bus restart.
4. With `--copy-existing-owner`, use the existing bounded `sync:RECV` ELF
   reader to copy the observed normal vendor executable, up to 8 MiB.
   Reject device paths, traversal, shell fragments, deleted links and non-ARM
   files. Recheck owner, bus ID and proc-exe link before publishing the copy.
5. Save the redacted report and optional binary privately in Termux only.

The output directory is new, mode 0700. Files are mode 0600 and never
overwrite existing output. Use a different `--output-dir` only when a
separate, justified follow-up observation is needed. Raw D-Bus replies,
bus IDs, unique names and PIDs are not saved. The observed executable path,
owner UID, copied file length, SHA-256 and ARM ELF class are recorded.
Temporary binary bytes are discarded if ownership/path checks change.

## How to interpret the result

| Result | Meaning and next step |
| --- | --- |
| `EXISTING_FOTA_OWNER_BINARY_COPIED_READONLY` | An existing service executable was retrieved through read-only SDB. Analyze `fota-owner-readonly.bin` offline to identify actual validation and privilege boundaries; do not execute it or commit it. |
| `EXISTING_FOTA_OWNER_EXECUTABLE_OBSERVED` | Registry and proc-link metadata identify a current owner. No binary was requested. |
| `NO_CURRENT_FOTA_OWNER` | The bus has no current owner at this instant. This does not prove the consumer is absent or justify starting it. |
| `REGISTRY_QUERY_DENIED` / `REGISTRY_TOOL_UNAVAILABLE` | This specific metadata route is denied or its command is unavailable. Preserve the report; do not add retries or alternate update calls. |
| `OWNER_PROCESS_LINK_ACCESS_DENIED` / `OWNER_PROCESS_LINK_UNAVAILABLE` | The registry queries progressed but the proc-exe read was denied or unavailable; no binary copy was attempted. |
| `FOTA_OWNER_CHANGED_DURING_OBSERVATION` / `FOTA_EXECUTABLE_CHANGED_DURING_COPY` | Identity changed; the collector withholds the binary and identity claim. |
| `OWNER_ARTIFACT_READ_REJECTED` | Preserve the categorical `artifact_error`. Missing, denied or unreadable bytes are not a successful capture. |

An owner UID of zero describes **the service**, not an elevated SDB shell or
an exploitable permission. Even successful acquisition does not prove a
signature bypass, bootloader code execution, exact-model rescue, custom boot
or firmware write authorization. All physical boot/recovery gates remain open.

## October 29 physical result: no current owner

The owner ran merged PR #119 on the physical watch and supplied the complete
redacted JSON: `watch_contacted=true`, `state=NO_CURRENT_FOTA_OWNER`, no
UID/executable/binary, and `service_activation_requested=false`. This is an
unowned name at that instant, not a transport failure. The collector did
not independently re-read model/firmware (`device_identity_attested=false`).
Do not repeat the probe or start the consumer just to make an owner exist.

The earlier physical inventory listed the exact 386-byte
`/usr/lib/systemd/system/fota-consumer.service`; its SDB RECV was denied or
unavailable. That supports a **different metadata read**: ask the existing
systemd manager for this known unit's configuration, without guessing an
executable or retrying the unreadable file. The separate optional mode in
the existing collector reuses its original SDB transport and ARM ELF reader:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_fota_owner_readonly.py \
  --watch-ip 10.115.12.131 --copy-configured-unit
cat ~/watch3-r840x-fota-unit-evidence/fota-unit-report.json
```

Use the current local watch IP, with normal Tizen running. The mode:

1. Queries the bus daemon for its ID and the existing systemd manager owner.
   If the manager name is unowned, stops before running systemctl.
2. Runs only a literal `systemctl ... show --all --property=...` command for
   `fota-consumer.service`. It selects unit identity/state, configured
   user/group, bus name, fragment path and `ExecStart`. `show` may load
   configuration into manager memory; it does not start, enable, reload or
   stop the unit. No journal or environment is included in its output.
3. Accepts only the exact observed unit ID/fragment path, a loaded unit and
   a single safe vendor executable in `ExecStart`. Arguments are ignored;
   neither the configured executable nor its arguments are ever executed.
4. Copies that configured path through bounded read-only SDB RECV, accepting
   ARM ELF only. A script or denied file is a failure. Rechecks selected
   unit fields and manager/bus identity before publishing the copy.
5. Creates a separate new mode-0700 directory and mode-0600 JSON plus, on
   success, `fota-configured-executable.bin` for private offline analysis.
   It preserves the earlier no-owner report. Raw responses, arguments, PIDs,
   timestamps and bus identities are not saved.

`CONFIGURED_FOTA_UNIT_BINARY_COPIED_READONLY` means the configured program
was copied. It **does not establish a live `fota.consumer` owner**: owner
UID, observed live executable and owner stability remain unset. Even
`configured_user=root` describes configuration, not a running process's
credentials or phone root access. A wrapper may not implement the endpoint.
Inspect the copied bytes offline before drawing that connection.
`configured_fields_stable` covers only the selected redacted fields at the
observations, not arguments or every intervening process/filesystem state.

If properties are denied, a unit/path is unavailable, or copying fails,
preserve the report and analyze that result first. No automatic service
start, update call, path scan, privilege attempt or firmware change follows.

Primary references: [systemctl show](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html),
[systemd manager API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html),
and [systemd v219's property formatter](https://github.com/systemd/systemd/blob/v219/src/systemctl/systemctl.c).
The parser supports its older `{ path=... ; argv[]=... }` framing and current
Ubuntu output. Watch3 tool support and policy remain unverified until run.

## October 29 physical result: configured consumer captured

The owner ran merged PR #120 and supplied the full redacted report. It
returned `CONFIGURED_FOTA_UNIT_BINARY_COPIED_READONLY`, with
`configured_fields_stable=true` and `binary_copied=true`:

| Field | Actual reported value |
| --- | --- |
| Unit / fragment | `fota-consumer.service` / `/usr/lib/systemd/system/fota-consumer.service` |
| State / type | `inactive` / `dead` / `dbus` |
| Configured bus name | `fota.consumer` |
| Configured user / group | `fota` / `fota` |
| Configured executable | `/usr/bin/fota-consumer` |
| Copied bytes / format | 89,980 / `ARM_ELF32` |
| Reported SHA-256 | `19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a` |

This resolves the previously unknown **configured consumer path**. It is
distinct from the earlier 87,036-byte accessory `fota-service` ELF and the
445,524-byte `updateclient`. The unit stayed inactive; no FOTA method,
service activation, firmware write, root or custom boot was reported.
Live-owner UID remains unset, and `configured_user=fota` supplies neither
a numeric runtime UID nor root access.

The actual copied bytes have not yet been received for offline examination
in this continuation. Preserve the phone's existing capture and attach
`fota-configured-executable.bin`, preferably with `fota-unit-report.json`.
No additional watch probe is needed. On receipt, independently verify the
length/hash above before examining code for endpoint registration/caller
checks, update validation and the recovery handoff. Keep the original ELF
private and never execute it. Metadata and a reported hash alone do not
establish a flaw or an accepted unsigned firmware path.

## Source acquisition crosscheck

Samsung's [exact SM-R840X Korea download page](https://www.samsungsvc.co.kr/download/view?code=SM-R840X&prd1DepNm=%EB%AA%A8%EB%B0%94%EC%9D%BC&prd2DepNm=%EC%9B%A8%EC%96%B4%EB%9F%AC%EB%B8%94)
was fetched on October 28, 2026 and explicitly displayed
`다운로드 컨텐츠가 없습니다.` (no downloadable content). Its public page
script uses `HOME.DOWN_DETAIL` with parameter `stModel=SM-R840X`;
an unauthenticated direct request to that detail API returned HTTP 401.
This rules out treating the catalog's model listing as obtained firmware.
It does not prove Samsung has no separately authorized service image.

## Validation scope

Tests cover fixed outgoing SDB commands, typed reply parsing, PID/path
injection rejection, no-owner early exit, owner/bus restart, proc-exe changes,
private output and discarded partial copies. A real **private host** D-Bus
integration test registers a disposable owner process, queries its actual
PID/UID and proc-exe link, and verifies an activatable service is **not**
started when no owner exists. CI requires this test on Ubuntu 22.04/24.04.
Host tests establish neither watch tool availability nor physical recovery.
Configured-unit tests also run the literal show command against a real
inactive disposable trap unit on Ubuntu 22.04/24.04. CI requires the real
manager and tools; missing prerequisites fail rather than skip. Only that
disposable host fixture is created/removed; no watch is connected.
The host fixture verifies its actual inode before accommodating Ubuntu 22's
`/lib` directory alias in the test's expected location. Its raw show output
is parsed unmodified. Production still requires the exact physically listed
R840X `/usr/lib/systemd/system/fota-consumer.service` path.
