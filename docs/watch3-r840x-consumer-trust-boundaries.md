# Original R840X consumer: verified offline trust boundaries

Issue #47. October 29, 2026. The owner's original `/usr/bin/fota-consumer`
has now been received and examined. **No device unlocking, root, accepted
unsigned kernel or tested stock restoration has been demonstrated.**

## Original bytes and validation

The owner's `watch3-fota-consumer-evidence.zip` contains only the captured
ELF and its redacted configured-unit report. Independently verified:

- 89,980 bytes; ARM ELF32 little endian, PIE.
- SHA-256: `19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a`.
- GNU build ID: `bb62b3fe4f1f2ae02cd58c18dd39bff093a2a9cd`.
- Build-path text identifies `fota-consumer-1.1.4`; this is a binary build
  hint, not a fresh attestation of installed firmware or package metadata.
- The supplied actual watch report identifies `Type=dbus`,
  `BusName=fota.consumer`, `User=fota`, `Group=fota`, inactive/dead.
  This describes configuration, not an observed running process UID.

The original vendor file remains private. It was not run, transferred to
CI, committed or modified. Capstone 5.0.6 decoded the selected instructions;
a separate standard-library decoder then verified the same call targets.
PLT names were resolved through the **actual ARM stub and GOT relocation**,
not the apparent PLT position. The result verifies 28 selected calls,
15 jump-slot resolutions, 10 PC-relative text references, eight control
instructions, the callback pointer and embedded interface definitions.
These are selected reviewed boundaries, not a complete control-flow proof.
All 180 focused local regressions also pass with unmocked SDB connections
rejected before network access. Five older output-collision fixture scopes
were corrected so they exercise actual collision handling through fake
data, rather than falling through to an unmocked connection attempt.

## What the original code establishes

All code addresses below are ELF-relative virtual addresses. Thumb function
pointers have their low bit set; the table contains `0xba05`, code `0xba04`.

| Boundary | Original instruction evidence | Meaning and limit |
| --- | --- | --- |
| Service registration | `0xac50`: system-bus enum 1; `0xac5c`: `g_bus_own_name`; `0xa3f0`: `g_dbus_connection_register_object`, object `/fota/consumer`, vtable `0x2500c` containing `0xba05` | This file registers the expected endpoint. No endpoint was started or called during analysis. |
| Caller input | Handler `0xba04`; original callback sender register overwritten at `0xba08`, connection overwritten at `0xba16`; `0xbab4`: `g_variant_get` with `(is)`; `0xbb12`: `g_free` on the cookie | The handler does not bind the supplied PID/cookie to the original sender in this reviewed body. External bus policy and MAC permissions remain unknown. |
| Reply | `0xbabc`: `getpid`; `0xbad4`: `g_variant_new`; `0xbadc`: return value, before later method branches | A returned process PID would not prove a successful firmware operation. No such call was made. |
| Claimed caller classification | `LaunchIp` builds `/proc/%d/attr/current`, reads it at `0xbbe8` / `0xbbfa`, compares labels at `0xbc44` / `0xbc52` | Recognized labels select caller category 1; mismatch calls `set_current_caller(0)` at `0xc172`, then rejoins `0xbc62`. This is classification, not a demonstrated rejection of an unauthorized caller. |
| Actual update entry | `main` registers callback `0xa821` for `db/fotaconsumer/ui_state` at `0xcc28`; callback calls `do_device_control` at `0xa84e` | The update path is connected to vconf state notifications. This does not prove a reachable arbitrary method-to-update path from the owner's SDB shell. |
| State checks | `do_device_control` compares consumer state with 60 at `0x656a` and 65 at `0x6572`; the installation branch calls `device_ctrl_do_firmware_update` at `0x6686` | State gates exist; no vconf key was changed. State 65 enters result/error handling, including the verification-failure marker. |
| Recovery preparation | Calls at `0x62ba`, `0x6312`, `0x6348`, `0x63de` | The actual wrapper extracts `delta.ua`, writes the recovery handoff path, processes the nested pre-update program, then calls `rw-update-prepare.sh FOTA`. These commands were decoded only. |
| Reboot | `0x66a8`: `request_reboot`; `0x42ec`: `device_power_reboot` | An installed recovery is the subsequent trust boundary; no reboot was requested. |

The embedded interface contains 15 methods, each with integer/string input
and integer output, including `Launch`, `LaunchIp`, `LaunchFota`, `Install`
and `DeleteTempFile`. The actual handler must be traced separately from
those declarations: an advertised name alone proves no operation or caller
authorization. API reference for the sender and parameter positions:
[GLib GDBusInterfaceMethodCallFunc](https://docs.gtk.org/gio/callback.DBusInterfaceMethodCallFunc.html).

## Nested archive execution boundary

In `device_ctrl_do_firmware_update` (`0x61d0`), the reviewed sequence:

1. Generates an MD5 log for `delta.tar` at `0x621e`. This function reads and
   logs it; no comparison against a trusted expected digest is visible here.
2. Extracts `delta.ua` from the fixed archive at `0x62ba`. A missing extracted
   file is logged; this wrapper still proceeds to the next stage.
3. Writes `/opt/usr/data/fota/save` into
   `/opt/data/recovery/DELTA.PATH` at `0x6312`.
4. Calls `_pre_update_client(delta.tar, "pre_update_client_2")` at `0x6348`.
5. Calls `/usr/bin/rw-update-prepare.sh FOTA` at `0x63de`.

The named `_pre_update_client` function (`0x437c`) extracts `pre_update.tar`
from the archive via `system_cmd` at `0x43fc`. If that file exists, it extracts
the requested program from the nested archive at `0x447c`. It constructs
`/opt/usr/data/fota/save/pre_update_client_2`, checks existence, and passes
that path to `system_cmd` at `0x44f0`. That helper forks at `0x8e72` and uses
`execve` at `0x8f7e` with `/bin/sh`, `sh`, `-c`, and the command text.

**This is an archive-supplied program execution boundary in the original
binary.** No explicit signature-verification gate was observed inside this
wrapper before that call. This does not rule out validation earlier in the
pipeline, in a called library, MAC enforcement, or later recovery/bootloader
checks. A missing nested pre-update archive is tolerated. A nonzero
pre-update result takes the logging/cleanup branch at `0x643c`, which rejoins
preparation at `0x6350`; it does not establish an aborting signature gate.

The MD5 operation is not evidence of keyed authentication. The imported DES
functions are a separate observation; their presence supplies no proof of
firmware-signature verification or bypass. Samsung's
[July 2021 wearable bulletin](https://security.samsungmobile.com/serviceWeb.smsb?year=2021&month=7)
documents FOTA validation/access-control vulnerabilities CVE-2021-25436 and
CVE-2021-25437, but neither bulletin nor these observations alone establishes
that a specific exploit succeeds on this R840X build.

The consumer therefore supplies the previously missing **actual Samsung
handoff** between its accessory archive directory and recovery metadata.
It does not supply `delta.ua`, a signed rescue image, original S-BOOT,
authenticated PIT, writable attack surface or unsigned-kernel acceptance.

## Crosscheck with the original accessory service

After the preparation-script read failed, recovered the owner's earlier
private `watch3-fota-service.bin` upload and independently reverified its
87,036-byte length and SHA-256
`008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757`.
This is the accessory service, distinct from the consumer above. No new
watch request or vendor-code execution was involved.

| Accessory-service stage | Original ELF-relative evidence | Bounded conclusion |
| --- | --- | --- |
| SAP connection admission | `0x6c24` calls `launch_fota_consumer("Launch")`; `0x6c3c` calls `acceptServiceConnection` on the accepted branch | The consumer launch attempt precedes accepting this connection. The library's peer authentication and actual caller policy are not established by this wrapper. |
| File completion | `0x6732` calls `chmod` with mode `0x1b6` (0666); state comparison at `0x6754` is 30; success branch `0x680e` / `0x6810` sets state 50 | This callback changes ordinary mode bits before its status/state handling. Its success transition is 50, not the installation state 60. MAC policy and an attacker's write access are unknown. |
| Request dispatch | Parser call `0x8632`; guarded TBH table at `0x866e`, indexed by parsed structure field `+0x34`; entry 8 resolves to `0x8838` | That branch loads 60 and calls `set_fota_consumer_state` at `0x883a`, then builds a response at `0x8842`. No protocol request was sent. |
| Notification bridge | A successful `send_msg_to_sap` at `0x86de` reaches `_do_device_control` at `0x8754`; that routine compares states 60/65 | On its state-60 branch, `0x760a` calls `vconf_set_int` for `db/fotaconsumer/ui_state`. The state setter at `0xaaa4` uses `db/fotaconsumer/state`. |
| Consumer-side continuation | The independently captured consumer registers its callback for the same `db/fotaconsumer/ui_state` key at `0xcc28` | This connects the two original wrappers' static handoff to the already reviewed update path. Runtime notification delivery, permissions and successful installation remain untested. |

Verified 14 selected accessory calls with both the existing Thumb decoder
and Capstone 5.0.6, six actual PLT/GOT jump-slot resolutions, seven control
assertions and two state-key references. The earlier callback observations
therefore do not imply that receiving a file automatically installs it.
No archive-signature gate was observed **inside this completion callback**;
upstream library/phone validation and later recovery checks remain unknown.
The consumer's named download-completion check also inspects configured
object size and actual file size; its name alone does not establish
cryptographic verification.

## The separate Install method reaches an imported implementation

Further review of the same original consumer distinguishes its D-Bus
`Install` branch from the accessory state-notification path above. The
method comparison calls `g_strcmp0` at `0xbf62`. On the matching branch,
after the visible storage-size checks, `0xc062` calls the helper at
`0xb144`. That helper loads `(r0,r1,r2)=(4,1,0)` and calls
`_IPC_interfaces` at `0xb2d2`.

Inside `_IPC_interfaces`, `0x7d86` calls `sync_agent_dm_set_task_id`.
The event dispatch subtracts one at `0x7da4`, bounds-checks at `0x7da6`,
then uses the actual TBB table at `0x7daa`. Its event-4 entry at `0x7db1`
contains `0x41`, resolving to `0x7e30`. That branch copies the retained
argument 1 into `r0` and calls imported `sync_agent_dm_fota_install` at
`0x7e32` through PLT `0x3a44`, GOT `0x252a8`.

The original ELF's dynamic dependency list includes `libsync-agent.so.0`.
The implementation of the imported call is not in the captured consumer;
its runtime provider, installed file path and validation behavior remain
unobserved. Thus a visible caller without a signature check cannot establish
that the full installation pipeline omits one. This identifies a concrete
missing implementation rather than another guessed script name.

Independently matched six selected immediate calls with the existing
standard-library decoder and Capstone, three actual PLT/GOT relocations,
the TBB target and fixed argument loads. These additional manual checks
are separate from the analyzer's existing 28-call report. No method was
invoked and no vendor code was executed.

## Reproduce the offline review

This extends the existing analyzer; its default accessory `fota-service`
profile and output remain available. The new profile needs only Python's
standard library and the existing captured file on the owner's phone:

```sh
python tools/analyze_watch3_r08_fota_elf.py --component fota-consumer
```

It writes a new private, no-overwrite
`~/watch3-r840x-fota-consumer-static-analysis.json`. It requires the exact
89,980-byte hash before producing reviewed conclusions. The report includes
only selected public API names, fixed reviewed paths, numeric instruction
evidence and limitations. No credentials, arbitrary strings, raw vendor
code, network or watch interaction are involved. A changed/sibling image
must receive a separate review and cannot inherit these findings.

## Preparation-script acquisition result: blocked

The actual original instruction at `0x63da` resolves the literal
`/usr/bin/rw-update-prepare.sh FOTA` and passes it to `system_cmd` at
`0x63de`. The owner ran merged PR #121's exact `--component update-prepare`
read on normal Tizen and received
`RECOVERY_SCRIPT_ERROR: REMOTE_MISSING_DENIED_OR_UNREADABLE`.

That category comes from the remote SDB sync FAIL after the bounded read
request, not a local report collision or a successful capture. It does not
distinguish absence from denied/unreadable content. No script bytes or JSON
report were acquired. The local directory may exist empty; the owner's
`&&` command chain stopped before packaging, so there is no new ZIP to send.

Record this unsuccessful sync read alongside the earlier unsuccessful
`recovery-update.sh` and `rw-update-systemd.sh` reads. Repeating the unchanged
collector would not distinguish their causes: its shared decoder discards
the remote FAIL text and emits the combined category. This is a limitation
of the diagnosis, not proof of permanent inaccessibility or a restriction
on the owner's authorized investigation. The installed ELF's literal remains
evidence of intended behavior, not proof that the script exists on this
installed image.

Offline cross-artifact analysis above used the original files already
captured. The remaining proof gates are runtime privileges/bus/MAC access,
archive control and prior verification, the original recovery verifier and
update agent, plus exact-model signed rescue/S-BOOT and tested return to
stock. A working unlock or recovery procedure has not been established.
