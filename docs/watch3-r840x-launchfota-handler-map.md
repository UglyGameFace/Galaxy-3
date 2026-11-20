# R840X LaunchFota handler: verified map and the one untraced branch

Issue #47. November 20, 2026. Desk audit of everything the
existing offline reviews establish about the `LaunchFota` path,
written before any new decoding, so the remaining gap is exact.
**No method was invoked, no binary was executed, and no watch
state changed. Root, bootloader unlock and stock rescue remain
NOT verified; firmware writes remain NO-GO.**

## Why this map exists

The November 20 reachability run closed every shell trigger
path except one: a D-Bus method call to `fota.consumer`. Whether
such a call would be a harmless ping or a pull of the update
trigger depends entirely on what the consumer's `LaunchFota`
branch does after the shared handler prologue — and that branch
has never been traced. The owner chose the offline trace first
(November 20). This document separates the verified edges from
the single untraced one.

## The call as sent (bapd side — verified)

From `docs/watch3-r840x-bapd-call-review.md` (owner's original
`/bin/bapd`, 103,356 bytes, SHA-256 `429d9611…6e29d300b67ea`):

- A callback registered for bapd's internal `dbus-connected`
  event (`0xac7c`–`0xac88`, callback entry `0xaad0`) contains the
  FOTA request; a local state compared at `0xaafe`–`0xab00`
  skips the request when nonzero.
- The request is constructed with `g_variant_new` at `0xab2a`
  and sent with `g_dbus_connection_call` at `0xab58`:
  destination/interface `fota.consumer`, object `/fota/consumer`,
  method `LaunchFota`, parameter format `(is)`.
- This proves call construction by one privileged Samsung
  daemon in one phone-driven flow. It proves nothing about who
  else may send it, and the receiver's handling is a separate
  question (below).

## The handler as received (consumer side — verified)

From `docs/watch3-r840x-consumer-trust-boundaries.md` and the
analyzer profile in `tools/analyze_watch3_r08_fota_elf.py`
(owner's original `/usr/bin/fota-consumer`, 89,980 bytes,
SHA-256 `19ad8468…c676a1a`):

- The consumer owns `fota.consumer` on the system bus
  (`g_bus_own_name` at `0xac5c`) and registers `/fota/consumer`
  with a vtable whose method callback is the handler at
  `0xba04` (`g_dbus_connection_register_object` at `0xa3f0`).
  Its embedded interface declares 15 methods, each `(is)` in,
  integer out, including `Launch`, `LaunchIp`, `LaunchFota`,
  `Install` and `DeleteTempFile`.
- The handler at `0xba04` overwrites the callback's sender
  register at `0xba08` and the connection at `0xba16`: it does
  not bind the supplied PID/cookie to the actual sender. It
  parses the `(is)` arguments with `g_variant_get` at `0xbab4`
  and frees the cookie string at `0xbb12`.
- It constructs the reply from its own `getpid` (`0xbabc`,
  `g_variant_new` at `0xbad4`) and returns it at `0xbadc`,
  ahead of the later method branches in the body. A returned
  PID proves the consumer answered, not that any firmware
  operation ran.
- The `LaunchIp` region reads `/proc/%d/attr/current` for the
  *claimed* PID (`fopen` `0xbbe8`, `fread` `0xbbfa`) and
  compares SMACK labels with `g_strcmp0` at `0xbc44` / `0xbc52`;
  a mismatch calls `set_current_caller(0)` at `0xc172` and
  rejoins the flow at `0xbc62`. Classification is verified;
  rejection of an unrecognized caller is not.
- One sibling branch **has** been traced (separate manual
  review): the `Install` method-name comparison at `0xbf62`
  leads, after storage-size checks, to helper `0xb144` and
  `_IPC_interfaces`, whose event 4 calls the imported
  `sync_agent_dm_fota_install`. So at least one method branch
  does real work beyond the shared prologue.
- The analyzer's verified call list for this binary (28 calls)
  covers registration, the vconf callback, the update wrapper
  and the handler items above. It contains **no method-name
  dispatch comparison for `LaunchFota`**.

## The gap — exactly what is not known

1. Which comparison chain selects `LaunchFota` in the dispatch,
   and the branch's entry address.
2. What the branch does: whether it only classifies/answers,
   reads or checks the archive directory or consumer state,
   sets any state, or can reach `do_device_control` /
   `device_ctrl_do_firmware_update` without the vconf state-60
   transition that the accessory service normally performs.
3. Whether the `LaunchIp`-style caller classification gates
   the `LaunchFota` branch, and in which order the two run.
4. What the `(is)` arguments mean inside this branch (the
   integer is consumed as a claimed caller PID in the
   classification region; the string's role here is untraced).

Until these are answered, a `LaunchFota` call from the shell
cannot be characterized as safe or unsafe — which is precisely
why none has been sent.

## Trace plan (executes when the binary is in hand)

Input: the owner's `watch3-fota-consumer-evidence.zip` only.
Steps: verify the extracted ELF is exactly 89,980 bytes with
SHA-256 `19ad8468…c676a1a` before drawing any conclusion (a
changed or sibling image gets a separate review); decode the
handler from `0xba04` through the dispatch region with
Capstone (5.0.7 prepared in this workspace), resolving every
`g_strcmp0` method-name comparison and its branch target via
the actual ARM PLT stubs and GOT relocations, never positional
guesses; PLT/GOT-resolve every call inside the `LaunchFota`
branch; cross-check against the analyzer's 28 verified calls.
Publish addresses, call targets and bounded conclusions only —
never vendor bytes.

Pre-registered reading of the outcome:

- If the branch is classification/reply only, a future D-Bus
  probe is a policy ping, and its design can be considered on
  that basis (still a separate owner decision).
- If the branch can set state or reach the update wrapper, a
  probe is a potential update trigger: it inherits the
  firmware-action NO-GO until an offline-verified exact-R840X
  rescue set exists, and the D-Bus door is then recorded as
  trigger-capable, not as an experiment to run.

## Trace result — November 20, 2026

The owner supplied the pinned consumer binary from the phone;
it was verified byte-exact before decoding (89,980 bytes,
SHA-256 `19ad8468…c676a1a`, build ID `bb62b3fe…`, and the repo
analyzer's pinned profile re-verified against it). The handler
was decoded with Capstone, resolving calls through the actual
ARM PLT stubs and GOT relocations (resolver validated against
the known `sync_agent_dm_fota_install` stub at `0x3a44` and the
analyzer's verified call sites). The binary was never executed.

**Dispatch.** The handler compares the incoming method name
with `g_strcmp0` in a chain. The `LaunchFota` comparison is at
`0xc65e` (candidate literal `0x14428` loaded at `0xc658`); on
equality control branches to the branch body at `0xc6f6`. (The
next comparison, `ReadMore` at `0xc66e`, falls through to a
direct call at `0xc67c` and rejoins the common exit.)

**Branch body (`0xc6f6`, complete).** Three operations only:
load the timeout interval `0x3e8` (1000 ms), compute the
callback pointer `0xadb1` (Thumb) by PIC add, and call
`g_timeout_add` at `0xc6fe` — the user-data register holds the
zero left by the equal comparison. Control then rejoins the
handler's common exit at `0xbb36`. The D-Bus reply (the
consumer's own PID) was already returned in the shared
prologue at `0xbadc`. **The branch itself touches no state,
no archive, and no update function.**

**The deferred callback is `_do_launch_oma_dm_agent`
(`0xadb0`)** — identified by its own debug-log function-name
string. One second after the method call it:

1. Tests the OMA-DM enabled marker by opening
   `/opt/usr/data/fota/oma-dm/.oma-dm-agent-enabled` for read
   (helper at `0xa640`: `fopen`/`fclose` only).
2. If that check returns 0, calls the helper at `0xa4a0`,
   which makes a synchronous D-Bus proxy call
   (`g_dbus_proxy_new_for_bus_sync`,
   `g_dbus_proxy_call_sync`) to bus name
   `com.samsung.omadmagent`, object `/com/samsung/omadmagent`,
   method `Launch`, with argument `(i)` built from the
   consumer's own `getpid`. A failure result is logged and the
   flow continues regardless.
3. Reads `db/retailmode/enabled` with `vconf_get_int`
   (helper at `0x9ecc`).
4. Calls `set_fota_context_processing_result` (`0x48f8`,
   device-ctrl.c), which performs
   `vconf_set_int(db/fotaconsumer/fota_enabler, 10)` when the
   retail-mode value is positive, else `…, 0)`.
5. Calls `_fota_consumer_terminate` (`0xad1c`), which quits
   the consumer's main loop (`g_main_loop_quit`) when one is
   running. The callback then returns FALSE, so the timeout
   is one-shot.

**Bounded conclusion.** Inside this binary, `LaunchFota` is a
**handoff, not an update trigger**: it wakes the separate
OMA-DM agent (when the enabled marker is absent), records the
retail-mode-derived `fota_enabler` value, and the consumer
exits. The traced chain contains **no** call to
`do_device_control` (`0x6530`), `device_ctrl_do_firmware_update`
(`0x61d0`), `_pre_update_client` (`0x437c`), any
`sync_agent_dm_fota_*` import, and no access to
`/opt/usr/data/fota/save`, `delta.tar`/`delta.ua`,
`/opt/data/recovery/DELTA.PATH`, or the vconf keys
`db/fotaconsumer/ui_state` / `db/fotaconsumer/state`. Under
the pre-registered reading, a future D-Bus probe of this
method is therefore **not** a firmware action — but it is not
a no-op either: its real side effects are an OMA-DM agent
launch, a vconf write, and the consumer process exiting (it
is D-Bus-activated and would start again on demand). Two
questions stay open and are **not** answered by this trace:
whether the shell's principal may send the method at all
(bus policy, still UNDETERMINED), and what the OMA-DM agent
does after being launched with `fota_enabler` set — that
behavior lives in the separate `oma-dm-agent` binary and
nothing here establishes it. Any probe remains a separate
owner decision; root, bootloader unlock and stock rescue
remain NOT verified, and firmware writes remain NO-GO.
