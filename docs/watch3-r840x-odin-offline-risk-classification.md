# SM-R840X wireless Odin: VERIFIED transport, NO-GO command matrix

**Research task:** [Issue #47](https://github.com/UglyGameFace/Galaxy-3/issues/47).
**Target:** owner’s single working SM-R840X R08, stock
`R840XXXU1AUA2`, Tizen 5.5, Android-only Termux development.
**Research mode:** source-only / filesystem-local, with the watch
left in normal stock Tizen. No live Odin session, PIT read/write, firmware
upload, partition mutation, bootloader attack or forced reboot.

## Exact hardware facts: October 27, 2026

- Owner photographed the real `Select REBOOT MODE` menu containing
  `Download (Wireless)`, observed its **approximately five-second**
  timeout, then entered download mode.
- Owner photographed `[WPS Mode] Not connected`, then after the
  model-specific physical double-press photographed
  `[AP Mode] SM-R840X` and `Wait for AP connection`.
- Their Android Termux host was assigned `192.168.49.20` on the
  temporary watch AP and the repository's **existing** strict
  magic-only client reported
  `ODIN_LOKE_MAGIC_VERIFIED_UNAUTHENTICATED_PEER` and
  `received_loke=true` at TCP port `13579`. On-wire bytes from
  host were only four ASCII `ODIN`, with four ASCII `LOKE` read back.
- The watch displayed
  `wd_core_process_cmd: Failed to recv cmd (0 != 1024)`. This is
  **consistent** with Ragnarök's source-documented follow-up 1024-byte
  command frame expectation and the intentionally closed client;
  it does NOT prove a complete diagnosis or absence of damage in
  other circumstances.
- After exiting Wireless Download, the owner explicitly confirmed
  the original watch **booted normally back into stock Tizen**.
  No regular Odin command, session-start, PIT request or firmware
  write was issued, and no custom kernel boot tested.
- The magic does not cryptographically authenticate the remote peer;
  the separate physically observed bootloader screen supplies
  independent evidence about the model. Normal reboot after this
  bounded test does **not** prove restore after failed firmware write.

## Source of protocol facts (frozen upstream commit)

This catalog was researched directly from AsteroidOS Ragnarök at
`f9164d2c227369ba711d89f12eef99186df61387`, in:

- [PROTOCOL.md](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/PROTOCOL.md)
  (TCP/13579, `ODIN`/`LOKE`, 1024-byte command frames,
  opcode/argument conventions; notes are explicitly incomplete).
- [magic_handshake.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/magic_handshake.rs)
  (four-byte magic, no session framing).
- [cmd.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/types/cmd.rs)
  and [cmd_packet.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/types/cmd_packet.rs)
  (0x64 session, 0x65 PIT, 0x66 flash, 0x67 end; fixed
  1024-byte host-to-target packets).
- [begin_session.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/begin_session.rs)
  (`0x64/0x00` negotiation, `0x64/0x05` packet sizing and
  `0x64/0x07` **erase user data**).
- [download_pit.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/download_pit.rs)
  and [flash_pit.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/flash_pit.rs)
  (PIT read-intent `0x65/0x01` versus repartition/write
  `0x65/0x00`).
- [end_session.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek/src/download_protocol/end_session.rs)
  (`0x67` may change session/power state).
- [CLI main.rs](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/ragnaroek-cli/src/main.rs)
  (`detect`, `print-pit`, and `save-pit` call
  `Session::begin`; `detect` also calls session end).

### Why “read-only” cannot be inferred from a command name

| Opcode / argument | Ragnarök behavior | Risk decision on the only Watch3 |
| --- | --- | --- |
| Four ASCII `ODIN`, receive `LOKE` | Magic exchange only, **physically observed** | Verified once; no reason to repeat |
| `0x64 / 0x00` | Begins/negotiates session | **NO-GO**: not passive, unknown loader side effects |
| `0x64 / 0x05` | Sets transfer packet size | **NO-GO**: changes transfer parameters |
| `0x64 / 0x07` | Factory reset / erase userdata | **NO-GO**: explicitly destructive |
| `0x64 / 0x08` | T-Flash storage mode | **NO-GO**: changes target |
| `0x65 / 0x01` | Requests PIT data, *after* session start | **NO-GO**: read intent alone does not prove safe |
| `0x65 / 0x00` | Uploads/replaces PIT partition layout | **NO-GO**: repartition / possible brick |
| `0x66 / 0x01` | Requests partition content dump in protocol docs | **NO-GO**: unverified device effects and potential sensitive data |
| `0x66 / 0x00` | Begins firmware flash transfer | **NO-GO**: possible permanent mutation |
| `0x67 / 0x00..0x03` | Ends session, possibly reboot/shutdown | **NO-GO**: state-changing; support unknown |

**Important:** Ragnarök CLI `detect` is **not just TCP ping or
a four-byte handshake**. It calls `Session::begin`, which emits the
1024-byte session-start command, then calls session end.
`print-pit` and `save-pit` likewise start a session before any
PIT transfer. Even a purportedly read-only PIT dump requires sending
loader commands and cannot be approved without full device-specific
behavioral evidence and a credible restore path. None of these
were tested on the owner's watch.

## Software safety tripwire (no live test)

New `tools/audit_watch3_r840x_odin_offline.py`:
1. Parses the **existing, source-controlled** four-byte magic-only
   Python client with `ast` and `ast.literal_eval`, without
   importing, executing, or connecting it.
2. Verifies its fixed literal `MAGIC_OUT=ODIN`,
   `MAGIC_IN=LOKE`, TCP port `13579`, exactly one
   `peer.sendall(MAGIC_OUT)`, and a single bound
   `peer.recv(4-len(answer))`. It rejects additional direct send
   sites, altered response size, dangerous dynamic execution
   calls and unexpected packet-oriented execution module imports.
3. Outputs a fixed, source-pinned, **NO-GO** command/argument matrix
   and records that no 1024-byte command was ever tested.
4. Has **no socket, subprocess, network, connection or
   firmware API**. All CLI flags relate only to a local JSON report.
   If a report file is requested, it is created mode 0600 with
   exclusive no-overwrite. No raw watch secrets are used.
5. The guard is intentionally narrow: AST patterns are a
   *regression tripwire*, **not a proof against arbitrary Python
   behavior** or a substitute for peer review. It also does not
   prove the safety of imported helper functions or of the hardware.
6. In-memory tests intentionally mutate the client (extra sends,
   changed magic/port, 1024-byte receive, `subprocess`, `exec`)
   and verify that the audit fails. The existing network contract
   tests use loopback, not the real watch, and the workflow runs
   Ubuntu 22.04 + 24.04 with no device connected.

To inspect locally in Termux after merge, while leaving the watch
in normal Tizen:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/audit_watch3_r840x_odin_offline.py \
  --report ~/watch3-r840x-offline-odin-risk.json
cat ~/watch3-r840x-offline-odin-risk.json
```

This is optional; repository CI already checks this risk matrix.

## Real remaining safety blockers

- No authenticated complete **OEM SM-R840X**
  `R840XXXU1AUA2` stock restoration set with independently
  verified firmware-signature provenance.
- No authentic matching PIT/rollback compatibility audit.
- No demonstrated recovery after a damaged/erased boot or recovery
  partition on a sacrificial R840X or supported repair fixture.
- No verified loader support for safe temporary custom kernel
  loading, OEM unlocking or accepted unsigned image boot.
- The original AsteroidOS ext4 is archived but **not a flashable
  Samsung firmware archive**.

**Current policy: NO FURTHER LIVE ODIN COMMAND EXPERIMENT.**
The verified magic-only result is enough to move the investigation
into static OEM firmware provenance and independent recovery
feasibility. If a future session were ever proposed, it would
require separate evidence, threat review, recovery validation and
the owner's specific informed approval.
