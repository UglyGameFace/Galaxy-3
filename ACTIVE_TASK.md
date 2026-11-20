# UgLy|OS Galaxy Watch3 R840X recovery and boot

Updated November 15, 2026. **Open issue #47.** Work is restricted to
the owner's Samsung Galaxy Watch3 **SM-R840X**, NOBLESSE-LARGE-BT R08,
stock version R840XXXU1AUA2, CSC PAP candidate. Android/Termux only,
free only, preserve the working watch. The target is a verified
**exact-variant stock rescue** followed by reproducible UgLy|OS boot.

## November 19, 2026: runtime D-Bus capture executed; one header fact left

The owner ran merged #142's `--runtime-ip` collector once on the
physical watch. The `dbus.service` unit query succeeded: loaded,
active, running, MainPID present, configured daemon family
`DBUS_DAEMON` (classic dbus-daemon, not dbus-broker), and **no**
explicit `--config-file` flag in the configured `ExecStart`. The
process snapshot returned `PS_LAYOUT_UNSUPPORTED` — the watch's real
`ps` header is not the previously assumed BusyBox
`PID USER VSZ STAT COMMAND` layout, the raw output was discarded as
designed, and no running process was attested. Established: the
configured unit and daemon family only. Still unknown: the config
file the running daemon actually loaded, the complete effective
policy, sender bus UID, SMACK/Cynara and consumer-side checks.
Effective shell send permission remains **UNDETERMINED**; this is not
root and not a FOTA authorization. A bounded `--ps-header-ip`
follow-up (retains only the `ps` column titles, discards every row)
is prepared so the runtime parser can learn the real layout; after
that single attestation re-run, read-only D-Bus provenance work is
exhausted and the remaining D-Bus unknowns are not reachable by these
collectors. **ROOT NOT VERIFIED; STOCK RESCUE NOT VERIFIED; LIVE
FIRMWARE WRITES NO-GO.** Keep Issue #47 open.

**November 20 follow-through:** The owner executed `--ps-header-ip`
on the physical watch. The real header is `PID TTY TIME CMD`
(procps), and plain `ps` in the SDB shell returned exactly one row —
it is session-scoped and could never have shown the system-bus
daemon. The runtime parser now accepts that exact layout, and the
allowlisted snapshot command is the fixed literal `ps -e`. The
final `--runtime-ip` re-run was executed the same night: the
snapshot parsed and returned zero daemon candidates — the running
daemon's arguments are not visible from the UID 5001 shell even
with `ps -e` (restricted process visibility is the consistent
inference). **Read-only D-Bus provenance is closed**: configured
daemon family and ExecStart known, running arguments unattested,
effective permission UNDETERMINED. Remaining routes: the authentic
rescue-firmware hunt and CVE-2021-25434–25437 exact-binary
research. **ROOT NOT VERIFIED; STOCK RESCUE NOT VERIFIED; LIVE
FIRMWARE WRITES NO-GO.** Keep Issue #47 open.

**November 20 research synthesis (owner directive: free routes
only, reverse engineer):** Three sweeps closed the literature
routes. No lawfully obtainable R840X-specific U1 firmware exists in
any public source; the only real combination artifact is the retail
SM-R840 FT55 set behind a paywall, and the owner declined paid
routes. The R810 sibling recipe reduces to that same missing
combination sboot. The CVE literature contains nothing further
(researcher Soomin Shin, WatchOver/KITRI BoB; no writeups or PoCs
exist). The live free routes are therefore: (1) continued offline
reverse engineering of the already-captured FOTA binaries — the
consumer's archive-supplied pre-update execution has no observed
signature gate, while the OMA-DM daemon verifies and its plugin
continues anyway; the open question is UID 5001 reachability of the
archive directory and state keys; and (2) the new read-only
kernel-gate collector (`tools/watch3_r840x_kernel_gate_readonly.py`,
doc `docs/watch3-r840x-kernel-gate-readonly.md`), whose four fixed
probes (machine class, Binder node presence, BPF switch) decide
whether the CVE-2019-2215 Binder family exists on this device at
all. One owner run of that collector is the next physical step.

**November 20 kernel-gate result:** The owner executed the
kernel-gate collector on the physical watch; all four probes
classified. Machine class is `AARCH64_64BIT` — the watch itself is
64-bit, correcting the earlier inference from R810 evidence
(dzImage/Thumb-2) that the stack was almost certainly 32-bit.
`/dev/binder` is **ABSENT** and `/dev/binderfs/binder-control` is
**ABSENT**, so the report's binder gate is
`BINDER_NODE_ABSENT_GATE_CLOSED`: the CVE-2019-2215 Binder family
does not exist on this device, regardless of patch state, and
kernel-LPE research through this collector stops, as the doc
pre-registered. The BPF probe classified `SETTING_ABSENT` (the
`unprivileged_bpf_disabled` sysctl file is not present), which is
a classification, not a 0/1/2 value. An earlier report file under
the first filename held a partial run (Binder and machine probes
connection-failed, gate UNDETERMINED) and is superseded by this
complete run. The remaining live free route is the FOTA consumer
reverse-engineering line and its open UID 5001 reachability
question (archive directory and state keys). **ROOT NOT VERIFIED;
STOCK RESCUE NOT VERIFIED; LIVE FIRMWARE WRITES NO-GO.** Keep
Issue #47 open.

**November 20 reachability collector prepared:** A read-only
collector for that reachability question is now built
(`tools/watch3_r840x_fota_reachability_readonly.py`, doc
`docs/watch3-r840x-fota-reachability-readonly.md`): eight fixed
probes covering the shell UID class, metadata and listing classes
for `/opt/usr/data/fota/save` and its parent, the
`/opt/data/recovery` directory and DELTA.PATH node presence, and
read-only gets of the `db/fotaconsumer/ui_state` and
`db/fotaconsumer/state` vconf keys. It creates no file, sets no
key, calls no FOTA method; a POSIX write bit would be reported
as a class only, never tested. One owner run is the next physical
step. Separately, the offline consumer RE continuation still
needs the October evidence ZIPs re-attached from the owner's
phone (they do not persist in this workspace).

**November 20 reachability result:** The owner executed the
reachability collector on the physical watch; all eight probes
classified. Shell UID confirmed 5001. The archive directory
`/opt/usr/data/fota/save` is **PRESENT** with shell-class access
`READ_WRITE_TRAVERSE` (owner and group are both other, so the
world bits apply), and the shell **empirically listed it**
(`LISTABLE`, 1–5 entries present, names discarded by design);
its parent `/opt/usr/data/fota` is `READ_TRAVERSE` for the
shell's class, so the traversal chain is open and read/traverse
passed the live system, not just the mode bits. The other half
of the question closed: `/opt/data/recovery` is `NO_ACCESS` for
the shell's class and the DELTA.PATH node probe returned
`ACCESS_DENIED`, and **both** vconf gets
(`db/fotaconsumer/ui_state`, `db/fotaconsumer/state`) returned
`ACCESS_DENIED` — the shell can neither read nor (by the same
gate) drive the consumer's state keys, and cannot touch the
recovery handoff side. Net: archive **placement** is POSIX-open
and read-proven, but no write was attempted (an actual create
under SMACK is still untested), and the vconf **trigger** is
closed to the shell; per the consumer review, state 60 is set
by the accessory service, not by any shell tool. The only
trigger door not yet classified is a D-Bus method call to
`fota.consumer` itself, which is a deliberate service
invocation, not a read, and remains a separate owner decision.
**ROOT NOT VERIFIED; STOCK RESCUE NOT VERIFIED; LIVE FIRMWARE
WRITES NO-GO.** Keep Issue #47 open.

## November 15, 2026: stock Tizen root is the immediate objective

**Owner request:** Restore progress on obtaining root on the *physical*
Samsung Galaxy Watch3 SM-R840X (`R840XXXU1AUA2`) using Android/Termux.
Keep **stock-Tizen UID 0** distinct from a bootloader unlock, arbitrary
code execution, custom kernel boot, and complete UgLy|OS installation.
An exploit/handshake, SDB access, archive parser, or offline boot model
does **not** prove root. A legitimate root milestone requires independent
on-watch `id -u` / effective UID 0 and a reproducible mechanism.

**Repository and hardware reconciliation:** At this review, `main`'s
last returned commit before this status-only update was
[`b41a617`](https://github.com/UglyGameFace/Galaxy-3/commit/b41a617733d473ddcf60945c305599ac446f4b87)
(2026-11-01). No open PRs were returned. Merged #142's bounded
`--runtime-ip` system-bus provenance mode remains **not run on the
watch**. Earlier actual physical `sdb root on` was denied with
`sdbd_rootperm:disabled`, `rootonoff_support:disabled`, UID/EUID 5001
and zero effective caps; do not retry it without new evidence.
The 2026-10-30 corrected original policy-file review matched a later
`fota.consumer` default allow **within the observed three-file subset**,
but not the actual runtime sender authorization or consumer checks.

**Exploit research reassessment:** Samsung's primary wearable bulletin
identifies pre-July-2021 Galaxy Watch3 bootloader param/recovery bugs
CVE-2021-25434/25435 and FOTA/SAP bugs CVE-2021-25436/25437:
https://security.samsungmobile.com/serviceWeb.smsb?year=2021&month=7 .
The original researcher lists these CVEs:
https://github.com/imssm99 .
This review did not locate public, exact-R840X code/PoC and recovery proof
for any of them. The CVEs are credible **research leads**, not a
working root procedure or permission to upload an arbitrary archive.
Current AsteroidOS OEM-unlock steps for Wear OS Galaxy Watch4+/FE are
**inapplicable** to this Tizen Watch3:
https://wiki.asteroidos.org/index.php/Fresh/wise .
As of this review the public AsteroidOS supported/experimental catalog
does not establish a Watch3 port:
https://flash.asteroidos.org/watches/ .
Third-party `R840XXXU1ATFA` and engineering `R840XTXXU1ATH1`
listings do not prove a genuine complete `R840XXXU1AUA2` rescue,
signature acceptance, safe downgrade, or a recoverable flash route.

**Next one-device evidence action:** On the *already authorized*
watch SDB connection, run merged
`tools/watch3_r840x_dbus_policy_readonly.py --runtime-ip <CURRENT_WATCH_IP>
--report <NEW_PRIVATE_JSON_PATH>` from Termux (see
`docs/watch3-r840x-dbus-policy-readonly.md`). This reads fixed
system-bus unit/process metadata only; it does not call any FOTA
method or test exploitability. The output can determine whether
further **offline** D-Bus policy work is worthwhile, not deliver root.
Separately seek an authorized unmodified original exact-R840X
firmware/S-BOOT set or a *sacrificial* R840X restoration study.
No synthetic scanners, repeated root-switch calls, blind Odin writes,
`LaunchFota` requests, recovery overwrites or supposed Wear OS unlocks.
**Current result: ROOT NOT VERIFIED; STOCK RESCUE NOT VERIFIED;
LIVE FIRMWARE WRITES NO-GO.** Keep Issue #47 open.

## Current verified state — November 1, 2026

**Latest main integration:** #143 (pinned original SM-R500 PIT guard opcode
exercise) merged as `e285350`, with original-firmware workflow
[41354502464](https://github.com/UglyGameFace/Galaxy-3/actions/runs/41354502464)
**passed**. #142 (bounded read-only live-system-bus provenance collector)
merged as `716d0b7`, after both Ubuntu 22.04/24.04 test jobs passed
[41122092047](https://github.com/UglyGameFace/Galaxy-3/actions/runs/41122092047).
GitHub reported zero open PRs at the time of this reconciliation. These
are separate additive investigations; neither is an authorization bypass.

**Donor opcode result:** Actual SHA-pinned 2019 and 2021 *SM-R500* ARM64
S-BOOT guard opcodes have matching seven-case synthetic register-input
branch classifications. The original instruction width is derived from
the opcode rather than assumed. This does **not** emulate Samsung's full
firmware/TrustZone/hardware, authenticate exact R840X firmware, verify
firmware signature policy, or prove R840 and R840X recovery equivalence.

**Target physical evidence:** Real R840X (R840XXXU1AUA2, active CSC PAP)
did previously prove Wi-Fi SDB reads and ODIN/LOKE four-byte transport,
21 named kernel partition text records (including boot, recovery, param)
and read-only FOTA daemon/policy analysis. No working root, unsigned
image acceptance, original stock rescue package, or recoverable custom boot
has been demonstrated. The owner's corrected focused D-Bus offline audit
did pass its **file-level** default-rule checks; actual system-bus loaded
configuration and User::Shell authorization are still unverified. The newly
merged `--runtime-ip` mode has **not** been physically executed.

**Firmware sourcing (repeat-scan avoided):** Samsung PAP public version
metadata matches the installed build but does not yield an authenticated
download. Historic third-party exact-variant `R840XXXU1ATFA` repair
catalog entries require access/payment and no ZIP bytes, OEM signatures,
manifest or compatible rollback proof are in research custody.
Retail `R840XX...`, engineering `R840XTXX...`, and an SM-R500 donor
are not interchangeable signed R840X recovery packages. Repeating catalog
searches or constructing more filename-only scanners does not close this
gap.

**Next evidence gate:** (1) Obtain a legally sourced **actual, unmodified
SM-R840X** BL/AP/CSC or original S-BOOT/boot/recovery/PIT set and verify
model/build, source provenance, SHA256, manifest, signatures and rollback
compatibility **offline** before comparing functions; or (2) independently
study exact-variant restoration on a sacrificial R840X / qualified repair
fixture. Separately, the already merged read-only `--runtime-ip`
collector may be run by the owner in Android/Termux to classify the
actual D-Bus process, but no new tool or privileged watch operation is
needed for that. Do not mistake a process identification for a privilege
or recovery grant. **FLASH / PARTITION WRITES / FOTA INVOCATION: NO-GO.**
Issue #47 stays open.

## Actual physical evidence

- **No unlock, root or custom recovery:** The native reader on the watch
  ran as UID/EUID 5001, User::Shell, with zero effective/permitted caps;
  earlier root-on failed. A prior ODIN/LOKE greeting proved transport
  recognition, not image acceptance, PIT or flash recovery.
- **Original private evidence pinned:** Owner's
  `watch3-privilege-inventory.zip` SHA-256
  `2454c2cbe7826a14984669bfad0e0da8ca92cfcacc51cfb59afd67c833c6083d`.
  Original `/bin/bapd` ARM ELF32 SHA-256
  `429d9611c47b2cebc8918294f076ce013c1947f74441b374b306e29d300b67ea`.
  Keep raw vendor binaries, credentials and device evidence **out of Git**.
  Physical privilege scan: 64 retained, 82 dropped records; 44
  copy candidates not selected; stat errors/incomplete inventory.
- **Original FOTA handoff:** Verified BAPD Thumb callsites send
  `fota.consumer.LaunchFota` on `/fota/consumer` with `(is)` arguments.
  A `dbus-connected` callback registration at `0xac7c` points to
  `0xaad0`; nonzero state branches around the call at `0xab58`.
  Static execution path only, not a user-triggerable update or bypass.
- **Exact owner-captured system-bus policies:** Original
  `/usr/share/dbus-1/system.conf` SHA-256
  `df59ef6b3bd808b8b131fc5eef7c45dd98622d5a52473ab3dd1f4f542b0d7cb1`
  has a default method-call deny and includes `/etc/dbus-1/system.d`.
  Original `/etc/dbus-1/system.conf` SHA-256
  `a6f50dc70ef082a110dcdb164579cd2af221b90226c5e0aca237edcad98a1c26`
  has no extracted policy nodes. Original 811-byte
  `/etc/dbus-1/system.d/fota-consumer.conf` SHA-256
  `499ae912f2397720c952f27143d2112427509b95335c91d5b0ec7749e6999fec`
  has explicit sender grants for root/fota/system, plus *within the
  same default block* a deny for FOTA method calls followed by an allow
  for destination+interface `fota.consumer` with **no method/path
  restriction**. All 3 file hashes matched the first physical capture.
  The effective policy remains **UNDETERMINED**: 103 other/unreported
  override-directory entries were not individually inspected, actual
  daemon loading/other policies/user-group-mandatory priority, sender
  D-Bus identity, SMACK/Cynara and consumer-side checks are not proven.
  An XML allow is not root or a firmware signature bypass.

## Merged and validated development

- PR #133: physical native reader and privilege inventory baseline.
- PR #134: strict private original ZIP offline verification.
- PR #135: pinned original BAPD callsite/Thumb/PLT analysis.
- PR #136: registered `dbus-connected` callback/guard proof.
- PR #137: read-only standard system-bus policy capture.
- PR #138: offline review of first redacted policy report.
- PR #139: 3-file exact original rule/include capture. Required NO WATCH
  CI run `41095003011` passed Ubuntu 22.04 and 24.04.
  Previous exact policy evidence capture and the v1 offline review
  also ran on the physical owner's Termux successfully.

### Current integration

PR #140 merged to `main` at `fbc7faa` and required NO WATCH
CI run `41096937375` passed both Ubuntu 22.04 and 24.04.
The source branch `issue-47-focused-policy-decision-audit` is a safe
retirement candidate after preservation checks; this connector does
not expose branch deletion.

One cohesive update to the existing
`tools/watch3_r840x_dbus_policy_readonly.py` adds
`--offline-focused-report` for the **already obtained three-file JSON**.
It validates pinned original file hashes, checks only the hypothetical
BAPD target message against original **default** send-rule match
attributes and order, and clearly separates an observed local-file
exception from effective D-Bus/SMACK authorization. Regression tests
cover changed hashes, changed interfaces/members, later denies, unknown
attributes, malformed inputs, no networking and no-clobber output.
No new watch capture or service call is needed for this milestone.
See `docs/watch3-r840x-dbus-policy-readonly.md`.

## October 30 focused offline audit regression

The owner ran the three-file offline default send-rule reviewer. Report
SHA-256 `c27bf1ee54229753e5e0ac6f31269ab1733ced3ce344b1c32edf3589e83644b3`
confirmed three original file hashes and FOTA default rule sequence
`deny -> allow`, but emitted `INCONCLUSIVE` with generic unknown flag.
**Actual root cause in code:** the matcher classified unrelated
`send_requested_reply=true,send_type=method_return/error` rules as
unknown *before* recognizing their definitive `method_call` mismatch.

PR #141 **merged to main** at `4dec7ad` after required NO WATCH CI
run `41098372119` passed on Ubuntu 22.04 and 24.04. The canonical
offline matcher now first rejects known mismatches, then evaluates
unsupported constraints, and returns explicit uncertainty reasons and
a count of definitely nonmatching default send rules. Regression tests
use original reply-only `method_return`/`error` shapes and verify genuine
unknown FOTA constraints still fail closed. No watch call, root action,
or firmware write. The owner has since executed the corrected offline v2 report successfully;
see the November 1 current-state section for the verified result. Branch
`issue-47-fota-audit-nonmatching-rules` is a safe retirement candidate,
but this connector lacks branch deletion.

## October 30 physical v2 audit and current development

Owner's v2 offline audit successfully verified the three original
policy-file hashes, default FOTA method-call sequence `deny -> allow`,
last matching *observed file-level default rule* `allow`, **15 known
nonmatching default rules excluded** and **no unknowns or drift in that
limited file subset**. Sender authorization, full effective merged
policy, SMACK/Cynara, recovery acceptance and root remain unknown.

Current branch `issue-47-running-system-bus-provenance` adds a single
read-only runtime evidence mode to the **existing** policy analyzer,
not a new competing script. It uses one fixed `systemctl show`
query for the configured `dbus.service` and reuses the **existing**
allowlisted `ps` query, displaying only bounded and redacted daemon
family/flags/unit metadata. It never starts/reloads a bus, invokes
FOTA, requests root or writes to the watch. Tests cover parser
privacy, unsupported BusyBox layouts, restricted commands, no-network
unit fixtures and legacy mode compatibility. CI/merge pending.

After merge, owner should run this one bounded physical runtime
snapshot from Termux and return only the JSON. It cannot by itself
attest complete live D-Bus security policy or unlock capability.
No other code should be added until that evidence is analyzed.

## Next evidence gate / safety

The offline default-rule audit is **already complete** and must not
be repeated. Establish the actual runtime system-bus daemon metadata,
then address sender/receiver credentials, other included policies,
SMACK/Cynara enforcement, and signed exact SM-R840X restoration from
read-only evidence. Do not repeatedly re-run prior captures or speculate
that the shell can invoke a privileged firmware method.

**Firmware/partition writes: NO-GO.** Root not proven, bootloader
not unlocked, recovery not installed, stock restore not verified,
signed-image acceptance not tested. Never substitute SM-R840 firmware
for SM-R840X by similarity, send FOTA requests to test reachability,
flash blind Odin/PIT images, or execute a discovered vendor helper.
Keep issue #47 open and related branch retirement safe; other projects
remain independent.
