# UgLy|OS Galaxy Watch3 R840X recovery and boot

Updated November 15, 2026. **Open issue #47.** Work is restricted to
the owner's Samsung Galaxy Watch3 **SM-R840X**, NOBLESSE-LARGE-BT R08,
stock version R840XXXU1AUA2, CSC PAP candidate. Android/Termux only,
free only, preserve the working watch. The target is a verified
**exact-variant stock rescue** followed by reproducible UgLy|OS boot.

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
