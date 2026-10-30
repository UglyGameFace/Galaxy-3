# UgLy|OS Galaxy Watch3 R840X recovery and boot

Updated October 30, 2026. **Open issue #47.** Work is restricted to
the owner's Samsung Galaxy Watch3 **SM-R840X**, NOBLESSE-LARGE-BT R08,
stock version R840XXXU1AUA2, CSC PAP candidate. Android/Termux only,
free only, preserve the working watch. The target is a verified
**exact-variant stock rescue** followed by reproducible UgLy|OS boot.

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

Branch: `issue-47-focused-policy-decision-audit` (CI / integration pending).

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

## Next evidence gate / safety

After green CI and merge, use only the owner's saved JSON for the next
offline audit. Then determine actual live bus config and sender/receiver
credentials, other applicable policy/SMACK/Cynara restrictions and
signed exact-variant SM-R840X rescue provenance with **read-only**
procedures. Do not repeatedly re-run prior captures or speculate
that the shell can invoke a privileged firmware method.

**Firmware/partition writes: NO-GO.** Root not proven, bootloader
not unlocked, recovery not installed, stock restore not verified,
signed-image acceptance not tested. Never substitute SM-R840 firmware
for SM-R840X by similarity, send FOTA requests to test reachability,
flash blind Odin/PIT images, or execute a discovered vendor helper.
Keep issue #47 open and related branch retirement safe; other projects
remain independent.
