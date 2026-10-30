# UgLy|OS R840X bootloader and recovery

Updated October 30, 2026. Issue #47. Owner-owned Samsung Galaxy Watch3
SM-R840X, NOBLESSE-LARGE-BT R08, stock R840XXXU1AUA2, CSC PAP candidate.
Goal: verified exact-variant stock rescue and reproducible UgLy|OS custom
boot. Android/Termux only, free only, preserve the working watch.

## Physical evidence and active state

PR #133 was merged into main at `3f7ca89`. The native reader executed
on the physical watch as UID/EUID 5001, User::Shell. Effective/permitted
capabilities both zero; inheritable mask `0x2000c2` is not root. Eight fixed
updater targets have no security.capability attribute; FOTA service runs as
`User=fota`. Earlier root-on was denied. The R840X ODIN/LOKE handshake is
transport magic only, with no flash session or proven stock restoration.

Owner supplied `watch3-privilege-inventory.zip`, SHA-256
`2454c2cbe7826a14984669bfad0e0da8ca92cfcacc51cfb59afd67c833c6083d`.
The raw probe matches the report; stage cleanup marker verified. Eight
original ARM ELF32 helper inputs match their reported hashes and lengths.
**64** candidate records retained; **82** candidate records dropped by
inventory bounds. **44** eligible helper-copy plans not selected (a distinct
limit). Scan stat errors persist. The directory inventory is incomplete.
No setuid/setgid modes among retained candidates, although file capabilities
are present. No helper executed or firmware changed.

The original `/bin/bapd` contains `_fota_launch_cb` and
`fota.consumer.LaunchFota` with `/fota/consumer`. The original
`/bin/csc-util` contains firmware-mode CSC preparation functions. These are
static links to the FOTA workflow, NOT proven caller authorization, root,
installer, bootloader access or a signature bypass. See
[offline review](docs/watch3-r840x-privilege-offline-review.md).

## Current development

Branch: `issue-47-privilege-offline-review`. The private-input verifier
`tools/watch3_r840x_privilege_offline.py` checks ZIP structure/limits,
report-to-probe consistency, cleanup/no-write flags, original hashes and
ARM ELF32 headers, and FOTA static markers. It creates a local JSON report
with restricted permissions; no SDB or binary execution. Synthetic tamper
tests: `tests/test_watch3_r840x_privilege_offline.py`.
Original Samsung executables and private reports remain **outside Git**.

Next research: map original `bapd` callback's actual relocation/call edges
offline, compare to previously reviewed consumer D-Bus method interface,
package registration and caller policies. Resolve `/bin` vs `/usr/bin` alias
questions, stat errors and dropped records in the inventory if needed.
Continue *exact R840X* stock recovery provenance, partition identity,
signed-boot checks and tested rescue feasibility before any write.

## Safety / definition of done

Root: NOT PROVEN. Bootloader unlocked: NO. Custom boot: NO.
Exact stock restoration: NOT PROVEN. Firmware writes: **NO-GO**.
Never flash R840 images onto R840X by model similarity, issue blind Odin/PIT
writes, call FOTA to test reachability, execute discovered privileged helpers
or change security labels/capabilities. No claim of production boot readiness
until signed-image acceptance and independent restoration are both proved.
Issue #47 stays open. User's unrelated projects continue independently.
