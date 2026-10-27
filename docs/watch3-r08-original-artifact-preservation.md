# Preserve the verified 2026-10-24 Watch3 offline image before artifact expiry

**Single device target:** SM-R840X, NOBLESSE-LARGE-BT R08, installed
Tizen `R840XXXU1AUA2`. This is a provenance and storage task tied to
[Issue #47](https://github.com/UglyGameFace/Galaxy-3/issues/47).
**NO FLASHING, NO BOOTLOADER UNLOCK, NO TIZEN REPLACEMENT.**

## Actual original build, current GitHub metadata (checked 2026-10-27)

- Source workflow: [#40095182440](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40095182440),
  completed 2026-10-24.
- `galaxy3-r08-OFFLINE-NOT-FLASHABLE-image-40095182440` (artifact
  **12561560022**) is **NOT expired**, downloaded archive size
  **249,555,979 bytes**, expires **2026-10-31 13:01:30 UTC**.
- Matching original stage artifact `galaxy3-r08-build-stage-40095182440`
  (artifact **12561206862**) is also available, expires
  **2026-10-31 13:01:46 UTC**, compressed archive 100,490 bytes.
- The complete **uncompressed original ext4** from that successful build:
  `asteroid-image-noblesse-r08.rootfs-20261024125252.ext4`
  **755,658,752 bytes**, SHA-256
  `8358d60f213c7acf8857a7a9795e7de9a35acbc70d6d3743b72299dfe8a3ed72`.
  This is the SHA recorded in the independent
  `watch3-r08-offline-ext4-audit.yml` and
  `docs/watch3-r08-offline-image-audit.md`.
- Original artifacts have seven-day retention, explicitly configured
  in the staged-image builder.

The source artifact is an **AsteroidOS ARM64 Linux root filesystem**.
The independent offline inspection identified the `orphan_file` ext4
feature, which creates a compatibility concern with the reference
Linux 4.9.59 target. It is **NOT A SAMSUNG FLASHABLE IMAGE**. Neither
offline filesystem integrity nor a preserved copy demonstrates that
the R840X bootloader accepts a custom kernel.

## Safe one-time preservation

New workflow
`watch3-r08-original-image-preservation.yml`:
1. For each PR, compile and test the provenance validator using **tiny
   synthetic fixture bytes only**, without downloading source artifacts.
2. **Only upon merger of this workflow to `main`**, automatically
   download the exact historical ext4 and stage artifacts through
   `actions/download-artifact@v4` with `actions:read`.
3. Validate the **full 755,658,752 bytes and exact SHA-256** of the
   original named ext4. If missing, renamed, altered, symlinked,
   or inconsistent, fail before publishing any replacement.
4. Re-upload the **same unchanged** ext4 and source stage metadata +
   newly generated private source-fingerprint proof under new artifact
   names with requested **90-day** retention. If the organization's
   maximum retention is shorter, this upload may fail; check the
   resulting artifact's actual `expires_at` rather than assuming.
5. `workflow_dispatch` permits an **explicit** subsequent run if
   needed; there is **no recurring scheduled duplication** or rebuild.

The workflow changes neither the watch nor source filesystem and has
no watch/network probe. It is a controlled GitHub artifact copy.
It may use GitHub Actions storage, but creates no paid external
accounts and requires no PC; GitHub is already connected.

## After the workflow actually succeeds

Verify the **new** `PRESERVED-OFFLINE-NOT-FLASHABLE` artifact exists,
has the full original file and source fingerprint, and note its *actual*
expiry. Do not claim preservation merely because a PR merged, the
validator passed, or the workflow started. Preserve an independent copy
via Android Downloads or private long-term storage when practical;
GitHub Actions artifacts are temporary by design.

## Remaining first-boot NO-GO blockers (not changed by this retention work)

1. No verified matching **complete OEM stock R840X** restoration set
   for installed `R840XXXU1AUA2`, including authentic image signatures
   and compatible rollback/bootloader revision.
2. No demonstrated fully restorative Wireless Download/Odin transport
   on this **specific** R840X, let alone recovery from damaged partitions.
3. No evidence that its bootloader accepts our custom signed/unsigned
   kernel/DTB/initramfs, or that temporary in-memory boot is available.
4. Physical SDB `sync:RECV` refuses or cannot find
   `/usr/bin/recovery-update.sh`; repeating it cannot supply the
   missing recovery proof. Samsung `recovery-update.service` and
   `rw-update.service` unit files were read and verified, but calling
   those privileged scripts is not an authorized boot method.

**GO:** original-image preservation, authentic firmware provenance
research, static source, offline partition parsing, and read-only
protocol feasibility research.

**NO-GO:** flashing, replacing Tizen, altering recovery, triggering
FOTA D-Bus methods, live exploit attempts, blindly using R840 retail
images, or reporting an unsupported bootloader bypass.
