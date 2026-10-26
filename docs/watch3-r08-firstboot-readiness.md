# UgLy|OS first-boot readiness for Galaxy Watch3 SM-R840X (R08)

**Status: NO-GO for firmware installation or flashing.**
This is a safe engineering milestone, not a completed custom-OS boot.

The watch's read-only observations support the NOBLESSE-LARGE-BT R08
board and Linux 4.9.59 reference. The true stock firmware and custom
bootloader acceptance remain unverified. The first-boot checker
is intentionally strict even if both existing Psplash and ext4 builds
have passed. Source-build success is NOT device boot.

## What this coherent slice adds

- One standard offline status report, with a human-readable Markdown
  summary and bounded, sanitized JSON.
- Reuses EXISTING privacy-filtered Watch3 read-only SDB boot report,
  storage-topology report and pinned historical kernel/DTB audit.
  No new SDB transport or watch interaction is introduced.
- Optional SHA-256 verification for local off-device kernel Image,
  R08 DTB, Psplash IPK, initramfs cpio.gz and AsteroidOS ext4.
  Checksums only prove local file identity, never signing/compatibility.
- True safety decision always **NO_GO** until a separately verified
  R840X-specific full restoration procedure and accepted boot path exist.
  A local report, checksum, checkbox or GitHub CI green check cannot
  flip the gate.
- The --enforce-install flag gives code 4 and a NO_GO report,
  useful for preventing future scripts from confusing compile success
  with flash authorization.
- Fast standalone fixture tests and GitHub Actions; no unnecessary
  full Yocto recompilation and no watch connections.

## Android / Termux, with existing redacted reports

Use the same repository already on the phone. Existing reports are
local only; no sensitive report is uploaded to GitHub:

    cd ~/Galaxy-3
    git pull --ff-only
    python tools/watch3_r08_first_boot_readiness.py \
      --boot-report ~/watch3-r08-boot-redacted.json \
      --storage-report ~/watch3-r08-storage-redacted.json \
      --output ~/uglyos-r08-readiness.json \
      --markdown ~/uglyos-r08-readiness.md

Read the report:

    cat ~/uglyos-r08-readiness.md

Optional: if a trusted copy of the historical audit JSON is also on
your phone, add --reference-report /path/to/r08-historical-boot-reference.json.
This file's SOURCE_COMMIT is verified against the exact pinned R08
vendor reference. The checker rejects unreadable, unsafe, malformed or
wrong-model reports. If a report isn't available yet, simply omit it.
Running with no reports still emits a safe NO_GO summary.

For optional **LOCAL** image integrity checking, add one or more
--artifact arguments in the form:

    --artifact kind:/absolute/path/to/file:sha256_hex

Recognized kinds: kernel_image, r08_dtb, psplash_ipk, initramfs_cpio,
asteroid_ext4. Files must exist and be at most 1 GiB; checksum must
match. The file bytes are only read locally, never uploaded or included
in the report. Don't download unknown flash packages for this check.

To enforce a deliberately blocked install gate in CI / scripts:

    python tools/watch3_r08_first_boot_readiness.py \
      --output ~/uglyos-r08-readiness.json --enforce-install
    echo $?

Exit code 4 means NO_GO, not a tool crash. Without --enforce-install,
exit code 0 means **only that the report was generated successfully**.

## Actual missing physical proof, in order

1. **Full stock rescue package, exact model and build.** Confirm a
   trusted, complete factory/repair firmware package specifically
   compatible with SM-R840X hardware, bootloader and deployed build
   R840XXXU1AUA2. An SM-R840 package and a matching chipset are not
   sufficient. The normal Samsung factory-reset screen is not a full
   boot partition recovery mechanism.
2. **Proven recovery transport.** Independently verify that exact
   device can reliably return to stock from a failed boot, using
   documented supported tools, with verified partition mapping.
   Read-only observation of a download screen is not a restoration test.
3. **Actual custom boot-chain acceptance.** Verify whether this
   Samsung Tizen bootloader permits loading a safe, non-destructive
   alternate kernel. Do NOT assume fastboot, kexec, Odin signing, or
   unlock support from other watch models.
4. **Non-destructive trial boot and hardware display.** If evidence for
   the previous gates becomes available, plan controlled tests with
   an explicit rollback. We have not verified the actual TGM/Mali
   framebuffer, touch, bezel, radio or power behavior under UgLy|OS.

**Avoid**: uploading raw SDB output or secret IDs, reading raw
/dev/mmcblk partitions, writing a PIT, flashing a .tar or .img,
selecting factory reset as a 'recovery test', downgrading to the
ordinary R840 firmware just because the model names look similar.

## Public reference links

- AsteroidOS supported devices: https://www.asteroidos.org/watches/
- Samsung Galaxy Watch3 Tizen app compatibility:
  https://developer.samsung.com/galaxy-watch-tizen/device-compatibility.html
- Samsung Galaxy Watch3 stock support and troubleshooting:
  https://www.samsung.com/us/support/troubleshoot/TSG10007068/
- Previous R08 boot evidence:
  docs/watch3-r08-first-boot-proof-matrix.md
- Previous read-only Termux procedure:
  docs/watch3-r08-live-boot-evidence.md

The physical device is **NOT FLASHABLE** based on information currently
verified by this project. No remote operations are performed by this PR.
