# Watch3 SM-R840X R08: first completed AsteroidOS ext4, offline audit, and blockers

Date: **2026-10-24**. Single active task: **offline image integrity and hardware-readiness triage**.
This document describes verified CI evidence. It does **not** authorize installing any image on a watch.

## Verified results from the actual completed build

- [GitHub Actions run #40095182440](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40095182440)
  succeeded with **8,040/8,040 BitBake tasks** and a verified Watch3-specific
  ARM64 rootfs/graphics gate.
- Original artifact:
  [OFFLINE-NOT-FLASHABLE image](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40095182440/artifacts/12561560022).
  Uploaded artifact ZIP is approximately 249.6 MB; the extracted ext4 is
  **755,658,752 bytes**.
- Original completed image filename:
  'asteroid-image-noblesse-r08.rootfs-20261024125252.ext4'.
- The artifact is scheduled to expire **2026-10-31**.
  Download/back up a copy independently; later CI runs do not extend its expiry.

## Independent read-only artifact inspection

Workflow: .github/workflows/watch3-r08-offline-ext4-audit.yml.
It downloads the exact image and original checksum/manifest artifacts by run ID,
never rebuilds them, and uses only read-only debugfs, dumpe2fs, and
e2fsck -fn. It checks the embedded launcher's AArch64 ELF header and verifies
the compositor configuration and systemd service inside the ext4 itself.

Source build's SHA-256 was independently verified against the downloaded ext4:

8358d60f213c7acf8857a7a9795e7de9a35acbc70d6d3743b72299dfe8a3ed72

- Ext4 superblock: valid; Linux 4 KiB blocks; filesystem state **clean**.
- A recent e2fsck (e2fsprogs **1.47+** on Ubuntu 24.04) completed read-only
  checks successfully. Ubuntu 22.04's 1.46.5 tool could not read FEATURE_C12;
  this was a *checker version mismatch*, not evidence of corrupt filesystem.
- Original installed package manifest contains **692** package names, including
  AsteroidOS launcher and Qt packages.
- Read-only extraction confirmed the ARM64 launcher header, LinuxFB software
  compositor configuration, and launcher service reference.

## Critical outstanding filesystem compatibility concern

The ext4 filesystem features include **orphan_file** (the older e2fsck
labels it FEATURE_C12). This feature was introduced for Linux **5.15**
and e2fsprogs **1.47**. Our pinned *reference* Watch3 R08 kernel is Linux
**4.9.59**, and the target's actual boot-time filesystem/mount features remain
unverified. Newer ext4 features may be ignored or handled differently by older
kernels depending on feature type and clean-shutdown state, but **nothing
here proves this particular image can be safely mounted by the R08 kernel**.

References:

- ext4 feature documentation: https://man7.org/linux/man-pages/man5/ext4.5.html
- e2fsprogs compatibility issue: https://github.com/tytso/e2fsprogs/issues/147
- RAUC documentation's Yocto compatibility mitigation:
  https://github.com/rauc/rauc/blob/master/docs/faq.rst

**Next safe engineering slice:** inspect pinned image_types.bbclass,
machine configuration, and actual ext4 mkfs flags. Evaluate a *separate*
R08-only image recipe configuration such as
EXTRA_IMAGECMD:ext4:append = " -O ^orphan_file" (documented by RAUC),
then rebuild only the affected image tasks using the existing sstate if
possible. Inspect the resulting filesystem with a modern checker **and**
test older kernel/e2fsprogs compatibility off-device. Preserve the original
passing artifact unchanged for provenance and comparison.

## Other hardware gates still completely open

- Prove signing, boot-chain and bootloader behavior for **SM-R840X R08**,
  rather than copying recovery advice from another Galaxy Watch.
- Verify reliable **full stock backup and recovery** before any write to
  watch storage or modification of boot/recovery partitions.
- Verify correct kernel/DTS, actual display scanout and Linux framebuffer,
  touchscreen/bezel input, Bluetooth/Wi-Fi and real speaker codec/ALSA routing.
- Verify secure boot expectations, DTB and kernel/userspace compatibility.
- Hardware startup and flashing remain **NOT TESTED / NOT AUTHORIZED**.

This report intentionally distinguishes a *clean, intact offline filesystem*
from a *bootable and safe watch firmware*. They are not equivalent.
