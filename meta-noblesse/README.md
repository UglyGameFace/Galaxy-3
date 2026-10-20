# Experimental AsteroidOS / OpenEmbedded board layer: NOBLESSE-LARGE-BT R08

**Target:** Galaxy Watch3 SM-R840X, firmware R840XXXU1AUA2, Exynos 9110,
hardware revision R08; currently running Tizen 5.5 and Linux 4.9.59.

**Status: research-only.** No valid custom boot or recovery route has been
established. Do **not** flash any files from this project.

## Evidence and provenance

From read-only SDB inspection of the user's watch:

- Device-tree `model`: `NOBLESSE-LARGE-BT`
- Device-tree `samsung,exynos-id` cells: `0x9110 8 0`, therefore R08
- Display `/dev/dri/card0`: Samsung `tgm-drm` driver
- Mali GPU `/dev/mali0`
- Touchscreen `/dev/input/event1`
- Buttons `/dev/input/event17`
- Rotating bezel `/dev/input/event18`
- Existing Tizen rootfs uses dm-verity, and owner SDB shell has no
  permission to back up boot/recovery partitions.

Public reference: [UsrBinLuna/kernel_samsung_galileo](https://github.com/UsrBinLuna/kernel_samsung_galileo),
pinned to commit `ec258e12887d37362b59e3291c1d3e5363c24bff`.
Although named for older watches, it has board-specific R08 device-tree source,
touchscreen, TGM DRM, Mali, Exynos and Noblesse settings.
**Matching board identifiers and Linux version do not establish a
firmware-identical kernel or valid signed boot image.**

Reference GitHub Actions build #6 compiled an ARM64 `Image` and R08 `dtb`:
https://github.com/UglyGameFace/Galaxy-3/actions/runs/39468714090

## Layer layout

- `conf/layer.conf`: experimental layer registration
- `conf/machine/noblesse-r08.conf`: AArch64 Cortex-A53 candidate machine
- `recipes-kernel/linux/linux-noblesse_4.9.59.bb`: historical kernel recipe
  pinned to the public reference commit, merging large-watch and Broadcom
  fragments, with the upstream `init/uh.elf` build dependency.

The machine requests a **64-bit** experimental userspace. Stock Tizen uses
**32-bit** userspace, so proprietary Tizen userspace graphics/sensor binaries
are not automatically reusable. The Samsung TGM/TDM/TBM DRM stack is not
proven compatible with standard Wayland/GBM/atomic KMS.

## Exact limits

**Already tested**
- Public reference source audit: 18/18 checks on Termux.
- R08 device-tree and Linux 4.9.59 reference `Image` compiled in Actions #6.
- BitBake metadata parse and source fetch/unpack passed in Actions recipe validation #6.
- Actual OpenEmbedded kernel configuration/compilation passed in
  [BitBake build #1](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39474346231).
- OpenEmbedded compiled `Image` and R08 `dtb` were uploaded as CI artifacts.
- `noblesse-r08` now targets glibc `OLDEST_KERNEL = "4.9.59"`.
- Repository uses only `main`.

**In progress**
- The [off-device rootfs research workflow](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39481244746)
  tests BitBake kernel deployment and a **minimal Linux** `ext4` userspace
  image using the corrected minimum kernel ABI.

**Not yet tested**
- Full AsteroidOS UI/root filesystem integration or boot.
- Compatibility of modern glibc with the watch's actual firmware and kernel.
- Qt/Wayland compositing, Mali GPU/DRM integration, touch, bezel,
  audio, connectivity, battery and power management under AsteroidOS.
- On-watch boot, firmware parity, signed boot acceptance, backup and
  recovery. No verified non-destructive boot method exists.

## How to evaluate safely

1. Use this directory as an additional layer in a separate Linux
   OpenEmbedded/AsteroidOS build workspace; don't put a build on the watch.
2. Ensure the selected AsteroidOS/OpenEmbedded branch supports
   `LAYERSERIES_COMPAT = "whinlatter"`, or update the metadata
   after checking the actual project's compatibility.
3. Configure `MACHINE = "noblesse-r08"`. BitBake parsing, kernel
   source fetch/unpack, configuration and compilation were already verified by
   Actions. These tests should be rerun if the kernel recipe changes.
4. The next gates are kernel deployment and minimum userspace image creation,
   followed by real AsteroidOS graphics/display and input integration,
   *not* flashing.

Never interpret a green static-validation or kernel-build status as an
authorization to install files on the watch.
