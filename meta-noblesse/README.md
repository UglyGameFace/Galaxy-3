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
- R08 reference DTS: successfully compiled in GitHub Actions.
- R08 kernel `Image`: successfully compiled in GitHub Actions #6.
- Repository uses only `main`.

**Not yet tested**
- BitBake parsing, resolution, or compilation of this new recipe.
- Full AsteroidOS root filesystem construction for this machine.
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
3. Configure `MACHINE = "noblesse-r08"`. Then use `bitbake -p`,
   `bitbake -e linux-noblesse`, and `bitbake linux-noblesse`
   to establish real BitBake compatibility. These checks **have not**
   been performed by the current CI.
4. If the kernel can be built with BitBake, the next engineering task is
   a real compositor/display and input integration, *not* flashing.

Never interpret a green static-validation or kernel-build status as an
authorization to install files on the watch.
