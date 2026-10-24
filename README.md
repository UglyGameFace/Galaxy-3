# Galaxy Watch3 / AsteroidOS R08 port research

## Current milestone: real image built, verified off-device, not flash-ready

On **October 24, 2026**, [full AsteroidOS ARM64 image build #40095182440](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40095182440)
passed all 8,040 BitBake tasks and the rootfs/Qt/ARM64 validation gates.
A real ext4 was uploaded as an explicitly **OFFLINE-NOT-FLASHABLE** artifact.
Download and preserve that original image before its scheduled expiry on **October 31, 2026**.

A separate, read-only artifact audit independently checked the original checksum,
ext4 filesystem consistency and embedded ARM64 launcher. It also detected the
newer ext4 **orphan_file** feature, which raises a compatibility concern with the
reference Linux **4.9.59** Watch3 kernel. Details and next safe steps are in
[the offline image audit and recovery gates](docs/watch3-r08-offline-image-audit.md).

**First-boot research is now the sole active hardware milestone.** The
[model-specific proof matrix](docs/watch3-r08-first-boot-proof-matrix.md)
compares Tizen SDB, wireless download, Ragnarök and internal service routes,
clearly separating proven operations from unverified R840X capabilities.
No firmware writes are permitted without exact stock recovery and proven
custom boot-chain acceptance.

**Status: image compilation and offline integrity successful; kernel filesystem
compatibility, bootloader, physical display/touch/audio, stock backup and recovery
remain unverified. No flashing is authorized.**


**Device:** Samsung Galaxy Watch3 SM-R840X, NOBLESSE-LARGE-BT (Exynos 9110, revision R08)
**Installed firmware:** R840XXXU1AUA2; Tizen 5.5; running kernel Linux 4.9.59.

This repository contains **off-device research, a successfully built Linux baseline, and experimental AsteroidOS machine-specific integration**.
Nothing here is a tested or flashable watch image. There is no verified custom boot or recovery
procedure for this particular firmware, and the public upstream source has **not** been proven
to match the production firmware.

## Known reference tree

- Public vendor kernel reference: https://github.com/UsrBinLuna/kernel_samsung_galileo
- Pinned reference commit: `ec258e12887d37362b59e3291c1d3e5363c24bff`
- Board DTS: `arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dts`
- Base configuration: `tizen_noblesse_defconfig`
- Additional fragments: `tizen_noblesse_large_defconfig` and `tizen_noblesse_brcm_defconfig`

These are historical *reference* files, not proven firmware-matched replacements.

## Verified reference compilation

GitHub Actions run [#6](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39468714090)
successfully cross-compiled the pinned Samsung Linux 4.9.59 reference kernel
`Image` and `exynos9110-tizen_noblesse_large_bt-r08.dtb`.
The original source needed modern GCC warning compatibility at build time.
These are **unverified experimental reference binaries**.

## AsteroidOS / OpenEmbedded adaptation (in progress)

The [`meta-noblesse` layer](meta-noblesse/README.md) contains an experimental
`noblesse-r08` machine configuration and pinned reference kernel recipe.

- [Static layer checks](https://github.com/UglyGameFace/Galaxy-3/actions/workflows/watch3-r08-layer-static-check.yml)
  passed. This checks metadata structure and provenance, not BitBake.
- [BitBake metadata parsing and source unpack](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39473830377)
  passed with pinned OE-Core `whinlatter` and BitBake `2.16`.
- [BitBake kernel configuration and compilation](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39474346231)
  passed and produced an ARM64 `Image` and R08 `dtb`.
- The experimental machine now sets `OLDEST_KERNEL = "4.9.59"` to target
  the older kernel ABI for prospective glibc userspace. Runtime compatibility
  is untested.
- [Completed minimum userspace build](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39505517130)
  passed 2,141 BitBake tasks and built kernel, R08 DTB, and minimal Linux `ext4` rootfs.
- [AsteroidOS image dependency preflight](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39514362687) passed, resolving 7,584 planned tasks without compiling the full graphical OS.
- The real AsteroidOS `asteroid-machine-config` package [built successfully](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39516972444); the job's final validator failed on incorrect metadata key names, which were later corrected and [tested separately](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39522874180).
- A **Watch3-only LinuxFB/software-QtQuick compositor override** is now implemented in `meta-noblesse/recipes-asteroid/asteroid-launcher/`. It targets Samsung's enabled DECON framebuffer driver, not the TGM DRM/KMS interface. See [display findings](docs/watch3-r08-display-linuxfb.md).
- The real compositor file-unpack check passed: BitBake selected the Watch3 LinuxFB configuration. The pinned launcher corner-mask QML patch has source-level CI coverage.
- R08 explicitly depends on `qtbase-plugins`, with BitBake metadata checks for Qt LinuxFB/launcher dependencies. [QtBase 6.11.3 package build #39593317503](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39593317503) **passed all 2,171 tasks** and verified a real AArch64 `libqlinuxfb.so` in the `qtbase-plugins` package. Its cold build needed nearly six hours (zero sstate cache hits). The expensive build workflow is now manual-only with resource diagnostics and an optional persistent-cache self-hosted runner. Final rootfs installation, live QtWayland software rendering, watch framebuffer, boot, backup, and recovery still require independent verification. **No device flashing is authorized.**

No device connection, signing or flashing steps are present.

## AsteroidOS integration

The [AsteroidOS integration preflight workflow](.github/workflows/watch3-r08-asteroidos-preflight.yml) now attempts to parse and resolve the **real** AsteroidOS `asteroid-image` metadata for `MACHINE=noblesse-r08` without compiling a flashable image. See the live workflow for actual results. Display, input, secure boot and recovery remain unverified.

**Do not flash artifacts from this repository to the watch.**
