# Galaxy Watch3 / AsteroidOS R08 port research

**Device:** Samsung Galaxy Watch3 SM-R840X, NOBLESSE-LARGE-BT (Exynos 9110, revision R08)
**Installed firmware:** R840XXXU1AUA2; Tizen 5.5; running kernel Linux 4.9.59.

This repository is for **off-device research and reproducible kernel/DTB compilation only**.
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
- [Experimental minimum userspace build](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39481244746)
  tests kernel deployment plus a minimal Linux `ext4` filesystem.
  It is **not** the AsteroidOS UI, and no boot is authorized.
- Full AsteroidOS userspace, Wayland/Mali compositor integration, on-watch
  boot, backups and recovery remain unvalidated.

No device connection, signing or flashing steps are present.

**Do not flash artifacts from this repository to the watch.**
