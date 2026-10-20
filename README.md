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

## Building

See the `Galaxy Watch3 R08 reference kernel build` GitHub Actions workflow.
It cross-compiles the reference device tree and kernel on an Ubuntu runner, saves
build logs and (if compilation succeeds) experimental build outputs. No device connection,
signing or flashing steps are present.

**Do not flash artifacts from this repository to the watch.**
