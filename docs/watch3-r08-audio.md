# Galaxy Watch3 SM-R840X revision R08: ABOX / COD9005X audio investigation

**Status: supported in pinned public vendor kernel source; not tested under AsteroidOS or on the physical watch.**

## Confirmed source wiring

- The exact R08 board DTS includes an audio CODEC node: `speedy@11A20000` → `cod9005x@03` (`compatible = "codec,cod9005x"`, `reg = <0x03>`, `vdd-supply = <&ldo27_reg>`). [R08 dtsi, about lines 368–379](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dtsi#L368-L379)
- The R08 ASoC sound card is `samsung,exynos9110-sound`; its DTS wiring maps `uaif@0` through an I²S link from `abox_uaif_0` to `audio_codec_cod9005x`. [R08 dtsi, about lines 817–986](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dtsi#L817-L986)
- `exynos9110_sound.c` binds its `UAIF0` backend to `cod9005x-aif`. [Machine driver](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/sound/soc/samsung/exynos9110_sound.c#L318-L328)
- The COD9005X codec implements speaker switching, `SPKDRV` DAPM events and DAC muting/power sequencing. These are **software controls in the vendor codec driver**, not a successful speaker playback test. [Codec source](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/sound/soc/codecs/cod9005x.c#L838-L951)
- The reference `tizen_noblesse_defconfig` enables `CONFIG_SND_SOC_SAMSUNG_EXYNOS9110_COD9005=y` and `CONFIG_SND_SOC_SAMSUNG_ABOX=y`. [Kernel config](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/configs/tizen_noblesse_defconfig#L2431-L2438)

## Confirmed firmware dependency

The vendor ABOX audio driver requests **`calliope_sram.bin`** (asynchronously) and **`calliope_dram.bin`**. It can also request named extra firmware from its device-tree children. [ABOX driver, about lines 5278–5441](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/sound/soc/samsung/abox/abox.c#L5278-L5441)

These filenames are requirements in public source, **not proof that the binaries are in this repository, publicly redistributable, compatible with SM-R840X firmware R840XXXU1AUA2, or available to an AsteroidOS root filesystem**. Do not download or ship unrelated watch firmware as a shortcut.

## Actual engineering gates

1. **Kernel source compatibility:** verify the pinned COD9005X, Samsung Speedy bus and ABOX drivers and DT references stay enabled as the R08 kernel recipe changes. The source audit workflow handles this off-device.
2. **Firmware provenance and licensing:** establish a lawful, firmware-compatible way to supply the required ABOX firmware without altering stock partitions or borrowing mismatched blobs. No firmware files are included here.
3. **ALSA card and DAPM routes:** only after a verified, recoverable custom boot method, inspect actual detected ALSA devices, control names, codec power and clock sequencing. Never infer a working audio card from `MACHINE_HAS_SPEAKER`.
4. **Sound server integration:** map the proven codec and ABOX mixer controls into a supported AsteroidOS audio service; test mute, volume, suspend/resume and power draw before enabling user-facing playback.
5. **Safety boundary:** no flashing, privileged SDB writes, boot or recovery modification, or speculative hardware register programming without complete stock backup and a verified recovery route.

## Current scope

- The watch **has a physical speaker**, and `meta-noblesse` sets `MACHINE_HAS_SPEAKER = "true"` accordingly.
- The audio kernel *reference source path* is now identified. AsteroidOS speaker playback remains unimplemented and unverified.
- The [fast pinned-source audit](https://github.com/UglyGameFace/Galaxy-3/actions/workflows/watch3-r08-audio-source-audit.yml) checks evidence in the public commit without building Linux or requiring the watch.
