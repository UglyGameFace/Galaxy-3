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

### R08-enabled auxiliary firmware (additional source finding)

The exact R08 board DTSI includes the Exynos 9110 base DTSI. Its ABOX
node enables two additional **auxiliary** firmware requests:

| Filename | Device-tree node | DRAM offset | State |
| --- | --- | --- | --- |
| `APDV_AUDIO_SLSI.bin` | `ext_bin@0` | `0x502000` | Enabled |
| `APSV_AUDIO_SLSI.bin` | `ext_bin@1` | `0x50C000` | Enabled |

[Exynos 9110 device-tree source](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/boot/dts/exynos/exynos9110.dtsi#L2159-L2170)
and [R08 include](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dtsi#L12-L18).

ABOX attempts to load these enabled entries, but logs a warning and continues
if an auxiliary file is missing. Whether these affect actual playback remains
unverified. Two other entries, `AP_AUDIO_SLSI.bin` and
`SoundBoosterParam.bin`, are **disabled** in this source and are not listed
as required firmware.

`meta-noblesse/conf/watch3-r08-abox-firmware.json` records the four
referenced filenames with their distinct roles. Our source audit compares
this manifest against the exact pinned vendor code without retrieving blobs.

### Optional local-only firmware inventory

Only after legally obtaining device-matched files, you can locally run:

```bash
python3 tools/audit_watch3_abox_firmware.py --skip-source --local-dir /path/to/local-firmware
```

This prints file sizes and SHA-256 hashes and flags missing/empty files.
It never copies, uploads, modifies, signs, installs or flashes anything.
**Presence and SHA-256 alone do not establish compatibility or licensing.**
No authoritative SM-R840X firmware hashes or redistribution grants have
been verified. Firmware from unrelated Exynos phones is not a safe substitute.

## Verified speaker signal path and read-only evidence probe

The pinned COD9005X codec source defines the following DAPM route:

```text
Exynos9110-Sound ALSA card (expected name from kernel driver)
    ABOX UAIF0 Playback -> cod9005x-aif
    AIF Playback -> DAC -> SPKDRV -> SPK [SPK On] -> SPKOUTLN
```

This chain comes from the Samsung [Exynos9110 machine driver](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/sound/soc/samsung/exynos9110_sound.c#L319-L328)
and the [COD9005X DAPM routes](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/sound/soc/codecs/cod9005x.c#L992-L1000).
The exact source route is checked by `tools/audit_watch3_audio.py`.

**Do not hardcode an ALSA/UCM2 mixer configuration from these DAPM labels.**
The running card and user-visible ALSA control names have not been observed
under AsteroidOS. We must confirm them before any sound-unmute commands.

### Optional read-only SDB diagnostic (no firmware extraction)

For an *already authorized* SDB connection, a one-command probe is available
from the repository. On a host with Python 3 and `sdb` installed:

```bash
python3 tools/probe_watch3_audio_readonly.py --live
```

If multiple SDB devices are attached, pass `--serial YOUR_SDB_SERIAL` as well.
The script only checks whether the four **known filenames** are visible in
five common firmware folders and reads `/proc/asound/cards` and
`/proc/asound/pcm` when permissions allow. It does not use root, change
volume, probe hardware registers, execute firmware, copy any files, or alter
watch partitions. An inaccessible/undetected path is reported as
`NOT_OBSERVED_IN_TESTED_PATHS`, **not** as proof the firmware is missing.

Running with no arguments prints a no-connect explanation. Tests exercise
the output parser with **synthetic strings**; passing CI does not mean we
have run this command on the physical watch or verified speaker playback.
Device access and any output sharing remain optional; the repository does
not include sensitive hardware logs or binary firmware.

### Next integration gate

Identify a legitimate, device-matched firmware source and, once a safe
recoverable test environment exists, confirm that ABOX initializes, ALSA
enumerates the expected card, and the actual mixer controls match the
source-backed DAPM route. Only then can we design a correct UCM2 playback
profile and test sound without risking the hardware.

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
