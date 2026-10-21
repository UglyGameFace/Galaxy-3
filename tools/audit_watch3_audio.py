#!/usr/bin/env python3
"""Offline-from-watch, read-only source audit of Galaxy Watch3 R08 audio wiring.

Fetches only public, pinned kernel SOURCE files. It does not retrieve firmware
binaries, connect to a watch, run audio commands, or alter a kernel config.
"""
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

SHA = "ec258e12887d37362b59e3291c1d3e5363c24bff"
BASE = f"https://raw.githubusercontent.com/UsrBinLuna/kernel_samsung_galileo/{SHA}/"
ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "board": "arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dts",
    "board_audio": "arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dtsi",
    "config": "arch/arm64/configs/tizen_noblesse_defconfig",
    "machine": "sound/soc/samsung/exynos9110_sound.c",
    "codec": "sound/soc/codecs/cod9005x.c",
    "abox": "sound/soc/samsung/abox/abox.c",
}

def fetch_source(path: str) -> str:
    request = urllib.request.Request(BASE + path, headers={"User-Agent": "Galaxy3-R08-Audio-Audit"})
    with urllib.request.urlopen(request, timeout=35) as response:
        return response.read().decode("utf-8")

def main() -> int:
    sources = {}
    for name, path in FILES.items():
        try:
            sources[name] = fetch_source(path)
        except (OSError, UnicodeError, urllib.error.URLError) as error:
            print(f"ERROR: Could not retrieve pinned public {name}: {error}", file=sys.stderr)
            return 1
        print(f"FETCHED {name}: {len(sources[name])} characters from {SHA}")
    board = sources["board"]
    dt = sources["board_audio"]
    config = sources["config"]
    machine = sources["machine"]
    codec = sources["codec"]
    abox = sources["abox"]
    uaif_begin = dt.find("uaif@0 {")
    uaif_end = dt.find("uaif@1 {", uaif_begin + 1) if uaif_begin != -1 else -1
    uaif0 = dt[uaif_begin:uaif_end] if uaif_begin != -1 and uaif_end > uaif_begin else ""
    local = (ROOT / "meta-noblesse/conf/machine/noblesse-r08.conf").read_text(encoding="utf-8")
    checks = {
        "R08 hardware revision in root DTS": "samsung,exynos-id = <0x00009110 8 0>;" in board,
        "root DTS includes exact R08 board fragment": "exynos9110-tizen_noblesse_large_bt-r08.dtsi" in board,
        "R08 audio codec compatible": 'compatible = "codec,cod9005x";' in dt,
        "R08 codec speedy device at address 0x03": bool(re.search(r"cod9005x@03\s*\{[^{}]*reg\s*=\s*<0x03>;", dt)),
        "R08 codec power source is LDO27": "vdd-supply = <&ldo27_reg>;" in dt,
        "R08 sound card compatible": 'compatible = "samsung,exynos9110-sound";' in dt,
        "sound routes ABOX playback": '"ABOX UAIF0 Playback"' in dt,
        "UAIF0 is I2S": 'format = "i2s";' in uaif0,
        "UAIF0 connects ABOX controller to COD9005X": "sound-dai = <&abox_uaif_0>;" in uaif0 and "sound-dai = <&audio_codec_cod9005x>;" in uaif0,
        "Exynos9110 ASoC card enabled in defconfig": "CONFIG_SND_SOC_SAMSUNG_EXYNOS9110_COD9005=y" in config,
        "Samsung ABOX audio enabled in defconfig": "CONFIG_SND_SOC_SAMSUNG_ABOX=y" in config,
        "Exynos9110 sound card uses codec DAI": '.codec_dai_name = "cod9005x-aif"' in machine,
        "ALSA sound card label is Exynos9110-Sound": '.name = "Exynos9110-Sound"' in machine,
        "Codec AIF playback feeds DAC": bool(re.search(r'\{\s*"DAC"\s*,\s*NULL\s*,\s*"AIF Playback"\s*\}', codec)),
        "Codec DAC feeds SPKDRV": bool(re.search(r'\{\s*"SPKDRV"\s*,\s*NULL\s*,\s*"DAC"\s*\}', codec)),
        "SPKDRV feeds gated SPK path": bool(re.search(r'\{\s*"SPK"\s*,\s*"SPK On"\s*,\s*"SPKDRV"\s*\}', codec)),
        "SPK feeds speaker output SPKOUTLN": bool(re.search(r'\{\s*"SPKOUTLN"\s*,\s*NULL\s*,\s*"SPK"\s*\}', codec)),
        "COD9005X speaker DAC has DAPM switch": 'SOC_DAPM_SINGLE("SPK On"' in codec,
        "COD9005X speaker driver has power events": "spkdrv_ev" in codec and 'SND_SOC_DAPM_OUT_DRV_E("SPKDRV"' in codec,
        "ABOX needs SRAM firmware": '"calliope_sram.bin"' in abox and "request_firmware_nowait" in abox,
        "ABOX needs DRAM firmware": '"calliope_dram.bin"' in abox and "abox_request_firmware" in abox,
        "AsteroidOS physical speaker capability enabled": 'MACHINE_HAS_SPEAKER = "true"' in local,
        "no guessed speaker firmware artifacts tracked": not (ROOT / "meta-noblesse/recipes-bsp/firmware/calliope_sram.bin").exists(),
    }
    for description, valid in checks.items():
        print(("PASS" if valid else "FAIL") + ": " + description)
    good = sum(checks.values())
    print(f"R08 audio source audit: {good}/{len(checks)} passed")
    print("IMPORTANT: firmware was referenced, NOT retrieved or redistributed.")
    print("Codec path exists in public source; audio playback is NOT verified on AsteroidOS.")
    return 0 if good == len(checks) else 1

if __name__ == "__main__":
    sys.exit(main())
