#!/usr/bin/env python3
"""Strictly read-only Watch3 audio evidence probe.

The probe is OPT-IN: nothing contacts the watch unless --live is specified.
Only tests known filenames in known directories and reads /proc/asound text.
It never downloads, copies, executes firmware, plays sound or changes settings.
"""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

EXPECTED = (
    ("calliope_sram.bin", "core"),
    ("calliope_dram.bin", "core"),
    ("APDV_AUDIO_SLSI.bin", "auxiliary"),
    ("APSV_AUDIO_SLSI.bin", "auxiliary"),
)

# All operations below are reads, existence tests and output. No privileged SDB.
REMOTE_SCRIPT = r"""
printf 'W3_AUDIO_PROBE_V1\n'
for directory in /vendor/firmware /lib/firmware /usr/lib/firmware /etc/firmware /opt/etc/firmware; do
    for filename in calliope_sram.bin calliope_dram.bin APDV_AUDIO_SLSI.bin APSV_AUDIO_SLSI.bin; do
        file="$directory/$filename"
        if [ -r "$file" ] && [ -f "$file" ]; then
            printf 'FOUND|%s|READABLE|%s\n' "$filename" "$file"
        elif [ -e "$file" ]; then
            printf 'FOUND|%s|PRESENT_NOT_READABLE|%s\n' "$filename" "$file"
        fi
    done
done
if [ -r /proc/asound/cards ]; then
    while IFS= read -r line; do printf 'CARD|%s\n' "$line"; done < /proc/asound/cards
else
    printf 'CARD_NOT_ACCESSIBLE\n'
fi
if [ -r /proc/asound/pcm ]; then
    while IFS= read -r line; do printf 'PCM|%s\n' "$line"; done < /proc/asound/pcm
else
    printf 'PCM_NOT_ACCESSIBLE\n'
fi
printf 'W3_AUDIO_PROBE_END\n'
"""


def interpret(output: str) -> tuple[bool, str]:
    lines = [line.strip("\r") for line in output.splitlines()]
    if "W3_AUDIO_PROBE_V1" not in lines or "W3_AUDIO_PROBE_END" not in lines:
        return False, "FAIL: Incomplete SDB output. No firmware or card conclusions."
    start = lines.index("W3_AUDIO_PROBE_V1")
    end = lines.index("W3_AUDIO_PROBE_END", start + 1)
    records = lines[start + 1:end]
    found = {name: [] for name, _ in EXPECTED}
    cards = []
    pcm = []
    cards_accessible = False
    pcm_accessible = False
    for line in records:
        if line.startswith("FOUND|"):
            parts = line.split("|", 3)
            if len(parts) != 4:
                return False, "FAIL: Malformed firmware observation."
            _, name, status, path = parts
            if name in found and status in ("READABLE", "PRESENT_NOT_READABLE"):
                found[name].append((status, path))
        elif line.startswith("CARD|"):
            cards_accessible = True
            cards.append(line[5:])
        elif line == "CARD_NOT_ACCESSIBLE":
            cards_accessible = False
        elif line.startswith("PCM|"):
            pcm_accessible = True
            pcm.append(line[4:])
        elif line == "PCM_NOT_ACCESSIBLE":
            pcm_accessible = False
    report = [
        "Galaxy Watch3 audio probe (read-only filesystem observations)",
        "WARNING: This is NOT evidence of firmware identity, legal rights, driver function or audio playback.",
    ]
    for name, role in EXPECTED:
        observations = found[name]
        if observations:
            status = "READABLE" if any(a[0] == "READABLE" for a in observations) else "PRESENT_NOT_READABLE"
            paths = ", ".join(a[1] for a in observations)
            report.append(f"{name} ({role}): {status} at {paths}")
        else:
            report.append(f"{name} ({role}): NOT_OBSERVED_IN_TESTED_PATHS (not proof of absence)")
    cards_text = "\n".join(cards)
    card_report = "CARD_MATCH_OBSERVED" if re.search(r"Exynos.?9110.?Sound", cards_text, re.I) else "NO_EXYNOS9110_CARD_OBSERVED"
    report.append("ALSA /proc/asound/cards: " + (card_report if cards_accessible else "NOT_ACCESSIBLE_OR_EMPTY"))
    report.append("ALSA /proc/asound/pcm: " + ("READABLE (" + str(len(pcm)) + " lines)" if pcm_accessible else "NOT_ACCESSIBLE_OR_EMPTY"))
    report.append("No firmware contents read, no file copied, no mixer settings changed.")
    return True, "\n".join(report)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--live", action="store_true", help="Use an already authenticated SDB connection, read-only")
    group.add_argument("--fixture", type=Path, help="Parse an offline text fixture instead of connecting to a watch")
    ap.add_argument("--serial", help="SDB device serial (only with --live)")
    args = ap.parse_args()
    if args.serial and not args.live:
        ap.error("--serial requires --live")
    if args.fixture:
        try:
            raw = args.fixture.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"FAIL: Fixture read failed: {exc}", file=sys.stderr)
            return 1
    elif args.live:
        if not shutil.which("sdb"):
            print("FAIL: SDB client not found. This probe requires installed SDB on your host.", file=sys.stderr)
            return 1
        cmd = ["sdb"]
        if args.serial:
            cmd += ["-s", args.serial]
        cmd += ["shell", REMOTE_SCRIPT]
        try:
            response = subprocess.run(cmd, capture_output=True, text=True, timeout=40, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"FAIL: Read-only SDB probe could not run: {exc}", file=sys.stderr)
            return 1
        if response.returncode:
            print(f"FAIL: SDB returned {response.returncode}: {response.stderr[:350]}", file=sys.stderr)
            return 1
        raw = response.stdout
    else:
        print("Not connecting to the watch. For an existing authorized SDB session, use --live.")
        print("No root access, firmware extraction, uploads, playback or writes are performed.")
        return 0
    ok, report = interpret(raw)
    print(report)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
