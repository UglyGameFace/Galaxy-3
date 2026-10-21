#!/usr/bin/env python3
"""Validate AsteroidOS generated Watch3 R08 machine.conf; this is NOT a driver test."""
import argparse
import configparser
from pathlib import Path
import sys

def verify(path: Path, speaker: str) -> bool:
    if not path.is_file() or not path.stat().st_size:
        print(f"FAIL: Missing or empty machine.conf: {path}", file=sys.stderr)
        return False
    cfg = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        with path.open(encoding="utf-8") as file:
            cfg.read_file(file)
    except (OSError, UnicodeError, configparser.Error) as error:
        print(f"FAIL: Invalid machine.conf: {error}", file=sys.stderr)
        return False
    checks = {
        ("Display", "ROUND"): "true",
        ("Capabilities", "HAS_WLAN"): "true",
        ("Capabilities", "HAS_SPEAKER"): speaker,
        ("Identity", "MACHINE"): "noblesse-r08",
    }
    passed = True
    for (section, key), expected in checks.items():
        actual = cfg.get(section, key, fallback=None)
        if actual != expected:
            print(f"FAIL: {section}.{key}: expected {expected!r}, found {actual!r}", file=sys.stderr)
            passed = False
        else:
            print(f"PASS: {section}.{key}={actual}")
    if passed:
        print("Hardware metadata validated. Playback/display and watch boot NOT validated.")
    return passed

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--expected-speaker", choices=("true", "false"), default="true")
    args = parser.parse_args()
    return 0 if verify(args.config, args.expected_speaker) else 1

if __name__ == "__main__":
    sys.exit(main())
