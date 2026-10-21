#!/usr/bin/env python3
"""Resolve R08 compositor BitBake metadata from any working directory.

This is a path/metadata guard only, not hardware validation.
"""
import argparse
from pathlib import Path
import sys

SOURCE_FRAGMENT = "meta-noblesse/recipes-asteroid/asteroid-launcher/asteroid-launcher-configs"


def parse_effective_environment(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        if line.startswith(("UNPACKDIR=", "FILESPATH=", "MACHINE=")):
            key, raw = line.split("=", 1)
            values[key] = raw.strip('"')
    return values


def check_paths(env_path: Path, output_path: Path) -> bool:
    if not output_path.is_absolute():
        print("FAIL: compositor diagnostic output path must be absolute", file=sys.stderr)
        return False
    if not env_path.is_file():
        print(f"FAIL: missing BitBake environment: {env_path}", file=sys.stderr)
        return False
    env = parse_effective_environment(env_path.read_text(encoding="utf-8"))
    if env.get("MACHINE") != "noblesse-r08":
        print(f"FAIL: unexpected MACHINE={env.get('MACHINE')!r}", file=sys.stderr)
        return False
    if SOURCE_FRAGMENT not in env.get("FILESPATH", ""):
        print("FAIL: R08 FILESPATH override not in effective metadata", file=sys.stderr)
        return False
    unpackdir = env.get("UNPACKDIR")
    if not unpackdir or not Path(unpackdir).is_absolute():
        print(f"FAIL: invalid absolute UNPACKDIR={unpackdir!r}", file=sys.stderr)
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(unpackdir + "\n", encoding="utf-8")
    print("PASS: R08 compositor FILESPATH and absolute UNPACKDIR resolved.")
    print(f"PASS: diagnostic written to {output_path}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("environment", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    return 0 if check_paths(args.environment, args.output) else 1


if __name__ == "__main__":
    sys.exit(main())
