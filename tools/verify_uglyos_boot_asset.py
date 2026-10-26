#!/usr/bin/env python3
"""Fail-closed R08 Psplash smoke GIF verification, no device actions."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import sys
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "meta-noblesse/recipes-core/psplash/psplash_%.bbappend"
ASSET = ROOT / "meta-noblesse/recipes-core/psplash/files/uglyos-smoke.gif"
EXPECTED_SHA256 = "2878bb3917eceec530f321acd61a21967fdb0f158370252866a21452b9f5060f"
SIZE = (280, 280)
FRAMES = 30

def verify_recipe() -> None:
    source = RECIPE.read_text()
    for required in ('SRC_URI:append:noblesse-r08 = " file://uglyos-smoke.gif"',
                     'do_install:append:noblesse-r08()', 'psplash-upstream.gif',
                     'FILES:', ':append:noblesse-r08', 'psplash.gif'):
        if required not in source:
            raise ValueError(f"R08 Psplash override contract is missing: {required}")
    if 'SRC_URI:append = ' in source or 'do_install:append()' in source:
        raise ValueError("Psplash override must not affect other watch models")

def verify_gif(path: Path = ASSET) -> None:
    if not path.is_file():
        raise ValueError(
            "REQUIRED binary missing. Add uglyos-smoke-boot-r08.gif as "
            "meta-noblesse/recipes-core/psplash/files/uglyos-smoke.gif "
            "to branch uglyos-r08-real-smoke-boot. Keep PR in draft."
        )
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"Exact user-video derivative hash mismatch: {digest}")
    if len(data) > 1_500_000:
        raise ValueError("GIF too large for lightweight startup")
    with Image.open(path) as gif:
        if gif.format != "GIF" or gif.size != SIZE or gif.n_frames != FRAMES:
            raise ValueError("Not the approved 280x280 30-frame smoke GIF")
        if FRAMES * 280 * 280 * 3 > 8_000_000:
            raise ValueError("Psplash RGB frame cache exceeds budget")
        for frame in range(FRAMES):
            gif.seek(frame)
            if gif.info.get("duration", 0) != 100:
                raise ValueError(f"Frame {frame} timing changed")
            rgb = gif.convert("RGB")
            for pos in ((0, 0), (279, 0), (0, 279), (279, 279)):
                if max(rgb.getpixel(pos)) > 16:
                    raise ValueError(f"Green-screen/background artifact in frame {frame}")
    print("PASS[smoke-boot]: exact smoke derivative matches approved hash")
    print("PASS[smoke-boot]: 280px/30 frames/3s, pure black corners")
    print("NOT TESTED: Psplash binary, rootfs, boot, recovery or flashing")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipe-only", action="store_true")
    args = parser.parse_args()
    try:
        verify_recipe()
        if not args.recipe_only:
            verify_gif()
    except (OSError, ValueError) as error:
        print(f"FAIL[smoke-boot]: {error}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
