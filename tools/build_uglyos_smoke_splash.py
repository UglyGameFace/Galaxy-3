#!/usr/bin/env python3
"""Convert a user-supplied green-screen smoke video to an OFF-DEVICE Psplash GIF.

Never downloads a YouTube video, changes a boot partition or installs onto a
watch. The exact clip and its reuse rights must be supplied and verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from PIL import Image, ImageSequence

PIXELS = 280
FPS = 10
SECONDS = 3
FRAMES = FPS * SECONDS
MAX_GIF_BYTES = 1_500_000
MAX_DECODE_BYTES = 8_000_000  # Upstream psplash GIF loader caches 24-bit RGB frames.
REFERENCE_URL = "https://youtu.be/WqeCrfgum38"


def command(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, check=True, text=True, capture_output=True,
                                timeout=100)
        return result
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise ValueError(f"Media conversion failed: {detail[-1400:]}") from error


def validate_gif(path: Path) -> dict:
    if not path.is_file() or not 2000 <= path.stat().st_size <= MAX_GIF_BYTES:
        raise ValueError("Missing, blank or oversized smoke GIF (1.5 MB cap)")
    with Image.open(path) as gif:
        if gif.format != "GIF" or gif.size != (PIXELS, PIXELS) or gif.n_frames != FRAMES:
            raise ValueError("Smoke output must be an exactly 280x280, 30-frame GIF")
        if FRAMES * PIXELS * PIXELS * 3 > MAX_DECODE_BYTES:
            raise ValueError("Upstream psplash decoded-frame memory budget exceeded")
        green = bright = total = 0
        samples = []
        delays = []
        for i, frame in enumerate(ImageSequence.Iterator(gif)):
            delays.append(frame.info.get("duration", 0))
            image = frame.convert("RGB")
            for pos in ((0, 0), (PIXELS - 1, 0), (0, PIXELS - 1),
                        (PIXELS - 1, PIXELS - 1)):
                if max(image.getpixel(pos)) > 16:
                    raise ValueError(f"Frame {i}: unsafe bright rectangular background")
            if i in (0, 7, 15, 23, 29):
                samples.append(hashlib.sha256(image.tobytes()).hexdigest())
            for y in range(30, PIXELS - 30, 4):
                for x in range(30, PIXELS - 30, 4):
                    r, g, b = image.getpixel((x, y))
                    green += int(g > 72 and g > r * 1.55 and g > b * 1.45)
                    bright += int(max(r, g, b) > 65)
                    total += 1
        if len(set(samples)) < 3:
            raise ValueError("Smoke effect is static or contains too few distinct frames")
        if green > total * 0.006:
            raise ValueError(f"Green-screen spill remains in output: {green}/{total} samples")
        if bright < total * 0.002:
            raise ValueError("Smoke is invisible after chroma key; adjust the keying parameters")
        if any(delay < 70 or delay > 150 for delay in delays):
            raise ValueError("Frame timing must remain near 10 fps; never add boot delay")
    return {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size, "width": PIXELS, "height": PIXELS,
            "frames": FRAMES, "fps": FPS, "duration_seconds": SECONDS,
            "decoded_rgb_bytes": FRAMES * PIXELS * PIXELS * 3,
            "background": "black, not the source green screen",
            "green_sample_ratio": round(green / total, 6),
            "distinct_visual_samples": len(set(samples)),
            "source_reference": REFERENCE_URL,
            "source_verified": False,
            "not_tested": ["Watch3 boot", "native Psplash playback", "recovery", "flashing"]}


def convert(source: Path, destination: Path, start: float = 0.0,
            similarity: float = 0.18, blend: float = 0.07) -> dict:
    if not source.is_file() or source.stat().st_size == 0:
        raise ValueError("Provide a local, authorized copy of the actual source clip")
    if source.resolve() == destination.resolve():
        raise ValueError("Never overwrite the original smoke source")
    if start < 0 or not (0.08 <= similarity <= 0.35) or not (0 <= blend <= 0.2):
        raise ValueError("Invalid trim or green-screen key parameters")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Pure black is intentional: the pinned psplash decoder produces 24-bit
    # RGB frames, not full alpha-composited video. No green-screen rectangle.
    # Center-fit keeps smoke within the 360x360 circular AMOLED safe region.
    filtergraph = (
        f"color=c=black:s={PIXELS}x{PIXELS}:r={FPS}:d={SECONDS}[bg];"
        f"[0:v]fps={FPS},"
        f"scale={PIXELS}:{PIXELS}:force_original_aspect_ratio=decrease:flags=lanczos,"
        f"pad={PIXELS}:{PIXELS}:(ow-iw)/2:(oh-ih)/2:color=0x00FF00,"
        f"format=yuv420p,chromakey=0x00FF00:{similarity:.3f}:{blend:.3f},"
        f"despill=type=green:mix=0.16[smoke];"
        "[bg][smoke]overlay=shortest=1:format=auto:repeatlast=0,"
        "hue=s=0,format=rgb24,split[a][b];"
        "[a]palettegen=max_colors=24:stats_mode=diff[p];"
        "[b][p]paletteuse=dither=bayer:bayer_scale=5[out]"
    )
    args = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-ss", f"{start:.3f}", "-t", str(SECONDS), "-i", str(source),
            "-filter_complex", filtergraph, "-map", "[out]",
            "-an", "-loop", "0", str(destination)]
    command(args)
    try:
        report = validate_gif(destination)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Authorized local MP4/MOV source")
    parser.add_argument("--output", type=Path, required=True, help="Off-device test GIF destination")
    parser.add_argument("--start", type=float, default=0.0)
    parser.add_argument("--similarity", type=float, default=0.18)
    parser.add_argument("--blend", type=float, default=0.07)
    parser.add_argument("--expected-source-sha256", default="", help="Optional expected SHA256 of authorized original")
    args = parser.parse_args()
    try:
        source_sha256 = hashlib.sha256(args.input.read_bytes()).hexdigest() if args.input.is_file() else ""
        if args.expected_source_sha256 and source_sha256 != args.expected_source_sha256:
            raise ValueError("Local smoke source checksum differs from supplied original")
        report = convert(args.input, args.output, args.start, args.similarity, args.blend)
        report["source_sha256"] = source_sha256
        report["source_verified"] = bool(args.expected_source_sha256)
        report_path = args.output.with_suffix(".report.json")
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS[smoke-key]: {report['frames']} frames, {report['bytes']} bytes, "
              f"green spill ratio {report['green_sample_ratio']}")
        print(f"OFF DEVICE ONLY: {args.output} | report: {report_path}")
        return 0
    except (ValueError, OSError) as exc:
        print(f"FAIL[smoke-key]: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
