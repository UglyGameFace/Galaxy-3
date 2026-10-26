"""Verify off-device green-screen removal using synthetic TEST media only.

The real user-selected YouTube clip is NOT available in this test environment.
No synthetic test image or copyrighted source video is shipped in the OS.
"""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import unittest

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from build_uglyos_smoke_splash import (
    convert, validate_gif, REFERENCE_URL, FRAMES, MAX_GIF_BYTES,
)


class SmokeKeyTests(unittest.TestCase):
    def test_source_video_identity_and_no_boot_mutation(self):
        code = (ROOT / "tools/build_uglyos_smoke_splash.py").read_text()
        self.assertEqual(REFERENCE_URL, "https://youtu.be/WqeCrfgum38")
        self.assertIn("chromakey=0x00FF00", code)
        self.assertIn("despill=type=green", code)
        self.assertIn("hue=s=0", code)
        self.assertIn("palettegen=max_colors=24", code)
        self.assertIn("background", code)
        self.assertIn("not_tested", code)
        self.assertNotIn("fastboot flash", code)
        self.assertNotIn("sdb shell", code)
        self.assertNotIn("wget ", code)
        self.assertNotIn("yt-dlp", code)
        self.assertNotIn("sleep(", code)

    def test_green_removal_round_geometry_memory_and_source_preservation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for i in range(FRAMES):
                frame = Image.new("RGB", (480, 270), (0, 255, 0))
                draw = ImageDraw.Draw(frame)
                draw.ellipse((145 + i * 2, 65 + i // 3, 235 + i * 2, 155 + i // 3),
                             fill=(220, 220, 220))
                draw.ellipse((215 - i, 95 + i // 2, 300 - i, 185 + i // 2),
                             fill=(170, 170, 170))
                frame.save(root / f"f-{i:03}.png")
            video = root / "fake-smoke.mp4"
            subprocess.run(
                ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                 "-framerate", "10", "-i", str(root / "f-%03d.png"),
                 "-pix_fmt", "yuv420p", "-c:v", "libx264", str(video)],
                check=True, timeout=50,
            )
            before = hashlib.sha256(video.read_bytes()).hexdigest()
            output = root / "smoke-only.gif"
            proof = convert(video, output)
            self.assertEqual(proof["frames"], 30)
            self.assertEqual(proof["width"], 280)
            self.assertEqual(proof["height"], 280)
            self.assertEqual(proof["duration_seconds"], 3)
            self.assertEqual(proof["fps"], 10)
            self.assertLess(proof["bytes"], MAX_GIF_BYTES)
            self.assertLess(proof["decoded_rgb_bytes"], 8_000_000)
            self.assertLess(proof["green_sample_ratio"], 0.006)
            self.assertGreaterEqual(proof["distinct_visual_samples"], 3)
            self.assertEqual(before, hashlib.sha256(video.read_bytes()).hexdigest())
            self.assertEqual(validate_gif(output)["sha256"], proof["sha256"])

    def test_no_source_or_invalid_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with self.assertRaisesRegex(ValueError, "authorized copy"):
                convert(path / "missing.mp4", path / "out.gif")
            source = path / "input.mp4"
            source.write_bytes(b"not a media clip")
            with self.assertRaisesRegex(ValueError, "Invalid trim"):
                convert(source, path / "out.gif", similarity=0.7)


if __name__ == "__main__":
    unittest.main()
