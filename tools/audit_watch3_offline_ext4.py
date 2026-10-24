#!/usr/bin/env python3
"""Read-only audit of a completed, previously built Watch3 R08 ext4 artifact.

This does not rebuild Yocto, mount with write access, flash, unlock, modify,
or prove that a Samsung Galaxy Watch3 can boot the image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from validate_watch3_graphics_rootfs import elf_aarch64, REQUIRED_MANIFEST


MIN_IMAGE_SIZE = 4 * 1024 * 1024
IMAGE_GLOB = "asteroid-image-noblesse-r08.rootfs-*.ext4"
VERIFY_FILES = {
    "/usr/bin/asteroid-launcher": "launcher",
    "/usr/lib/systemd/user/asteroid-launcher.service": "launcher_service",
    "/var/lib/environment/compositor/10-platform.conf": "compositor_config",
}
NEEDED_CONFIG = ("QT_QPA_PLATFORM=linuxfb", "QT_QUICK_BACKEND=software",
                 "QT_QPA_FB_DRM=0")


def one_real_file(root: Path, pattern: str) -> Path:
    matches = [
        file for file in root.rglob(pattern)
        if file.is_file() and not file.is_symlink()
        and file.resolve().is_relative_to(root.resolve())
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one real {pattern} in {root}, got "
            f"{len(matches)}: {[p.name for p in matches[:10]]}")
    return matches[0]


def expected_digest(path: Path, image_name: str) -> str:
    entries = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    if len(entries) != 1:
        raise ValueError("Expected exactly one sha256sum record from the original build")
    match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?(.+)", entries[0])
    if not match or Path(match.group(2)).name != image_name:
        raise ValueError("Original build checksum is missing or belongs to a different ext4")
    return match.group(1).lower()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def package_closure(path: Path) -> dict:
    names = {line.split()[0] for line in path.read_text(errors="replace").splitlines()
             if line.strip() and not line.lstrip().startswith("#")}
    missing = sorted(REQUIRED_MANIFEST - names)
    if missing:
        raise ValueError(f"Original installed-package manifest lacks {missing}")
    return {"package_count": len(names),
            "required_graphics_packages": sorted(REQUIRED_MANIFEST)}


def run_tool(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args, capture_output=True, text=True, stdin=subprocess.DEVNULL,
            timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Read-only filesystem inspection unavailable: {exc}") from exc


def dump_file(image: Path, source: str, target: Path) -> None:
    # debugfs is read-only by default. In particular DO NOT add the -w flag.
    if not source.startswith("/") or "\n" in source:
        raise ValueError("Invalid image-internal path")
    result = run_tool(
        "debugfs", "-R", f"dump {source} {target}", str(image), timeout=120)
    if result.returncode or not target.is_file() or target.stat().st_size == 0:
        raise ValueError(f"Missing/unreadable {source} in ext4: "
                         f"{result.stderr[-300:]}")


def audit(image_dir: Path, stage_dir: Path) -> dict:
    image = one_real_file(image_dir, IMAGE_GLOB)
    checksums = one_real_file(stage_dir, "asteroid-image.sha256")
    manifest = one_real_file(stage_dir, "installed-packages.manifest")
    if image.stat().st_size < MIN_IMAGE_SIZE:
        raise ValueError("Ext4 smaller than 4 MiB, unlikely to be the built rootfs")
    expected = expected_digest(checksums, image.name)
    actual = sha256_file(image)
    if actual != expected:
        raise ValueError(f"Artifact SHA256 does not match original build: "
                         f"expected {expected}, got {actual}")
    with image.open("rb") as stream:
        stream.seek(1024 + 56)
        if stream.read(2) != b"\x53\xef":
            raise ValueError("Wrong ext-family superblock magic (expected 0xEF53)")

    packages = package_closure(manifest)
    fsck = run_tool("e2fsck", "-f", "-n", str(image), timeout=240)
    if fsck.returncode != 0:
        raise ValueError(
            f"Read-only e2fsck returned {fsck.returncode}: "
            f"{(fsck.stdout + fsck.stderr)[-1600:]}")
    header = run_tool("dumpe2fs", "-h", str(image), timeout=90)
    if header.returncode or not re.search(
            r"^Filesystem magic number:\s+0xEF53\s*$",
            header.stdout, re.MULTILINE):
        raise ValueError(f"Invalid ext4 superblock header: {header.stderr[-500:]}")
    fields = {}
    for line in header.stdout.splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            if name.strip() in ("Filesystem volume name", "Filesystem state",
                                "Filesystem features", "Block size",
                                "Block count", "Inode count"):
                fields[name.strip()] = value.strip()
    if "extent" not in fields.get("Filesystem features", "").split():
        raise ValueError("Ext4 expected extent feature is absent")
    feature_names = set(fields.get("Filesystem features", "").split())
    # orphan_file was added upstream in Linux 5.15. The Watch3 R08
    # reference kernel is 4.9.59. This is a compatibility concern even if
    # ext4 metadata is structurally healthy and e2fsck 1.47+ accepts it.
    # Do not modify an existing successful image to "fix" the feature.
    legacy_kernel_feature_risk = "orphan_file" in feature_names

    with tempfile.TemporaryDirectory(prefix="watch3-offline-audit-") as temporary:
        root = Path(temporary)
        output = {}
        for internal, label in VERIFY_FILES.items():
            destination = root / label
            dump_file(image, internal, destination)
            output[label] = destination
        good, reason = elf_aarch64(output["launcher"])
        if not good:
            raise ValueError(f"Launcher extracted from ext4 is not real ARM64: {reason}")
        config = output["compositor_config"].read_text(errors="replace")
        for setting in NEEDED_CONFIG:
            if setting not in set(config.splitlines()):
                raise ValueError(f"Deployed ext4 compositor config lacks {setting}")
        service = output["launcher_service"].read_text(errors="replace")
        if "/var/lib/environment/compositor/" not in service:
            raise ValueError("Deployed launcher service lacks compositor environment")

    return {
        "result": "PASS_OFF_DEVICE_IMAGE_AUDIT",
        "source_run_id": 40095182440,
        "image_name": image.name,
        "image_size_bytes": image.stat().st_size,
        "verified_sha256": actual,
        "filesystem": fields,
        "read_only_e2fsck": "clean (return code 0)",
        "ext4_orphan_file_present": legacy_kernel_feature_risk,
        "legacy_watch3_kernel_4_9_compatibility_risk": legacy_kernel_feature_risk,
        "kernel_feature_risk_action": (
            "Stop: require a separate legacy-compatible image build and "
            "read-only kernel/filesystem evidence before any device action"
            if legacy_kernel_feature_risk else
            "No orphan_file flag found; further hardware and kernel checks still required"
        ),
        "deployed_arm64_launcher": "ELF64 little-endian AArch64 header verified",
        "deployed_compositor_config": list(NEEDED_CONFIG),
        "deployed_launcher_service": "environment reference verified",
        **packages,
        "hardware_boot_tested": False,
        "watch_display_input_audio_tested": False,
        "bootloader_unlock_and_stock_recovery_verified": False,
        "flashable": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", type=Path, required=True)
    parser.add_argument("--stage-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(args.image_dir, args.stage_dir)
    except (ValueError, OSError) as exc:
        result = {"result": "FAIL", "reason": str(exc), "flashable": False}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n")
        print(f"FAIL[offdevice]: {exc}", file=sys.stderr)
        return 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    print("PASS: ext4 SHA256, superblock, filesystem consistency and extracted "
          "ARM64 launcher/config checked WITHOUT modifying the image.")
    if result["legacy_watch3_kernel_4_9_compatibility_risk"]:
        print("BLOCKER: ext4 orphan_file flag is newer than pinned Watch3 "
              "Linux 4.9.59 reference kernel; no hardware installation.")
    print("NOT TESTED: physical watch boot, secure boot, display, input, audio or "
          "stock firmware recovery. NOT FLASHABLE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
