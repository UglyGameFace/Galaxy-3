#!/usr/bin/env python3
"""Resolve real, paired Yocto image outputs instead of re-evaluating DATETIME.

A separate "bitbake -e" invocation can expand IMAGE_MANIFEST with a newer
timestamp than the completed image tasks. Use the deployed ext4's exact basename
to select its manifest, never a guessed post-build IMAGE_MANIFEST path.

OFF-DEVICE ONLY. Discovering image outputs is not validation or flash approval.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import sys


FIELDS = (
    "PN", "MACHINE", "DISTRO", "IMAGE_ROOTFS", "IMAGE_MANIFEST",
    "DEPLOY_DIR_IMAGE", "IMAGE_LINK_NAME",
)


def read_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        for field in FIELDS:
            prefix = field + "="
            if line.startswith(prefix):
                value = line[len(prefix):]
                values[field] = (value[1:-1] if value.startswith('"')
                                 and value.endswith('"') else value)
    return values


def discover(values: dict[str, str]) -> tuple[Path, Path, Path]:
    for field, expected in (
        ("PN", "asteroid-image"), ("MACHINE", "noblesse-r08"),
        ("DISTRO", "asteroid"),
    ):
        if values.get(field) != expected:
            raise ValueError(f"{field}: expected {expected}, got {values.get(field)!r}")

    rootfs = Path(values["IMAGE_ROOTFS"])
    deploy = Path(values["DEPLOY_DIR_IMAGE"])
    name = values["IMAGE_LINK_NAME"]
    if not name.startswith("asteroid-image") or "/" in name or not name:
        raise ValueError(f"Unexpected image link name: {name!r}")
    if not deploy.is_dir():
        raise ValueError(f"Actual deployed image directory missing: {deploy}")

    # Prefer versioned real files over stable symlinks. All candidates must
    # resolve inside the actual DEPLOY_DIR_IMAGE, with nonzero content.
    folder = deploy.resolve()
    candidates = [
        p for p in deploy.glob(name + "*.ext4")
        if p.is_file() and p.stat().st_size > 0
        and p.resolve().is_relative_to(folder)
    ]
    candidates.sort(key=lambda p: (
        p.is_symlink(), -p.stat().st_mtime_ns, p.name
    ))
    if not candidates:
        raise ValueError(
            f"No non-empty deployed AsteroidOS ext4 under {deploy} "
            f"with prefix {name!r}"
        )
    image = candidates[0].resolve()

    # Image and installed-package manifest share IMAGE_NAME. The separate
    # post-build "bitbake -e" IMAGE_MANIFEST value often has a later DATETIME.
    manifest = image.with_suffix(".manifest")
    if not manifest.is_file() or not manifest.resolve().is_relative_to(folder):
        found = sorted(p.name for p in deploy.glob(name + "*.manifest"))
        raise ValueError(
            f"No paired installed-package manifest for {image.name} "
            f"(expected {manifest.name}; deployed manifests: {found}). "
            f"Post-build metadata path was {values.get('IMAGE_MANIFEST')!r}"
        )
    if not rootfs.is_dir():
        raise ValueError(f"Actual extracted rootfs missing: {rootfs}")

    return rootfs, manifest, image


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", type=Path)
    parser.add_argument("paths_output", type=Path)
    parser.add_argument("github_env", type=Path)
    args = parser.parse_args()
    try:
        values = read_environment(args.environment)
        # Capture the actual ext4 path for diagnostics even if validation
        # fails, without treating that ext4 as validated or flashable.
        link_name = values.get("IMAGE_LINK_NAME", "")
        deploy = Path(values.get("DEPLOY_DIR_IMAGE", "/__missing__"))
        potential = sorted(
            (p for p in deploy.glob(link_name + "*.ext4")
             if link_name.startswith("asteroid-image")
             and p.is_file() and p.stat().st_size > 0
             and p.resolve().is_relative_to(deploy.resolve())
             and not p.is_symlink()),
            key=lambda p: (-p.stat().st_mtime_ns, p.name),
        )
        if potential:
            with args.github_env.open("a") as out:
                out.write("UNVALIDATED_IMAGE_PATH=" + str(potential[0].resolve()) + "\n")
        rootfs, manifest, image = discover(values)
        args.paths_output.write_text(
            f"{rootfs}\n{manifest}\n{image}\n"
        )
        print(f"PASS[outputs]: rootfs={rootfs}")
        print(f"PASS[outputs]: paired manifest={manifest}")
        print(f"PASS[outputs]: deployed ext4={image}")
        print("NOT TESTED: rootfs contents, executable startup, watch boot or flashing")
        return 0
    except (OSError, KeyError, ValueError) as error:
        print("FAIL[outputs]: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
