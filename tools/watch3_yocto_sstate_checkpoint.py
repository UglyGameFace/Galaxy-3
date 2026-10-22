#!/usr/bin/env python3
"""Create/restore size-bounded Yocto sstate cache snapshots for free Actions.

Only copy complete sstate archive + .siginfo pairs. No TMPDIR, toolchains
installed under sysroot, secrets, or firmware are cached. The source sstate
is never modified. A snapshot is a *subset*, not a proof of warm build.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

# Keep the outputs of expensive Qt/core toolchains first. Archive naming
# is sstate:<recipe>:<triple>:..._<task>.tar.zst, per pinned BitBake 2.16.
PREFERRED = (
    "qtbase", "qtdeclarative", "qtwayland", "qtshadertools",
    "qttools-native", "gcc-cross", "glibc", "binutils-cross",
)


def priority(name: str) -> int:
    if not name.startswith("sstate:"):
        return len(PREFERRED)
    recipe = name.split(":", 2)[1]
    for index, fragment in enumerate(PREFERRED):
        if recipe == fragment or recipe.startswith(fragment + "-"):
            return index
    return len(PREFERRED)


def _validate_dirs(source: Path, destination: Path) -> tuple[Path, Path]:
    source, destination = source.resolve(), destination.resolve()
    if source == destination or source.is_relative_to(destination) or destination.is_relative_to(source):
        raise ValueError("Cache source and destination must be disjoint directories")
    return source, destination


def pairs(root: Path):
    if not root.is_dir():
        return
    root_real = root.resolve()
    for file in root.rglob("*.tar.zst"):
        sidecar = file.with_name(file.name + ".siginfo")
        if (file.is_symlink() or sidecar.is_symlink()
                or not file.is_file() or not sidecar.is_file()
                or not file.resolve().is_relative_to(root_real)
                or not sidecar.resolve().is_relative_to(root_real)):
            continue
        yield file, sidecar


def checkpoint(source: Path, destination: Path, max_bytes: int) -> dict:
    source, destination = _validate_dirs(source, destination)
    if max_bytes < 1024:
        raise ValueError("Cache budget must be at least 1024 bytes")
    candidates = list(pairs(source))
    candidates.sort(key=lambda pair: (
        priority(pair[0].name),
        -pair[0].stat().st_mtime,
        pair[0].as_posix(),
    ))
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    total = 0
    selected = 0
    skipped = 0
    for archive, siginfo in candidates:
        size = archive.stat().st_size + siginfo.stat().st_size
        if total + size > max_bytes:
            skipped += 1
            continue
        for file in (archive, siginfo):
            target = destination / file.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, target)
        selected += 1
        total += size
    stats = {
        "version": 1, "archive_pairs": selected, "skipped_pairs": skipped,
        "bytes": total, "max_bytes": max_bytes,
    }
    (destination / "watch3-sstate-manifest.json").write_text(
        json.dumps(stats, sort_keys=True, indent=2) + "\n"
    )
    return stats


def restore(source: Path, destination: Path) -> dict:
    source, destination = _validate_dirs(source, destination)
    info = source / "watch3-sstate-manifest.json"
    if not info.is_file():
        raise ValueError("Cache snapshot has no manifest")
    data = json.loads(info.read_text())
    if data.get("version") != 1:
        raise ValueError("Unknown cache snapshot format")
    found = list(pairs(source))
    if len(found) != data.get("archive_pairs"):
        raise ValueError("Sstate cache archive pairs do not match snapshot manifest")
    copied = 0
    for archive, siginfo in found:
        for file in (archive, siginfo):
            target = destination / file.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, target)
        copied += 1
    return {"restored_pairs": copied}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("checkpoint", "restore"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--max-mib", type=int, default=4096)
    args = parser.parse_args()
    try:
        result = (checkpoint(args.source, args.destination, args.max_mib * 1024**2)
                  if args.mode == "checkpoint" else restore(args.source, args.destination))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"FAIL[sstate]: {error}\n")
    print("PASS[sstate]: " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
