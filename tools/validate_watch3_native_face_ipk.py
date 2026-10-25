#!/usr/bin/env python3
"""Fail-closed inspection of an IPK produced by Yocto do_package_write_ipk.

The source assets and package staging must match the real pinned BitBake run.
This is off-device verification only, NEVER a boot or flash authorization.
"""
from __future__ import annotations
import argparse
import hashlib
import io
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from validate_uglyos_face_package import (
    FACES, PACKAGE, PackageError, inspect_package, variables,
)

PAYLOAD = {f"usr/share/asteroid-launcher/watchfaces/{name}": name for name in FACES}
PAYLOAD["usr/share/uglyos/edition.json"] = "uglyos-edition.json"
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024


def _command(*args: str) -> bytes:
    try:
        return subprocess.run(args, check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PackageError(f"Cannot inspect native IPK using {args[0]}") from exc


def _tar_files(data: bytes, label: str) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise PackageError(f"{label} archive too large")
    output: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            for member in tar:
                name = member.name.removeprefix("./")
                if name in (".", ""):
                    continue
                if (name.startswith("/") or ".." in Path(name).parts or
                        member.issym() or member.islnk() or member.isdev()):
                    raise PackageError(f"Unsafe {label} tar entry")
                if member.isdir():
                    continue
                if not member.isfile() or name in output or member.size > MAX_MEMBER_BYTES:
                    raise PackageError(f"Invalid/duplicate {label} tar file")
                fileobj = tar.extractfile(member)
                if fileobj is None:
                    raise PackageError(f"Unreadable {label} tar file")
                output[name] = fileobj.read()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise PackageError(f"Corrupt {label} tar content") from exc
    return output


def read_real_ipk(path: Path) -> tuple[dict[str, str], dict[str, bytes]]:
    if not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackageError("Native IPK is missing or unexpectedly large")
    if not path.read_bytes().startswith(b"!<arch>\n"):
        raise PackageError("Native IPK is not an ar archive")
    names = _command("ar", "t", str(path)).decode("utf-8").splitlines()
    if len(names) != 3 or names[0] != "debian-binary" or names[1] != "control.tar.gz" or names[2] not in ("data.tar.zst", "data.tar.gz"):
        raise PackageError(f"Unexpected native IPK members: {names!r}")
    if _command("ar", "p", str(path), "debian-binary") != b"2.0\n":
        raise PackageError("Bad IPK format version")
    ctrl = _tar_files(_command("ar", "p", str(path), "control.tar.gz"), "control")
    if "control" not in ctrl:
        raise PackageError("Missing native opkg control file")
    fields: dict[str, str] = {}
    for line in ctrl["control"].decode("utf-8").splitlines():
        if line.startswith(" ") or line.startswith("\t"):
            continue   # continuation of Description, not another field
        if ": " not in line:
            raise PackageError("Malformed IPK control field")
        key, value = line.split(": ", 1)
        if key in fields:
            raise PackageError("Duplicate IPK control field")
        fields[key] = value
    data_blob = _command("ar", "p", str(path), names[2])
    if names[2].endswith(".zst"):
        try:
            proc = subprocess.run(["zstd", "-d", "-q", "-c"], input=data_blob,
                                  capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise PackageError("Cannot decompress Yocto Zstandard payload") from exc
        data_blob = proc.stdout
    return fields, _tar_files(data_blob, "payload")


def verify_native_ipk(info: dict[str, str], source: Path, package: Path) -> str:
    inspect_package(info, source)
    expected_arch = info.get("PACKAGE_ARCH")
    expected_version = info.get("PV", "") + "-" + info.get("PR", "")
    if expected_arch != "noblesse_r08" or not re.fullmatch(r"[0-9A-Za-z.+_~-]+", expected_version):
        raise PackageError("Unexpected native IPK architecture/version from BitBake")
    expected_name = f"{PACKAGE}_{expected_version}_{expected_arch}.ipk"
    if package.name != expected_name:
        raise PackageError(f"Native IPK filename mismatch: {package.name} != {expected_name}")
    fields, payload = read_real_ipk(package)
    for key, expected in (("Package", PACKAGE), ("Version", expected_version), ("Architecture", expected_arch)):
        if fields.get(key) != expected:
            raise PackageError(f"Native IPK {key} does not match BitBake metadata")
    dependencies = fields.get("Depends", "")
    if dependencies.strip() != "asteroid-launcher":
        raise PackageError("Native IPK must have exactly asteroid-launcher as its runtime dependency")
    if set(payload) != set(PAYLOAD):
        raise PackageError(f"Native IPK payload paths differ: {sorted(set(payload) ^ set(PAYLOAD))}")
    for name, original in PAYLOAD.items():
        if not payload[name] or payload[name] != (source / original).read_bytes():
            raise PackageError(f"Native IPK payload mismatch: {name}")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    print(f"PASS[native-ipk]: Yocto-built {package.name} contains four identical installed assets")
    print(f"SHA256: {digest}")
    print("NOT TESTED: rootfs integration, opkg install, watch boot, stock recovery or flashing")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("environment", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("native_ipk", type=Path)
    args = parser.parse_args()
    try:
        verify_native_ipk(variables(args.environment), args.source, args.native_ipk)
    except (PackageError, OSError, ValueError, UnicodeError) as exc:
        print("FAIL[native-ipk]: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
