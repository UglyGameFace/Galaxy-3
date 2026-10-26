#!/usr/bin/env python3
"""Create and inspect a CI-only opkg IPK from actual BitBake D.

This does not execute OE-Core do_package or do_package_write_ipk. The output
is an OFFLINE proof artifact, not authorized for device installation/flashing.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from validate_uglyos_face_package import FACES, PACKAGE, PackageError, inspect_installed, variables

REQUIRED_FILES = tuple(f"usr/share/asteroid-launcher/watchfaces/{name}" for name in FACES) + ("usr/share/uglyos/edition.json",)
AR_MAGIC = b"!<arch>\n"


def _metadata(info: dict[str, str]) -> dict[str, str]:
    if info.get("PN") != PACKAGE or info.get("MACHINE") != "noblesse-r08" or info.get("DISTRO") != "asteroid":
        raise PackageError("IPK metadata is not the Watch3 R08 AsteroidOS recipe")
    fields = {name: info.get(name, "") for name in ("PV", "PR", "PACKAGE_ARCH")}
    for name, value in fields.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_~-]*", value):
            raise PackageError(f"Unsafe/missing IPK metadata: {name}")
    if info.get("RDEPENDS:watch3-faces", "").split() != ["asteroid-launcher"]:
        raise PackageError("Unexpected runtime dependencies for the offline package")
    if fields["PACKAGE_ARCH"] != "noblesse_r08":
        raise PackageError("Package architecture is not the R08 machine architecture")
    return fields


def _tar_gz(files: dict[str, bytes]) -> bytes:
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0, filename="") as gz:
        with tarfile.open(fileobj=gz, mode="w|") as tar:
            for filename, content in sorted(files.items()):
                member = tarfile.TarInfo("./" + filename)
                member.size = len(content)
                member.mode = 0o644
                member.uid = member.gid = 0
                member.uname = member.gname = "root"
                member.mtime = 0
                tar.addfile(member, io.BytesIO(content))
    return compressed.getvalue()


def _ar_member(name: str, data: bytes) -> bytes:
    if len(name) > 15 or "/" in name:
        raise PackageError("Unsafe ar member")
    header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}{chr(96)}\n".encode("ascii")
    if len(header) != 60:
        raise PackageError("Invalid ar header length")
    return header + data + (b"\n" if len(data) % 2 else b"")


def create_ipk(info: dict[str, str], source: Path, destination: Path) -> Path:
    inspect_installed(info, source)
    meta = _metadata(info)
    root = Path(info["D"])
    payload = {name: (root / name).read_bytes() for name in REQUIRED_FILES}
    version = meta["PV"] + "-" + meta["PR"]
    control = (f"Package: {PACKAGE}\n"
               f"Version: {version}\n"
               f"Architecture: {meta['PACKAGE_ARCH']}\n"
               "Maintainer: UgLy|OS project\n"
               "Depends: asteroid-launcher\n"
               "License: MIT\n"
               "Description: UgLy|OS R08 optional watch faces (offline proof only)\n").encode("utf-8")
    md5sums = "".join(f"{hashlib.md5(content).hexdigest()}  {name}\n" for name, content in sorted(payload.items())).encode("ascii")
    archive = (AR_MAGIC
               + _ar_member("debian-binary", b"2.0\n")
               + _ar_member("control.tar.gz", _tar_gz({"control": control, "md5sums": md5sums}))
               + _ar_member("data.tar.gz", _tar_gz(payload)))
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / f"{PACKAGE}_{version}_{meta['PACKAGE_ARCH']}.ipk"
    target.write_bytes(archive)
    verify_ipk(target, info, payload)
    print(f"PASS[offline-ipk]: ar/opkg archive and all 6 embedded files verified: {target.name}")
    print("NOT TESTED: Yocto do_package, do_package_write_ipk, opkg install, firmware or device boot")
    return target


def _ar_members(archive: bytes) -> dict[str, bytes]:
    if not archive.startswith(AR_MAGIC):
        raise PackageError("Not an ar-format IPK")
    items: dict[str, bytes] = {}
    offset = len(AR_MAGIC)
    while offset < len(archive):
        header = archive[offset:offset + 60]
        if len(header) != 60 or header[-2:] != bytes((96, 10)):
            raise PackageError("Invalid IPK ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as exc:
            raise PackageError("Invalid IPK ar member size") from exc
        offset += 60
        body = archive[offset:offset + size]
        if len(body) != size or name in items:
            raise PackageError("Truncated or duplicate IPK member")
        items[name] = body
        offset += size + size % 2
    if offset != len(archive):
        raise PackageError("Invalid IPK archive alignment")
    return items


def _untar(blob: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for entry in tar:
            name = entry.name.removeprefix("./")
            if (not entry.isfile() or name.startswith("/") or ".." in Path(name).parts
                    or name in files or entry.mode != 0o644 or entry.uid != 0 or entry.gid != 0):
                raise PackageError("Unsafe or duplicate IPK tar entry")
            handle = tar.extractfile(entry)
            if handle is None:
                raise PackageError("Missing IPK file content")
            files[name] = handle.read()
    return files


def verify_ipk(path: Path, info: dict[str, str], expected_payload: dict[str, bytes]) -> None:
    meta = _metadata(info)
    members = _ar_members(path.read_bytes())
    if set(members) != {"debian-binary", "control.tar.gz", "data.tar.gz"}:
        raise PackageError("IPK must contain exactly the three opkg ar members")
    if members["debian-binary"] != b"2.0\n":
        raise PackageError("Invalid IPK format version")
    controls = _untar(members["control.tar.gz"])
    if set(controls) != {"control", "md5sums"}:
        raise PackageError("Missing or unexpected IPK control files")
    values = dict(line.split(": ", 1) for line in controls["control"].decode("utf-8").splitlines())
    required = {"Package": PACKAGE, "Version": meta["PV"] + "-" + meta["PR"],
                "Architecture": meta["PACKAGE_ARCH"], "Depends": "asteroid-launcher"}
    if any(values.get(key) != value for key, value in required.items()):
        raise PackageError("Wrong IPK control metadata")
    payload = _untar(members["data.tar.gz"])
    if payload != expected_payload or set(payload) != set(REQUIRED_FILES):
        raise PackageError("IPK payload differs from actual BitBake install staging")
    checksums = "".join(f"{hashlib.md5(content).hexdigest()}  {name}\n" for name, content in sorted(payload.items())).encode("ascii")
    if controls["md5sums"] != checksums:
        raise PackageError("IPK checksum manifest differs from payload")
    listing = subprocess.run(["ar", "t", str(path)], capture_output=True, text=True, check=True)
    if listing.stdout.splitlines() != ["debian-binary", "control.tar.gz", "data.tar.gz"]:
        raise PackageError("Binutils rejected expected IPK archive layout")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("environment", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        create_ipk(variables(args.environment), args.source, args.destination)
    except (PackageError, OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"FAIL[offline-ipk]: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
