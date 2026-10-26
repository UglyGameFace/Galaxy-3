#!/usr/bin/env python3
"""Fail-closed native UgLy App Hub BitBake metadata, package and image checks.

Native binaries are build evidence, NOT verified bootloader/install approval.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import re
import sys

from validate_watch3_native_face_ipk import read_real_ipk

PN = "uglyos-app-hub"
TARGET = "noblesse-r08"
INPUTS = (
    "CMakeLists.txt", "main.cpp", "main.qml", "HubPage.qml",
    "HubCatalog.js", "uglyos-app-hub.in", "uglyos-app-hub.desktop.template",
    "i18n/uglyos-app-hub.desktop.h",
)

class NativeHubError(ValueError):
    pass

def variables(file: Path) -> dict[str,str]:
    wanted = ("PN","MACHINE","DISTRO","PACKAGE_ARCH","PACKAGES","DEPENDS",
              "SRC_URI","IMAGE_INSTALL","D","PKGDEST","PV","PR","bindir",
              "libdir","datadir","S")
    found={}
    for line in file.read_text().splitlines():
        line=line.removeprefix("export ")
        for key in wanted:
            match=re.fullmatch(re.escape(key) + r'="(.*)"',line)
            if match: found[key]=match.group(1)
    return found

def check_metadata(recipe: dict, image: dict) -> None:
    for key, expected in (("PN",PN),("MACHINE",TARGET),("DISTRO","asteroid"),
                          ("PACKAGE_ARCH","noblesse_r08")):
        if recipe.get(key)!=expected:
            raise NativeHubError(f"Wrong real BitBake {key}")
    if PN not in recipe.get("PACKAGES","").split():
        raise NativeHubError("Native app package missing from PACKAGES")
    if not {"qml-asteroid","asteroid-generate-desktop-native"}.issubset(
           set(recipe.get("DEPENDS","").split())):
        raise NativeHubError("Missing actual upstream Qt6 app CMake dependencies")
    src=recipe.get("SRC_URI","").split()
    for name in INPUTS:
        if "file://"+name not in src:
            raise NativeHubError("Missing reviewed local source: "+name)
    if image.get("MACHINE")!=TARGET or image.get("DISTRO")!="asteroid":
        raise NativeHubError("Wrong actual image environment")
    if PN not in image.get("IMAGE_INSTALL","").split():
        raise NativeHubError("R08 root image doesn't include native App Hub")
    print("PASS[hub-bitbake]: pinned machine, dependencies, eight sources, IMAGE_INSTALL")

def check_graph(recipe_list: Path, dot: Path) -> None:
    recipes=set(recipe_list.read_text().splitlines())
    graph=dot.read_text()
    tasks=set(re.findall(r'"([^"]+\.do_[^"]+)"',graph))
    if PN not in recipes or PN not in graph:
        raise NativeHubError("Actual native Hub IPK task graph missing")
    forbidden=recipes & {"asteroid-image","initramfs-android-image","linux-noblesse"}
    if forbidden:
        raise NativeHubError("Full firmware/kernel build unexpectedly required: "+str(sorted(forbidden)))
    if not 100 <= len(tasks) <= 4500:
        raise NativeHubError(f"Native Qt6 task count outside guarded budget: {len(tasks)}")
    print(f"PASS[hub-graph]: {len(recipes)} recipes, {len(tasks)} native tasks")

def inspect_file(root: Path, relative: str) -> bytes:
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        raise NativeHubError("Unsafe native package staging root")
    p=root/relative
    if not p.is_file() or p.is_symlink():
        raise NativeHubError("Missing or unsafe actual staged file: "+relative)
    return p.read_bytes()

def check_ipk(env: dict, archive: Path) -> None:
    version=env.get("PV","")+"-"+env.get("PR","")
    arch=env.get("PACKAGE_ARCH")
    if arch!="noblesse_r08" or not re.fullmatch(r"[0-9A-Za-z.+_~-]+",version):
        raise NativeHubError("Invalid native IPK version/arch")
    if archive.name!=f"{PN}_{version}_{arch}.ipk":
        raise NativeHubError("Wrong actual native IPK filename/version/arch")
    for key, expected in (("bindir","/usr/bin"),("datadir","/usr/share")):
        if env.get(key)!=expected:
            raise NativeHubError("Unexpected native file install directory: "+key)
    libdir=env.get("libdir","")
    if libdir not in ("/usr/lib","/usr/lib64"):
        raise NativeHubError("Unsafe/missing native Qt library directory")
    files={
        "usr/bin/uglyos-app-hub": "launcher",
        libdir.lstrip("/")+"/uglyos-app-hub.so": "binary",
        "usr/share/applications/uglyos-app-hub.desktop": "desktop",
    }
    control,payload=read_real_ipk(archive)
    for key,expected in (("Package",PN),("Architecture",arch),("Version",version)):
        if control.get(key)!=expected:
            raise NativeHubError("Actual opkg control mismatch: "+key)
    if control.get("Depends","").strip()=="":
        raise NativeHubError("Native Qt app cannot have an empty runtime dependency list")
    staged={}
    for relative in files:
        blob=payload.get(relative)
        if not blob:
            raise NativeHubError("Missing actual compiled IPK entry: "+relative)
        for where in ("D","PKGDEST"):
            base=env.get(where,"")
            root=Path(base) / (PN if where=="PKGDEST" else "")
            if not base or not Path(base).is_absolute():
                raise NativeHubError("Missing absolute native "+where)
            if inspect_file(root,relative)!=blob:
                raise NativeHubError("Staged vs packaged mismatch: "+relative)
        staged[relative]=blob
    elf=staged[libdir.lstrip("/")+"/uglyos-app-hub.so"]
    if not elf.startswith(b"\x7fELF") or len(elf)<5000:
        raise NativeHubError("Genuine compiled Qt6 ARM shared object missing")
    script=staged["usr/bin/uglyos-app-hub"]
    if not script.startswith(b"#!/bin/sh") or b"invoker --single-instance --type=asteroid-qt6" not in script:
        raise NativeHubError("Native launcher does not invoke AsteroidApp6")
    desktop=staged["usr/share/applications/uglyos-app-hub.desktop"]
    if b"Exec=uglyos-app-hub" not in desktop or b"Name=UgLy|OS App Hub" not in desktop:
        raise NativeHubError("Native app desktop metadata incomplete")
    print("PASS[hub-native-ipk]: real ELF, launcher, desktop, native staging and opkg archive")
    print("IPK_SHA256="+hashlib.sha256(archive.read_bytes()).hexdigest())
    print("OFFDEVICE NOT FLASHABLE. Physical Watch3 boot/restore still unverified.")

def main()->int:
    cli=argparse.ArgumentParser()
    cli.add_argument("mode",choices=("metadata","graph","native-ipk"))
    cli.add_argument("first",type=Path)
    cli.add_argument("second",type=Path)
    args=cli.parse_args()
    try:
        if args.mode=="metadata":
            check_metadata(variables(args.first),variables(args.second))
        elif args.mode=="graph":
            check_graph(args.first,args.second)
        else:
            check_ipk(variables(args.first),args.second)
        return 0
    except (OSError,ValueError,KeyError) as exc:
        print("FAIL[hub-native]: "+str(exc),file=sys.stderr)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
