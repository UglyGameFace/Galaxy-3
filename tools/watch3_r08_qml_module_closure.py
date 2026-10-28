#!/usr/bin/env python3
"""Check the ORIGINAL extracted UgLy|OS ARM64 Qt/QML module deployment.

Tests target-root filesystem metadata, qmldir declarations and installed
AArch64 module plugin binaries. No QML execution, GUI startup, watch contact,
bootloader or system filesystem mutation. This is a *module closure*, not an
SM-R840X boot proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from watch3_r08_qemu_userland_smoke import read_arm64, SmokeFailure

REQUIRED = ("QtQuick", "QtQml", "QtWayland.Compositor")
OPTIONAL = ("QtQuick.Window", "QtWayland.Compositor.XdgShell")
ROOTS = ("usr/lib/qml", "usr/lib64/qml", "lib/qml", "lib64/qml",
         "usr/share/qt6/qml", "usr/lib/qt6/qml", "usr/lib64/qt6/qml")
MAX_QMLDIR = 32_768
MODULE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$")
PLUGIN_RE = re.compile(r"^[A-Za-z0-9_]+$")


class ModuleClosureError(ValueError):
    pass


def inside(root: Path, target: Path) -> bool:
    return target.resolve().is_relative_to(root.resolve())


def locate_module(root: Path, module: str) -> dict:
    if not MODULE_RE.fullmatch(module):
        raise ModuleClosureError("INVALID_QML_MODULE_NAME")
    hits: list[tuple[Path, Path]] = []
    relative = Path(*module.split("."))
    for prefix in ROOTS:
        parent = root / prefix / relative
        config = parent / "qmldir"
        if config.exists():
            if not config.is_file() or not inside(root, config):
                raise ModuleClosureError("QMLDIR_ESCAPES_GUEST_ROOT:" + module)
            hits.append((parent, config))
    if not hits:
        raise ModuleClosureError("REQUIRED_QML_MODULE_MISSING:" + module)
    # Qt modules can legitimately appear under alternate import roots, but
    # identical duplicate targets can mask which module QML actually chooses.
    if len(hits) != 1:
        raise ModuleClosureError("AMBIGUOUS_QML_MODULE_DEPLOYMENT:" + module)
    parent, config = hits[0]
    if config.stat().st_size > MAX_QMLDIR or config.stat().st_size == 0:
        raise ModuleClosureError("QMLDIR_EMPTY_OR_UNBOUNDED:" + module)
    source = config.read_text(encoding="utf-8")
    declared = []
    plugins = []
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0] == "module":
            if len(fields) != 2 or not MODULE_RE.fullmatch(fields[1]):
                raise ModuleClosureError("BAD_QML_MODULE_DECLARATION:" + module)
            declared.append(fields[1])
        if fields[0] == "plugin" or (fields[:2] == ["optional", "plugin"]):
            is_optional = fields[0] == "optional"
            start = 2 if is_optional else 1
            if len(fields) not in (start + 1, start + 2):
                raise ModuleClosureError("INVALID_QML_PLUGIN_DECLARATION:" + module)
            name = fields[start]
            if not PLUGIN_RE.fullmatch(name):
                raise ModuleClosureError("UNSAFE_QML_PLUGIN_NAME:" + module)
            plugins.append((name, is_optional))
    if declared != [module]:
        raise ModuleClosureError("QML_MODULE_IDENTITY_MISMATCH:" + module)
    verified_plugins = []
    optional_missing = []
    for plugin, optional in plugins:
        candidate = parent / ("lib" + plugin + ".so")
        if not candidate.is_file():
            if optional:
                optional_missing.append(plugin)
                continue
            raise ModuleClosureError("REQUIRED_QML_PLUGIN_MISSING:" + module + ":" + plugin)
        if not inside(root, candidate):
            raise ModuleClosureError("PLUGIN_SYMLINK_ESCAPE:" + module)
        try:
            metadata = read_arm64(candidate)
        except SmokeFailure as exc:
            raise ModuleClosureError("QML_PLUGIN_NOT_REAL_AARCH64:" + module) from exc
        verified_plugins.append({"name": plugin, "sha256": metadata["sha256"]})
    return {"module": module, "qmldir_path_in_guest": "/" + str(config.relative_to(root)),
            "qmldir_sha256": __import__("hashlib").sha256(config.read_bytes()).hexdigest(),
            "plugins_aarch64_verified": verified_plugins,
            "optional_plugins_absent": optional_missing}


def audit(root: Path) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise ModuleClosureError("INVALID_EXTRACTED_GUEST_ROOT")
    root = root.resolve()
    deployed = [locate_module(root, module) for module in REQUIRED]
    optional_modules = {}
    for module in OPTIONAL:
        try:
            optional_modules[module] = locate_module(root, module)
        except ModuleClosureError as error:
            if str(error) == "REQUIRED_QML_MODULE_MISSING:" + module:
                optional_modules[module] = {"status": "ABSENT_NOT_REQUIRED_BY_THIS_GATE"}
            else:
                raise
    return {
        "schema": "uglyos-r08-target-arm64-qml-deployment-closure-v1",
        "status": "REAL_ARM64_QML_MODULE_DEPLOYMENT_VERIFIED",
        "required_modules": deployed,
        "optional_modules": optional_modules,
        "required_modules_present": True,
        "required_present_plugin_binaries_checked_as_aarch64": True,
        "module_loading_at_runtime_tested": False,
        "qml_or_wayland_compositor_started": False,
        "physical_watch_contacted": False,
        "stock_restore_proven": False,
        "flashable": False,
        "decision": "NO_GO",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extracted-rootfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(args.extracted_rootfs)
        if args.output.exists() or args.output.is_symlink():
            raise ModuleClosureError("REPORT_ALREADY_EXISTS")
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    except (ModuleClosureError, OSError, UnicodeError) as error:
        print("QML_DEPLOYMENT_NOT_VERIFIED: " + str(error), file=sys.stderr)
        return 2
    print("PASS: genuine installed ARM64 QML module declarations/plugins; NO WATCH BOOT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
