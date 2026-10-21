#!/usr/bin/env python3
"""Check effective BitBake Qt/launcher metadata, not built plugin files or watch GUI."""
import argparse
from pathlib import Path
import sys


def read_variable(environment: str, key: str) -> str | None:
    # Ignore BitBake's assignment history in comments; use the effective value.
    for line in environment.splitlines():
        if line.startswith(key + '='):
            value = line.partition('=')[2]
            return value[1:-1] if value.startswith('"') and value.endswith('"') else value
    return None


def check_metadata(qtbase_env: str, launcher_env: str) -> list[str]:
    errors = []
    for label, env in (("qtbase", qtbase_env), ("asteroid-launcher", launcher_env)):
        machine = read_variable(env, "MACHINE")
        if machine != "noblesse-r08":
            errors.append(f"{label}: expected MACHINE=noblesse-r08, got {machine!r}")

    qt_features = set((read_variable(qtbase_env, "PACKAGECONFIG") or "").split())
    for needed in ("gui", "linuxfb"):
        if needed not in qt_features:
            errors.append(f"qtbase PACKAGECONFIG is missing {needed!r}")

    # Qt6's qt6.inc places QPA platform plugins in qtbase-plugins. The .so
    # still requires a successful build and package inspection to validate.
    plugin_files = read_variable(qtbase_env, "FILES:qtbase-plugins") or ""
    if '/plugins/' not in plugin_files:
        errors.append("qtbase-plugins does not include Qt's plugin directory")

    deps = set((read_variable(launcher_env, "RDEPENDS:asteroid-launcher") or "").split())
    for needed in ("qtbase-plugins", "qtwayland-plugins"):
        if needed not in deps:
            errors.append(f"asteroid-launcher RDEPENDS is missing {needed!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("qtbase_env", type=Path)
    parser.add_argument("launcher_env", type=Path)
    args = parser.parse_args()
    for path in (args.qtbase_env, args.launcher_env):
        if not path.is_file():
            print(f"FAIL: missing BitBake environment {path}", file=sys.stderr)
            return 1
    errors = check_metadata(args.qtbase_env.read_text(encoding="utf-8"),
                            args.launcher_env.read_text(encoding="utf-8"))
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if errors:
        return 1
    print("PASS: QtBase linuxfb+gui are enabled; qtbase-plugins packages QPA plugins.")
    print("PASS: R08 launcher depends on qtbase-plugins and qtwayland-plugins.")
    print("NOT TESTED: compiled libqlinuxfb.so, wl_shm rendering, or Watch3 /dev/fb0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
