#!/usr/bin/env python3
"""Verify Watch3-specific AsteroidOS compositor override, not device graphics."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "meta-noblesse/recipes-asteroid/asteroid-launcher"
BBAPPEND = BASE / "asteroid-launcher-configs_%.bbappend"
ENV = BASE / "asteroid-launcher-configs/10-platform.conf"

def main():
    recipe = BBAPPEND.read_text(encoding="utf-8")
    env = ENV.read_text(encoding="utf-8")
    values = {}
    for line in env.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key in values:
            print("FAIL: malformed or duplicate compositor environment setting")
            return 1
        values[key] = value
    checks = {
        "recipe only applies to R08": "FILESEXTRAPATHS:prepend:noblesse-r08 :=" in recipe,
        "extends upstream installation without replacement": "SRC_URI =" not in recipe and "do_install()" not in recipe and "do_install:append:noblesse-r08()" in recipe,
        "upstream 10-platform.conf path overridden": "${THISDIR}/asteroid-launcher-configs:" in recipe,
        "Qt6 uses Linux framebuffer": values.get("QT_QPA_PLATFORM") == "linuxfb",
        "Qt Quick software scenegraph": values.get("QT_QUICK_BACKEND") == "software",
        "Qt LinuxFB not DRM fallback": values.get("QT_QPA_FB_DRM") == "0",
        "no unverified EGLFS settings": not any(k.startswith("QT_QPA_EGLFS") for k in values),
        "no unsupported firmware writing": all(s not in env+recipe for s in ("fastboot flash", "heimdall flash", "sdb root")),
    }
    for label, ok in checks.items():
        print(("PASS" if ok else "FAIL") + ": " + label)
    print("LinuxFB candidate configured. This does not prove fbdev presence, a Qt plugin, or a working GUI.")
    return 0 if all(checks.values()) else 1

if __name__ == "__main__":
    sys.exit(main())
