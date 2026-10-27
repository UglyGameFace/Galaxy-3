#!/usr/bin/env python3
"""Fail-fast real BitBake qtbase R08 bezel patch gate, BEFORE ARM64 compile."""
from pathlib import Path
import argparse
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RECIPE = "meta-noblesse/recipes-qt/qt6/qtbase_%.bbappend"
PATCH_DIR = "meta-noblesse/recipes-qt/qt6/qtbase"
PATCH = "0001-noblesse-r08-tizen-detent-wheel-only.patch"
EVDEV = "src/platformsupport/input/evdevmouse/qevdevmousehandler.cpp"
HEADER = "src/platformsupport/input/evdevmouse/qevdevmousehandler_p.h"
LIBINPUT = "src/platformsupport/input/libinput/qlibinputhandler.cpp"


class GateError(ValueError):
    pass


def parse_env(body: str) -> dict[str, str]:
    # Do not match commented variable history in bitbake -e output.
    keys = ("PN", "MACHINE", "DISTRO", "PV", "OVERRIDES", "SRC_URI",
            "FILESPATH", "PACKAGECONFIG", "S")
    found: dict[str, str] = {}
    for line in body.splitlines():
        for key in keys:
            if line.startswith(key + "="):
                val = line[len(key)+1:]
                if not (val.startswith('"') and val.endswith('"')):
                    raise GateError("Malformed effective " + key)
                found[key] = val[1:-1]
    return found


def verify(body: str, stage: str, root: Path = ROOT) -> dict[str, str]:
    v = parse_env(body)
    for name, want in (("PN", "qtbase"), ("MACHINE", "noblesse-r08"),
                       ("DISTRO", "asteroid"), ("PV", "6.11.3")):
        if v.get(name) != want:
            raise GateError(name + ": expected " + want + ", got " + repr(v.get(name)))
    if "noblesse-r08" not in v.get("OVERRIDES", "").split(":"):
        raise GateError("Machine override missing")
    recipe = root / RECIPE
    patchfile = root / PATCH_DIR / PATCH
    if not recipe.is_file() or not patchfile.is_file():
        raise GateError("Missing machine-only bbappend or patch")
    bbappend = recipe.read_text()
    if "SRC_URI:append:noblesse-r08" not in bbappend or PATCH not in bbappend:
        raise GateError("Missing exact R08 patch append")
    if "FILESEXTRAPATHS:prepend:noblesse-r08" not in bbappend:
        raise GateError("Machine-specific file search path missing")
    if "Upstream-Status: Pending" not in patchfile.read_text():
        raise GateError("Missing Yocto patch status")
    if v.get("SRC_URI", "").split().count("file://" + PATCH) != 1:
        raise GateError("Effective SRC_URI does not select the R08 patch exactly once")
    patchdir = (root / PATCH_DIR).resolve()
    if not any(Path(p).resolve() == patchdir or patchdir in Path(p).resolve().parents
               for p in v.get("FILESPATH", "").split(":") if p):
        raise GateError("Effective FILESPATH cannot resolve machine patch")
    for feature in ("linuxfb", "libinput"):
        if feature not in v.get("PACKAGECONFIG", "").split():
            raise GateError("QtBase feature missing: " + feature)
    result = {"patch_selected": "true", "real_sources_patched": "false"}
    if stage == "metadata":
        return result

    src = v.get("S", "")
    if not src or not Path(src).is_absolute() or not Path(src).is_dir():
        raise GateError("S is not an existing absolute post-do_patch source directory")
    sources = {}
    for name in (EVDEV, HEADER, LIBINPUT):
        f = Path(src) / name
        if not f.is_file():
            raise GateError("Missing source after do_patch: " + name)
        sources[name] = f.read_text()
    evdev, header, li = sources[EVDEV], sources[HEADER], sources[LIBINPUT]
    for body, needed in (
        (evdev, 'std::strcmp(inputName, "tizen_detent") == 0'),
        (evdev, "EVIOCGNAME(sizeof(inputName))"),
        (evdev, "EVIOCGBIT(EV_REL, sizeof(relFeatures))"),
        (evdev, "TEST_BIT(relFeatures, REL_WHEEL)"),
        (evdev, "delta.setY(120 * data->value);"),
        (evdev, "emit handleWheelEvent(delta);"),
        (header, "bool m_watch3Detent = false;"),
        (li, 'std::strcmp(deviceName, "tizen_detent") == 0'),
        (li, "m_pointer->processAxis(libinput_event_get_pointer_event(ev));"),
        (li, "m_pointer->processButton(libinput_event_get_pointer_event(ev));"),
        (li, "m_touch->processTouchDown(libinput_event_get_touch_event(ev));"),
        (li, "m_keyboard->processKey(libinput_event_get_keyboard_event(ev));"),
    ):
        if needed not in body:
            raise GateError("Missing applied patch or original Qt input code: " + needed)
    if not re.search(r'if \(m_watch3Detent && \(data->code == REL_X \|\| data->code == REL_Y\)\)\s+continue;', evdev):
        raise GateError("Evdev hall pointer suppression not applied")
    if not re.search(r'if \(deviceName && std::strcmp\(deviceName, "tizen_detent"\) == 0\s+&& '
                     r'\(type == LIBINPUT_EVENT_POINTER_MOTION\s+\|\| '
                     r'type == LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE\)\)\s+return;', li):
        raise GateError("Libinput bezel pointer suppression not applied")
    result["real_sources_patched"] = "true"
    return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("environment", type=Path)
    p.add_argument("--stage", choices=("metadata", "patched"), required=True)
    args = p.parse_args()
    try:
        result = verify(args.environment.read_text(), args.stage)
    except (GateError, OSError, UnicodeError) as exc:
        print("FAIL[bezel-bitbake]: " + str(exc), file=sys.stderr)
        return 1
    print("PASS[bezel-bitbake]: R08 QtBase 6.11.3 patch selected; " +
          ("actual do_patch verified" if result["real_sources_patched"] == "true"
           else "real do_patch still required"))
    print("NOT TESTED: native ARM64 compile, runtime wheel delivery, boot/recovery")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
