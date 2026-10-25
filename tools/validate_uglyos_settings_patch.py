#!/usr/bin/env python3
"""Check R08-only Settings patch against the exact pinned upstream revision.

Source-patch proof only: not a Settings binary/runtime, physical watch or OTA.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = "60340bd1c27a7b9e4884bd61c0563d091bc8b240"
TARGET = Path("src/qml/WatchfacePage.qml")
PATCH = ROOT / "meta-noblesse/recipes-asteroid/asteroid-settings/files/0001-uglyos-watchface-accent.patch"
BBAPPEND = ROOT / "meta-noblesse/recipes-asteroid/asteroid-settings/asteroid-settings_%.bbappend"
KEY = "/desktop/uglyos/appearance/accent"
PALETTES = ("original", "emerald", "ice", "violet", "ember", "rose")


def run(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=True, text=True)
    return p.stdout.strip()


def validate(repo: Path) -> None:
    actual = run(repo, "rev-parse", "HEAD")
    if actual != EXPECTED:
        raise RuntimeError(f"Unexpected upstream Settings revision: {actual}")
    original = (repo / TARGET).read_text()
    if KEY in original:
        raise RuntimeError("Pinned upstream already includes UgLy|OS accent key")

    bb = BBAPPEND.read_text()
    if 'SRC_URI:append:noblesse-r08 = " file://0001-uglyos-watchface-accent.patch"' not in bb:
        raise RuntimeError("Settings patch must be scoped to the R08 machine")
    if 'FILESEXTRAPATHS:prepend := "$' + '{THISDIR}/files:"' not in bb:
        raise RuntimeError("Settings recipe does not reference its patch folder")
    run(repo, "apply", "--check", str(PATCH))
    run(repo, "apply", str(PATCH))
    patched = (repo / TARGET).read_text()
    for token in (
        'key: "/desktop/asteroid/watchface"',
        'key: "/org/asteroidos/settings/use-12h-format"',
        'key: "' + KEY + '"',
        'defaultValue: "original"',
        'OptionCycler {',
        'text: qsTr("UgLy|OS accent")',
        'onValueChanged: (selected) =>',
        'WatchfaceSelector {',
        'anchors.bottom: accentRow.top',
    ):
        if token not in patched:
            raise RuntimeError(f"Missing Settings control or original key: {token}")
    for name in PALETTES:
        if f'"{name}"' not in patched:
            raise RuntimeError(f"Missing palette: {name}")
    if patched.count("WatchfaceSelector {") != 1:
        raise RuntimeError("Stock WatchfaceSelector was replaced or duplicated")
    diff = run(repo, "diff", "--", str(TARGET))
    if KEY not in diff or "OptionCycler" not in diff:
        raise RuntimeError("The patch did not create the intended source changes")
    print("PASS[settings-patch]: applies to exact pinned upstream AsteroidOS Settings revision")
    print("PASS[settings-patch]: stock selector + six accent choices use Nemo.Configuration")
    print("NOT TESTED: native Settings binary, persistence, watch boot or flashing")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: validate_uglyos_settings_patch.py PINNED_SETTINGS_GIT_CHECKOUT")
    try:
        validate(Path(sys.argv[1]).resolve())
    except (OSError, subprocess.CalledProcessError, RuntimeError) as err:
        print(f"FAIL[settings-patch]: {err}", file=sys.stderr)
        raise SystemExit(1)
