#!/usr/bin/env python3
"""Render REAL UgLy|OS watch-face QML using host Qt 6, with MOCKED watch signals.

A screenshot here is a host software-Qt render, not proof of Watch3 hardware,
AsteroidOS runtime imports, bootability, or install/flash safety.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QUICK_BACKEND", "software")
os.environ.setdefault("QT_OPENGL", "software")

from PySide6.QtCore import QObject, Property, QDateTime, Qt, QUrl, QLocale, QPoint, QPointF
from PySide6.QtGui import QGuiApplication, QImage, QPainter, QPainterPath
from PySide6.QtQuick import QQuickView
from PySide6.QtTest import QTest

ROOT = Path(__file__).resolve().parents[1]
FACES = ROOT / "meta-noblesse/recipes-asteroid/watch3-faces/watch3-faces"
STUBS = ROOT / "tools/uglyos-render-fixtures"
EXPECTED = ("900-watch3-orbit.qml", "901-watch3-focus.qml", "902-watch3-signal.qml", "903-watch3-solo-arcade.qml",
            "904-watch3-solo-lounge.qml")
FIXED_TIME = QDateTime.fromString("2026-10-25T15:42:00", Qt.ISODate)
CASES = (
    ("active-24h", 360, False, False, False),
    ("active-12h", 360, True, False, False),
    ("ambient", 360, False, True, False),
    ("nightstand", 360, False, False, True),
    ("compact-240", 240, False, False, False),
    ("palette-emerald", 360, False, False, False),
    ("palette-ice", 360, False, False, False),
    ("palette-violet", 360, False, False, False),
    ("palette-ember", 360, False, False, False),
    ("palette-rose", 360, False, False, False),
)


class Clock(QObject):
    @Property(QDateTime, constant=True)
    def time(self) -> QDateTime:
        return FIXED_TIME


class FormatPreference(QObject):
    def __init__(self, use12: bool):
        super().__init__()
        self._use12 = use12

    @Property(bool, constant=True)
    def value(self) -> bool:
        return self._use12


class BurnInMock(QObject):
    def __init__(self):
        super().__init__()
        self._width = 0.0
        self._height = 0.0

    @Property(float)
    def widthOffset(self) -> float:
        return self._width

    @widthOffset.setter
    def widthOffset(self, number: float) -> None:
        self._width = number

    @Property(float)
    def heightOffset(self) -> float:
        return self._height

    @heightOffset.setter
    def heightOffset(self, number: float) -> None:
        self._height = number


def _round_preview(raw: QImage) -> QImage:
    """Visualize a round watch by alpha-masking the original host render."""
    size = raw.width()
    result = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    result.fill(Qt.transparent)
    painter = QPainter(result)
    painter.setRenderHint(QPainter.Antialiasing, True)
    circle = QPainterPath()
    circle.addEllipse(1.0, 1.0, size - 2.0, size - 2.0)
    painter.setClipPath(circle)
    painter.drawImage(0, 0, raw)
    painter.end()
    return result


def _measure(raw: QImage) -> dict[str, int]:
    """Reject empty/black frames; require painted information inside the dial."""
    size = raw.width()
    highlights = 0
    distinct = set()
    for y in range(0, size, 4):
        for x in range(0, size, 4):
            if ((x - size / 2) ** 2 + (y - size / 2) ** 2) > (size * 0.46) ** 2:
                continue
            c = raw.pixelColor(x, y)
            r, g, b = c.red(), c.green(), c.blue()
            if max(r, g, b) >= 90:
                highlights += 1
            distinct.add((r // 32, g // 32, b // 32))
    if highlights < 40 or len(distinct) < 5:
        raise RuntimeError(f"Blank watch-face render: {highlights} highlights, {len(distinct)} colors")
    return {"highlight_samples": highlights, "color_buckets": len(distinct)}


def _render_one(app: QGuiApplication, source: Path, size: int,
                use12: bool, ambient: bool, nightstand: bool, preset: str) -> tuple[QImage, dict]:
    clock = Clock()
    preference = FormatPreference(use12)
    burnin = BurnInMock()
    errors = []
    view = QQuickView()
    view.engine().addImportPath(str(STUBS))
    view.engine().warnings.connect(lambda warnings: errors.extend(str(w.toString()) for w in warnings))
    context = view.rootContext()
    context.setContextProperty("wallClock", clock)
    context.setContextProperty("use12H", preference)
    context.setContextProperty("burnInProtectionManager", burnin)
    context.setContextProperty("displayAmbient", ambient)
    context.setContextProperty("nightstand", nightstand)
    context.setContextProperty("mockAccentPreset", preset)
    view.setResizeMode(QQuickView.SizeRootObjectToView)
    view.resize(size, size)
    view.setSource(QUrl.fromLocalFile(str(source.resolve())))
    if view.status() != QQuickView.Ready or view.rootObject() is None:
        errors.extend(str(e.toString()) for e in view.errors())
        raise RuntimeError(f"QML rejected {source.name}: {'; '.join(errors)}")
    # The host mock supplies the palette through the exact real ConfigurationValue key.
    choice = str(view.rootObject().property("accentChoice"))
    if choice != preset:
        raise RuntimeError(f"Accent preset mismatch in {source.name}: {choice!r} != {preset!r}")
    # Assert the semantic clock text, not just that font sizes changed.
    clock_text = str(view.rootObject().property("currentTime"))
    expected_time = "3:42 PM" if use12 else "15:42"
    if clock_text != expected_time:
        raise RuntimeError(f"Wrong {('12h' if use12 else '24h')} clock text in {source.name}: "
                           f"{clock_text!r} != {expected_time!r}")
    view.show()
    QTest.qWait(450)
    app.processEvents()
    raw = view.grabWindow()
    if raw.isNull():
        QTest.qWait(450)
        raw = view.grabWindow()
    if raw.isNull() or raw.width() != size or raw.height() != size:
        raise RuntimeError(f"Qt did not capture the {size}x{size} QML window for {source.name}")
    if errors:
        raise RuntimeError(f"QML warning/error in {source.name}: {'; '.join(errors)}")
    measure = _measure(raw)
    # Exercise the real active Qt MouseArea. Never mutate the physical watch.
    if size == 360 and not ambient and not nightstand and not use12 and preset == "original":
        root = view.rootObject()
        target_name = ("uglyos-solo-quest-card" if source.name.startswith("903")
                       else "uglyos-solo-mood-card" if source.name.startswith("904")
                       else None)
        if target_name:
            card = root.findChild(QObject, target_name)
            if card is None:
                raise RuntimeError(f"Missing real solo touch control in {source.name}")
            scene = card.mapToScene(QPointF(card.width() / 2, card.height() / 2))
            click = QPoint(round(scene.x()), round(scene.y()))
            QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier, click)
            app.processEvents()
            if source.name.startswith("903") and root.property("questCompleted") != 1:
                raise RuntimeError("Solo Arcade tap failed to advance offline challenge")
            if source.name.startswith("904") and root.property("currentMood") != "FOCUS":
                raise RuntimeError("Solo Lounge tap failed to cycle local mood")
    expected_offset = size * .16
    if abs(burnin.widthOffset - expected_offset) > 1.5 or abs(burnin.heightOffset - expected_offset) > 1.5:
        raise RuntimeError(f"Burn-in offset invalid for {source.name}: {burnin.widthOffset}, {burnin.heightOffset}")
    view.close()
    view.deleteLater()
    app.processEvents()
    return _round_preview(raw), measure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    faces = tuple(sorted(path.name for path in FACES.glob("*.qml")))
    if faces != EXPECTED:
        raise RuntimeError(f"Unexpected R08 watch face list: {faces}")
    if not (STUBS / "Nemo/Mce/qmldir").is_file():
        raise RuntimeError("Mock Nemo.Mce module missing")
    if not (STUBS / "Nemo/Configuration/qmldir").is_file():
        raise RuntimeError("Mock Nemo.Configuration module missing")
    QLocale.setDefault(QLocale(QLocale.English, QLocale.UnitedStates))
    app = QGuiApplication.instance() or QGuiApplication(["uglyos-host-renderer"])
    report = {"renderer": "PySide6 host Qt Quick software, off-device",
              "runtime_data": "MOCK clock, battery, accent config, 12h preference, ambient, burn-in offsets",
              "fixed_time": "2026-10-25T15:42:00",
              "not_verified": ["AsteroidOS Qt 6.11 target imports", "Watch3 framebuffer",
                               "hardware AOD", "watch boot", "flashing"],
              "images": []}
    image_bytes: dict[tuple[str, str], bytes] = {}
    for name in EXPECTED:
        for mode, size, use12, ambient, nightstand in CASES:
            preset = mode.removeprefix("palette-") if mode.startswith("palette-") else "original"
            preview, measure = _render_one(app, FACES / name, size, use12, ambient, nightstand, preset)
            target = args.output / (name.removesuffix(".qml") + "--" + mode + ".png")
            if not preview.save(str(target), "PNG"):
                raise RuntimeError(f"Cannot save PNG preview: {target}")
            data = target.read_bytes()
            if len(data) < 1800:
                raise RuntimeError(f"Suspiciously small PNG: {target.name}")
            image_bytes[(name, mode)] = data
            report["images"].append({"file": target.name, "size": size,
                                     "mode": mode, "palette": preset,
                                     "sha256": hashlib.sha256(data).hexdigest(),
                                     **measure})
            print(f"PASS[host-qt]: {target.name} ({measure['highlight_samples']} highlight samples)")
    for name in EXPECTED:
        if image_bytes[(name, "active-24h")] == image_bytes[(name, "ambient")]:
            raise RuntimeError(f"Ambient does not change rendering: {name}")
        if image_bytes[(name, "active-24h")] == image_bytes[(name, "active-12h")]:
            raise RuntimeError(f"12/24h setting does not change rendering: {name}")
        palette_modes = ["active-24h", "palette-emerald", "palette-ice",
                         "palette-violet", "palette-ember", "palette-rose"]
        if len({image_bytes[(name, mode)] for mode in palette_modes}) != len(palette_modes):
            raise RuntimeError(f"Accent palettes do not produce distinct renders: {name}")
    (args.output / "render-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS[host-qt]: 50 real QML previews: 5 modes and 5 distinct accent palettes per face")
    print("NOT TESTED: Watch3 firmware, target QML modules, physical screen, AOD or boot")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL[host-qt]: {exc}", file=sys.stderr)
        raise SystemExit(1)
