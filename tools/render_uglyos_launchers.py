#!/usr/bin/env python3
"""Host Qt test: render real UgLy|OS launcher QML with fake installed apps.

Mocks are intentionally scoped to this test; nothing touches the actual watch.
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

from PySide6.QtCore import (QAbstractListModel, QModelIndex, QObject, Property,
                             QPoint, Qt, Slot, QUrl)
from PySide6.QtGui import QGuiApplication, QImage, QPainter, QPainterPath
from PySide6.QtQuick import QQuickView
from PySide6.QtTest import QTest

ROOT = Path(__file__).resolve().parents[1]
FACES_FIXTURES = ROOT / "tools/uglyos-render-fixtures"
FIXTURES = ROOT / "tools/uglyos-launcher-fixtures"
LAYOUTS = ROOT / "meta-noblesse/recipes-asteroid/uglyos-launchers/uglyos-launchers"
EXPECTED = ("900-uglyos-fast-list.qml", "901-uglyos-compact-grid.qml",
            "902-uglyos-stoner-lounge.qml", "903-uglyos-gamer-arcade.qml")
CASES = (("original-360", 360, "original", "subtle"),
         ("rose-360", 360, "rose", "subtle"),
         ("compact-240", 240, "original", "subtle"),
         ("effects-off-360", 360, "original", "off"))


class AppItem(QObject):
    def __init__(self, title: str, icon: str):
        super().__init__()
        self._title, self._icon = title, icon
        self.activations = 0

    @Property(str, constant=True)
    def title(self) -> str:
        return self._title

    @Property(str, constant=True)
    def iconId(self) -> str:
        return self._icon

    @Slot()
    def launchApplication(self):
        self.activations += 1


class AppModel(QAbstractListModel):
    ObjectRole = int(Qt.UserRole) + 1

    def __init__(self):
        super().__init__()
        self.items = [AppItem(n, i) for n, i in (
            ("Agenda", "ios-calendar-outline"),
            ("Alarm Clock", "ios-alarm-outline"),
            ("Calculator", "ios-calculator-outline"),
            ("Music", "ios-musical-notes-outline"),
            ("Settings", "ios-settings-outline"),
            ("Stopwatch", "ios-stopwatch-outline"),
            ("Timer", "ios-timer-outline"),
            ("Weather", "ios-cloudy-outline"),
            ("Notes", "ios-document-text-outline"),
            ("Utilities", "ios-apps-outline"),
        )]

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.items)

    def data(self, index: QModelIndex, role: int):
        if not index.isValid() or index.row() >= len(self.items):
            return None
        return self.items[index.row()] if role == self.ObjectRole else None

    def roleNames(self) -> dict[int, bytes]:
        return {self.ObjectRole: b"object"}


class FakeGrid(QObject):
    @Property(int, constant=True)
    def currentVerticalPos(self) -> int:
        return 0

    @Property(int, constant=True)
    def currentHorizontalPos(self) -> int:
        return 0

    @Slot()
    def changeAllowedDirections(self):
        return None


class FakeLocale(QObject):
    @Property(str, constant=True)
    def changesObserver(self) -> str:
        return ""


def circular(image: QImage) -> QImage:
    size = image.width()
    result = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    result.fill(Qt.transparent)
    painter = QPainter(result)
    painter.setRenderHint(QPainter.Antialiasing, True)
    path = QPainterPath()
    path.addEllipse(1, 1, size - 2, size - 2)
    painter.setClipPath(path)
    painter.drawImage(0, 0, image)
    painter.end()
    return result


def verify_pixels(image: QImage) -> int:
    width = image.width()
    lit = 0
    for y in range(0, width, 4):
        for x in range(0, width, 4):
            if (x - width / 2) ** 2 + (y - width / 2) ** 2 > (width * .46) ** 2:
                continue
            c = image.pixelColor(x, y)
            if max(c.red(), c.green(), c.blue()) > 105:
                lit += 1
    if lit < 45:
        raise RuntimeError(f"Empty or unreadable launcher render: {lit} lit pixels")
    return lit


def render(app: QGuiApplication, qml: Path, size: int, palette: str, effects: str):
    model = AppModel()
    grid = FakeGrid()
    locale = FakeLocale()
    warnings = []
    view = QQuickView()
    view.engine().addImportPath(str(FACES_FIXTURES))
    view.engine().addImportPath(str(FIXTURES))
    view.engine().warnings.connect(
        lambda errs: warnings.extend(str(e.toString()) for e in errs))
    context = view.rootContext()
    context.setContextProperty("launcherModel", model)
    context.setContextProperty("grid", grid)
    context.setContextProperty("localeManager", locale)
    context.setContextProperty("mockAccentPreset", palette)
    context.setContextProperty("mockEffectsPreset", effects)
    # Runtime integration uses these existing ancestor properties in MainScreen.qml.
    for name in ("forbidTop", "forbidBottom", "forbidLeft", "forbidRight",
                 "toTopAllowed", "toBottomAllowed", "toLeftAllowed",
                 "toRightAllowed", "launcherColorOverride"):
        context.setContextProperty(name, False)
    view.setResizeMode(QQuickView.SizeRootObjectToView)
    view.resize(size, size)
    view.setSource(QUrl.fromLocalFile(str(qml.resolve())))
    if view.status() != QQuickView.Ready:
        raise RuntimeError(f"Cannot load {qml.name}: {view.errors()}")
    if qml.name.startswith(("902", "903")):
        effective = bool(view.rootObject().property("effectsEnabled"))
        if effective != (effects == "subtle"):
            raise RuntimeError(f"Touch motion setting ignored in {qml.name}: {effective}")
    view.show()
    QTest.qWait(400)
    app.processEvents()
    img = view.grabWindow()
    if img.isNull():
        QTest.qWait(350)
        img = view.grabWindow()
    if img.isNull() or img.width() != size:
        raise RuntimeError(f"Cannot capture {qml.name} at {size}px")
    if warnings:
        raise RuntimeError(f"Qt warnings from {qml.name}: {warnings}")
    lit = verify_pixels(img)
    # Confirm this layout is actually actionable: first app dispatches through
    # the unmodified launcherModel object's launchApplication method.
    point = QPoint(size // 2 if qml.name.startswith(("900", "902")) else size // 4,
                   int(size * 0.24))
    QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier, point)
    app.processEvents()
    if model.items[0].activations != 1:
        raise RuntimeError(f"First app activation missing in {qml.name}: {model.items[0].activations}")
    view.close()
    view.deleteLater()
    app.processEvents()
    return circular(img), lit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    found = tuple(sorted(p.name for p in LAYOUTS.glob("*.qml")))
    if found != EXPECTED:
        raise RuntimeError(f"Unexpected set of launcher layouts: {found}")
    qt = QGuiApplication.instance() or QGuiApplication(["uglyos-launcher-host-test"])
    previews = []
    by_name = {}
    for qml in EXPECTED:
        for case, size, palette, effects in CASES:
            rendered, lit = render(qt, LAYOUTS / qml, size, palette, effects)
            name = f"{qml.removesuffix('.qml')}--{case}.png"
            dest = args.output / name
            if not rendered.save(str(dest), "PNG"):
                raise RuntimeError(f"Failed to save {name}")
            data = dest.read_bytes()
            if len(data) < 1500:
                raise RuntimeError(f"Suspiciously tiny visual evidence: {name}")
            by_name[(qml, case)] = data
            previews.append({"file": name, "size": size, "palette": palette, "effects": effects,
                             "lit_samples": lit,
                             "sha256": hashlib.sha256(data).hexdigest()})
            print(f"PASS[launcher-qt]: {name}: {lit} lit samples; click dispatched")
    for qml in EXPECTED:
        if qml.startswith(("900", "901")) and by_name[(qml, "original-360")] == by_name[(qml, "rose-360")]:
            raise RuntimeError(f"Accent setting ignored by QML: {qml}")
        if qml.startswith(("902", "903")) and by_name[(qml, "original-360")] != by_name[(qml, "effects-off-360")]:
            raise RuntimeError(f"Idle appearance should be identical with touch effects off: {qml}")
    report = {"source": "REAL QML plus MOCK app model and icon module",
              "safety": "OFF-DEVICE ONLY: no real launcher backend, watch boot or install",
              "previews": previews}
    (args.output / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS[launcher-qt]: 16 previews, four lightweight app launchers and click dispatch")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL[launcher-qt]: {exc}", file=sys.stderr)
        raise SystemExit(1)
