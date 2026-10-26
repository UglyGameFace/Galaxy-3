#!/usr/bin/env python3
"""Off-device actual Qt6 BezelPage UI rendering with a local Nemo mock."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QUICK_BACKEND", "software")
os.environ.setdefault("QT_OPENGL", "software")

from PySide6.QtCore import QPoint, QPointF, Qt, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQuick import QQuickView
from PySide6.QtTest import QTest

PAGE = (Path(__file__).resolve().parents[1] /
        "meta-noblesse/recipes-asteroid/uglyos-bezel-lab/uglyos-bezel-lab/BezelPage.qml")


def visual(root, name):
    queue = [root]
    for _ in range(1400):
        if not queue:
            break
        node = queue.pop()
        if node.objectName() == name:
            return node
        if hasattr(node, "childItems"):
            queue.extend(node.childItems())
    raise RuntimeError("Missing Qt visual control: " + name)


def click(view, name):
    node = visual(view.rootObject(), name)
    center = node.mapToScene(QPointF(node.width()/2, node.height()/2))
    QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier,
                     QPoint(round(center.x()), round(center.y())))
    QTest.qWait(60)
    QGuiApplication.processEvents()


def displayed(root):
    return visual(root, "uglyos-bezel-selection").property("text")


def lit_pixels(frame):
    if frame.isNull():
        raise RuntimeError("No rendered screenshot")
    lit = 0
    for y in range(0, frame.height(), 4):
        for x in range(0, frame.width(), 4):
            if (x-frame.width()/2)**2+(y-frame.height()/2)**2 > (frame.width()*.48)**2:
                continue
            color = frame.pixelColor(x, y)
            if max(color.red(), color.green(), color.blue()) > 100:
                lit += 1
    if lit < 25:
        raise RuntimeError("Bezel UI not visible; lit pixels=" + str(lit))
    return lit


def run(output):
    output.mkdir(parents=True, exist_ok=True)
    app = QGuiApplication.instance() or QGuiApplication(["bezel-lab-host"])
    screenshots = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)/"Nemo"/"Configuration"
        path.mkdir(parents=True)
        (path/"qmldir").write_text(
            "module Nemo.Configuration\nConfigurationValue 1.0 ConfigurationValue.qml\n")
        (path/"ConfigurationValue.qml").write_text(
            "import QtQml\nQtObject {\n"
            " property string key: \"\"\n"
            " property var defaultValue: undefined\n"
            " property var value: defaultValue\n}\n")
        for size in (360, 240):
            errors = []
            view = QQuickView()
            view.engine().addImportPath(tmp)
            view.engine().warnings.connect(
                lambda messages: errors.extend(str(x.toString()) for x in messages))
            view.setResizeMode(QQuickView.SizeRootObjectToView)
            view.resize(size, size)
            view.setSource(QUrl.fromLocalFile(str(PAGE)))
            if view.status() != QQuickView.Ready:
                raise RuntimeError("Actual BezelPage QML failed: " + str(view.errors()))
            view.show()
            QTest.qWait(160)
            root = view.rootObject()
            if displayed(root) != "RING":
                raise RuntimeError("Initial ring not rendered: " + str(displayed(root)))
            click(view, "uglyos-bezel-action-2")
            if displayed(root) != "PRECISION":
                raise RuntimeError("Clockwise did not move ring: " + str(displayed(root)))
            click(view, "uglyos-bezel-action-1")
            if "50" not in displayed(root):
                raise RuntimeError("Selecting dial failed: " + str(displayed(root)))
            click(view, "uglyos-bezel-action-2")
            if "50" in displayed(root):
                raise RuntimeError("Precision dial did not react: " + str(displayed(root)))
            image = view.grabWindow()
            lit = lit_pixels(image)
            outfile = output / ("bezel-precision-%d.png" % size)
            if not image.save(str(outfile), "PNG"):
                raise RuntimeError("Cannot save image proof")
            screenshots.append({"size":size, "mode":"precision",
                                "lit":lit, "bytes":outfile.stat().st_size})
            click(view, "uglyos-bezel-action-3")
            if displayed(root) != "PRECISION":
                # Back exits dial, returning to last highlighted ring position.
                raise RuntimeError("Back did not return to ring selection")
            click(view, "uglyos-bezel-secondary-0")
            image = view.grabWindow()
            lit = lit_pixels(image)
            outfile = output / ("bezel-ring-%d.png" % size)
            if not image.save(str(outfile), "PNG"):
                raise RuntimeError("Cannot save ring image proof")
            screenshots.append({"size":size, "mode":"ring",
                                "lit":lit, "bytes":outfile.stat().st_size})
            if errors:
                raise RuntimeError("Qt runtime warnings: " + "; ".join(errors))
            view.close()
            view.deleteLater()
            app.processEvents()
    proof = {
        "kind": "OFFDEVICE-QT-MOCK-NOT-WATCH-BOOT",
        "screenshots": screenshots,
        "physical_wheel_verified": False,
        "phone_transport_verified": False
    }
    (output/"proof.json").write_text(json.dumps(proof, indent=2)+"\n")
    print("PASS[bezel-qt]: 360px/240px actual QML rendered; touch detents, select, dial, back")
    print("NOT TESTED: real Watch3 bezel, keys, input backend, Android, boot or flash")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        run(args.output)
    except Exception as exc:
        print("FAIL[bezel-qt]: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
