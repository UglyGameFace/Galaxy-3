#!/usr/bin/env python3
"""Render and exercise actual offline UgLy|OS native HubPage on host Qt6."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QUICK_BACKEND", "software")

from PySide6.QtCore import QObject, QPoint, QPointF, Qt, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQuick import QQuickView
from PySide6.QtTest import QTest

PAGE = (Path(__file__).resolve().parents[1] /
        "meta-noblesse/recipes-asteroid/uglyos-app-hub/uglyos-app-hub/HubPage.qml")
TARGETS = ("ALL", "WATCH", "PHONE", "LIMITS")


def click(view: QQuickView, name: str):
    root = view.rootObject()
    node = root.findChild(QObject, name)
    if node is None:
        raise RuntimeError("Missing real Qt interaction control: " + name)
    center = node.mapToScene(QPointF(node.width()/2, node.height()/2))
    QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier,
                     QPoint(round(center.x()), round(center.y())))
    QTest.qWait(80)
    QGuiApplication.processEvents()


def check_pixels(frame):
    if frame.isNull():
        raise RuntimeError("Empty Qt rendering")
    lit=0
    for y in range(0, frame.height(), 4):
        for x in range(0, frame.width(), 4):
            if (x-frame.width()/2)**2+(y-frame.height()/2)**2 > (frame.width()*.48)**2:
                continue
            c=frame.pixelColor(x,y)
            if max(c.red(), c.green(), c.blue()) > 105:
                lit+=1
    if lit < 35:
        raise RuntimeError("Blank or illegible watch hub: " + str(lit))
    return lit


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    app=QGuiApplication.instance() or QGuiApplication(["uglyos-hub-host"])
    proofs=[]
    for size in (360, 240):
        warning=[]
        view=QQuickView()
        view.engine().warnings.connect(
            lambda messages: warning.extend(str(m.toString()) for m in messages))
        view.setResizeMode(QQuickView.SizeRootObjectToView)
        view.resize(size,size)
        view.setSource(QUrl.fromLocalFile(str(PAGE)))
        if view.status()!=QQuickView.Ready:
            raise RuntimeError("Native HubPage QML failed to load: "+str(view.errors()))
        view.show()
        QTest.qWait(220)
        for index,title in enumerate(TARGETS):
            if view.rootObject().property("groupIndex") != index:
                raise RuntimeError("Filter navigation does not match "+title)
            pic=view.grabWindow()
            lit=check_pixels(pic)
            output=args.output/("hub-%s-%d.png"%(title.lower(),size))
            if not pic.save(str(output), "PNG"):
                raise RuntimeError("Screenshot save failed")
            proofs.append({"screen":size,"filter":title,"lit":lit,"bytes":output.stat().st_size})
            if index == 0 and size == 360:
                click(view, "uglyos-hub-card-0")
                if not view.rootObject().property("detailsOpen"):
                    raise RuntimeError("Tapping app card failed to open detail sheet")
                back=view.rootObject().findChild(QObject,"uglyos-hub-close")
                if back is None:
                    raise RuntimeError("Missing back control")
                pos=back.mapToScene(QPointF(back.width()/2,back.height()/2))
                QTest.mouseClick(view,Qt.LeftButton,Qt.NoModifier,
                    QPoint(round(pos.x()),round(pos.y())))
                QTest.qWait(80)
                if view.rootObject().property("detailsOpen"):
                    raise RuntimeError("Back failed to dismiss detail sheet")
            if index < 3:
                click(view, "uglyos-hub-next-filter")
        if warning:
            raise RuntimeError("Runtime QML warnings: " + "; ".join(warning))
        view.close()
        view.deleteLater()
        app.processEvents()
    (args.output/"proof.json").write_text(json.dumps({
        "kind":"OFFDEVICE-QT-MOCK-NOT-WATCH-BOOT",
        "screenshots":proofs,"installs_allowed":False},indent=2)+"\n")
    print("PASS[hub-qt]: 8 actual QML rendered filters at 360/240, detail card/back tested")
    print("NO WATCH ACCESS, NO APPS INSTALLED")
    return 0


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("FAIL[hub-qt]: "+str(exc),file=sys.stderr)
        raise SystemExit(1)
