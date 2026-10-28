#!/usr/bin/env python3
"""Audit actual ARM64 guest's English fallback .qm before real QEMU screenshots.

Pinned AsteroidOS/asteroid-launcher@0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31
lipstick/src/localemanager.cpp uses:
  QTranslator::load("asteroid-launcher.en", "/usr/share/translations")
This ABSOLUTE application file path is not transparently rebased by
QEMU_LD_PREFIX (which selects the ELF interpreter and target libraries).
The off-device capture container therefore needs an explicit read-only bind
of the VERIFIED guest /usr/share/translations tree at that exact path.

Never manufacture a .qm, silently use host locales, or infer a rendered
translation from this file inventory. The saved 2026-10-24 rootfs is immutable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

EXPECTED_RELATIVE = Path("usr/share/translations/asteroid-launcher.en.qm")
# Qt's compiled QTranslator .qm file header (not a text XML .ts catalog).
QM_MAGIC = bytes.fromhex("3cb86418caef9c95cd211cbf60a1bddd")
MAX_QM_BYTES = 16_000_000


class LocaleAuditError(ValueError):
    pass


def inspect(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise LocaleAuditError("INVALID_EXTRACTED_GUEST_ROOT")
    root = root.resolve()
    folder = root / "usr/share/translations"
    if not folder.is_dir() or not folder.resolve().is_relative_to(root):
        raise LocaleAuditError("GUEST_QT_TRANSLATIONS_DIRECTORY_ABSENT_OR_UNSAFE")
    qm = folder / "asteroid-launcher.en.qm"
    if not qm.is_file() or not qm.resolve().is_relative_to(root):
        discovered = sorted(x.name for x in folder.glob("asteroid-launcher*.qm"))[:24]
        raise LocaleAuditError(
            "EXACT_GUEST_ENGLISH_FALLBACK_CATALOG_MISSING:" + ",".join(discovered))
    if qm.is_symlink():
        raise LocaleAuditError("ENGLISH_TRANSLATION_IS_SYMLINK")
    size = qm.stat().st_size
    if not len(QM_MAGIC) < size <= MAX_QM_BYTES:
        raise LocaleAuditError("GUEST_ENGLISH_QM_BAD_FILE_SIZE")
    with qm.open("rb") as stream:
        if stream.read(len(QM_MAGIC)) != QM_MAGIC:
            raise LocaleAuditError("GUEST_ENGLISH_QM_WRONG_MAGIC")
        digest = hashlib.sha256()
        stream.seek(0)
        for piece in iter(lambda: stream.read(1_048_576), b""):
            digest.update(piece)
    return {
        "schema": "uglyos-r08-exact-guest-english-translation-v1",
        "status": "ACTUAL_GUEST_COMPILED_ENGLISH_QM_VERIFIED",
        "installed_guest_catalog": "/usr/share/translations/asteroid-launcher.en.qm",
        "original_pinned_compositor_loader": (
            "AsteroidOS/asteroid-launcher@"
            "0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31:"
            "lipstick/src/localemanager.cpp"),
        "english_qm_bytes": size,
        "english_qm_sha256": digest.hexdigest(),
        "original_offdevice_vnc_capture_2026_10_28_uses_absolute_host_translation_dir": True,
        "safe_offdevice_correction": (
            "Bind extracted/usr/share/translations read-only at "
            "/usr/share/translations INSIDE the network-none container only"),
        "catalog_loaded_by_arm64_process_proven": False,
        "translated_pixels_proven": False,
        "watch_contacted": False,
        "guest_rootfs_modified": False,
        "flashable": False,
        "decision": "NO_GO",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extracted-rootfs", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        print("REFUSING_EXISTING_LOCALE_REPORT", file=sys.stderr)
        return 2
    try:
        evidence = inspect(args.extracted_rootfs)
    except (OSError, LocaleAuditError) as error:
        print("GUEST_ENGLISH_TRANSLATIONS_UNPROVEN:", str(error), file=sys.stderr)
        return 2
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(evidence, indent=2) + "\n")
    print("REAL_GUEST_ENGLISH_QM_PRESENT", evidence["english_qm_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
