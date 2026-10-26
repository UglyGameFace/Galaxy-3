#!/usr/bin/env python3
"""Generate deterministic, read-only native AsteroidOS catalog from validated data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from build_uglyos_app_hub import CatalogError, load

FIELDS = ("id", "name", "category", "kind", "platform",
          "state", "summary", "installable")


def make_catalog(source: Path) -> str:
    catalog = load(source)
    entries = [{key: entry[key] for key in FIELDS} for entry in catalog["entries"]]
    if any(entry["installable"] is not False for entry in entries):
        raise CatalogError("Watch catalog cannot enable installations")
    data = json.dumps(entries, ensure_ascii=True, indent=2)
    return ("// SPDX-License-Identifier: MIT\n"
            "// Auto-derived from reviewed app-hub/catalog.json by tools/generate_uglyos_watch_catalog.py\n"
            "// Offline-only static compatibility data. No downloads or install action.\n"
            + "var entries = " + data + ";\n")


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--catalog", type=Path, default=Path("app-hub/catalog.json"))
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--verify", action="store_true",
                     help="Only compare against committed immutable generated data")
    args = cli.parse_args()
    try:
        rendered = make_catalog(args.catalog)
        if args.output.is_symlink():
            raise CatalogError("Refuse symlinked watch catalog")
        if args.verify:
            if args.output.read_text() != rendered:
                raise CatalogError("Committed watch catalog differs from validated source")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered)
    except (CatalogError, OSError, UnicodeError) as exc:
        print("FAIL[watch-app-hub]: " + str(exc), file=sys.stderr)
        return 1
    print("PASS[watch-app-hub]: deterministic native-compatible offline catalog")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
