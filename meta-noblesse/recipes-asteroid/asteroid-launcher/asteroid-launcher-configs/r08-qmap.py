#!/usr/bin/env python3
"""Generate the exact, deliberately restricted Watch3 R08 Qt evdev .qmap.

Based on the pinned Qt 6.11 QKeyboardMap format: QDataStream (big endian)
writes four quint32 fields followed by Mapping fields HHIBBH for each key.
This only supports the six real Noblesse Watch3 keys. Do not generalize it
to arbitrary Linux keymaps without implementing Qt's full symbol parser.

Why not simply call upstream kmap2qmap? AsteroidOS keys.kmap uses MenuKB and
Sleep, which are Qt::Key values but not present in QtTools 6.11 kmap2qmap's
symbol_map table. The upstream converter silently drops those four keys.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import struct

QMAP_MAGIC = 0x514D4150
QMAP_VERSION = 1

# Values from Qt 6.11 src/corelib/global/qnamespace.h (Qt::Key_*).
EXPECTED = {
    114: ("VolumeDown", 0x01000070),
    115: ("VolumeUp", 0x01000072),
    116: ("Sleep", 0x01020004),
    128: ("MenuKB", 0x010000DC),
    139: ("MenuKB", 0x010000DC),
    750: ("MenuKB", 0x010000DC),
}

LINE = re.compile(r"keycode\s+([0-9]+)\s*=\s*([A-Za-z][A-Za-z0-9_]*)\s*")


def convert(source: str) -> bytes:
    observed: dict[int, str] = {}
    for number, line in enumerate(source.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError(f"unsupported keys.kmap syntax on line {number}: {line}")
        code, symbol = int(match.group(1)), match.group(2)
        if code in observed:
            raise ValueError(f"duplicate keycode {code} on line {number}")
        observed[code] = symbol

    expected_symbols = {code: sym for code, (sym, _) in EXPECTED.items()}
    if observed != expected_symbols:
        missing = sorted(set(expected_symbols) - set(observed))
        extra = sorted(set(observed) - set(expected_symbols))
        incorrect = {code: (observed[code], expected_symbols[code])
                     for code in observed.keys() & expected_symbols.keys()
                     if observed[code] != expected_symbols[code]}
        raise ValueError(f"R08 keymap drift: missing={missing} extra={extra} wrong={incorrect}")

    # QDataStream default byte order is BigEndian. FileMagic, version,
    # keymap count, compose count, then QKeyboardMap::Mapping records.
    out = bytearray(struct.pack(">IIII", QMAP_MAGIC, QMAP_VERSION, len(EXPECTED), 0))
    for code in sorted(EXPECTED):
        _, qtkey = EXPECTED[code]
        # Mapping: quint16 keycode, quint16 unicode (0xffff = no text),
        # quint32 qtcode, quint8 modifiers, quint8 flags, quint16 special.
        out.extend(struct.pack(">HHIBBH", code, 0xFFFF, qtkey, 0, 0, 0))
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    payload = convert(args.source.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(f"PASS: R08 Qt qmap generated: {len(EXPECTED)} keys, {len(payload)} bytes")


if __name__ == "__main__":
    main()
