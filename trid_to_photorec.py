#!/usr/bin/env python3
"""Convert TrID XML definitions to PhotoRec photorec.sig entries.

Usage:
  ./trid_to_photorec.py /path/to/triddefs_xml -o photorec.sig
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

_VALID_EXT_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _normalize_extensions(raw_ext: str) -> List[str]:
    """Split TrID extension strings like 'TRK/WPT' into valid PhotoRec ext tokens."""
    cleaned = raw_ext.strip().lower()
    if not cleaned:
        return []

    parts = re.split(r"[\s,;/|]+", cleaned)
    out: List[str] = []
    seen: Set[str] = set()
    for part in parts:
        part = part.strip().lstrip(".")
        if not part:
            continue
        if not _VALID_EXT_RE.match(part):
            continue
        if part not in seen:
            seen.add(part)
            out.append(part)
    return out


def _normalize_hex(raw_hex: str) -> str | None:
    """Return compact uppercase hex string if valid, otherwise None."""
    value = "".join(raw_hex.split()).upper()
    if not value or len(value) % 2 != 0:
        return None
    if not _HEX_RE.match(value):
        return None
    return value


def _iter_patterns(root: ET.Element) -> Iterable[Tuple[int, str]]:
    """Yield (offset, hex) for all fixed-byte patterns found in a TrID definition."""
    for pattern in root.findall(".//Pattern"):
        bytes_elem = pattern.find("Bytes")
        pos_elem = pattern.find("Pos")
        if bytes_elem is None or pos_elem is None:
            continue
        if bytes_elem.text is None or pos_elem.text is None:
            continue

        magic_hex = _normalize_hex(bytes_elem.text)
        if magic_hex is None:
            continue

        raw_pos = pos_elem.text.strip()
        try:
            # TrID Pos values are typically decimal; int(..., 0) also allows 0xNN.
            offset = int(raw_pos, 0)
        except ValueError:
            continue
        if offset < 0:
            continue

        yield offset, magic_hex


def convert_trid_to_photorec(xml_dir: Path) -> Tuple[List[str], Dict[str, int]]:
    stats = {
        "xml_seen": 0,
        "xml_parse_error": 0,
        "xml_no_ext": 0,
        "xml_no_pattern": 0,
        "sig_generated": 0,
        "sig_unique": 0,
    }

    lines: Set[str] = set()

    for xml_file in xml_dir.rglob("*.trid.xml"):
        stats["xml_seen"] += 1
        try:
            root = ET.parse(xml_file).getroot()
        except ET.ParseError:
            stats["xml_parse_error"] += 1
            continue

        ext_elem = root.find(".//Ext")
        exts = _normalize_extensions(ext_elem.text if ext_elem is not None and ext_elem.text else "")
        if not exts:
            stats["xml_no_ext"] += 1
            continue

        patterns = list(_iter_patterns(root))
        if not patterns:
            stats["xml_no_pattern"] += 1
            continue

        for ext in exts:
            for offset, magic_hex in patterns:
                lines.add(f"{ext} {offset} {magic_hex}")
                stats["sig_generated"] += 1

    sorted_lines = sorted(lines)
    stats["sig_unique"] = len(sorted_lines)
    return sorted_lines, stats


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert TrID XML definitions into PhotoRec photorec.sig signatures."
    )
    parser.add_argument(
        "xml_dir",
        type=Path,
        help="Directory containing *.trid.xml definitions (searched recursively).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("photorec.sig"),
        help="Output file path for generated signatures.",
    )
    return parser


def main(argv: List[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    xml_dir = args.xml_dir
    output = args.output

    if not xml_dir.exists() or not xml_dir.is_dir():
        parser.error(f"xml_dir does not exist or is not a directory: {xml_dir}")

    lines, stats = convert_trid_to_photorec(xml_dir)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="ascii", errors="strict")

    print(f"Scanned XML files:         {stats['xml_seen']}")
    print(f"XML parse errors:          {stats['xml_parse_error']}")
    print(f"No usable extension:       {stats['xml_no_ext']}")
    print(f"No fixed-byte patterns:    {stats['xml_no_pattern']}")
    print(f"Raw signatures generated:  {stats['sig_generated']}")
    print(f"Unique signatures written: {stats['sig_unique']}")
    print(f"Output: {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
