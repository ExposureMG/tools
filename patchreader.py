#!/usr/bin/env python3
"""
patchreader.py - Xbox 360 Patch Binary Parser

Reads big-endian patch binaries (xeBuild / gxbuild3 style), detects or parses
the target console mode ([GLITCH] vs [JTAG]), and outputs a formatted text file.

Usage:
  python3 patchreader.py <patchfile.bin> [-o output.txt] [--type {auto,glitch,jtag}]
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

DELIMITER = 0xFFFFFFFF


def read_be32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise ValueError("Unexpected end of data while reading 32-bit int")
    val = struct.unpack_from(">I", data, offset)[0]
    return val, offset + 4


def split_raw_sections(data: bytes) -> list[bytes]:
    sections: list[bytes] = []
    cursor = 0
    start = 0
    while cursor + 4 <= len(data):
        val, next_cursor = read_be32(data, cursor)
        if val == DELIMITER:
            sections.append(data[start:cursor])
            cursor = next_cursor
            start = cursor
            continue
        cursor += 4
    if start < len(data):
        sections.append(data[start:])
    return [s for s in sections if len(s) > 0]


def parse_xepatch_entries(sec_data: bytes) -> tuple[list[tuple[int, list[int]]], bytes]:
    """
    Parse (address, words) entries from XePatch binary format.
    Returns (entries, remaining_raw_bytes).
    """
    entries: list[tuple[int, list[int]]] = []
    cursor = 0
    while cursor + 8 <= len(sec_data):
        addr, next_cursor = read_be32(sec_data, cursor)
        if addr == DELIMITER:
            cursor = next_cursor
            break

        length, next_cursor = read_be32(sec_data, next_cursor)
        cursor = next_cursor

        words_byte_len = length * 4
        if cursor + words_byte_len > len(sec_data):
            cursor -= 8
            break

        words: list[int] = []
        for _ in range(length):
            w, cursor = read_be32(sec_data, cursor)
            words.append(w)

        entries.append((addr, words))

    remaining = sec_data[cursor:]
    return entries, remaining


def format_words(words: list[int], words_per_line: int = 8) -> str:
    lines = []
    for i in range(0, len(words), words_per_line):
        chunk = words[i : i + words_per_line]
        line = " ".join(f"{w:08X}" for w in chunk)
        lines.append(line)
    return "\n            ".join(lines)


def format_bytes_as_words(raw: bytes, words_per_line: int = 8) -> str:
    words = []
    for i in range(0, len(raw) - (len(raw) % 4), 4):
        w = struct.unpack_from(">I", raw, i)[0]
        words.append(w)
    return format_words(words, words_per_line)


def detect_target_type(raw_sections: list[bytes], type_arg: str) -> str:
    if type_arg.lower() in ("glitch", "g", "rgh"):
        return "GLITCH"
    if type_arg.lower() in ("jtag", "j"):
        return "JTAG"

    if len(raw_sections) >= 4:
        return "JTAG"
    return "GLITCH"


def parse_patch_file(file_path: Path, target_type_override: str = "auto") -> str:
    data = file_path.read_bytes()
    raw_sections = split_raw_sections(data)
    target_type = detect_target_type(raw_sections, target_type_override)

    if target_type == "JTAG":
        section_names = ["1bl", "cb", "cd", "khv"]
    else:
        section_names = ["cbb", "cd", "khv"]

    lines: list[str] = [f"[{target_type}]", ""]

    for idx, sec_data in enumerate(raw_sections):
        if not sec_data and idx >= len(section_names):
            continue

        sec_name = section_names[idx] if idx < len(section_names) else f"section_{idx + 1}"
        lines.append(f"{sec_name}:")

        if not sec_data:
            lines.append("    (empty)")
            lines.append("")
            continue

        entries, remaining_raw = parse_xepatch_entries(sec_data)

        if entries:
            for addr, words in entries:
                lines.append(f"    0x{addr:08X}:")
                lines.append(f"        {format_words(words)}")
        
        if remaining_raw and any(b != 0 for b in remaining_raw):
            offset = len(sec_data) - len(remaining_raw)
            lines.append(f"    0x{offset:08X} (raw):")
            lines.append(f"        {format_bytes_as_words(remaining_raw)}")

        if not entries and (not remaining_raw or all(b == 0 for b in remaining_raw)):
            lines.append("    (empty)")

        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Xbox 360 Patch Binary Parser")
    parser.add_argument("patchfile", type=Path, help="Path to big-endian patch binary file (.bin / rglp)")
    parser.add_argument("-o", "--output", type=Path, help="Path to output text file (default: stdout)")
    parser.add_argument(
        "-t",
        "--type",
        choices=["auto", "glitch", "jtag"],
        default="auto",
        help="Target patch type (default: auto)",
    )

    args = parser.parse_args()

    if not args.patchfile.exists():
        print(f"Error: file not found: {args.patchfile}", file=sys.stderr)
        sys.exit(1)

    result_text = parse_patch_file(args.patchfile, args.type)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result_text, encoding="utf-8")
        print(f"Parsed patch written to: {args.output}")
    else:
        print(result_text)


if __name__ == "__main__":
    main()
