#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

PAGE_SIZE_WITH_SPARE = 0x210  # 512 + 16 = 528
LOGICAL_PAGE_SIZE = 0x200     # 512


def strip_spare_data(input_data: bytes) -> bytes:
    """Strip 16 bytes spare from each 528-byte page."""
    if len(input_data) % PAGE_SIZE_WITH_SPARE != 0:
        raise ValueError(
            f"Input size {len(input_data)} is not a multiple of {PAGE_SIZE_WITH_SPARE} "
            f"(512+16). The file may not be in per-page spare format."
        )

    output = bytearray()
    for offset in range(0, len(input_data), PAGE_SIZE_WITH_SPARE):
        page_data = input_data[offset:offset + LOGICAL_PAGE_SIZE]
        output.extend(page_data)

    return bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Strip 16 bytes spare data from each 528-byte page (512+16) "
                    "to produce a logical 512-byte-per-page image."
    )
    parser.add_argument("input", help="Input binary file (528-byte pages)")
    parser.add_argument("-o", "--output", help="Output file path (default: input.stripped.bin)")
    args = parser.parse_args()

    input_path = Path(args.input)
    input_data = input_path.read_bytes()

    output_data = strip_spare_data(input_data)

    output_path = Path(args.output) if args.output else Path(str(input_path) + ".stripped.bin")
    output_path.write_bytes(output_data)

    input_pages = len(input_data) // PAGE_SIZE_WITH_SPARE
    output_pages = len(output_data) // LOGICAL_PAGE_SIZE
    print(f"Input:  {input_path} ({len(input_data):,} bytes, {input_pages:,} pages)")
    print(f"Output: {output_path} ({len(output_data):,} bytes, {output_pages:,} pages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
