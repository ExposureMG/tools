#!/usr/bin/env python3

from __future__ import annotations

import argparse
import struct
from pathlib import Path


SIZE_OFFSET = 0x0C
SIZE_LENGTH = 4


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Set the NAND header size field (offset 0x0C) to 0."
    )
    parser.add_argument("image", help="Input NAND image path")
    parser.add_argument(
        "-o",
        "--output",
        help="Write the patched image to this path instead of modifying the input in place",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create a .bak file when modifying the input in place",
    )
    return parser.parse_args()


def read_be32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def main() -> int:
    args = parse_args()
    input_path = Path(args.image)

    data = bytearray(input_path.read_bytes())
    if len(data) < SIZE_OFFSET + SIZE_LENGTH:
        raise ValueError(
            f"File is too small to contain the size field at 0x{SIZE_OFFSET:X}"
        )

    old_value = read_be32(data, SIZE_OFFSET)
    struct.pack_into(">I", data, SIZE_OFFSET, 0)

    if args.output:
        output_path = Path(args.output)
        output_path.write_bytes(data)
        print(f"Wrote patched image: {output_path}")
    else:
        if not args.no_backup:
            backup_path = input_path.with_suffix(input_path.suffix + ".bak")
            backup_path.write_bytes(input_path.read_bytes())
            print(f"Created backup: {backup_path}")
        input_path.write_bytes(data)
        print(f"Patched image in place: {input_path}")

    print(f"Old size value: 0x{old_value:08X}")
    print("New size value: 0x00000000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
