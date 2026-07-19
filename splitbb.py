#!/usr/bin/env python3
"""
Split Big Block (BB) NAND format into Small Block (SB) format.

BB format: 2048 bytes data + 64 bytes spare = 2112 bytes per page
SB format: 512 bytes data + 16 bytes spare = 528 bytes per page

Each BB page is split into 4 SB pages:
- Data: 2048 bytes -> 4 x 512 bytes
- Spare: 64 bytes -> 4 x 16 bytes

Usage:
    python3 splitbb.py input_bb.bin -o output_sb.bin
"""

from __future__ import annotations

import argparse
from pathlib import Path

# Big Block format
BB_PAGE_SIZE = 0x800      # 2048 bytes
BB_SPARE_SIZE = 0x40     # 64 bytes
BB_TOTAL_SIZE = 0x840    # 2112 bytes (2048 + 64)

# Small Block format
SB_PAGE_SIZE = 0x200     # 512 bytes
SB_SPARE_SIZE = 0x10     # 16 bytes
SB_TOTAL_SIZE = 0x210    # 528 bytes (512 + 16)

# Number of SB pages per BB page
SB_PER_BB = 4


def split_bb_to_sb(bb_data: bytes) -> bytes:
    """
    Convert Big Block NAND format to Small Block format.
    
    Each 2112-byte BB page becomes 4 x 528-byte SB pages.
    """
    if len(bb_data) % BB_TOTAL_SIZE != 0:
        raise ValueError(
            f"Input size {len(bb_data):,} is not a multiple of {BB_TOTAL_SIZE} "
            f"(2048+64). The file may not be in BB format."
        )
    
    num_bb_pages = len(bb_data) // BB_TOTAL_SIZE
    num_sb_pages = num_bb_pages * SB_PER_BB
    
    output = bytearray(num_sb_pages * SB_TOTAL_SIZE)
    
    for bb_page_idx in range(num_bb_pages):
        # Calculate offset of this BB page
        bb_offset = bb_page_idx * BB_TOTAL_SIZE
        
        # Extract data (2048 bytes) and spare (64 bytes)
        bb_data_start = bb_offset
        bb_data_end = bb_data_start + BB_PAGE_SIZE
        bb_spare_start = bb_data_end
        bb_spare_end = bb_spare_start + BB_SPARE_SIZE
        
        page_data = bb_data[bb_data_start:bb_data_end]
        page_spare = bb_data[bb_spare_start:bb_spare_end]
        
        # Split into 4 SB pages
        for sb_idx in range(SB_PER_BB):
            # Calculate SB page position
            sb_page_num = bb_page_idx * SB_PER_BB + sb_idx
            sb_offset = sb_page_num * SB_TOTAL_SIZE
            
            # Split data: 512 bytes per SB page
            sb_data_start = sb_idx * SB_PAGE_SIZE
            sb_data_end = sb_data_start + SB_PAGE_SIZE
            sb_data = page_data[sb_data_start:sb_data_end]
            
            # Split spare: 16 bytes per SB page
            sb_spare_start = sb_idx * SB_SPARE_SIZE
            sb_spare_end = sb_spare_start + SB_SPARE_SIZE
            sb_spare = page_spare[sb_spare_start:sb_spare_end]
            
            # Write SB page to output
            output[sb_offset:sb_offset + SB_PAGE_SIZE] = sb_data
            output[sb_offset + SB_PAGE_SIZE:sb_offset + SB_TOTAL_SIZE] = sb_spare
    
    return bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Split Big Block NAND format (2048+64) into Small Block format (4x 512+16)."
    )
    parser.add_argument("input", help="Input binary file in BB format (2048+64 bytes per page)")
    parser.add_argument("-o", "--output", 
                        help="Output file path (default: input.split_sb.bin)")
    args = parser.parse_args()
    
    input_path = Path(args.input)
    input_data = input_path.read_bytes()
    
    # Validate input
    if len(input_data) % BB_TOTAL_SIZE != 0:
        print(f"Error: Input size {len(input_data):,} is not a multiple of {BB_TOTAL_SIZE} (2048+64)")
        print("       The file may not be in Big Block format.")
        return 1
    
    output_data = split_bb_to_sb(input_data)
    
    output_path = Path(args.output) if args.output else Path(str(input_path) + ".split_sb.bin")
    output_path.write_bytes(output_data)
    
    input_pages = len(input_data) // BB_TOTAL_SIZE
    output_pages = len(output_data) // SB_TOTAL_SIZE
    
    print(f"Input:  {input_path} ({len(input_data):,} bytes, {input_pages:,} BB pages)")
    print(f"Output: {output_path} ({len(output_data):,} bytes, {output_pages:,} SB pages)")
    print(f"        (Each BB page split into {SB_PER_BB} SB pages)")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
