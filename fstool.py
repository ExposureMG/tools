#!/usr/bin/env python3
"""
fstool.py - Xbox 360 FlashFS Tool

Validate, inspect, and extract the Flash Filesystem (FlashFS) from a
gxBuild / xeBuild / RGBuild Xbox 360 NAND image.

Supported formats:
  - Raw logical NAND (no spare / ECC)
  - Small Block with per-page spare  (512 data + 16 spare per page)
  - Big Block with chunked spare     (2048 data + 64 spare per page)

Sub-commands
  info      Parse the NAND header + FlashFS and print a summary
  validate  Check that the NAND header and FlashFS are structurally sound
  list      List all FlashFS file entries
  extract   Extract individual files or the entire FlashFS to a directory

Based on:
  - gxbuild3/src/FlashImage.cpp          (FlashFS read / parse logic)
  - gxbuild3/src/bootloaders/FlashFileSystem.cpp (blockmap + entry layout)
  - gxbuild3/include/utils/FlashBlockDriver.hpp  (spare types)
  - RGBuild/NAND/FileSystem.cs            (RGBuild reference)
  - tools/extract.py                      (spare scanning helpers)
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants (mirrored from gxbuild3 / RGBuild)
# ---------------------------------------------------------------------------

HEADER_SIZE = 0x80

HEADER_MAGIC_VALID = 0xFF4F
BL_MAGIC_CB = 0x4342
BL_MAGIC_CD = 0x4344
BL_MAGIC_CE = 0x4345
BL_MAGIC_CF = 0x4346
BL_MAGIC_CG = 0x4347
BL_MAGIC_SC = 0x5343

BL_MAGICS = {
    BL_MAGIC_CB: "CB",
    BL_MAGIC_CD: "CD",
    BL_MAGIC_CE: "CE",
    BL_MAGIC_CF: "CF",
    BL_MAGIC_CG: "CG",
    BL_MAGIC_SC: "SC",
}

FS_ROOT_ENTRY     = 0x30
FS_ROOT_ENTRY_ALT = 0x2C
FS_MOBILE_TYPES   = set(range(0x31, 0x3A))
FS_RESERVED       = 0x1FFB
FS_END_OF_CHAIN   = 0x1FFF
FS_FREE           = 0x1FFE

FS_ENTRY_SIZE        = 0x20
FS_FILENAME_LEN      = 0x16
FS_ENTRIES_PER_PAGE  = 0x10
FS_BLOCKS_PER_PAGE   = 0x100

SB_PAGE_SIZE  = 0x200
SB_SPARE_SIZE = 0x010
SB_TOTAL      = SB_PAGE_SIZE + SB_SPARE_SIZE

BB_PAGE_SIZE  = 0x800
BB_SPARE_SIZE = 0x040
BB_TOTAL      = BB_PAGE_SIZE + BB_SPARE_SIZE

LIL_BLOCK_LENGTH = 0x4000

KNOWN_FS_FILES = {"crl.bin", "dae.bin", "extended.bin", "fcrt.bin", "secdata.bin"}


# ---------------------------------------------------------------------------
# Spare type detection
# ---------------------------------------------------------------------------

class SpareType:
    NONE      = "none"
    SMALL     = "smallblock"
    BIG_SMALL = "bigonsmall"
    BIG       = "bigblock"


@dataclass
class SpareInfo:
    spare_type: str
    page_size: int
    spare_size: int
    page_total: int
    lil_block_length: int


def detect_spare_type(raw: bytes) -> SpareInfo:
    size = len(raw)

    # Small Block / BigOnSmall: 512-byte data pages + 16-byte spare (528 bytes total per page)
    if size % SB_TOTAL == 0 and size >= SB_TOTAL:
        probe_page = 0x22
        probe_off  = probe_page * SB_TOTAL + SB_PAGE_SIZE
        p0_spare   = raw[SB_PAGE_SIZE : SB_PAGE_SIZE + SB_SPARE_SIZE] if size >= SB_TOTAL else b""
        
        # Check if page 0 spare or probe page spare looks like valid 16-byte per-page spare
        if len(p0_spare) == SB_SPARE_SIZE and (p0_spare[0] == 0xFF or p0_spare[5] == 0xFF):
            stype = SpareType.BIG_SMALL if p0_spare[0] == 0xFF else SpareType.SMALL
            if probe_off + SB_SPARE_SIZE <= size:
                spare = raw[probe_off : probe_off + SB_SPARE_SIZE]
                if spare[0] == 0xFF:
                    stype = SpareType.BIG_SMALL
                elif len(spare) > 5 and spare[5] == 0xFF:
                    stype = SpareType.SMALL
            return SpareInfo(
                spare_type=stype,
                page_size=SB_PAGE_SIZE,
                spare_size=SB_SPARE_SIZE,
                page_total=SB_TOTAL,
                lil_block_length=LIL_BLOCK_LENGTH,
            )

    # Big Block: 2048-byte data pages + 64-byte spare (Jasper 256/512, TrinityBB)
    # lil_block_length is still 0x4000 (= 8 physical big-block pages)
    if size % BB_TOTAL == 0 and size >= BB_TOTAL:
        return SpareInfo(
            spare_type=SpareType.BIG,
            page_size=BB_PAGE_SIZE,     # 0x800 physical page size
            spare_size=BB_SPARE_SIZE,   # 0x40 spare per physical page
            page_total=BB_TOTAL,        # 0x840
            lil_block_length=LIL_BLOCK_LENGTH,  # 0x4000 logical
        )

    return SpareInfo(
        spare_type=SpareType.NONE,
        page_size=SB_PAGE_SIZE,
        spare_size=0,
        page_total=SB_PAGE_SIZE,
        lil_block_length=LIL_BLOCK_LENGTH,
    )


def strip_spare(raw: bytes, si: SpareInfo) -> bytes:
    if si.spare_type == SpareType.NONE:
        return raw
    out = bytearray()
    for off in range(0, len(raw), si.page_total):
        out.extend(raw[off : off + si.page_size])
    return bytes(out)


# ---------------------------------------------------------------------------
# Spare field accessors
# ---------------------------------------------------------------------------

def _spare_seq_smallblock(spare: bytes) -> int:
    if len(spare) < 7:
        return 0
    return spare[2] | (spare[3] << 8) | (spare[4] << 16) | (spare[6] << 24)


def _spare_seq_bigonsmall(spare: bytes) -> int:
    if len(spare) < 5:
        return 0
    return spare[0] | (spare[3] << 8) | (spare[4] << 16)


def _spare_seq_bigblock(spare: bytes) -> int:
    if len(spare) < 6:
        return 0
    return spare[5] | (spare[4] << 8) | (spare[3] << 16)


def _spare_block_type_sb(spare: bytes) -> int:
    return spare[12] if len(spare) > 12 else 0


def _spare_block_type_bb(spare: bytes) -> int:
    return spare[12] if len(spare) > 12 else 0


def _spare_size_sb(spare: bytes) -> int:
    if len(spare) < 8:
        return 0
    return spare[6] | (spare[7] << 8)


def _spare_page_count_sb(spare: bytes) -> int:
    return spare[11] if len(spare) > 11 else 0


def get_spare_accessors(si: SpareInfo):
    if si.spare_type == SpareType.BIG_SMALL:
        return (_spare_seq_bigonsmall, _spare_block_type_sb, _spare_size_sb, _spare_page_count_sb)
    elif si.spare_type == SpareType.BIG:
        return (_spare_seq_bigblock, _spare_block_type_bb, None, None)
    else:
        return (_spare_seq_smallblock, _spare_block_type_sb, _spare_size_sb, _spare_page_count_sb)



def read_page_spare(raw: bytes, page_idx: int, si: SpareInfo) -> Optional[bytes]:
    if si.spare_type == SpareType.NONE:
        return None
    off = page_idx * si.page_total + si.page_size
    if off + si.spare_size > len(raw):
        return None
    return raw[off : off + si.spare_size]


def read_lil_block_spare(raw: bytes, lil_block_idx: int, si: SpareInfo) -> Optional[bytes]:
    pages_per_lil_block = si.lil_block_length // si.page_size
    first_page = lil_block_idx * pages_per_lil_block
    return read_page_spare(raw, first_page, si)


def read_lil_block(raw_logical: bytes, lil_block_idx: int, si: SpareInfo) -> Optional[bytes]:
    off = lil_block_idx * si.lil_block_length
    end = off + si.lil_block_length
    if end > len(raw_logical):
        return None
    return raw_logical[off:end]


# ---------------------------------------------------------------------------
# NAND Header
# ---------------------------------------------------------------------------

@dataclass
class NandHeader:
    magic:             int
    version:           int
    pairing:           int
    flags:             int
    entrypoint:        int
    size:              int
    copyright:         str
    payload_indicator: int
    kv_size:           int
    cf1_offset:        int
    patch_slots:       int
    kv_version:        int
    kv_offset:         int
    fs_offset:         int
    smc_config_offset: int
    smc_size:          int
    smc_offset:        int


def parse_nand_header(data: bytes) -> NandHeader:
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Image too small ({len(data)} bytes) to contain NAND header (need {HEADER_SIZE})"
        )
    r = lambda fmt, off: struct.unpack_from(fmt, data, off)[0]
    return NandHeader(
        magic             = r(">H", 0x00),
        version           = r(">H", 0x02),
        pairing           = r(">H", 0x04),
        flags             = r(">H", 0x06),
        entrypoint        = r(">I", 0x08),
        size              = r(">I", 0x0C),
        copyright         = data[0x10:0x50].rstrip(b"\x00").decode("ascii", errors="replace"),
        payload_indicator = r(">I", 0x50),
        kv_size           = r(">I", 0x60),
        cf1_offset        = r(">I", 0x64),
        patch_slots       = r(">H", 0x68),
        kv_version        = r(">H", 0x6A),
        kv_offset         = r(">I", 0x6C),
        fs_offset         = r(">I", 0x70),
        smc_config_offset = r(">I", 0x74),
        smc_size          = r(">I", 0x78),
        smc_offset        = r(">I", 0x7C),
    )


def validate_nand_header(hdr: NandHeader) -> list:
    errors = []
    if hdr.magic == 0:
        errors.append("header.magic is 0x0000 (invalid)")
    elif hdr.magic != HEADER_MAGIC_VALID:
        errors.append(
            f"header.magic 0x{hdr.magic:04X} is not expected flash header magic 0xFF4F"
        )
    if hdr.version == 0:
        errors.append("header.version is 0")
    if hdr.entrypoint == 0 or hdr.entrypoint == 0xFFFFFFFF:
        errors.append(f"header.entrypoint (CB offset) is 0x{hdr.entrypoint:08X} (invalid)")
    if hdr.kv_offset == 0 or hdr.kv_offset == 0xFFFFFFFF:
        errors.append(f"header.kv_offset 0x{hdr.kv_offset:08X} looks invalid")
    if hdr.smc_offset == 0 or hdr.smc_offset == 0xFFFFFFFF:
        errors.append(f"header.smc_offset 0x{hdr.smc_offset:08X} looks invalid")
    return errors


# ---------------------------------------------------------------------------
# Bootloader chain
# ---------------------------------------------------------------------------

@dataclass
class BootloaderInfo:
    name:         str
    offset:       int
    version:      int
    flags:        int
    size:         int
    aligned_size: int


def _bl_aligned_size(size: int) -> int:
    return (size + 0xF) & ~0xF


def scan_bootloaders(logical: bytes, start: int = 0x8000, end: int = 0x200000) -> list:
    found = []
    counts: dict = {}
    last_off = -0x1000
    end = min(end, len(logical) - 0x10)

    for off in range(start, end, 0x10):
        if len(logical) < off + 0x10:
            break
        magic, version, pairing, flags, entrypoint, size = struct.unpack_from(
            ">HHHH II", logical, off
        )
        if magic not in BL_MAGICS:
            continue
        if not (1888 <= version < 20000 and 0x1000 <= size < 0x2000000):
            continue
        if off - last_off < 0x100:
            continue
        name = BL_MAGICS[magic]
        counts[name] = counts.get(name, 0) + 1
        found.append(BootloaderInfo(
            name         = name,
            offset       = off,
            version      = version,
            flags        = flags,
            size         = size,
            aligned_size = _bl_aligned_size(size),
        ))
        last_off = off
    return found


# ---------------------------------------------------------------------------
# FlashFS detection via spare
# ---------------------------------------------------------------------------

@dataclass
class FsRootCandidate:
    block_idx: int
    sequence:  int


def detect_flashfs_root_from_spare(raw: bytes, si: SpareInfo) -> Optional[FsRootCandidate]:
    if si.spare_type == SpareType.NONE:
        return None

    get_seq, get_block_type, _, _ = get_spare_accessors(si)
    
    # Calculate logical size from raw size
    logical_size = len(raw) * si.page_size // si.page_total
    pages_per_lil_block = si.lil_block_length // si.page_size
    lil_block_count = logical_size // si.lil_block_length
    
    best = None

    for block_idx in range(lil_block_count):
        spare = read_lil_block_spare(raw, block_idx, si)
        if spare is None:
            continue
        seq      = get_seq(spare)
        blk_type = get_block_type(spare)
        if seq == 0:
            continue
        if (blk_type & 0x3F) not in (FS_ROOT_ENTRY, FS_ROOT_ENTRY_ALT):
            continue
        if best is None or seq > best.sequence or (
            seq == best.sequence and block_idx > best.block_idx
        ):
            best = FsRootCandidate(block_idx=block_idx, sequence=seq)

    return best


def fs_offset_to_block_idx(fs_offset: int, lil_block_length: int) -> Optional[int]:
    if lil_block_length == 0 or (fs_offset % lil_block_length) != 0:
        return None
    return fs_offset // lil_block_length


# ---------------------------------------------------------------------------
# FlashFS parser (mirrors gxbuild3 FlashFileSystem::load())
# ---------------------------------------------------------------------------

@dataclass
class FlashFsEntry:
    filename:     str
    block_number: int
    length:       int
    timestamp:    int
    deleted:      bool = False


@dataclass
class FlashFs:
    block_idx: int
    version:   int
    blockmap:  list
    entries:   list
    errors:    list = field(default_factory=list)


def format_timestamp(ts: int) -> str:
    if ts == 0:
        return "N/A"
    dos_date = (ts >> 16) & 0xFFFF
    dos_time = ts & 0xFFFF
    year = ((dos_date >> 9) & 0x7F) + 1980
    month = (dos_date >> 5) & 0x0F
    day = dos_date & 0x1F
    hour = (dos_time >> 11) & 0x1F
    minute = (dos_time >> 5) & 0x3F
    second = (dos_time & 0x1F) * 2
    if 1 <= month <= 12 and 1 <= day <= 31 and 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59:
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
    return f"0x{ts:08X}"


def _parse_fs_entry(data: bytes, off: int) -> Optional[FlashFsEntry]:
    if off + FS_ENTRY_SIZE > len(data):
        return None
    raw_name = data[off : off + FS_FILENAME_LEN]
    if raw_name[0] == 0x00:
        return None
    null_pos = raw_name.find(b"\x00")
    if null_pos >= 0:
        raw_name = raw_name[:null_pos]
    if not raw_name:
        return None
    deleted = False
    if raw_name[0] == 0x05:
        raw_name = b"_" + raw_name[1:]
        deleted = True
    try:
        name = raw_name.decode("ascii")
    except UnicodeDecodeError:
        return None
    block_number, length, timestamp = struct.unpack_from(">H I I", data, off + FS_FILENAME_LEN)
    if block_number == 0 and length == 0:
        return None
    return FlashFsEntry(
        filename     = name,
        block_number = block_number,
        length       = length,
        timestamp    = timestamp,
        deleted      = deleted,
    )


def load_flashfs(raw: bytes, logical: bytes, si: SpareInfo, block_idx: int, version: int, visited=None) -> FlashFs:
    if visited is None:
        visited = set()

    fs = FlashFs(block_idx=block_idx, version=version, blockmap=[], entries=[])

    def _load_block(blk_idx: int, is_root: bool = False) -> bool:
        if blk_idx in visited:
            fs.errors.append(f"Cycle detected at block 0x{blk_idx:X}")
            return False
        visited.add(blk_idx)

        block_data = read_lil_block(logical, blk_idx, si)
        if block_data is None:
            fs.errors.append(
                f"Block 0x{blk_idx:X} out of range (logical size 0x{len(logical):X})"
            )
            return False

        pages_per_block = si.lil_block_length // si.page_size
        blockmap_pages = [i for i in range(pages_per_block) if i % 2 == 0]
        entry_pages    = [i for i in range(pages_per_block) if i % 2 == 1]

        blocks_per_page = si.page_size // 2
        entries_per_page = si.page_size // FS_ENTRY_SIZE

        # Calculate total number of blocks in the logical image
        total_blocks = len(logical) // si.lil_block_length

        for pg in blockmap_pages:
            pg_data = block_data[pg * si.page_size : (pg + 1) * si.page_size]
            for j in range(blocks_per_page):
                if j * 2 + 2 > len(pg_data):
                    break
                if len(fs.blockmap) >= total_blocks:
                    break
                val = struct.unpack_from(">H", pg_data, j * 2)[0]
                fs.blockmap.append(val)
            if len(fs.blockmap) >= total_blocks:
                break

        if is_root:
            done = False
            for pg in entry_pages:
                if done:
                    break
                pg_data = block_data[pg * si.page_size : (pg + 1) * si.page_size]
                for j in range(entries_per_page):
                    off = j * FS_ENTRY_SIZE
                    entry = _parse_fs_entry(pg_data, off)
                    if entry is None:
                        done = True
                        break
                    if not any(e.filename == entry.filename for e in fs.entries):
                        fs.entries.append(entry)

        if blk_idx < len(fs.blockmap):
            bmap_val = fs.blockmap[blk_idx] & 0x7FFF
            free_mask = FS_RESERVED & 0x7FFF
            if bmap_val < free_mask:
                _load_block(bmap_val, is_root=False)
        return True

    _load_block(block_idx, is_root=True)
    return fs


def _flashfs_has_valid_entries(fs: FlashFs) -> bool:
    """Check if a FlashFS has at least some valid system file entries."""
    if not fs.entries:
        return False
    known_files = {"crl.bin", "dae.bin", "extended.bin", "fcrt.bin", "secdata.bin",
                  "sysupdate.xexp1", "aac.xexp1", "bootanim.xex", "createprofile.xex",
                  "dash.xex", "deviceselector.xex", "gamerprofile.xex", "hud.xex",
                  "huduiskin.xex", "mfgbootlauncher.xex", "minimediaplayer.xex",
                  "nomni.xexp1", "nomnifwm.xexp1", "nomnifwk.xexp1",
                  "SegoeXbox-Light.xtt", "signin.xex", "xam.xex"}
    for entry in fs.entries:
        if entry.filename in known_files or entry.filename.endswith(".xex"):
            return True
    return False


def validate_flashfs(fs: FlashFs, logical: bytes, si: SpareInfo) -> list:
    problems = list(fs.errors)
    if not fs.blockmap:
        problems.append("Blockmap is empty")
        return problems
    seen_blocks: set = set()
    for entry in fs.entries:
        if entry.deleted:
            continue
        if entry.block_number == 0 and entry.length > 0:
            problems.append(f"Entry '{entry.filename}': block_number=0 but length=0x{entry.length:X}")
            continue
        if entry.block_number >= len(fs.blockmap):
            problems.append(
                f"Entry '{entry.filename}': block_number 0x{entry.block_number:X} "
                f"exceeds blockmap size {len(fs.blockmap)}"
            )
            continue
        if entry.block_number in seen_blocks:
            problems.append(f"Entry '{entry.filename}': block_number 0x{entry.block_number:X} shared")
        seen_blocks.add(entry.block_number)
        data_off = entry.block_number * si.lil_block_length
        if data_off + entry.length > len(logical):
            problems.append(
                f"Entry '{entry.filename}': data at 0x{data_off:X}+0x{entry.length:X} "
                f"exceeds logical image 0x{len(logical):X}"
            )
    return problems


# ---------------------------------------------------------------------------
# File data extraction
# ---------------------------------------------------------------------------

def _get_block_chain(blockmap: list, start_block: int, max_blocks: int = 2048) -> list:
    chain = []
    current = start_block
    visited: set = set()
    while True:
        if current in visited or current >= len(blockmap):
            break
        visited.add(current)
        chain.append(current)
        nxt = blockmap[current] & 0x7FFF
        if nxt >= (FS_RESERVED & 0x7FFF):
            break
        if len(chain) >= max_blocks:
            break
        current = nxt
    return chain


def get_entry_data(entry: FlashFsEntry, fs: FlashFs, logical: bytes, si: SpareInfo) -> bytes:
    chain = _get_block_chain(fs.blockmap, entry.block_number)
    buf = bytearray()
    for blk in chain:
        off = blk * si.lil_block_length
        buf.extend(logical[off : off + si.lil_block_length])
    return bytes(buf[: entry.length])


# ---------------------------------------------------------------------------
# SMC decryption
# ---------------------------------------------------------------------------

def smc_decrypt(data: bytes) -> bytes:
    buf = bytearray(data)
    key = [0x42, 0x75, 0x4E, 0x79]
    for i in range(len(buf)):
        ciphertext = buf[i]
        buf[i] ^= key[i & 3] & 0xFF
        mod_val = (ciphertext * 0xFB) & 0xFFFFFFFF
        key[(i + 1) & 3] = (key[(i + 1) & 3] + mod_val) & 0xFFFFFFFF
        key[(i + 2) & 3] = (key[(i + 2) & 3] + (mod_val >> 8)) & 0xFFFFFFFF
    return bytes(buf)


# ---------------------------------------------------------------------------
# NandImage loader
# ---------------------------------------------------------------------------

@dataclass
class NandImage:
    path:             Path
    raw:              bytes
    logical:          bytes
    spare_info:       SpareInfo
    header:           NandHeader
    header_errors:    list
    bootloaders:      list
    fs_block_idx:     Optional[int]
    fs_from_header:   Optional[int]
    flashfs:          Optional[FlashFs]
    flashfs_problems: list

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


def load_image(path: Path) -> NandImage:
    raw = path.read_bytes()
    si  = detect_spare_type(raw)
    logical = strip_spare(raw, si)
    hdr = parse_nand_header(logical)
    hdr_errors = validate_nand_header(hdr)

    bootloaders = []
    if hdr.entrypoint not in (0, 0xFFFFFFFF):
        try:
            bootloaders = scan_bootloaders(logical, start=hdr.entrypoint)
        except Exception:
            pass

    fs_block_from_hdr = fs_offset_to_block_idx(hdr.fs_offset, si.lil_block_length)
    fs_block_detected: Optional[int] = None
    if si.spare_type != SpareType.NONE:
        cand = detect_flashfs_root_from_spare(raw, si)
        if cand:
            fs_block_detected = cand.block_idx

    # Try both header fs_offset and spare-detected block, pick the one with valid entries
    candidate_blocks = []
    if fs_block_from_hdr is not None:
        candidate_blocks.append(fs_block_from_hdr)
    if fs_block_detected is not None and fs_block_detected not in candidate_blocks:
        candidate_blocks.append(fs_block_detected)

    flashfs: Optional[FlashFs] = None
    flashfs_problems: list = []
    best_fs = None
    best_block = None
    fs_block_idx = None
    
    for block_idx in candidate_blocks:
        version = 1
        if si.spare_type != SpareType.NONE:
            spare = read_lil_block_spare(raw, block_idx, si)
            if spare:
                get_seq, _, _, _ = get_spare_accessors(si)
                version = get_seq(spare)
        
        try:
            fs_candidate = load_flashfs(raw, logical, si, block_idx, version)
            problems = validate_flashfs(fs_candidate, logical, si)
            
            # Prefer filesystem with valid entries
            if _flashfs_has_valid_entries(fs_candidate):
                if best_fs is None or len(fs_candidate.entries) > len(best_fs.entries):
                    best_fs = fs_candidate
                    best_block = block_idx
                    flashfs_problems = problems
        except Exception:
            continue
    
    if best_fs is not None:
        flashfs = best_fs
        fs_block_idx = best_block  # Use the block that produced valid entries
    elif candidate_blocks and fs_block_from_hdr is not None:
        # Fallback: use first candidate (header fs_offset)
        block_idx = fs_block_from_hdr
        version = 1
        if si.spare_type != SpareType.NONE:
            spare = read_lil_block_spare(raw, block_idx, si)
            if spare:
                get_seq, _, _, _ = get_spare_accessors(si)
                version = get_seq(spare)
        flashfs = load_flashfs(raw, logical, si, block_idx, version)
        flashfs_problems = validate_flashfs(flashfs, logical, si)
        fs_block_idx = fs_block_from_hdr
    else:
        fs_block_idx = None

    return NandImage(
        path             = path,
        raw              = raw,
        logical          = logical,
        spare_info       = si,
        header           = hdr,
        header_errors    = hdr_errors,
        bootloaders      = bootloaders,
        fs_block_idx     = fs_block_idx,
        fs_from_header   = fs_block_from_hdr,
        flashfs          = flashfs,
        flashfs_problems = flashfs_problems,
    )


# ---------------------------------------------------------------------------
# Print helpers
# ---------------------------------------------------------------------------

def _h(label: str, value, width: int = 22) -> str:
    return f"  {label:<{width}}: {value}"


def _hx(label: str, value: int, width: int = 22) -> str:
    return _h(label, f"0x{value:08X}  ({value:,})", width)


def print_info(img: NandImage) -> None:
    hdr = img.header
    si  = img.spare_info

    print("=" * 64)
    print("  NAND Image Info")
    print("=" * 64)
    print(_h("File",          img.path))
    print(_h("Raw size",      f"0x{len(img.raw):X}  ({len(img.raw):,} bytes)"))
    print(_h("Logical size",  f"0x{len(img.logical):X}  ({len(img.logical):,} bytes)"))
    print(_h("SHA-256 (raw)", img.sha256))
    print(_h("Spare type",    si.spare_type))
    print(_h("Page size",     f"0x{si.page_size:X}"))
    print(_h("Spare size",    f"0x{si.spare_size:X}"))
    if si.spare_type != SpareType.NONE:
        print(_h("Lil-block length", f"0x{si.lil_block_length:X}"))

    print()
    print("  --- NAND Header ---")
    print(_h("magic",              f"0x{hdr.magic:04X}"))
    print(_h("version",            hdr.version))
    print(_h("pairing",            hdr.pairing))
    print(_h("flags",              f"0x{hdr.flags:04X}"))
    print(_hx("entrypoint (CB)",   hdr.entrypoint))
    print(_hx("kv_offset",         hdr.kv_offset))
    print(_hx("kv_size",           hdr.kv_size))
    print(_h("kv_version",         hdr.kv_version))
    print(_hx("fs_offset",         hdr.fs_offset))
    print(_hx("smc_offset",        hdr.smc_offset))
    print(_hx("smc_size",          hdr.smc_size))
    print(_hx("smc_config_offset", hdr.smc_config_offset))
    print(_hx("cf1_offset",        hdr.cf1_offset))
    print(_h("patch_slots",        hdr.patch_slots))
    if hdr.copyright:
        print(_h("copyright",      repr(hdr.copyright)))

    if img.header_errors:
        print()
        print("  *** Header validation errors ***")
        for e in img.header_errors:
            print(f"    [!] {e}")

    print()
    print("  --- SMC ---")
    if hdr.smc_offset not in (0, 0xFFFFFFFF) and hdr.smc_size > 0:
        smc_enc = img.logical[hdr.smc_offset : hdr.smc_offset + hdr.smc_size]
        if len(smc_enc) >= hdr.smc_size:
            smc_dec = smc_decrypt(smc_enc)
            if len(smc_dec) >= 0x107:
                ver_bytes = smc_dec[0x100:0x107]
                print(_h("SMC version bytes", ver_bytes.hex()))
        print(_h("SMC SHA-256", hashlib.sha256(smc_enc).hexdigest()[:32] + "..."))
    else:
        print("  (not found)")

    print()
    print("  --- Bootloaders ---")
    if img.bootloaders:
        for bl in img.bootloaders:
            print(
                f"    {bl.name:<4}  offset=0x{bl.offset:08X}  "
                f"version={bl.version:<6}  size=0x{bl.size:X}  flags=0x{bl.flags:04X}"
            )
    else:
        print("  (none found)")

    print()
    print("  --- FlashFS ---")
    if img.fs_block_idx is not None:
        print(_h("Root block (spare)",  f"0x{img.fs_block_idx:X}"))
    if img.fs_from_header is not None:
        print(_h("Root block (header)", f"0x{img.fs_from_header:X}"))
    if img.flashfs:
        fs = img.flashfs
        print(_h("FS version (seq)",    fs.version))
        print(_h("Blockmap entries",    len(fs.blockmap)))
        active = [e for e in fs.entries if not e.deleted]
        deleted = [e for e in fs.entries if e.deleted]
        print(_h("File entries",        len(active)))
        if deleted:
            print(_h("Deleted entries", len(deleted)))
        if img.flashfs_problems:
            print()
            print("  *** FlashFS problems ***")
            for p in img.flashfs_problems:
                print(f"    [!] {p}")
    elif img.fs_block_idx is None:
        print("  (FlashFS block index not found)")
    else:
        print("  (FlashFS failed to load)")
    print()


def print_list(img: NandImage, show_deleted: bool = False) -> None:
    if img.flashfs is None:
        print("No FlashFS found in image.")
        return

    fs = img.flashfs
    entries = fs.entries if show_deleted else [e for e in fs.entries if not e.deleted]

    print(f"FlashFS at block 0x{fs.block_idx:X}  (version {fs.version})")
    print(f"  {len(entries)} {'total' if show_deleted else 'active'} entries\n")

    if not entries:
        print("  (no entries)")
        return

    print(f"  {'Filename':<24}  {'Block':>7}  {'Size':>12}  {'Timestamp':>19}  Notes")
    print("  " + "-" * 81)
    for e in entries:
        known_mark = " *" if e.filename in KNOWN_FS_FILES else ""
        del_mark   = " [DEL]" if e.deleted else ""
        ts_str     = format_timestamp(e.timestamp)
        print(
            f"  {e.filename:<24}  "
            f"0x{e.block_number:04X}  "
            f"{e.length:>12,}  "
            f"  {ts_str:>19}  "
            f"{known_mark}{del_mark}"
        )
    print()
    print("  (* = known FlashFS system file)")


def print_validate(img: NandImage, verbose: bool = False) -> bool:
    all_ok = True
    print("=== Validation Report ===\n")

    hdr_ok = len(img.header_errors) == 0
    print(f"  NAND Header      : {'OK' if hdr_ok else 'FAIL'}")
    if not hdr_ok:
        all_ok = False
        for e in img.header_errors:
            print(f"    [!] {e}")
    elif verbose:
        print(f"    magic=0x{img.header.magic:04X}, version={img.header.version}")

    bl_ok = len(img.bootloaders) > 0
    print(f"  Bootloader chain : {'OK (' + str(len(img.bootloaders)) + ' found)' if bl_ok else 'WARN (none found)'}")
    if not bl_ok:
        all_ok = False
    elif verbose:
        for bl in img.bootloaders:
            print(f"    {bl.name} v{bl.version} @ 0x{bl.offset:X}")

    if img.flashfs is None:
        print("  FlashFS          : NOT FOUND")
        all_ok = False
    elif img.flashfs_problems:
        print(f"  FlashFS          : FAIL ({len(img.flashfs_problems)} problem(s))")
        all_ok = False
        for p in img.flashfs_problems:
            print(f"    [!] {p}")
    else:
        active = [e for e in img.flashfs.entries if not e.deleted]
        print(
            f"  FlashFS          : OK "
            f"({len(active)} active files, {len(img.flashfs.blockmap)} blockmap entries)"
        )
        if verbose:
            for e in active:
                print(f"    {e.filename}  ({e.length:,} bytes)")

    print()
    print("Result:", "PASS" if all_ok else "FAIL")
    return all_ok


def extract_flashfs(
    img: NandImage,
    output_dir: Path,
    files=None,
    include_deleted: bool = False,
    raw_fs_block: bool = False,
) -> None:
    if img.flashfs is None:
        print("Error: FlashFS not found or failed to load.", file=sys.stderr)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)
    fs = img.flashfs
    si = img.spare_info

    entries = fs.entries if include_deleted else [e for e in fs.entries if not e.deleted]
    if files:
        entries = [e for e in entries if e.filename in files]

    print(f"Extracting {len(entries)} file(s) from FlashFS to {output_dir}/")
    print()

    extracted = 0
    for entry in entries:
        if entry.block_number == 0 and entry.length == 0:
            print(f"  SKIP  {entry.filename}  (empty)")
            continue
        try:
            data = get_entry_data(entry, fs, img.logical, si)
        except Exception as exc:
            print(f"  ERROR {entry.filename}: {exc}", file=sys.stderr)
            continue

        out_path = output_dir / entry.filename
        out_path.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()[:16]
        del_note = " [DELETED]" if entry.deleted else ""
        print(
            f"  OK    {entry.filename:<24}{del_note}  "
            f"{len(data):>10,} bytes  sha256={sha}..."
        )
        extracted += 1

    if raw_fs_block and img.fs_block_idx is not None:
        raw_block = read_lil_block(img.logical, img.fs_block_idx, si)
        if raw_block:
            raw_path = output_dir / "flashfs_raw_block.bin"
            raw_path.write_bytes(raw_block)
            print(f"\n  Saved raw FlashFS root block -> {raw_path.name}")

    print()
    print(f"Done: {extracted}/{len(entries)} files extracted to {output_dir}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fstool",
        description="Xbox 360 Flash Filesystem (FlashFS) tool — validate, inspect, list and extract.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    p_info = sub.add_parser("info", help="Print NAND header, bootloaders, and FlashFS summary.")
    p_info.add_argument("image", type=Path, help="Path to NAND image file")

    p_val = sub.add_parser("validate", help="Validate NAND header, bootloaders, and FlashFS structure.")
    p_val.add_argument("image", type=Path, help="Path to NAND image file")
    p_val.add_argument("-v", "--verbose", action="store_true", help="Show details for passing checks too.")

    p_list = sub.add_parser("list", help="List all FlashFS file entries.")
    p_list.add_argument("image", type=Path, help="Path to NAND image file")
    p_list.add_argument("--deleted", action="store_true", help="Include deleted entries.")

    p_ext = sub.add_parser("extract", help="Extract FlashFS files to a directory.")
    p_ext.add_argument("image", type=Path, help="Path to NAND image file")
    p_ext.add_argument("-o", "--output", type=Path, dest="output_dir", default=None,
                       help="Output directory (default: <image_name>_flashfs/)")
    p_ext.add_argument("-f", "--file", dest="files", action="append", metavar="FILENAME",
                       help="Only extract this filename (can repeat). Default: all files.")
    p_ext.add_argument("--deleted", action="store_true", help="Include deleted entries in extraction.")
    p_ext.add_argument("--raw-block", action="store_true", dest="raw_block",
                       help="Also save raw FlashFS root block as flashfs_raw_block.bin.")

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    image_path: Path = args.image
    if not image_path.exists():
        print(f"Error: file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {image_path} ...")
    img = load_image(image_path)
    si  = img.spare_info
    print(
        f"  {len(img.raw):,} bytes raw  |  "
        f"spare: {si.spare_type}  |  "
        f"logical: {len(img.logical):,} bytes"
    )
    print()

    if args.command == "info":
        print_info(img)
    elif args.command == "validate":
        ok = print_validate(img, verbose=args.verbose)
        sys.exit(0 if ok else 1)
    elif args.command == "list":
        print_list(img, show_deleted=args.deleted)
    elif args.command == "extract":
        out = args.output_dir or (image_path.parent / (image_path.stem + "_flashfs"))
        extract_flashfs(
            img,
            output_dir      = out,
            files           = args.files,
            include_deleted = args.deleted,
            raw_fs_block    = args.raw_block,
        )


if __name__ == "__main__":
    main()
