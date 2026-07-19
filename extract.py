#!/usr/bin/env python3
"""
Extract all possible data from gxBuild/xeBuild NAND images.

This script extracts and saves:
- Raw and stripped (ECC-removed) images
- Header information
- Key Vault (KV) data
- SMC (Secure Monitor Call) - both encrypted and decrypted
- SMC Config
- All bootloaders (CB, CD, CE, CF, CG) - both encrypted and decrypted if keys available
- Filesystem regions detected via spare data scanning
- Spare data from NAND pages

Decryption is performed automatically when keys are provided:
- CB (1BL) decryption requires --secret-1bl or --secret-1bl-file
- CF decryption requires --secret-1bl or --secret-1bl-file
- CD decryption requires prior CB decryption
- CE decryption requires prior CD decryption
- CG decryption requires prior CF decryption
- SMC is always decrypted (uses built-in key)

Based on compare.py from the same repository.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
from datetime import datetime
from pathlib import Path


# Header field definitions
HEADER_FIELDS = [
    ("magic", 0x00, ">H"),
    ("version", 0x02, ">H"),
    ("pairing", 0x04, ">H"),
    ("flags", 0x06, ">H"),
    ("entrypoint", 0x08, ">I"),
    ("size", 0x0C, ">I"),
    ("kv_size", 0x60, ">I"),
    ("sys_update_addr", 0x64, ">I"),
    ("patch_slots", 0x68, ">h"),
    ("kv_version", 0x6A, ">H"),
    ("kv_addr", 0x6C, ">I"),
    ("fs_offset", 0x70, ">I"),
    ("smc_config_offset", 0x74, ">I"),
    ("smc_size", 0x78, ">I"),
    ("smc_addr", 0x7C, ">I"),
]

MAGIC_NAMES = {
    0x4342: "CB",
    0x4344: "CD",
    0x4345: "CE",
    0x4346: "CF",
    0x4347: "CG",
    0x5343: "SC",
}

DECRYPTABLE_BOOTLOADERS = {"CB", "CD", "CE", "CF", "CG"}

# Filesystem spare data scanning constants
FsRootEntry = 0x30
FsRootEntryAlt = 0x2C


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def format_value(value: int) -> str:
    if isinstance(value, int):
        return f"{value} (0x{value & 0xFFFFFFFF:X})"
    return str(value)


def load(path: Path) -> bytes:
    return path.read_bytes()


def parse_hex_key(value: str, name: str) -> bytes:
    compact = value.strip().replace(" ", "").replace("\t", "").replace("\n", "")
    compact = compact.replace(":", "").replace("-", "")
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if len(compact) % 2 != 0:
        raise ValueError(f"{name} must contain an even number of hex characters")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"{name} must be a hex string") from exc


def load_key(value: str | None, file_path: Path | None, name: str) -> bytes | None:
    if value and file_path:
        raise ValueError(f"Provide either --{name} or --{name}-file, not both")
    if value:
        return parse_hex_key(value, name)
    if file_path:
        raw = load(file_path)
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            text = ""
        if text:
            try:
                raw = parse_hex_key(text, name)
            except ValueError:
                pass
        if not raw:
            raise ValueError(f"{name} cannot be empty")
        if len(raw) != 0x10:
            raise ValueError(f"{name} must be 16 bytes")
        return raw
    return None


def require_key_length(key: bytes | None, name: str) -> bytes | None:
    if key is None:
        return None
    if len(key) != 0x10:
        raise ValueError(f"{name} must be 16 bytes")
    return key


def load_and_validate_key(value: str | None, file_path: Path | None, name: str) -> bytes | None:
    return require_key_length(load_key(value, file_path, name), name)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for pos, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[pos] = value ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def hmac_sha1_16(secret: bytes, data: bytes) -> bytes:
    return hmac.new(secret, data, hashlib.sha1).digest()[:0x10]


def build_version(data: bytes) -> int:
    if len(data) < 4:
        return 0
    return struct.unpack_from(">H", data, 0x02)[0]


def decrypt_cb_1bl(section: bytes, secret_1bl: bytes) -> bytes:
    key = hmac_sha1_16(secret_1bl, section[0x10:0x20])
    return section[0:0x10] + key + rc4_crypt(key, section[0x20:])


def decrypt_cb_cpu(section: bytes, previous_cb: bytes, cpu_key: bytes) -> bytes:
    material = section[0x10:0x20] + cpu_key
    key = hmac_sha1_16(previous_cb[0x10:0x20], material)
    return section[0:0x10] + key + rc4_crypt(key, section[0x20:])


def decrypt_cd(section: bytes, previous_cb: bytes, cpu_key: bytes | None) -> bytes:
    key = hmac_sha1_16(previous_cb[0x10:0x20], section[0x10:0x20])
    if cpu_key and build_version(section) >= 1920:
        key = hmac_sha1_16(cpu_key, key)
    return section[0:0x10] + key + rc4_crypt(key, section[0x20:])


def decrypt_ce(section: bytes, cd_section: bytes) -> bytes:
    key = hmac_sha1_16(cd_section[0x10:0x20], section[0x10:0x20])
    return section[0:0x10] + key + rc4_crypt(key, section[0x20:])


def decrypt_cf(section: bytes, secret_1bl: bytes) -> bytes:
    key = hmac_sha1_16(secret_1bl, section[0x20:0x30])
    return section[0:0x20] + key + rc4_crypt(key, section[0x30:])


def decrypt_cg(section: bytes, cf_section: bytes) -> bytes:
    key = hmac_sha1_16(cf_section[0x330:0x340], section[0x10:0x20])
    return section[0:0x10] + key + rc4_crypt(key, section[0x20:])


def aligned_bootloader_size(size: int) -> int:
    return (size + 0xF) & ~0xF


def bb_spare_offset_per_page(page: int) -> int:
    return (page * 0x210) + 0x200


def bb_spare_offset_chunked(page: int) -> int:
    chunk = page // 4
    idx = page % 4
    return (chunk * 0x840) + 0x800 + (idx * 0x10)


def bb_meta2_block_id(spare: bytes) -> int | None:
    if len(spare) < 3:
        return None
    return spare[1] | ((spare[2] & 0xF) << 8)


def bb_score_spare(candidate: bytes) -> int:
    if len(candidate) < 16:
        return -(1 << 30)
    if all(b == 0x00 for b in candidate[:12]):
        return -10

    score = 0
    if candidate[0] == 0xFF:
        score += 5
    elif candidate[0] == 0x00:
        score -= 1
    else:
        score -= 2

    if candidate[3] == 0x00 and candidate[4] == 0x00:
        score += 1
    if candidate[5] == 0xFF:
        score += 1

    ecc = candidate[0x0C:0x10]
    if all(b == 0x00 for b in ecc) or all(b == 0xFF for b in ecc):
        score -= 1
    else:
        score += 1
    return score


def detect_bb_physical_format(raw: bytes) -> str:
    per_page_hits = 0
    chunked_hits = 0
    for block in range(64):
        page0 = block * 256

        a_off = bb_spare_offset_per_page(page0)
        if a_off + 16 <= len(raw):
            spare = raw[a_off:a_off + 16]
            if bb_score_spare(spare) > 0:
                per_page_hits += 1
            if spare[0] == 0xFF and bb_meta2_block_id(spare) == block:
                per_page_hits += 4

        b_off = bb_spare_offset_chunked(page0)
        if b_off + 16 <= len(raw):
            spare = raw[b_off:b_off + 16]
            if bb_score_spare(spare) > 0:
                chunked_hits += 1
            if spare[0] == 0xFF and bb_meta2_block_id(spare) == block:
                chunked_hits += 4

    return "chunked" if chunked_hits > per_page_hits else "per-page"


def maybe_strip_ecc(raw: bytes) -> tuple[bytes, bool]:
    if len(raw) % 0x840 == 0 and len(raw) >= 0x4200000:
        fmt = detect_bb_physical_format(raw)
        if fmt == "chunked":
            out = bytearray()
            for off in range(0, len(raw), 0x840):
                out.extend(raw[off : off + 0x800])
            return bytes(out), True

    if len(raw) % 0x210 == 0:
        out = bytearray()
        for off in range(0, len(raw), 0x210):
            out.extend(raw[off : off + 0x200])
        return bytes(out), True

    if len(raw) % 0x840 == 0:
        out = bytearray()
        for off in range(0, len(raw), 0x840):
            out.extend(raw[off : off + 0x800])
        return bytes(out), True

    return raw, False


def parse_header(image: bytes) -> dict[str, int]:
    return {name: struct.unpack_from(fmt, image, off)[0] for name, off, fmt in HEADER_FIELDS}


def parse_spare_data_smallblock(spare: bytes) -> tuple[int, int]:
    """
    Parse spare data (16 bytes) in SmallBlock format.
    Returns (FsSequence, FsBlockType)
    """
    if len(spare) < 16:
        return 0, 0
    
    fs_seq = spare[2] | (spare[3] << 8) | (spare[4] << 16) | (spare[6] << 24)
    fs_block_type = spare[12]
    
    return fs_seq, fs_block_type


def parse_spare_data_bigblock(spare: bytes) -> tuple[int, int]:
    """
    Parse spare data (16 bytes) in BigBlock format.
    Returns (FsSequence, FsBlockType)
    """
    if len(spare) < 16:
        return 0, 0
    
    fs_seq = spare[3] | (spare[4] << 8) | (spare[5] << 16)
    fs_block_type = spare[12]
    
    return fs_seq, fs_block_type


def detect_nand_type(raw: bytes) -> str:
    """
    Detect NAND type by reading spare data at offset 0x4400.
    Returns 'bigblock', 'smallblock', 'bigonsmall', or 'none' (eMMC)
    """
    PAGE_SIZE_WITH_SPARE = 0x210
    
    if len(raw) < 0x4400 + 0x10:
        return "none"
    
    page_num = 0x4400 // 0x200
    page_start = page_num * PAGE_SIZE_WITH_SPARE
    spare_start = page_start + 0x200
    
    if spare_start + 0x10 > len(raw):
        return "none"
    
    spare = raw[spare_start:spare_start + 0x10]
    
    if spare[0] == 0xFF:
        return "bigblock"
    elif len(spare) > 5 and spare[5] == 0xFF:
        return "smallblock"
    elif len(spare) > 1 and spare[1] == 1:
        return "bigonsmall"
    else:
        return "none"


def scan_filesystem_offsets(raw: bytes, page_size: int = 0x200, spare_size: int = 0x10, 
                           pages_per_block: int = 0x40) -> list[int]:
    """
    Scan spare data for filesystem root entries.
    Returns list of unique byte offsets where filesystems were found.
    """
    offsets = []
    page_total = page_size + spare_size
    
    if len(raw) < page_total:
        return offsets
    
    nand_type = detect_nand_type(raw)
    
    if nand_type in ("smallblock", "bigonsmall"):
        parse_func = parse_spare_data_smallblock
    elif nand_type == "bigblock":
        parse_func = parse_spare_data_bigblock
    else:
        return offsets
    
    num_pages = len(raw) // page_total
    for page_idx in range(num_pages):
        page_start = page_idx * page_total
        spare_start = page_start + page_size
        spare_end = spare_start + spare_size
        
        if spare_end > len(raw):
            break
        
        spare = raw[spare_start:spare_end]
        fs_seq, fs_block_type = parse_func(spare)
        
        if fs_seq != 0 and fs_block_type in (FsRootEntry, FsRootEntryAlt):
            block_idx = page_idx // pages_per_block
            block_offset = block_idx * pages_per_block * page_size
            if block_offset not in offsets:
                offsets.append(block_offset)
    
    return offsets


def contains_meaningful_data(data: bytes) -> bool:
    return any(b not in (0x00, 0xFF) for b in data)


def extract_slice(image: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(image):
        return b""
    return image[offset : offset + size]


def scan_bootloaders(image: bytes, start: int = 0x8000, end: int = 0x100000) -> list[dict[str, int | str]]:
    found: list[dict[str, int | str]] = []
    last_off = -0x1000
    counts: dict[str, int] = {}
    for off in range(start, min(end, len(image) - 0x10), 0x10):
        magic, version, _pairing, _flags, entrypoint, size = struct.unpack_from(">HHHHII", image, off)
        if not (1888 <= version < 20000 and 0x1000 <= size < 0x2000000):
            continue
        if magic not in MAGIC_NAMES:
            continue
        if off - last_off <= 0x100:
            continue
        name = MAGIC_NAMES[magic]
        counts[name] = counts.get(name, 0) + 1
        occurrence = counts[name]
        label = f"{name}{occurrence}" if occurrence > 1 else name
        found.append(
            {
                "offset": off,
                "magic": magic,
                "name": name,
                "occurrence": occurrence,
                "label": label,
                "version": version,
                "entrypoint": entrypoint,
                "size": size,
                "aligned_size": aligned_bootloader_size(size),
            }
        )
        last_off = off
    return found


def decrypt_bootloader_chain(
    image: bytes,
    chain: list[dict[str, int | str]],
    secret_1bl: bytes | None,
    cpu_key: bytes | None,
) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    last_cb: bytes | None = None
    last_cd: bytes | None = None
    last_cf: bytes | None = None

    for bootloader in chain:
        section = extract_slice(image, int(bootloader["offset"]), int(bootloader["aligned_size"]))
        name = str(bootloader["name"])
        occurrence = int(bootloader["occurrence"])
        decrypted: bytes | None = None
        decrypt_error: str | None = None

        try:
            if name == "CB":
                if occurrence == 1:
                    if secret_1bl is None:
                        decrypt_error = "needs 1BL key"
                    elif len(section) < 0x20:
                        decrypt_error = "section too small"
                    else:
                        decrypted = decrypt_cb_1bl(section, secret_1bl)
                else:
                    if last_cb is None:
                        decrypt_error = "needs prior decrypted CB"
                    elif cpu_key is None:
                        decrypt_error = "needs CPU key"
                    elif len(section) < 0x20:
                        decrypt_error = "section too small"
                    else:
                        decrypted = decrypt_cb_cpu(section, last_cb, cpu_key)
                if decrypted is not None:
                    last_cb = decrypted
            elif name == "CD":
                if last_cb is None:
                    decrypt_error = "needs decrypted CB"
                elif len(section) < 0x20:
                    decrypt_error = "section too small"
                else:
                    decrypted = decrypt_cd(section, last_cb, cpu_key)
                    last_cd = decrypted
            elif name == "CE":
                if last_cd is None:
                    decrypt_error = "needs decrypted CD"
                elif len(section) < 0x20:
                    decrypt_error = "section too small"
                else:
                    decrypted = decrypt_ce(section, last_cd)
            elif name == "CF":
                if secret_1bl is None:
                    decrypt_error = "needs 1BL key"
                elif len(section) < 0x30:
                    decrypt_error = "section too small"
                else:
                    decrypted = decrypt_cf(section, secret_1bl)
                    last_cf = decrypted
            elif name == "CG":
                if last_cf is None:
                    decrypt_error = "needs decrypted CF"
                elif len(section) < 0x20:
                    decrypt_error = "section too small"
                else:
                    decrypted = decrypt_cg(section, last_cf)
        except Exception as exc:
            decrypt_error = str(exc)

        entry = dict(bootloader)
        entry["bytes"] = section
        entry["decrypted"] = decrypted
        entry["decrypt_error"] = decrypt_error
        out.append(entry)
    return out


def smc_crypt(buf: bytearray, encrypt: bool) -> None:
    key = [0x42, 0x75, 0x4E, 0x79]
    for i in range(len(buf)):
        ciphertext = buf[i] ^ (key[i & 3] & 0xFF) if encrypt else buf[i]
        mod_val = (ciphertext * 0xFB) & 0xFFFFFFFF
        if encrypt:
            buf[i] = ciphertext
        else:
            buf[i] ^= key[i & 3] & 0xFF
        key[(i + 1) & 3] = (key[(i + 1) & 3] + mod_val) & 0xFFFFFFFF
        key[(i + 2) & 3] = (key[(i + 2) & 3] + (mod_val >> 8)) & 0xFFFFFFFF


def decrypt_smc(section: bytes) -> bytes:
    data = bytearray(section)
    smc_crypt(data, False)
    return bytes(data)


def ensure_directory(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)


def save_file(output_dir: Path, filename: str, data: bytes, description: str = "") -> Path:
    """Save data to a file in the output directory."""
    filepath = output_dir / filename
    filepath.write_bytes(data)
    print(f"  Saved: {filename} ({len(data):,} bytes) {description}")
    return filepath


def extract_and_save_all(
    image: bytes,
    raw_image: bytes,
    output_dir: Path,
    secret_1bl: bytes | None,
    cpu_key: bytes | None,
    prefix: str = "",
) -> None:
    """Extract and save all possible components from the image."""
    
    print(f"\n{'='*60}")
    print(f"Extracting from image: {prefix}")
    print(f"{'='*60}")
    
    # Create subdirectories
    bootloader_dir = output_dir / "bootloaders"
    ensure_directory(bootloader_dir)
    
    # Parse header
    header = parse_header(image)
    print(f"\n[Header Information]")
    for field, value in header.items():
        print(f"  {field:17}: {format_value(value)}")
    
    # Extract copyright string
    copyright = image[0x10:0x50].rstrip(b"\x00")
    if copyright:
        print(f"  {'copyright':17}: {copyright!r}")
    
    # Save raw and stripped images
    print(f"\n[Image Files]")
    save_file(output_dir, f"{prefix}raw.bin", raw_image, "(original with ECC)")
    if raw_image != image:
        save_file(output_dir, f"{prefix}stripped.bin", image, "(ECC stripped)")
    
    # Extract KV (Key Vault)
    print(f"\n[Key Vault]")
    kv_addr = header.get("kv_addr", 0)
    kv_size = header.get("kv_size", 0)
    kv_data = extract_slice(image, kv_addr, kv_size)
    if kv_data and len(kv_data) > 0:
        save_file(output_dir, f"{prefix}kv.bin", kv_data, f"(addr: 0x{kv_addr:X}, size: 0x{kv_size:X})")
        print(f"  KV version: {header.get('kv_version', 0)}")
    else:
        print(f"  KV not found at 0x{kv_addr:X}")
    
    # Extract SMC (Secure Monitor Call)
    print(f"\n[SMC]")
    smc_addr = header.get("smc_addr", 0)
    smc_size = header.get("smc_size", 0)
    smc_encrypted = extract_slice(image, smc_addr, smc_size)
    if smc_encrypted and len(smc_encrypted) > 0:
        save_file(output_dir, f"{prefix}smc_encrypted.bin", smc_encrypted, f"(addr: 0x{smc_addr:X}, size: 0x{smc_size:X})")
        
        # Decrypt SMC
        smc_decrypted = decrypt_smc(smc_encrypted)
        save_file(output_dir, f"{prefix}smc_decrypted.bin", smc_decrypted, "(decrypted)")
        
        # Try to extract SMC version
        if len(smc_decrypted) >= 0x107:
            smc_version_bytes = smc_decrypted[0x100:0x107]
            print(f"  SMC version bytes: {smc_version_bytes.hex()}")
    else:
        print(f"  SMC not found at 0x{smc_addr:X}")
    
    # Extract SMC Config
    print(f"\n[SMC Config]")
    smc_config_offset = header.get("smc_config_offset", 0x3DF0000)
    smc_config_size = 0x10000  # 64KB
    smc_config = extract_slice(image, smc_config_offset, smc_config_size)
    if smc_config and contains_meaningful_data(smc_config):
        save_file(output_dir, f"{prefix}smc_config.bin", smc_config, f"(offset: 0x{smc_config_offset:X})")
        print(f"  SMC Config contains meaningful data: True")
    else:
        print(f"  SMC Config at 0x{smc_config_offset:X} is empty or all FF")
    
    # Scan and extract bootloaders
    print(f"\n[Bootloaders]")
    chain = scan_bootloaders(image)
    
    if not chain:
        print("  No bootloaders found")
    else:
        # Save encrypted bootloaders
        print("  Encrypted bootloaders:")
        for bl in chain:
            bl_data = extract_slice(image, int(bl["offset"]), int(bl["aligned_size"]))
            filename = f"{prefix}{bl['label']}_encrypted.bin"
            save_file(bootloader_dir, filename, bl_data, 
                     f"(offset: 0x{bl['offset']:X}, version: {bl['version']})")
        
        # Decrypt bootloader chain
        decrypted_chain = decrypt_bootloader_chain(image, chain, secret_1bl, cpu_key)
        
        print("  Decrypted bootloaders:")
        for stage in decrypted_chain:
            name = str(stage["name"])
            label = str(stage["label"])
            if name not in DECRYPTABLE_BOOTLOADERS:
                continue
            
            decrypted = stage.get("decrypted")
            error = stage.get("decrypt_error")
            
            if decrypted and isinstance(decrypted, bytes):
                filename = f"{prefix}{label}_decrypted.bin"
                save_file(bootloader_dir, filename, decrypted, f"(decrypted {name})")
                print(f"    {label}: DECRYPTED OK")
            elif error:
                print(f"    {label}: NOT DECRYPTED - {error}")
            else:
                print(f"    {label}: NOT DECRYPTED - no decrypted data")
    
    # Filesystem detection
    print(f"\n[Filesystem Detection]")
    nand_type = detect_nand_type(raw_image)
    print(f"  NAND type: {nand_type}")
    
    fs_offsets = scan_filesystem_offsets(raw_image)
    if fs_offsets:
        print(f"  Filesystem offsets found: {', '.join(f'0x{off:08X}' for off in sorted(fs_offsets))}")
        
        # Extract filesystem regions
        header_fs_offset = header.get("fs_offset", 0)
        if header_fs_offset:
            print(f"  Header fs_offset: 0x{header_fs_offset:08X}")
        
        # Try to extract filesystem at each found offset
        fs_dir = output_dir / "filesystems"
        ensure_directory(fs_dir)
        
        for i, fs_offset in enumerate(sorted(fs_offsets)):
            # Try to read a reasonable filesystem size (e.g., 1MB for testing)
            # In practice, filesystem can be very large
            test_size = min(0x100000, len(image) - fs_offset)  # 1MB test
            if test_size > 0:
                fs_data = extract_slice(image, fs_offset, test_size)
                filename = f"{prefix}filesystem_{i:02d}_offset_0x{fs_offset:08X}.bin"
                save_file(fs_dir, filename, fs_data, f"(first {test_size:,} bytes)")
    else:
        print("  No filesystem offsets found (eMMC or no spare data)")
    
    # Full filesystem extraction at header offset if available
    if header.get("fs_offset", 0) > 0:
        fs_start = header["fs_offset"]
        # Extract from fs_offset to end of image
        fs_size = len(image) - fs_start
        if fs_size > 0:
            fs_data = extract_slice(image, fs_start, fs_size)
            fs_dir = output_dir / "filesystems"
            ensure_directory(fs_dir)
            filename = f"{prefix}filesystem_full.bin"
            save_file(fs_dir, filename, fs_data, f"(from header offset 0x{fs_start:X})")
    
    # Extract raw spare data if NAND type is not eMMC
    if nand_type != "none":
        print(f"\n[Spare Data]")
        spare_dir = output_dir / "spare"
        ensure_directory(spare_dir)
        
        PAGE_SIZE_WITH_SPARE = 0x210
        PAGE_SIZE = 0x200
        SPARE_SIZE = 0x10
        
        if len(raw_image) % PAGE_SIZE_WITH_SPARE == 0:
            num_pages = len(raw_image) // PAGE_SIZE_WITH_SPARE
            
            # Extract all spare data
            all_spare = bytearray()
            for i in range(num_pages):
                offset = i * PAGE_SIZE_WITH_SPARE + PAGE_SIZE
                spare = raw_image[offset:offset + SPARE_SIZE]
                all_spare.extend(spare)
            
            save_file(spare_dir, f"{prefix}all_spare.bin", bytes(all_spare), 
                     f"({len(all_spare):,} bytes, {num_pages:,} pages)")
            
            # Also save first few pages of spare for analysis
            first_pages_spare = raw_image[PAGE_SIZE:PAGE_SIZE + (10 * PAGE_SIZE_WITH_SPARE):PAGE_SIZE_WITH_SPARE]
            first_spare_only = b''.join([first_pages_spare[i:i+SPARE_SIZE] for i in range(0, len(first_pages_spare), PAGE_SIZE_WITH_SPARE)])
            save_file(spare_dir, f"{prefix}first_10_pages_spare.bin", first_spare_only, 
                     "(first 10 pages spare data)")
    
    print(f"\n[Extraction Summary]")
    print(f"  Raw image size: {len(raw_image):,} bytes")
    print(f"  Stripped image size: {len(image):,} bytes")
    print(f"  All files saved to: {output_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract all possible data from gxBuild/xeBuild NAND images and decrypt if keys are available."
    )
    parser.add_argument("image", help="Path to the NAND image file")
    parser.add_argument("-o", "--output", dest="output_dir", 
                        help="Output directory (default: ./extract_<timestamp>)",
                        default=None)
    parser.add_argument("--prefix", dest="prefix", 
                        help="Prefix for output filenames",
                        default="")
    parser.add_argument("--secret-1bl", dest="secret_1bl", 
                        help="Hex 1BL key used for CB/CF decryption")
    parser.add_argument(
        "--secret-1bl-file",
        dest="secret_1bl_file",
        type=Path,
        help="File containing a raw or ASCII-hex 1BL key",
    )
    parser.add_argument("--cpu-key", dest="cpu_key", 
                        help="Hex CPU key used for paired CB/CD decryption")
    parser.add_argument(
        "--cpu-key-file",
        dest="cpu_key_file",
        type=Path,
        help="File containing a raw or ASCII-hex CPU key",
    )
    parser.add_argument("--no-strip", action="store_true",
                        help="Skip ECC stripping (treat input as already logical)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed extraction information")
    
    args = parser.parse_args()

    # Setup output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(f"extract_{timestamp}")
    
    ensure_directory(output_dir)
    
    # Load keys
    secret_1bl = load_and_validate_key(args.secret_1bl, args.secret_1bl_file, "secret-1bl")
    cpu_key = load_and_validate_key(args.cpu_key, args.cpu_key_file, "cpu-key")
    
    # Load image
    image_path = Path(args.image)
    raw_image = load(image_path)
    
    print(f"[Input]")
    print(f"  File: {image_path}")
    print(f"  Raw size: {len(raw_image):,} bytes ({len(raw_image):X} hex)")
    print(f"  SHA256: {sha256_hex(raw_image)}")
    print(f"  1BL key provided: {secret_1bl is not None}")
    print(f"  CPU key provided: {cpu_key is not None}")
    print(f"  Output directory: {output_dir}")
    
    # Strip ECC if not disabled
    if args.no_strip:
        logical_image = raw_image
        stripped = False
    else:
        logical_image, stripped = maybe_strip_ecc(raw_image)
        if stripped:
            print(f"  ECC stripped: Yes (reduced from {len(raw_image):,} to {len(logical_image):,} bytes)")
        else:
            print(f"  ECC stripped: No (already logical or unknown format)")
    
    # Extract everything
    extract_and_save_all(
        logical_image,
        raw_image,
        output_dir,
        secret_1bl,
        cpu_key,
        args.prefix,
    )
    
    # Also save a summary file
    summary_path = output_dir / "extraction_summary.txt"
    with open(summary_path, 'w') as f:
        f.write(f"Extraction Summary\n")
        f.write(f"==================\n\n")
        f.write(f"Input file: {image_path}\n")
        f.write(f"Raw size: {len(raw_image):,} bytes\n")
        f.write(f"SHA256: {sha256_hex(raw_image)}\n")
        f.write(f"1BL key: {'provided' if secret_1bl else 'NOT provided'}\n")
        f.write(f"CPU key: {'provided' if cpu_key else 'NOT provided'}\n")
        f.write(f"ECC stripped: {'Yes' if not args.no_strip and stripped else 'No'}\n")
        f.write(f"Logical size: {len(logical_image):,} bytes\n")
        f.write(f"Output directory: {output_dir.absolute()}\n")
        f.write(f"Extraction time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print(f"\n  Summary saved to: {summary_path}")
    print(f"\nExtraction complete!")


if __name__ == "__main__":
    main()
