#!/usr/bin/env python3
"""
nandtool.py - Xbox 360 NAND Image Tool

Inspect, compare, and extract Xbox 360 gxBuild / xeBuild NAND images,
bootloaders, KeyVault, SMC, and filesystems.

Sub-commands:
  info      Inspect NAND header, bootloader chain, SMC, and filesystem offsets
  compare   Compare two NAND images section by section with byte diffs
  extract   Extract raw/stripped images, header, KV, SMC, bootloaders, and filesystems
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

FsRootEntry = 0x30
FsRootEntryAlt = 0x2C


# ---------------------------------------------------------------------------
# General Utilities & Cryptography
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def format_value(value: int) -> str:
    if isinstance(value, int):
        return f"{value} (0x{value & 0xFFFFFFFF:X})"
    return str(value)


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
        raw = file_path.read_bytes()
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
            raise ValueError(f"{name} key file cannot be empty")
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
    for pos, val in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[pos] = val ^ s[(s[i] + s[j]) & 0xFF]
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


def aligned_bootloader_size(size: int) -> int:
    return (size + 0xF) & ~0xF


def contains_meaningful_data(data: bytes) -> bool:
    return any(b not in (0x00, 0xFF) for b in data)


def extract_slice(image: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(image):
        return b""
    return image[offset : offset + size]


# ---------------------------------------------------------------------------
# NAND Geometry & Spare Data Scanning
# ---------------------------------------------------------------------------

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


def detect_nand_type(raw: bytes) -> str:
    """
    Detect NAND type by reading spare data at offset 0x4400.
    Returns 'bigblock', 'smallblock', 'bigonsmall', or 'none' (eMMC).
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
        return "bigonsmall" if len(spare) > 5 and spare[5] == 0x00 else "bigblock"
    elif len(spare) > 5 and spare[5] == 0xFF:
        return "smallblock"
    elif len(spare) > 1 and spare[1] == 1:
        return "bigonsmall"
    else:
        return "none"


def parse_spare_data_smallblock(spare: bytes) -> tuple[int, int]:
    if len(spare) < 16:
        return 0, 0
    fs_seq = spare[2] | (spare[3] << 8) | (spare[4] << 16) | (spare[6] << 24)
    fs_block_type = spare[12]
    return fs_seq, fs_block_type


def parse_spare_data_bigblock(spare: bytes) -> tuple[int, int]:
    if len(spare) < 16:
        return 0, 0
    fs_seq = spare[3] | (spare[4] << 8) | (spare[5] << 16)
    fs_block_type = spare[12]
    return fs_seq, fs_block_type


def scan_filesystem_offsets(raw: bytes, page_size: int = 0x200, spare_size: int = 0x10,
                            pages_per_block: int = 0x40) -> list[int]:
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

        if fs_seq != 0 and (fs_block_type & 0x3F) in (FsRootEntry, FsRootEntryAlt):
            block_idx = page_idx // pages_per_block
            block_offset = block_idx * pages_per_block * page_size
            if block_offset not in offsets:
                offsets.append(block_offset)

    return offsets


def parse_header(image: bytes) -> dict[str, int]:
    return {name: struct.unpack_from(fmt, image, off)[0] for name, off, fmt in HEADER_FIELDS}


def scan_bootloaders(image: bytes, start: int = 0x8000, end: int = 0x200000) -> list[dict[str, int | str]]:
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


def format_decrypt_status(stage: dict[str, object]) -> str:
    if stage.get("decrypted") is not None:
        return "ok"
    error = stage.get("decrypt_error")
    return str(error) if error else "n/a"


def diff_count(a: bytes, b: bytes) -> int:
    return sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))


def diff_ranges(a: bytes, b: bytes, limit: int = 10) -> list[tuple[int, int]]:
    size = min(len(a), len(b))
    out: list[tuple[int, int]] = []
    start = None
    for i in range(size):
        if a[i] != b[i]:
            if start is None:
                start = i
        elif start is not None:
            out.append((start, i))
            if len(out) >= limit:
                return out
    if start is not None and len(out) < limit:
        out.append((start, size))
    if len(a) != len(b) and len(out) < limit:
        out.append((size, max(len(a), len(b))))
    return out


# ---------------------------------------------------------------------------
# Commands: info, compare, extract
# ---------------------------------------------------------------------------

def run_info(image_path: Path, secret_1bl: bytes | None = None, cpu_key: bytes | None = None) -> None:
    raw = image_path.read_bytes()
    logical, is_stripped = maybe_strip_ecc(raw)
    nand_type = detect_nand_type(raw)
    header = parse_header(logical)

    print("=" * 64)
    print("  NAND Image Summary")
    print("=" * 64)
    print(f"  File               : {image_path}")
    print(f"  Raw size           : 0x{len(raw):X} ({len(raw):,} bytes)")
    print(f"  Raw SHA-256        : {sha256_hex(raw)}")
    print(f"  Stripped           : {is_stripped}")
    print(f"  Logical size       : 0x{len(logical):X} ({len(logical):,} bytes)")
    print(f"  Logical SHA-256    : {sha256_hex(logical)}")
    print(f"  Detected NAND type : {nand_type}")

    print("\n  --- Header ---")
    for field, _off, _fmt in HEADER_FIELDS:
        val = header[field]
        print(f"  {field:<18} : {format_value(val)}")

    copyright_str = logical[0x10:0x50].rstrip(b"\x00").decode("ascii", errors="replace")
    if copyright_str:
        print(f"  copyright          : {copyright_str!r}")

    print("\n  --- SMC ---")
    smc_addr = header.get("smc_addr", 0x1000)
    smc_size = header.get("smc_size", 0x3000)
    smc_enc = extract_slice(logical, smc_addr, smc_size)
    if smc_enc and contains_meaningful_data(smc_enc):
        print(f"  Offset             : 0x{smc_addr:X}")
        print(f"  Size               : 0x{smc_size:X}")
        print(f"  Encrypted SHA-256  : {sha256_hex(smc_enc)}")
        smc_dec = decrypt_smc(smc_enc)
        print(f"  Decrypted SHA-256  : {sha256_hex(smc_dec)}")
        if len(smc_dec) >= 0x107:
            print(f"  SMC version bytes  : {smc_dec[0x100:0x107].hex()}")
    else:
        print("  (not found)")

    print("\n  --- Bootloader Chain ---")
    chain = scan_bootloaders(logical)
    if chain:
        dec_chain = decrypt_bootloader_chain(logical, chain, secret_1bl, cpu_key)
        for bl in dec_chain:
            status = format_decrypt_status(bl)
            print(
                f"  {bl['label']:<4}  off=0x{bl['offset']:08X}  "
                f"ver={bl['version']:<6}  size=0x{bl['size']:X}  decrypted={status}"
            )
    else:
        print("  (none found)")

    print("\n  --- Filesystem Offsets ---")
    fs_offsets = scan_filesystem_offsets(raw)
    if fs_offsets:
        print(f"  Spare scanned      : {', '.join(f'0x{off:08X}' for off in sorted(fs_offsets))}")
    else:
        print("  Spare scanned      : none found")
    print(f"  Header fs_offset   : 0x{header.get('fs_offset', 0):08X}")
    print()


def run_compare(path_a: Path, path_b: Path, secret_1bl: bytes | None = None, cpu_key: bytes | None = None) -> None:
    raw_a = path_a.read_bytes()
    raw_b = path_b.read_bytes()
    logical_a, stripped_a = maybe_strip_ecc(raw_a)
    logical_b, stripped_b = maybe_strip_ecc(raw_b)

    print("[Files]")
    print(f"A: {path_a}")
    print(f"   raw size   : {len(raw_a)} (0x{len(raw_a):X})")
    print(f"   raw sha256 : {sha256_hex(raw_a)}")
    print(f"   stripped   : {stripped_a}")
    print(f"   logical sha: {sha256_hex(logical_a)}")
    print(f"B: {path_b}")
    print(f"   raw size   : {len(raw_b)} (0x{len(raw_b):X})")
    print(f"   raw sha256 : {sha256_hex(raw_b)}")
    print(f"   stripped   : {stripped_b}")
    print(f"   logical sha: {sha256_hex(logical_b)}")
    print(f"logical equal : {logical_a == logical_b}")
    print(f"logical diff  : {diff_count(logical_a, logical_b)} / {max(len(logical_a), len(logical_b))}")

    # Headers
    header_a = parse_header(logical_a)
    header_b = parse_header(logical_b)
    print("\n[Header]")
    for field, _off, _fmt in HEADER_FIELDS:
        va = header_a[field]
        vb = header_b[field]
        marker = "==" if va == vb else "!="
        print(f"{field:17} {marker}  A={format_value(va):>18}  B={format_value(vb)}")
    copyright_a = logical_a[0x10:0x50].rstrip(b"\x00")
    copyright_b = logical_b[0x10:0x50].rstrip(b"\x00")
    print(f"{'copyright':17} {'==' if copyright_a == copyright_b else '!='}  A={copyright_a!r}  B={copyright_b!r}")

    # Sections
    kv_a = extract_slice(logical_a, header_a["kv_addr"], header_a["kv_size"])
    kv_b = extract_slice(logical_b, header_b["kv_addr"], header_b["kv_size"])
    print("\n[KV]")
    print(f"equal       : {kv_a == kv_b}")
    print(f"diff bytes  : {diff_count(kv_a, kv_b)} / {max(len(kv_a), len(kv_b))}")

    smc_a = extract_slice(logical_a, header_a["smc_addr"], header_a["smc_size"])
    smc_b = extract_slice(logical_b, header_b["smc_addr"], header_b["smc_size"])
    print("\n[SMC (encrypted)]")
    print(f"equal       : {smc_a == smc_b}")
    print(f"diff bytes  : {diff_count(smc_a, smc_b)} / {max(len(smc_a), len(smc_b))}")

    smc_dec_a = decrypt_smc(smc_a) if smc_a else b""
    smc_dec_b = decrypt_smc(smc_b) if smc_b else b""
    print("\n[SMC (decrypted)]")
    print(f"equal       : {smc_dec_a == smc_dec_b}")
    print(f"diff bytes  : {diff_count(smc_dec_a, smc_dec_b)} / {max(len(smc_dec_a), len(smc_dec_b))}")
    if smc_dec_a and smc_dec_b:
        if len(smc_dec_a) >= 0x107:
            print(f"SMC version bytes A: {smc_dec_a[0x100:0x107].hex()}")
        if len(smc_dec_b) >= 0x107:
            print(f"SMC version bytes B: {smc_dec_b[0x100:0x107].hex()}")

    smc_config_off_a = header_a["smc_config_offset"] or 0x3DF0000
    smc_config_off_b = header_b["smc_config_offset"] or 0x3DF0000
    smc_config_a = extract_slice(logical_a, smc_config_off_a, 0x10000)
    smc_config_b = extract_slice(logical_b, smc_config_off_b, 0x10000)
    print("\n[SMC Config]")
    print(f"equal       : {smc_config_a == smc_config_b}")
    print(f"diff bytes  : {diff_count(smc_config_a, smc_config_b)} / {max(len(smc_config_a), len(smc_config_b))}")
    print(f"SMC Config A meaningful: {contains_meaningful_data(smc_config_a)}")
    print(f"SMC Config B meaningful: {contains_meaningful_data(smc_config_b)}")

    # Filesystem Detection
    print("\n[Filesystem Detection]")
    nand_type_a = detect_nand_type(raw_a)
    nand_type_b = detect_nand_type(raw_b)
    print(f"NAND type A: {nand_type_a}")
    print(f"NAND type B: {nand_type_b}")

    fs_offsets_a = scan_filesystem_offsets(raw_a)
    fs_offsets_b = scan_filesystem_offsets(raw_b)
    if fs_offsets_a:
        print(f"Filesystem offsets A: {', '.join(f'0x{off:08X}' for off in sorted(fs_offsets_a))}")
    else:
        print("Filesystem offsets A: none found (eMMC or no spare data)")
    if fs_offsets_b:
        print(f"Filesystem offsets B: {', '.join(f'0x{off:08X}' for off in sorted(fs_offsets_b))}")
    else:
        print("Filesystem offsets B: none found (eMMC or no spare data)")
    print(f"Header fs_offset A: 0x{header_a.get('fs_offset', 0):08X}")
    print(f"Header fs_offset B: 0x{header_b.get('fs_offset', 0):08X}")

    # Bootloaders
    chain_a = scan_bootloaders(logical_a)
    chain_b = scan_bootloaders(logical_b)
    print("\n[Bootloader Chain]")
    print("A:")
    for bl in chain_a:
        print(
            f"  {bl['label']:4} off=0x{bl['offset']:06X} ver={bl['version']} "
            f"size=0x{bl['size']:X} aligned=0x{bl['aligned_size']:X}"
        )
    print("B:")
    for bl in chain_b:
        print(
            f"  {bl['label']:4} off=0x{bl['offset']:06X} ver={bl['version']} "
            f"size=0x{bl['size']:X} aligned=0x{bl['aligned_size']:X}"
        )

    print("\n[Bootloader Stage Diffs]")
    for left, right in zip(chain_a, chain_b):
        size = min(int(left["aligned_size"]), int(right["aligned_size"]))
        left_bytes = extract_slice(logical_a, int(left["offset"]), size)
        right_bytes = extract_slice(logical_b, int(right["offset"]), size)
        print(
            f"{left['label']:4} A@0x{int(left['offset']):06X} B@0x{int(right['offset']):06X} "
            f"diff={diff_count(left_bytes, right_bytes)} / {size}"
        )
    if len(chain_a) != len(chain_b):
        print(f"stage count differs: A={len(chain_a)} B={len(chain_b)}")

    # Decryption comparison
    dec_a = decrypt_bootloader_chain(logical_a, chain_a, secret_1bl, cpu_key)
    dec_b = decrypt_bootloader_chain(logical_b, chain_b, secret_1bl, cpu_key)

    print("\n[Bootloader Decryption]")
    print(f"1BL key provided : {secret_1bl is not None}")
    print(f"CPU key provided : {cpu_key is not None}")
    print("A:")
    for stage in dec_a:
        if str(stage["name"]) in DECRYPTABLE_BOOTLOADERS:
            print(f"  {stage['label']:4} {format_decrypt_status(stage)}")
    print("B:")
    for stage in dec_b:
        if str(stage["name"]) in DECRYPTABLE_BOOTLOADERS:
            print(f"  {stage['label']:4} {format_decrypt_status(stage)}")

    comparable = False
    print("\n[Bootloader Decrypted Diffs]")
    for left, right in zip(dec_a, dec_b):
        if str(left["name"]) not in DECRYPTABLE_BOOTLOADERS or str(right["name"]) not in DECRYPTABLE_BOOTLOADERS:
            continue
        left_dec = left.get("decrypted")
        right_dec = right.get("decrypted")
        if isinstance(left_dec, bytes) and isinstance(right_dec, bytes):
            comparable = True
            print(
                f"{left['label']:4} diff={diff_count(left_dec, right_dec)} / {max(len(left_dec), len(right_dec))}"
            )
            if left_dec != right_dec:
                for start, end in diff_ranges(left_dec, right_dec):
                    print(f"  range       : 0x{start:08X}-0x{end - 1:08X} ({end - start} bytes)")
        else:
            print(
                f"{left['label']:4} unavailable "
                f"A={format_decrypt_status(left)} B={format_decrypt_status(right)}"
            )
    if len(dec_a) != len(dec_b):
        print(f"stage count differs: A={len(dec_a)} B={len(dec_b)}")
    elif not comparable:
        print("no decrypted stages available to compare")


def save_file(target_dir: Path, name: str, data: bytes, info: str = "") -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / name
    out_path.write_bytes(data)
    info_str = f" {info}" if info else ""
    print(f"  Saved {name:<32} ({len(data):>10,} bytes){info_str}")


def run_extract(
    image_path: Path,
    output_dir: Path,
    secret_1bl: bytes | None = None,
    cpu_key: bytes | None = None,
    prefix: str = "",
) -> None:
    raw = image_path.read_bytes()
    logical, is_stripped = maybe_strip_ecc(raw)
    header = parse_header(logical)
    bootloader_dir = output_dir / "bootloaders"

    print("=" * 64)
    print("  Extracting NAND Components")
    print("=" * 64)
    print(f"  Image              : {image_path}")
    print(f"  Output directory   : {output_dir}/")
    print(f"  Prefix             : {prefix!r}")
    print()

    # Raw & Stripped
    save_file(output_dir, f"{prefix}nand_raw.bin", raw, "(raw image)")
    if is_stripped:
        save_file(output_dir, f"{prefix}nand_stripped.bin", logical, "(spare data removed)")

    # Header info text
    hdr_lines = [
        f"NAND Header Summary for {image_path.name}",
        "=" * 48,
        f"Raw size        : {len(raw)} bytes (0x{len(raw):X})",
        f"Raw SHA-256     : {sha256_hex(raw)}",
        f"Logical size    : {len(logical)} bytes (0x{len(logical):X})",
        f"Logical SHA-256 : {sha256_hex(logical)}",
        f"Stripped        : {is_stripped}",
        "",
        "Header fields:",
    ]
    for field, _off, _fmt in HEADER_FIELDS:
        hdr_lines.append(f"  {field:<18}: {format_value(header[field])}")
    copyright_str = logical[0x10:0x50].rstrip(b"\x00").decode("ascii", errors="replace")
    if copyright_str:
        hdr_lines.append(f"  copyright         : {copyright_str!r}")
    hdr_path = output_dir / f"{prefix}header_info.txt"
    hdr_path.write_text("\n".join(hdr_lines) + "\n")
    print(f"  Saved {hdr_path.name:<32} (header summary)")

    # KeyVault
    kv_addr = header.get("kv_addr", 0x4000)
    kv_size = header.get("kv_size", 0x4000)
    kv_data = extract_slice(logical, kv_addr, kv_size)
    if kv_data:
        save_file(output_dir, f"{prefix}keyvault.bin", kv_data, f"(offset: 0x{kv_addr:X})")

    # SMC
    smc_addr = header.get("smc_addr", 0x1000)
    smc_size = header.get("smc_size", 0x3000)
    smc_enc = extract_slice(logical, smc_addr, smc_size)
    if smc_enc and contains_meaningful_data(smc_enc):
        save_file(output_dir, f"{prefix}smc_encrypted.bin", smc_enc, f"(offset: 0x{smc_addr:X})")
        smc_dec = decrypt_smc(smc_enc)
        save_file(output_dir, f"{prefix}smc_decrypted.bin", smc_dec, "(decrypted)")
        if len(smc_dec) >= 0x107:
            print(f"  SMC version bytes: {smc_dec[0x100:0x107].hex()}")

    # SMC Config
    smc_config_off = header.get("smc_config_offset", 0x3DF0000)
    smc_config = extract_slice(logical, smc_config_off, 0x10000)
    if smc_config and contains_meaningful_data(smc_config):
        save_file(output_dir, f"{prefix}smc_config.bin", smc_config, f"(offset: 0x{smc_config_off:X})")

    # Bootloaders
    print("\n[Bootloaders]")
    chain = scan_bootloaders(logical)
    if chain:
        for bl in chain:
            bl_data = extract_slice(logical, int(bl["offset"]), int(bl["aligned_size"]))
            save_file(bootloader_dir, f"{prefix}{bl['label']}_encrypted.bin", bl_data,
                      f"(offset: 0x{bl['offset']:X}, ver: {bl['version']})")

        dec_chain = decrypt_bootloader_chain(logical, chain, secret_1bl, cpu_key)
        for stage in dec_chain:
            name = str(stage["name"])
            label = str(stage["label"])
            if name not in DECRYPTABLE_BOOTLOADERS:
                continue
            decrypted = stage.get("decrypted")
            error = stage.get("decrypt_error")
            if isinstance(decrypted, bytes):
                save_file(bootloader_dir, f"{prefix}{label}_decrypted.bin", decrypted, f"(decrypted {name})")
            elif error:
                print(f"  SKIP  {label:<32} (decryption failed: {error})")
    else:
        print("  (no bootloaders found)")

    # Filesystem Regions
    print("\n[Filesystem Regions]")
    nand_type = detect_nand_type(raw)
    print(f"  NAND type          : {nand_type}")
    fs_offsets = scan_filesystem_offsets(raw)
    if fs_offsets:
        fs_dir = output_dir / "filesystems"
        for i, off in enumerate(sorted(fs_offsets)):
            test_size = min(0x100000, len(logical) - off)
            if test_size > 0:
                fs_data = extract_slice(logical, off, test_size)
                save_file(fs_dir, f"{prefix}filesystem_{i:02d}_offset_0x{off:08X}.bin", fs_data)

    print()
    print(f"Extraction complete -> {output_dir}/")


# ---------------------------------------------------------------------------
# CLI Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nandtool",
        description="Xbox 360 NAND Image Tool — inspect, compare, and extract NAND images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # info
    p_info = sub.add_parser("info", help="Inspect NAND header, bootloader chain, SMC, and filesystem offsets.")
    p_info.add_argument("image", type=Path, help="Path to NAND image file")
    p_info.add_argument("--secret-1bl", dest="secret_1bl", help="Hex 1BL key used for CB/CF decryption")
    p_info.add_argument("--secret-1bl-file", dest="secret_1bl_file", type=Path, help="File containing 1BL key")
    p_info.add_argument("--cpu-key", dest="cpu_key", help="Hex CPU key used for paired CB/CD decryption")
    p_info.add_argument("--cpu-key-file", dest="cpu_key_file", type=Path, help="File containing CPU key")

    # compare
    p_comp = sub.add_parser("compare", help="Compare two NAND images section by section.")
    p_comp.add_argument("image_a", type=Path, help="Path to first NAND image (A)")
    p_comp.add_argument("image_b", type=Path, help="Path to second NAND image (B)")
    p_comp.add_argument("--secret-1bl", dest="secret_1bl", help="Hex 1BL key used for CB/CF decryption")
    p_comp.add_argument("--secret-1bl-file", dest="secret_1bl_file", type=Path, help="File containing 1BL key")
    p_comp.add_argument("--cpu-key", dest="cpu_key", help="Hex CPU key used for paired CB/CD decryption")
    p_comp.add_argument("--cpu-key-file", dest="cpu_key_file", type=Path, help="File containing CPU key")

    # extract
    p_ext = sub.add_parser("extract", help="Extract raw/stripped images, header, KV, SMC, bootloaders, and filesystems.")
    p_ext.add_argument("image", type=Path, help="Path to NAND image file")
    p_ext.add_argument("-o", "--output", type=Path, dest="output_dir", default=None,
                       help="Output directory (default: <image_name>_extracted/)")
    p_ext.add_argument("--prefix", default="", help="Prefix added to all extracted filenames")
    p_ext.add_argument("--secret-1bl", dest="secret_1bl", help="Hex 1BL key used for CB/CF decryption")
    p_ext.add_argument("--secret-1bl-file", dest="secret_1bl_file", type=Path, help="File containing 1BL key")
    p_ext.add_argument("--cpu-key", dest="cpu_key", help="Hex CPU key used for paired CB/CD decryption")
    p_ext.add_argument("--cpu-key-file", dest="cpu_key_file", type=Path, help="File containing CPU key")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    secret_1bl = load_and_validate_key(
        getattr(args, "secret_1bl", None),
        getattr(args, "secret_1bl_file", None),
        "secret-1bl",
    )
    cpu_key = load_and_validate_key(
        getattr(args, "cpu_key", None),
        getattr(args, "cpu_key_file", None),
        "cpu-key",
    )

    if args.command == "info":
        if not args.image.exists():
            print(f"Error: file not found: {args.image}", file=sys.stderr)
            sys.exit(1)
        run_info(args.image, secret_1bl=secret_1bl, cpu_key=cpu_key)

    elif args.command == "compare":
        if not args.image_a.exists():
            print(f"Error: file not found: {args.image_a}", file=sys.stderr)
            sys.exit(1)
        if not args.image_b.exists():
            print(f"Error: file not found: {args.image_b}", file=sys.stderr)
            sys.exit(1)
        run_compare(args.image_a, args.image_b, secret_1bl=secret_1bl, cpu_key=cpu_key)

    elif args.command == "extract":
        if not args.image.exists():
            print(f"Error: file not found: {args.image}", file=sys.stderr)
            sys.exit(1)
        out = args.output_dir or (args.image.parent / f"{args.image.stem}_extracted")
        run_extract(args.image, output_dir=out, secret_1bl=secret_1bl, cpu_key=cpu_key, prefix=args.prefix)


if __name__ == "__main__":
    main()
