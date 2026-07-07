#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
from pathlib import Path


DEFAULT_A = Path("/home/e3xp0/Projects/GxOSS/gxBuild/References/xebuild_bb.bin")
DEFAULT_B = Path("/home/e3xp0/Projects/GxOSS/gxBuild/References/gxbuild_bb.bin")

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


# Filesystem spare data scanning constants
FsRootEntry = 0x30
FsRootEntryAlt = 0x2C

def parse_spare_data_smallblock(spare: bytes) -> tuple[int, int]:
    """
    Parse spare data (16 bytes) in SmallBlock format.
    Returns (FsSequence, FsBlockType)
    """
    if len(spare) < 16:
        return 0, 0
    
    # FsSequence bytes: 2,3,4,6
    fs_seq = spare[2] | (spare[3] << 8) | (spare[4] << 16) | (spare[6] << 24)
    
    # FsBlockType is in EDC[0] which is at byte 12
    fs_block_type = spare[12]
    
    return fs_seq, fs_block_type


def parse_spare_data_bigblock(spare: bytes) -> tuple[int, int]:
    """
    Parse spare data (16 bytes) in BigBlock format.
    Returns (FsSequence, FsBlockType)
    """
    if len(spare) < 16:
        return 0, 0
    
    # FsSequence bytes: 3,4,5
    fs_seq = spare[3] | (spare[4] << 8) | (spare[5] << 16)
    
    # FsBlockType is in EDC[0] which is at byte 12
    fs_block_type = spare[12]
    
    return fs_seq, fs_block_type


def detect_nand_type(raw: bytes) -> str:
    """
    Detect NAND type by reading spare data at offset 0x4400.
    Returns 'bigblock', 'smallblock', 'bigonsmall', or 'none' (eMMC)
    """
    PAGE_SIZE_WITH_SPARE = 0x210  # 528 bytes (512 + 16)
    
    if len(raw) < 0x4400 + 0x10:
        return "none"
    
    # Read spare data at page that contains 0x4400
    # For 0x210 page+spare size, page containing 0x4400 is:
    page_num = 0x4400 // 0x200  # 0x4400 / 512 = 0x11 = 17
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
    
    # Detect NAND type
    nand_type = detect_nand_type(raw)
    
    # Parse spare data based on type
    if nand_type in ("smallblock", "bigonsmall"):
        parse_func = parse_spare_data_smallblock
    elif nand_type == "bigblock":
        parse_func = parse_spare_data_bigblock
    else:
        # eMMC has no spare data
        return offsets
    
    # Scan each page
    num_pages = len(raw) // page_total
    for page_idx in range(num_pages):
        page_start = page_idx * page_total
        spare_start = page_start + page_size
        spare_end = spare_start + spare_size
        
        if spare_end > len(raw):
            break
        
        spare = raw[spare_start:spare_end]
        fs_seq, fs_block_type = parse_func(spare)
        
        # Check for filesystem markers
        if fs_seq != 0 and fs_block_type in (FsRootEntry, FsRootEntryAlt):
            # Calculate block number and offset
            block_idx = page_idx // pages_per_block
            block_offset = block_idx * pages_per_block * page_size
            if block_offset not in offsets:
                offsets.append(block_offset)
    
    return offsets


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
            start = None
    if start is not None and len(out) < limit:
        out.append((start, size))
    if len(a) != len(b) and len(out) < limit:
        out.append((size, max(len(a), len(b))))
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


def format_decrypt_status(stage: dict[str, object]) -> str:
    if stage.get("decrypted") is not None:
        return "ok"
    error = stage.get("decrypt_error")
    return str(error) if error else "n/a"


def compare_sections(name: str, a: bytes, b: bytes) -> None:
    print(f"\n[{name}]")
    print(f"equal       : {a == b}")
    print(f"diff bytes  : {diff_count(a, b)} / {max(len(a), len(b))}")
    if a != b:
        for start, end in diff_ranges(a, b):
            print(f"range       : 0x{start:08X}-0x{end - 1:08X} ({end - start} bytes)")


def compare_headers(a: bytes, b: bytes) -> None:
    ha = parse_header(a)
    hb = parse_header(b)
    print("\n[Header]")
    for field, _off, _fmt in HEADER_FIELDS:
        va = ha[field]
        vb = hb[field]
        marker = "==" if va == vb else "!="
        print(f"{field:17} {marker}  A={format_value(va):>18}  B={format_value(vb)}")
    copyright_a = a[0x10:0x50].rstrip(b"\x00")
    copyright_b = b[0x10:0x50].rstrip(b"\x00")
    print(f"{'copyright':17} {'==' if copyright_a == copyright_b else '!='}  A={copyright_a!r}  B={copyright_b!r}")


def compare_bootloaders(a: bytes, b: bytes) -> None:
    chain_a = scan_bootloaders(a)
    chain_b = scan_bootloaders(b)
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
        left_bytes = extract_slice(a, int(left["offset"]), size)
        right_bytes = extract_slice(b, int(right["offset"]), size)
        print(
            f"{left['label']:4} A@0x{int(left['offset']):06X} B@0x{int(right['offset']):06X} "
            f"diff={diff_count(left_bytes, right_bytes)} / {size}"
        )
    if len(chain_a) != len(chain_b):
        print(f"stage count differs: A={len(chain_a)} B={len(chain_b)}")


def compare_bootloader_decryption(a: bytes, b: bytes, secret_1bl: bytes | None, cpu_key: bytes | None) -> None:
    chain_a = decrypt_bootloader_chain(a, scan_bootloaders(a), secret_1bl, cpu_key)
    chain_b = decrypt_bootloader_chain(b, scan_bootloaders(b), secret_1bl, cpu_key)

    print("\n[Bootloader Decryption]")
    print(f"1BL key provided : {secret_1bl is not None}")
    print(f"CPU key provided : {cpu_key is not None}")
    print("A:")
    for stage in chain_a:
        if str(stage["name"]) not in {"CB", "CD", "CE", "CF", "CG"}:
            continue
        print(f"  {stage['label']:4} {format_decrypt_status(stage)}")
    print("B:")
    for stage in chain_b:
        if str(stage["name"]) not in {"CB", "CD", "CE", "CF", "CG"}:
            continue
        print(f"  {stage['label']:4} {format_decrypt_status(stage)}")

    comparable = False
    print("\n[Bootloader Decrypted Diffs]")
    for left, right in zip(chain_a, chain_b):
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
    if len(chain_a) != len(chain_b):
        print(f"stage count differs: A={len(chain_a)} B={len(chain_b)}")
    elif not comparable:
        print("no decrypted stages available to compare")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two gxBuild/xeBuild NAND images.")
    parser.add_argument("image_a", nargs="?", default=str(DEFAULT_A))
    parser.add_argument("image_b", nargs="?", default=str(DEFAULT_B))
    parser.add_argument("--secret-1bl", dest="secret_1bl", help="Hex 1BL key used for CB/CF decryption")
    parser.add_argument(
        "--secret-1bl-file",
        dest="secret_1bl_file",
        type=Path,
        help="File containing a raw or ASCII-hex 1BL key",
    )
    parser.add_argument("--cpu-key", dest="cpu_key", help="Hex CPU key used for paired CB/CD decryption")
    parser.add_argument(
        "--cpu-key-file",
        dest="cpu_key_file",
        type=Path,
        help="File containing a raw or ASCII-hex CPU key",
    )
    args = parser.parse_args()

    path_a = Path(args.image_a)
    path_b = Path(args.image_b)
    secret_1bl = load_and_validate_key(args.secret_1bl, args.secret_1bl_file, "secret-1bl")
    cpu_key = load_and_validate_key(args.cpu_key, args.cpu_key_file, "cpu-key")
    raw_a = load(path_a)
    raw_b = load(path_b)
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

    compare_headers(logical_a, logical_b)

    header_a = parse_header(logical_a)
    header_b = parse_header(logical_b)

    kv_a = extract_slice(logical_a, header_a["kv_addr"], header_a["kv_size"])
    kv_b = extract_slice(logical_b, header_b["kv_addr"], header_b["kv_size"])
    compare_sections("KV", kv_a, kv_b)

    smc_a = extract_slice(logical_a, header_a["smc_addr"], header_a["smc_size"])
    smc_b = extract_slice(logical_b, header_b["smc_addr"], header_b["smc_size"])
    compare_sections("SMC (encrypted)", smc_a, smc_b)

    smc_dec_a = decrypt_smc(smc_a) if smc_a else b""
    smc_dec_b = decrypt_smc(smc_b) if smc_b else b""
    compare_sections("SMC (decrypted)", smc_dec_a, smc_dec_b)
    if smc_dec_a and smc_dec_b:
        print(f"SMC version bytes A: {smc_dec_a[0x100:0x107].hex()}")
        print(f"SMC version bytes B: {smc_dec_b[0x100:0x107].hex()}")

    smc_config_off_a = header_a["smc_config_offset"] or 0x3DF0000
    smc_config_off_b = header_b["smc_config_offset"] or 0x3DF0000
    smc_config_a = extract_slice(logical_a, smc_config_off_a, 0x10000)
    smc_config_b = extract_slice(logical_b, smc_config_off_b, 0x10000)
    compare_sections("SMC Config", smc_config_a, smc_config_b)
    print(f"SMC Config A meaningful: {contains_meaningful_data(smc_config_a)}")
    print(f"SMC Config B meaningful: {contains_meaningful_data(smc_config_b)}")

    # Filesystem detection via spare data scanning
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
    
    # Compare with header fields
    print(f"Header fs_offset A: 0x{header_a.get('fs_offset', 0):08X}")
    print(f"Header fs_offset B: 0x{header_b.get('fs_offset', 0):08X}")

    compare_bootloaders(logical_a, logical_b)
    compare_bootloader_decryption(logical_a, logical_b, secret_1bl, cpu_key)


if __name__ == "__main__":
    main()
