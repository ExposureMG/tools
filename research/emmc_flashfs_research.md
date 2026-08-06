# eMMC (Corona 4GB) Filesystem Building: Research Notes

## The Core Difference: How Spare Data Works

### Small Block / Big Block NAND — Spare-driven metadata

In NAND flash images (`page_length = 528`, data=512 + spare=16 per page), every page has
a 16-byte **spare area** that carries the FlashFS metadata:

| Spare byte(s) | Meaning |
|---|---|
| `[0]` or `[5]` | Bad block marker (0xFF = good) |
| `[1..2]` | Block index in blockmap chain |
| `[0..4,6]` | Sequence number (packed, varies by type) |
| `[7..8]` | FlashFS size field |
| `[9]` | Page count |
| `[C]` | Block type (`0x30`=FlashFS root, `0x31-0x39`=mobile data, etc.) |
| `[C..F]` | ECC (26-bit computed CRC) |

The FlashFS **root block** is identified at parse time by scanning spare data for blocks with
`block_type == 0x30` and a non-zero sequence number — the highest sequence wins.

The FlashFS block chain is linked purely through the **blockmap** stored in the root block's
data pages (even pages = blockmap, odd pages = file entries). Each `uint16_t` entry in the
blockmap is a forward pointer to the next block in a chain, with `0x1fff` = end, `0x1ffe` = free,
`0x1ffb` = reserved.

---

## eMMC (Corona 4GB) — No Spare. Completely Different Metadata Mechanism.

On Corona 4GB, `page_length = 512` (no spare bytes at all). The eMMC controller does not
provide any out-of-band storage. So:

- There is **no spare to read for block type, sequence, or bad-block flags**
- There is **no ECC appended to pages**
- The blockmap chain pointer format is the same in the data pages
- But the **root block location and filesystem version** must come from somewhere else

### Where Corona stores FS metadata: the **Config Block**

On the eMMC, the console reserves the last few blocks of the image (the "reserve area") as
a **config block**. At `reserve_block_idx - 4` is the `config_block_idx`.

The config block contains a structure (`XeCoronaFsData` in gxbuild3,
`XECONFIGDATA` / `COFIG_BLOCK` in xebuild references):

```
Offset  Size  Field
0x00    0x14  section_digest         (SHA1 hash of all data in this struct)
0x04    0x04  unknown1
0x08    0x04  fs_version             (FlashFS sequence number → replaces spare seq)
0x0C    0x02  fs_block_idx           (FlashFS root block index → replaces spare detection)
0x0E    0x02  unknown2
0x10    0x02  mobile1_block_idx      (first mobile data block)
0x12    0x02  mobile1_length         (mobile data 1 length)
0x14    0x08  unknown3
0x1C    0x02  mobile2_block_idx
0x1E    0x02  mobile2_length
0x20    0x1D0 reserved
```

> **This is the structural replacement for the spare-based FlashFS root detection on eMMC.**
> Without a valid `XeCoronaFsData` in the config block, the console cannot find the FlashFS.

---

## What gxbuild3 Currently Does for eMMC

### What works:

1. **Image creation**: `FlashBlockDriver::create_image()` correctly allocates `page_length = 512`
   for `Corona4GB`, no ECC, correct block geometry (`0x4000` blocks × `0xC00` count)
2. **Parsing**: `FlashImage::parse()` → `open_continue()` → `load_flash_config()` for Corona4GB
   sets the correct spare type, block counts, etc.
3. **Synthetic image**: `resolve_synthetic_target()` for `SyntheticNandFamily::Emmc` sets
   `image_length = 0x03000000`, `flash_config = Corona4GB`, `patchslot_base = 0x000B0000`
4. `XeCoronaFsData` struct is **defined** in `FlashFileSystem.hpp` and used in `FlashFileSystem`
   constructors
5. `FlashFileSystem` has a `m_corona_data` member and uses it in `load()` to get version:
   ```cpp
   // If corona_data is set and has a version, use it instead of spare
   if (!m_corona_data || m_corona_data->fs_version == 0) {
       // Read spare data (FAILS for eMMC - no spare)
       auto spare = m_block_driver->read_lil_block_spare(block_idx);
   } else {
       m_version = m_corona_data->fs_version;  // Corona path
   }
   ```
6. `create_defaults()` in `FlashFileSystem` correctly updates `m_corona_data->fs_version`
   and `m_corona_data->fs_block_idx` if the `m_corona_data` pointer is set

### What is MISSING / Broken:

#### 1. `FlashImage::parse()` — Corona FS data is never populated

In `FlashImage.cpp` L1711–1722, when the FlashFS is loaded at parse time:
```cpp
auto fs_driver = std::make_shared<gxbuild3::utils::FlashBlockDriver>(image.driver);
gxbuild3::bootloaders::FlashFileSystem filesystem(fs_driver);  // ← no corona_data passed!
```
The `FlashFileSystem` is constructed without `corona_data`, so even if a Corona config block
exists on the real eMMC image, the `fs_version` from the config block is **never read** and
passed into the FlashFileSystem. The `XeCoronaFsData` is never parsed from the image.

The `FlashImage` struct has a `corona_fs_data` field:
```cpp
std::optional<gxbuild3::bootloaders::XeCoronaFsData> corona_fs_data;
```
**But nothing ever populates it.** It is set nowhere in the codebase.

#### 2. Config block is never read on parse

There is no code path that:
- Reads the config block at `driver.config_block_idx()`
- Parses the `XeCoronaFsData` from it
- Uses `fs_block_idx` from that struct to locate the FlashFS root

The eMMC FlashFS root detection relies **entirely** on `detect_flashfs_root_from_spare()` in
`FlashImage.cpp` which calls `read_lil_block_spare()` — which **returns `std::nullopt` for eMMC**
because `m_page_length < 0x210`. So on eMMC the FlashFS is **never detected**.

#### 3. Config block is never written on build

In `FlashFileSystem::save()` L605–613, when the spare is available it writes the block type
and version into it:
```cpp
auto spare = m_block_driver->read_lil_block_spare(block_idx);
if (spare) {  // ← returns nullopt for eMMC, entire spare update is silently skipped
    ...write spare seq field, block type...
}
```
The spare write being silently skipped is fine for eMMC (no spare). But nothing **writes the
XeCoronaFsData config block** after saving the FlashFS. So the console will never find the FS.

#### 4. `FlashFileSystem` constructor used in the build path has no corona_data

In the build path at `FlashImage.cpp` L2096–2097:
```cpp
auto fs_driver = std::make_shared<gxbuild3::utils::FlashBlockDriver>(built.driver);
gxbuild3::bootloaders::FlashFileSystem filesystem(fs_driver);  // ← no corona_data!
```
Even if `XeCoronaFsData` were populated on the `flash_image_t`, it is never connected to the
`FlashFileSystem` being created here, so `create_defaults()` never updates it, and nothing
gets written to the config block.

---

## What Needs to Be Implemented

### Step 1: Parse the config block on eMMC images

Add a function `read_corona_config_block()` called from `FlashImage::parse()` when
`driver.flash_config() == FlashConfig::Corona4GB`:

```cpp
std::optional<XeCoronaFsData> read_corona_config_block(
        const gxbuild3::utils::FlashBlockDriver& driver) {
    // Config block is at reserve_block_idx - 4, data size = 0x200 (one page)
    const uint32_t config_offset = 
        (driver.config_block_idx()) * driver.block_length();
    
    auto data = driver.read(config_offset, sizeof(XeCoronaFsData));
    if (!data) return std::nullopt;
    
    XeCoronaFsData cfg{};
    std::memcpy(&cfg, data->data(), sizeof(XeCoronaFsData));
    // XeCoronaFsData fields are little-endian on eMMC
    cfg.fs_version = bswap32(cfg.fs_version);   // if stored BE
    cfg.fs_block_idx = bswap16(cfg.fs_block_idx);
    cfg.mobile1_block_idx = bswap16(cfg.mobile1_block_idx);
    cfg.mobile2_block_idx = bswap16(cfg.mobile2_block_idx);
    return cfg;
}
```

> [!NOTE]
> Endian-ness of `XeCoronaFsData` needs to be verified against a real Corona dump.
> The digest at offset 0x00 is SHA1 of the rest of the structure. Verify the field
> byte order by reading a known-good Corona image.

### Step 2: Use `corona_fs_data` to locate the FlashFS root

In `FlashImage::parse()`, after `image.nand_results = read(image.driver)`:
```cpp
if (image.driver.flash_config() == FlashConfig::Corona4GB) {
    image.corona_fs_data = read_corona_config_block(image.driver);
    if (image.corona_fs_data && image.corona_fs_data->fs_block_idx != 0) {
        image.nand_results->fs_block_idx = image.corona_fs_data->fs_block_idx;
        image.nand_results->fs_offset = 
            image.corona_fs_data->fs_block_idx * image.driver.lil_block_length();
    }
}
```

And in `FlashFileSystem::load()` — already handled if `corona_data` is passed in the
constructor. Fix: pass `corona_data` when constructing `FlashFileSystem` for parse:
```cpp
auto corona = std::make_shared<XeCoronaFsData>(*image.corona_fs_data);
gxbuild3::bootloaders::FlashFileSystem filesystem(fs_driver, corona);
```

### Step 3: Write the config block after FlashFS save

After `filesystem.save(fs_root_block_idx)` in `build()`, for eMMC:
```cpp
if (built.driver.flash_config() == FlashConfig::Corona4GB) {
    // Get the updated corona data from the filesystem
    auto& corona = filesystem.corona_data();
    if (corona) {
        // Compute SHA1 digest of the struct (bytes 0x04..end)
        // Write to config block
        write_corona_config_block(built.driver, *corona);
    }
}
```

The write function:
```cpp
bool write_corona_config_block(gxbuild3::utils::FlashBlockDriver& driver,
                               XeCoronaFsData& cfg) {
    // Compute SHA1 of config data (offset 0x04 to sizeof(XeCoronaFsData))
    // cfg.section_digest = SHA1(cfg bytes [0x04..end])
    
    // Byte-swap fields before writing
    XeCoronaFsData out = cfg;
    out.fs_version = bswap32(cfg.fs_version);
    out.fs_block_idx = bswap16(cfg.fs_block_idx);
    // ... etc
    
    const uint32_t config_offset = 
        driver.config_block_idx() * driver.block_length();
    return driver.write(config_offset,
                        reinterpret_cast<const uint8_t*>(&out),
                        sizeof(XeCoronaFsData));
}
```

### Step 4: `FlashFileSystem::save()` — skip spare logic for eMMC

The `save()` function already does this implicitly (spare `read_lil_block_spare` returns nullopt
for eMMC, so the `if (spare)` block is skipped). **This is correct** — no changes needed here.

### Step 5: Verify `config_block_idx` is calculated correctly for Corona

In `FlashBlockDriver::load_flash_config()` for Corona4GB:
```cpp
m_block_count = 0xC00;
m_reserve_block_idx = 0xC00;   // ← this is past the end!
m_config_block_idx = m_reserve_block_idx - 4;  // = 0xBFC
```

> [!WARNING]
> `m_reserve_block_idx = 0xC00` and `m_config_block_idx = 0xBFC`. The image has
> `0xC00` blocks of size `0x4000` = `0x3000000` bytes total. Block `0xBFC` starts at
> `0xBFC * 0x4000 = 0x2FF0000`. Verify this is the actual location of the config block
> in a real Corona dump (it should be near the end, at `0x2FF0000` or similar).

---

## Summary Table

| Feature | NAND (SB/BB) | eMMC (Corona) | gxbuild3 status |
|---|---|---|---|
| FlashFS root detection | Spare block_type `0x30` scan | Config block `XeCoronaFsData.fs_block_idx` | ❌ eMMC path never implemented |
| FlashFS version | Spare sequence field | Config block `fs_version` | ❌ never read |
| Config block parse | N/A | Read at `config_block_idx * block_length` | ❌ missing |
| Config block write | N/A | Write after FlashFS save | ❌ missing |
| FlashFS data pages | same interleaved blockmap/entries layout | **same format** | ✅ works |
| Spare type/seq write | `write_lil_block_spare()` → spare bytes | None needed | ✅ correctly skipped |
| SHA1 digest of config block | N/A | Required for console to trust it | ❌ not implemented |
| Mobile data block refs | Spare block_type `0x31-0x39` scan | Config block `mobile1_block_idx/length` | ❌ config block not written |
