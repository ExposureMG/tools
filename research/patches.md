# Xbox 360 Patches

## Types

- xeBuild / RGLP
- Loaderpatch
- Embedded

## xeBuild / RGLP

Most common patch format, used by freeBOOT, xeBuild, RGBuild and RGLoader.xex.

Format <address>:<words>:<data>

### xeBuild

Designed by either Ikari or [c0z]

Patch files are multiple sections of patches, delimited by FFFFFFFF. They come in 1, 3 or 4 sections.

JTAG patch files; None applied directly, inserted into the nand image and applied by freeboot.

- 1bl patches (?)
- CB
- CD
- KHV

Glitch patch files, Only KHV applied by freeboot, everything else applied by bootloader.

- CB_B
- CD
- KHV

Addon patches, 1 section, inserted with KHV patches to be applied by freeboot

mitchellwaite has [a repository full of xebuild patchsets](https://github.com/mitchellwaite/xbox360_xebuild_patches).



### RGLP

Same format as xeBuild, havent investigated the binary format yet.

Can be applied directly or by RGLoader.xex. Almost better then freeBOOT as it can be applied to stuff like xam.

Can be found in [RGLoader-Patches](https://github.com/RGLoader/RGLoader-Patches.git).

## LoaderPatch

TXT files, patching engine, by [c0z]?

Can insert compiled byte data or raw asm code.

Compliles and applies on the fly.

Format:

```asm
.data 0x53C0 // Address 0x53C0
48 00 01 68 // Data to insert
.eod

.code b 0x5B4 // PPC ASM at Address 0x5B40
                 #li        %r5, 0x5F00      # patches are at 0x5900 in CD
                 #oris      %r5, %r5, 0x400   # %r5 = address of CD and patches

                 mfmsr     %r7              # get original machine state
                 li        %r8, 0x10
                 andc      %r8, %r7, %r8    # and machine state with 0x
                 li        %r5, 0x200       # 0x0000_0000_0000_0200
                 oris      %r5, %r5, 0x8000 # 0x0000_0000_8000_0200
                 sldi      %r5, %r5, 32     # 0x8000_0200_0000_0000
				 oris      %r5, %r5, 0xC811 # 0x8000_0200_C80F_0000
                 ori       %r5, %r5, 0x0004  # 0x8000_0200_C800_0204
```

Can be found in [RGLoader-Patches](https://github.com/RGLoader/RGLoader-Patches.git).

## Embedded

Allot of patches are embedded into xeBuid directly, mostly smaller ones.

SMC patches and freeBOOT core patches are integrated and triggered via command line option or build type.

wurthless-elektroniks has a good breakdown on these patches at [smc360/hackedsmcs.md](https://github.com/wurthless-elektroniks/smc360/blob/main/docs/hackedsmcs.md).
