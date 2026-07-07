# Heavy WIP

# Basic Exploit

Unsigned shader (KK hack), exploited to point at any addr in the hv?

The task is to get data to an address to get pointed at and executed?

No code execution yet, so we need external hardware. Glitch chip was considered and even used but theres a single 8051 core already on the motherboard (the SMC); SMC Firmware is an attack surface because the only protection is a static encryption algorithm that we already know.

Aim to trigger a DMA read NAND-to-SDRAM

SMC has no DMA read access / for the required location, so it cant be done directly from the firmware.

GPU JTAG does have DMA read access.

SMC has unpopulated headers on the board with access from the SMC firmware? DBG_LED 0-3 iirc

Use JTAG wiring (SMC DBG_LED to GPU JTAG port) and you now have access to a NAND-to-SDRAM DMA read.

Can now read JTAG payload from NAND, and point to it using the KK exploit?

Put the exploit payload where the cpu gets current time

# Use the exploit

Payload known to do 3 things:

XeLL image: 
- Load and execute XeLL from NAND

Old 1f freeBOOT dual-nand image: 
- Load and execute freeboot.bin from NAND
- Reboot into second NAND?

Modern 2f freeBOOT image: 
- Load and execute freeboot.bin from NAND
- Applies second patchslots to KHV?
- freeBOOT loads patches from nand and applies them in memory
- Reboot into hacked Xbox OS