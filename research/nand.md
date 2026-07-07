# retail image
header
SMC
Keyvault
cb / cb_a
possible cb_b
cd
ce
cf / cg 0
cf / cg 1
SMC Config / XConfig
FlashFS

# ? 1f jtag xell image
header
JTAG Payload
SMC
Keyvault
cb
cd
ce
cf / cg 0 4532 or 4548
xell 1f
fuses
SMC Config / XConfig

# 1f jtag freeboot image
???

# 2f jtag freeboot image
header
JTAG Payload
SMC
Keyvault
cb
cd
ce
cf / cg 0 4532 or 4548
cf / cg 1 whatever
xell 2f
freeboot
patchset
fuses
SMC Config / XConfig
FlashFS

# glitch1 xell image
header
SMC
Keyvault
cb
cd
xell gggggg
SMC Config / XConfig

# glitch2/3 xell image
header
SMC
Keyvault
cb_a 9188 mfg
possible cb_x
cb_b 9188 mfg
cd
xell gggggg
SMC Config / XConfig

# glitch1/2/3 freeboot image
header
SMC
Keyvault
cb / cb_a
possible cb_x
possible cb_b
cd
ce
xell gggggg
cf / cg 0
cf / cg 1
patchset
fuses (g2m only)
SMC Config / XConfig
FlashFS

# devkit image
header
SMC
Keyvault
sb
sc
sd
se
SMC Config / XConfig
FlashFS

# rgloader glitch image
header
SMC
Keyvault
cb / cb_a
possible cb_x
possible cb_b
cd
se
xell
patchset
fuses
SMC Config / XConfig
FlashFS

# rgloader jtag image
???

# xdkbuild image
header
SMC
Keyvault
cb / cb_a
possible cb_x
possible cb_b
sc
sd
se

# ? devgl image
header
SMC
Keyvault
sb
sc
cd
ce
cf / cg 0
cf / cg 1