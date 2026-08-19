compiling:
zig build

gcc -Os -DUSE_OPENSSL -ffunction-sections -fdata-sections -Wl,--gc-sections -s -o zns zns.c -lcrypto
gcc -Os -DUSE_MBEDTLS -ffunction-sections -fdata-sections -Wl,--gc-sections -s -o zns zns.c -lmbedcrypto
