cmake_minimum_required(VERSION 3.22.1)
project(veilkdf C)

# libveilkdf: PBKDF2-HMAC-SHA256 for Pbkdf2Sha256.kt (see src/main/cpp).
add_library(veilkdf SHARED
  src/main/cpp/pbkdf2_sha256.c
  src/main/cpp/veil_kdf_jni.c
)

# Always optimise, debug builds included: a dev build at -O0 would undo most
# of the speed-up this library exists for.
target_compile_options(veilkdf PRIVATE -O2 -Wall -Wextra)
# 16 KB page alignment (Android 15+ devices with 16 KB pages; harmless on 4 KB).
target_link_options(veilkdf PRIVATE "-Wl,-z,max-page-size=16384")
