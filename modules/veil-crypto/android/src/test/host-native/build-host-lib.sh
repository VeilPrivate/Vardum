#!/usr/bin/env bash
# Builds a host (Windows x64) copy of libveilkdf from the SAME C sources the
# APK ships, so Pbkdf2Sha256Test can run the native code on a PC JVM:
#
#   bash src/test/host-native/build-host-lib.sh <out-dir>
#   cd <app>/android && ./gradlew :veil-crypto:testDebugUnitTest -PveilkdfLibDir=<out-dir>
#
# Uses only the NDK's clang + lld and the JDK's jni.h; the DLL is
# freestanding (no CRT), which is why crt.c supplies memset/memcpy.
set -euo pipefail
OUT="${1:?usage: build-host-lib.sh <out-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../../main/cpp"
NDK="${ANDROID_NDK_HOME:-$LOCALAPPDATA/Android/Sdk/ndk/26.1.10909125}"
BIN="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin"
JDK="${JAVA_HOME:?set JAVA_HOME to a JDK 17}"
mkdir -p "$OUT/stub"
: > "$OUT/stub/stdio.h" # jni.h includes it; nothing from it is used
cat > "$OUT/crt.c" <<'C'
#include <stddef.h>
void *memset(void *d, int c, size_t n) { unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, size_t n) { unsigned char *p = d; const unsigned char *q = s; while (n--) *p++ = *q++; return d; }
C
for f in "$SRC/pbkdf2_sha256.c" "$SRC/veil_kdf_jni.c" "$OUT/crt.c"; do
  "$BIN/clang" --target=x86_64-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector \
    -I"$OUT/stub" -I"$JDK/include" -I"$JDK/include/win32" -I"$SRC" -Wall -Wextra \
    -c "$f" -o "$OUT/$(basename "$f" .c).obj"
done
cp "$BIN/ld.lld.exe" "$OUT/lld-link.exe" # lld picks its COFF linker flavour from its file name
PATH="$BIN:$PATH" "$OUT/lld-link.exe" -dll -noentry -nodefaultlib -out:"$OUT/veilkdf.dll" \
  "$OUT/pbkdf2_sha256.obj" "$OUT/veil_kdf_jni.obj" "$OUT/crt.obj"
echo "built $OUT/veilkdf.dll"
