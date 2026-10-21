/*
 * PBKDF2-HMAC-SHA256 (RFC 8018 section 5.2) — plain C, no libc, no
 * allocation. Output is byte-identical to javax.crypto
 * "PBKDF2WithHmacSHA256", WebCrypto deriveBits and @noble/hashes
 * pbkdf2(sha256, ...). See pbkdf2_sha256.c for why it is fast.
 */
#ifndef VEIL_PBKDF2_SHA256_H
#define VEIL_PBKDF2_SHA256_H

#include <stddef.h>
#include <stdint.h>

/*
 * Derives dk_len bytes into `out`. password/salt may be any length (an empty
 * password is allowed; callers reject an empty salt). iterations >= 1.
 */
void veil_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                             const uint8_t *salt, size_t salt_len,
                             uint32_t iterations,
                             uint8_t *out, size_t dk_len);

#endif
