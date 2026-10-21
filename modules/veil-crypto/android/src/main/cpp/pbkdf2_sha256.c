/*
 * PBKDF2-HMAC-SHA256 (RFC 8018 section 5.2) for Vardum on Android.
 *
 * Why this exists: the platform's SecretKeyFactory "PBKDF2WithHmacSHA256"
 * (BouncyCastle, Java) took ~41 us per iteration on a 32-bit budget phone —
 * ~8.6 s for the 210k-iteration app passcode and ~25 s per 600k-iteration
 * vault slot. This is the same algorithm with the same output; it is only
 * faster because:
 *   - the HMAC inner/outer pad states are hashed once per call (not per
 *     iteration), so each iteration is exactly two SHA-256 compressions;
 *   - from iteration 2 on, U(j) is fed back as eight 32-bit words straight
 *     into a pre-padded 64-byte block (32 bytes U || 0x80 || zeros ||
 *     bit-length 768), so there is no byte packing, buffering or allocation
 *     in the hot loop;
 *   - it is plain native code, so it runs at full speed in debuggable builds
 *     too (no interpreter/JIT dependence).
 * Iteration count, salt, dkLen and the PRF are untouched: the output is
 * byte-identical to javax.crypto, WebCrypto and @noble/hashes (see the JVM
 * unit test Pbkdf2Sha256Test, which cross-checks this file's code).
 */
#include "pbkdf2_sha256.h"

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t IV[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* One SHA-256 compression of a 16-word (big-endian-decoded) block into state. */
static void compress(uint32_t state[8], const uint32_t block[16]) {
  uint32_t w[64];
  int i;
  for (i = 0; i < 16; i++) w[i] = block[i];
  for (i = 16; i < 64; i++) {
    uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
  uint32_t t1, t2;
  /* 8 rounds per pass; renaming the arguments replaces the h=g, g=f, ... shuffle. */
#define ROUND(a, b, c, d, e, f, g, h, k) \
  t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + (g ^ (e & (f ^ g))) + K[k] + w[k]; \
  t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) | (c & (a | b))); \
  d += t1; \
  h = t1 + t2;
  for (i = 0; i < 64; i += 8) {
    ROUND(a, b, c, d, e, f, g, h, i);
    ROUND(h, a, b, c, d, e, f, g, i + 1);
    ROUND(g, h, a, b, c, d, e, f, i + 2);
    ROUND(f, g, h, a, b, c, d, e, i + 3);
    ROUND(e, f, g, h, a, b, c, d, i + 4);
    ROUND(d, e, f, g, h, a, b, c, i + 5);
    ROUND(c, d, e, f, g, h, a, b, i + 6);
    ROUND(b, c, d, e, f, g, h, a, i + 7);
  }
#undef ROUND
  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void wipe(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
}

/* RV-29: compress() leaves w[64] and its working variables (derived from the
   key pads and U values) on the stack. Wiping inside compress() would cost
   every iteration, so instead, once the derivation is done, this overwrites
   the stack region the nested sha/compress frames used. 1 KiB comfortably
   covers compress (~300 B) under sha_update/sha_final_words. */
__attribute__((noinline)) static void scrub_stack(void) {
  volatile uint8_t pad[1024];
  size_t i;
  for (i = 0; i < sizeof pad; i++) pad[i] = 0;
}

/* ---------- streaming SHA-256 (used outside the hot loop only) ---------- */

typedef struct {
  uint32_t h[8];
  uint8_t buf[64];
  size_t buf_len;
  uint64_t total; /* bytes hashed so far */
} sha256_ctx;

static void block_from_bytes(uint32_t w[16], const uint8_t *p) {
  int i;
  for (i = 0; i < 16; i++, p += 4) {
    w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  }
}

static void sha_init_from(sha256_ctx *c, const uint32_t h[8], uint64_t total) {
  int i;
  for (i = 0; i < 8; i++) c->h[i] = h[i];
  c->buf_len = 0;
  c->total = total;
}

static void sha_update(sha256_ctx *c, const uint8_t *data, size_t len) {
  uint32_t w[16];
  c->total += len;
  while (len > 0) {
    c->buf[c->buf_len++] = *data++;
    len--;
    if (c->buf_len == 64) {
      block_from_bytes(w, c->buf);
      compress(c->h, w);
      c->buf_len = 0;
    }
  }
  wipe(w, sizeof w);
}

/* Finishes the hash; the digest is returned as eight big-endian words. */
static void sha_final_words(sha256_ctx *c, uint32_t out[8]) {
  uint32_t w[16];
  uint64_t bits = c->total * 8;
  size_t i;
  c->buf[c->buf_len++] = 0x80;
  if (c->buf_len > 56) {
    while (c->buf_len < 64) c->buf[c->buf_len++] = 0;
    block_from_bytes(w, c->buf);
    compress(c->h, w);
    c->buf_len = 0;
  }
  while (c->buf_len < 56) c->buf[c->buf_len++] = 0;
  for (i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
  block_from_bytes(w, c->buf);
  compress(c->h, w);
  for (i = 0; i < 8; i++) out[i] = c->h[i];
  wipe(w, sizeof w);
}

static void words_to_bytes(uint8_t out[32], const uint32_t w[8]) {
  int i;
  for (i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(w[i] >> 24);
    out[4 * i + 1] = (uint8_t)(w[i] >> 16);
    out[4 * i + 2] = (uint8_t)(w[i] >> 8);
    out[4 * i + 3] = (uint8_t)w[i];
  }
}

/* ---------- PBKDF2 ---------- */

void veil_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                             const uint8_t *salt, size_t salt_len,
                             uint32_t iterations,
                             uint8_t *out, size_t dk_len) {
  uint8_t k0[64], pad[64], tmp[32], counter[4];
  uint32_t istate[8], ostate[8], u[8], t[8], blk[16], s[8];
  sha256_ctx ctx;
  size_t i, pos;
  uint32_t block_index, j;

  /* HMAC key K0 (RFC 2104): keys longer than the block are hashed first. */
  for (i = 0; i < 64; i++) k0[i] = 0;
  if (password_len > 64) {
    sha_init_from(&ctx, IV, 0);
    sha_update(&ctx, password, password_len);
    sha_final_words(&ctx, u);
    words_to_bytes(k0, u);
  } else {
    for (i = 0; i < password_len; i++) k0[i] = password[i];
  }

  /* Precompute the states after hashing (K0 ^ ipad) and (K0 ^ opad). */
  for (i = 0; i < 8; i++) { istate[i] = IV[i]; ostate[i] = IV[i]; }
  for (i = 0; i < 64; i++) pad[i] = k0[i] ^ 0x36;
  block_from_bytes(blk, pad);
  compress(istate, blk);
  for (i = 0; i < 64; i++) pad[i] = k0[i] ^ 0x5c;
  block_from_bytes(blk, pad);
  compress(ostate, blk);

  for (pos = 0, block_index = 1; pos < dk_len; pos += 32, block_index++) {
    /* U1 = HMAC(P, S || INT_32_BE(i)) */
    counter[0] = (uint8_t)(block_index >> 24);
    counter[1] = (uint8_t)(block_index >> 16);
    counter[2] = (uint8_t)(block_index >> 8);
    counter[3] = (uint8_t)block_index;
    sha_init_from(&ctx, istate, 64);
    sha_update(&ctx, salt, salt_len);
    sha_update(&ctx, counter, 4);
    sha_final_words(&ctx, u);
    words_to_bytes(tmp, u);
    sha_init_from(&ctx, ostate, 64);
    sha_update(&ctx, tmp, 32);
    sha_final_words(&ctx, u);
    for (i = 0; i < 8; i++) t[i] = u[i];

    /* U2..Uc: HMAC over a 32-byte message — one pre-padded block each for the
       inner and outer hash (64 key-pad bytes + 32 message bytes = 768 bits). */
    for (i = 8; i < 15; i++) blk[i] = 0;
    blk[8] = 0x80000000u;
    blk[15] = (64 + 32) * 8;
    for (j = 1; j < iterations; j++) {
      for (i = 0; i < 8; i++) { blk[i] = u[i]; s[i] = istate[i]; }
      compress(s, blk);
      for (i = 0; i < 8; i++) { blk[i] = s[i]; u[i] = ostate[i]; }
      compress(u, blk);
      for (i = 0; i < 8; i++) t[i] ^= u[i];
    }

    words_to_bytes(tmp, t);
    for (i = 0; i < 32 && pos + i < dk_len; i++) out[pos + i] = tmp[i];
  }

  wipe(k0, sizeof k0); wipe(pad, sizeof pad); wipe(tmp, sizeof tmp);
  wipe(istate, sizeof istate); wipe(ostate, sizeof ostate);
  wipe(u, sizeof u); wipe(t, sizeof t); wipe(blk, sizeof blk); wipe(s, sizeof s);
  wipe(&ctx, sizeof ctx);
  scrub_stack();
}
