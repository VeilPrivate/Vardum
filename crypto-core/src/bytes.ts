/**
 * @veil/crypto-core — byte & encoding helpers.
 * Mirrors the web bundle exactly: b64 via btoa/atob semantics, Bitcoin base58
 * alphabet for veil_id / fingerprints, TextEncoder for UTF-8.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function toB64(bytes: Uint8Array): string {
  // b199 (owner hardware test Oct 16: a 2.4 MB photo took up to 12 s around
  // the native AES call): one String.fromCharCode per byte is millions of
  // tiny string appends under Hermes. Build the binary string in chunks
  // instead (8 KB at a time) — same output, a fraction of the work.
  const CHUNK = 0x2000; // 8 KB: well inside Hermes's argument-count limit for apply()
  let s = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return btoaSafe(s);
}

export function fromB64(b64: string): Uint8Array {
  const s = atobSafe(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function btoaSafe(s: string): string {
  if (typeof btoa === 'function') return btoa(s);
  return (Buffer as any).from(s, 'binary').toString('base64');
}

function atobSafe(s: string): string {
  try {
    if (typeof atob === 'function') return atob(s);
    return (Buffer as any).from(s, 'base64').toString('binary');
  } catch (e) {
    // b188-r6 (owner repro: "Found invalid character when decoding base 64
    // string" on first forum send, exact field unknown): name the culprit.
    // The preview is only as long as needed to identify WHICH field it is —
    // group key, identity seed, peer key, sig — without leaking material.
    let bad = -1;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (!/[A-Za-z0-9+/=\s]/.test(c)) { bad = i; break; }
    }
    const m = /length (\d+)|position (\d+)/.exec(String((e as Error).message || e));
    throw new Error(
      `base64 decode failed: len=${s.length} firstBadCharIdx=${bad >= 0 ? bad : (m ? (m[1] || m[2]) : '?')} ` +
      `preview=<${s.slice(0, 8)}…> (${String((e as Error).message || e).slice(0, 90)})`
    );
  }
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Bitcoin-alphabet base58, leading zero bytes -> '1' (matches bundle impl). */
export function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}
