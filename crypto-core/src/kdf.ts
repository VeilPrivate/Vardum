/**
 * @veil/crypto-core — KDF helpers (WebCrypto only).
 * Semantics extracted from the live bundle:
 *  - hkdf(ikm, salt, info, len)            -> HKDF-SHA256 expand
 *  - advanceChain(chain)                   -> HMAC-SHA256 with label bytes
 *      mk = HMAC(chain, [0x01]), ck' = HMAC(chain, [0x02])
 *  - bip39Seed(words)                      -> PBKDF2-SHA-512, salt 'mnemonic', 2048 iters, 512 bits
 *  - combine(a, b)                         -> plain concatenation (rb() in bundle)
 *  - sessionFingerprint(secret)            -> HEX(SHA-256(secret)) upper, 4-char groups '-'
 */

import { utf8 } from './bytes';

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, len: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: utf8(info) as BufferSource },
    key,
    len * 8,
  );
  return new Uint8Array(bits);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data as BufferSource));
}

export interface ChainAdvance {
  /** next chain key */
  ck: Uint8Array;
  /** message key for this step */
  mk: Uint8Array;
}

/** Symmetric-ratchet chain step (ob() in the bundle). */
export async function advanceChain(chain: Uint8Array): Promise<ChainAdvance> {
  const mk = await hmacSha256(chain, new Uint8Array([1]));
  const ck = await hmacSha256(chain, new Uint8Array([2]));
  return { ck, mk };
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

export function combine(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export async function bip39Seed(words: string[]): Promise<Uint8Array> {
  const material = utf8(words.join(' '));
  const key = await crypto.subtle.importKey('raw', material as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-512', salt: utf8('mnemonic') as BufferSource, iterations: 2048 },
    key,
    512,
  );
  return new Uint8Array(bits);
}

/**
 * veil-ratchet-6 session fingerprint over the full handshake transcript:
 *   SHA-256( lp(label) || lp(field_1) || ... || lp(field_n) )
 * where lp(x) = 4-byte big-endian length || x. Every public handshake value
 * (both session DH pubs, the PQ public key and ciphertext, token, version) and
 * SHA-256(shared) are bound, so any substitution or downgrade by the relay
 * changes the value both users compare. Rendered like sessionFingerprint.
 */
export async function transcriptFingerprint(label: string, fields: Uint8Array[]): Promise<string> {
  const parts = [utf8(label), ...fields];
  const total = parts.reduce((n, p) => n + 4 + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    new DataView(buf.buffer).setUint32(off, p.length);
    buf.set(p, off + 4);
    off += 4 + p.length;
  }
  return sessionFingerprint(buf);
}

/** Session fingerprint: D456-4641-... style (pb() in the bundle). */
export async function sessionFingerprint(secret: Uint8Array): Promise<string> {
  const h = await sha256(secret);
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{1,4}/g)!.join('-');
}
