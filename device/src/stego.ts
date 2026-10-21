/**
 * @veil/device — steganographic embed/extract (web parity, extracted from
 * the live bundle Tools-ES0JAH-6.js on Sept 19 2026).
 *
 * Payload format (byte-exact):
 *   [8B magic "VEILSTG1"][1B encrypted flag 0|1][4B u32 BE payload length][payload]
 *   max payload 262,144 bytes; message up to 256 KB of text (b57 raise).
 *   encrypted payload (optional passphrase): [16B salt][12B iv][AES-256-GCM ct]
 *   key = PBKDF2-SHA256(passphrase, salt, 600k) — same derivation as vaults.
 *
 * Embedding: LSB into the R,G,B channels (alpha untouched), 1 bit per channel
 * byte, MSB-first, pixels in reading order; capacity check
 *   bits needed = (13 + payload length) * 8  <=  floor(data.length / 4) * 3
 * Output is always PNG (lossless — the payload survives; the web warns that
 * re-uploading through any lossy pipeline destroys it).
 */
import { utf8 } from '../../crypto-core/src/index';
import { aesGcmKey, pbkdf2Sha256Bytes, VAULT_PBKDF2_ITERATIONS } from './kdf';

export const STEGO_MAGIC = 'VEILSTG1';
export const STEGO_HEADER_BYTES = 13;
export const STEGO_MAX_PAYLOAD = 262144; // b57: 32 KB -> 256 KB (owner request)
export const STEGO_MAX_MESSAGE = 262144;

function magicBytes(): Uint8Array {
  return utf8(STEGO_MAGIC);
}

/** web J(): capacity in BITS — floor(pixels) * 3 channel bytes. */
export function stegoCapacityBits(rgbaByteLength: number): number {
  // Batch E (F-7): ONE bit per R, G, B byte. This used to multiply by 8 more, so
  // the capacity checks passed for carriers 8x too small and lsbEmbed silently
  // wrote a truncated stream.
  return Math.floor(rgbaByteLength / 4) * 3;
}

/** web rt(): optional-payload encryption — salt16 + iv12 + AES-256-GCM. */
export async function encryptStegoPayload(message: string, passphrase: string): Promise<Uint8Array> {
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, utf8(message) as unknown as BufferSource),
  );
  const out = new Uint8Array(28 + ct.byteLength);
  out.set(salt, 0);
  out.set(iv, 16);
  out.set(ct, 28);
  return out;
}

/** web it(): payload decryption — salt + iv prefix, AES-256-GCM. */
export async function decryptStegoPayload(payload: Uint8Array, passphrase: string): Promise<string> {
  if (payload.length < 29) throw new Error('Corrupted payload');
  const salt = payload.slice(0, 16);
  const iv = payload.slice(16, 28);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const pt = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      key,
      payload.slice(28) as unknown as BufferSource,
    ),
  );
  return new TextDecoder().decode(pt);
}

/** web at(): build the full embedded stream for an RGBA buffer. */
export async function buildStegoStream(message: string, passphrase: string | null, rgbaLength?: number): Promise<Uint8Array> {
  // Batch E (Superagent round 3, F-7): check the carrier's room BEFORE the (slow)
  // passphrase encryption. Encrypted payloads add salt 16 + iv 12 + tag 16 bytes.
  if (rgbaLength !== undefined && (STEGO_HEADER_BYTES + utf8(message).length + (passphrase ? 44 : 0)) * 8 > stegoCapacityBits(rgbaLength)) {
    throw new Error('Image is too small to hold this message');
  }
  const payload = passphrase ? await encryptStegoPayload(message, passphrase) : utf8(message);
  if (payload.length === 0) throw new Error('Message is empty');
  if (payload.length > STEGO_MAX_PAYLOAD) throw new Error('Message exceeds the 256 KB limit');
  const stream = new Uint8Array(STEGO_HEADER_BYTES + payload.length);
  stream.set(magicBytes(), 0);
  stream[8] = passphrase ? 1 : 0;
  new DataView(stream.buffer).setUint32(9, payload.length);
  stream.set(payload, STEGO_HEADER_BYTES);
  return stream;
}

/** web at() LSB write: bits into R,G,B of each pixel, MSB-first, alpha untouched. */
export function lsbEmbed(rgba: Uint8Array, stream: Uint8Array): void {
  const bits = stream.length * 8;
  if (bits > stegoCapacityBits(rgba.length)) throw new Error('Image is too small to hold this message');
  let u = 0;
  for (let p = 0; p < rgba.length && u < bits; p += 4) {
    for (let c = 0; c < 3 && u < bits; c++) {
      rgba[p + c] = (rgba[p + c] & 0xfe) | ((stream[u >> 3] >> (7 - (u & 7))) & 1);
      u++;
    }
  }
}

/** web ot(): LSB read back n bytes from an RGBA buffer. */
export function lsbExtract(rgba: Uint8Array, byteCount: number): Uint8Array {
  const out = new Uint8Array(byteCount);
  const bits = byteCount * 8;
  let a = 0;
  for (let p = 0; p < rgba.length && a < bits; p += 4) {
    for (let c = 0; c < 3 && a < bits; c++) {
      out[a >> 3] |= (rgba[p + c] & 1) << (7 - (a & 7));
      a++;
    }
  }
  return out;
}

/** web st(): extract a hidden message from RGBA pixels. */
export async function extractStego(rgba: Uint8Array, passphrase: string | null): Promise<string> {
  const header = lsbExtract(rgba, STEGO_HEADER_BYTES);
  if (new TextDecoder().decode(header.slice(0, 8)) !== STEGO_MAGIC) {
    throw new Error('No Vardum payload found in this image');
  }
  const encrypted = header[8] === 1;
  const payloadLen = new DataView(header.buffer).getUint32(9);
  if (payloadLen > STEGO_MAX_PAYLOAD || STEGO_HEADER_BYTES + payloadLen > stegoCapacityBits(rgba.length) / 8) {
    throw new Error('Corrupted payload');
  }
  const payload = lsbExtract(rgba, STEGO_HEADER_BYTES + payloadLen).slice(STEGO_HEADER_BYTES);
  if (encrypted) {
    if (!passphrase) throw new Error('This payload is encrypted — enter the passphrase');
    return decryptStegoPayload(payload, passphrase);
  }
  return new TextDecoder().decode(payload);
}
