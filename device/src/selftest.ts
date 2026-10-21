/**
 * @veil/device — On-device crypto self-test (web parity: Stego's "Crypto
 * self-test" mode, Sept 19 build). Web's copy: "runs the protocol's parity
 * suite against this device's encryption core." Native equivalent: a small,
 * fast set of REAL roundtrips against the exact primitives the app depends
 * on, run live on THIS device/binary — useful for confirming a build's
 * SubtleCrypto + native-module surface actually works before trusting it
 * with real conversations.
 */
import {
  randomBytes, toB64, utf8, fromUtf8,
  mlkemKeypair, mlkemEncap, mlkemDecap,
  sha256,
} from '../../crypto-core/src/index';

/** local hex helper (vendor crypto-core does not export toHex) */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
import { getNativeCrypto } from './applock';

export interface SelfTestResult {
  name: string;
  ok: boolean;
  detail: string;
  ms: number;
}

async function timed(name: string, fn: () => Promise<string>): Promise<SelfTestResult> {
  const t0 = Date.now();
  try {
    const detail = await fn();
    return { name, ok: true, detail, ms: Date.now() - t0 };
  } catch (e) {
    return { name, ok: false, detail: String((e as Error).message || e), ms: Date.now() - t0 };
  }
}

/** AES-256-GCM roundtrip via SubtleCrypto — the cipher every message, vault and note uses. */
async function testAesGcm(): Promise<string> {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = randomBytes(12);
  const plaintext = utf8('veil-self-test-' + Date.now());
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, plaintext as unknown as BufferSource);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, ct);
  if (fromUtf8(new Uint8Array(pt)) !== fromUtf8(plaintext)) throw new Error('roundtrip mismatch');
  return 'encrypt → decrypt roundtrip matched';
}

/** X25519 key agreement roundtrip — the classical half of every session handshake. */
async function testX25519(): Promise<string> {
  const a = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const b = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const sharedA = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: b.publicKey } as unknown as EcdhKeyDeriveParams, a.privateKey, 256));
  const sharedB = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: a.publicKey } as unknown as EcdhKeyDeriveParams, b.privateKey, 256));
  if (toHex(sharedA) !== toHex(sharedB)) throw new Error('shared secrets diverged');
  return `both sides derived the same 256-bit secret (${toHex(sharedA).slice(0, 12)}…)`;
}

/** ML-KEM-768 encapsulate/decapsulate roundtrip — the post-quantum half of every handshake. */
async function testMlKem(): Promise<string> {
  const kp = await mlkemKeypair();
  const { ct, secret: sentSecret } = await mlkemEncap(kp.pub);
  const recvSecret = await mlkemDecap(kp.priv, ct);
  if (toB64(recvSecret) !== toB64(sentSecret)) throw new Error('encap/decap secrets diverged');
  return 'encapsulated and decapsulated to the same shared secret';
}

/** SHA-256 determinism sanity — the hash used throughout HKDF, fingerprints and write-hashes. */
async function testSha256(): Promise<string> {
  const msg = utf8('veil-protocol-v1');
  const h1 = toHex(await sha256(msg));
  const h2 = toHex(await sha256(msg));
  if (h1 !== h2) throw new Error('non-deterministic hash');
  if (h1.length !== 64) throw new Error(`unexpected digest length ${h1.length}`);
  return `sha256("veil-protocol-v1") = ${h1.slice(0, 16)}…`;
}

/** PBKDF2 path check — confirms whether this binary has the compiled native
 *  module (fast) or falls back to the JS path (slow; App Lock unlock takes
 *  seconds on this path). Uses the lowest iteration count the native module
 *  accepts (RV-27: native PBKDF2 refuses < 100,000, same as kdf.ts); natively
 *  that is well under a second, so the self-test doesn't freeze the UI. This
 *  checks WHICH path runs, not the production 210,000-iteration timing. */
async function testPbkdf2Path(): Promise<string> {
  const native = getNativeCrypto();
  if (!native) return 'JS fallback only — native module not compiled into this build yet (App Lock unlock will take several seconds)';
  const t0 = Date.now();
  await native.pbkdf2Sha256('veil-self-test', 'ab'.repeat(16), 100_000, 32);
  const ms = Date.now() - t0;
  return `native module responded in ${ms} ms for 100,000 iterations — App Lock unlock will be fast`;
}

/** (b66) Stego full round-trip ON THIS DEVICE: build the stream, LSB-embed it
 *  into pixels, encode a real PNG, decode that PNG back, and extract with the
 *  passphrase — proving encode/decode + LSB + GCM all interop in this binary.
 *  If this passes but extracting a Photos-saved image fails, the Photos
 *  save/load path altered the file, not the stego code. */
async function testStegoRoundtrip(): Promise<string> {
  const { buildStegoStream, lsbEmbed, extractStego } = await import('./stego');
  const { decodePng, encodePng } = await import('./png');
  const msg = 'veil-stego-selftest-' + Date.now() + ' — the words travel inside, invisible.';
  const pass = 'stego-selftest-passphrase';
  const W = 64, H = 64;
  const rgba = new Uint8Array(W * H * 4);
  // pseudo-random carrier (deterministic so failures are reproducible)
  for (let i = 0; i < rgba.length; i++) rgba[i] = (i * 31 + 7) & 0xff;
  for (let p = 3; p < rgba.length; p += 4) rgba[p] = 255;
  lsbEmbed(rgba, await buildStegoStream(msg, pass));
  const png = encodePng({ width: W, height: H, rgba });
  const again = decodePng(new Uint8Array(png));
  if (again.width !== W || again.height !== H) throw new Error(`png decode size mismatch (${again.width}x${again.height})`);
  const out = await extractStego(again.rgba, pass);
  if (out !== msg) throw new Error('extracted message mismatch');
  // and the no-passphrase variant
  lsbEmbed(again.rgba, await buildStegoStream(msg + ' (plain)', null));
  const png2 = encodePng({ width: W, height: H, rgba: again.rgba });
  const out2 = await extractStego(decodePng(new Uint8Array(png2)).rgba, null);
  if (out2 !== msg + ' (plain)') throw new Error('plain extract mismatch');
  return 'embed → PNG → decode → extract matched (passphrase and plain)';
}

/** Run the whole suite. Independent tests — one failure doesn't stop the rest. */
export async function runSelfTest(): Promise<SelfTestResult[]> {
  return [
    await timed('AES-256-GCM', testAesGcm),
    await timed('X25519 key agreement', testX25519),
    await timed('ML-KEM-768 (post-quantum)', testMlKem),
    await timed('SHA-256', testSha256),
    await timed('PBKDF2 native module', testPbkdf2Path),
    await timed('Stego PNG round-trip', testStegoRoundtrip),
  ];
}
