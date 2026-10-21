/**
 * @veil/crypto-core — account identity (Phase-1 design, verified live).
 *
 * Derivation chain (extracted from the web bundle, byte-exact):
 *   24-word BIP39 phrase
 *     -> PBKDF2-SHA-512('mnemonic', 2048, 512-bit) seed
 *     -> HKDF-SHA256(seed, salt=empty, info='veil-identity-ed25519', 32) = ikSeed
 *     -> Ed25519 private key (PKCS#8 DER prefix + ikSeed)
 *     -> IK_pub (32-byte raw, b64)
 *     -> veil_id  = base58(SHA-256(IK_pub))[0:16]
 *     -> identity fingerprint = full base58(SHA-256(IK_pub)) in 4-char groups
 *
 * SPK is an X25519 keypair (fresh per device); SPK_sig = Ed25519(IK_priv, SPK_pub).
 * PQ prekey is ML-KEM-768. All public material only ever leaves the device.
 */

import { toB64, fromB64, base58, concat, randomBytes, utf8 } from './bytes';
import { PQ_PREKEY_SIG_LABEL } from './constants';
import { hkdf, sha256 } from './kdf';
import { phraseSeed, validatePhrase, entropyToWords } from './bip39';
import { mlkemKeypair, type MlKemKeypairB64 } from './mlkem';

/** 48-byte PKCS#8 DER prefix for a raw Ed25519 seed (xv() in the bundle). */
const PKCS8_ED25519_PREFIX = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32]);

function pkcs8Wrap(seed: Uint8Array): Uint8Array {
  const out = new Uint8Array(48);
  out.set(PKCS8_ED25519_PREFIX, 0);
  out.set(seed, 16);
  return out;
}

/** ikSeed -> Ed25519 keypair; returns raw 32-byte public key. */
export async function ikFromSeed(seed: Uint8Array): Promise<{ pubBytes: Uint8Array; privKey: CryptoKey }> {
  const privKey = await crypto.subtle.importKey('pkcs8', pkcs8Wrap(seed) as BufferSource, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', privKey);
  if (!jwk.x) throw new Error('Could not derive the identity public key');
  return { pubBytes: b64ToBytes(jwk.x), privKey };
}

function b64ToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  return fromB64(b64 + pad);
}

/** veil_id = base58(SHA-256(IK_pub))[0:16] — verified against live relay vectors. */
export async function veilIdFromIkPub(ikPubB64: string): Promise<string> {
  const h = await sha256(fromB64(ikPubB64));
  return base58(h).slice(0, 16);
}

/** Human fingerprint card: full base58 digest in 4-char groups (Iv() in the bundle). */
export async function identityFingerprint(ikPubB64: string): Promise<string> {
  const h = await sha256(fromB64(ikPubB64));
  return (base58(h).match(/.{1,4}/g) || []).join(' ');
}

export interface X25519KeypairB64 {
  pubB64: string;
  privSeedB64: string;
}

/** X25519 SPK (Tv() in the bundle). */
export async function generateSpk(): Promise<X25519KeypairB64> {
  const kp = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey', 'deriveBits'])) as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { pubB64: toB64(pub), privSeedB64: toB64(b64ToBytes(jwk.d!)) };
}

export interface VeilIdentityMaterial {
  mnemonic: string[];
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  spkPubB64: string;
  spkPrivB64: string;
  spkSigB64: string;
  pq: MlKemKeypairB64;
  /** b54: Ed25519(IK, PQ_PREKEY_SIG_LABEL || pq_pub) — published as pq_sig */
  pqSigB64: string;
}

/** Create a brand-new identity (ov+K_ path in the bundle). */
export async function createIdentity(): Promise<VeilIdentityMaterial> {
  const words = await entropyToWords(randomBytes(32));
  return restoreIdentity(words.join(' '), undefined, true);
}

/**
 * Restore an identity from a 24-word phrase.
 * Reproduces the exact veil_id on any device (verified live).
 * If expectedVeilId is provided and mismatches, throws (Dv() in the bundle).
 * The `withFreshPrekeys` flag makes this usable for creation (fresh SPK + PQ pair).
 */
export async function restoreIdentity(
  phrase: string,
  expectedVeilId?: string,
  withFreshPrekeys = false,
): Promise<VeilIdentityMaterial> {
  const words = await validatePhrase(phrase);
  const seed = await phraseSeed(words);
  const ikSeed = await hkdf(seed, new Uint8Array(), 'veil-identity-ed25519', 32);
  const { pubBytes, privKey } = await ikFromSeed(ikSeed);
  const ikPubB64 = toB64(pubBytes);
  const veilId = await veilIdFromIkPub(ikPubB64);
  if (expectedVeilId && veilId !== expectedVeilId) {
    throw new Error('This recovery phrase belongs to a different Vardum identity.');
  }
  const spk = await generateSpk();
  const spkSig = new Uint8Array(await crypto.subtle.sign('Ed25519', privKey, fromB64(spk.pubB64) as BufferSource));
  const pq = await mlkemKeypair();
  return {
    mnemonic: words,
    veilId,
    ikSeedB64: toB64(ikSeed),
    ikPubB64,
    spkPubB64: spk.pubB64,
    spkPrivB64: spk.privSeedB64,
    spkSigB64: toB64(spkSig),
    pq,
    pqSigB64: await signPqPrekey(toB64(ikSeed), pq.pub),
  };
}

/** Re-publish path: existing ikSeed, fresh SPK + PQ prekeys (Ov() in the bundle). */
export async function republishPrekeys(ikSeedB64: string): Promise<{
  ikPubB64: string;
  spkPubB64: string;
  spkPrivB64: string;
  spkSigB64: string;
  pq: MlKemKeypairB64;
  pqSigB64: string;
  veilId: string;
}> {
  const { pubBytes, privKey } = await ikFromSeed(fromB64(ikSeedB64));
  const spk = await generateSpk();
  const spkSig = new Uint8Array(await crypto.subtle.sign('Ed25519', privKey, fromB64(spk.pubB64) as BufferSource));
  const pq = await mlkemKeypair();
  return {
    ikPubB64: toB64(pubBytes),
    spkPubB64: spk.pubB64,
    spkPrivB64: spk.privSeedB64,
    spkSigB64: toB64(spkSig),
    pq,
    pqSigB64: await signPqPrekey(ikSeedB64, pq.pub),
    veilId: await veilIdFromIkPub(toB64(pubBytes)),
  };
}

/** Ed25519 sign with the identity key (kv() in the bundle) — nonce-signed auth. */
export async function ikSign(ikSeedB64: string, messageB64: string): Promise<string> {
  const { privKey } = await ikFromSeed(fromB64(ikSeedB64));
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privKey, fromB64(messageB64) as BufferSource));
  return toB64(sig);
}

/** Ed25519 verify of a peer's SPK signature against their pinned IK (client-side trust anchor). */
export async function verifySpkSig(ikPubB64: string, spkPubB64: string, spkSigB64: string): Promise<boolean> {
  const pubKey = await crypto.subtle.importKey('raw', fromB64(ikPubB64) as BufferSource, { name: 'Ed25519' }, true, ['verify']);
  return crypto.subtle.verify('Ed25519', pubKey, fromB64(spkSigB64) as BufferSource, fromB64(spkPubB64) as BufferSource);
}

/** Generic Ed25519 verify against a peer's raw IK pub (initiator_sig check, SPEC §3.1). */
export async function verifyWithIk(ikPubB64: string, messageB64: string, sigB64: string): Promise<boolean> {
  const pubKey = await crypto.subtle.importKey('raw', fromB64(ikPubB64) as BufferSource, { name: 'Ed25519' }, true, ['verify']);
  return crypto.subtle.verify('Ed25519', pubKey, fromB64(sigB64) as BufferSource, fromB64(messageB64) as BufferSource);
}

function pqPrekeyMessage(pqPubB64: string): Uint8Array {
  return concat(utf8(PQ_PREKEY_SIG_LABEL), fromB64(pqPubB64));
}

/** b54 (Batch A, review H-1): sign the published ML-KEM prekey with the identity key. */
export async function signPqPrekey(ikSeedB64: string, pqPubB64: string): Promise<string> {
  return ikSign(ikSeedB64, toB64(pqPrekeyMessage(pqPubB64)));
}

/** b54: verify a peer's pq_sig against their PINNED / verified IK. Never throws. */
export async function verifyPqPrekeySig(ikPubB64: string, pqPubB64: string, pqSigB64: string): Promise<boolean> {
  if (!ikPubB64 || !pqPubB64 || !pqSigB64) return false;
  try {
    return await verifyWithIk(ikPubB64, toB64(pqPrekeyMessage(pqPubB64)), pqSigB64);
  } catch {
    return false;
  }
}

/** b54 (pre-audit T-1, cross-protocol signature oracle): the identity-bind
 *  challenge is RELAY-CHOSEN. Signing it raw let a malicious relay pick
 *  32 bytes that are its own X25519 key and receive a valid SPK_sig (also a
 *  raw signature over 32 bytes). The client now signs only a domain-separated
 *  message: utf8("vardum-identity-bind-v1:") || nonce || utf8(":" + veil_id). */
export const BIND_SIG_LABEL = 'vardum-identity-bind-v1:';
export function bindChallengeMessage(nonceB64: string, veilId: string): Uint8Array {
  return concat(utf8(BIND_SIG_LABEL), fromB64(nonceB64), utf8(':' + veilId));
}
