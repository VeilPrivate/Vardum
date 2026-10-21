/**
 * @veil/crypto-core — vault key derivation (extracted params).
 *
 * Live bundle params (claims register, verified):
 *  - Vault unlock: PBKDF2-SHA256, 600,000 iterations for new vaults
 *    (existing vaults keep their recorded parameter — forward compatibility).
 *  - Lock codes: PBKDF2-SHA256, 210,000 iterations, per-config salt.
 *  - Containers: AES-256-GCM, fixed-size layout, hidden volume;
 *    `has_hidden_volume` must NEVER be stored truthfully server-side.
 *
 * NOTE: the exact 32MB fixed-layout container byte format (header offsets,
 * hidden-volume placement) is ported in a follow-up extraction pass; the KDF +
 * AEAD primitives below are verified against the live app.
 */

import { fromB64 } from './bytes';
import { utf8 } from './bytes';

export const VAULT_PBKDF2_ITERATIONS_NEW = 600_000;
export const LOCK_CODE_PBKDF2_ITERATIONS = 210_000;

/** Vault unlock key: PBKDF2-SHA256(passcode, salt, iterations). */
/** Batch F (round-4 review R4-4-23): the supported PBKDF2 range. An imported
 *  .veilenc file names its own count; 1e10 used to freeze the app. */
export const VAULT_PBKDF2_ITERATIONS_MAX = 1_000_000;
/** Batch H (R6-1-12): matches PBKDF2_MIN_ITERATIONS in vendor/device/src/kdf.ts */
export const VAULT_PBKDF2_ITERATIONS_MIN = 100_000;

export async function deriveVaultKey(passcode: string, saltB64: string, iterations = VAULT_PBKDF2_ITERATIONS_NEW): Promise<CryptoKey> {
  // Batch H (round-6 review R6-1-12): the same lower bound as the device KDF (100k)
  if (!Number.isInteger(iterations) || iterations < VAULT_PBKDF2_ITERATIONS_MIN || iterations > VAULT_PBKDF2_ITERATIONS_MAX) {
    throw new Error('This file\'s key settings are out of the supported range, so it was not opened.');
  }
  const base = await crypto.subtle.importKey('raw', utf8(passcode) as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64) as BufferSource, iterations },
    base,
    256,
  );
  return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function vaultEncrypt(key: CryptoKey, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, plaintext as BufferSource));
}

export async function vaultDecrypt(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ciphertext as BufferSource));
}
