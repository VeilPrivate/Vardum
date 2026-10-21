/**
 * @veil/device — deniable encrypted vaults (web parity, extracted from the
 * live bundle index-CXHmaNHA.js + Vaults-DKxWFv05.js on Sept 19 2026).
 *
 * Container format (byte-exact):
 *   - 24 MB fixed-size block of CSPRNG bytes (24 MB = 25,165,824; the size
 *     never hints at content). Legacy containers: 32 MB / 4 MB keep working.
 *   - Format v2 (Batch C, A4a; kdf label ".../v2"): slot at offset T =
 *     [16B salt][12B header iv][32B AES-GCM(header: u32 body length ‖ 12B body iv)]
 *     [4B random][body ct]. Nothing in the slot is readable without the
 *     passphrase — an unused slot (random bytes) and a used one look the same.
 *     AAD binds the slot index, so slots can't be swapped.
 *   - Format v1 (pre-Batch-C, still readable): [u32 BE ct.length][16B salt][12B iv][ct]
 *     — the plaintext length revealed a used hidden slot (review finding A4a).
 *   - Outer/decoy volume at offset 0; hidden volume at
 *     12,582,912 (24 MB container) / 16,777,216 (32 MB) / 2,097,152 (4 MB).
 *   - Opening ALWAYS derives a key for, and tries, BOTH slots (constant work).
 *   - Volume plaintext = JSON { files: [{ name, type, size, data(base64) }] },
 *     encrypted with AES-256-GCM under PBKDF2-SHA256(passphrase, salt, 600k).
 *   - File limit 8 MB; encrypted volume must fit its 12 MB slot.
 *
 * Web flow parity: create -> UploadPrivateFile(container.bin) -> VeilVault
 * record { name, container_uri, byte_length, kdf, cipher: 'AES-GCM-256' }.
 * Unlock -> vaultFileSignedUrl({file_uri}) -> fetch -> try outer, then hidden.
 */
import { randomBytes, toB64, utf8, fromB64, hkdf, fromUtf8 } from '../../crypto-core/src/index';
import { aesGcmKey, pbkdf2Sha256Bytes, VAULT_KDF_LABEL, VAULT_PBKDF2_ITERATIONS, PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS } from './kdf';

export const CONTAINER_BYTES = 25165824; // 24 MB (web YE)
export const HIDDEN_OFFSET_24MB = 12582912; // web JE
export const HIDDEN_OFFSET_32MB = 16777216; // web XE (legacy containers)
export const HIDDEN_OFFSET_4MB = 2097152; // web qE (legacy containers)
export const SLOT_BYTES = 12582912; // each volume slot is 12 MB
export const VAULT_FILE_LIMIT_BYTES = 8388608; // 8 MB per file (web KE)
export const VAULT_CIPHER = 'AES-GCM-256';

export interface VaultFileEntry {
  name: string;
  type: string;
  size: number;
  /** base64 file bytes */
  data: string;
}

export interface VaultManifest {
  files: VaultFileEntry[];
}

export interface VolumeBlob {
  salt: Uint8Array;
  iv: Uint8Array;
  ct: Uint8Array;
}

export type VaultStage = 'derive' | 'encrypt' | 'container';

export interface CreateVaultArgs {
  passphrase: string;
  file: { name: string; type: string; bytes: Uint8Array };
  hiddenPassphrase?: string | null;
  hiddenFile?: { name: string; type: string; bytes: Uint8Array } | null;
  onStage?: (s: VaultStage) => void;
}

export interface OpenVaultResult {
  partition: 'outer' | 'hidden';
  manifest: VaultManifest;
}

/** web eD(): file entry with 8 MB limit; data base64 (btoa chunked on web). */
export function vaultFileEntry(name: string, type: string, bytes: Uint8Array): VaultFileEntry {
  if (bytes.byteLength > VAULT_FILE_LIMIT_BYTES) {
    throw new Error('File exceeds the 8 MB limit for deniable containers');
  }
  return { name, type: type || 'application/octet-stream', size: bytes.byteLength, data: toB64(bytes) };
}

/**
 * Batch C (A4c; review P3 R7): the kdf label comes from the relay record, so
 * only the known shape is accepted — `PBKDF2-SHA256-<n>` or `PBKDF2-SHA256-<n>/v2`
 * with n inside the app-wide PBKDF2 bounds. A missing label is a pre-label
 * record (600k, format v1). Anything else is refused, never guessed.
 */
export function parseVaultKdfLabel(kdf: string | undefined | null): { iterations: number; format: 1 | 2 } {
  if (kdf === undefined || kdf === null || kdf === '') return { iterations: VAULT_PBKDF2_ITERATIONS, format: 1 };
  const m = /^PBKDF2-SHA256-(\d{6,7})(\/v2)?$/.exec(String(kdf));
  const n = m ? parseInt(m[1], 10) : NaN;
  if (!m || !Number.isInteger(n) || n < PBKDF2_MIN_ITERATIONS || n > PBKDF2_MAX_ITERATIONS) throw new Error('This vault uses an unsupported format.');
  return { iterations: n, format: m[2] ? 2 : 1 };
}

/** web GE(): kdf label -> iterations (bounded; see parseVaultKdfLabel). */
export function parseVaultKdf(kdf: string | undefined): number {
  return parseVaultKdfLabel(kdf).iterations;
}

// ---------- Batch C (A4a): container format v2 ----------

const V2_HEADER_BYTES = 64; // salt 16 | header iv 12 | header ct 32 | random 4
const v2Aad = (part: 'hdr' | 'body', slot: number) => utf8(`vardum-vault-v2:${part}:${slot}`);

/** Encrypt a volume as a v2 slot image (no plaintext length anywhere). */
export async function encryptVolumeV2(passphrase: string, manifest: VaultManifest, slot: 0 | 1): Promise<Uint8Array> {
  const salt = randomBytes(16);
  const ivh = randomBytes(12);
  const ivb = randomBytes(12);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const body = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivb as unknown as BufferSource, additionalData: v2Aad('body', slot) as unknown as BufferSource },
    key, utf8(JSON.stringify(manifest)) as unknown as BufferSource,
  ));
  if (V2_HEADER_BYTES + body.length > SLOT_BYTES) throw new Error('Encrypted payload does not fit its slot');
  const hdrPt = new Uint8Array(16);
  new DataView(hdrPt.buffer).setUint32(0, body.length);
  hdrPt.set(ivb, 4);
  const hdrCt = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivh as unknown as BufferSource, additionalData: v2Aad('hdr', slot) as unknown as BufferSource },
    key, hdrPt as unknown as BufferSource,
  ));
  const out = new Uint8Array(V2_HEADER_BYTES + body.length);
  out.set(salt, 0);
  out.set(ivh, 16);
  out.set(hdrCt, 28); // 32 bytes (16 + tag)
  out.set(randomBytes(4), 60);
  out.set(body, V2_HEADER_BYTES);
  return out;
}

/** Try a v2 slot; null on any failure. The key is always derived (constant work). */
export async function readVolumeSlotV2(container: Uint8Array, offset: number, slot: 0 | 1, passphrase: string, iterations: number): Promise<VaultManifest | null> {
  if (container.length < offset + V2_HEADER_BYTES) return null;
  const salt = container.slice(offset, offset + 16);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, iterations));
  try {
    const hdr = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: container.slice(offset + 16, offset + 28) as unknown as BufferSource, additionalData: v2Aad('hdr', slot) as unknown as BufferSource },
      key, container.slice(offset + 28, offset + 60) as unknown as BufferSource,
    ));
    const len = new DataView(hdr.buffer, hdr.byteOffset).getUint32(0);
    if (len < 17 || V2_HEADER_BYTES + len > SLOT_BYTES || offset + V2_HEADER_BYTES + len > container.length) return null;
    const pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: hdr.slice(4, 16) as unknown as BufferSource, additionalData: v2Aad('body', slot) as unknown as BufferSource },
      key, container.slice(offset + V2_HEADER_BYTES, offset + V2_HEADER_BYTES + len) as unknown as BufferSource,
    ));
    return JSON.parse(new TextDecoder().decode(pt)) as VaultManifest;
  } catch {
    return null;
  }
}

/** web tD(): encrypt a volume payload (fresh 16B salt + 12B IV, AES-256-GCM). */
export async function encryptVolume(passphrase: string, manifest: VaultManifest): Promise<VolumeBlob> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const plaintext = utf8(JSON.stringify(manifest));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, plaintext as unknown as BufferSource),
  );
  if (32 + ct.length > SLOT_BYTES) throw new Error('Encrypted payload does not fit its slot');
  return { salt, iv, ct };
}

/** web nD(): write a volume into its slot (32-byte header + ciphertext). */
export function writeVolumeSlot(container: Uint8Array, offset: number, vol: VolumeBlob): void {
  const header = new Uint8Array(32);
  new DataView(header.buffer).setUint32(0, vol.ct.length);
  header.set(vol.salt, 4);
  header.set(vol.iv, 20);
  container.set(header, offset);
  container.set(vol.ct, offset + 32);
}

/** web rD(): try to open a volume slot; null on any failure (no error leak). */
export async function readVolumeSlot(
  container: Uint8Array,
  offset: number,
  passphrase: string,
  iterations: number,
): Promise<VaultManifest | null> {
  if (container.length < offset + 32) return null;
  const ctLen = new DataView(container.slice(offset, offset + 4).buffer as ArrayBuffer).getUint32(0);
  if (ctLen < 17 || ctLen > SLOT_BYTES - 32 || offset + 32 + ctLen > container.length) return null;
  try {
    const salt = container.slice(offset + 4, offset + 20);
    const iv = container.slice(offset + 20, offset + 32);
    const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, iterations));
    const pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        key,
        container.slice(offset + 32, offset + 32 + ctLen) as unknown as BufferSource,
      ),
    );
    return JSON.parse(new TextDecoder().decode(pt)) as VaultManifest;
  } catch {
    return null;
  }
}

/**
 * (b57) Native CSPRNG fill — one bridge call for the whole 24 MB container
 * via VeilCrypto.randomBytesBase64 (SecRandomCopyBytes). The old path was 384
 * chunked react-native-get-random-values calls, which cost several seconds on
 * device. Falls back to the exact same chunked JS path on old binaries / Node
 * tests, so output is byte-equivalent either way (both are pure CSPRNG bytes).
 */
async function fillRandom(container: Uint8Array): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireNativeModule?: <T>(name: string) => T };
    const mod = emc?.requireNativeModule?.<{ randomBytesBase64?: (n: number) => Promise<string> }>('VeilCrypto');
    if (mod?.randomBytesBase64) {
      const t0 = Date.now();
      const b64 = await mod.randomBytesBase64(container.length);
      const bytes = fromB64(b64);
      if (bytes.length === container.length) {
        container.set(bytes);
        console.log(`[veil-rng] fill NATIVE ${container.length} B in ${Date.now() - t0} ms`);
        return;
      }
      console.log(`[veil-rng] native length mismatch (${bytes.length} vs ${container.length}) — JS path`);
    }
  } catch { /* module missing on old binaries — JS path below */ }
  console.log('[veil-rng] fill JS (chunked) — native path unavailable');
  const CHUNK = 65536;
  for (let i = 0; i < container.length; i += CHUNK) {
    // CSPRNG fill (react-native-get-random-values on device, WebCrypto in tests)
    globalThis.crypto.getRandomValues(container.subarray(i, Math.min(i + CHUNK, container.length)));
  }
}

/** web iD(): build the 24 MB container (decoy volume at 0, hidden at 12 MB). */
export async function createVaultContainer(args: CreateVaultArgs): Promise<{ container: Uint8Array; byteLength: number; hasHidden: boolean }> {
  if (!args.passphrase) throw new Error('Passphrase is required');
  const stage = (s: VaultStage) => args.onStage?.(s);

  const container = new Uint8Array(CONTAINER_BYTES);
  await fillRandom(container);

  // Batch C (A4a): format v2 — an unused hidden slot stays pure random bytes,
  // which a used v2 slot is indistinguishable from
  stage('derive');
  container.set(await encryptVolumeV2(args.passphrase, { files: [vaultFileEntry(args.file.name, args.file.type, args.file.bytes)] }, 0), 0);

  stage('encrypt');
  if (args.hiddenPassphrase) {
    if (args.hiddenPassphrase === args.passphrase) throw new Error('The hidden passphrase must be different');
    const hf = args.hiddenFile ?? null;
    container.set(await encryptVolumeV2(args.hiddenPassphrase, { files: hf ? [vaultFileEntry(hf.name, hf.type, hf.bytes)] : [] }, 1), HIDDEN_OFFSET_24MB);
  }

  stage('container');
  return { container, byteLength: CONTAINER_BYTES, hasHidden: !!args.hiddenPassphrase };
}

/** web aD(): unlock — try the decoy volume at 0, then the hidden volume. */
export async function openVaultContainer(container: Uint8Array, passphrase: string, kdf: string | undefined): Promise<OpenVaultResult> {
  if (!passphrase) throw new Error('Passphrase is required');
  const { iterations, format } = parseVaultKdfLabel(kdf);
  let hiddenOffset = HIDDEN_OFFSET_4MB;
  if (container.length >= 33554432) hiddenOffset = HIDDEN_OFFSET_32MB;
  else if (container.length >= CONTAINER_BYTES) hiddenOffset = HIDDEN_OFFSET_24MB;

  // Batch C (A4a): constant work — BOTH slots are always tried (a key is
  // derived for each), so the time taken does not tell which one opened.
  const outer = format === 2
    ? await readVolumeSlotV2(container, 0, 0, passphrase, iterations)
    : await readVolumeSlot(container, 0, passphrase, iterations);
  const hidden = format === 2
    ? await readVolumeSlotV2(container, hiddenOffset, 1, passphrase, iterations)
    : await readVolumeSlot(container, hiddenOffset, passphrase, iterations);
  if (outer) return { partition: 'outer', manifest: outer };
  if (hidden) return { partition: 'hidden', manifest: hidden };

  throw new Error('Wrong passphrase, or the container is corrupted');
}

/** The VeilVault entity record created after upload (web parity). */
export function vaultRecord(name: string, containerUri: string, byteLength: number): Record<string, unknown> {
  return {
    name,
    container_uri: containerUri,
    byte_length: byteLength,
    kdf: VAULT_KDF_LABEL,
    cipher: VAULT_CIPHER,
  };
}

// ---------- b54 (audit M-4): vault names never reach the relay in clear ----------

/** Sealed names look like `enc1:<b64(iv12 || AES-GCM(ct of a 64-byte padded name))>`.
 *  The key is HKDF(identity seed, "vardum-vault-name-v1") — per identity, so a
 *  phrase restore can still read the list; the relay stores only ciphertext of
 *  one fixed size (the name length does not leak). Pre-b54 records keep a
 *  plain `name` and still display. */
export const VAULT_NAME_PREFIX = 'enc1:';
const VAULT_NAME_PADDED = 64;
const VAULT_NAME_MAX_BYTES = VAULT_NAME_PADDED - 2;

async function vaultNameKey(ikSeedB64: string): Promise<CryptoKey> {
  const raw = await hkdf(fromB64(ikSeedB64), utf8('vardum-vault-name-v1'), 'vault-name', 32);
  return crypto.subtle.importKey('raw', raw as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Longest prefix of `name` that fits the padded slot, cut on a code point. */
function fitName(name: string): Uint8Array {
  let out = '';
  for (const ch of Array.from(name)) {
    if (utf8(out + ch).length > VAULT_NAME_MAX_BYTES) break;
    out += ch;
  }
  return utf8(out);
}

export async function sealVaultName(ikSeedB64: string, name: string): Promise<string> {
  const body = fitName(name);
  const padded = new Uint8Array(VAULT_NAME_PADDED);
  new DataView(padded.buffer).setUint16(0, body.length);
  padded.set(body, 2);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, await vaultNameKey(ikSeedB64), padded as unknown as BufferSource));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return VAULT_NAME_PREFIX + toB64(out);
}

/** Display name for a stored record: decrypts sealed names, passes legacy plain
 *  names through, and never throws (an unreadable name shows as "Vault"). */
export async function openVaultName(ikSeedB64: string | null | undefined, stored: string): Promise<string> {
  if (!stored || !stored.startsWith(VAULT_NAME_PREFIX)) return stored;
  if (!ikSeedB64) return 'Vault';
  try {
    const raw = fromB64(stored.slice(VAULT_NAME_PREFIX.length));
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) as unknown as BufferSource }, await vaultNameKey(ikSeedB64), raw.slice(12) as unknown as BufferSource));
    const len = new DataView(pt.buffer, pt.byteOffset).getUint16(0);
    return fromUtf8(pt.subarray(2, 2 + len)) || 'Vault';
  } catch {
    return 'Vault';
  }
}
