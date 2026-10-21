/**
 * @veil/device — private notes (web parity, extracted from the live bundle
 * index-CXHmaNHA.js + Notes-ZChV35c8.js on Sept 19 2026).
 *
 * Web contract:
 *   - a device-local AES-GCM-256 key (web: localStorage `veil_notes_key` JWK;
 *     native: raw key base64 in the secure keystore — never leaves the device);
 *   - note payload { title, body } JSON -> AES-256-GCM, fresh 12-byte IV ->
 *     { payload_ciphertext (b64), payload_iv (b64), byte_length };
 *   - VeilNote entity rows: { payload_ciphertext, payload_iv, byte_length };
 *     nothing but ciphertext server-side. Title lives inside the ciphertext.
 */
import { randomBytes, toB64, utf8, fromB64 } from '../../crypto-core/src/index';
import { aesGcmKey } from './kdf';
import { hkdf } from '../../crypto-core/src/kdf';

export const NOTES_KEY_STORAGE = 'veil_notes_key';
/** Batch C (B8): device-local newest-version-seen per note id */
export const NOTES_VERSIONS_STORAGE = 'veil_notes_versions';

/** Batch C (B8): a note's binding — client-chosen id (32 hex) and version (1, 2, ...). */
export interface NoteMeta { nid: string; version: number }

export function newNoteId(): string {
  return [...randomBytes(16)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** meta stored on a relay row (note_nid, note_v), or null for a pre-Batch-C row */
export function noteMetaOf(row: { note_nid?: unknown; note_v?: unknown }): NoteMeta | null {
  return typeof row.note_nid === 'string' && Number.isInteger(row.note_v) ? { nid: row.note_nid, version: Number(row.note_v) } : null;
}

function noteAad(meta: NoteMeta): Uint8Array {
  return utf8(`vardum-note-v2:${meta.nid}:${meta.version}`);
}

export interface NotePayload {
  title: string;
  body: string;
}

export interface EncryptedNote {
  ciphertext: string; // base64 AES-GCM ct
  iv: string; // base64 12-byte IV
  byteLength: number;
}

export type NotesGet = (key: string) => Promise<string | null>;
export type NotesSet = (key: string, value: string) => Promise<unknown>;

export class NotesStore {
  constructor(private get: NotesGet, private set: NotesSet) {}

  /** Device-local AES-GCM key — created once, stored raw (b64) in the keystore. */
  private key: CryptoKey | null = null;

  async getKey(): Promise<CryptoKey> {
    if (this.key) return this.key;
    let rawB64: string | null = null;
    try {
      rawB64 = await this.get(NOTES_KEY_STORAGE);
    } catch {
      /* keystore unavailable — fall through to a fresh key */
    }
    if (rawB64) {
      try {
        this.key = await aesGcmKey(this.b64ToBytes(rawB64));
        return this.key;
      } catch {
        /* corrupted key — replace it (old notes become unreadable, web parity: web also re-keys on bad JWK) */
      }
    }
    const fresh = randomBytes(32);
    try {
      await this.set(NOTES_KEY_STORAGE, toB64(fresh));
    } catch {
      /* storage unavailable — keep the key in memory only (Nothing-at-Rest behaviour) */
    }
    this.key = await aesGcmKey(fresh);
    return this.key;
  }

    /**
   * b96: set (and persist) the notes key explicitly — used by the identity-
   * derived key path (see deriveNotesKeyB64 / adoptNotesIdentityKey). After
   * a Nothing-at-Rest wipe the phrase-restore reproduces the SAME key, so
   * every VeilNote row on the relay decrypts again ("the phrase restores
   * everything" — owner directive, Sept 21).
   */
  async setKey(rawB64: string): Promise<void> {
    this.key = await aesGcmKey(this.b64ToBytes(rawB64));
    await this.set(NOTES_KEY_STORAGE, rawB64);
  }

  /** b96: activate a key in RAM without persisting (restore paths re-persist). */
  async useKey(rawB64: string): Promise<void> {
    this.key = await aesGcmKey(this.b64ToBytes(rawB64));
  }

/**
   * web Zd(): encrypt { title, body } -> VeilNote record fields.
   * Batch C (B8; reviews P2, P3 R6): with `meta`, the ciphertext is bound to a
   * client-chosen note id and a version number (AES-GCM associated data), so
   * the relay can't move a note's content to another note, and an older
   * version served back is refused by a device that has seen a newer one.
   */
  async encryptNote(note: NotePayload, meta?: NoteMeta): Promise<EncryptedNote> {
    const key = await this.getKey();
    const iv = randomBytes(12);
    const pt = utf8(JSON.stringify(note));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource, ...(meta ? { additionalData: noteAad(meta) as unknown as BufferSource } : {}) },
        key, pt as unknown as BufferSource,
      ),
    );
    if (meta) await this.noteVersionSeen(meta);
    return { ciphertext: toB64(ct), iv: toB64(iv), byteLength: ct.length };
  }

  /** web Qd(): decrypt VeilNote payload fields -> { title, body }.
   *  Batch C (B8): rows carrying note_nid / note_v decrypt only with that
   *  binding and only if not older than the newest version this device saw.
   *  Pre-Batch-C rows (no meta) still open; they get the binding on their next save. */
  async decryptNote(ciphertext: string, iv: string, meta?: NoteMeta | null): Promise<NotePayload> {
    const key = await this.getKey();
    if (meta) {
      if (!/^[0-9a-f]{32}$/.test(meta.nid) || !Number.isInteger(meta.version) || meta.version < 1) throw new Error('Malformed note.');
      const seen = (await this.versions())[meta.nid] ?? 0;
      if (meta.version < seen) throw new Error('This note was rolled back to an older version.');
    }
    const pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: this.b64ToBytes(iv) as unknown as BufferSource, ...(meta ? { additionalData: noteAad(meta) as unknown as BufferSource } : {}) },
        key,
        this.b64ToBytes(ciphertext) as unknown as BufferSource,
      ),
    );
    if (meta) await this.noteVersionSeen(meta);
    return JSON.parse(new TextDecoder().decode(pt)) as NotePayload;
  }

  /** Batch C (B8): newest version seen per note id (device-local high-water marks). */
  private async versions(): Promise<Record<string, number>> {
    try { return JSON.parse((await this.get(NOTES_VERSIONS_STORAGE)) || '{}') as Record<string, number>; } catch { return {}; }
  }

  private async noteVersionSeen(meta: NoteMeta): Promise<void> {
    const v = await this.versions();
    if ((v[meta.nid] ?? 0) >= meta.version) return;
    v[meta.nid] = meta.version;
    try { await this.set(NOTES_VERSIONS_STORAGE, JSON.stringify(v)); } catch { /* best-effort: RAM-only devices re-learn */ }
  }

  private b64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
}

/**
 * b96 (owner directive: "key phrase should restore everything"): the notes
 * key is now DERIVED from the identity — HKDF(ik seed, 'veil-notes-v1', 32B).
 * The ik seed itself derives from the 24-word phrase, so restoring the phrase
 * after a Nothing-at-Rest wipe reproduces the notes key exactly and every
 * relay-side VeilNote row decrypts again. Previously the key was a device-local
 * random value, meaning a NaR wipe made existing notes permanently unreadable.
 */
export async function deriveNotesKeyB64(ikSeedB64: string): Promise<string> {
  const k = await hkdf(fromB64(ikSeedB64), new Uint8Array(), 'veil-notes-v1', 32);
  return toB64(k);
}

export interface NotesMigrationDeps {
  get: NotesGet;
  set: NotesSet;
  /** list ALL VeilNote rows (relay): { id, payload_ciphertext, payload_iv } */
  listRows: () => Promise<Array<{ id: string; payload_ciphertext: string; payload_iv: string }>>;
  /** update one VeilNote row (relay): id + record fields */
  updateRow: (id: string, record: Record<string, unknown>) => Promise<unknown>;
}

/**
 * Adopt the identity-derived notes key. Re-encrypts every existing VeilNote
 * row that decrypts under the OLD (device-local random) key, so existing
 * notes keep working instead of dying at the key change. Rows that don't
 * decrypt (foreign device's key, corrupted) are left untouched.
 * Returns 'migrated' when old rows were re-encrypted, 'ok' otherwise.
 */
export async function adoptNotesIdentityKey(
  notes: NotesStore,
  ikSeedB64: string,
  deps: NotesMigrationDeps,
): Promise<'ok' | 'migrated'> {
  const newB64 = await deriveNotesKeyB64(ikSeedB64);
  const oldB64 = await deps.get(NOTES_KEY_STORAGE).catch(() => null);
  if (oldB64 === newB64) {
    await notes.useKey(newB64);
    return 'ok';
  }
  if (oldB64) {
    const oldKey = await aesGcmKey(fromB64(oldB64));
    const newKey = await aesGcmKey(fromB64(newB64));
    const rows = await deps.listRows().catch(() => []);
    for (const r of rows) {
      try {
        const iv = fromB64(r.payload_iv);
        const pt = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as unknown as BufferSource },
          oldKey,
          fromB64(r.payload_ciphertext) as unknown as BufferSource,
        ));
        const iv2 = randomBytes(12);
        const ct2 = new Uint8Array(await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: iv2 as unknown as BufferSource },
          newKey,
          pt as unknown as BufferSource,
        ));
        await deps.updateRow(r.id, { payload_ciphertext: toB64(ct2), payload_iv: toB64(iv2), byte_length: ct2.length });
      } catch { /* not decryptable under the old key — leave the row as-is */ }
    }
    await notes.setKey(newB64);
    return 'migrated';
  }
  await notes.setKey(newB64);
  return 'ok';
}

/** The VeilNote entity record (web parity field names; Batch C adds note_nid / note_v). */
export function noteRecord(enc: EncryptedNote, meta?: NoteMeta): Record<string, unknown> {
  return {
    payload_ciphertext: enc.ciphertext, payload_iv: enc.iv, byte_length: enc.byteLength,
    ...(meta ? { note_nid: meta.nid, note_v: meta.version } : {}),
  };
}
