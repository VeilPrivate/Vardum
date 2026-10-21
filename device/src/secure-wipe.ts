/**
 * @veil/device — b93 P2 anti-forensics: overwrite-before-delete.
 *
 * The Sept 20 roadmap item: duress + sign-out wipes must OVERWRITE key
 * material, not just dereference it. A bare `remove()` is a logical delete —
 * on iOS the backing store (SQLite/MMKV/keychain-backed adapter) keeps the
 * plaintext bytes in its file until the region is reused, so a Cellebrite-
 * class logical extraction of the store file reads the "deleted" keyvault,
 * session keys and ratchet states verbatim.
 *
 * `secureRemove` first rewrites the key's value IN PLACE with a same-length
 * block of zeroes — forcing the storage engine to overwrite the stored
 * record with junk — and only then deletes the key. After the pass the
 * store file contains zeros where the key material lived, not the keys.
 * (Flash wear-leveling still applies below the file layer; this closes the
 * application-layer gap, which is what a logical forensic extraction sees.)
 *
 * Best-effort by design: a failed overwrite still proceeds to the delete,
 * and callers under duress must never be blocked by a storage hiccup.
 */

import type { VeilStorage } from '../../crypto-core/src/index';

/**
 * Batch G (round-5 review R5-3-04 / R4-4-31): keys whose READ is biometric-gated
 * in hardware mode. Reading one raises Face ID — under duress that is a tell —
 * so a wipe overwrites and deletes them blind and checks them by listing only.
 */
export const GATED_KEYS: readonly string[] = ['veil_keyvault_identity'];

/** Zero-fill a key in place, then delete it. */
export async function secureRemove(storage: VeilStorage, key: string): Promise<void> {
  if (GATED_KEYS.includes(key)) {
    // Batch H (round-6 review R6-1-02): no overwrite. In Android hardware mode a
    // write of this key wraps it with the hardware key, which shows a biometric
    // prompt (a tell during a duress wipe). The stored value is a wrapped blob;
    // the app also resets the hardware wrap key at every wipe (crypto-shred), so
    // a surviving copy can never be unwrapped.
    try { await storage.remove(key); } catch { /* already gone */ }
    return;
  }
  let len = 0;
  try {
    const cur = await storage.get(key);
    if (typeof cur === 'string') len = cur.length;
  } catch { /* unreadable — delete anyway */ }
  if (len > 0) {
    try { await storage.set(key, '0'.repeat(len)); } catch { /* overwrite is best-effort */ }
  }
  try { await storage.remove(key); } catch { /* already gone */ }
}

/**
 * Batch E (Superagent round 3, F-5): wipe every key under a prefix (except the
 * kept ones), then VERIFY: every key that was there is read back, removed again
 * if it is still readable, and counted if it survives. Returns that count
 * (0 = clean). Never throws — callers under duress must not be blocked.
 * Batch I (local review V-04): -1 = UNKNOWN (the keys couldn't be listed), never
 * reported as clean.
 */
export const WIPE_UNKNOWN = -1;
export async function wipeAndVerify(storage: VeilStorage, prefix: string, keep: string[] = []): Promise<number> {
  let doomed: string[] = [];
  try { doomed = (await storage.keys(prefix)).filter((k) => !keep.includes(k)); } catch { return WIPE_UNKNOWN; }
  for (const k of doomed) await secureRemove(storage, k);
  try { for (const k of await storage.keys(prefix)) if (!keep.includes(k) && !doomed.includes(k)) doomed.push(k); } catch { /* listing failed: verify what we know */ }
  let stuck = 0;
  let listed: string[] | null = null;
  for (const k of doomed) {
    let still = false;
    if (GATED_KEYS.includes(k)) {
      // Batch G (R5-3-04): never read a gated key; it is "still there" if still listed
      try { listed = listed ?? await storage.keys(prefix); still = listed.includes(k); } catch { still = false; }
    } else {
      try { still = (await storage.get(k)) !== null; } catch { still = false; }
    }
    if (!still) continue;
    await secureRemove(storage, k);
    if (GATED_KEYS.includes(k)) { try { if ((await storage.keys(prefix)).includes(k)) stuck += 1; } catch { /* listing failed */ } continue; }
    try { if ((await storage.get(k)) !== null) stuck += 1; } catch { /* unreadable counts as gone */ }
  }
  return stuck;
}

/** Zero-fill + delete every key under a prefix (rk, gk, msgcache, ...). */
export async function secureRemovePrefix(storage: VeilStorage, prefix: string): Promise<void> {
  let keys: string[] = [];
  try { keys = await storage.keys(prefix); } catch { return; }
  for (const k of keys) await secureRemove(storage, k);
}
