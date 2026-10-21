/**
 * @veil/device — secure storage over the platform keystore.
 *
 * The ONLY primitive the Expo shell must implement: SecureStore
 * (react-native-keychain / expo-secure-store / Keychain on iOS, Keystore on
 * Android). Keychain-style stores are not enumerable, so VeilStorage's
 * keys(prefix) sweep is served through a maintained index record.
 *
 * Everything the web app kept in localStorage under veil_* keys lives here:
 * NO plaintext key material ever touches AsyncStorage or plain files.
 */

import type { VeilStorage } from '../../crypto-core/src/index';

/** Platform primitive the Expo shell provides. Never returns secrets in logs. */
export interface SecureStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

const INDEX_KEY = 'veil_keychain_index';
/** Batch C (B2): a second copy of the index — a corrupted copy can't hide keys from a wipe */
const INDEX_KEY_B = 'veil_keychain_index_b';
const isIndexKey = (k: string) => k === INDEX_KEY || k === INDEX_KEY_B;

/**
 * VeilStorage over a non-enumerable secure store, with a key index.
 * Batch C (B2; reviews P2 V-22, P3 R2, P4 F-16): every index read-modify-write
 * runs under one lock (concurrent saves used to drop entries — those keys then
 * escaped every wipe); the index is kept twice and read as the union of the
 * copies that parse; a wipe deletes key by key (one failure no longer stops
 * it) and finishes with a verify pass.
 */
export class KeychainStorage implements VeilStorage {
  constructor(private store: SecureStore) {}

  private indexLock: Promise<unknown> = Promise.resolve();
  private withIndex<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.indexLock.catch(() => undefined).then(fn);
    this.indexLock = run.catch(() => undefined);
    return run;
  }

  private async readIndex(): Promise<string[]> {
    const out = new Set<string>();
    for (const k of [INDEX_KEY, INDEX_KEY_B]) {
      try {
        const v = JSON.parse((await this.store.get(k)) || '[]') as unknown;
        if (Array.isArray(v)) for (const x of v) if (typeof x === 'string') out.add(x);
      } catch { /* this copy is unreadable — the other one still counts */ }
    }
    return [...out];
  }

  private async writeIndex(keys: string[]): Promise<void> {
    const v = JSON.stringify(keys);
    await this.store.set(INDEX_KEY, v);
    await this.store.set(INDEX_KEY_B, v);
  }

  async get(key: string): Promise<string | null> {
    return this.store.get(key);
  }

  async set(key: string, value: string): Promise<boolean> {
    try {
      // Batch I (local review V-04; RV-37): the index entry is written FIRST.
      // A value written before its entry escaped every wipe if the index write
      // then failed; an entry for a value that never landed is harmless.
      // b63 review (I3-1): the value write stays inside the index lock, so a
      // wipe can't run between the entry and the value and orphan the value.
      if (!isIndexKey(key)) {
        await this.withIndex(async () => {
          const keys = await this.readIndex();
          if (!keys.includes(key)) {
            keys.push(key);
            await this.writeIndex(keys);
          }
          await this.store.set(key, value);
        });
      } else {
        await this.store.set(key, value);
      }
      return true;
    } catch (e) {
      // b196-r7: never swallow silently — Metro must see the native failure
      // (user-facing copy stays sanitized elsewhere; this is the developer log).
      console.error('[veil-secure] KeychainStorage.set failed:', key, e);
      return false;
    }
  }

  async remove(key: string): Promise<void> {
    try {
      if (isIndexKey(key)) {
        await this.store.delete(key);
      } else {
        // b63 review (I3-1): delete under the index lock, in order with set()
        await this.withIndex(async () => {
          await this.store.delete(key);
          const keys = await this.readIndex();
          const i = keys.indexOf(key);
          if (i >= 0) {
            keys.splice(i, 1);
            await this.writeIndex(keys);
          }
        });
      }
    } catch {
      /* never throws */
    }
  }

  async keys(prefix: string): Promise<string[]> {
    return (await this.withIndex(() => this.readIndex())).filter((k) => k.startsWith(prefix) && !isIndexKey(k));
  }

  /** Wipe every key under the prefixes (duress / storage-mode flip / end-session).
   *  Returns how many keys could NOT be removed (0 = clean). */
  async wipe(...prefixes: string[]): Promise<number> {
    return this.withIndex(async () => {
      const all = await this.readIndex();
      const doomed = all.filter((k) => prefixes.some((p) => k.startsWith(p)));
      const failed: string[] = [];
      for (const k of doomed) {
        try { await this.store.delete(k); } catch { failed.push(k); }
      }
      // verify pass: anything still readable gets one more delete
      const stuck: string[] = [];
      for (const k of doomed) {
        let still = failed.includes(k);
        try { still = still || (await this.store.get(k)) !== null; } catch { /* unreadable counts as gone */ }
        if (!still) continue;
        try { await this.store.delete(k); if ((await this.store.get(k)) !== null) stuck.push(k); } catch { stuck.push(k); }
      }
      await this.writeIndex(all.filter((k) => !doomed.includes(k) || stuck.includes(k)));
      return stuck.length;
    });
  }
}
