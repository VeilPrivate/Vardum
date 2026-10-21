/**
 * @veil/device — identity keyvault + storage-mode rules.
 *
 * Web behaviour ported (verified on the NaR battery, Sept 13):
 *  - 'device'   : keyvault + session keys persist across reloads.
 *  - 'hardware' : same persistence as 'device'; the identity keyvault entry
 *                 additionally requires a biometric/passcode prompt from the
 *                 OS keystore on every read (see secure-store.rn.ts) — a
 *                 stronger-than-'device', weaker-than-'memory' middle option.
 *  - 'memory'   : session keys (veil_rk_* / veil_gk_*) are wiped at flip and
 *                 at close; identity is recoverable ONLY via the 24-word
 *                 phrase. (Web P2 fix adopted natively: the keyvault itself
 *                 is wiped at close under memory mode — the web copy's
 *                 "nothing is stored anywhere, ever" finally becomes true.)
 */

import type { VeilStorage } from '../../crypto-core/src/index';
import { secureRemove, secureRemovePrefix } from './secure-wipe';

export type StorageMode = 'device' | 'hardware' | 'memory';

export const STORAGE_MODE_KEY = 'veil_storage_mode';
export const KEYVAULT_KEY = 'veil_keyvault_identity';

export interface KeyvaultIdentity {
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  spkPubB64: string;
  spkPrivB64: string;
  spkSigB64: string;
  pqPubB64: string;
  pqPrivB64: string;
  /** b54: Ed25519(IK, label || pq_pub), published as pq_sig. Absent on
   *  pre-b54 keyvaults until ensurePqPrekeySigned() backfills it. */
  pqSigB64?: string;
  createdAt: string;
}

export class IdentityVault {
  constructor(private storage: VeilStorage) {}

  async save(id: KeyvaultIdentity): Promise<void> {
    await this.storage.set(KEYVAULT_KEY, JSON.stringify(id));
  }

  async load(): Promise<KeyvaultIdentity | null> {
    const raw = await this.storage.get(KEYVAULT_KEY);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  async clear(): Promise<void> {
    // b93 P2: the keyvault is THE crown-jewel record (ik seed, spk priv, PQ
    // priv) — overwrite it in place before the delete.
    await secureRemove(this.storage, KEYVAULT_KEY);
  }

  async mode(): Promise<StorageMode> {
    return ((await this.storage.get(STORAGE_MODE_KEY)) as StorageMode) || 'device';
  }

  /** Flip the storage mode; wiping conversation keys as the web build does. */
  async setMode(mode: StorageMode): Promise<number> {
    await this.storage.set(STORAGE_MODE_KEY, mode);
    if (mode === 'memory') {
      const ks = await this.storage as unknown as { wipe?: (...p: string[]) => Promise<number> };
      if (typeof ks.wipe === 'function') return ks.wipe('veil_rk_', 'veil_gk_', 'veil_msgcache_');
      // b93 P2: conversation keys are overwritten in place, then deleted.
      await secureRemovePrefix(this.storage, 'veil_rk_');
      await secureRemovePrefix(this.storage, 'veil_gk_');
      // b92 F-S2 (settings sweep): the PLAINTEXT message cache is history
      // too — leaving it on disk broke the Nothing-at-Rest claim.
      await secureRemovePrefix(this.storage, 'veil_msgcache_');
    }
    return 0;
  }

  /**
   * Nothing-at-Rest wipe hook — the CONVERSATION layer of the b95 v2 design
   * (owner hardware verify, Sept 21: "lock the phone, unlock — absolutely
   * nothing happened"). Called by App.tsx's naRWipeStorage() on mode flip,
   * on ANY departure from the foreground ('inactive' = screen lock included,
   * 'background' = app switch), and at every cold boot while the mode is on.
   * Under memory mode NOTHING Veil-stored survives: conversation keys, the
   * plaintext history cache, and the identity keyvault itself — the identity
   * returns only via the 24-word recovery phrase. App.tsx extends this to
   * the full surface (notes, vaults, stego, saved media).
   */
  async onClose(): Promise<void> {
    if ((await this.mode()) === 'memory') {
      await secureRemovePrefix(this.storage, 'veil_rk_');
      await secureRemovePrefix(this.storage, 'veil_gk_');
      // b92 F-S2: Nothing-at-Rest must include the plaintext history cache.
      await secureRemovePrefix(this.storage, 'veil_msgcache_');
      await this.clear(); // the identity keyvault goes too — "nothing" means nothing
    }
  }
}
