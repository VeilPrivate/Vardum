/**
 * @veil/device — device-local pinned contacts + nicknames.
 *
 * ANTI-GOAL ENFORCED BY DESIGN: this module imports NO network code. Pins and
 * nicknames NEVER leave the device — never transmitted, never synced, never
 * stored server-side (the VeilContact server-table mistake stays dead).
 *
 * Ported from the web app's veil_pins_v1 / veil_nicks_v1 localStorage keys.
 */

import { verifySpkSig, verifyPqPrekeySig, veilIdFromIkPub } from '../../crypto-core/src/index';

/** Batch C (V-25): the pin store could not be read — never treated as "no pins". */
export class PinStoreUnreadableError extends Error {
  constructor() { super('Your pinned contacts could not be read right now. Try again in a moment.'); this.name = 'PinStoreUnreadableError'; }
}

export interface PinnedContact {
  /** pinned identity key — THE trust anchor; pin = identity */
  ikPubB64: string;
  /** peer's Veil id at pin time (display only; key is authoritative) */
  veilId: string;
  pinnedAt: string;
  /** set once the user completes "I compared the fingerprint" */
  verified: boolean;
}

export interface Nickname {
  veilId: string;
  nickname: string;
}

const PINS_KEY = 'veil_pins_v1';
const NICKS_KEY = 'veil_nicks_v1';

type PinMap = Record<string, PinnedContact>;
type NickMap = Record<string, string>;

export class PinStore {
  constructor(private get: (k: string) => Promise<string | null>, private set: (k: string, v: string) => Promise<boolean>) {}

  /**
   * Batch C (V-25; review P2): unreadable is NOT empty. A storage error or a
   * corrupted value throws instead of returning {} — otherwise a "not pinned"
   * answer could re-trust a changed key, and the next pin() would overwrite
   * every existing pin. Only a genuinely absent value is an empty map.
   */
  private async pins(): Promise<PinMap> {
    let raw: string | null;
    try { raw = await this.get(PINS_KEY); } catch { throw new PinStoreUnreadableError(); }
    if (raw === null || raw === undefined || raw === '') return {};
    try {
      const m = JSON.parse(raw) as unknown;
      if (!m || typeof m !== 'object' || Array.isArray(m)) throw new Error('shape');
      return m as PinMap;
    } catch { throw new PinStoreUnreadableError(); }
  }
  private async savePins(map: PinMap): Promise<void> {
    const ok = await this.set(PINS_KEY, JSON.stringify(map));
    if (ok === false) throw new Error('Your pinned contacts could not be saved.');
  }
  private async nicks(): Promise<NickMap> {
    try { return JSON.parse((await this.get(NICKS_KEY)) || '{}'); } catch { return {}; }
  }

  async pin(veilId: string, ikPubB64: string): Promise<void> {
    // Batch C (B1; reviews P2 V-8, P3 R4): a Vardum ID IS the hash of its
    // identity key — a key that does not hash to the ID is never pinned
    if ((await veilIdFromIkPub(ikPubB64).catch(() => '')) !== veilId) {
      throw new Error('That identity key does not belong to this Vardum ID.');
    }
    const map = await this.pins();
    const existing = map[veilId];
    if (existing && existing.ikPubB64 === ikPubB64) return; // re-pin of the same key keeps "verified"
    map[veilId] = { ikPubB64, veilId, pinnedAt: new Date().toISOString(), verified: false };
    await this.savePins(map);
  }

  /** Two-tap "unpin?" confirmation happens in the UI; storage just removes. */
  async unpin(veilId: string): Promise<void> {
    const map = await this.pins();
    delete map[veilId];
    await this.savePins(map);
    const nicks = await this.nicks();
    delete nicks[veilId];
    await this.set(NICKS_KEY, JSON.stringify(nicks));
  }

  async markVerified(veilId: string): Promise<void> {
    const map = await this.pins();
    if (map[veilId]) {
      map[veilId].verified = true;
      await this.savePins(map);
    }
  }

  async getPin(veilId: string): Promise<PinnedContact | null> {
    return (await this.pins())[veilId] ?? null;
  }

  async listPins(): Promise<PinnedContact[]> {
    return Object.values(await this.pins());
  }

  async setNickname(veilId: string, nickname: string): Promise<void> {
    const nicks = await this.nicks();
    nicks[veilId] = nickname;
    await this.set(NICKS_KEY, JSON.stringify(nicks));
  }

  async getNickname(veilId: string): Promise<string | null> {
    return (await this.nicks())[veilId] ?? null;
  }

  /**
   * MITM guard (client-side, before trusting published prekeys):
   * SPK_sig must verify against the PINNED IK — not the lookup response's IK.
   * b54: pq_sig must ALSO verify against the pinned IK — an unsigned or
   * substituted ML-KEM prekey is refused (no classical fallback).
   * Returns the prekeys only when both signatures check out.
   */
  async verifyPeerPrekeys(veilId: string, published: { IK_pub: string; SPK_pub: string; SPK_sig: string; pq_pub?: string; pq_sig?: string }): Promise<{ trusted: true; spkPubB64: string; pqPubB64: string } | { trusted: false; reason: string }> {
    const pin = await this.getPin(veilId);
    if (!pin) return { trusted: false, reason: 'not-pinned' };
    if (published.IK_pub !== pin.ikPubB64) {
      return { trusted: false, reason: 'identity-key-changed' };
    }
    // Batch C (B1): also holds for pins made before the pin-time check
    if ((await veilIdFromIkPub(pin.ikPubB64).catch(() => '')) !== veilId) {
      return { trusted: false, reason: 'identity-key-mismatch' };
    }
    if (!(await verifySpkSig(pin.ikPubB64, published.SPK_pub, published.SPK_sig))) {
      return { trusted: false, reason: 'spk-sig-invalid' };
    }
    if (!(await verifyPqPrekeySig(pin.ikPubB64, published.pq_pub ?? '', published.pq_sig ?? ''))) {
      return { trusted: false, reason: 'pq-prekey-unsigned' };
    }
    return { trusted: true, spkPubB64: published.SPK_pub, pqPubB64: published.pq_pub as string };
  }
}
