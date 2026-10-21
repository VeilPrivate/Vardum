/**
 * Batch I (local security review 19 Oct 2026, V-01): the duress wipe.
 *
 * The duress branch used to await the relay (session purge, per-thread end,
 * vault and note deletes) BEFORE it erased anything on the phone, and the relay
 * client has no deadline. A stalled or malicious relay held the local erase
 * back, and killing the app in that window kept every local secret.
 *
 * Now, in three phases:
 *  1. capture (local reads only): the account id, each thread's write secret,
 *     the saved-photo ids and the push target, which the wipe would delete;
 *  2. local erase: every veil_* key except the account login (overwrite, then
 *     delete, then verify), the hardware wrap key, the vault/stego file cache.
 *     No network call can run before this phase ends;
 *  3. remote cleanup, in the background and bounded: Photos (an OS dialog on
 *     some phones), the session purge, per-thread end, vault and note records,
 *     and the push registration, using only what phase 1 captured. Each call
 *     gets a deadline and the whole phase has one. If the app is killed here,
 *     the server copies stay: they are ciphertext the server can't read, and
 *     the phone no longer holds the keys.
 */

import type { VeilStorage } from '../vendor/crypto-core/src/index';
import { wipeAndVerify } from '../vendor/device/src/secure-wipe';

export interface DuressRelay {
  sessionPurge(userId: string): Promise<unknown>;
  sessionList(userId: string, cursor: undefined): Promise<unknown>;
  sessionEnd(token: string, writeSecret: string | null, userId: string): Promise<unknown>;
  entityList(entity: string, params: Record<string, string | number>): Promise<unknown>;
  entityDelete(entity: string, id: string): Promise<unknown>;
}

export interface DuressDeps<T> {
  storage: VeilStorage;
  relay: DuressRelay;
  /** the signed-in account id, read from the stored login (no network) */
  userId(): Promise<string | null>;
  localTokens(): Promise<string[]>;
  writeSecretOf(token: string): Promise<string | null>;
  capturePushTarget(): Promise<T | null>;
  shredHardwareKey(): Promise<void>;
  clearFileCache(): Promise<void>;
  deleteSavedMedia(ids: string[]): Promise<void>;
  dropPushRegistration(target: T | null): Promise<void>;
}

export interface DuressOptions {
  /** deadline for one remote step */
  callMs: number;
  /** deadline for the whole remote phase */
  totalMs: number;
}

export interface DuressResult {
  /** keys the local erase could not remove (0 = clean) */
  leftAfterWipe: number;
  /** the bounded remote cleanup; callers don't wait for it */
  remote: Promise<void>;
}

/** the account login survives a duress wipe: the server cleanup needs it */
export const DURESS_KEEP = ['veil_auth_session'];
const DEFAULTS: DuressOptions = { callMs: 4000, totalMs: 20000 };

function within<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('duress: step timed out')), ms); });
  return Promise.race([p, late]).finally(() => clearTimeout(timer));
}

export async function runDuressWipe<T>(d: DuressDeps<T>, opts: Partial<DuressOptions> = {}): Promise<DuressResult> {
  const o = { ...DEFAULTS, ...opts };

  // ---- 1. capture: local reads only ----
  let userId: string | null = null;
  try { userId = await d.userId(); } catch { /* no login: nothing to clean remotely */ }
  const secrets = new Map<string, string | null>();
  try {
    for (const t of await d.localTokens()) {
      try { secrets.set(t, await d.writeSecretOf(t)); } catch { secrets.set(t, null); }
    }
  } catch { /* no thread list: the relay's own list still drives the cleanup */ }
  let mediaIds: string[] = [];
  try {
    const raw = await d.storage.get('veil_saved_media');
    const v = raw ? (JSON.parse(raw) as unknown) : [];
    if (Array.isArray(v)) mediaIds = v.filter((x): x is string => typeof x === 'string');
  } catch { /* unreadable: nothing to delete */ }
  let pushTarget: T | null = null;
  try { pushTarget = await d.capturePushTarget(); } catch { /* no target */ }

  // ---- 2. local erase: no network before this is done ----
  let leftAfterWipe = 0;
  try { leftAfterWipe = await wipeAndVerify(d.storage, 'veil_', DURESS_KEEP); } catch { /* never throws; belt and braces */ }
  // Batch I (V-04): -1 means the keys couldn't be listed, so nothing is known
  // to be gone. One more pass; the result stays "not clean" (leftAfterWipe !== 0).
  if (leftAfterWipe < 0) {
    try { leftAfterWipe = await wipeAndVerify(d.storage, 'veil_', DURESS_KEEP); } catch { /* still unknown */ }
  }
  try { await d.shredHardwareKey(); } catch { /* best-effort, silent */ }
  try { await d.clearFileCache(); } catch { /* best-effort */ }

  // ---- 3. remote cleanup: background, every step bounded ----
  const stopAt = Date.now() + o.totalMs;
  const left = () => stopAt - Date.now();
  const step = async <R>(fn: () => Promise<R>): Promise<{ ok: true; value: R } | { ok: false }> => {
    const ms = Math.min(o.callMs, left());
    if (ms <= 0) return { ok: false };
    try { return { ok: true, value: await within(fn(), ms) }; } catch { return { ok: false }; }
  };
  const valueOf = <R>(s: { ok: true; value: R } | { ok: false }): R | undefined => (s.ok ? s.value : undefined);
  const remote = (async () => {
    // b63 review (I3-6): first, so the time budget can't skip it (a wiped
    // phone that keeps getting banners is a giveaway)
    await step(() => d.dropPushRegistration(pushTarget));
    if (mediaIds.length) await step(() => d.deleteSavedMedia(mediaIds));
    if (userId) {
      const uid = userId;
      await step(() => d.relay.sessionPurge(uid));
      const r = valueOf(await step(() => d.relay.sessionList(uid, undefined)));
      const data = (r as { data?: unknown } | undefined)?.data;
      const list = (data as { data?: unknown[] })?.data ?? (data as { sessions?: unknown[] })?.sessions ?? data;
      for (const raw of Array.isArray(list) ? list : []) {
        if (left() <= 0) break;
        const rec = raw as Record<string, unknown>;
        const tok = String(rec.token ?? '');
        const rid = String(rec.id ?? '');
        if (!tok) continue;
        await step(() => d.relay.sessionEnd(tok, secrets.get(tok) ?? null, uid));
        if (rid) await step(() => d.relay.entityDelete('VeilSession', rid));
      }
      for (const ent of ['VeilVault', 'VeilNote'] as const) {
        for (let guard = 0; guard < 50 && left() > 0; guard++) {
          const raw = valueOf(await step(() => d.relay.entityList(ent, { limit: 100, sort: '-created_date' })));
          const rec = raw as { data?: unknown } | undefined;
          const rows = (Array.isArray(rec?.data) ? rec!.data : (Array.isArray(raw) ? raw : [])) as { id?: string }[];
          if (!rows.length) break;
          let removed = 0;
          for (const row of rows) {
            const id = String(row?.id ?? '');
            if (!id) continue;
            if ((await step(() => d.relay.entityDelete(ent, id))).ok) removed++;
          }
          if (removed === 0) break;
        }
      }
    }
  })().catch(() => undefined);

  return { leftAfterWipe, remote };
}
