/**
 * @veil/device — session state persistence (veil_rk_<token>).
 *
 * The web app kept serialized ratchet state in localStorage (the veil_rk_*
 * family). Natively the serialized state lives in the secure store; the
 * end-session path must remove BOTH the state and its wrapper record, so the
 * P1-1 ghost class cannot exist structurally: removeRatchet is the ONLY
 * delete path and it always clears every residue key for the token.
 */

import type { RatchetStateSerialized } from '../../crypto-core/src/index';
import type { VeilStorage } from '../../crypto-core/src/index';
import { secureRemove } from './secure-wipe';
import type { ChatMessage } from './chat';
import { parseAnchor, type BackfillAnchor } from './backfill';

export class SessionStore {
  constructor(private storage: VeilStorage) {}

  static keyFor(token: string): string {
    return `veil_rk_${token}`;
  }

  async save(token: string, state: RatchetStateSerialized): Promise<boolean> {
    return this.storage.set(SessionStore.keyFor(token), JSON.stringify(state));
  }

  async load(token: string): Promise<RatchetStateSerialized | null> {
    const raw = await this.storage.get(SessionStore.keyFor(token));
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  /** End-session: removes ALL residue for the token — state, wrapper, msgcache,
   * processed-id ledger. */
  async remove(token: string): Promise<void> {
    // b93 P2: overwrite before delete — ratchet states, wrapped keys and the
    // PLAINTEXT message cache are exactly the bytes a forensic extraction
    // of the store file wants; a bare remove() left them on disk.
    await secureRemove(this.storage, SessionStore.keyFor(token));
    await secureRemove(this.storage, `veil_rk_wrap_${token}`);
    await secureRemove(this.storage, `veil_msgcache_${token}`);
    // b172: chunked cache parts (see cacheWrite) die with the session too
    for (let pi = 0; pi < 256; pi++) {
      const pk = `veil_msgcache_${token}_p${pi}`;
      if (await this.storage.get(pk) == null) break;
      await secureRemove(this.storage, pk);
    }
    await secureRemove(this.storage, this.procKey(token));
    await secureRemove(this.storage, this.skipKey(token));
    await secureRemove(this.storage, this.backfillKey(token));
    await secureRemove(this.storage, this.unreadKey(token));
    await secureRemove(this.storage, this.strayKey(token));
    await secureRemove(this.storage, this.strayPendingKey(token));
    await secureRemove(this.storage, this.desyncPendingKey(token));
    // b102: pending-burn retry queue dies with the session too — a stale
    // queue would keep firing burn calls for envelopes of a session this
    // device no longer has state for.
    await secureRemove(this.storage, this.pendingBurnKey(token));
  }

  // ---------- unread counters (b90) ----------
  // Per-session count of decrypted-but-unseen messages. Persisted so the
  // badge survives app restarts; cleared the moment the thread is opened.
  // Never counts messages decrypted while the thread was open (the user is
  // looking at them) and never counts system notes or receipts.
  private unreadKey(token: string): string {
    return `veil_unread_${token}`;
  }

  async getUnread(token: string): Promise<number> {
    const raw = await this.storage.get(this.unreadKey(token));
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

  /** Add n (or pass a negative to decay); returns the new count. Clamped >= 0. */
  async bumpUnread(token: string, n: number): Promise<number> {
    const next = Math.max(0, Math.floor((await this.getUnread(token)) + n));
    if (next > 0) {
      await this.storage.set(this.unreadKey(token), String(next));
    } else {
      await this.storage.remove(this.unreadKey(token)); // 0 = no key, keeps storage lean
    }
    return next;
  }

  async clearUnread(token: string): Promise<void> {
    await this.storage.remove(this.unreadKey(token));
  }

  // ---------- stray-envelope ledger (b91) ----------
  // Envelopes classified as strays (failed to decrypt, but newer messages
  // in the same session decrypt fine). A consumed ratchet message key can
  // never be re-derived, so re-attempting a classified stray every poll
  // only re-logs the failure — and once the newer envelopes are all in the
  // processed ledger, the stray fails ALONE and would flip to "desync".
  // Ledgered strays are skipped on future passes, permanently.
  private strayKey(token: string): string {
    return `veil_stray_${token}`;
  }

  async strayIds(token: string): Promise<Set<string>> {
    const raw = await this.storage.get(this.strayKey(token));
    try {
      const arr = JSON.parse(raw ?? '[]') as string[];
      return new Set(Array.isArray(arr) ? arr : []);
    } catch { return new Set(); }
  }

  async markStrayIds(token: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    const cur = await this.strayIds(token);
    for (const id of ids) cur.add(id);
    await this.storage.set(this.strayKey(token), JSON.stringify(Array.from(cur).slice(-500)));
  }

  // ---------- pending stray/desync notices (b92 F1, b91 audit) ----------
  // Strays classified while a thread was CLOSED are ledgered silently — the
  // foreground soft-notice renders in React state that no longer exists when
  // the thread later opens, so the failed message would leave ZERO trace.
  // These counters keep the fact that something failed while closed, so
  // openChat can render the same soft notice the user would have seen live.
  // Cleared on drain (opening = seeing).
  private strayPendingKey(token: string): string {
    return `veil_straypending_${token}`;
  }

  async pendingStrayCount(token: string): Promise<number> {
    const raw = await this.storage.get(this.strayPendingKey(token));
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

  async bumpPendingStrays(token: string, n: number): Promise<void> {
    if (n > 0) await this.storage.set(this.strayPendingKey(token), String((await this.pendingStrayCount(token)) + n));
  }

  /** Drains the pending count (returns it, then clears). */
  async takePendingStrays(token: string): Promise<number> {
    const n = await this.pendingStrayCount(token);
    if (n > 0) await this.storage.remove(this.strayPendingKey(token));
    return n;
  }

  /** b157: calls this device never answered — typically an offer held out by
   *  hold-until-unlock (a locked phone holds no message data, and call
   *  offers are ratcheted exactly like messages, so they cannot bypass the
   *  hold). openChat drains these into a "Missed call" system notice. */
  private missedCallKey(token: string): string {
    return `veil_missedcall_${token}`;
  }

  async missedCallInfo(token: string): Promise<{ n: number; peer: string; at: number } | null> {
    const raw = await this.storage.get(this.missedCallKey(token));
    if (!raw) return null;
    try { return JSON.parse(raw) as { n: number; peer: string; at: number }; } catch { return null; }
  }

  async bumpMissedCalls(token: string, peer: string): Promise<void> {
    const cur = (await this.missedCallInfo(token)) ?? { n: 0, peer, at: Date.now() };
    cur.n += 1; cur.peer = peer; cur.at = Date.now();
    await this.storage.set(this.missedCallKey(token), JSON.stringify(cur));
  }

  /** Drains the record (returns it, then clears). */
  async takeMissedCalls(token: string): Promise<{ n: number; peer: string; at: number } | null> {
    const info = await this.missedCallInfo(token);
    if (info) await this.storage.remove(this.missedCallKey(token));
    return info;
  }

  /** A genuine desync signature fired while the thread was closed — openChat
   *  surfaces the one-time end-session recommendation when it next opens. */
  private desyncPendingKey(token: string): string {
    return `veil_desyncpending_${token}`;
  }

  async setPendingDesync(token: string): Promise<void> {
    await this.storage.set(this.desyncPendingKey(token), '1');
  }

  async takePendingDesync(token: string): Promise<boolean> {
    const raw = await this.storage.get(this.desyncPendingKey(token));
    if (raw) await this.storage.remove(this.desyncPendingKey(token));
    return !!raw;
  }

  // ---------- processed-envelope ledger (b78) ----------
  // The relay RE-SERVES every envelope on every poll (the entity list never
  // consumes; 'delivered' marks are metadata only), so the only thing that
  // stands between a poll and a RE-DECRYPT of an already-consumed envelope —
  // which re-runs the PQ rekey, rotates both chains and permanently desyncs
  // the session (the "Message counter out of range" class) — is a durable
  // per-token record of every envelope id this device has decrypted. App-level
  // known-id sets are per-thread and seed from the message cache only, which
  // MISSES filtered control payloads (cover/intro/receipt) — re-decrypting one
  // of those poisons the ratchet exactly the same. This ledger records ALL
  // of them, per token, capped so it can't grow unbounded.
  private procKey(token: string): string {
    return `veil_procids_${token}`;
  }

  // ---------- pending-burn retry ledger (b102) ----------
  // Owner Metro repro Sept 21: "burn failed for <id>: Network request
  // failed". Root cause traced in chat.ts — the envelope is marked
  // PROCESSED (procKey, above) the instant decrypt succeeds, before the burn
  // call even runs; that ledger is what makes the NEXT sync pass skip an
  // envelope entirely. So once decrypt succeeds, a burn call that fails on a
  // plain network error was NEVER retried — the envelope sat on the relay at
  // its ORIGINAL expiry (hours/a day) instead of the shortened burn-after-
  // open one, silently defeating the feature's whole privacy promise on
  // nothing more than a dropped connection. This ledger tracks {id,attempts}
  // pairs per token so syncChat can retry them on every subsequent pass
  // (attempts cap at MAX_BURN_RETRY_ATTEMPTS so a permanently-failing id,
  // e.g. a dead session, doesn't retry forever — see chat.ts retryPendingBurns).
  private pendingBurnKey(token: string): string {
    return `veil_pendburn_${token}`;
  }

  async pendingBurns(token: string): Promise<{ id: string; attempts: number; displayed?: boolean; blob?: string; blobDeleteAt?: number; retryAt?: number; failingSince?: number }[]> {
    const raw = await this.storage.get(this.pendingBurnKey(token));
    try { return raw ? (JSON.parse(raw) as { id: string; attempts: number }[]) : []; } catch { return []; }
  }

  async setPendingBurns(token: string, list: { id: string; attempts: number; displayed?: boolean; blob?: string; blobDeleteAt?: number; retryAt?: number; failingSince?: number }[]): Promise<{ saved: boolean; full: boolean }> {
    if (!list.length) { await secureRemove(this.storage, this.pendingBurnKey(token)); return { saved: true, full: false }; }
    // Batch F (R4-4-12): keep up to 2000 (was 200, which silently dropped burns)
    const full = list.length > 2000;
    if (full) console.log(`[veil] pending burn queue for #${token.slice(0, 4)} over 2000 — oldest dropped`);
    // Batch H (round-6 review R6-1-10 / R5-1-09): the write result is checked and,
    // with a full queue, reported to the caller (the thread says so)
    const saved = (await this.storage.set(this.pendingBurnKey(token), JSON.stringify(list.slice(-2000))).catch(() => false)) !== false;
    if (!saved) console.log(`[veil] pending burn queue for #${token.slice(0, 4)} not saved (storage refused)`);
    return { saved, full };
  }

  // ---------- envelope-list pagination cursor (b87) ----------
  // b87 (owner repro Sept 21 — "still nothing new" on a day-old heavily-used
  // thread): envelopeList always fetches the OLDEST 200 envelopes for a
  // session (web-parity query, no server-side "already delivered" filter).
  // Once a session accumulates more than 200 total rows — trivial after a
  // day of cover traffic — every poll re-fetches the SAME stale head
  // forever and can never reach anything sent after it: a silent,
  // permanent sync stall with zero error, zero log signal beyond an
  // unchanging "fetched 200 envelope(s)" line. This cursor lets syncChat
  // skip past a head it has fully accounted for. Advances ONLY on a full
  // (200-row) page, by (pageSize - SAFETY_MARGIN) — never on a partial
  // page, since a partial page IS the live tail and must be re-scanned
  // every poll for freshness. The margin absorbs index drift from the
  // relay's burn sweeper deleting expired rows elsewhere in the list
  // (safe either way: a row that vanished because it expired was going to
  // be skipped by the per-record expiry check regardless).
  private skipKey(token: string): string {
    return `veil_syncskip_${token}`;
  }

  // ---------- deep-backlog anchor (audit doc 13, R1) ----------
  // Set only while a sync pass is still descending a backlog deeper than its
  // fetch cap (see backfill.ts); absent otherwise. Losing it is harmless:
  // the next pass just starts the descent from the top again.
  private backfillKey(token: string): string {
    return `veil_backfill_${token}`;
  }

  async backfillAnchor(token: string): Promise<BackfillAnchor | null> {
    const raw = await this.storage.get(this.backfillKey(token));
    try { return raw ? parseAnchor(JSON.parse(raw)) : null; } catch { return null; }
  }

  async setBackfillAnchor(token: string, anchor: BackfillAnchor | null): Promise<void> {
    if (anchor) await this.storage.set(this.backfillKey(token), JSON.stringify(anchor));
    else await this.storage.remove(this.backfillKey(token));
  }

  async syncSkip(token: string): Promise<number> {
    const raw = await this.storage.get(this.skipKey(token));
    const n = raw ? Number(raw) : 0;
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  async saveSyncSkip(token: string, skip: number): Promise<void> {
    await this.storage.set(this.skipKey(token), String(Math.max(0, Math.floor(skip))));
  }

  async processedIds(token: string): Promise<Set<string>> {
    const raw = await this.storage.get(this.procKey(token));
    try { return new Set(raw ? (JSON.parse(raw) as string[]) : []); } catch { return new Set(); }
  }

  async markProcessedIds(token: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    const cur = await this.processedIds(token);
    for (const id of ids) cur.add(id);
    const arr = [...cur];
    await this.storage.set(this.procKey(token), JSON.stringify(arr.slice(-1000)));
  }

  // ---------- message cache (own sends + decrypted peers survive reload) ----------

  private cacheKey(token: string): string {
    return `veil_msgcache_${token}`;
  }

  /** b92 F-S1/F-S2: true when local history must not persist (memory mode
   *  or the localHistory dial off). Reads the same keys the vault/settings
   *  stores own, so the decision always matches the live configuration. */
  async historyPersistBlocked(): Promise<boolean> {
    try {
      if (((await this.storage.get('veil_storage_mode')) ?? '') === 'memory') return true;
      const raw = await this.storage.get('veil_settings_v1');
      if (raw) {
        const s = JSON.parse(raw) as { localHistory?: boolean };
        if (s.localHistory === false) return true;
      }
      return false;
    } catch {
      return false; // unreadable config → keep prior behavior (persist)
    }
  }

  async cacheMessages(token: string, messages: ChatMessage[]): Promise<boolean> {
    // b92 F-S1/F-S2 (settings sweep): honor the history dials at the WRITE
    // site. Nothing-at-Rest ('memory' mode) and "Keep conversation history
    // on this device" = Off must mean plaintext never lands on disk.
    // b172: returns false when the store REFUSES the write — the caller can
    // surface it; silence here is what made this bug look like deletion.
    if (await this.historyPersistBlocked()) return true; // policy, not a failure
    const list = await this.cacheRead(token);
    const ids = new Set(list.map((m) => m.id));
    const merged = [...list, ...messages.filter((m) => !ids.has(m.id))];
    return await this.cacheWrite(token, merged);
  }

  /** b127: read the cached thread rows back (receipt sweep + cache
   * renders). Returns [] when history persistence is blocked or empty. */
  async cachedMessages(token: string): Promise<ChatMessage[]> {
    return await this.cacheRead(token);
  }

  /** b198 CACHE-RENDER LOOPHOLE: anchor the VIEW burn clock at the HUMAN open
   *  for cache-rendered peer rows whose pendingBurn just flipped. Background
   *  decrypt stamps openedAt at MACHINE time — the countdown then ran while
   *  nobody was looking and the bubble could vanish without a human ever
   *  seeing it, while the relay copy survived. Called only for rows whose burn
   *  entry flipped this instant, so thread reopens never reset a running clock.
   *  Respects the cache-write policy (blocked stores skip silently). Returns
   *  the number of rows stamped. */
  async stampOpenedAt(token: string, ids: string[]): Promise<number> {
    if (!ids.length) return 0;
    const set = new Set(ids);
    const rows = await this.cacheRead(token);
    let stamped = 0;
    const next = rows.map((m) => {
      if (!set.has(m.id) || m.mine) return m;
      stamped++;
      return { ...m, openedAt: Date.now() };
    });
    if (stamped) await this.cacheWrite(token, next);
    return stamped;
  }

  // ---------- b172: chunked cache core ----------
  // Owner hardware finding (Oct 2, first real native-to-native test):
  // threads lost ALL history the instant they closed - "messages delete" -
  // while the same thread on web kept everything. Root cause: this cache
  // used to be ONE keychain item per token, and the iOS Keychain silently
  // refuses large values; KeychainStorage.set returns false on refusal and
  // every cache write site ignored the result. A thread with media
  // (screenshots carry uri + wrapped keys + iv) crossed the practical size
  // cliff and every write from then on failed invisibly: history lived in
  // RAM only. Fix: split the cache into bounded parts so no single item can
  // exceed a safe size, and surface write refusals through
  // onCacheWriteFailure so the UI can tell the user, not fake amnesia.

  /** Per-part ceiling: 60 KB of JSON and at most 100 rows. iOS Keychain's
   * practical per-item limit is far below web localStorage's ~5 MB; 60 KB
   * stays comfortably inside it with room for a large media row. */
  private static readonly CACHE_PART_BYTES = 61440;
  private static readonly CACHE_PART_ROWS = 100;
  private static readonly CACHE_MAX_MSGS = 500;

  /** b172: UI hook - fires once per failed cache write. Silent failure is
   *  how this bug masqueraded as "deleting messages" for a whole session. */
  onCacheWriteFailure?: (token: string) => void;

  private partKey(token: string, i: number): string {
    return `veil_msgcache_${token}_p${i}`;
  }

  /** b172: merge parts + the legacy monolithic key (one-time migration). */
  private async cacheRead(token: string): Promise<ChatMessage[]> {
    const out: ChatMessage[] = [];
    const ids = new Set<string>();
    for (let i = 0; i < 4096; i++) {
      const raw = await this.storage.get(this.partKey(token, i));
      if (raw == null) break;
      try {
        for (const m of JSON.parse(raw) as ChatMessage[]) {
          if (ids.has(m.id)) continue;
          ids.add(m.id); out.push(m);
        }
      } catch { break; } // corrupt part: keep what we have
    }
    const legacy = await this.storage.get(this.cacheKey(token));
    if (legacy != null) {
      try {
        for (const m of JSON.parse(legacy) as ChatMessage[]) {
          if (ids.has(m.id)) continue;
          ids.add(m.id); out.push(m);
        }
      } catch { /* corrupt legacy blob ignored */ }
    }
    return out;
  }

  /** b172: bounded parts. Returns false when the store refuses a write
   *  (KeychainStorage.set returns false on failure; void-style stores are
   *  treated as success). Retires the legacy key + stale parts ONLY after
   *  every part wrote clean, so a failed write never destroys old data. */
  private async cacheWrite(token: string, list: ChatMessage[]): Promise<boolean> {
    const capped = list.slice(-SessionStore.CACHE_MAX_MSGS);
    const parts: string[] = [];
    let cur: ChatMessage[] = [];
    let bytes = 2;
    for (const m of capped) {
      const sz = JSON.stringify(m).length + 1;
      if (cur.length && (bytes + sz > SessionStore.CACHE_PART_BYTES || cur.length >= SessionStore.CACHE_PART_ROWS)) {
        parts.push(JSON.stringify(cur)); cur = []; bytes = 2;
      }
      cur.push(m); bytes += sz;
    }
    parts.push(JSON.stringify(cur));
    let ok = true;
    for (let i = 0; i < parts.length; i++) {
      const r = await this.storage.set(this.partKey(token, i), parts[i]);
      if (r === false) ok = false;
    }
    if (ok) {
      // retire the legacy monolithic key + parts left over from a bigger past
      const stale: string[] = [];
      if (await this.storage.get(this.cacheKey(token)) != null) stale.push(this.cacheKey(token));
      for (let i = parts.length; i < 4096; i++) {
        const k = this.partKey(token, i);
        if (await this.storage.get(k) == null) break;
        stale.push(k);
      }
      for (const k of stale) await secureRemove(this.storage, k);
    } else {
      console.log(`[veil-cache] write FAILED for session ${token.slice(0, 8)} - history is NOT being saved on this device`);
      try { this.onCacheWriteFailure?.(token); } catch { /* hook must never throw */ }
    }
    return ok;
  }

  // ---------- b127: per-token receipted-ids ledger ----------
  // Which PEER message ids this device has already acknowledged with a
  // read receipt. Without it, the b127 receipt sweep would re-receipt the
  // whole cached thread after every app restart (harmless for the peer,
  // but wasteful and it re-advances the send chain every launch).

  private receiptedKey(token: string): string {
    return `veil_receipted_${token}`;
  }

  async receiptedIds(token: string): Promise<Set<string>> {
    const raw = await this.storage.get(this.receiptedKey(token));
    try { return new Set(raw ? (JSON.parse(raw) as string[]) : []); } catch { return new Set(); }
  }

  async markReceiptedIds(token: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    const cur = await this.receiptedIds(token);
    for (const id of ids) cur.add(id);
    const arr = [...cur];
    await this.storage.set(this.receiptedKey(token), JSON.stringify(arr.slice(-1000)));
  }

  /** b160 K-4 fix: drop this token's receipted-ids ledger. Delivery-only
   * receipts (sent while the read-receipts dial was OFF, or by the pre-b129
   * sweep) can never upgrade to read:true — the peer's messages stay
   * 'delivered' forever. Clearing the ledger lets the open-thread sweep
   * re-acknowledge the cached backlog with the CURRENT dial state (one
   * bounded burst per thread per launch / toggle flip). */
  async clearReceiptedIds(token: string): Promise<void> {
    await this.storage.set(this.receiptedKey(token), JSON.stringify([]));
  }

  /** b69: persist read receipts into the cache — the 'read' tick otherwise
   *  vanished every time the thread was closed and reopened. */
  async markCachedRead(token: string, envIds: string[]): Promise<void> {
    if (!envIds.length) return;
    const list = await this.cacheRead(token);
    const set = new Set(envIds);
    let changed = false;
    const out = list.map((m) => {
      if (m.read) return m;
      if ((m.envId && set.has(m.envId)) || set.has(m.id)) {
        changed = true;
        // b198 two-dial: the PEER's read receipt is the true human-open moment —
        // the sender's burn clock (UI countdown + local purge) anchors HERE,
        // matching the relay copy's burn-at-recipient-open
        return { ...m, read: true, openedAt: Date.now() };
      }
      return m;
    });
    if (changed) await this.cacheWrite(token, out);
  }

  /** b199: persist a reaction on the cached message whose id or envId is
   *  `target` (side 'mine' = this device's, 'peer' = the other person's). */
  async setCachedReaction(token: string, target: string, side: 'mine' | 'peer', emoji: string | null): Promise<void> {
    const list = await this.cacheRead(token);
    let changed = false;
    const out = list.map((m) => {
      if (m.id !== target && m.envId !== target) return m;
      changed = true;
      const reactions = { ...(m.reactions ?? {}) };
      if (emoji) reactions[side] = emoji; else delete reactions[side];
      return { ...m, reactions };
    });
    if (changed) await this.cacheWrite(token, out);
  }

  /** Play UGC: drop cached rows whose id or envId is listed (founder removal).
   *  Returns how many rows were removed. */
  async removeCachedMessages(token: string, ids: string[]): Promise<number> {
    if (!ids.length) return 0;
    const set = new Set(ids);
    const list = await this.cacheRead(token);
    const out = list.filter((m) => !set.has(m.id) && !(m.envId && set.has(m.envId)));
    if (out.length !== list.length) await this.cacheWrite(token, out);
    return list.length - out.length;
  }

  /** b123: bind a relay envelope id onto a locally-sent group bubble
   *  (own-echo path). Group sends don't learn their envelope id at submit
   *  time — the inbox poll echoes it back — and without the binding the
   *  b69 read-tick persistence (markCachedRead matches envId) can never
   *  reach these rows. */
  async setCachedEnvId(token: string, localId: string, envId: string): Promise<void> {
    const list = await this.cacheRead(token);
    let changed = false;
    const out = list.map((m) => {
      if (m.id === localId && m.envId !== envId) { changed = true; return { ...m, envId }; }
      return m;
    });
    if (changed) await this.cacheWrite(token, out);
  }

  /** b72: stamp openedAt on cached rows that pre-date the field (or were
   *  cached before the thread was ever displayed) — "opened" means first
   *  rendered on this device, so the burn countdown starts from NOW for
   *  them. Returns the updated list. */
  async ensureOpenedAt(token: string): Promise<ChatMessage[]> {
    const list = await this.listMessages(token);
    const now = Date.now();
    let changed = false;
    const out = list.map((m) => {
      if (m.openedAt) return m;
      changed = true;
      return { ...m, openedAt: now };
    });
    if (changed) await this.cacheWrite(token, out);
    return out;
  }

  /** b89 (owner burn test Sept 21 ~03:32 Bris: 5-minute window hit 0 and
   *  the messages stayed on screen AND in this cache): burn-after-open must
   *  actually DELETE expired rows from the local plaintext msgcache, not
   *  just render a "0m 00s" countdown next to them. A row is burned when
   *  openedAt + burnSeconds*1000 <= now. Rows without openedAt are kept —
   *  they were never displayed on this device, so their clock hasn't
   *  started (ensureOpenedAt stamps them on the next open). Returns the
   *  purged ids so callers can prune in-memory state cheaply. */
  async purgeBurnedMessages(token: string, burnSeconds: number): Promise<string[]> {
    if (!(burnSeconds > 0)) return [];
    const list = await this.listMessages(token);
    const now = Date.now();
    // b198 (founder report, receipts battery): OWN copies whose burn clock was
    // anchored to the peer's READ RECEIPT never purged when the recipient has
    // read receipts OFF — no receipt ever lands, so the clock never starts and
    // the sent bubble sat in the thread forever. The anchor now ALSO honors the
    // relay envelope's real lifetime: an own copy purges at send + the
    // unopened horizon (the same moment the relay's sweeper deletes the
    // envelope) — receipts on or off, the sender's copy never outlives the
    // relay's copy.
    let horizonMs = 0;
    try {
      const sealed = (await this.load(token)) as { expireAfterSeconds?: number } | null;
      horizonMs = (Number(sealed?.expireAfterSeconds) || 86400) * 1000;
    } catch { horizonMs = 86400 * 1000; }
    const keep: ChatMessage[] = [];
    const purged: string[] = [];
    for (const m of list) {
      // systemNote rows are UI artifacts, not burnable chat content; rows
      // without openedAt were never displayed here so their clock never started.
      if ((m as { systemNote?: boolean }).systemNote || !m.openedAt || m.openedAt + burnSeconds * 1000 > now) keep.push(m);
      else if (m.mine && m.ts && Date.parse(m.ts) + horizonMs < now) purged.push(m.id); // b198: own copy = the envelope's lifetime
      else purged.push(m.id);
    }
    if (purged.length) {
      await this.cacheWrite(token, keep);
      // b198 (live-caught, first post-flip voice message): a row whose burn
      // countdown COMPLETED was human-displayed by definition — its relay burn
      // (and media blob delete) must unlock NOW, not orphan at the horizon.
      // The purge previously dropped the cache row and left the pendingBurn
      // entry displayed:false forever. Flip ONLY this pass's purged ids:
      // those are provably displayed; entries whose row is absent for other
      // reasons (cache-write refusals) still wait for the human (horizon).
      const list = await this.pendingBurns(token);
      if (list.length) {
        const purgedSet = new Set(purged);
        let flipped = false;
        for (const p of list) {
          if ((p as { displayed?: boolean }).displayed === false && purgedSet.has(p.id)) { p.displayed = true; flipped = true; }
        }
        if (flipped) await this.setPendingBurns(token, list);
      }
    }
    return purged;
  }

  async listMessages(token: string): Promise<ChatMessage[]> {
    return await this.cacheRead(token);
  }

  async listTokens(): Promise<string[]> {
    const keys = await this.storage.keys('veil_rk_');
    return keys.filter((k) => !k.startsWith('veil_rk_wrap_')).map((k) => k.slice('veil_rk_'.length));
  }
}
