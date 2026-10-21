/**
 * @veil/device — report / block / founder removal (Play UGC policy, 18 Oct 2026).
 *
 * Nothing here weakens end-to-end encryption: the relay never sees what a report
 * says, a block list, or why a post was removed. It (and every forum member) can
 * see THAT a report post was sent, by whom and when (Batch E R3-05 wording).
 *
 *  REPORT  A tester reports a forum post. The report is sealed to the forum
 *          founder with the same construction as the group rekey wrap
 *          (groups.ts buildRekeyWrap): ML-KEM-768 encapsulation to the
 *          founder's published PQ prekey, HKDF-SHA-256, AES-256-GCM. The PQ
 *          prekey is accepted only when its pq_sig verifies under the founder
 *          key pinned in the app (FORUM_PIN), so the relay can't swap it. The
 *          sealed report then travels as an ordinary signed forum post
 *          ({"__veil_report":...}): forum members can see that a control post
 *          was sent, but only the founder's phone can open it. Older apps
 *          already consume unknown __veil_* markers without showing them.
 *  REMOVE  The founder removes a post for everyone: a founder-signed
 *          {"__veil_remove":1,"ids":[...]} post tells every phone to drop the
 *          post (members accept it only from the founder's sender tag), and
 *          the relay deletes the stored copy for the founder's account only.
 *  BLOCK   Device-local list of Vardum IDs. Blocked senders' messages are not
 *          shown and don't notify. Nothing is sent anywhere.
 */
import { mlkemEncap, mlkemDecap } from '../../crypto-core/src/mlkem';
import { hkdf } from '../../crypto-core/src/kdf';
import { fromB64, toB64, utf8 } from '../../crypto-core/src/bytes';
import { verifyPqPrekeySig, veilIdFromIkPub } from '../../crypto-core/src/identity';

export const REPORT_MARKER = '{"__veil_report":';
export const REMOVE_MARKER = '{"__veil_remove":';
const REPORT_KDF_LABEL = 'vardum-forum-report-v1';
const MAX_FIELD = 500;
const MAX_REMOVE_IDS = 20;

/** What the founder learns from a report (the reporter is the post's signed sender). */
export interface ForumReport {
  /** envelope id of the reported post */
  postId: string;
  /** Vardum ID of the reported post's sender ('' when unknown) */
  authorVeilId: string;
  /** a short excerpt of the reported post, so the founder can find it */
  excerpt: string;
  /** the reporter's own words ('' when none given) */
  reason: string;
  /** ISO time the report was made */
  at: string;
}

interface SealedReport { v: 1; to: string; ct: string; wk: string; wi: string }

const clip = (s: unknown, n = MAX_FIELD) => String(s ?? '').slice(0, n);

async function reportKey(secret: Uint8Array, toVeilId: string, groupToken: string, usage: KeyUsage): Promise<CryptoKey> {
  const k = await hkdf(secret, utf8(REPORT_KDF_LABEL), `${toVeilId}:${groupToken}`, 32);
  return crypto.subtle.importKey('raw', k as unknown as BufferSource, { name: 'AES-GCM' }, false, [usage]);
}

/** Seal a report to the founder. Returns the post text to send through the forum. */
export async function sealForumReport(founderPqPubB64: string, founderVeilId: string, groupToken: string, report: ForumReport): Promise<string> {
  const body = JSON.stringify({
    post: clip(report.postId, 100), author: clip(report.authorVeilId, 40),
    excerpt: clip(report.excerpt), reason: clip(report.reason), at: clip(report.at, 40),
  });
  const { ct, secret } = await mlkemEncap(founderPqPubB64);
  const key = await reportKey(secret, founderVeilId, groupToken, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wk = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, utf8(body) as unknown as BufferSource));
  const sealed: SealedReport = { v: 1, to: founderVeilId, ct, wk: toB64(wk), wi: toB64(iv) };
  return JSON.stringify({ __veil_report: sealed });
}

/** True for a sealed-report post (whoever can or can't open it). */
export function isForumReportText(text: string): boolean {
  return text.startsWith(REPORT_MARKER);
}

/** Open a sealed report with my PQ private key. Null when it isn't addressed to
 *  me, is malformed, or fails to decrypt (never throws). */
/**
 * Batch E (Superagent round 3, N3-2): each report open is one ML-KEM
 * decapsulation on the founder's phone. A member flooding reports could burn
 * battery; cap opens per group in a sliding 10-minute window. Reports over the
 * cap wait in the queue below (Batch F; this said "dropped" until Batch H).
 */
const REPORT_OPEN_CAP = 30;
/** Batch F (round-4 review R4-2-02): one sender can't use the whole budget */
const REPORT_OPEN_CAP_PER_SENDER = 5;
const REPORT_OPEN_WINDOW_MS = 10 * 60_000;
const reportOpens = new Map<string, number[]>();
export function reportOpenAllowed(groupToken: string, now: number = Date.now(), sender?: string | null): boolean {
  const recent = (reportOpens.get(groupToken) ?? []).filter((t) => now - t < REPORT_OPEN_WINDOW_MS);
  reportOpens.set(groupToken, recent);
  if (recent.length >= REPORT_OPEN_CAP) return false;
  const sk = sender === undefined ? null : `${groupToken}|${sender ?? '?'}`;
  const mine = sk ? (reportOpens.get(sk) ?? []).filter((t) => now - t < REPORT_OPEN_WINDOW_MS) : [];
  if (sk) reportOpens.set(sk, mine);
  if (sk && mine.length >= REPORT_OPEN_CAP_PER_SENDER) return false;
  recent.push(now);
  if (sk) mine.push(now);
  return true;
}

/**
 * Batch F (R4-2-02): the cheap check, before any queueing or decapsulation — is
 * this a well-formed sealed report addressed to me? (Batch E spent a cap slot
 * before it, so junk posts used up the budget.)
 */
export function reportAddressedTo(text: string, myVeilId: string): boolean {
  if (!isForumReportText(text)) return false;
  try {
    const s = (JSON.parse(text) as { __veil_report?: { v?: unknown; to?: unknown } }).__veil_report;
    return !!s && s.v === 1 && s.to === myVeilId;
  } catch { return false; }
}

/**
 * Batch F (R4-2-02): reports over the cap WAIT instead of being lost. A group
 * envelope can't be decrypted twice (replay window), so the decrypted, still
 * sealed report text is queued on the founder's phone and opened on later
 * passes as the caps allow. At most 10 queued per sender and 200 in all.
 */
export interface QueuedReport { id: string; reporter: string | null; text: string; sentAt: string }
const REPORT_QUEUE_PREFIX = 'veil_report_queue_';
/** Batch H (round-6 review R6-2-02): each queued report is its own item; the
 *  queue key above is only a small index (id, reporter, time — no report text).
 *  One item held ~3.5 KB per report, so a busy queue hit the phone's size limit
 *  and every new report was then refused. */
const REPORT_ITEM_PREFIX = 'veil_report_q_';
const reportItemKey = (groupToken: string, id: string) => `${REPORT_ITEM_PREFIX}${groupToken}_${id}`;
const REPORT_QUEUE_PER_SENDER = 10;
const REPORT_QUEUE_MAX = 200;
/** an index entry; `text` is present only in the Batch F/G one-item format */
type QueueEntry = { id: string; reporter: string | null; sentAt: string; text?: string };
async function loadQueueIndex(storage: KV, groupToken: string): Promise<QueueEntry[]> {
  try {
    const raw = await storage.get(REPORT_QUEUE_PREFIX + groupToken);
    const arr = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(arr) ? (arr as QueueEntry[]).filter((x) => x && typeof x.id === 'string') : [];
  } catch { return []; }
}
async function removeKey(storage: KV, key: string): Promise<void> {
  try { if (storage.remove) await storage.remove(key); else await storage.set(key, ''); } catch { /* best-effort */ }
}
const indexOnly = (q: QueueEntry[]) => q.map((x) => (x.text !== undefined ? x : { id: x.id, reporter: x.reporter, sentAt: x.sentAt }));
/**
 * Batch G (round-5 reviews NF-2 / R5-2-01 / R5-2-02): a full share never refuses
 * a newcomer. When one sender has 10 queued, THAT sender's oldest goes; when the
 * queue holds 200, the oldest item of the sender with the most queued goes. So
 * a flood only ever pushes out its own items, and a refused write is an error.
 * Returns how many items were dropped to make room.
 */
export async function enqueueReport(storage: KV, groupToken: string, item: QueuedReport): Promise<number> {
  const q = await loadQueueIndex(storage, groupToken);
  if (q.some((x) => x.id === item.id)) return 0;
  const evicted: QueueEntry[] = [];
  const mine = q.filter((x) => x.reporter === item.reporter);
  if (mine.length >= REPORT_QUEUE_PER_SENDER) { q.splice(q.indexOf(mine[0]), 1); evicted.push(mine[0]); }
  if (q.length >= REPORT_QUEUE_MAX) {
    const counts = new Map<string | null, number>();
    for (const x of q) counts.set(x.reporter, (counts.get(x.reporter) ?? 0) + 1);
    let top: string | null = null, max = -1;
    for (const [r, c] of counts) if (c > max) { max = c; top = r; }
    const at = q.findIndex((x) => x.reporter === top);
    if (at >= 0) evicted.push(...q.splice(at, 1));
  }
  // Batch H (R6-2-02): the report's own item first, then the index; a refused
  // write is an error and leaves nothing half-saved
  let wrote: unknown;
  try { wrote = await storage.set(reportItemKey(groupToken, item.id), item.text); } catch { wrote = false; }
  if (wrote === false) throw new Error('Report queue not saved');
  q.push({ id: item.id, reporter: item.reporter, sentAt: item.sentAt });
  let wroteIndex: unknown;
  try { wroteIndex = await storage.set(REPORT_QUEUE_PREFIX + groupToken, JSON.stringify(indexOnly(q))); } catch { wroteIndex = false; }
  if (wroteIndex === false) { await removeKey(storage, reportItemKey(groupToken, item.id)); throw new Error('Report queue not saved'); }
  for (const e of evicted) if (e.text === undefined) await removeKey(storage, reportItemKey(groupToken, e.id));
  return evicted.length;
}
export async function drainReportQueue(
  storage: KV, groupToken: string, open: (item: QueuedReport) => Promise<void>, now: number = Date.now(),
  /** Batch G: a blocked reporter's items leave the queue unopened */
  isBlocked?: (veilId: string) => boolean,
): Promise<{ opened: number; waiting: number }> {
  const q = await loadQueueIndex(storage, groupToken);
  if (!q.length) return { opened: 0, waiting: 0 };
  const keep: QueueEntry[] = [];
  const done: QueueEntry[] = [];
  let n = 0;
  for (const it of q) {
    if (it.reporter && isBlocked?.(it.reporter)) { done.push(it); continue; }
    if (!reportOpenAllowed(groupToken, now, it.reporter)) { keep.push(it); continue; }
    let text = it.text;
    if (text === undefined) { try { text = (await storage.get(reportItemKey(groupToken, it.id))) ?? undefined; } catch { text = undefined; } }
    done.push(it);
    if (!text) continue; // the item is gone: nothing to open
    try { await open({ id: it.id, reporter: it.reporter, text, sentAt: it.sentAt }); n += 1; } catch { /* unreadable report: dropped */ }
  }
  // Batch H (R6-2-02): an item from the older one-key format that must still wait
  // moves to its own key (it stays in the index with its text if that fails)
  for (const k of keep) {
    if (k.text === undefined) continue;
    let moved: unknown;
    try { moved = await storage.set(reportItemKey(groupToken, k.id), k.text); } catch { moved = false; }
    if (moved !== false) delete k.text;
  }
  if ((await storage.set(REPORT_QUEUE_PREFIX + groupToken, JSON.stringify(indexOnly(keep)))) === false) throw new Error('Report queue not saved');
  for (const d of done) if (d.text === undefined) await removeKey(storage, reportItemKey(groupToken, d.id));
  return { opened: n, waiting: keep.length };
}
/** test hook */
export function resetReportOpenLimits(): void { reportOpens.clear(); }

/**
 * Batch F (Superagent round 4, agent-01): this phone sends at most 3 reports a
 * day. The relay can't tell a report from a post (it is an ordinary sealed forum
 * post), so a modified app can ignore this. The founder phone's per-sender caps
 * and queue (R4-2-02) keep one sender from silencing others; a Sybil flood can
 * still make reports wait (Batch H, R6-2-09).
 */
const REPORT_SENDS_KEY = 'veil_report_sends_v1';
const REPORT_SENDS_PER_DAY = 3;
/** Batch G (R5-2-10): check without spending a slot … */
export async function reportSendAvailable(storage: KV, now: number = Date.now()): Promise<boolean> {
  let recent: number[] = [];
  try { const raw = await storage.get(REPORT_SENDS_KEY); const a = raw ? JSON.parse(raw) as unknown : []; if (Array.isArray(a)) recent = a.filter((t): t is number => typeof t === 'number'); } catch { /* damaged: start over */ }
  return recent.filter((t) => now - t < 86_400_000).length < REPORT_SENDS_PER_DAY;
}
/** … and spend it only after the report was actually sent */
export async function recordReportSend(storage: KV, now: number = Date.now()): Promise<void> {
  let recent: number[] = [];
  try { const raw = await storage.get(REPORT_SENDS_KEY); const a = raw ? JSON.parse(raw) as unknown : []; if (Array.isArray(a)) recent = a.filter((t): t is number => typeof t === 'number'); } catch { /* damaged: start over */ }
  recent = recent.filter((t) => now - t < 86_400_000);
  recent.push(now);
  await storage.set(REPORT_SENDS_KEY, JSON.stringify(recent));
}

export async function reportSendAllowed(storage: KV, now: number = Date.now()): Promise<boolean> {
  let recent: number[] = [];
  try { const raw = await storage.get(REPORT_SENDS_KEY); const a = raw ? JSON.parse(raw) as unknown : []; if (Array.isArray(a)) recent = a.filter((t): t is number => typeof t === 'number'); } catch { /* damaged: start over */ }
  recent = recent.filter((t) => now - t < 86_400_000);
  if (recent.length >= REPORT_SENDS_PER_DAY) return false;
  recent.push(now);
  await storage.set(REPORT_SENDS_KEY, JSON.stringify(recent));
  return true;
}

export async function openForumReport(myPqPrivB64: string, myVeilId: string, groupToken: string, text: string): Promise<ForumReport | null> {
  if (!isForumReportText(text)) return null;
  try {
    const s = (JSON.parse(text) as { __veil_report?: SealedReport }).__veil_report;
    if (!s || s.v !== 1 || s.to !== myVeilId || typeof s.ct !== 'string' || typeof s.wk !== 'string' || typeof s.wi !== 'string') return null;
    const secret = await mlkemDecap(myPqPrivB64, s.ct);
    const key = await reportKey(secret, myVeilId, groupToken, 'decrypt');
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(s.wi) as unknown as BufferSource }, key, fromB64(s.wk) as unknown as BufferSource);
    const b = JSON.parse(new TextDecoder().decode(pt)) as Record<string, unknown>;
    return { postId: clip(b.post, 100), authorVeilId: clip(b.author, 40), excerpt: clip(b.excerpt), reason: clip(b.reason), at: clip(b.at, 40) };
  } catch {
    return null;
  }
}

/**
 * The founder's PQ prekey, accepted only when the relay's identity record
 * carries the PINNED founder key and the PQ prekey is signed by it.
 */
export async function resolveFounderPqKey(
  relay: { identityLookup: (veilId: string) => Promise<unknown> },
  pin: { founderVeilId: string; founderIkPubB64: string },
): Promise<string> {
  const r = (await relay.identityLookup(pin.founderVeilId)) as { data?: Record<string, unknown> } | null;
  const d = (r?.data ?? {}) as Record<string, unknown>;
  const rec = ((d.data as Record<string, unknown>) ?? (d.identity as Record<string, unknown>) ?? d) as Record<string, unknown>;
  const ik = String(rec?.IK_pub ?? '');
  const pq = String(rec?.pq_pub ?? '');
  const sig = String(rec?.pq_sig ?? '');
  if (ik !== pin.founderIkPubB64 || (await veilIdFromIkPub(ik).catch(() => '')) !== pin.founderVeilId) {
    throw new Error('The founder’s identity could not be confirmed, so the report was not sent. Try again later.');
  }
  if (!pq || !(await verifyPqPrekeySig(ik, pq, sig))) {
    throw new Error('The founder’s encryption key could not be confirmed, so the report was not sent. Try again later.');
  }
  return pq;
}

/** The founder's "remove for everyone" post. */
export function buildRemoveText(envelopeIds: string[]): string {
  return JSON.stringify({ __veil_remove: 1, ids: envelopeIds.map((x) => clip(x, 100)).filter(Boolean).slice(0, MAX_REMOVE_IDS) });
}

/** Envelope ids named by a removal post, or null when the text isn't one. */
export function parseRemoveText(text: string): string[] | null {
  if (!text.startsWith(REMOVE_MARKER)) return null;
  try {
    const t = JSON.parse(text) as { __veil_remove?: unknown; ids?: unknown };
    if (t.__veil_remove !== 1 || !Array.isArray(t.ids)) return [];
    return t.ids.filter((x): x is string => typeof x === 'string' && !!x).slice(0, MAX_REMOVE_IDS);
  } catch {
    return [];
  }
}

// ---------- block list (device-local) ----------

export const BLOCK_LIST_KEY = 'veil_blocked_ids_v1';

interface KV { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown>; remove?(k: string): Promise<unknown> }

/** Batch E (Superagent round 3, N3-4 / F-4): the block list could not be read.
 *  Callers keep what they had (and retry) — never an empty list. */
export class BlockListUnreadableError extends Error {
  constructor() { super('The block list could not be read on this phone. Try again in a moment.'); this.name = 'BlockListUnreadableError'; }
}

function parseBlockList(raw: string): Set<string> {
  const arr = JSON.parse(raw) as unknown;
  if (!Array.isArray(arr)) throw new Error('not a list');
  return new Set(arr.filter((x): x is string => typeof x === 'string' && !!x));
}

/** Batch E (N3-4): fails closed. A damaged list falls back to the backup copy
 *  written with every save; if neither reads, it throws instead of returning an
 *  empty list (which used to un-hide every blocked sender, and a later block
 *  then overwrote the whole list). */
export async function loadBlockList(storage: KV): Promise<Set<string>> {
  let main: string | null;
  try { main = await storage.get(BLOCK_LIST_KEY); } catch { throw new BlockListUnreadableError(); }
  if (main) { try { return parseBlockList(main); } catch { /* damaged: try the backup */ } }
  let bak: string | null = null;
  try { bak = await storage.get(BLOCK_LIST_KEY + '_bak'); } catch { /* fall through */ }
  if (bak) { try { return parseBlockList(bak); } catch { /* fall through */ } }
  if (!main && !bak) return new Set();
  throw new BlockListUnreadableError();
}

async function saveBlockList(storage: KV, ids: Set<string>): Promise<Set<string>> {
  // the phone's secure store answers false when it refuses a write
  // Batch F (R4-2-05): never drop a block silently past the limit
  if (ids.size > 2000) throw new Error('The block list is full (2,000 people). Unblock someone first.');
  const body = JSON.stringify([...ids]);
  if ((await storage.set(BLOCK_LIST_KEY, body)) === false) throw new Error('This phone’s secure storage refused the change. Try again.');
  await storage.set(BLOCK_LIST_KEY + '_bak', body); // Batch E (N3-4): the fallback copy
  return ids;
}

export async function blockVeilId(storage: KV, veilId: string): Promise<Set<string>> {
  const ids = await loadBlockList(storage);
  const v = veilId.trim();
  if (v) ids.add(v);
  return saveBlockList(storage, ids);
}

export async function unblockVeilId(storage: KV, veilId: string): Promise<Set<string>> {
  const ids = await loadBlockList(storage);
  ids.delete(veilId.trim());
  return saveBlockList(storage, ids);
}

/** A message is hidden when its sender's Vardum ID is blocked. My own messages never are. */
export function isFromBlocked(m: { mine?: boolean; senderVid?: string | null }, blocked: ReadonlySet<string>): boolean {
  return !m.mine && !!m.senderVid && blocked.has(m.senderVid);
}

export function withoutBlocked<T extends { mine?: boolean; senderVid?: string | null }>(messages: T[], blocked: ReadonlySet<string>): T[] {
  if (!blocked.size) return messages;
  return messages.filter((m) => !isFromBlocked(m, blocked));
}
