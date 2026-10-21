/**
 * @veil/device — chat sync + send: the exact web envelope loop.
 *   fetch (veilSessionGate action:fetch, write_secret) -> decrypt new envelopes
 *   in order -> advance + reseal the ratchet. Send: encrypt -> submitEnvelope
 *   with the web's TTL/expiry contract.
 */

import { parseCallSignal, type CallSignal } from './calls';
import {
  encryptMessage, decryptMessage, completeHandshake,
  deserializeRatchetState, serializeRatchetState, senderPseudonym,
  toB64, fromB64, splitForBuckets, clampDials, type DialsInput,
} from '../../crypto-core/src/index';
import type { VeilRelay, SessionStore } from './index.js';
import { saveOrThrow } from './save-strict';
import { relayTimestampToIso } from './time';
import { serializeRatchetSend } from './send-queue';
import { relaySessionLiveness } from './session-liveness';
import { PEEK_DIALS_BURN_FLOOR_SECONDS } from './invite';
import { pageBacklog } from './backfill';

/** Media message descriptor — the web bundle's __veil_media payload (parser
 *  Hp). Media messages carry text:'' and render from these fields instead. */
export interface ChatMedia {
  /** encrypted blob URI in private storage */
  uri?: string;
  /** AES-256-GCM key (b64) — generated fresh per file, only ever E2E */
  k?: string;
  /** AES-GCM IV (b64) */
  iv?: string;
  mime?: string;
  name?: string;
  size?: number;
  /** sender allowed saving this file to the device (web dl:1) */
  dl?: boolean;
  /** device-local render source for the DECRYPTED bytes (sender: picker uri;
   *  receiver: in-memory data: URI — plaintext never touches disk) */
  localUri?: string;
}

export interface ChatMessage {
  id: string;
  text: string;
  mine: boolean;
  ts: string | null;
  media?: ChatMedia;
  /** b199: a group invitation card (text is '' for these) */
  groupInvite?: ChatGroupInvite;
  /** set on MY messages when a peer receipt confirms read:true (web read-receipt parity) */
  read?: boolean;
  /** b199: one reaction per side (pairwise threads) */
  reactions?: { mine?: string; peer?: string };
  /** relay record id captured from the submitEnvelope response (web envelopeId
   *  parity) — MY messages match incoming receipt ids on this, not the local id */
  envId?: string;
  /** b72: when this message was FIRST OPENED on this device (epoch ms) — the
   *  anchor for the web-parity "burn N hours after open" countdown. Stamped at
   *  creation on the receive/send path; older cached rows without it are
   *  stamped on first display by SessionStore.ensureOpenedAt(). */
  openedAt?: number;
  /** Play UGC: the sender's Vardum ID on received group/forum rows (block list match) */
  senderVid?: string;
}

/** b82 EMERGENCY KILL-SWITCH for burn-after-open calls.
 *  HISTORY (Sept 20 incident): the relay gate's 'burn' action was
 *  deleting the ENTIRE VeilSession row, not just the target envelope —
 *  every burn_after_open session self-destructed on its first decrypted
 *  envelope (f240, ed5c1c8a, the b80-era "dead session" flood). b82
 *  disabled ALL native burn calls until the gate was fixed.
 *  b86 (Sept 21): FIX CONFIRMED. The builder delivered the verbatim
 *  burn branch — its ONLY write is VeilEnvelope.update(env.id, ...)
 *  shortening expires_at to the session's burn window (never-extend,
 *  idempotent, no session delete/cascade anywhere in the branch), and a
 *  live end-to-end test on the deployed gate showed the session row
 *  surviving with repeat burn calls returning ok. Kill-switch flipped
 *  OFF; burn-after-open is live again. Keep the flag as an emergency
 *  switch: set callsDisabled back to true ONLY if the invariant breaks
 *  again (symptom: "Session not found" right after a successful burn). */
export const burnFlags = { callsDisabled: false };

export interface SyncResult {
  /** b80: set when this sync discovered the session no longer exists
   *  server-side (a real 404 from the relay, not a guess) — caller should
   *  drop this token from sessionRows / mark the thread ended locally. */
  ended?: boolean;
  /** b87: the skip cursor the caller should persist via
   *  SessionStore.saveSyncSkip() before the next poll — see chat.ts's
   *  syncChat for the advance rule. Always present (0 is a valid value). */
  nextSkip: number;
  /** b143: call signaling payloads decrypted this pass (offers, answers,
   *  ICE candidates, hangups) — filtered from messages, consumed by the
   *  call UI. Empty on every ordinary poll. */
  callSignals?: CallSignal[];
  /** b91 (web stray-classifier parity): envelope ids that failed to decrypt
   *  BUT a newer envelope in the same pass decrypted fine — a stale stray
   *  the ratchet has moved past. Caller surfaces a soft notice. */
  strayIds?: string[];
  /** b91: true when failures look like a GENUINE desync — header-key
   *  mismatch (epoch divergence), timestamp-less failures, or failures with
   *  no successful newer decrypt after them. Caller keeps the destructive
   *  end-session recommendation. */
  desync?: boolean;
  /** b175: the relay rejected a burn/fetch this pass with its anti-abuse
   *  rate limiter. Caller should back off its poll interval instead of
   *  retrying at full speed — see App.tsx syncToken. */
  rateLimited?: boolean;
  /** Batch E (Superagent round 3, F-1): burns the relay keeps refusing after
   *  the fast retries — still queued (with backoff), shown in the thread. */
  burnStuck?: number;
  /** Batch H (R6-1-06): this phone's storage refused the chat state this pass */
  stateNotSaved?: boolean;
  /** Batch H (R5-1-09): the burn queue could not be saved, or is full */
  burnQueueTrouble?: boolean;
  messages: ChatMessage[];
  /** every envelope id decrypted this pass — including filtered control/cover
   *  ones — so the caller's knownIds set stays complete (a consumed ratchet
   *  message key can't be re-derived; re-decrypt on the next poll fails). */
  processedIds: string[];
  /** ids of MY messages the peer confirmed READ (receipt payloads with
   *  read:true) — caller marks those bubbles read (web parity). */
  readIds: string[];
  /** b199 reactions: the peer's reaction changes this pass, in order —
   *  target = the reacted message's envelope id, emoji null = removed. */
  reactions?: { target: string; emoji: string | null }[];
  state: import('../../crypto-core/src/index').RatchetStateSerialized;
}

/** b199 (owner request, Oct 17): hold a message to react. The only emoji a
 *  reaction may carry — anything else received is ignored. */
export const REACTION_EMOJI = ['👍', '👎', '❤️', '🙏', '😂', '😮'] as const;

interface EnvelopeRecord {
  id?: string;
  ciphertext?: string;
  iv?: string;
  header?: string;
  sender_client_id?: string;
  created_date?: string;
  expires_at?: string;
}

/**
 * The relay returns the created record's id in the submitEnvelope response
 * (web: `.data?.id`). Native's invoke hands back the raw body, so the id can
 * sit at data.id or data.data.id depending on wrapping — try both.
 */
/** b127: the relay's gate can reject an envelope submission with HTTP 200
 *  + an error body (owner repro Sept 25 23:24 UTC: read-receipt #2 returned
 *  {ok:true} to the caller, never appeared as a VeilEnvelope row, and the
 *  ratchet send-counter showed no advance). Silent 200-wrapped rejects were
 *  eating receipts — and would eat messages/covers the same way. Every
 *  submit site now throws on any error marker so the caller's retry
 *  actually engages. */
function assertSubmitOk(r: { data: unknown; status: number }, what: string): void {
  const d = r.data as { error?: unknown } | null;
  if (r.status >= 400 || (d && typeof d.error === 'string')) {
    throw new Error(`${what} rejected by relay (${r.status}): ${d?.error ?? 'no detail'}`);
  }
}

function submitResponseId(data: unknown): string | undefined {
  const d = data as { id?: unknown; data?: { id?: unknown } };
  if (typeof d?.id === 'string' && d.id) return d.id;
  if (typeof d?.data?.id === 'string' && d.data.id) return d.data.id;
  return undefined;
}

function extractEnvelopes(data: unknown): EnvelopeRecord[] {
  const d = data as { data?: unknown; envelopes?: unknown };
  const list = d?.data ?? d?.envelopes ?? data;
  if (!Array.isArray(list)) return [];
  const recs = list as EnvelopeRecord[];
  // process OLDEST FIRST — counters must advance in order; anything still
  // out of order lands in the skipped-key cache, never dropped
  return recs.slice().sort((a, b) =>
    String(a.created_date ?? '').localeCompare(String(b.created_date ?? '')));
}

/**
 * AAD is the envelope record's header field STRING, byte-for-byte exactly as
 * received from the relay — NEVER parsed and re-stringified (even a key-order
 * change fails the AES-GCM tag on every message, silently). Object form is a
 * legacy fallback only; the string form round-trips untouched.
 */
/** non-ratchet fields that must survive every reseal (serialize drops them).
 *  Batch D (D-09, RV-07): ALL the dials, not only burnAfterOpen — before this the
 *  expiry and burn dials were dropped by the first reseal, so every envelope
 *  after the first fell back to a 24 h expiry. */
// Batch F (R4-1-04): plus who the chat is with (sealed at the contact handshake)
// Batch F (R4-1-03): plus this phone's own safety-code confirmation; (R4-1-01) where the dials came from
const SEALED_DIAL_FIELDS = ['burnAfterOpen', 'defaultTtlSeconds', 'expireAfterSeconds', 'keyRetentionHours', 'peerVeilId', 'peerIkPub', 'myVerifiedFp', 'dialsSource'] as const;
function withExtras(serialized: unknown, sealed: unknown): never {
  const extras: Record<string, unknown> = {};
  for (const f of SEALED_DIAL_FIELDS) {
    const v = (sealed as Record<string, unknown>)[f];
    if (v !== undefined) extras[f] = v;
  }
  return { ...(serialized as Record<string, unknown>), ...extras } as never;
}

/**
 * Batch D (D-09): the session's dials. The signed transcript copy (state.dials,
 * bound into the fingerprint since V-12) comes first; sessions from before it
 * use the copy sealed at completion. Never the relay row.
 */
export function sessionDials(sealed: unknown): DialsInput | null {
  const s = (sealed ?? {}) as { dials?: unknown; burnAfterOpen?: unknown; defaultTtlSeconds?: unknown; expireAfterSeconds?: unknown; keyRetentionHours?: unknown };
  if (typeof s.dials === 'string') {
    const m = /^t=(\d+);e=(\d+);r=(\d+);b=([01])$/.exec(s.dials);
    if (m) return clampDials({ defaultTtlSeconds: Number(m[1]), expireAfterSeconds: Number(m[2]), keyRetentionHours: Number(m[3]), burnAfterOpen: m[4] === '1' });
  }
  if (s.defaultTtlSeconds !== undefined || s.expireAfterSeconds !== undefined || s.keyRetentionHours !== undefined) {
    return clampDials({
      defaultTtlSeconds: s.defaultTtlSeconds as number, expireAfterSeconds: s.expireAfterSeconds as number,
      keyRetentionHours: s.keyRetentionHours as number, burnAfterOpen: s.burnAfterOpen === true,
    });
  }
  return null;
}

/**
 * Batch F (round-4 review R4-1-03): did the user on THIS phone confirm the
 * safety code for the session's current fingerprint? The relay's per-side
 * "verified" flags are only hints for the badge; a relay could set them. The
 * send gate needs this local confirmation. Bound to the fingerprint, so a key
 * change (a new fingerprint) needs a new confirmation.
 */
export function locallyVerified(sealed: unknown): boolean {
  const s = (sealed ?? null) as { fingerprint?: string | null; myVerifiedFp?: unknown } | null;
  if (!s || typeof s.myVerifiedFp !== 'string' || !s.myVerifiedFp) return false;
  // Batch G (round-5 NF-1 / R5-1-07): no fingerprint on this phone = nothing was compared
  if (typeof s.fingerprint !== 'string' || !s.fingerprint) return false;
  return s.myVerifiedFp === s.fingerprint;
}

/** Batch H (round-6 review R6-1-05): a key-change revocation clears the sealed
 *  confirmation, so it survives a restart and a fresh comparison is needed. */
export async function clearLocalVerification(sessions: SessionStore, token: string): Promise<void> {
  await serializeRatchetSend(token, async () => {
    const sealed = await sessions.load(token);
    if (!sealed || !(sealed as { myVerifiedFp?: string }).myVerifiedFp) return;
    const { myVerifiedFp: _gone, ...rest } = sealed as unknown as Record<string, unknown>;
    void _gone;
    // Batch I (local review V-03): a refused save used to resolve quietly and
    // the confirmation came back after a restart. It's reported now; the app
    // keeps the gate closed and retries.
    if ((await sessions.save(token, rest as never)) === false) {
      throw new Error('The key-change revocation could not be saved on this phone.');
    }
  });
}

/** Batch F (R4-1-03): seal "I compared the codes and they match" for the session's
 *  current fingerprint. Runs under the session's ratchet lock so a sync or send
 *  in flight can't write over it. */
export async function markLocallyVerified(sessions: SessionStore, token: string): Promise<void> {
  await serializeRatchetSend(token, async () => {
    const sealed = await sessions.load(token);
    if (!sealed) throw new Error('No ratchet state for this session on this device.');
    const fp = (sealed as { fingerprint?: string | null }).fingerprint;
    // Batch G (NF-1): never seal a confirmation without a safety code to compare
    if (typeof fp !== 'string' || !fp) throw new Error('This chat has no safety code on this phone, so it can’t be verified.');
    await sessions.save(token, { ...(sealed as unknown as Record<string, unknown>), myVerifiedFp: fp } as never);
  });
}

/**
 * Batch E (round-3 review F-14): text the user typed is never a control post.
 * Text that happens to start like one ({"__veil_...) gets an invisible word
 * joiner in front, so receivers show it as text and the send-side control
 * exemptions (eviction pending, stale member key) don't apply to it.
 */
export function userText(text: string): string {
  // Batch F (R4-4-15): any text that starts like JSON (the 1:1 classifier parses
  // JSON and matches keys anywhere), not only a literal {"__veil_ prefix
  return text.trimStart().startsWith('{') ? '\u2060' + text : text;
}

/**
 * Batch E (round-3 review R1-01): the burn window used to purge local
 * plaintext. The session's own dials (signed transcript copy, else the copy
 * sealed at completion) always win; the relay row's dials are used only for a
 * legacy thread that has no local dials at all (disclosed residual). Before
 * this, closed threads purged on the row alone, so the relay could set a 1 s
 * burn and wipe history early.
 */
export function burnWindow(sealed: unknown, row?: { burn: boolean; burnSecs: number }): { burn: boolean; secs: number } {
  const d = sessionDials(sealed);
  // Batch F (R4-1-01): dials a joiner took from the relay (an older link) only
  // ever lengthen the local window, never shorten it
  if (d && (sealed as { dialsSource?: unknown } | null)?.dialsSource === 'peek') {
    return { burn: !!d.burnAfterOpen, secs: Math.max(Number(d.defaultTtlSeconds) || 0, PEEK_DIALS_BURN_FLOOR_SECONDS) };
  }
  if (d) {
    // a b74-era web-joined thread sealed its TTL but not the burn flag: the row may
    // still switch burn ON, but only at the session's own window
    const s = (sealed ?? {}) as { dials?: unknown; burnAfterOpen?: unknown };
    const flagKnown = typeof s.dials === 'string' || s.burnAfterOpen !== undefined;
    return { burn: flagKnown ? !!d.burnAfterOpen : !!row?.burn, secs: Number(d.defaultTtlSeconds) || 0 };
  }
  if (row) return { burn: !!row.burn, secs: Number(row.burnSecs) || 0 };
  return { burn: false, secs: 0 };
}

/**
 * Web sends protocol-control envelopes (session intro metadata, delivery
 * receipts) and continuous cover-traffic padding through the SAME encrypted
 * channel as real chat text — decrypt succeeds for all of them, so the app
 * layer (not the crypto layer) must keep non-chat payloads out of the UI.
 * Cover envelopes decrypt to filler content (random bytes, no real meaning);
 * control envelopes decrypt to a JSON object tagged with a __veil_* key.
 */
/** Web parity (Hp): a valid __veil_media body needs uri + k + iv; defaults
 *  match the bundle (mime application/octet-stream, name 'media', size 0,
 *  dl only when ===1). */
export function parseMediaPayload(text: string): ChatMedia | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_media":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_media !== 1 || !t.uri || !t.k || !t.iv) return null;
    return {
      uri: String(t.uri),
      k: String(t.k),
      iv: String(t.iv),
      mime: t.mime ? String(t.mime) : 'application/octet-stream',
      name: t.name ? String(t.name) : 'media',
      size: Number(t.size) || 0,
      dl: t.dl === 1,
    };
  } catch { /* not valid media JSON */ }
  return null;
}

/** b199 group invite delivered inside an encrypted 1:1 chat (owner request,
 *  Oct 16 2026: add pinned contacts to groups instead of sharing links). The
 *  link inside carries the group key, so it only ever travels E2E-encrypted;
 *  the seat it points at is locked to the recipient's Veil ID on the relay. */
export interface ChatGroupInvite {
  name: string;
  link: string;
  /** the inviter's Veil ID (display only — the join itself is the proof) */
  from?: string;
}

export function buildGroupInvitePayload(inv: ChatGroupInvite): string {
  return JSON.stringify({ __veil_group_invite: 1, name: String(inv.name).slice(0, 40), link: inv.link, ...(inv.from ? { from: inv.from } : {}) });
}

export function parseGroupInvitePayload(text: string): ChatGroupInvite | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_group_invite":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    const link = String(t.link ?? '');
    if (t.__veil_group_invite !== 1 || !/[?&]join=[0-9a-f]+/.test(link) || !/[?&#]w=/.test(link) || !/[?&]g=/.test(link)) return null;
    return { name: String(t.name ?? 'Group').slice(0, 40) || 'Group', link, ...(t.from ? { from: String(t.from) } : {}) };
  } catch { return null; }
}

/** b198 (cutover battery, owner decision): the media cap is 25 MB on BOTH sides —
 * the relay's disk-fill guard and this client cap are ALIGNED (the old mismatch:
 * client allowed 100 MB while the relay 413'd at 12 MB — a confusing failure the
 * battery would have caught). No soft-warn tier: the cap IS the disclosure. */
export const MEDIA_LIMIT_BYTES = 26214400; // b198: 25 MB hard cap, relay-aligned
export const MEDIA_SOFT_WARN_BYTES = 26214400; // b198: no separate warn tier

/** Web parity (Td): fresh 32-byte AES-GCM key + 12-byte IV per file. */
export async function encryptMedia(bytes: Uint8Array): Promise<{ ciphertext: Uint8Array; keyB64: string; ivB64: string }> {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await crypto.subtle.importKey('raw', key as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, k, bytes as unknown as BufferSource));
  return { ciphertext: ct, keyB64: toB64(key), ivB64: toB64(iv) };
}

/** Web parity (Ed): decrypt with the b64 key/iv carried in the payload. */
export async function decryptMedia(bytes: Uint8Array, keyB64: string, ivB64: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', fromB64(keyB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource }, k, bytes as unknown as BufferSource));
}

function classifyDecrypted(dec: { text: string; cover: boolean }): 'chat' | 'cover' | 'intro' | 'receipt' | 'media' | 'call' | 'invite' {
  if (dec.cover) return 'cover';
  try {
    const parsed = JSON.parse(dec.text) as Record<string, unknown>;
    if (parsed && typeof parsed === 'object') {
      if (parsed.__veil_intro) return 'intro';
      if (parsed.__veil_receipt) return 'receipt';
      if (parseMediaPayload(dec.text)) return 'media';
      if (parseGroupInvitePayload(dec.text)) return 'invite';
      if (parsed.__veil_call === 1) return 'call';
    }
  } catch { /* not JSON — a normal chat message */ }
  return 'chat';
}

function headerString(h: unknown): string {
  if (typeof h === 'string') return h;
  if (h && typeof h === 'object') { try { return JSON.stringify(h); } catch { return ''; } }
  return '';
}

/**
 * b85: fire the server-side alert push for a just-submitted REAL message.
 * Fire-and-forget on purpose — delivery of the message itself must never
 * depend on the notify path (the gate action may not exist yet server-side;
 * it will 400 "Unknown action" until the builder lands it, which we swallow
 * and log once per send).
 */
export async function notifySent(relay: VeilRelay, token: string, writeSecret: string | null): Promise<void> {
  // b183: a rapid-fire burst fires one notify per send, and each call while
  // the relay limiter is locked is a wasted 429/500 that keeps eating the
  // SAME anti-abuse budget that locked it (owner Metro + live-relay battery
  // Oct 2: veilSessionGate(notify) 500 "Rate limit exceeded" storms during
  // bursts). Two guards, both self-healing:
  //  - coalesce: at most one notify attempt per token per 5s — the reader's
  //    1.5-3s poll cycle makes anything denser redundant.
  //  - suppress: a rate-limited notify mutes ALL notifies for 60s; the next
  //    successful send's notify re-probes the gate on its own.
  const now = Date.now();
  if (now < notifyLimiterUntil) return;
  const last = notifyLastAt.get(token) ?? 0;
  if (now - last < 5_000) return;
  notifyLastAt.set(token, now);
  if (notifyLastAt.size > 200) notifyLastAt.clear(); // bound: sessions churn
  try {
    await relay.sessionNotify(token, writeSecret);
  } catch (e) {
    const msg = (e as Error).message ?? String(e);
    if (/rate limit/i.test(msg)) {
      notifyLimiterUntil = Date.now() + 60_000;
      console.log(`[veil] notify suppressed 60s (relay limiter) after #${token.slice(0, 4)}`);
    }
    console.log(`[veil] notify push skipped for #${token.slice(0, 4)}: ${msg}`);
  }
}
let notifyLimiterUntil = 0;
const notifyLastAt = new Map<string, number>();

/** Pull new envelopes for a session and decrypt them. Ratchet resealed after. */
/**
 * b102 shared burn-result classifier — used by both the fresh-decrypt burn
 * call and the pending-burn retry pass so the two sites can never drift.
 * "gone-session": the VeilSession row is dead server-side — stop entirely,
 * the caller sets sessionGoneRef. "gone-envelope": only this one envelope
 * vanished (concurrent teardown) — burn's goal is already met, drop it.
 * "retry": an ordinary transient failure (network, 5xx) — queue for the
 * next sync pass.
 */
function classifyBurnError(msg: string): 'gone-session' | 'gone-envelope' | 'rate-limited' | 'retry' {
  // Batch F (round-4 review R4-4-07): the exact relay answer only, not a substring
  if (/^\s*session not found\s*$/i.test(msg)) return 'gone-session';
  if (/entity veilenvelope with id .* not found/i.test(msg)) return 'gone-envelope';
  // b175 (owner Metro repro, Oct 2: rapid-fire burst tripped the relay's
  // own anti-abuse limiter — burn/heartbeat/list all 500'd "Rate limit
  // exceeded"). Pre-fix this fell into the generic 'retry' bucket, so a
  // rate-limited pass just kept firing burn attempts for every remaining
  // queued envelope AT FULL SPEED — the opposite of backing off, and the
  // same abuse signature that caused the historical K-4 10-minute lockout.
  if (/rate limit exceeded/i.test(msg)) return 'rate-limited';
  return 'retry';
}

/** b197-r8m: mark an envelope DISPLAYED — the human actually saw it. Flips its
 *  awaiting-display burn entry so the next sync pass delivers the burn.
 *  Called from App.tsx at the live-render site (where openedAt is stamped).
 *  Undisplayed envelopes are never burned — they live to the unopened
 *  horizon (the expire dial), per the owner's two-dial lifetime spec. */
export async function markEnvelopeDisplayed(relay: VeilRelay, sessions: SessionStore, token: string, envId: string): Promise<void> {
  return markEnvelopesDisplayed(relay, sessions, token, [envId]);
}

/**
 * b198 CACHE-RENDER LOOPHOLE (live-caught, media test Oct 15): a message
 * decrypted by BACKGROUND sync while the thread was closed is cached with
 * openedAt = machine-DECRYPT time and a pendingBurn entry stuck displayed:false.
 * The old marker fired ONLY on the live-arrival render path, so cache-rendered
 * messages NEVER unlocked their relay burn: the local view countdown ran off
 * the stale decrypt-stamped clock and the bubble vanished at the dial while the
 * relay envelope (and the media blob file) lived on — the two-dial semantics
 * broke exactly for the most common case (peer sends while you're not in the
 * thread). This batch marker is called at THREAD OPEN for every cached peer
 * row: it flips the pending entries (the relay burn fires next pass, media
 * blobs ride along) and RE-ANCHORS the cached rows' openedAt to the human-open
 * moment. Idempotent: already-displayed entries are skipped and their clock is
 * never re-anchored (thread reopens don't reset a running burn).
 */
export async function markEnvelopesDisplayed(relay: VeilRelay, sessions: SessionStore, token: string, envIds: string[]): Promise<void> {
  const ids = envIds.filter(Boolean);
  if (!ids.length) return;
  const list = await sessions.pendingBurns(token);
  const flipped: string[] = [];
  for (const id of ids) {
    const entry = list.find(p => p.id === id) as { id: string; attempts: number; displayed?: boolean } | undefined;
    if (!entry || entry.displayed) continue;
    entry.displayed = true;
    flipped.push(id);
  }
  if (flipped.length) {
    await sessions.setPendingBurns(token, list);
    await sessions.stampOpenedAt(token, flipped);
    console.log(`[veil] burn UNLOCKED for ${flipped.length} message(s) on #${token.slice(0, 4)} (human open) — fires next pass`);
  }
}

/** b102: cap on pending-burn retry attempts per envelope before giving up
 *  and logging a visible error — protects against retrying forever against
 *  a permanently-broken relay while still surviving many transient blips
 *  (each sync pass is 1.5-3s while a thread is open, so 20 attempts is
 *  30-60s of retrying, plus it resumes across app restarts). */
const MAX_BURN_RETRY_ATTEMPTS = 20;
/** Batch E (F-1): after the fast retries a refused burn is NOT dropped — it is
 *  retried with backoff (1 min doubling to 1 h) until the relay's own sweep
 *  backstop (49 h) has certainly removed the envelope. */
// Batch F (R4-4-12): an envelope can live up to 30 days (the forum dial), not just
// the 49 h file backstop, so refused burns keep trying for that long
const BURN_BACKSTOP_MS = 30 * 24 * 3600_000;
const BURN_BACKOFF_MAX_MS = 3600_000;

export function syncChat(...args: Parameters<typeof syncChatUnlocked>): ReturnType<typeof syncChatUnlocked> {
  // b173: syncs mutate ratchet state (load -> decrypt -> save) exactly like
  // sends do — but the two ran UNSERIALIZED against each other. b147 chained
  // every ratchet-encrypting send per token, while syncChat read the sealed
  // state, spent hundreds of ms paging the relay, and saved on its own
  // schedule. A send landing mid-poll wrote its advance from the pre-sync
  // state; the poll's save then clobbered it (or vice versa). The ratchet
  // forked, the peer's next decrypt hit "counter out of range", and threads
  // "dropped in and out" as the forks alternated. Both sides of the race now
  // share the same per-token chain.
  return serializeRatchetSend(args[2] as string, () => syncChatUnlocked(...args));
}

export async function syncChatUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  knownIds: ReadonlySet<string>,
  burnAfterOpen = false,
  startSkip = 0,
  /** Batch D (D-09): ignored — the burn window comes from the session's own dials, never the relay row */
  _burnSecondsHint = 0,
): Promise<SyncResult> {
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const state = await deserializeRatchetState(sealed);
  // b78: durable dedupe — the relay re-serves every envelope on every poll,
  // and a re-decrypt of a consumed envelope re-runs the PQ rekey and
  // PERMANENTLY desyncs the session ("Message counter out of range"). The
  // caller's knownIds set is a per-thread accelerator; this ledger is the
  // authoritative record (it also covers filtered control payloads the
  // message cache never sees).
  const ledger = await sessions.processedIds(token);
  // b91: strays classified on a previous pass are never re-attempted (a
  // consumed ratchet key can't be re-derived; re-attempts only re-log)
  const strayLedger = await sessions.strayIds(token);

  // WEB-PARITY RECEIVE: the web client polls the VeilEnvelope ENTITY
  // (filter({session_token}, 'created_date', 200)) — it never calls a gate
  // 'fetch' action.
  // b83 (owner repro, direct server confirmation): the legacy gate 'fetch'
  // fallback that used to live here is DEAD — veilSessionGate now rejects
  // it with HTTP 400 "Unknown action". It was only ever reached on a
  // transient entity-poll network failure (exactly the case that's common
  // around a lock/unlock or network handoff), so every one of those
  // recoverable hiccups was being turned into a SECOND, confusing, terminal
  // error ("Unknown action") that killed the whole sync pass. Removed —
  // a network failure here now just propagates once, cleanly, and the next
  // poll (1.5-3s later) retries on its own.
  // b196: newest-first pager (forum-parity with lounge.ts b195-r1). The old
  // ascending skip cursor froze an offset that SHIFTED every time the
  // sweeper purged expired rows — the same deletion-shift class the forum
  // path just fixed: a frozen offset could stride past unprocessed backlog,
  // and a partial page re-downloaded the entire remaining window on EVERY
  // pass (owner Metro log Oct 12: a 77-row thread re-fetched all 77 rows
  // every 1.5-10s, dominating per-account rate pressure). Pages anchor at
  // the NEWEST row — stable against expired-row deletion, which only ever
  // happens at the old/deep end of the sort — and depth is re-derived each
  // pass from the processed-id ledger (b78), never persisted as an offset.
  // The ledger check still runs on every fetched row before decrypt, so
  // ratchet-safety is unchanged; ordering is reversed back to oldest-first
  // so all downstream processing is untouched.
  // R1 (audit doc 13): the old fixed 3-page cap never reached a backlog
  // deeper than one pass, and the newest rows must not be decrypted ahead of
  // older ones (the ratchet keeps only 100 skipped keys per chain). The pager
  // (backfill.ts) now walks to the processed boundary or the thread's end,
  // resuming at a persisted row anchor when that takes more than one pass,
  // and the loop below stops after SYNC_BUDGET definitive outcomes so each
  // pass still does a bounded amount of decrypt work, oldest-first.
  const SYNC_PAGE = 50;
  const SYNC_FETCH_PAGES = 10;
  const SYNC_BUDGET = 150;
  // test doubles of SessionStore predate the anchor; without it a pass just
  // starts its descent from the top
  const anchorStore = sessions as Partial<Pick<SessionStore, 'backfillAnchor' | 'setBackfillAnchor'>>;
  const priorAnchor = (await anchorStore.backfillAnchor?.(token)) ?? null;
  const backlog = await pageBacklog({
    fetchPage: async (skip) => {
      const r = await relay.entityList('VeilEnvelope', {
        session_token: token, sort: '-created_date', limit: SYNC_PAGE,
        ...(skip > 0 ? { skip } : {}),
      });
      return extractEnvelopes(r) as Record<string, unknown>[];
    },
    isKnown: (id) => ledger.has(id) || strayLedger.has(id) || knownIds.has(id),
    pageSize: SYNC_PAGE,
    maxPages: SYNC_FETCH_PAGES,
    anchor: priorAnchor,
  });
  if (backlog.anchor || priorAnchor) await anchorStore.setBackfillAnchor?.(token, backlog.anchor);
  if (backlog.anchor) console.log(`[veil] sync #${token.slice(0, 4)}: backlog deeper than ${backlog.pages} page(s) — still descending, nothing decrypted this pass`);
  const recs = backlog.rows as EnvelopeRecord[]; // oldest-first, unprocessed only
  // vestigial cursor: kept for call-site type compat, never advances now
  const nextSkip = startSkip;
  // burn dial lives WITH the sealed ratchet (stored at completion/accept from
  // the session record); the param stays as a legacy fallback
  const burn = (sealed as { burnAfterOpen?: boolean }).burnAfterOpen ?? burnAfterOpen;
  console.log(`[veil] sync #${token.slice(0, 4)}: fetched ${recs.length} envelope(s)${burn ? ' (burn-after-open on)' : ''} (newest-first pager)`);

  const messages: ChatMessage[] = [];
  const cached: ChatMessage[] = [];
  const callSignals: CallSignal[] = [];
  const processedIds: string[] = [];
  const readIds: string[] = [];
  const reactions: { target: string; emoji: string | null }[] = [];
  let ownSkipped = 0;
  let filtered = 0;
  const sessionGoneRef = { gone: false };
  // b91 (web stray-classifier parity): every decrypt failure is recorded
  // with its header diagnostics + timestamp; after the pass, a failure that
  // a SUCCESSFUL decrypt of a NEWER envelope in the SAME session follows is
  // a stray (stale envelope the ratchet moved past) → soft notice. Key-
  // mismatch failures (header rp is not the expected remote ratchet key =
  // epoch divergence), timestamp-less failures, and failures with no later
  // success (stacking) never downgrade → genuine desync, end-session prompt.
  const failRecs: { id: string; ts: string | null; rpMismatch: boolean; order: number }[] = [];
  let orderCounter = 0;
  let lastSuccessOrder = -1;

  // b102 PENDING-BURN RETRY (owner Metro repro Sept 21: "burn failed for
  // <id>: Network request failed" — that envelope was already added to the
  // processed-ledger by the time burn ran, so it was NEVER retried and sat
  // at its full original expiry instead of burning on open). Runs BEFORE the
  // main loop, every pass, so a queued retry doesn't wait on new traffic —
  // an idle thread with only pending burns still drains them every poll.
  // b175: once the relay rate-limits ANY burn this pass, every further
  // burn attempt (retry queue AND the main loop below) stops immediately —
  // queued instead of fired. Hammering 20 more 500s in the same pass is
  // the exact anti-abuse signature that risked the K-4-era 10-minute lock.
  const rateLimitedRef = { hit: false };
  let burnStuck = 0;
  let pendingBurn = burn ? await sessions.pendingBurns(token) : [];
  if (pendingBurn.length && burn && !burnFlags.callsDisabled) {
    // b197-r8i (K-22 fix): burns pending → AMBIENT TRAFFIC YIELDS. Heartbeats
    // (7s) and cover sends were eating the per-account limiter budget while
    // the privacy-critical deletes starved, exhausted their 20-attempt
    // budget, and stayed on the relay. Hold ambient for this pass + a
    // grace window so the burn queue gets the budget first.
    relay.holdAmbientFor(10000);
    const survivors: { id: string; attempts: number; blob?: string; blobDeleteAt?: number; retryAt?: number; failingSince?: number }[] = [];
    for (const p of pendingBurn) {
      // Batch E (F-1): a late retry waits for its backoff
      const late = p as { retryAt?: number };
      if (late.retryAt && Date.now() < late.retryAt) { burnStuck++; survivors.push(p); continue; }
      // b197-r8m: AWAITING-DISPLAY entries are NOT burned — the human hasn't
      // seen them yet. They wait (the unopened horizon bounds the relay copy);
      // App.tsx flips displayed=true at live render, and the NEXT pass burns.
      if ((p as { displayed?: boolean }).displayed === false) { survivors.push(p); continue; }
      // b198 (live-caught): MEDIA BLOB DELETION IS SCHEDULED AT WINDOW END —
      // deleting at burn-unlock made the media unplayable the moment it was
      // opened (a replay inside the burn window hit a deleted file → 404 →
      // "couldn't load media"). The blob must live exactly as long as the
      // dial says the message does.
      const blobUri = (p as { blob?: string }).blob;
      const blobDeleteAt = (p as { blobDeleteAt?: number }).blobDeleteAt ?? 0;
      if (blobUri && blobDeleteAt) {
        if (Date.now() < blobDeleteAt) { survivors.push(p); continue; }
        try {
          await relay.deleteBlob(blobUri);
          console.log('[veil] media blob deleted from relay storage (burn window elapsed)');
          continue; // blob handled — entry complete
        } catch (e) {
          console.log(`[veil] media blob delete deferred: ${(e as Error).message ?? e}`);
          survivors.push(p); continue;
        }
      }
      if (sessionGoneRef.gone || rateLimitedRef.hit) { survivors.push(p); continue; } // session died or relay said slow down — keep queued
      try {
        await relay.sessionBurn(token, sealed.writeSecret, p.id);
        console.log(`[veil] burn retry OK for ${p.id} (after ${p.attempts + 1} attempt(s))`);
        // b198 MEDIA DELETION: media payloads carry the blob: uri INSIDE the
        // E2E body — this device decrypted it, so it holds the deletion
        // capability. SCHEDULE the file deletion at window end (open + the
        // burn dial) so the media stays playable for the whole window; the
        // 49h relay sweep is only the never-opened backstop.
        if (p.blob) {
          // b199 (ZTE device run, A3): the file lives exactly as long as the
          // bubble. The bubble reads the chat's dial (sealed, else the relay
          // row the caller passes); this used to fall back to a hard 300 s, so
          // a 60-min chat lost its photo after 5 min while the bubble stayed.
          // Batch D (D-09): the session's own dial (signed transcript, else sealed) — no relay-row fallback
          const burnSeconds = sessionDials(sealed)?.defaultTtlSeconds || 7200;
          survivors.push({ id: p.id, attempts: p.attempts, blob: p.blob, blobDeleteAt: Date.now() + burnSeconds * 1000 });
          console.log(`[veil] media blob deletion scheduled at window end (+${burnSeconds}s)`);
        }
      } catch (e) {
        const msg = (e as Error).message ?? String(e);
        const outcome = classifyBurnError(msg);
        if (outcome === 'gone-session') {
          console.log(`[veil] burn retry: session gone server-side while retrying ${p.id} — cleaning up`);
          sessionGoneRef.gone = true;
          survivors.push(p); // session teardown elsewhere handles this thread's full cleanup
        } else if (outcome === 'gone-envelope') {
          console.log(`[veil] burn retry: ${p.id} already gone — goal met, dropping from queue`);
        } else if (outcome === 'rate-limited') {
          console.log(`[veil] burn retry rate-limited for ${p.id} — pausing ALL burns this pass, caller should back off polling`);
          rateLimitedRef.hit = true;
          survivors.push(p); // don't burn the retry-attempt budget on a server-side throttle
        } else {
          const attempts = p.attempts + 1;
          const now = Date.now();
          const failingSince = (p as { failingSince?: number }).failingSince ?? now;
          if (now - failingSince > BURN_BACKSTOP_MS) {
            // the relay's sweep has removed the envelope by now (or the relay keeps copies, which no client can stop)
            console.log(`[veil] burn retry ended for ${p.id}: past the relay's expiry backstop`);
          } else if (attempts >= MAX_BURN_RETRY_ATTEMPTS) {
            // Batch E (Superagent round 3, F-1): never give up silently — back off and keep trying
            const retryAt = now + Math.min(60_000 * 2 ** Math.min(attempts - MAX_BURN_RETRY_ATTEMPTS, 6), BURN_BACKOFF_MAX_MS);
            console.log(`[veil] burn still refused for ${p.id} (attempt ${attempts}): ${msg} — retrying later`);
            burnStuck++;
            survivors.push({ id: p.id, attempts, blob: (p as { blob?: string }).blob, failingSince, retryAt });
          } else {
            console.log(`[veil] burn retry still failing for ${p.id} (attempt ${attempts}/${MAX_BURN_RETRY_ATTEMPTS}): ${msg}`);
            survivors.push({ id: p.id, attempts, blob: (p as { blob?: string }).blob, failingSince });
          }
        }
      }
    }
    pendingBurn = survivors;
  }

  for (const rec of recs) {
    if (sessionGoneRef.gone) break;
    // R1: per-pass budget counts definitive outcomes only, so rows that stay
    // retryable can't starve the newer ones behind them
    if (processedIds.length >= SYNC_BUDGET) break;
    if (!rec.id) continue;
    if (knownIds.has(rec.id) || ledger.has(rec.id) || strayLedger.has(rec.id)) continue;
    // web parity (Zu caller): expired envelopes are skipped client-side
    if (rec.expires_at && new Date(rec.expires_at).getTime() < Date.now()) continue;
    const header = headerString(rec.header);
    // Own-envelope filter (web rule Qu): skip ONLY when the header's rp is
    // one of OUR past ratchet pub JWKs (myPubs). sender_client_id is a
    // per-message pseudonym that rotates — NEVER filter on it.
    let rp = '';
    if (header) { try { rp = (JSON.parse(header) as { rp?: string }).rp ?? ''; } catch { /* decrypt logs the parse failure */ } }
    if (rp && state.myPubs.has(rp)) {
      ownSkipped++;
      // b174 (owner Metro repro, Oct 2: growing fetch counts every poll —
      // 21→22→23→24... — then UI freeze + scroll "ticking"): this branch
      // skips OUR OWN echoed envelopes BEFORE the decrypt step, which is
      // also where burn-after-open fires below. An own envelope therefore
      // never got added to the processed ledger and never got burned —
      // every message you sent sat on the relay forever, re-fetched AND
      // re-rechecked on EVERY poll, unbounded, for the life of the TTL.
      // Under a rapid-fire burst that list only grows, so each poll does
      // strictly more work than the last — exactly the freeze/jank seen.
      // Fix: ledger it immediately (stops the endless re-check in every
      // mode), and burn it server-side too when burn-after-open is on —
      // we already know it's consumed, no decrypt needed to prove that.
      processedIds.push(rec.id);
      // b198 (OWNER SPEC OVERRULES r8m): own echoes must NOT burn the shared
      // relay copy. That single envelope row IS the recipient's delivery —
      // burning it at the author's echo destroyed the recipient's unopened
      // horizon (the "burn starts at send, not open" behavior the founder
      // caught in live battery testing on the self-hosted relay).
      // The copy now dies ONLY by the two-dial contract:
      //   unopened by the recipient → expire_after horizon (12–48 h)
      //   recipient opens          → their display-flip burns it (open + burn window)
      if (burn && !burnFlags.callsDisabled && !sessionGoneRef.gone) {
        console.log(`[veil] own echo ${rec.id.slice(0, 8)}… ledgered, NOT burned — b198 two-dial: the RECIPIENT's open owns the burn clock`);
      }
      continue;
    }
    try {
      const dec = await decryptMessage(state, {
        ciphertext: String(rec.ciphertext ?? ''),
        iv: String(rec.iv ?? ''),
        header, // byte-for-byte AAD — untouched
      }, rec.id);
      if (dec) {
        lastSuccessOrder = ++orderCounter; // b91: successful decrypt — earlier failures may be strays
        let n = -1; try { n = (JSON.parse(header) as { n?: number }).n ?? -1; } catch { /* non-fatal */ }
        processedIds.push(rec.id);
        const kind = classifyDecrypted(dec);
        if (kind === 'chat') {
          console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}, rp=${rp.slice(0, 16)}...)`);
          const msg: ChatMessage = { id: rec.id, text: dec.text, mine: false, ts: relayTimestampToIso(rec.created_date), openedAt: Date.now() };
          messages.push(msg);
          cached.push(msg);
        } else if (kind === 'media') {
          // web parity: media messages render text:'' + the parsed descriptor
          console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — media message (${parseMediaPayload(dec.text)?.mime ?? '?'})`);
          const msg: ChatMessage = { id: rec.id, text: '', mine: false, ts: relayTimestampToIso(rec.created_date), openedAt: Date.now(), media: parseMediaPayload(dec.text) ?? undefined };
          messages.push(msg);
          cached.push(msg);
        } else if (kind === 'invite') {
          // b199: group invitation — rendered as a Join / Decline card
          console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — group invite`);
          const msg: ChatMessage = { id: rec.id, text: '', mine: false, ts: relayTimestampToIso(rec.created_date), openedAt: Date.now(), groupInvite: parseGroupInvitePayload(dec.text) ?? undefined };
          messages.push(msg);
          cached.push(msg);
        } else if (kind === 'receipt') {
          // web Wp parser: {"__veil_receipt":1,ids:[...],read:true|false}
          try {
            const r = JSON.parse(dec.text) as { __veil_receipt?: number; ids?: unknown; read?: boolean; react?: { t?: unknown; e?: unknown } };
            if (r.__veil_receipt === 1 && Array.isArray(r.ids) && r.read === true) {
              for (const id of r.ids) if (typeof id === 'string') readIds.push(id);
            }
            // b199 reactions ride a receipt envelope with no ids, so builds
            // that predate them treat it as an empty receipt (never as text)
            if (r.__veil_receipt === 1 && r.react && typeof r.react.t === 'string' && r.react.t) {
              const e = r.react.e;
              if (e === null || (typeof e === 'string' && (REACTION_EMOJI as readonly string[]).includes(e))) {
                reactions.push({ target: r.react.t, emoji: e as string | null });
              }
            }
          } catch { /* malformed receipt: not fatal, already processed */ }
          filtered++;
          console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — receipt payload (${readIds.length} read id(s) so far this pass)`);
        } else if (kind === 'call') {
          // b143: call signaling (offer/answer/ice/end) rides this channel
          // (design S3, L1). Filtered from the chat list like receipts, but
          // surfaced to the caller so the call UI can ring/connect.
          const sig = parseCallSignal(dec.text);
          if (sig) callSignals.push(sig);
          filtered++;
          console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — call signal (op=${sig?.op ?? '?'}), not shown in chat`);
        } else {
          filtered++;
          console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — ${kind} payload, not shown in chat`);
        }
        // b197-r8m (BURN-ON-HUMAN-OPEN, the owner's two-dial spec): PEER
        // envelopes NO LONGER burn at machine-decrypt — background sync
        // decrypts within minutes of sending, which made the fuse start
        // before any human saw anything (K-22/K-24 finding: "Jimmy hasn't
        // opened it and it's already burning"). Instead the envelope is
        // queued as AWAITING-DISPLAY: it burns only when the human actually
        // sees it (App.tsx stamps openedAt at live display and calls
        // markEnvelopeDisplayed). Undisplayed envelopes live to the
        // unopened horizon (the expire dial) — per the owner's two-dial spec.
        if (burn && !burnFlags.callsDisabled && !sessionGoneRef.gone && (kind === 'chat' || kind === 'media' || kind === 'invite')) {
          // HUMAN-DISPLAY payloads: queue AWAITING-DISPLAY — burns only when
          // the human actually sees it (App.tsx → markEnvelopeDisplayed).
          // b198: media payloads ride their blob: uri — carried on the burn
          // entry so the executed burn also deletes the ciphertext FILE from
          // the relay's disk (the relay cannot map blobs to sessions itself;
          // the uri only exists inside this E2E payload).
          pendingBurn.push({ id: rec.id, attempts: 0, displayed: false, blob: kind === 'media' ? (parseMediaPayload(dec.text)?.uri ?? undefined) : undefined });
          await sessions.setPendingBurns(token, pendingBurn);
          if (rec === recs[recs.length - 1]) console.log(`[veil] burn queued AWAITING-DISPLAY for #${token.slice(0, 4)} (${rec.id.slice(0, 8)}…)`);
        } else if (burn && !burnFlags.callsDisabled && !sessionGoneRef.gone) {
          // CONTROL payloads (receipt/call/cover/intro): machine-consumed,
          // never rendered to a human — burn at decrypt exactly as before.
          if (rateLimitedRef.hit) {
            pendingBurn.push({ id: rec.id, attempts: 0 });
          } else {
            try { await relay.sessionBurn(token, sealed.writeSecret, rec.id); }
            catch (e) {
              const msg = (e as Error).message ?? String(e);
              const outcome = classifyBurnError(msg);
              if (outcome === 'rate-limited') { rateLimitedRef.hit = true; pendingBurn.push({ id: rec.id, attempts: 0 }); }
              else if (outcome === 'gone-envelope') { console.log(`[veil] control burn: ${rec.id} already gone`); }
              else if (outcome === 'gone-session') { sessionGoneRef.gone = true; }
              else { pendingBurn.push({ id: rec.id, attempts: 0 }); }
            }
          }
        } else if (burn && (burnFlags.callsDisabled || rateLimitedRef.hit)) {
          if (rec === recs[recs.length - 1]) console.log(`[veil] burn-after-open SKIPPED for #${token.slice(0, 4)} (b82/rate-limit: queued state visible in Metro)`);
        } else if (burn) {
          try { await relay.sessionBurn(token, sealed.writeSecret, rec.id); }
          catch (e) {
            const msg = (e as Error).message ?? String(e);
            const outcome = classifyBurnError(msg);
            // b82: a gone-session burn refusal is an EXPECTED, HANDLED
            // condition — logging it via console.error made RN dev-mode
            // LogBox pop a full red "error" screen (owner saw exactly that
            // on b81) for a normal cleanup event. Only UNEXPECTED burn
            // failures on a live session stay console.error.
            if (outcome === 'gone-session') {
              console.log(`[veil] burn refused for ${rec.id} — session gone server-side, cleaning up`);
              sessionGoneRef.gone = true; break;
            }
            if (outcome === 'rate-limited') {
              console.log(`[veil] burn rate-limited for ${rec.id} — pausing ALL burns this pass, caller should back off polling`);
              rateLimitedRef.hit = true;
              pendingBurn.push({ id: rec.id, attempts: 0 }); // queued, not spent against the retry budget
              continue;
            }
            // b88 (owner repro Sept 21 ~03:15 Bris, Metro: burn HTTP 500
            // "Entity VeilEnvelope with ID ... not found" — same envelope
            // id this exact device had JUST decrypted a moment earlier in
            // the same pass, then a concurrent session-teardown swept it
            // before the burn call landed): the envelope being gone already
            // satisfies burn's own goal (it isn't sitting around any more),
            // so this is a miss, not a failure. Unlike the session-gone
            // case above, only THIS one envelope is affected — the session
            // itself may still be alive, so don't set sessionGoneRef; just
            // skip to the next envelope in the pass.
            if (outcome === 'gone-envelope') {
              console.log(`[veil] burn skipped for ${rec.id} — envelope already gone (${msg})`);
              continue;
            }
            // b102 (owner Metro repro Sept 21: "burn failed for <id>:
            // Network request failed"): rec.id is ALREADY in processedIds
            // above, so this envelope will never be re-decrypted or
            // re-attempted by the normal path — without this queue, a
            // dropped connection here meant the envelope sat at its full
            // original expiry, defeating burn-after-open on nothing more
            // than a network blip. Queue it; the retry pass at the top of
            // the NEXT call to this function (including the next poll, a
            // few seconds away) tries again.
            pendingBurn.push({ id: rec.id, attempts: 0 });
            console.log(`[veil] burn failed for ${rec.id}, queued for retry: ${msg}`);
            // b80 (owner report: Metro flooded non-stop with this exact
            // failure): "Session not found" from a well-formed token means
            // the VeilSession ROW is genuinely gone server-side (confirmed
            // directly against the live relay: a real dead token 404s here,
            // a real live token 403s on a bad credential instead) — but this
            // device's local ratchet cache is still valid, so it keeps
            // treating the thread as live forever, endlessly re-draining
            // whatever backlog of un-cleaned envelopes is still sitting on
            // the relay for that dead token. Detection + stop happens above.
          }
        }
      }
    } catch (e) {
      // NO silent catches — log the failure WITH reason
      console.error(`[veil] envelope ${rec.id}: decrypt FAILED — ${(e as Error).message ?? e}; header rp=${rp || '(unparsed)'} expected remote=${(state.remoteRatchetPub ?? '?').slice(0, 16)}...; state n=${state.recvCount} (skipped-key cache holds out-of-order counters, nothing is dropped)`);
      // b91: diagnostics for the stray-vs-desync classification below
      const rpMismatch = !!rp && !!state.remoteRatchetPub && rp !== state.remoteRatchetPub;
      failRecs.push({ id: rec.id, ts: rec.created_date ?? null, rpMismatch, order: ++orderCounter });
    }
  }
  // b91: classify the pass's failures. Stray = timestamped, key-matching, and
  // superseded by a later successful decrypt in this same pass. Everything
  // else (key mismatch / no timestamp / stacking with no later success) is
  // treated as a genuine desync.
  const strayIds = failRecs
    .filter((f) => !f.rpMismatch && f.ts !== null && f.order < lastSuccessOrder)
    .map((f) => f.id);
  if (strayIds.length) {
    await sessions.markStrayIds(token, strayIds);
  }
  const desync = failRecs.length > strayIds.length;
  if (ownSkipped) console.log(`[veil] sync #${token.slice(0, 4)}: skipped ${ownSkipped} own envelope(s) (header rp in myPubs)`);
  if (filtered) console.log(`[veil] sync #${token.slice(0, 4)}: filtered ${filtered} non-chat envelope(s) (cover/intro/receipt)`);
  const next = withExtras(await serializeRatchetState(state), sealed);
  // Batch F (round-4 review R4-1-02): a burn or fetch answer alone doesn't wipe a
  // chat. Ask the relay about THIS session (the same check as the open-chat
  // path); only a definite "Session not found" removes keys and history.
  if (sessionGoneRef.gone && (await relaySessionLiveness(relay, token, sealed.writeSecret ?? null)) !== 'gone') {
    console.log(`[veil] sync #${token.slice(0, 4)}: a relay answer said the session is gone, but the session check says otherwise — keeping it`);
    sessionGoneRef.gone = false;
  }
  if (sessionGoneRef.gone) {
    // b80: the relay confirmed this session no longer exists — remove ALL
    // local residue (state, wrapper, msgcache, ledger) instead of re-saving
    // it, so the next poll finds nothing and stops for good.
    console.log(`[veil] sync #${token.slice(0, 4)}: session confirmed deleted server-side — clearing local state, will not sync again`);
    await sessions.remove(token);
    return { messages, processedIds, readIds, reactions, state: next, ended: true, nextSkip, strayIds: [], desync: false, callSignals, rateLimited: rateLimitedRef.hit };
  }
  // Batch H (round-6 review R6-1-06): the ratchet is saved FIRST and the ids are
  // marked only once it landed. (Marking first meant a refused ratchet save made
  // the next pass skip envelopes whose advance was never stored.) A refused save
  // keeps reading working — this pass's messages are shown — and is reported.
  let stateSaved = true;
  if (cached.length || processedIds.length) {
    stateSaved = (await sessions.save(token, next).catch(() => false)) !== false;
    if (!stateSaved) console.log(`[veil] sync #${token.slice(0, 4)}: the chat state was not saved (storage refused) — kept for this pass only`);
  }
  if (processedIds.length && stateSaved) {
    await sessions.markProcessedIds(token, processedIds);
  }
  // b102: persist the pending-burn queue every pass — new failures queued
  // this pass, retries resolved this pass (removed), and attempt counts for
  // ones still failing. Runs even when unchanged (cheap) so a queue that
  // drains to empty is reliably cleared from storage.
  // Batch H (R5-1-09): a refused write or a full queue is reported
  let burnQueueTrouble = false;
  if (burn) {
    const bq = await sessions.setPendingBurns(token, pendingBurn) as { saved: boolean; full: boolean } | undefined;
    burnQueueTrouble = !!bq && (!bq.saved || bq.full);
  }
  if (cached.length) await sessions.cacheMessages(token, cached);
  if (strayIds.length) {
    console.log(`[veil] sync #${token.slice(0, 4)}: ${strayIds.length} stray envelope(s) failed to decrypt but newer messages arrived fine — classified as strays, not a desync`);
  }
  if (desync) {
    console.error(`[veil] sync #${token.slice(0, 4)}: ${(failRecs.length - strayIds.length)} decrypt failure(s) show genuine desync signatures (key mismatch or stacking) — recommending end + new session`);
  }
  return { messages, processedIds, readIds, reactions, state: next, nextSkip, strayIds, desync, callSignals, rateLimited: rateLimitedRef.hit, ...(burnStuck ? { burnStuck } : {}), ...(stateSaved ? {} : { stateNotSaved: true }), ...(burnQueueTrouble ? { burnQueueTrouble: true } : {}) };
}

/**
 * b91 (builder receipt-expiry parity): ONE per-session TTL for EVERY envelope
 * submission — messages, media, cover, receipts — derived from the session's
 * expire dial (expire_after_seconds, default 24h), exactly like the web's
 * send path. The old hardcoded ttl 3600 let a relay observer single out
 * receipts (and native-origin messages) by expiry alone, contradicting the
 * uniform-envelope claim and the UI's "expire N hours after sending" text.
 */
export function envelopeTtlSeconds(sealed: object): number {
  // Batch D (D-09): the signed transcript dials first (see sessionDials)
  const d = sessionDials(sealed);
  const raw = (d ?? sealed ?? {}) as { expireAfterSeconds?: number };
  // b92 F-S7 (settings sweep): EXPLICIT Off (0) is a chosen dial, not a
  // missing one — web Kh semantics give it the relay's 36 h hard cap, not a
  // silent 24 h expiry that contradicts the "Off" choice. A MISSING/invalid
  // value keeps the defensive 24 h default.
  if (raw.expireAfterSeconds === 0) return 129600; // Off → 36 h relay hard cap (web parity)
  const dial = Number(raw.expireAfterSeconds);
  return Number.isFinite(dial) && dial > 0 ? Math.floor(dial) : 86400;
}

/** Encrypt + submit. Returns the locally-echoed message + advanced ratchet. */
export function sendChatMessage(...args: Parameters<typeof sendChatMessageUnlocked>): ReturnType<typeof sendChatMessageUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendChatMessageUnlocked(...args));
}

async function sendChatMessageUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  text: string,
  ttlSeconds?: number,
): Promise<ChatMessage> {
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const state = await deserializeRatchetState(sealed);
  // b91: per-session expire dial (web parity — the live bundle sends with the
  // session's expire_after_seconds, NOT a hardcoded 1h; see envelopeTtlSeconds)
  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed);

  // b197 (audit M-4): messages larger than the largest padded bucket used to
  // hard-fail with "Message too long for the padded bucket sizes". Split at
  // UTF-8-safe code-point boundaries and send as sequential envelopes — each
  // chunk is its own ratchet step; the relay's per-session FIFO + receiver
  // counters preserve order. The LOCAL echo stays one bubble with the full
  // text; the peer renders each chunk as its own message (documented).
  const chunks = splitForBuckets(text);
  const id = `local_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  let lastEnvId = '';
  for (let i = 0; i < chunks.length; i++) {
    const env = await encryptMessage(state, chunks[i]);
    // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
    // here, so a step can never be sent twice; a send that then fails leaves a
    // one-step gap, which the peer's skipped-key window absorbs.
    await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
    const r = await relay.submitEnvelope({
      session_token: token,
      client_id: clientId,
      write_secret: sealed.writeSecret,
      sender_client_id: await senderPseudonym(env.header),
      ciphertext: env.ciphertext,
      iv: env.iv,
      header: env.header,
      byte_length: env.byteLength ?? env.ciphertext.length,
      ttl_seconds: ttl,
      protocolVersion: sealed.proto ?? 'veil-ratchet-6',
    });
    assertSubmitOk(r, 'message submit'); // b127: HTTP-200-wrapped rejects were silent
    // (saved per chunk, before each chunk went out — Batch H)
    lastEnvId = submitResponseId(r.data) ?? '';
  }
  // b198 (two-dial burn): own bubbles get NO burn clock at send — the clock
  // starts when the PEER's read receipt lands (see markCachedRead/App receipt
  // paths), matching the relay copy's burn-at-recipient-open. Pre-receipt the
  // row is treated as never-displayed: no countdown, no local purge.
  // b199: a sent group invite renders as the same card on my side (never raw JSON)
  const sentInvite = parseGroupInvitePayload(text);
  const msg: ChatMessage = sentInvite
    ? { id, text: '', mine: true, ts: new Date().toISOString(), envId: lastEnvId, groupInvite: sentInvite }
    : { id, text, mine: true, ts: new Date().toISOString(), envId: lastEnvId };
  await sessions.cacheMessages(token, [msg]);
  // b85: real text message — fire the lock-screen alert push
  void notifySent(relay, token, sealed.writeSecret);
  return msg;
}

/**
 * Send a COVER-TRAFFIC envelope — web parity (live bundle: 15% of poll cycles
 * while a session is open submit a ratchet-encrypted filler message, so an
 * observer of the relay cannot tell active chatting from idle polling). The
 * filler is 1536 random bytes as hex, marked cover:true inside the encrypted
 * plaintext; receivers decrypt it normally and their app layer filters it
 * out (classifyDecrypted -> 'cover'). It advances the ratchet exactly like
 * the web's cover sends do, so both sides stay in lockstep.
 */
export function sendCoverEnvelope(...args: Parameters<typeof sendCoverEnvelopeUnlocked>): ReturnType<typeof sendCoverEnvelopeUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendCoverEnvelopeUnlocked(...args));
}

async function sendCoverEnvelopeUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  ttlSeconds?: number,
): Promise<boolean> {
  const sealed = await sessions.load(token);
  if (!sealed) return false;
  const state = await deserializeRatchetState(sealed);
  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed); // b91: same dial as messages — cover must be indistinguishable by expiry
  const bytes = crypto.getRandomValues(new Uint8Array(1536));
  const filler = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const env = await encryptMessage(state, filler, { cover: true });
  // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
  // here, so a step can never be sent twice; a send that then fails leaves a
  // one-step gap, which the peer's skipped-key window absorbs.
  await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
  const r = await relay.submitEnvelope({
    session_token: token,
    client_id: clientId,
    write_secret: sealed.writeSecret,
    sender_client_id: await senderPseudonym(env.header),
    ciphertext: env.ciphertext,
    iv: env.iv,
    header: env.header,
    byte_length: env.byteLength ?? env.ciphertext.length,
    ttl_seconds: ttl,
    protocolVersion: sealed.proto ?? 'veil-ratchet-6',
  });
  assertSubmitOk(r, 'cover submit'); // b127: silent-reject parity with messages/receipts
  return true;
}

/**
 * Send a READ RECEIPT — the web bundle's Wp/Up contract byte-exact:
 *   body = {"__veil_receipt":1,ids:[...max 20],read:true|false}
 * ratchet-encrypted like any other message (covers + forward secrecy apply).
 * Web batches up to 20 ids per receipt; ids are the peer's message envelope
 * ids the user has now seen. read reflects the LOCAL read-receipts dial —
 * receipts flow for delivery state even with receipts off (web parity:
 * c ? {__veil_receipt:1,ids:r,read:true} : {__veil_receipt:1,ids:r}).
 */
/**
 * b199 REACTION (owner request, Oct 17): set or clear MY reaction on one
 * message, ratchet-encrypted like everything else. Shape:
 *   {"__veil_receipt":1,"ids":[],"react":{"t":<envelope id>,"e":<emoji|null>}}
 * Riding the receipt shape is deliberate: older builds parse it as an empty
 * receipt and drop it, instead of showing the JSON as a chat message. The
 * relay sees one more ordinary encrypted envelope, as with any receipt.
 */
export function sendReaction(
  relay: VeilRelay, sessions: SessionStore, token: string, clientId: string, target: string, emoji: string | null,
): Promise<void> {
  if (emoji !== null && !(REACTION_EMOJI as readonly string[]).includes(emoji)) return Promise.reject(new Error('Unsupported reaction'));
  return serializeRatchetSend(token, async () => {
    const sealed = await sessions.load(token);
    if (!sealed) throw new Error('No ratchet state for this session on this device.');
    const state = await deserializeRatchetState(sealed);
    const env = await encryptMessage(state, JSON.stringify({ __veil_receipt: 1, ids: [], react: { t: target, e: emoji } }));
    // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
    // here, so a step can never be sent twice; a send that then fails leaves a
    // one-step gap, which the peer's skipped-key window absorbs.
    await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
    const r = await relay.submitEnvelope({
      session_token: token,
      client_id: clientId,
      write_secret: sealed.writeSecret,
      sender_client_id: await senderPseudonym(env.header),
      ciphertext: env.ciphertext,
      iv: env.iv,
      header: env.header,
      byte_length: env.byteLength ?? env.ciphertext.length,
      ttl_seconds: envelopeTtlSeconds(sealed),
      protocolVersion: sealed.proto ?? 'veil-ratchet-6',
    });
    assertSubmitOk(r, 'reaction submit');
    // b199 (owner, Oct 17 device run): a new reaction alerts the peer like a
    // message does (same content-free push); clearing one stays silent.
    if (emoji !== null) void notifySent(relay, token, sealed.writeSecret);
  });
}

export function sendReadReceipt(...args: Parameters<typeof sendReadReceiptUnlocked>): ReturnType<typeof sendReadReceiptUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendReadReceiptUnlocked(...args));
}

async function sendReadReceiptUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  ids: string[],
  read: boolean,
  ttlSeconds?: number,
): Promise<void> {
  if (!ids.length) return;
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const state = await deserializeRatchetState(sealed);

  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed); // b91: receipts ride the SAME per-session expiry as messages/cover — no 1h receipt fingerprint
  // b177 (owner report, Oct 2 live Metro: 2 messages sent ~9 min earlier
  // never ticked read, no sign of catching up): this function used to
  // bare `ids.slice(0, 20)` into ONE envelope and silently drop anything
  // past index 20 — but the caller (App.tsx's read-receipt sweep, both
  // native and web) marks the ENTIRE requested `ids` batch as sent in its
  // own bookkeeping the moment this call resolves, regardless of how many
  // ids were actually transmitted. Once a sweep pass accumulates a backlog
  // over 20 un-receipted peer messages (easy right after a rate-limited
  // burst, since receipt-sending itself gets backed off along with
  // everything else), the overflow ids were marked "done" locally and
  // NEVER retried — no error, no log, permanently stuck. Fix: this call
  // now delivers every id in `ids`, looping in chunks of 20 (one envelope,
  // one ratchet step, per chunk) so the caller's "I called this, therefore
  // it's receipted" assumption is actually true.
  for (let i = 0; i < ids.length; i += 20) {
    const chunk = ids.slice(i, i + 20);
    const body = JSON.stringify({ __veil_receipt: 1, ids: chunk, ...(read ? { read: true } : {}) });
    const env = await encryptMessage(state, body);
    // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
    // here, so a step can never be sent twice; a send that then fails leaves a
    // one-step gap, which the peer's skipped-key window absorbs.
    await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
    const r = await relay.submitEnvelope({
      session_token: token,
      client_id: clientId,
      write_secret: sealed.writeSecret,
      sender_client_id: await senderPseudonym(env.header),
      ciphertext: env.ciphertext,
      iv: env.iv,
      header: env.header,
      byte_length: env.byteLength ?? env.ciphertext.length,
      ttl_seconds: ttl,
      protocolVersion: sealed.proto ?? 'veil-ratchet-6',
    });
    assertSubmitOk(r, 'receipt submit'); // b127: owner repro — receipts vanished silently

    // b177: the ratchet advance is persisted per chunk (since Batch H, before
    // each chunk goes out), so a LATER failing chunk never leaves the ones that
    // landed out of step with local state.
  }
}

/**
 * Send an encrypted media message — the web bundle's image flow, byte-exact:
 *   1. fresh AES-256-GCM key + 12-byte IV encrypt the file bytes (Td)
 *   2. ciphertext uploads as 'veil-media' via the private-blob endpoint
 *   3. body = {"__veil_media":1,uri,k,iv,name,mime,size,dl?} — ratchet-
 *      encrypted exactly like text (cd), so forward secrecy + covers apply
 *   4. submitEnvelope carries media_uri (web adds it for media bodies)
 * The blob key rides INSIDE the end-to-end body — the relay never sees it.
 * localUri is the sender-side preview source; never transmitted.
 */
export function sendMediaMessage(...args: Parameters<typeof sendMediaMessageUnlocked>): ReturnType<typeof sendMediaMessageUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendMediaMessageUnlocked(...args));
}

async function sendMediaMessageUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  media: { bytes: Uint8Array; name?: string; mime?: string; size?: number; dl?: boolean },
  localUri?: string,
  ttlSeconds: number | undefined = undefined,
  /**
   * Optional ciphertext upload adapter (React Native shell): the app writes
   * the ciphertext to a temp file and uploads it as a file:// FormData part —
   * the guaranteed RN networking path. Default: in-memory Blob upload.
   */
  uploadCiphertext?: (ciphertext: Uint8Array) => Promise<string>,
): Promise<ChatMessage> {
  const size = media.size ?? media.bytes.byteLength;
  if (size > MEDIA_LIMIT_BYTES) throw new Error('Media is limited to 25 MB per message.');
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const state = await deserializeRatchetState(sealed);
  // b91: per-session expire dial — media rides the same expiry as every
  // other envelope (see envelopeTtlSeconds)
  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed);

  const { ciphertext, keyB64, ivB64 } = await encryptMedia(media.bytes);
  const fileUri = uploadCiphertext
    ? await uploadCiphertext(ciphertext)
    : await relay.uploadPrivateFile({ bytes: ciphertext, name: 'veil-media' });

  const f: Record<string, unknown> = {
    name: media.name || 'media',
    mime: media.mime || 'application/octet-stream',
    size,
  };
  if (media.dl) f.dl = 1;
  const body = JSON.stringify({ __veil_media: 1, uri: fileUri, k: keyB64, iv: ivB64, ...f });

  const env = await encryptMessage(state, body);
  // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
  // here, so a step can never be sent twice; a send that then fails leaves a
  // one-step gap, which the peer's skipped-key window absorbs.
  await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
  const id = `local_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const r = await relay.submitEnvelope({
    session_token: token,
    client_id: clientId,
    write_secret: sealed.writeSecret,
    sender_client_id: await senderPseudonym(env.header),
    ciphertext: env.ciphertext,
    iv: env.iv,
    header: env.header,
    byte_length: env.byteLength ?? env.ciphertext.length,
    ttl_seconds: ttl,
    media_uri: fileUri,
    protocolVersion: sealed.proto ?? 'veil-ratchet-6',
  });
  // Batch H (round-5 review R4-4-32, dropped in Batch G): a rejected media send is not "sent"
  assertSubmitOk(r, 'media submit');
  // b198 two-dial: own media bubbles have no burn clock until the peer's receipt
  const msg: ChatMessage = {
    id, text: '', mine: true, ts: new Date().toISOString(), envId: submitResponseId(r.data),
    media: { uri: fileUri, k: keyB64, iv: ivB64, mime: String(f.mime), name: String(f.name), size, dl: !!media.dl, localUri },
  };
  await sessions.cacheMessages(token, [msg]);
  // b85: real media message — fire the lock-screen alert push
  void notifySent(relay, token, sealed.writeSecret);
  return msg;
}

/**
 * Receive side: fetch + decrypt a media blob — the web loader contract
 * (vaultFileSignedUrl → fetch → Ed decrypt), with the web's 5-attempt
 * retry (signed URLs can lag the upload by a moment). Returns the
 * DECRYPTED bytes — callers keep them in memory (web parity: blob URLs,
 * never plaintext on disk).
 */
export async function loadMediaFile(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  media: ChatMedia,
): Promise<Uint8Array> {
  if (!media.uri || !media.k || !media.iv) throw new Error('Media message has no retrievable blob (key missing).');
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  let lastErr: unknown = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const url = await relay.vaultFileSignedUrl(media.uri, token, sealed.writeSecret);
      const bytes = await relay.fetchBytes(url);
      return await decryptMedia(bytes, media.k, media.iv);
    } catch (e) {
      lastErr = e;
      console.error(`[veil] media load failed (attempt ${attempt + 1}/5): ${(e as Error).message ?? e}`);
      if (attempt < 4) await new Promise((r) => setTimeout(r, 3500));
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

/**
 * Initiator-side completion: once the responder has joined (session record now
 * carries responder_* keys), derive the sending chains and reseal. No-op when
 * already ready. Throws when the peer has not joined yet (composer gate).
 */
/** Batch H (round-5 review R5-1-07, second half): completion runs under the
 *  session's send lock, so a send or sync in flight can't write over it. */
export function completeContactHandshake(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  prefetched?: Record<string, unknown>,
): Promise<void> {
  return serializeRatchetSend(token, () => completeContactHandshakeUnlocked(relay, sessions, token, prefetched));
}

async function completeContactHandshakeUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  prefetched?: Record<string, unknown>,
): Promise<void> {
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const state = await deserializeRatchetState(sealed);
  if (state.ready) return;

  let rec = prefetched as Record<string, string> | null | undefined;
  if (!rec) {
    const r = await relay.sessionPeek(token, sealed.writeSecret);
    const d = r.data as { data?: { session?: Record<string, string> }; session?: Record<string, string> };
    rec = d?.data?.session ?? d?.session ?? (r.data as Record<string, string>);
  }
  if (!rec?.responder_ratchet_pub_jwk) throw new Error('Waiting for your contact to accept.');

  await completeHandshake(
    state, token,
    rec.responder_pub_jwk, rec.responder_ratchet_pub_jwk, rec.responder_pq_ct || null,
  );
  // keep the session's dials with the ratchet so sync can burn and sends
  // derive the same per-message TTL (web Kh semantics).
  // Batch C (V-12): the initiator keeps its OWN dials (sealed at create and
  // bound into the fingerprint) — never the relay row's copy.
  const own = sealed as { burnAfterOpen?: boolean; defaultTtlSeconds?: number; expireAfterSeconds?: number; peerVeilId?: string; peerIkPub?: string; myVerifiedFp?: string };
  await saveOrThrow(sessions, token, { // Batch H (R6-1-06)
    ...(await serializeRatchetState(state)),
    ...(own.peerVeilId && own.peerIkPub ? { peerVeilId: own.peerVeilId, peerIkPub: own.peerIkPub } : {}), // Batch F (R4-1-04)
    ...(own.myVerifiedFp ? { myVerifiedFp: own.myVerifiedFp } : {}), // Batch F (R4-1-03)
    burnAfterOpen: own.burnAfterOpen === true,
    defaultTtlSeconds: Number.isFinite(Number(own.defaultTtlSeconds)) ? Number(own.defaultTtlSeconds) : 7200,
    expireAfterSeconds: Number.isFinite(Number(own.expireAfterSeconds)) ? Number(own.expireAfterSeconds) : 86400,
  } as never);
}

/**
 * SPEC §3 (initiator pending loop): while a sent contact request is pending,
 * poll the participant-scoped session listing (veilSessionGate
 * {action:'list', client_id}) — the same listing the web client polls.
 * The request is accepted exactly when the record shows state === 'active'
 * AND both responder_pub_jwk and responder_ratchet_pub_jwk are non-empty;
 * then complete the handshake EXACTLY ONCE from the stored request-time state.
 */
export async function pollContactAcceptance(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  veilId?: string | null,
): Promise<'pending' | 'accepted' | 'ready'> {
  const sealed = await sessions.load(token);
  if (sealed?.ready) return 'ready';

  const r = await relay.sessionList(clientId, veilId ?? undefined);
  const list = (r.data as { data?: unknown[] })?.data
    ?? (r.data as { sessions?: unknown[] })?.sessions
    ?? (r.data as unknown as unknown[]);
  const rec = (Array.isArray(list) ? list : [])
    .map((x) => x as Record<string, unknown>)
    .find((x) => String(x.token ?? '') === token);
  if (!rec) return 'pending';
  if (rec.state !== 'active' || !rec.responder_pub_jwk || !rec.responder_ratchet_pub_jwk) return 'pending';

  await completeContactHandshake(relay, sessions, token, rec);
  return 'accepted';
}
