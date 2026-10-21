/**
 * @veil/device — GROUP messaging protocol (veil-group-1), ported byte-exact
 * from the live web bundle (extracted Sept 19, 2026).
 *
 * Wire contract summary (all verified against the bundle):
 *  - Envelope header: JSON {v:'veil-group-1', sid:<sender tag>, ge:<epoch>, n:<send counter>}
 *    plus optional `sig` (per-sender Ed25519 over the concat of the header-JSON
 *    bytes WITHOUT sig and the raw IV bytes).
 *  - Message key: HKDF-SHA256(ikm=GEK, salt=SHA256('veil-group-bind:'+groupToken+':'+epoch+':'+pqPubB64),
 *    info='veil-group-msg:'+sid+':'+n, 32) — AES-256-GCM, IV 12B random,
 *    additionalData = the FULL header JSON (with sig).
 *  - Payload: padded to buckets [1024, 4096]: [1 cover flag][2 BE length][utf8 text][zero pad].
 *  - Sender tag: 'g' + hex(first 6 bytes of SHA-256('veil-group-sender:'+groupToken+':'+epoch+':'+veilId)).
 *  - Replay guard: per-sender {last, skipped[]} — n<=last must be in skipped
 *    (then consumed); n>last skips (last+1..n-1) get buffered (cap 64).
 *  - Rekey: creator encapsulates the new GEK with ML-KEM-768 against EACH
 *    member's published PQ prekey: wrap {to, ct, wk, wi} where
 *    wk = AES-GCM(HKDF(mlkemSecret, salt='veil-group-rekey', info=toVeilId), newGEK).
 *    Broadcast as a group message whose text is JSON
 *    {"__veil_group_rekey":1, ge, pq:<new group pq pub>, wraps:[...]}, then
 *    gate action 'rotate' with the new epoch + group PQ pub. Receivers find
 *    their own wrap, ML-KEM-decapsulate, and move to the new epoch (sendN
 *    resets, recv cleared, new sender tag).
 *  - Epoch fingerprint: SHA-256('veil-group-epoch:'+groupToken+':'+sorted member list joined ',')
 *    → hex, uppercased, grouped in 4s with dashes.
 *  - Creator attest: Ed25519(ikSeed) over b64(JSON{group_token, veil_id, IK_pub, joined_epoch}).
 *  - Evict deny-sig: Ed25519(ikSeed) over b64(JSON{group_token, target_IK_pub, deny_epoch}).
 *  - Group name blob: 'enc1:'+b64(iv)+':'+b64(AES-GCM(GEK, name)).
 *  - Protocol version on submitEnvelope: 'veil-group-1'; group envelopes carry
 *    BOTH session_token and group_token.
 *  - Auto-rotation trigger (creator): 100 envelopes received or 24 h since
 *    epoch start.
 *  - Group record persistence: web stores AES-GCM(JSON record) under
 *    localStorage 'veil_gk_'+token (7-day TTL). Native stores the JSON record
 *    in the OS keychain (SecureStore) under the same logical name — strictly
 *    stronger at rest, same lifetime semantics (no TTL — keys are per-device).
 */
import { toB64, fromB64, utf8, fromUtf8, concat } from '../../crypto-core/src/bytes';
import { hkdf, sha256, hmacSha256 } from '../../crypto-core/src/kdf';
import { ikSign, verifyWithIk, veilIdFromIkPub } from '../../crypto-core/src/identity';
import { mlkemEncap, mlkemDecap } from '../../crypto-core/src/mlkem';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';

export const GROUP_PROTO = 'veil-group-1';
export const GROUP_KEY_PREFIX = 'veil_gk_';
/** Batch H (round-6 review R6-2-01): the send counter lives in its own small item
 *  (`veil_gk_<token>~send`), so a group record too large for the phone's secure
 *  store no longer blocks sends. Same prefix, so every group-key wipe covers it. */
export const GROUP_SEND_SUFFIX = '~send';
/** Batch H (R6-2-01): bounds for open-membership (forum) records, which never rotate */
const OPEN_RECV_MAX = 150;
const OPEN_RECV_IDLE_MS = 30 * 86400_000;
const PAD_BUCKETS = [1024, 4096];
/** b54: rekey parts carry up to REKEY_WRAPS_PER_PART ML-KEM wraps (~1.6 KB each)
 *  plus the new group PQ key, so they get their own larger buckets. The
 *  largest stays under the relay's 48,000-char envelope cap (Deno KV 64 KB). */
const REKEY_BUCKETS = [4096, 16384, 32768];
export const REKEY_WRAPS_PER_PART = 16;
const PAYLOAD_HDR = 3; // 1 cover byte + 2 BE length bytes
const MAX_SKIPPED = 64;
export const EPOCH_MAX_ENVELOPES = 100;
export const EPOCH_MAX_MS = 24 * 60 * 60 * 1000;
/** Batch D (D-06, RV-05): a member stops sending on a key older than this. The
 *  creator rotates every EPOCH_MAX_MS while its app runs, so a key this old means
 *  rotations are not arriving (or are being withheld) — a removed member may
 *  still hold it. Owner decision (18 Oct 2026): 7 days, not the reviewer's 48 h,
 *  so quiet groups whose creator is away for a few days keep working. */
export const MEMBER_EPOCH_MAX_MS = 7 * 24 * 60 * 60 * 1000;
export const GROUP_MEMBER_CAP = 100; // b198: the Founding Tester Forum cohort (was 8)

export interface GroupRecvState {
  last: number;
  skipped: number[];
  /** b196-r2: posting-session token the sender's counter `n` belongs to. A
   * re-minted posting session (founder end+rejoin, device restore) restarts
   * the sender chain at n=0 while the sender TAG stays identical — keying the
   * replay guard on (sid, n) alone rejected every message from the new chain
   * as a replay (owner repro Oct 12: fresh founder welcome invisible to any
   * listener that had seen the old chain). */
  chain?: string;
  /** b54 (T-3): chains this sender already replaced — never accepted again */
  retired?: string[];
  /** Batch H (R6-2-01): when this sender was last seen (ms), for bounding forum records */
  at?: number;
}

export interface GroupRecord {
  groupToken: string;
  /** b198: this member's own group session token (background poll + push
   *  credential). Older records predate it — derive via findMainGroupSession. */
  sessionToken?: string;
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  role: 'creator' | 'member' | 'listener' | 'forum-member';
  epoch: number;
  gekB64: string;
  nameGekB64: string;
  pqPubB64: string;
  myTag: string;
  sendN: number;
  recv: Record<string, GroupRecvState>;
  envCount?: number;
  epochStartedAt?: string;
  /** roster: sender tag -> member IK_pub b64 (for per-sender signature checks) */
  senderKeys?: Record<string, string>;
  /** my own display nickname in this group (used for roster display) */
  myNick?: string;
  /** durable sender tag -> nickname map (intros are one-shot; this survives polls) */
  nicks?: Record<string, string>;
  /** b92 F10: per-group envelope pagination cursor (full-page advance rule) */
  syncSkip?: number;
  /** b195: deletion-immune inbox cursor — server created_date of the last
   *  definitively-processed envelope (−1ms). Replaces the skip cursor for
   *  fetches: skip offsets SHIFT every time the relay purges expired rows,
   *  silently striding past unprocessed backlog at tester volume. */
  syncCursorAt?: string;
  /** b187 lounge: display name (listener records hold no relay session to
   *  fetch the encrypted name blob from, so the descriptor name persists
   *  locally; creator/member records keep using the relay blob). */
  name?: string;
  /** b92 F11: persistently-known envelope ids (marked only after definitive outcome), capped */
  knownEnvIds?: string[];  /** b188 forum mode: token of the SELF-CREATED posting session bound to
   *  this group (forum members have no invite session; they post envelopes
   *  under their own session credential). */
  postingSessionToken?: string;
  /** forum: envelope ids the founder removed for everyone (never rendered again), capped */
  removedEnvIds?: string[];
  /** b190: ms-epoch cooldown — auto-rotation stops re-attempting (identity
   *  lookups) until this time when a member has no published PQ prekey. */
  rotateBlockedUntil?: number;
  /** b190: the server-side session row is gone (deleted group) — the thread
   *  is fail-closed ended; roster polls stop, local history stays readable. */
  sessionEnded?: boolean;
  /** b54 (T-3): this device's current sender chain id (fresh at counter 0) */
  sendChain?: string;
  /** b54 (Batch A, N-1): the group creator's IK — the ONLY key whose signature
   *  can move this group to a new epoch. Creator: own IK. Member: from the
   *  invite link `c=` fragment. Lounge / forum: the descriptor's founder IK. */
  creatorIkPubB64?: string;
  /** b54 (Batch A, H-3): creator-side LOCAL deny list (evicted IKs). A rekey
   *  never wraps to these, whatever the relay roster says. */
  evictedIks?: string[];
  /** Batch C (A1): creator — every seat this device minted: seat token ->
   *  { key: HKDF of the seat link's secret `k` (the relay never sees k),
   *    invitee: locked Vardum ID if any, usedBy: the ONE IK admitted through it }. */
  seats?: Record<string, GroupSeat>;
  /** Batch C (A1): creator — admitted members, IK_pub -> veil_id. Only these
   *  receive rekey wraps or count as senders (minus evictedIks). */
  admitted?: Record<string, string>;
  /** Batch E (round-3 review F-3): a pre-Batch-C creator record — the relay roster
   *  seen on its first poll (IK_pub -> veil_id), waiting for the creator to confirm.
   *  Nobody on it is trusted until confirmed. */
  legacyRoster?: Record<string, string>;
  /** Batch E (F-3): the signed member list must be (re)published on the next pass */
  memberListDirty?: boolean;
  /** Batch C (A1): member — the creator-signed member list (IK_pub -> veil_id).
   *  memberSeq undefined = a pre-Batch-C record (verified relay roster until the
   *  first signed list arrives); 0 = strict, trusts only the creator so far. */
  memberList?: Record<string, string>;
  memberSeq?: number;
  /** Batch C (A1): member — the seat I joined through and my proof for it (re-sent in my intro) */
  seatToken?: string;
  seatProof?: string;
  /** ms-epoch of my last intro send (the re-send throttle) */
  introSentAt?: number;
  /** Batch C (A3): ms-epoch of my last missing-wrap request (the re-ask throttle) */
  wrapRequestedAt?: number;
  /** Batch C (A3): a rotation persisted BEFORE anything was sent; a retry resends these exact parts */
  pendingRotation?: PendingRotation;
  /** Batch C (A3): an eviction is waiting for its rotation — normal sends are refused
   *  until a rotation that excludes every evicted IK completes. Value = epoch at eviction. */
  evictionPendingAt?: number;
  /** Batch C (A3): IKs the last completed rotation wrapped to (an eviction checks it excluded the evicted) */
  lastRotationRecipients?: string[];
  /** Batch D (D-06): Vardum IDs the last rotation skipped (no valid signed prekey);
   *  they recover the key through the missing-wrap request once their prekey is good */
  lastRotationSkipped?: string[];
  /** Batch C (A1): the founder's record of the FORUM group — open by design
   *  (anyone with the public forum link joins; identities are registry-verified,
   *  veil_id = f(IK)). Set only by markForumGroupIfFounder; every other group
   *  is creator-authorised. */
  openMembership?: boolean;
}

export interface GroupSeat { key: string; invitee?: string; usedBy?: string }

export interface PendingRotation {
  epoch: number;
  gekB64: string;
  pqPubB64: string;
  rid: string;
  /** the signed rekey texts, part i of n */
  parts: string[];
  /** indices already accepted by the relay */
  sent: number[];
  /** IKs that received a wrap */
  recipients: string[];
  /** Batch D (D-06): Vardum IDs skipped for a missing or badly signed prekey */
  skipped?: string[];
}

export interface GroupEnvelopeHeader {
  v: string; sid: string; ge: number; n: number; sig?: string;
  /** b54 (pre-audit T-3): the sender's chain id, chosen by the SENDER at
   *  counter 0 and carried inside the AEAD-authenticated, signed header. The
   *  receiver's replay window keys on it, never on relay metadata. */
  ch?: string;
  /** b188 forum mode: the sender's veil-id. Batch C: part of the signed core.
   *  Lets a receiver resolve and verify an UNKNOWN sender against the
   *  published identity registry. */
  vid?: string;
  /** Batch C (A2): sender-signature version. Only GROUP_SIG_VERSION is accepted. */
  sv?: number;
}

/** Batch C (A2): v2 sender signatures cover the ciphertext. */
export const GROUP_SIG_VERSION = 2;
const GROUP_SIG_LABEL = 'vardum-group-msg-v2:';

/** Batch C (A2): bytes the sender signs — label ‖ core header ‖ IV ‖ SHA-256(ct). */
export async function groupSigMessage(coreStr: string, iv: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
  return concat(utf8(GROUP_SIG_LABEL), utf8(coreStr), iv, await sha256(ct));
}

/** Batch C (A2): true only if `senderIkB64` signed this exact envelope (header, IV and ciphertext). */
export async function verifyGroupEnvelopeSig(senderIkB64: string, headerStr: string, ciphertextB64: string, ivB64: string): Promise<boolean> {
  const parsed = parseSignedGroupHeader(headerStr);
  if (!parsed || !senderIkB64) return false;
  try {
    return await verifyWithIk(senderIkB64, toB64(await groupSigMessage(parsed.coreStr, fromB64(ivB64), fromB64(ciphertextB64))), parsed.header.sig);
  } catch { return false; }
}

/** Batch C (A2 + A5): parse a group envelope header strictly. The only form
 *  accepted is the canonical v2 one — {v, sid, ge, n, ch, (vid), sv, sig}
 *  in exactly that order — so the core string the receiver re-derives is
 *  byte-identical to what the sender signed and bound as AEAD data. Headers
 *  without a sender chain id (the old relay-supplied fallback) are refused. */
export function parseSignedGroupHeader(headerStr: string): { header: Required<Pick<GroupEnvelopeHeader, 'v' | 'sid' | 'ge' | 'n' | 'ch' | 'sv' | 'sig'>> & { vid?: string }; coreStr: string } | null {
  let h: Record<string, unknown>;
  try { h = JSON.parse(headerStr); } catch { return null; }
  if (!h || typeof h !== 'object' || Array.isArray(h)) return null;
  const { v, sid, ge, n, ch, vid, sv, sig } = h as Record<string, unknown>;
  if (v !== GROUP_PROTO || sv !== GROUP_SIG_VERSION) return null;
  // b54 (T-4): sender tags are exactly 'g' + 12 hex — '__proto__' etc. refused
  if (typeof sid !== 'string' || !/^g[0-9a-f]{12}$/.test(sid)) return null;
  if (!Number.isInteger(ge) || (ge as number) < 0 || !Number.isInteger(n) || (n as number) < 0) return null;
  if (typeof ch !== 'string' || !/^[0-9a-f]{16}$/.test(ch)) return null;
  if (vid !== undefined && (typeof vid !== 'string' || !vid)) return null;
  if (typeof sig !== 'string' || !sig) return null;
  const core = vid !== undefined ? { v, sid, ge, n, ch, vid, sv } : { v, sid, ge, n, ch, sv };
  const coreStr = JSON.stringify(core);
  if (JSON.stringify({ ...core, sig }) !== headerStr) return null; // no extra or reordered fields
  return {
    header: { v: v as string, sid: sid as string, ge: ge as number, n: n as number, ch: ch as string, sv: sv as number, sig: sig as string, ...(vid !== undefined ? { vid: vid as string } : {}) },
    coreStr,
  };
}

export interface GroupDecryptResult {
  /** Batch G (R5-2-03): the record could not be saved (kept in memory) */
  stateNotSaved?: boolean;
  cover: boolean;
  text: string;
  senderVerified: boolean;
}

// ---------- record store (web's nm Map + um persistence) ----------

/**
 * Per-device record caches, keyed by the storage INSTANCE. Two group sessions
 * on different stores (two devices simulated in one process, tests, a future
 * multi-profile build) never share or clobber each other's group state —
 * the send counter, replay window and epoch live with the store that owns them.
 */
const registries = new WeakMap<VeilStorage, Map<string, GroupRecord>>();
function registry(store: VeilStorage): Map<string, GroupRecord> {
  let m = registries.get(store);
  if (!m) { m = new Map(); registries.set(store, m); }
  return m;
}
const sendLocks = new Map<string, Promise<void>>();

async function persist(store: VeilStorage, rec: GroupRecord): Promise<void> {
  try {
    // Batch F (round-4 review R4-2-06): the phone's secure store reports a refused
    // write by answering false, not by throwing — treat it as the failure it is
    if ((await store.set(GROUP_KEY_PREFIX + rec.groupToken, JSON.stringify(rec))) === false) throw new Error('refused write');
  } catch (e) {
    // Batch D (D-07, RV-06): fail closed — a caller that must not continue on an
    // unsaved state (the rotation's persist-before-send) has to see the failure
    console.error('[veil-group] key persistence failed:', e);
    throw new Error('Group keys could not be saved on this device. Try again in a moment.');
  }
}

/**
 * Batch G (round-5 review R5-2-03, a Batch F regression): BOOKKEEPING writes —
 * the receive replay window and the envelope counter — must not block a group
 * when the phone's storage refuses the record (the iOS Keychain refuses large
 * items). The state stays in memory and the caller is told (false). Safety
 * writes (rotation, admission, eviction, member list, the send counter) keep
 * using persist(), which fails closed.
 */
async function persistBookkeeping(store: VeilStorage, rec: GroupRecord): Promise<boolean> {
  try {
    if ((await store.set(GROUP_KEY_PREFIX + rec.groupToken, JSON.stringify(rec))) === false) throw new Error('refused write');
    return true;
  } catch (e) {
    console.log('[veil-group] group state not saved (kept in memory):', String((e as Error)?.message ?? e), 'bytes', groupRecordBytes(rec));
    return false;
  }
}

/** Batch G (R5-2-03): the record's stored size, for the size log */
export function groupRecordBytes(rec: GroupRecord): number {
  try { return JSON.stringify(rec).length; } catch { return -1; }
}

/** Batch H (R6-2-01): the send counter, saved on its own and fail-closed (a
 *  counter that did not land would be reused). Small, so the phone's size limit
 *  for the big record never reaches it. */
async function persistSendState(store: VeilStorage, rec: GroupRecord): Promise<void> {
  const send = { epoch: rec.epoch, myTag: rec.myTag, sendN: rec.sendN, sendChain: rec.sendChain };
  try {
    if ((await store.set(GROUP_KEY_PREFIX + rec.groupToken + GROUP_SEND_SUFFIX, JSON.stringify(send))) === false) throw new Error('refused write');
  } catch (e) {
    console.error('[veil-group] send counter persistence failed:', e);
    throw new Error('Group keys could not be saved on this device. Try again in a moment.');
  }
}

/** b63 review (I3-5): records whose saved send counter couldn't be read */
const sendUnconfirmed = new WeakSet<GroupRecord>();

/** Batch H (R6-2-01): a saved counter ahead of the big record wins, but only for
 *  the same epoch and sender tag (a rotation resets the counter in the record). */
async function mergeSendState(store: VeilStorage, rec: GroupRecord): Promise<void> {
  let raw: string | null;
  try {
    raw = await store.get(GROUP_KEY_PREFIX + rec.groupToken + GROUP_SEND_SUFFIX);
  } catch (e) {
    // b63 review (I3-5): fail closed. The big record's counter may be behind,
    // so sending on it could reuse counters; encryptGroupMessage retries this.
    console.error('[veil-group] send counter unreadable — sends held until it reads:', e);
    sendUnconfirmed.add(rec);
    return;
  }
  sendUnconfirmed.delete(rec);
  try {
    if (!raw) return;
    const s = JSON.parse(raw) as { epoch?: number; myTag?: string; sendN?: number; sendChain?: string };
    if (s.epoch === rec.epoch && s.myTag === rec.myTag && Number(s.sendN) > Number(rec.sendN ?? 0)) {
      rec.sendN = Number(s.sendN);
      if (s.sendChain) rec.sendChain = s.sendChain;
    }
  } catch { /* the big record's counter stands */ }
}

const isOpenRecord = (rec: GroupRecord) => rec.role === 'forum-member' || rec.role === 'listener' || rec.openMembership === true;

/**
 * Batch H (R6-2-01): a forum never rotates, so its record only grew: one replay
 * window per sender ever seen, plus their keys and nicknames. Keep the 150 most
 * recently seen senders, drop any unseen for 30 days, never the founder or me.
 * (A dropped sender's old envelopes stay refused by the envelope-id ledger and the
 * inbox cursor; a dropped key is looked up again when they next post.)
 * Private groups are left alone: their rotations reset this state.
 */
export function boundOpenRecord(rec: GroupRecord, now = Date.now(), keepTag?: string): void {
  if (!isOpenRecord(rec)) return;
  const keep = new Set<string>([rec.myTag, ...(keepTag ? [keepTag] : [])].filter(Boolean) as string[]);
  for (const [t, ik] of Object.entries(rec.senderKeys ?? {})) if (ik && ik === rec.creatorIkPubB64) keep.add(t);
  const entries = Object.entries(rec.recv ?? {}).map(([t, s]) => { if (s.at === undefined) s.at = now; return [t, s] as const; });
  const live = entries
    .filter(([t, s]) => keep.has(t) || now - Number(s.at) <= OPEN_RECV_IDLE_MS)
    .sort((a, b) => Number(b[1].at) - Number(a[1].at));
  const kept = new Map<string, GroupRecvState>();
  for (const [t, s] of live) if (keep.has(t)) kept.set(t, s);
  for (const [t, s] of live) { if (kept.size >= OPEN_RECV_MAX) break; if (!kept.has(t)) kept.set(t, s); }
  if (kept.size !== entries.length) rec.recv = Object.fromEntries(kept);
  const allowed = (t: string) => keep.has(t) || kept.has(t);
  // the founder's own record rebuilds senderKeys from the roster each pass; members' records only grow
  if (rec.role !== 'creator' && rec.senderKeys) rec.senderKeys = Object.fromEntries(Object.entries(rec.senderKeys).filter(([t]) => allowed(t)));
  if (rec.nicks) rec.nicks = Object.fromEntries(Object.entries(rec.nicks).filter(([t]) => allowed(t)));
}

/** Batch D (D-07): the record as it is ON DISK (not the in-memory copy). */
export async function readPersistedGroupRecord(store: VeilStorage, groupToken: string): Promise<GroupRecord | null> {
  try {
    const raw = await store.get(GROUP_KEY_PREFIX + groupToken);
    return raw ? JSON.parse(raw) as GroupRecord : null;
  } catch {
    return null;
  }
}

/** web's dm(): normalize + memory map + persist */
export async function saveGroupRecord(store: VeilStorage, rec: GroupRecord): Promise<GroupRecord> {
  // b198 EPOCH MONOTONICITY (live-caught: One's record regressed 3 → 2 after a
  // rotation — a stale in-flight record save clobbered the advanceEpoch that
  // landed while the pass was running; the background group pass widened that
  // window). Group epochs only ever move FORWARD: a save carrying an OLDER
  // epoch has the newer epoch's key material preserved so the regression can
  // never stick. (Re-join flows re-attest at the CURRENT epoch, so forward is
  // always the right direction.)
  // Batch D (D-01): a record not yet loaded this run is still checked
  // Batch E (F-9): an unreadable stored record throws here instead of passing the guard
  const cur = registry(store).get(rec.groupToken) ?? (await loadGroupRecordStrict(store, rec.groupToken)) ?? undefined;
  // Batch C: saving the LIVE record keeps its identity — callers that hold it
  // (a poll pass, a rotation) keep seeing every later change, and nobody ends
  // up writing back a stale copy (which could regress replay windows).
  if (cur && cur === rec) {
    rec.recv = rec.recv ?? {};
    rec.envCount = rec.envCount ?? 0;
    rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
    await persist(store, rec);
    return rec;
  }
  let r: GroupRecord = {
    ...rec,
    recv: rec.recv ?? {},
    envCount: rec.envCount ?? 0,
    epochStartedAt: rec.epochStartedAt ?? new Date().toISOString(),
  };
  if (cur && cur !== rec) {
    assertSameGroup(cur, r);
    r = mergeMembershipState(cur, r);
  }
  if (cur && Number(rec.epoch ?? 0) < Number(cur.epoch ?? 0)) {
    r = {
      ...r,
      epoch: cur.epoch,
      gekB64: cur.gekB64,
      pqPubB64: cur.pqPubB64,
      myTag: cur.myTag,
      sendN: cur.sendN,
      recv: cur.recv ?? r.recv,
      envCount: cur.envCount ?? r.envCount,
      epochStartedAt: cur.epochStartedAt ?? r.epochStartedAt,
    };
    console.log(`[veil-group] stale record save blocked — kept epoch ${cur.epoch} over ${rec.epoch} for ${rec.groupToken.slice(0, 8)}`);
  }
  registry(store).set(r.groupToken, r);
  await persist(store, r);
  return r;
}

/** Batch D (D-01, RV-01/RV-03): thrown when a save would turn one group's record
 *  into another kind of group (a relay-named token colliding with a group this
 *  device already holds). */
export class GroupRecordConflictError extends Error {
  constructor() {
    super('This link points at another group already on this device, so it was not joined.');
    this.name = 'GroupRecordConflictError';
  }
}

const isPrivateRole = (role: GroupRecord['role']) => role === 'creator' || role === 'member';

/**
 * Batch D (D-01): a save that is not the live record may never change what group
 * a token belongs to: a private group (creator / member) never becomes a forum or
 * lounge record or the other way round, a creator never becomes a member (or back),
 * and a known creator key or own identity key is never replaced. Listener <-> forum
 * member stays allowed (the same public forum, re-joined).
 */
function assertSameGroup(cur: GroupRecord, r: GroupRecord): void {
  const roleOk = cur.role === r.role || (!isPrivateRole(cur.role) && !isPrivateRole(r.role));
  const creatorOf = (x: GroupRecord) => x.creatorIkPubB64 || (x.role === 'creator' ? x.ikPubB64 : undefined);
  const creatorOk = !creatorOf(cur) || !creatorOf(r) || creatorOf(cur) === creatorOf(r);
  const selfOk = !cur.ikPubB64 || cur.ikPubB64 === r.ikPubB64;
  if (!roleOk || !creatorOk || !selfOk) throw new GroupRecordConflictError();
}

/**
 * Batch C (V-28 + A1/A3): a stale write-back (a copy loaded before an eviction,
 * an admission or a rotation was recorded) must never undo it. Deny lists,
 * admissions and seat bindings only grow; the member list keeps the higher
 * sequence; a pending rotation / eviction survives until a save shows the
 * epoch it was waiting for.
 */
function mergeMembershipState(cur: GroupRecord, r: GroupRecord): GroupRecord {
  const out: GroupRecord = { ...r };
  // Batch D (D-01/D-02): only the live record can change the open-membership flag
  out.openMembership = cur.openMembership;
  if (cur.evictedIks?.length || r.evictedIks?.length) out.evictedIks = [...new Set([...(cur.evictedIks ?? []), ...(r.evictedIks ?? [])])];
  if (cur.admitted || r.admitted) out.admitted = { ...(cur.admitted ?? {}), ...(r.admitted ?? {}) };
  if (cur.seats || r.seats) {
    const seats: Record<string, GroupSeat> = { ...(cur.seats ?? {}) };
    for (const [t, s] of Object.entries(r.seats ?? {})) seats[t] = { ...s, usedBy: seats[t]?.usedBy ?? s.usedBy };
    out.seats = seats;
  }
  if ((cur.memberSeq ?? -1) > (r.memberSeq ?? -1)) { out.memberSeq = cur.memberSeq; out.memberList = cur.memberList; }
  if (!r.pendingRotation && cur.pendingRotation && cur.pendingRotation.epoch > Number(r.epoch ?? 0)) out.pendingRotation = cur.pendingRotation;
  if (r.evictionPendingAt === undefined && cur.evictionPendingAt !== undefined && Number(r.epoch ?? 0) <= cur.evictionPendingAt) out.evictionPendingAt = cur.evictionPendingAt;
  return out;
}

export function groupRecord(store: VeilStorage, groupToken: string): GroupRecord | null {
  return registry(store).get(groupToken) ?? null;
}

export function listGroupTokens(store: VeilStorage): string[] {
  return [...registry(store).keys()];
}

export async function forgetGroup(store: VeilStorage, groupToken: string): Promise<void> {
  registry(store).delete(groupToken);
  sendLocks.delete(groupToken);
  try { await store.remove(GROUP_KEY_PREFIX + groupToken); } catch { /* already gone */ }
  try { await store.remove(GROUP_KEY_PREFIX + groupToken + GROUP_SEND_SUFFIX); } catch { /* already gone */ }
}

/** web's Am(): export all records (device transfer payload) */
export function exportGroupRecords(store: VeilStorage): GroupRecord[] {
  return [...registry(store).values()].map((r) => ({ ...r }));
}

/** web's jm(): restore records from a device transfer */
export async function importGroupRecords(store: VeilStorage, recs: GroupRecord[]): Promise<number> {
  let n = 0;
  for (const r of recs ?? []) {
    if (!r || !r.groupToken || registry(store).has(r.groupToken)) continue;
    await saveGroupRecord(store, { ...r, recv: r.recv ?? {}, envCount: r.envCount ?? 0, epochStartedAt: r.epochStartedAt ?? new Date().toISOString() });
    n += 1;
  }
  return n;
}

/**
 * Boot-time reload (web's hm() counterpart): the native SecureStore has no key
 * enumeration, so the App layer re-hydrates records from the session rows the
 * gate returns (group sessions carry group_token) plus this explicit loader
 * for tokens the caller knows about.
 */
/** Batch E (round-3 review F-9): a stored group record exists but can't be read. */
export class GroupRecordUnreadableError extends Error {
  constructor() { super('This group\'s keys could not be read on this device. Try again in a moment.'); this.name = 'GroupRecordUnreadableError'; }
}

/** Batch E (F-9): like loadGroupRecord, but "unreadable" is not "absent" — it
 *  throws, so joins and saves never overwrite a record they couldn't read. */
export async function loadGroupRecordStrict(store: VeilStorage, groupToken: string): Promise<GroupRecord | null> {
  if (registry(store).has(groupToken)) return registry(store).get(groupToken)!;
  let raw: string | null;
  try { raw = await store.get(GROUP_KEY_PREFIX + groupToken); } catch { throw new GroupRecordUnreadableError(); }
  if (!raw) return null;
  const rec = await loadGroupRecord(store, groupToken);
  if (!rec) throw new GroupRecordUnreadableError();
  return rec;
}

export async function loadGroupRecord(store: VeilStorage, groupToken: string): Promise<GroupRecord | null> {
  if (registry(store).has(groupToken)) return registry(store).get(groupToken)!;
  try {
    const raw = await store.get(GROUP_KEY_PREFIX + groupToken);
    if (!raw) return null;
    const rec = JSON.parse(raw) as GroupRecord;
    if (!rec?.groupToken) return null;
    rec.recv = rec.recv ?? {};
    rec.envCount = rec.envCount ?? 0;
    rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
    await mergeSendState(store, rec); // Batch H (R6-2-01)
    registry(store).set(rec.groupToken, rec);
    return rec;
  } catch (e) {
    // Do not destroy key material on transient Keychain/read or parse errors.
    console.error('[veil-group] key restore failed — keeping the record for retry', e);
    return null;
  }
}

/**
 * Boot-time reload for ALL persisted groups (web hm() counterpart). The
 * native keychain index is enumerable, so every veil_gk_ record loads in one
 * sweep. Unlike the web's 7-day localStorage TTL, native records do not
 * expire — losing them means losing group access on this device.
 */
export async function loadGroupRecords(store: VeilStorage): Promise<number> {
  let n = 0;
  try {
    const keys = await store.keys(GROUP_KEY_PREFIX);
    for (const k of keys ?? []) {
      const token = k.slice(GROUP_KEY_PREFIX.length);
      if (!token || token.endsWith(GROUP_SEND_SUFFIX) || registry(store).has(token)) continue;
      const raw = await store.get(k);
      if (!raw) continue;
      try {
        const rec = JSON.parse(raw) as GroupRecord;
        if (!rec?.groupToken) continue;
        rec.recv = rec.recv ?? {};
        rec.envCount = rec.envCount ?? 0;
        rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
        await mergeSendState(store, rec); // Batch H (R6-2-01)
        registry(store).set(rec.groupToken, rec);
        n += 1;
      } catch (e) {
        // Preserve unreadable key material so a later unlock/recovery can retry.
        console.error('[veil-group] key restore failed — keeping the record for retry', e);
      }
    }
  } catch (e) {
    console.error('[veil-group] boot restore failed:', e);
  }
  return n;
}

// ---------- primitives ----------

async function sha256HexPrefix(s: string, bytes: number): Promise<string> {
  const h = await sha256(utf8(s));
  return [...h.subarray(0, bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** web's lm(): deterministic per-sender tag for THIS epoch */
export async function senderTag(groupToken: string, epoch: number, veilId: string): Promise<string> {
  return `g${await sha256HexPrefix(`veil-group-sender:${groupToken}:${epoch}:${veilId}`, 6)}`;
}

/**
 * Epoch fingerprint shown to users (web's bm() twin — MUST stay byte-exact
 * with the web app so cross-platform comparisons work).
 *
 * b136 (Sept 27, rotation test finding): the old input bound only
 * groupToken + sorted member veil IDs, so the fingerprint was IDENTICAL
 * across epochs — matching prints proved roster agreement, not KEY
 * agreement. A forked/malicious rekey (different GEKs or group PQ keys
 * delivered to different members) would still show identical
 * fingerprints, defeating the entire purpose of an "epoch" fingerprint.
 * The input now binds the full key-agreement state: epoch number, GEK,
 * and the epoch's group PQ public key. Two members now display the same
 * fingerprint iff they hold the same keys for the same epoch.
 * (SHA-256 of the GEK does not leak it — the fingerprint remains safe to
 * read aloud / compare out-of-band.) Web lockstep change requested from
 * the builder in the same cadence.
 *
 * b137 (builder reconciliation, Sept 27): the member element is the
 * sorted Ed25519 IK PUBS (b64), NOT veil IDs — the web's bm() has always
 * hashed IK pubs, so the native's pre-b136 "web's bm()" comment was wrong
 * and the two platforms were ALREADY fingerprint-divergent before b136.
 * Final cross-platform contract (byte-exact, both sides):
 *   veil-group-epoch:${groupToken}:${epoch}:${gekB64}:${pqPubB64}:${sortedIkPubsCommaJoined}
 * - groupToken: the 40-char hex group token, as-is
 * - epoch: DEVICE-LOCAL applied epoch, decimal, no padding ("2", "3") —
 *   NOT the relay-stamped group_epoch, for the same fork reason as GEK
 * - gekB64 / pqPubB64: device-LOCAL group state (identical to the relay
 *   row in normal operation; divergence under fork is the point)
 * - sortedIkPubs: member Ed25519 IK pub b64 strings, lexical sort, comma
 *   join, no spaces
 */
export async function epochFingerprint(
  groupToken: string,
  epoch: number,
  gekB64: string,
  pqPubB64: string,
  ikPubs: string[],
): Promise<string> {
  const sorted = [...(ikPubs ?? [])].sort();
  const h = await sha256(utf8(`veil-group-epoch:${groupToken}:${epoch}:${gekB64}:${pqPubB64}:${sorted.join(',')}`));
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{1,4}/g)!.join('-');
}

/** web's xm(): per-message AES key */
async function groupMsgKey(rec: GroupRecord, sid: string, n: number): Promise<Uint8Array> {
  const salt = await sha256(utf8(`veil-group-bind:${rec.groupToken}:${rec.epoch}:${rec.pqPubB64}`));
  return hkdf(fromB64(rec.gekB64), salt, `veil-group-msg:${sid}:${n}`, 32);
}

/** web's sm(): pad payload into a fixed bucket so envelope sizes don't leak length */
function padGroupPayload(text: string, cover: boolean): Uint8Array {
  const body = utf8(text);
  const need = PAYLOAD_HDR + body.length;
  const buckets = isMembershipControl(text) ? REKEY_BUCKETS : PAD_BUCKETS;
  const bucket = buckets.find((b) => b >= need);
  if (!bucket) throw new Error('Message too long for the padded bucket sizes');
  const out = new Uint8Array(bucket);
  out[0] = cover ? 1 : 0;
  new DataView(out.buffer).setUint16(1, body.length);
  out.set(body, PAYLOAD_HDR);
  return out;
}

/** web's cm(): parse the padded payload */
function parseGroupPayload(bytes: Uint8Array): { cover: boolean; text: string } {
  if (bytes.length < PAYLOAD_HDR) throw new Error('Corrupted group message payload');
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(1);
  if (PAYLOAD_HDR + len > bytes.length) throw new Error('Corrupted group message payload');
  return { cover: bytes[0] === 1, text: fromUtf8(bytes.subarray(PAYLOAD_HDR, PAYLOAD_HDR + len)) };
}

/** web's _m(): encrypted group name blob */
export async function encryptGroupText(gekB64: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', fromB64(gekB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, utf8(text) as unknown as BufferSource));
  return `enc1:${toB64(iv)}:${toB64(ct)}`;
}

/** web's vm(): open a name blob (falls back to the raw string) */
export async function decryptGroupText(gekB64: string, blob: string): Promise<string> {
  const m = /^enc1:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/.exec(String(blob ?? ''));
  if (!m) return String(blob ?? '');
  const key = await crypto.subtle.importKey('raw', fromB64(gekB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(m[1]) as unknown as BufferSource }, key, fromB64(m[2]) as unknown as BufferSource));
  return fromUtf8(pt);
}

// ---------- encrypt / decrypt ----------

export interface GroupEnvelopeOut {
  ciphertext: string; iv: string; header: string; byteLength: number; senderTag: string;
}

/** web's Sm(): send-path encrypt. Serialized under a per-group lock so the
 *  send counter never interleaves. */
export async function encryptGroupMessage(
  store: VeilStorage, groupToken: string, text: string, cover = false,
): Promise<GroupEnvelopeOut> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  // Batch C (A3): while an eviction waits for its rotation, only the rotation's
  // own control messages may go out under the old key
  if (rec.evictionPendingAt !== undefined && !isMembershipControl(text)) {
    throw new Error('A member is being removed — waiting for the group keys to rotate. Try again in a moment.');
  }
  // Batch D (D-06, RV-05): members get no eviction signal, so they stop on a key
  // the creator should long since have replaced (intros still go out: they are
  // how a member asks to be let back in)
  if (rec.role === 'member' && !isMembershipControl(text) && !text.startsWith('{"__veil_intro":')) {
    const started = rec.epochStartedAt ? Date.parse(rec.epochStartedAt) : Date.now();
    if (Date.now() - started > MEMBER_EPOCH_MAX_MS) {
      throw new Error('This group\'s keys are out of date. Waiting for the group creator to refresh them — open Vardum on the creator\'s phone, or try again later.');
    }
  }
  const prev = sendLocks.get(groupToken) ?? Promise.resolve();
  let release!: () => void;
  sendLocks.set(groupToken, new Promise<void>((r) => (release = r)));
  await prev;
  try {
    if (sendUnconfirmed.has(rec)) {
      await mergeSendState(store, rec); // b63 review (I3-5): try the read again
      if (sendUnconfirmed.has(rec)) throw new Error('Group keys could not be read on this device. Try again in a moment.');
    }
    const n = rec.sendN;
    // b54 (T-3): a fresh sender chain id whenever the counter (re)starts
    if (n === 0 || !rec.sendChain) rec.sendChain = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, '0')).join('');
    rec.sendN += 1;
    const ch = rec.sendChain;
    // Batch C (A2; reviews P1 NF-3, P2 V-5): sender-signature v2 covers the
    // CIPHERTEXT. The AEAD associated data is the core header (everything but
    // sig); the signature, appended last, covers label ‖ core ‖ IV ‖ SHA-256(ct),
    // so a GEK holder can no longer swap content under another member's header.
    const core: GroupEnvelopeHeader = rec.role === 'forum-member'
      ? { v: GROUP_PROTO, sid: rec.myTag, ge: rec.epoch, n, ch, vid: rec.veilId, sv: GROUP_SIG_VERSION }
      : { v: GROUP_PROTO, sid: rec.myTag, ge: rec.epoch, n, ch, sv: GROUP_SIG_VERSION };
    const coreStr = JSON.stringify(core);
    const msgKey = await groupMsgKey(rec, rec.myTag, n);
    const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = padGroupPayload(text, cover);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource, additionalData: utf8(coreStr) as unknown as BufferSource },
      key, payload as unknown as BufferSource,
    ));
    if (!rec.ikSeedB64) throw new Error('Group identity key missing — cannot sign.');
    const sig = await ikSign(rec.ikSeedB64, toB64(await groupSigMessage(coreStr, iv, ct)));
    const headerStr = JSON.stringify({ ...core, sig });
    // Batch H (R6-2-01): the counter is saved on its own (fail closed); the big
    // record is bookkeeping here, so its size can't stop a send or a removal post
    await persistSendState(store, rec);
    await persistBookkeeping(store, rec);
    return { ciphertext: toB64(ct), iv: toB64(iv), header: headerStr, byteLength: payload.length, senderTag: rec.myTag };
  } finally {
    release();
  }
}

/** web's Cm(): receive-path decrypt with replay guard + per-sender sig check. */
export async function decryptGroupMessage(
  store: VeilStorage, groupToken: string, headerStr: string, ciphertextB64: string, ivB64: string,
  relayChainId?: string,
): Promise<GroupDecryptResult> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  void relayChainId; // Batch C (A5 / V-29): no longer used — the chain id comes ONLY from the signed header
  const parsed = parseSignedGroupHeader(headerStr);
  // an unsigned, pre-Batch-C or malformed envelope is a signature failure, not a transient one
  if (!parsed) throw new Error('veil-group-sig: unsigned, old-format or malformed envelope');
  const { header, coreStr } = parsed;
  const chainId = 'h:' + header.ch;
  const sid = header.sid;
  const n = header.n;
  const senderIk = rec.senderKeys && Object.prototype.hasOwnProperty.call(rec.senderKeys, sid) ? rec.senderKeys[sid] : undefined;

  // b54 (Batch A, N-2): private groups render ONLY messages signed by a
  // verified roster member. Thrown before any counter work, so a roster gap
  // just retries on the next poll. (Lounge / forum keep their own policy.)
  if ((rec.role === 'creator' || rec.role === 'member') && !senderIk) {
    throw new Error('veil-group-sig: sender not on the verified roster');
  }
  // Batch C (A2): verify the v2 signature (covers the ciphertext) BEFORE any
  // decryption or counter work. Unknown forum senders stay unverified here;
  // the forum policy (lounge.ts) refuses to render them.
  let senderVerified = false;
  if (senderIk) {
    const ok = await verifyWithIk(senderIk, toB64(await groupSigMessage(coreStr, fromB64(ivB64), fromB64(ciphertextB64))), header.sig)
      .catch(() => false);
    if (!ok) throw new Error('veil-group-sig: this envelope was not signed by the roster member it claims');
    senderVerified = true;
  }

  const hadSender = Object.prototype.hasOwnProperty.call(rec.recv, sid);
  const prior = hadSender ? rec.recv[sid] : undefined;
  // b54 (pre-audit T-3b): snapshot the STORED state before anything changes,
  // and work on a copy — a failed decrypt must never leave a reset window behind
  // (previously a garbage envelope with a new chain id reset the window for good).
  const snapshot: GroupRecvState | undefined = prior
    ? { last: prior.last, skipped: [...prior.skipped], chain: prior.chain, retired: [...(prior.retired ?? [])] }
    : undefined;
  const saved: GroupRecvState = snapshot
    ? { last: snapshot.last, skipped: [...snapshot.skipped], chain: snapshot.chain, retired: [...(snapshot.retired ?? [])] }
    : { last: -1, skipped: [] };
  // b54 (T-3): never go BACK to a sender chain that was already replaced —
  // that is how an old chain's messages would be replayed after a restart
  if ((saved.retired ?? []).includes(chainId)) {
    throw new Error('Replayed or too-old group message.');
  }
  // b196-r2 chain switch: a DIFFERENT (or, for pre-r2 records, absent-vs-
  // present) posting-session token means this sender's counter restarted —
  // reset the per-chain baseline and judge `n` on the new chain alone.
  // True replays of old-chain envelopes stay impossible to RENDER: exact
  // duplicates sit below the b195 inbox cursor (never fetched) or in the
  // envelope-id ledger, and anything that does decrypt still has to pass the
  // founder-signature fail-closed policy. Classic groups post through one
  // shared session token, so this never fires there (guard unchanged).
  if (saved.chain !== chainId) {
    saved.last = -1;
    saved.skipped = [];
  }
  const switchingFrom = saved.chain !== undefined && saved.chain !== chainId ? saved.chain : undefined;
  try {
    if (n <= saved.last) {
      const idx = saved.skipped.indexOf(n);
      if (idx === -1) throw new Error('Replayed or too-old group message.');
      saved.skipped.splice(idx, 1);
    } else {
      // The counter is in unauthenticated JSON until AES-GCM succeeds. Bound
      // the gap before iterating to avoid a hostile huge-counter UI freeze.
      if (n - saved.last > 1_000_000) throw new Error('Group message counter jump too large.');
      // Only the most recent MAX_SKIPPED positions are recoverable; do not
      // loop over the entire unauthenticated gap even when it is legitimate.
      for (let k = Math.max(saved.last + 1, n - MAX_SKIPPED); k < n; k++) saved.skipped.push(k);
      if (saved.skipped.length > MAX_SKIPPED) saved.skipped = saved.skipped.slice(-64);
      saved.last = n;
    }
    rec.recv[sid] = saved;

    const msgKey = await groupMsgKey(rec, sid, n);
    const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource, additionalData: utf8(coreStr) as unknown as BufferSource },
      key, fromB64(ciphertextB64) as unknown as BufferSource,
    ));
    // b196-r2: only committed after GCM auth succeeds; b54: the replaced chain is retired
    if (switchingFrom !== undefined) saved.retired = [...(saved.retired ?? []), switchingFrom].slice(-16);
    saved.chain = chainId;
    saved.at = Date.now(); // Batch H (R6-2-01)
    boundOpenRecord(rec);
    const out = parseGroupPayload(pt);
    // Batch G (R5-2-03): the replay window is bookkeeping — a refused save keeps it in memory
    const wrote = await persistBookkeeping(store, rec);
    const result: GroupDecryptResult = { ...out, senderVerified, ...(wrote ? {} : { stateNotSaved: true }) };
    return result;
  } catch (e) {
    if (snapshot) rec.recv[sid] = snapshot;
    else delete rec.recv[sid];
    throw e;
  }
}

/** b123: read-only decrypt of MY OWN group envelope — the inbox poll's
 *  own-echo path uses it to learn which envelope id carries a locally-sent
 *  bubble, so group read receipts can tick that bubble (pairwise already
 *  had this via sendChatMessage's envId). Deliberately does NOT touch the
 *  per-sender recv bookkeeping or the sender-signature check — it only
 *  reads the payload back with the same GEK-derived message key. */
export async function decryptOwnGroupEnvelope(
  store: VeilStorage, groupToken: string, headerStr: string, ciphertextB64: string, ivB64: string,
): Promise<{ cover: boolean; text: string }> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  const parsed = parseSignedGroupHeader(headerStr);
  if (!parsed) throw new Error('Malformed group message header.');
  const { header, coreStr } = parsed;
  const msgKey = await groupMsgKey(rec, header.sid, header.n);
  const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource, additionalData: utf8(coreStr) as unknown as BufferSource },
    key, fromB64(ciphertextB64) as unknown as BufferSource,
  ));
  return parseGroupPayload(pt);
}

/** web's fm(): bump the rotation counter (creator auto-rotate trigger) */
export async function bumpGroupEnvCount(store: VeilStorage, groupToken: string): Promise<number> {
  const rec = registry(store).get(groupToken);
  if (!rec) return 0;
  rec.envCount = (rec.envCount ?? 0) + 1;
  await persistBookkeeping(store, rec); // Batch G (R5-2-03)
  return rec.envCount;
}

// ---------- rekey / epoch rotation ----------

export interface GroupRekeyWrap { to: string; ct: string; wk: string; wi: string }
/** b54: signed rekey (v2). `body` is the exact signed string; t/ge/pq/wraps are parsed from it.
 *  Batch C (A3): also rid (rotation id), kc (key commitment), pi/pc (part i of n). */
export interface GroupRekeyPayload {
  t: string; ge: number; pq: string; wraps: GroupRekeyWrap[]; body: string; sig: string;
  rid: string; kc: string; pi: number; pc: number;
}

/** Batch C (A3): commitment to a group key, bound to the group and epoch. Every
 *  part of one rotation carries the same value; a member checks its unwrapped key against it. */
export async function gekCommitment(groupToken: string, epoch: number, gekB64: string): Promise<string> {
  return toB64(await sha256(concat(utf8(`vardum-gek-commit-v1:${groupToken}:${epoch}:`), fromB64(gekB64))));
}

/** Batch C (A1/A3): control messages that may travel while an eviction is pending,
 *  and that use the larger rekey buckets. */
export function isMembershipControl(text: string): boolean {
  return text.startsWith('{"__veil_group_rekey":') || text.startsWith('{"__veil_group_members":');
}

// ---------- Batch C (A1): seats and the creator-signed member list ----------

/** Seat key = HKDF(link secret k, salt "vardum-seat-v1:" ‖ seat token). k lives only in
 *  the link fragment, so the relay — which sees the seat token — cannot derive it. */
export async function deriveSeatKey(linkSecret: string, seatToken: string): Promise<string> {
  if (!/^[0-9a-f]{64}$/i.test(linkSecret)) throw new Error('This invite link is missing its secret.');
  return toB64(await hkdf(utf8(linkSecret.toLowerCase()), utf8(`vardum-seat-v1:${seatToken}`), 'seat', 32));
}

/** Proof that the holder of seat `seatToken` is admitting exactly (veilId, ik). */
export async function seatProof(seatKeyB64: string, groupToken: string, seatToken: string, veilId: string, ikPubB64: string): Promise<string> {
  return toB64(await hmacSha256(fromB64(seatKeyB64), utf8(`vardum-seat-proof-v1:${groupToken}:${seatToken}:${veilId}:${ikPubB64}`)));
}

const MEMBERS_SIG_LABEL = 'vardum-group-members-v1:';

export interface GroupMembersPayload { t: string; seq: number; members: Array<[string, string]>; body: string; sig: string }

/** Creator-signed member list: body = JSON{t, seq, m: [[IK_pub, veil_id], ...]}. */
export async function buildSignedMembersText(creatorIkSeedB64: string, groupToken: string, seq: number, members: Array<[string, string]>): Promise<string> {
  const body = JSON.stringify({ t: groupToken, seq, m: members });
  const sig = await ikSign(creatorIkSeedB64, toB64(utf8(MEMBERS_SIG_LABEL + body)));
  return JSON.stringify({ __veil_group_members: 1, body, sig });
}

export function parseMembersPayload(text: string): GroupMembersPayload | 'invalid' | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_group_members":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_group_members !== 1 || typeof t.body !== 'string' || typeof t.sig !== 'string') return 'invalid';
    const b = JSON.parse(t.body) as Record<string, unknown>;
    if (typeof b.t !== 'string' || !Number.isInteger(b.seq) || Number(b.seq) < 1 || !Array.isArray(b.m)) return 'invalid';
    const members = (b.m as unknown[]).filter((x): x is [string, string] => Array.isArray(x) && x.length === 2 && typeof x[0] === 'string' && typeof x[1] === 'string');
    if (members.length !== (b.m as unknown[]).length || members.length > GROUP_MEMBER_CAP) return 'invalid';
    return { t: b.t, seq: Number(b.seq), members, body: t.body, sig: t.sig };
  } catch { return 'invalid'; }
}

/** Member: accept a member list only if the group creator signed it, it names this
 *  group, it is newer than the one held, and every entry's ID is the hash of its key. */
export async function applyMembersPayload(store: VeilStorage, groupToken: string, payload: GroupMembersPayload): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec || !rec.creatorIkPubB64) return false;
  const ok = await verifyWithIk(rec.creatorIkPubB64, toB64(utf8(MEMBERS_SIG_LABEL + payload.body)), payload.sig).catch(() => false);
  if (!ok) throw new Error('veil-group-sig: member list not signed by the group creator');
  if (payload.t !== groupToken) throw new Error('Member list names a different group — refused.');
  if (payload.seq <= (rec.memberSeq ?? 0)) return false;
  const list: Record<string, string> = {};
  for (const [ik, vid] of payload.members) {
    if ((await veilIdFromIkPub(ik).catch(() => '')) !== vid) continue;
    list[ik] = vid;
  }
  rec.memberList = list;
  rec.memberSeq = payload.seq;
  await saveGroupRecord(store, rec);
  return true;
}

/**
 * Batch C (A1): the senders this device trusts, IK_pub -> veil_id.
 *  creator: itself + admitted, minus the local deny list
 *  member (strict): the creator + the creator-signed list, minus the deny list
 *  member (pre-Batch-C record, no signed list yet): null -> caller falls back to the verified roster
 *  The creator's veil_id is derived from its key, never taken from the relay.
 */
export async function trustedMembers(rec: GroupRecord): Promise<Record<string, string> | null> {
  const denied = new Set(rec.evictedIks ?? []);
  const out: Record<string, string> = {};
  if (rec.role === 'creator') {
    if (rec.openMembership) return null; // the forum: verified roster
    out[rec.ikPubB64] = rec.veilId;
    for (const [ik, vid] of Object.entries(rec.admitted ?? {})) if (!denied.has(ik)) out[ik] = vid;
    return out;
  }
  if (rec.role !== 'member' || rec.memberSeq === undefined) return null;
  if (rec.creatorIkPubB64) out[rec.creatorIkPubB64] = await veilIdFromIkPub(rec.creatorIkPubB64);
  for (const [ik, vid] of Object.entries(rec.memberList ?? {})) if (!denied.has(ik)) out[ik] = vid;
  out[rec.ikPubB64] = rec.veilId;
  return out;
}

/** web's wm(): wrap the new GEK for one member via their published PQ prekey */
export async function buildRekeyWrap(memberPqPubB64: string, toVeilId: string, newGekB64: string): Promise<GroupRekeyWrap> {
  const { ct, secret } = await mlkemEncap(memberPqPubB64);
  const wrapKey = await hkdf(secret, utf8('veil-group-rekey'), toVeilId, 32);
  const key = await crypto.subtle.importKey('raw', wrapKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wk = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, fromB64(newGekB64) as unknown as BufferSource,
  ));
  return { to: toVeilId, ct, wk: toB64(wk), wi: toB64(iv) };
}

/** web's Tm(): unwrap a new GEK with my PQ private key */
export async function openRekeyWrap(myPqPrivB64: string, wrap: GroupRekeyWrap): Promise<string> {
  const secret = await mlkemDecap(myPqPrivB64, wrap.ct);
  const wrapKey = await hkdf(secret, utf8('veil-group-rekey'), wrap.to, 32);
  const key = await crypto.subtle.importKey('raw', wrapKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(wrap.wi) as unknown as BufferSource }, key, fromB64(wrap.wk) as unknown as BufferSource,
  ));
  return toB64(pt);
}

/** b54 (Batch A, N-1): domain label for the creator's rekey signature. */
const REKEY_SIG_LABEL = 'vardum-group-rekey-v2:';

/**
 * b54: build the signed rekey message (creator only). The signed bytes are the
 * exact `body` string carried in the message, so no JSON canonicalisation is
 * needed: sig = Ed25519(creator IK, utf8(label || body)), where body =
 * JSON{t: group token, ge: new epoch, pq: new group PQ pub, wraps}.
 */
export async function buildSignedRekeyText(
  creatorIkSeedB64: string, groupToken: string, ge: number, pq: string, wraps: GroupRekeyWrap[],
  meta: { rid: string; kc: string; pi: number; pc: number },
): Promise<string> {
  const body = JSON.stringify({ t: groupToken, ge, pq, rid: meta.rid, kc: meta.kc, pi: meta.pi, pc: meta.pc, wraps });
  const sig = await ikSign(creatorIkSeedB64, toB64(utf8(REKEY_SIG_LABEL + body)));
  return JSON.stringify({ __veil_group_rekey: 2, body, sig });
}

/**
 * Parse decrypted group text. null = not a rekey message at all;
 * 'invalid' = a rekey-shaped message that must be dropped (old unsigned v1
 * format or malformed) — never rendered as text, never applied.
 */
export function parseRekeyPayload(text: string): GroupRekeyPayload | 'invalid' | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_group_rekey":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_group_rekey !== 2 || typeof t.body !== 'string' || typeof t.sig !== 'string') return 'invalid';
    const b = JSON.parse(t.body) as Record<string, unknown>;
    if (typeof b.t !== 'string' || !Number.isInteger(b.ge) || Number(b.ge) < 1 || typeof b.pq !== 'string' || !Array.isArray(b.wraps)) return 'invalid';
    // Batch C (A3): rotation id, key commitment and part i of n are mandatory
    if (typeof b.rid !== 'string' || !/^[0-9a-f]{16,64}$/.test(b.rid) || typeof b.kc !== 'string' || !b.kc
      || !Number.isInteger(b.pi) || !Number.isInteger(b.pc) || Number(b.pc) < 1 || Number(b.pi) < 0 || Number(b.pi) >= Number(b.pc)) return 'invalid';
    return {
      t: b.t,
      ge: Number(b.ge),
      pq: b.pq,
      rid: b.rid,
      kc: b.kc,
      pi: Number(b.pi),
      pc: Number(b.pc),
      wraps: (b.wraps as GroupRekeyWrap[]).filter((w) => w && typeof w.to === 'string' && typeof w.ct === 'string' && typeof w.wk === 'string' && typeof w.wi === 'string'),
      body: t.body,
      sig: t.sig,
    };
  } catch { return 'invalid'; }
}

/**
 * Apply a rekey to my group record. b54 (Batch A, N-1): accepted ONLY when
 * (1) it is signed by the group creator's IK held in my record, (2) it names
 * this group, and (3) it moves the epoch FORWARD. Anyone else holding the
 * current GEK (a member, a leaked link) can no longer fork or roll back the
 * group's epoch.
 */
export async function applyRekeyPayload(
  store: VeilStorage, groupToken: string, payload: GroupRekeyPayload, myPqPrivB64: string,
): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec) return false;
  if (!rec.creatorIkPubB64) throw new Error('Group creator key unknown on this device — rekey refused.');
  const okSig = await verifyWithIk(rec.creatorIkPubB64, toB64(utf8(REKEY_SIG_LABEL + payload.body)), payload.sig).catch(() => false);
  if (!okSig) throw new Error('Rekey not signed by the group creator — refused.');
  if (payload.t !== groupToken) throw new Error('Rekey names a different group — refused.');
  // a later part of the rekey we already applied: nothing to do (never re-key
  // within an epoch); anything OLDER is a rollback attempt
  if (payload.ge === rec.epoch) {
    // Batch C (A3): same epoch — it must be the SAME key, or the group has split
    if (payload.kc !== await gekCommitment(groupToken, rec.epoch, rec.gekB64)) {
      console.error('[veil-group] rekey for the current epoch commits to a different key — ignored', { groupToken: groupToken.slice(0, 6), epoch: rec.epoch });
    }
    return false;
  }
  if (payload.ge < rec.epoch) throw new Error('Rekey does not move the epoch forward — refused.');
  const wrap = (payload.wraps || []).find((w) => w && w.to === rec.veilId);
  if (!wrap) return false;
  const newGekB64 = await openRekeyWrap(myPqPrivB64, wrap);
  if (payload.kc !== await gekCommitment(groupToken, payload.ge, newGekB64)) {
    throw new Error('Rekey key does not match its signed commitment — refused.');
  }
  return advanceEpoch(store, groupToken, payload.ge, newGekB64, String(payload.pq || rec.pqPubB64));
}

const verifiedAttestations = new Set<string>();

/**
 * b54 (Batch A, H-3): keep only roster rows whose attestation verifies:
 * veil_id = f(IK_pub), Ed25519(IK, {group_token, veil_id, IK_pub, joined_epoch})
 * checks out, a 'creator' row carries the creator IK this device holds, and
 * the IK is not on this device's local deny list. Never trusts the relay's
 * word for who is in the group.
 */
export async function verifiedRosterRows<T extends { veil_id?: unknown; IK_pub?: unknown; joined_epoch?: unknown; attestation_sig?: unknown; role?: unknown }>(
  rec: Pick<GroupRecord, 'groupToken' | 'creatorIkPubB64' | 'evictedIks'>, rows: T[],
): Promise<T[]> {
  const out: T[] = [];
  const denied = new Set(rec.evictedIks ?? []);
  // verified attestations are immutable facts: check each one once per process
  // (a 100-member forum polled every few seconds must not re-verify 100 sigs)
  for (const m of rows) {
    const veilId = String(m.veil_id ?? '');
    const ik = String(m.IK_pub ?? '');
    const sig = String(m.attestation_sig ?? '');
    const joinedEpoch = Number(m.joined_epoch ?? NaN);
    if (!veilId || !ik || !sig || !Number.isInteger(joinedEpoch)) continue;
    if (denied.has(ik)) continue;
    if (String(m.role ?? '') === 'creator' && ik !== rec.creatorIkPubB64) continue;
    const cacheKey = `${rec.groupToken}|${veilId}|${ik}|${joinedEpoch}|${sig}`;
    if (!verifiedAttestations.has(cacheKey)) {
      try {
        if ((await veilIdFromIkPub(ik)) !== veilId) continue;
        const msg = toB64(utf8(JSON.stringify({ group_token: rec.groupToken, veil_id: veilId, IK_pub: ik, joined_epoch: joinedEpoch })));
        if (!(await verifyWithIk(ik, msg, sig))) continue;
      } catch { continue; }
      verifiedAttestations.add(cacheKey);
    }
    out.push(m);
  }
  return out;
}

/** web's Dm(): move to a new epoch (sendN/recv reset, new sender tag) */
export async function advanceEpoch(
  store: VeilStorage, groupToken: string, epoch: number, gekB64: string, pqPubB64: string,
): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  rec.epoch = epoch;
  rec.gekB64 = gekB64;
  rec.pqPubB64 = pqPubB64;
  rec.myTag = await senderTag(groupToken, epoch, rec.veilId);
  rec.sendN = 0;
  rec.recv = {};
  rec.envCount = 0;
  rec.epochStartedAt = new Date().toISOString();
  await saveGroupRecord(store, rec);
  await persistSendState(store, rec).catch(() => undefined); // Batch H: an old-epoch counter is ignored anyway
  return true;
}

/** creator: does this group need an auto-rotation? (100 envelopes / 24 h) */
export function groupNeedsRotation(rec: GroupRecord): boolean {
  const byCount = (rec.envCount ?? 0) >= EPOCH_MAX_ENVELOPES;
  const started = rec.epochStartedAt ? Date.parse(rec.epochStartedAt) : Date.now();
  const byAge = Date.now() - started >= EPOCH_MAX_MS;
  return byCount || byAge;
}

// ---------- signatures ----------

/** web's Om(): creator/member attestation signature */
export function attestSignature(ikSeedB64: string, groupToken: string, veilId: string, ikPubB64: string, joinedEpoch: number): Promise<string> {
  return ikSign(ikSeedB64, toB64(utf8(JSON.stringify({ group_token: groupToken, veil_id: veilId, IK_pub: ikPubB64, joined_epoch: joinedEpoch }))));
}

/** web's km(): deny-list eviction signature */
export function denySignature(ikSeedB64: string, groupToken: string, targetIkPubB64: string, denyEpoch: number): Promise<string> {
  return ikSign(ikSeedB64, toB64(utf8(JSON.stringify({ group_token: groupToken, target_IK_pub: targetIkPubB64, deny_epoch: denyEpoch }))));
}

// ---------- intro (web's Kp/Im) ----------

/** Batch C (A1): v2 intros also carry the seat token and its proof (seat, sp). */
export interface GroupIntro { veilId: string; ikPub: string; nick: string; seat?: string; sp?: string }

export function parseGroupIntro(text: string): { p: string; s: string } | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_intro":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_intro !== 1 || typeof t.p !== 'string' || typeof t.s !== 'string') return null;
    const inner = JSON.parse(t.p) as Record<string, unknown>;
    if ((inner.v !== 1 && inner.v !== 2) || typeof inner.id !== 'string' || typeof inner.ik !== 'string') return null;
    return { p: t.p, s: t.s };
  } catch { return null; }
}

export async function verifyGroupIntro(intro: { p: string; s: string }): Promise<GroupIntro | null> {
  try {
    const inner = JSON.parse(intro.p) as { v?: number; id?: string; ik?: string; nick?: string; seat?: unknown; sp?: unknown };
    const okSig = await verifyWithIk(String(inner.ik), toB64(utf8(intro.p)), intro.s);
    if (!okSig) return null;
    const derived = await veilIdFromIkPub(String(inner.ik));
    if (derived !== String(inner.id)) return null;
    const seat = inner.v === 2 && typeof inner.seat === 'string' && typeof inner.sp === 'string' ? { seat: inner.seat, sp: inner.sp } : {};
    return { veilId: String(inner.id), ikPub: String(inner.ik), nick: typeof inner.nick === 'string' ? inner.nick.slice(0, 40) : '', ...seat };
  } catch { return null; }
}
