/**
 * @veil/device — LOUNGE broadcast mode (b187, veil-lounge-1 descriptor).
 *
 * A lounge is a FOUNDER-BROADCAST channel on top of the existing veil-group-1
 * envelope format — deliberately NOT a new group protocol:
 *
 *  - The FOUNDER runs a normal group (createGroup) whose MAIN session is the
 *    broadcast channel. He is the only sender; every envelope he submits is
 *    per-sender Ed25519-signed (encryptGroupMessage signs whenever the
 *    identity seed is present — it always is for a founder record).
 *  - LISTENERS never join the relay group: no invite session, no gate
 *    attest, no VeilGroupMember roster row, no pairwise ratchet. They hold a
 *    LOCAL GroupRecord with role 'listener' whose senderKeys map contains
 *    exactly ONE entry: the founder's sender tag -> founder IK_pub.
 *
 * SECURITY MODEL (honest, claims-discipline reviewed):
 *  - Descriptor security == invite-link security: the GEK travels in the
 *    descriptor exactly as it travels in an invite link fragment (#w=, &g=).
 *    Anyone holding the descriptor can read lounge traffic. The descriptor
 *    is hosted and rotated by the owner (same rotation path as the current
 *    lounge invite file). This is a beta-founder broadcast room, NOT a
 *    private-membership group — the spec says so in user-facing copy.
 *  - Listener receive policy is FAIL-CLOSED: an envelope is rendered ONLY
 *    when (a) its header.sid is the founder's tag, (b) it carries a valid
 *    signature by the founder's IK key. Unsigned or wrongly-signed founder
 *    envelopes are discarded with onSenderVerifyFailed — for the lounge
 *    there is no "signature verified only when present" middle ground.
 *    (Client-side policy: a modified client can still read descriptor
 *    traffic by hand, but the shipped app will not render forgeries.)
 *  - Listeners never burn relay rows (they hold no session credential to
 *    authorise a burn) and send nothing — the module exposes no send path
 *    and the UI locks the composer for role 'listener'.
 *  - Rotation: lounge rotation is CODE ROTATION (owner publishes a new
 *    descriptor; listeners re-join). Per-member ML-KEM rekey wraps are
 *    impossible without a roster — this is a documented, deliberate limit.
 *    Foreign-epoch rows are skipped and stay retryable, same as members.
 *  - The 8-member cap is untouched: it bounds group MEMBERSHIP (roster),
 *    and listeners are not members of anything on the relay.
 */
import { GROUP_PROTO, decryptGroupMessage, encryptGroupMessage, saveGroupRecord, loadGroupRecord, groupRecord, senderTag, bumpGroupEnvCount, attestSignature, parseGroupIntro, verifyGroupIntro, GroupRecordConflictError, groupRecordBytes, boundOpenRecord } from './groups';
import type { GroupRecord } from './groups';
import { veilIdFromIkPub } from '../../crypto-core/src/identity';
import { createInviteSession, parseInviteLink } from './invite';
import { fromB64 } from '../../crypto-core/src/bytes';
import type { InviteDials } from './invite';
import { relayTimestampToIso } from './time';
import { pageBacklog, parseAnchor, type BackfillAnchor } from './backfill';
import type { GroupSessionDeps, GroupIncomingMedia, GroupInboxEvents } from './group-session';
import { parseRemoveText, resolveFounderPqKey, sealForumReport, reportSendAvailable, recordReportSend } from './moderation';

export const LOUNGE_DESC_VERSION = 'veil-lounge-1';
/** b188: FORUM mode — every holder of the join code can read AND write
 *  (founder + all founding testers talk together). Same descriptor shape;
 *  the version string selects the join policy. */
export const FORUM_DESC_VERSION = 'veil-forum-1';
/** b188-r8: LINK-BASED forum descriptor. Carries the founder's group invite
 *  LINK (clipboard-copied by the owner, never re-typed by anyone) + founder
 *  identity. group token / epoch / PQ key are read from the relay
 *  session-peek at join time, so no long key material is ever hand-copied
 *  into the descriptor. (The r7 GEK loss and the r8 PQ-key loss were both
 *  hand-transcription of long base64 strings — this shape ends that class.) */
export const FORUM_DESC_VERSION_2 = 'veil-forum-2';
/** the record key prefix keeps lounge joins discoverable for thread rows */
export const LOUNGE_TOKEN_PREFIX = 'lounge_';

/** Batch D (D-02/D-04): the forum's identity, shipped in the app so nothing the
 *  relay serves can say which group is the forum. Null until the owner's forum
 *  rotation (D-04) sets it; while null the founder's phone marks no group open. */
export interface ForumPin { groupToken: string; founderVeilId: string; founderIkPubB64: string }
// D-04 (owner rotation, 18 Oct 2026): the Founding Tester Forum created by the founder
// Vardum ID EC2oRHsF2uRS98rb on the owner's new phone. The key was read from the relay's
// identity record and checked to hash to that ID; the group token is the one the founder
// link names and the relay's row confirms (epoch 1). Changing the forum means a new app build.
export const FORUM_PIN: ForumPin | null = {
  // Public copy: the forum's group token is part of its private invite link, so it is
  // left out here. The shipped app carries the real value.
  groupToken: '<forum-group-token>',
  founderVeilId: 'EC2oRHsF2uRS98rb',
  founderIkPubB64: '7s6X2L4XjIupECm5aGMr8z4ebUsxot7uMANoHoHQOqg=',
};
/** Test hook only: tests that build their own forum founders set `pin` to null
 *  (or another pin). The app never touches it. */
export const forumPinTestOverride: { pin: ForumPin | null | undefined } = { pin: undefined };
const activeForumPin = (): ForumPin | null => (forumPinTestOverride.pin !== undefined ? forumPinTestOverride.pin : FORUM_PIN);

/** Batch E (round-3 review F-8): is this the pinned forum's group token? */
export function isPinnedForumToken(groupToken: string): boolean {
  const pin = activeForumPin();
  return !!pin && groupToken === pin.groupToken;
}

/** Batch E (round-3 review F-2): is this group the pinned forum, and this phone
 *  the pinned founder (ID AND identity key)? Reports open only when it is. */
export function isPinnedForumFounder(groupToken: string, myVeilId: string, myIkPubB64: string): boolean {
  const pin = activeForumPin();
  return !!pin && groupToken === pin.groupToken && myVeilId === pin.founderVeilId && myIkPubB64 === pin.founderIkPubB64;
}
const FORUM_PIN_MISMATCH = 'This forum invitation is not the Vardum forum this app trusts, so it was not opened. Update Vardum, or ask the founder.';

export interface LoungeDescriptor {
  v: string;
  /** the founder group's token (envelope group_token filter) */
  group_token: string;
  /** base64 GEK shared by every lounge participant (== invite-link &g=) */
  gek: string;
  /** expected group epoch (lounge rotates by NEW DESCRIPTOR, not rekeys) */
  epoch: number;
  /** founder veil-id — source of the founder sender tag */
  founder_veil_id: string;
  /** founder identity IK_pub (b64) — signature verification key */
  founder_ik_pub: string;
  /** b188-r8: the group's ML-KEM public key — the message-key KDF salt binds
   *  it (veil-group-bind:token:epoch:pqPub), so without it members derive the
   *  wrong key and the founder's messages fail to decrypt. Normal members get
   *  it from the invite-session peek; forum members get it here. */
  group_pq_pub?: string;
  /** b188-r8 (veil-forum-2): the founder group's invite link — the group
   *  token / epoch / PQ key resolve at join time via the relay peek. */
  link?: string;
  /** human display name of the lounge */
  name?: string;
}

/** Validate a hosted lounge descriptor. Throws a user-safe message on any
 *  shape problem — never returns a half-parsed descriptor. */
export function parseLoungeDescriptor(payload: unknown, pin: ForumPin | null = activeForumPin()): LoungeDescriptor {
  const p = (payload ?? {}) as Record<string, unknown>;
  if (p.v !== LOUNGE_DESC_VERSION && p.v !== FORUM_DESC_VERSION && p.v !== FORUM_DESC_VERSION_2) {
    throw new Error('This lounge invitation is not in a supported format.');
  }
  let group_token = String(p.group_token ?? '').trim();
  let gek = String(p.gek ?? '').trim();
  const founderVeilId = String(p.founder_veil_id ?? '').trim();
  const founderIkPub = String(p.founder_ik_pub ?? '').trim();
  let epoch = Number(p.epoch ?? 0);
  const link = String(p.link ?? '').trim();
  // b188-r8: forum-2 resolves gek/epoch from the invite link itself (owner's
  // clipboard copy) — group token and PQ key arrive from the relay peek in
  // joinForum, never from this descriptor.
  if (p.v === FORUM_DESC_VERSION_2) {
    if (!/^https:\/\//.test(link)) throw new Error('This forum invitation is malformed.');
    const parsed = parseInviteLink(link);
    gek = parsed.gek ?? '';
    epoch = parsed.epoch ?? 0;
  }
  if (String(p.v) !== FORUM_DESC_VERSION_2 && !/^[0-9a-f]{16,}$/.test(group_token)) throw new Error('This lounge invitation is malformed.');
  if (!gek || gek.length < 40) throw new Error('This lounge invitation is missing its group key.');
  // b188-r7 (owner repro Oct 11: hosted descriptor served a key ONE CHARACTER
  // short — 43 chars, undecodable — and the old `length < 40` check waved it
  // through, so join "succeeded" and every send then died on a base64 error).
  // The group key must decode to exactly 32 bytes; refuse at the door.
  try {
    if (fromB64(gek).length !== 32) throw new Error('bad length');
  } catch {
    throw new Error('This lounge invitation has a damaged group key. Ask the founder to refresh it.');
  }
  if (!founderVeilId || !founderIkPub) throw new Error('This lounge invitation is missing the founder identity.');
  const groupPqPub = String(p.group_pq_pub ?? '').trim();
  if (String(p.v) === FORUM_DESC_VERSION) {
    // b188-r8: the forum message-key KDF binds the group PQ key — a descriptor
    // without it would join "successfully" and then fail every decrypt. (v2
    // descriptors fetch it from the relay peek instead — see joinForum.)
    let pqOk = false;
    try { pqOk = fromB64(groupPqPub).length >= 800; } catch { pqOk = false; }
    if (!pqOk) throw new Error('This forum invitation is missing its group key material. Ask the founder to refresh it.');
  }
  if (!Number.isInteger(epoch) || epoch < 1) throw new Error('This lounge invitation has an invalid epoch.');
  // Batch D (D-04): with the forum pinned in the app, a descriptor naming another
  // founder (ID or key) or another group is refused here, before any relay call
  if (pin) {
    if (founderVeilId !== pin.founderVeilId || founderIkPub !== pin.founderIkPubB64) throw new Error(FORUM_PIN_MISMATCH);
    if (p.v === FORUM_DESC_VERSION_2) {
      const linkGroup = parseInviteLink(link).groupToken;
      if (linkGroup && linkGroup !== pin.groupToken) throw new Error(FORUM_PIN_MISMATCH);
    } else if (group_token !== pin.groupToken) {
      throw new Error(FORUM_PIN_MISMATCH);
    }
  }
  return {
    v: String(p.v),
    group_token, gek, epoch, link: link || undefined,
    founder_veil_id: founderVeilId,
    founder_ik_pub: founderIkPub,
    group_pq_pub: groupPqPub || undefined,
    name: p.name ? String(p.name).slice(0, 60) : undefined,
  };
}

/** The pseudo-thread token for a lounge in the session list (no relay
 *  session exists — the app needs a stable local row key). */
export function loungeThreadToken(groupToken: string): string {
  return LOUNGE_TOKEN_PREFIX + groupToken;
}

/** Join (or re-join after code rotation) a lounge as a LISTENER.
 *  Purely local: derives the founder's sender tag, stores the listener
 *  record, keeps the previous recv/skip state only when the epoch matches.
 *  No relay calls — a lounge join is invisible to the relay by design. */
export async function joinLounge(
  deps: Pick<GroupSessionDeps, 'storage'>,
  opts: {
    descriptor: LoungeDescriptor;
    identity: { veilId: string; ikSeedB64: string; ikPubB64: string };
    nickname?: string;
    /** Batch D (D-04): defaults to the in-app FORUM_PIN */
    pin?: ForumPin | null;
  },
): Promise<{ threadToken: string; alreadyJoined: boolean; groupToken: string }> {
  const d = opts.descriptor;
  // Batch D (D-04): the pinned forum only
  const lpin = opts.pin === undefined ? activeForumPin() : opts.pin;
  if (lpin && (d.group_token !== lpin.groupToken || d.founder_veil_id !== lpin.founderVeilId || d.founder_ik_pub !== lpin.founderIkPubB64)) throw new Error(FORUM_PIN_MISMATCH);
  const prev = (await loadGroupRecord(deps.storage, d.group_token)) ?? groupRecord(deps.storage, d.group_token);
  // Batch D (D-01, RV-01): the token came from the relay; never let it land on a
  // private group this device already holds
  if (prev && (prev.role === 'creator' || prev.role === 'member')) throw new GroupRecordConflictError();
  const founderTag = await senderTag(d.group_token, d.epoch, d.founder_veil_id);
  const myTag = await senderTag(d.group_token, d.epoch, opts.identity.veilId);
  const rec: GroupRecord = {
    groupToken: d.group_token,
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'listener',
    creatorIkPubB64: d.founder_ik_pub, // b54: only the founder can rekey
    epoch: d.epoch,
    gekB64: d.gek,
    nameGekB64: d.gek,
    pqPubB64: d.group_pq_pub ?? '',
    myTag,
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    name: d.name,
    nicks: { [founderTag]: d.name ?? 'Founder' },
    // FAIL-CLOSED receive policy rides on the existing per-sender signature
    // machinery: the founder is the only key holder in the map.
    senderKeys: { [founderTag]: d.founder_ik_pub },
    // epoch-matched re-join keeps read progress; a rotated code resets it.
    ...(prev && prev.role === 'listener' && prev.epoch === d.epoch
      ? { sendN: prev.sendN, recv: prev.recv, envCount: prev.envCount, syncSkip: prev.syncSkip, syncCursorAt: prev.syncCursorAt, knownEnvIds: prev.knownEnvIds }
      : { sendN: 0, recv: {}, envCount: 0 }),
  };
  await saveGroupRecord(deps.storage, rec);
  return { threadToken: loungeThreadToken(d.group_token), alreadyJoined: !!prev, groupToken: d.group_token };
}

/** Posting-session dials for forum members — long-lived envelopes, no burn
 *  (a forum thread must not vanish readers' history mid-conversation). */
const FORUM_DIALS: InviteDials = { burnAfterOpen: false, expireAfterSeconds: 2592000, keyRetentionHours: 48, defaultTtlSeconds: 2592000 };

/**
 * b188: join the forum (veil-forum-1) as a WRITING member.
 *  One hosted code, one tap — no per-person invites, invisible join:
 *   - creates a SELF-OWNED posting session bound to the forum group token
 *     (the same entityCreate path a group creator's invite sessions use —
 *     no roster row, no gate attest, nothing for the founder to accept)
 *   - stores a forum record: role 'forum-member' with the founder pre-pinned
 *     in senderKeys (founder-tag envelopes verify before any lookup) and the
 *     member's own sender tag + counter for sending
 *  Fail-closed on every shape problem, same as the lounge join.
 */
async function joinForumInner(
  deps: Pick<GroupSessionDeps, 'relay' | 'sessions' | 'storage' | 'webBaseUrl'>,
  opts: {
    descriptor: LoungeDescriptor;
    identity: { veilId: string; ikSeedB64: string; ikPubB64: string };
    clientId: string;
    nickname?: string;
    /** Batch D (D-04): defaults to the in-app FORUM_PIN (tests pass their own) */
    pin?: ForumPin | null;
  },
): Promise<{ threadToken: string; alreadyJoined: boolean; groupToken: string }> {
  let d = opts.descriptor;
  const pin = opts.pin === undefined ? activeForumPin() : opts.pin;
  if (pin && (d.founder_veil_id !== pin.founderVeilId || d.founder_ik_pub !== pin.founderIkPubB64)) throw new Error(FORUM_PIN_MISMATCH);
  if (d.v !== FORUM_DESC_VERSION && d.v !== FORUM_DESC_VERSION_2) throw new Error('This forum invitation is not in a supported format.');
  if (d.v === FORUM_DESC_VERSION_2) {
    // b188-r8 (founder message decrypt repro): forum-2 descriptors carry the
    // founder invite link; the REAL group token / epoch / PQ key are read from
    // the relay session-peek — the same path every normal member join uses —
    // so a 1,568-char PQ key never passes through human hands. The r7 GEK
    // loss and the r8 PQ loss were both hand-transcription failures.
    const parsed = parseInviteLink(d.link ?? '');
    const peek = await deps.relay.invoke('veilSessionGate', {
      action: 'peek', token: parsed.token, write_secret: parsed.writeSecret,
    }) as { data?: { session?: Record<string, unknown> }; session?: Record<string, unknown> };
    const row = peek?.data?.session ?? peek?.session ?? null;
    const groupToken = String(row?.group_token ?? '');
    const rowEpoch = Number(row?.group_epoch ?? 0);
    const pqPubB64 = String(row?.group_pq_pub ?? '');
    if (!/^[0-9a-f]{16,}$/.test(groupToken)) throw new Error('This forum invitation is no longer active. Ask the founder to refresh it.');
    if (!Number.isInteger(rowEpoch) || rowEpoch < 1) throw new Error('This forum invitation has an invalid epoch. Ask the founder to refresh it.');
    let pqOk = false;
    try { pqOk = fromB64(pqPubB64).length >= 800; } catch { pqOk = false; }
    if (!pqOk) throw new Error('This forum is missing its group key material. Ask the founder to refresh it.');
    if (parsed.epoch && parsed.epoch !== rowEpoch) throw new Error('This forum invitation has rotated. Ask the founder for a fresh one.');
    // Batch D (D-03): a founder link that names its group must match the peek
    if (parsed.groupToken && parsed.groupToken !== groupToken) throw new Error('This forum invitation does not match its group. Ask the founder to refresh it.');
    // Batch D (D-04): the relay's answer must be the pinned forum group
    if (pin && groupToken !== pin.groupToken) throw new Error(FORUM_PIN_MISMATCH);
    d = { ...d, group_token: groupToken, epoch: rowEpoch, gek: parsed.gek ?? d.gek, group_pq_pub: pqPubB64 };
  }
  const prev = (await loadGroupRecord(deps.storage, d.group_token)) ?? groupRecord(deps.storage, d.group_token);
  // Batch D (D-01, RV-01): the token came from the relay; never let it land on a
  // private group this device already holds
  if (prev && (prev.role === 'creator' || prev.role === 'member')) throw new GroupRecordConflictError();
  const founderTag = await senderTag(d.group_token, d.epoch, d.founder_veil_id);
  const myTag = await senderTag(d.group_token, d.epoch, opts.identity.veilId);

  // epoch-matched re-join keeps the posting session + read progress; a
  // rotated code starts clean (the old posting session is simply abandoned).
  // b196-r8 (owner repro Oct 12: "[veil-forum] posting session did not
  // persist after mint: 1183aa99" + join stuck at 'not ready' forever): the
  // record can point at a posting session whose sealed state is GONE —
  // end-session ✕, restore, or the app-delete survivor paths all leave a
  // record with a dangling postingSessionToken. The join used to reuse that
  // dead token and throw 'not ready' on every attempt while the SEND path
  // (F7) silently re-minted. The join must self-heal the same way: if the
  // recorded session cannot be loaded back sealed, re-mint fresh.
  let postingSessionToken = prev?.postingSessionToken;
  let rSealed = postingSessionToken
    ? await deps.sessions.load(postingSessionToken) as { writeSecret?: string } | null
    : null;
  if (!rSealed?.writeSecret || !postingSessionToken || prev?.epoch !== d.epoch || prev?.role !== 'forum-member') {
    const created = await createInviteSession(
      { relay: deps.relay, sessions: deps.sessions, webBaseUrl: deps.webBaseUrl },
      { clientId: opts.clientId, dials: FORUM_DIALS, group: { groupToken: d.group_token, groupNameBlob: '', activate: true, epoch: d.epoch, stampEpoch: true } },
    );
    postingSessionToken = created.token;
    rSealed = await deps.sessions.load(postingSessionToken) as { writeSecret?: string } | null;
  }

  // b188-r8 (owner repro: "Sender is not a member of this group epoch"): the
  // relay gate checks the VeilGroupMember roster for the sender's identity at
  // this epoch before accepting a group envelope. Normal members get their
  // roster row via veilGroupGate attest during the invite join; forum members
  // self-mint a posting session instead — so the join MUST attest here, with
  // the fresh posting session's credentials, or every post 403s.
  if (!rSealed?.writeSecret) {
    // b196-r7: the read-back failure is logged with the token so Metro shows
    // which mint was lost; the user-facing copy stays plain (sanitized rule).
    console.error('[veil-forum] posting session did not persist after mint:', postingSessionToken.slice(0, 8), '— secure store rejected the write');
    throw new Error('The forum posting session is not ready — try joining again. If it keeps failing, restart the app and try once more.');
  }
  const sig = await attestSignature(opts.identity.ikSeedB64, d.group_token, opts.identity.veilId, opts.identity.ikPubB64, d.epoch);
  const doAttest = (sessionToken: string, writeSecret: string) =>
    deps.relay.invoke('veilGroupGate', {
      action: 'attest',
      group_token: d.group_token,
      session_token: sessionToken,
      write_secret: writeSecret,
      veil_id: opts.identity.veilId,
      IK_pub: opts.identity.ikPubB64,
      joined_epoch: d.epoch,
      sig,
    });
  try {
    await doAttest(postingSessionToken, rSealed.writeSecret);
  } catch (e) {
    // b196-r8: sealed state can outlive its relay row (the row was ended or
    // swept while the keychain copy survived). Re-attesting a dead row 403s
    // 'Invalid session credential' forever — the join must re-mint once and
    // attest with the fresh session instead of throwing raw relay text.
    const m = String((e as Error)?.message ?? e);
    if (!/invalid session|not found|no such|already/i.test(m)) throw e;
    console.error('[veil-forum] posting session dead on relay — re-minting at join (b196-r8):', postingSessionToken.slice(0, 8), m);
    const created = await createInviteSession(
      { relay: deps.relay, sessions: deps.sessions, webBaseUrl: deps.webBaseUrl },
      { clientId: opts.clientId, dials: FORUM_DIALS, group: { groupToken: d.group_token, groupNameBlob: '', activate: true, epoch: d.epoch, stampEpoch: true } },
    );
    postingSessionToken = created.token;
    const fresh = await deps.sessions.load(postingSessionToken) as { writeSecret?: string } | null;
    if (!fresh?.writeSecret) {
      console.error('[veil-forum] fresh posting session did not persist:', postingSessionToken.slice(0, 8));
      throw new Error('The forum posting session is not ready — try joining again. If it keeps failing, restart the app and try once more.');
    }
    rSealed = fresh;
    await doAttest(postingSessionToken, fresh.writeSecret);
  }

  const rec: GroupRecord = {
    groupToken: d.group_token,
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'forum-member',
    creatorIkPubB64: d.founder_ik_pub, // b54: only the founder can rekey
    epoch: d.epoch,
    gekB64: d.gek,
    nameGekB64: d.gek,
    pqPubB64: d.group_pq_pub ?? '',
    myTag,
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    name: d.name,
    postingSessionToken,
    ...(prev && prev.role === 'forum-member' && prev.epoch === d.epoch
      ? { sendN: prev.sendN, recv: prev.recv, envCount: prev.envCount, syncSkip: prev.syncSkip, syncCursorAt: prev.syncCursorAt, knownEnvIds: prev.knownEnvIds, senderKeys: prev.senderKeys, nicks: prev.nicks }
      : { sendN: 0, recv: {}, envCount: 0, nicks: { [founderTag]: d.name ?? 'Founder' }, senderKeys: { [founderTag]: d.founder_ik_pub } }),
  };
  await saveGroupRecord(deps.storage, rec);
  // b188-r8: groupToken returned so forum-2 callers (where the token resolves
  // from the relay peek inside this call) can address the thread afterwards.
  return { threadToken: loungeThreadToken(d.group_token), alreadyJoined: !!prev && prev.role === 'forum-member' && prev.epoch === d.epoch, groupToken: d.group_token };
}

/**
/** b189 (MissionControl: mass-join resilience): the Base44 relay 429s burst
 *  gate traffic — a whole beta cohort tapping the forum banner at once could
 *  hard-fail joins. joinForumInner is idempotent (an epoch-matched re-join
 *  reuses the existing posting session), so the WHOLE join retries on 429
 *  with exponential backoff + jitter; after the retries the user gets one
 *  honest sentence, never a raw "Rate limit exceeded". */
/**
 * Batch C (A1): on the FOUNDER's phone, mark the creator record of the forum
 * group as open membership. The forum is open by design — anyone holding the
 * public forum link joins, identities verified through the registry — so the
 * founder's view keeps trusting the attestation-verified roster there, while
 * every other group the founder created stays creator-authorised (seat proofs).
 * Only acts when the descriptor names THIS identity as founder (by Vardum ID
 * and key) and this device holds the creator record of the linked group.
 *
 * Batch D (D-02, RV-02): the forum group is no longer resolved from anything the
 * relay serves (the descriptor's token, or a peek). It must be the group pinned
 * in the app (FORUM_PIN), and a group that already admitted anyone through a
 * seat proof is never opened. (Unused seats are allowed:
 * the forum's founder link is itself a seat link.) Until the pin is set (D-04)
 * nothing is marked.
 */
export async function markForumGroupIfFounder(
  deps: Pick<GroupSessionDeps, 'relay' | 'storage'>,
  opts: { descriptor: LoungeDescriptor; identity: { veilId: string; ikPubB64: string } },
  pin: ForumPin | null = activeForumPin(),
): Promise<string | null> {
  const d = opts.descriptor;
  if (!pin) return null;
  if (d.founder_veil_id !== opts.identity.veilId || d.founder_ik_pub !== opts.identity.ikPubB64) return null;
  if (pin.founderVeilId !== opts.identity.veilId || pin.founderIkPubB64 !== opts.identity.ikPubB64) return null;
  const groupToken = pin.groupToken;
  const rec = (await loadGroupRecord(deps.storage, groupToken)) ?? groupRecord(deps.storage, groupToken);
  if (!rec || rec.role !== 'creator' || rec.ikPubB64 !== opts.identity.ikPubB64) return null;
  // (a member list the founder phone signed before it had the pin admits nobody,
  // so only a real admission counts — owner rotation, 18 Oct)
  const hasPrivateMembership = Object.keys(rec.admitted ?? {}).length > 0;
  if (hasPrivateMembership && !rec.openMembership) return null;
  if (!rec.openMembership) {
    rec.openMembership = true;
    await saveGroupRecord(deps.storage, rec);
    console.log('[veil-forum] founder record marked as the open forum group', { groupToken: groupToken.slice(0, 6) });
  }
  return groupToken;
}

export async function joinForum(
  deps: Parameters<typeof joinForumInner>[0],
  opts: Parameters<typeof joinForumInner>[1],
): Promise<{ threadToken: string; alreadyJoined: boolean; groupToken: string }> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await joinForumInner(deps, opts);
    } catch (e: unknown) {
      const msg = String((e as Error)?.message ?? e);
      if (!/429|rate limit/i.test(msg) || attempt >= 3) {
        if (attempt >= 3 && /429|rate limit/i.test(msg)) {
          throw new Error('The forum is busy right now — please try again in a few seconds.');
        }
        throw e;
      }
      const wait = 5000 * attempt + Math.floor(Math.random() * 3000);
      console.log(`[veil-forum] join rate-limited (attempt ${attempt}/3) — backing off ${wait}ms`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
}

/** b189: inbox polls are idempotent reads too — back one off instead of
 *  letting the 3s UI cadence hammer a rate-limited relay. */
async function withBackoff429<T>(label: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (e: unknown) {
      const msg = String((e as Error)?.message ?? e);
      if (!/429|rate limit/i.test(msg) || attempt >= 3) throw e;
      const wait = 3000 * attempt + Math.floor(Math.random() * 2000);
      console.log(`[veil-forum] ${label} rate-limited (attempt ${attempt}/3) — backing off ${wait}ms`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
}

/**
 * b188: post to the forum under the member's OWN posting session. The
 *  envelope is per-sender Ed25519-signed (identity seed is always present)
 *  and carries the member's veil-id in the AEAD-associated header so every
 *  receiver can verify it against the published identity registry.
 */
export async function sendForumMessage(
  deps: GroupSessionDeps,
  opts: { groupToken: string; clientId: string; text: string; cover?: boolean; /** reports: no notify request */ silent?: boolean },
): Promise<{ senderTag: string }> {
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec || rec.role !== 'forum-member' || !rec.postingSessionToken) {
    throw new Error('This forum thread is not joined on this device.');
  }
  let sealed = await deps.sessions.load(rec.postingSessionToken);
  if (!sealed) {
    // b188-r5 SELF-HEAL (owner repro Oct 11): a forum record can point at a
    // posting session that never persisted (pre-r5 joins ignored a silently
    // failed secure-store write, e.g. transient iOS keychain errors). Same
    // recovery semantics as an epoch rotation: mint a fresh posting session,
    // rebind the record, keep all send/recv progress. Fail honestly only if
    // the re-mint ALSO cannot persist.
    console.log('[veil] forum posting session missing on device — re-minting (record kept, progress kept)');
    const remint = await createInviteSession(
      { relay: deps.relay, sessions: deps.sessions, webBaseUrl: (deps as { webBaseUrl: string }).webBaseUrl },
      { clientId: opts.clientId, dials: FORUM_DIALS, group: { groupToken: opts.groupToken, groupNameBlob: '', activate: true, epoch: rec.epoch, stampEpoch: true } },
    );
    const remintSealed = await deps.sessions.load(remint.token);
    if (!remintSealed) throw new Error('Secure storage refused the posting session — could not recover. End this thread and rejoin from Getting started.');
    await saveGroupRecord(deps.storage, { ...rec, postingSessionToken: remint.token });
    sealed = remintSealed;
    rec.postingSessionToken = remint.token;
  }
  const env = await encryptGroupMessage(deps.storage, opts.groupToken, opts.text, opts.cover ?? false);
  // b195: the submit now backs off on 429s (the per-thread cap is ~20 msgs/min;
  // the old single attempt surfaced raw rate errors to fast typists), and a
  // dead relay-side posting session (ended rows, expired sessions — anything
  // the local keychain cannot see) re-mints ONCE and retries, instead of
  // leaving the member stuck on "Session is not available" forever.
  const submitOnce = () => deps.relay.submitEnvelope({
    session_token: rec.postingSessionToken as string,
    group_token: opts.groupToken,
    client_id: opts.clientId,
    write_secret: (sealed as { writeSecret?: string }).writeSecret ?? null,
    sender_client_id: env.senderTag,
    ciphertext: env.ciphertext,
    iv: env.iv,
    header: env.header,
    byte_length: env.byteLength,
    ttl_seconds: Number((sealed as { expireAfterSeconds?: number }).expireAfterSeconds) || 86400,
    protocolVersion: GROUP_PROTO,
  });
  const isDeadSession = (m: string) => /session is not (available|found)|not found/i.test(m);
  let submitRes: unknown;
  try {
    submitRes = await withBackoff429('forum-send', submitOnce);
  } catch (e: unknown) {
    const msg = String((e as Error)?.message ?? e);
    if (!isDeadSession(msg)) throw e;
    console.log('[veil] forum posting session dead on relay — re-minting (b195 self-heal)');
    const remint = await createInviteSession(
      { relay: deps.relay, sessions: deps.sessions, webBaseUrl: (deps as { webBaseUrl: string }).webBaseUrl },
      { clientId: opts.clientId, dials: FORUM_DIALS, group: { groupToken: opts.groupToken, groupNameBlob: '', activate: true, epoch: rec.epoch, stampEpoch: true } },
    );
    const remintSealed = await deps.sessions.load(remint.token);
    if (!remintSealed) throw new Error('Secure storage refused the posting session — could not recover. End this thread and rejoin from Getting started.');
    await saveGroupRecord(deps.storage, { ...rec, postingSessionToken: remint.token });
    rec.postingSessionToken = remint.token;
    sealed = remintSealed;
    submitRes = await withBackoff429('forum-send', submitOnce); // one retry, same budget
  }
  if (submitRes && typeof submitRes === 'object' && 'status' in submitRes && Number((submitRes as { status: number }).status) >= 400) {
    throw new Error('The forum is briefly unavailable — try again in a moment.');
  }
  // b199 (owner decision, Oct 17): a real post asks the relay to ping the
  // forum; the RELAY only honours it for the founder's posts (tester posts
  // stay silent, and a modified app can't use this to spam the cohort).
  if (!opts.cover && !opts.silent) {
    void deps.relay.invoke('veilGroupGate', {
      action: 'notify',
      group_token: opts.groupToken,
      session_token: rec.postingSessionToken as string,
      write_secret: (sealed as { writeSecret?: string }).writeSecret ?? null,
    }).then((r) => {
      const d = (r as { data?: { data?: { pinged?: number }; skipped?: string; coalesced?: boolean } } | null)?.data;
      console.log(`[veil-forum] notify → ${d?.skipped ? 'not sent (' + d.skipped + ')' : d?.coalesced ? 'coalesced' : 'pinged ' + (d?.data?.pinged ?? '?') + ' device(s)'}`);
    }).catch(() => undefined);
  }
  return { senderTag: env.senderTag };
}

/**
 * Play UGC (18 Oct 2026): report a forum post to the founder. The report is
 * sealed to the founder's PQ prekey (verified under the pinned founder key —
 * see moderation.ts) and posted silently through the reporter's own posting
 * session. The relay holds the forum key, so it can see that the post is a
 * report (and who sent it); only the founder's phone can read what it says.
 * (Corrected in Batch H, R6-2-09: this said "one more opaque forum post".)
 */
export async function sendForumReport(
  deps: GroupSessionDeps,
  opts: { groupToken: string; clientId: string; post: { envelopeId: string; senderVeilId: string | null; text: string }; reason?: string; pin?: ForumPin | null },
): Promise<void> {
  const pin = opts.pin === undefined ? activeForumPin() : opts.pin;
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec || rec.role !== 'forum-member' || !rec.creatorIkPubB64) throw new Error('This forum thread is not joined on this device.');
  const founder = pin ?? { founderVeilId: await veilIdFromIkPub(rec.creatorIkPubB64), founderIkPubB64: rec.creatorIkPubB64 };
  if (founder.founderIkPubB64 !== rec.creatorIkPubB64) throw new Error(FORUM_PIN_MISMATCH);
  // Batch F (agent-01 round 4): a send cap on this phone
  if (!(await reportSendAvailable(deps.storage))) throw new Error('You can send up to 3 reports a day. Try again tomorrow, or block the sender now.');
  const pq = await resolveFounderPqKey(deps.relay as never, founder);
  const text = await sealForumReport(pq, founder.founderVeilId, opts.groupToken, {
    postId: opts.post.envelopeId, authorVeilId: opts.post.senderVeilId ?? '',
    excerpt: opts.post.text, reason: (opts.reason ?? '').trim(), at: new Date().toISOString(),
  });
  await sendForumMessage(deps, { groupToken: opts.groupToken, clientId: opts.clientId, text, silent: true });
  await recordReportSend(deps.storage).catch(() => undefined); // Batch G (R5-2-10): only a sent report spends a slot
}

export interface LoungeInboxResult {
  founderVerified: boolean;
  /** founder display nick (descriptor name or veil-id slice) */
  founderNick: string;
}

/**
 * Listener inbox poll — the veil-group-1 envelope list with lounge policy:
 * oldest-first pages, the same full-200 cursor rule and known-after-definitive-
 * outcome ledger as pollGroupInbox, but:
 *   - no roster fetch, no burn, no receipts/intro/rekey handling (a listener
 *     has no session credential and there is nothing to send back)
 *   - founder-tag-only + signature-REQUIRED: sid mismatch, missing sig or
 *     failed verification all discard the row as onSenderVerifyFailed
 *   - cover traffic from the founder is consumed silently (no local bubble)
 */
export async function pollLoungeInbox(
  deps: GroupSessionDeps,
  opts: { groupToken: string; knownIds: Set<string>; events: Pick<GroupInboxEvents, 'onMessage' | 'onSystem' | 'onSenderVerifyFailed'> & {
    /** the founder removed these posts for everyone — drop them from the thread */
    onRemove?: (envelopeIds: string[]) => void;
  } },
): Promise<LoungeInboxResult | null> {
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec || (rec.role !== 'listener' && rec.role !== 'forum-member')) return null;
  // Batch C (B6/F-8): the founder tag is derived from the founder key this
  // record pinned at join — not "the first key in senderKeys", which now also
  // holds persisted forum member keys
  if (!rec.creatorIkPubB64) return null;
  const founderTag = await senderTag(opts.groupToken, rec.epoch, await veilIdFromIkPub(rec.creatorIkPubB64));
  if (!rec.senderKeys?.[founderTag]) return null;
  const founderNick = rec.nicks?.[founderTag] ?? 'Founder';

  // b195-r1: the client entity API exposes NO range filtering (probed live
  // Oct 12: filter_type=gt is inert on every field and wire format), so the
  // inbox pages NEWEST-FIRST from a top anchor recomputed every pass. The
  // old ascending skip cursor froze an offset that SHIFTED every time the
  // sweeper purged expired rows — silently striding past unprocessed
  // backlog at tester volume — and its frozen-not-full rule re-downloaded
  // up to 200 tail ciphertext rows on every poll. Descending pages anchor
  // at the newest row (stable against expired-row deletion, which only
  // happens at the old/deep end), the depth is re-derived each pass from
  // knownEnvIds (never persisted as an offset), and steady state fetches
  // only the newest 50-row page.
  // R1 (audit doc 13): the fixed 4-page cap never reached a backlog deeper
  // than one pass ("converges at 200 rows/pass" did not hold), and decrypting
  // the newest rows first would lose older ones anyway (the replay guard keeps
  // only 64 skipped counters per sender). The pager (backfill.ts) now walks
  // to the processed boundary or the thread's end, resuming at a row anchor
  // kept in the group record when that takes more than one pass; the loop
  // below stops after LOUNGE_BUDGET definitive outcomes, oldest-first.
  const LOUNGE_PAGE = 50;
  const LOUNGE_FETCH_PAGES = 10;
  const LOUNGE_BUDGET = 200;
  const knownAtStart = new Set<string>(rec.knownEnvIds ?? []);
  const anchorRec = rec as GroupRecord & { backfillAnchor?: BackfillAnchor | null };
  const backlog = await pageBacklog({
    fetchPage: async (skip, limit) => {
      const envRaw = await withBackoff429('inbox-poll', () => deps.relay.entityList('VeilEnvelope', {
        group_token: opts.groupToken, sort: '-created_date', limit, skip,
      }));
      const ed = envRaw as unknown[] | { data?: unknown[] };
      return (Array.isArray(ed) ? ed : ed.data ?? []).map((r) => (r ?? {}) as Record<string, unknown>);
    },
    isKnown: (id) => knownAtStart.has(id) || opts.knownIds.has(id),
    pageSize: LOUNGE_PAGE,
    maxPages: LOUNGE_FETCH_PAGES,
    anchor: parseAnchor(anchorRec.backfillAnchor),
  });
  // persisted with the record save at the end of the pass
  if (backlog.anchor) anchorRec.backfillAnchor = backlog.anchor;
  else delete anchorRec.backfillAnchor;
  if (backlog.anchor) console.log(`[veil-forum] backlog deeper than ${backlog.pages} page(s) — still descending, nothing decrypted this pass`);
  const envelopes = backlog.rows; // oldest-first, unprocessed only

  const persistedKnown = new Set<string>(rec.knownEnvIds ?? []);
  let storageRefused = false; // Batch H (R6-2-01)
  let decided = 0;
  const markKnown = (id: string): void => { opts.knownIds.add(id); persistedKnown.add(id); decided++; };
  let founderVerified = false;
  const removed = new Set<string>(rec.removedEnvIds ?? []);

  for (const env of envelopes) {
    // R1: per-pass budget counts definitive outcomes only, so rows that stay
    // retryable can't starve the newer ones behind them
    if (decided >= LOUNGE_BUDGET) break;
    const id = String(env.id ?? '');
    if (!id || opts.knownIds.has(id) || persistedKnown.has(id)) continue;
    // Play UGC: a post the founder removed is never shown, even if its copy is still on the relay
    if (removed.has(id)) { markKnown(id); continue; }
    const expiresAt = env.expires_at ? String(env.expires_at) : null;
    if (expiresAt && new Date(expiresAt).getTime() < Date.now()) continue;
    const headerStr = String(env.header ?? '');
    let header: { v?: string; sid?: string; ge?: number };
    if (!headerStr) { markKnown(id); continue; }
    try { header = JSON.parse(headerStr); } catch { markKnown(id); continue; }
    if (header.v !== GROUP_PROTO) { markKnown(id); continue; }
    const ge = Number(header.ge);
    // lounge listeners never send — an envelope from OUR tag on the relay is
    // someone else's collision or a stale record from a different role; skip.
    if (header.sid === rec.myTag) { markKnown(id); continue; }
    if (ge !== rec.epoch) {
      if (ge < rec.epoch) markKnown(id); // past epoch — keys gone by design
      continue; // future epoch — stays retryable (descriptor rotation gap)
    }
    // FAIL-CLOSED sender policy. LOUNGE (read-only): only the founder's tag
    // may speak. FORUM (b188): the founder is pre-pinned; any OTHER sender
    // must bind — header.vid must hash to the claimed sender tag, the
    // identity must be published, and the published IK_pub must re-derive
    // the veil-id (self-authenticating: a fake registry record cannot match,
    // because the id IS the hash of the key). Only then is the key pinned
    // and the signature verified. Every failure discards the envelope.
    if (header.sid !== founderTag) {
      if (rec.role === 'listener') {
        console.error('[veil-lounge] non-founder envelope discarded', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id);
        markKnown(id);
        continue;
      }
      const vid = (header as { vid?: unknown }).vid;
      if (typeof vid !== 'string' || !vid) {
        console.error('[veil-forum] sender without a verifiable veil-id — discarded', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id);
        markKnown(id);
        continue;
      }
      const bindTag = await senderTag(opts.groupToken, rec.epoch, vid);
      if (bindTag !== header.sid) {
        console.error('[veil-forum] veil-id does not bind to the sender tag — discarded', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id);
        markKnown(id);
        continue;
      }
      if (!rec.senderKeys?.[header.sid]) {
        let ikPub = '';
        try {
          // b189 fix: the REAL relay identity gate returns the record FLAT
          // ({ data: { veil_id, IK_pub, ... } }) — the old nested read
          // (data.identity.IK_pub) never matched the live shape, so every
          // non-founder forum post stayed 'retryable' forever on other
          // members' devices (founder messages worked: pre-pinned key).
          // Accept both shapes; the flat one is what the live gate serves.
          // b195 (stress-probe repro Oct 12): the identity lookup shares the
          // per-account rate budget with writes — under burst load it 429s,
          // the old single attempt swallowed it as "not published yet", and
          // the whole poll pass rendered nothing (the "empty forum" symptom
          // on a fresh join). Backoff + retry within the same pass.
          const lk = (await withBackoff429('identity-lookup', () => deps.relay.identityLookup(vid))) as { data?: { IK_pub?: string; identity?: { IK_pub?: string } }; identity?: { IK_pub?: string }; IK_pub?: string };
          ikPub = String(lk?.data?.IK_pub ?? lk?.data?.identity?.IK_pub ?? lk?.identity?.IK_pub ?? lk?.IK_pub ?? '');
        } catch { /* transient — stays retryable */ }
        if (!ikPub) {
          console.error('[veil-forum] sender identity not published yet — retryable', { envelopeId: id });
          continue;
        }
        const derived = await veilIdFromIkPub(ikPub);
        if (derived !== vid) {
          console.error('[veil-forum] identity registry mismatch — discarded', { envelopeId: id });
          opts.events.onSenderVerifyFailed(id);
          markKnown(id);
          continue;
        }
        rec.senderKeys = { ...(rec.senderKeys ?? {}), [header.sid]: ikPub };
        rec.nicks = { ...(rec.nicks ?? {}), [header.sid]: vid.slice(0, 8) };
        // Batch C (F-8): persist the resolved key now, not only at the end of the pass
        try { await saveGroupRecord(deps.storage, rec); } catch { /* re-resolved next pass */ }
      }
    }
    let out;
    try {
      out = await decryptGroupMessage(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''), String(env.session_token ?? '') || undefined);
    } catch (e) {
      const msg = (e as Error).message ?? '';
      if (/veil-group-sig/i.test(msg)) {
        console.error('[veil-lounge] founder signature failed — envelope discarded', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id);
        markKnown(id); // forged founder envelope — permanently irrelevant
        continue;
      }
      // b198: replay rejections stay SILENT (the poll re-reads the live tail
      // every pass — a correctly-refused replay must not spam the log; same
      // rule as the member path's b198 fix).
      if (!/replayed or too-old/i.test(msg)) console.error('[veil-lounge] envelope decrypt failed', { envelopeId: id, msg });
      continue; // transient — retryable, same rule as the member path
    }
    if (!out.senderVerified) {
      // decryptGroupMessage verifies only senders with a pinned key; the lounge
      // contract requires it. Unsigned founder-tag envelopes are forgeries.
      console.error('[veil-lounge] unsigned founder envelope discarded', { envelopeId: id });
      opts.events.onSenderVerifyFailed(id);
      markKnown(id);
      continue;
    }
    founderVerified = true;
    markKnown(id);
    // Batch H (round-6 review R6-2-01): members get the same once-per-pass note as the founder
    if (out.stateNotSaved) storageRefused = true;
    await bumpGroupEnvCount(deps.storage, opts.groupToken).catch(() => undefined); // Batch E (N3-5)
    if (out.cover) continue; // founder cover traffic — consumed, never rendered

    // b196-r6: PROTOCOL CONTROL MESSAGES NEVER RENDER AS BUBBLES. The forum is
    // two-way now: the web shell announces joins with {"__veil_intro":...} and
    // sends {"__veil_receipt":...} read receipts through the same group inbox.
    // The listener-era poll had no handling for either, so they surfaced as raw
    // JSON in the thread (owner repro Oct 12). Receipts are consumed silently
    // (a forum has no per-message read UI; no burn — listeners hold no write
    // credential). Intros are signature-verified (Ed25519 + veil_id derivation)
    // and surfaced as a system line; a forged/malformed intro is dropped.
    // Both are already markKnown()'d above, so they are never re-processed.
    if (out.text.startsWith('{"__veil_receipt":')) continue;
    // Play UGC: "remove for everyone" counts only from the founder's tag (whose
    // signature was required above); anyone else's is consumed and ignored
    const removeIds = parseRemoveText(out.text);
    if (removeIds) {
      if (header.sid === founderTag && removeIds.length) {
        for (const r of removeIds) removed.add(r);
        rec.removedEnvIds = Array.from(removed).slice(-500);
        opts.events.onRemove?.(removeIds);
      } else if (header.sid !== founderTag) {
        console.error('[veil-forum] removal from a non-founder ignored', { envelopeId: id });
      }
      continue;
    }
    if (out.text.startsWith('{"__veil_intro":')) {
      try {
        const parsedIntro = parseGroupIntro(out.text);
        const intro = parsedIntro ? await verifyGroupIntro(parsedIntro) : null;
        // Batch C (B6): the intro must be signed by the key this sender tag
        // verified under; only the founder's tag may carry the founder's name
        const introSid = String(header.sid);
        const introMatches = !!intro && intro.ikPub === rec.senderKeys?.[introSid]
          && (introSid === founderTag ? intro.ikPub === rec.creatorIkPubB64 : intro.veilId === (header as { vid?: string }).vid);
        const nickAllowed = !!intro && (introSid === founderTag
          || (intro.nick.trim().toLowerCase() !== founderNick.trim().toLowerCase() && !/^founder\b/i.test(intro.nick.trim())));
        if (intro && !introMatches) console.error('[veil-forum] intro does not match its sender — dropped', { envelopeId: id });
        if (intro && introMatches) {
          if (intro.nick && nickAllowed) { rec.nicks = { ...(rec.nicks ?? {}), [introSid]: intro.nick }; }
          opts.events.onSystem({
            envelopeId: id,
            note: `${(nickAllowed && intro.nick) || intro.veilId.slice(0, 8)} joined the forum`,
            sentAt: relayTimestampToIso(env.created_date as string | undefined),
          });
        }
      } catch { /* malformed intro — dropped, never rendered */ }
      continue;
    }
    // Fail-closed default (parity contract W-22): ANY other __veil_* control
    // marker that is not media (rendered below) is consumed and logged, never
    // shown as chat text. Covers rekey/call/future markers reaching this path.
    if (/^\{"__veil_(?!media")[a-z_]+":/.test(out.text)) {
      console.log('[veil-lounge] unrecognised control marker consumed (not rendered)');
      continue;
    }

    let media: GroupIncomingMedia | undefined;
    let text = out.text;
    if (out.text.startsWith('{"__veil_media":')) {
      try {
        const t = JSON.parse(out.text) as Record<string, unknown>;
        if (t.__veil_media === 1 && typeof t.uri === 'string' && typeof t.k === 'string' && typeof t.iv === 'string') {
          media = {
            uri: String(t.uri), k: String(t.k), iv: String(t.iv),
            mime: String(t.mime ?? 'application/octet-stream'), name: String(t.name ?? 'media'),
            size: Number(t.size ?? 0), dl: t.dl === 1 ? true : undefined,
          };
          text = '';
        }
      } catch { /* not media after all — render as text */ }
    }
    const senderNick = rec.nicks?.[String(header.sid)] ?? (((header as { vid?: string }).vid) ? String(header.sid).slice(0, 8) : founderNick);
    opts.events.onMessage({
      envelopeId: id,
      text,
      senderTag: String(header.sid),
      senderVeilId: ((header as { vid?: string }).vid) ?? null,
      senderNick,
      senderVerified: true,
      sentAt: relayTimestampToIso(env.created_date as string | undefined),
      media,
      expiresAt,
    });
  }

  // b195-r1: no persisted fetch cursor exists anymore (see fetch block) —
  // knownEnvIds is both the dedupe set and the backfill-depth signal. Rows
  // with retryable outcomes simply stay unmarked here, so the descending
  // pager keeps reaching them on the next pass.
  // Batch H (R6-2-01): the same 300-id bound as the founder's path, the forum
  // record bounded, its size logged, and a refused save said once
  rec.knownEnvIds = Array.from(persistedKnown).slice(-300);
  boundOpenRecord(rec, Date.now(), founderTag);
  if (groupRecordBytes(rec) > 40_000) console.log('[veil-lounge] large forum record', { bytes: groupRecordBytes(rec) });
  try { await saveGroupRecord(deps.storage, rec); } catch { storageRefused = true; }
  if (storageRefused) opts.events.onSystem({ envelopeId: `storage_${opts.groupToken}`, note: 'This phone’s storage refused to save the forum’s state. Messages still open, but some of it is only kept until the app closes. Free up space, then reopen the forum.', sentAt: new Date().toISOString() });
  return { founderVerified, founderNick };
}
