/**
 * @veil/device — GROUP session orchestration (create / join / inbox / send /
 * rotate / evict), ported from the live web bundle (Sept 19, 2026).
 *
 * All cryptography lives in groups.ts (veil-group-1, byte-exact web parity).
 * This module owns the relay/gate/entity flows:
 *
 *  CREATE (creator):
 *    groupToken = hex(16), GEK = 32 random bytes, group PQ pub = ML-KEM keypair
 *    main session: invite-style createSession bound to the group
 *      (VeilSession group_token + encrypted group_name blob), state ACTIVE —
 *      it is the creator's broadcast channel; nobody ever joins it 1:1.
 *    N invite sessions: plain invite sessions; links carry #w= plus &g=<GEK>&e=1.
 *    veilGroupGate rotate {new_epoch:1, group_pq_pub} → stamps group_epoch on
 *    the group's sessions; veilGroupGate attest (creator sig over
 *      {group_token, veil_id, IK_pub, joined_epoch}); local group record
 *      (role creator); signed intro broadcast into the group channel.
 *
 *  JOIN (member):
 *    parse link → #w= write secret, &g= GEK, &e= expected epoch.
 *    normal invite join (peek → ratchet join → gate join); the gate's session
 *    record carries group_token / group_epoch / group_pq_pub.
 *    Epoch must equal the link's epoch (rotated-after-invite → fresh link).
 *    veilGroupGate attest (member sig); local record (role member, GEK from
 *      the link fragment); signed intro broadcast.
 *
 *  INBOX (poll, per open group thread):
 *    VeilEnvelope filter {group_token} ascending, 200 — decrypt oldest-first,
 *    skip own (sid === myTag) and foreign-epoch headers, discard cover filler,
 *    apply rekey payloads (ML-KEM unwrap against MY pqPriv), render intros as
 *    system notes, surface receipts/media/text, bump the rotation counter.
 *    Roster: VeilGroupMember filter {group_token} → senderKeys for per-sender
 *    signature checks + tag→veilId names + epoch fingerprint input.
 *
 *  SEND: Sm-encrypt via groups.ts, submitEnvelope with BOTH session_token and
 *    group_token, sender_client_id = group sender tag, protocol_version
 *    'veil-group-1'.
 */
import { toB64, fromB64, utf8, randomBytes } from '../../crypto-core/src/bytes';
import { ikSign, verifyWithIk, verifyPqPrekeySig } from '../../crypto-core/src/identity';
import { mlkemKeypair } from '../../crypto-core/src/mlkem';
import { createSession, serializeRatchetState, type RatchetStateSerialized } from '../../crypto-core/src/ratchet';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';
import type { SessionStore } from './session-store';
import type { VeilRelay } from './relay';
import {
  createInviteSession, groupInviteLink, groupLinkBinding, parseInviteLink, joinInviteSession, writeHashHex,
} from './invite';
import { encryptMedia } from './chat';
import { openForumReport, isForumReportText, parseRemoveText, reportAddressedTo, enqueueReport, drainReportQueue, type ForumReport } from './moderation';
import { isPinnedForumFounder, isPinnedForumToken } from './lounge';
import { relayTimestampToIso } from './time';
import {
  GROUP_PROTO, encryptGroupMessage, decryptGroupMessage, saveGroupRecord, loadGroupRecord, loadGroupRecordStrict, readPersistedGroupRecord,
  loadGroupRecords, groupRecord, bumpGroupEnvCount, groupRecordBytes, senderTag, epochFingerprint,
  buildRekeyWrap, parseRekeyPayload, applyRekeyPayload, attestSignature, denySignature,
  buildSignedRekeyText, verifiedRosterRows, REKEY_WRAPS_PER_PART, verifyGroupEnvelopeSig,
  encryptGroupText, decryptGroupText, groupNeedsRotation, exportGroupRecords,
  importGroupRecords, forgetGroup, decryptOwnGroupEnvelope, type GroupRecord, type GroupRekeyPayload, type GroupRekeyWrap,
  parseGroupIntro, verifyGroupIntro, advanceEpoch,
  trustedMembers, parseMembersPayload, applyMembersPayload, buildSignedMembersText, gekCommitment,
  seatProof, deriveSeatKey, type PendingRotation, type GroupSeat,
} from './groups';
// b185: parseGroupIntro/verifyGroupIntro/advanceEpoch moved to this STATIC import.
// The previous dynamic `await import('./groups')` resolved to a SECOND module
// instance under any loader that separates static and dynamic module graphs
// (node:test/tsx demonstrated it live; some bundler configurations do too) —
// the WeakMap group-key registry silently split in two and a rotation could
// throw "Group keys are not established" while the record sat intact in the
// other instance. One module, one registry, no loader-dependent behavior.

export interface GroupIdentity {
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  /** the member's OWN ML-KEM private key — only used to unwrap rekey GEKs */
  pqPrivB64: string;
}

export interface GroupSessionDeps {
  relay: VeilRelay;
  sessions: SessionStore;
  storage: VeilStorage;
  webBaseUrl: string;
}

export interface InviteDialsInput {
  burnAfterOpen: boolean;
  expireAfterSeconds: number;
  keyRetentionHours: number;
  defaultTtlSeconds: number;
}

export interface CreatedGroup {
  groupToken: string;
  groupName: string;
  mainToken: string;
  inviteLinks: string[];
  /** b199: one seat per invited contact, locked to their Veil ID — the app
   *  delivers each link privately inside the encrypted 1:1 chat. */
  contactInvites: { veilId: string; link: string }[];
}

export interface JoinedGroup {
  token: string;
  groupToken: string;
  epoch: number;
}

function hexRand(n: number): string {
  return Array.from(randomBytes(n)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** web's Nm()/Ep(): the signed intro payload broadcast into a group. */
export async function buildIntroPayload(id: GroupIdentity, nickname: string, seat?: { token: string; proof: string }): Promise<string> {
  const nick = (nickname || '').trim().slice(0, 40);
  // Batch C (A1): v2 intros carry the seat token and its proof (link-secret HMAC)
  const p = seat
    ? JSON.stringify({ v: 2, id: id.veilId, ik: id.ikPubB64, nick, seat: seat.token, sp: seat.proof })
    : JSON.stringify({ v: 1, id: id.veilId, ik: id.ikPubB64, nick });
  const s = await ikSign(id.ikSeedB64, toB64(utf8(p)));
  return JSON.stringify({ __veil_intro: 1, p, s });
}

/** b135: the pairwise submit path got assertSubmitOk in b127 after an
 *  HTTP-200-wrapped {error} silently ate a receipt — the GROUP path never
 *  did. Owner repro (Sept 27 lounge test): a harness `say` returned
 *  {ok:true} but its envelope never appeared on the relay (verified by full
 *  ascending page scan of VeilEnvelope rows for the group — every other row
 *  present, that one absent). A 200-wrapped reject must throw here so the
 *  caller can surface it; silence turns a dropped message into a "delivered"
 *  lie. */
function assertGroupSubmitOk(r: { data: unknown; status: number }, what: string): void {
  const d = r.data as { error?: unknown } | null;
  if (r.status >= 400 || (d && typeof d.error === 'string')) {
    throw new Error(`${what} rejected by relay (${r.status}): ${d?.error ?? 'no detail'}`);
  }
}

async function submitGroupEnvelope(
  deps: GroupSessionDeps, opts: {
    groupToken: string; sessionToken: string; clientId: string; text: string; cover?: boolean;
  },
): Promise<{ senderTag: string; byteLength: number }> {
  const sealed = await deps.sessions.load(opts.sessionToken);
  if (!sealed) throw new Error('No session state for this group on this device.');
  const env = await encryptGroupMessage(deps.storage, opts.groupToken, opts.text, opts.cover ?? false);
  const submitRes = await deps.relay.submitEnvelope({
    session_token: opts.sessionToken,
    group_token: opts.groupToken,
    client_id: opts.clientId,
    write_secret: (sealed as RatchetStateSerialized & { writeSecret?: string }).writeSecret ?? null,
    sender_client_id: env.senderTag,
    ciphertext: env.ciphertext,
    iv: env.iv,
    header: env.header,
    byte_length: env.byteLength,
    // b91: group envelopes (messages + receipts) use the session's expire
    // dial, not a hardcoded 1h — same uniform-expiry rule as pairwise
    ttl_seconds: Number((sealed as { expireAfterSeconds?: number }).expireAfterSeconds) || 86400,
    protocolVersion: GROUP_PROTO,
  });
  assertGroupSubmitOk(submitRes, 'group submit'); // b135: no more silent 200-wrapped rejects
  // b198 GROUP PUSH: real group sends (never cover — the caller passes cover
  // only for fillers) ping the other members through the relay's group notify
  // action. Fire-and-forget; the relay coalesces per group+sender.
  if (!opts.cover) {
    void deps.relay.invoke('veilGroupGate', {
      action: 'notify',
      group_token: opts.groupToken,
      session_token: opts.sessionToken,
      write_secret: (sealed as RatchetStateSerialized & { writeSecret?: string }).writeSecret ?? null,
    }).then((r) => {
      // b199 (owner: group pushes not arriving): say what the relay did with the ping
      const d = (r as { data?: { data?: { pinged?: number }; coalesced?: boolean; error?: string } } | null)?.data;
      console.log(`[veil-group] notify → ${d?.coalesced ? 'coalesced (pinged <30s ago)' : d?.error ? 'refused: ' + d.error : 'pinged ' + (d?.data?.pinged ?? '?') + ' device(s)'}`);
    }).catch((e) => console.log(`[veil-group] notify failed: ${(e as Error)?.message ?? e}`));
  }
  return { senderTag: env.senderTag, byteLength: env.byteLength };
}

// ---------- create ----------

export async function createGroup(
  deps: GroupSessionDeps,
  opts: { identity: GroupIdentity; groupName: string; inviteCount: number; clientId: string; dials: InviteDialsInput; nickname?: string;
          /** b199: pinned contacts to invite directly (one locked seat each) */
          invitees?: string[] },
): Promise<CreatedGroup> {
  const groupToken = hexRand(16);
  const pq = await mlkemKeypair();
  const gek = toB64(randomBytes(32));
  const nameBlob = await encryptGroupText(gek, opts.groupName);
  // Batch D (D-03): every link names its group and binds the group's PQ key
  const bind = await groupLinkBinding(groupToken, pq.pub);

  // creator's MAIN group session — active immediately, bound to the group
  const main = await createInviteSession(deps, {
    clientId: opts.clientId,
    dials: opts.dials,
    group: { groupToken, groupNameBlob: nameBlob, activate: true, epoch: 1, pqPubB64: pq.pub },
  });

  // member invite sessions (plain invite links + group fragments)
  // Batch C (A1): every seat is recorded with a key derived from its link
  // secret, so the creator can later admit exactly one identity per seat
  const seats: Record<string, GroupSeat> = {};
  const recordSeat = async (inv: { token: string; link: string }, invitee?: string) => {
    seats[inv.token] = { key: await deriveSeatKey(parseInviteLink(inv.link).linkSecret ?? '', inv.token), ...(invitee ? { invitee } : {}) };
  };
  const invites: string[] = [];
  for (let i = 0; i < opts.inviteCount; i++) {
    const inv = await createInviteSession(deps, { clientId: opts.clientId, dials: opts.dials, group: { groupToken, groupNameBlob: nameBlob, epoch: 1, pqPubB64: pq.pub } });
    await recordSeat(inv);
    invites.push(groupInviteLink(inv.link, gek, 1, opts.identity.ikPubB64, groupToken, bind));
  }
  // b199: contact seats — same invite mechanism, locked to the invitee
  const contactInvites: { veilId: string; link: string }[] = [];
  for (const veilId of [...new Set(opts.invitees ?? [])]) {
    const inv = await createInviteSession(deps, { clientId: opts.clientId, dials: opts.dials, group: { groupToken, groupNameBlob: nameBlob, epoch: 1, pqPubB64: pq.pub, inviteeVeilId: veilId } });
    await recordSeat(inv, veilId);
    contactInvites.push({ veilId, link: groupInviteLink(inv.link, gek, 1, opts.identity.ikPubB64, groupToken, bind) });
  }

  await deps.relay.invoke('veilGroupGate', {
    action: 'rotate',
    group_token: groupToken,
    session_token: main.token,
    write_secret: (await deps.sessions.load(main.token) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    new_epoch: 1,
    group_pq_pub: pq.pub,
  });

  const sig = await attestSignature(opts.identity.ikSeedB64, groupToken, opts.identity.veilId, opts.identity.ikPubB64, 1);
  await deps.relay.invoke('veilGroupGate', {
    action: 'attest',
    group_token: groupToken,
    session_token: main.token,
    write_secret: (await deps.sessions.load(main.token) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    veil_id: opts.identity.veilId,
    IK_pub: opts.identity.ikPubB64,
    joined_epoch: 1,
    sig,
  });

  await saveGroupRecord(deps.storage, {
    groupToken,
    sessionToken: main.token, // b198: the member's own group session (background poll + push credential)
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'creator',
    creatorIkPubB64: opts.identity.ikPubB64,
    evictedIks: [],
    seats,
    admitted: {},
    memberSeq: 0,
    epoch: 1,
    gekB64: gek,
    nameGekB64: gek,
    pqPubB64: pq.pub,
    // b199: the creator keeps the plain name so "Add people" can mint seats later
    name: opts.groupName,
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    myTag: await senderTag(groupToken, 1, opts.identity.veilId),
    sendN: 0,
    recv: {},
    envCount: 0,
  });

  try {
    await submitGroupEnvelope(deps, {
      groupToken,
      sessionToken: main.token,
      clientId: opts.clientId,
      text: await buildIntroPayload(opts.identity, opts.nickname ?? ''),
    });
  } catch (e) {
    console.error('group-create:auto-intro-failed', e);
  }

  return { groupToken, groupName: opts.groupName, mainToken: main.token, inviteLinks: invites, contactInvites };
}

/**
 * b199 "Add people" (creator only): mint new seats for an existing group at its
 * CURRENT epoch — the link carries the current group key and epoch, exactly
 * what joinGroup expects (a seat minted before a rotation would be refused as
 * stale). Locked seats when inviteeVeilId is given; plain link seats otherwise.
 */
export async function createGroupSeats(
  deps: GroupSessionDeps,
  opts: { groupToken: string; clientId: string; dials: InviteDialsInput; invitees?: string[]; linkCount?: number },
): Promise<{ groupName: string; contactInvites: { veilId: string; link: string }[]; inviteLinks: string[] }> {
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('This group is not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the person who created this group can add people.');
  const name = rec.name || 'Group';
  const nameBlob = await encryptGroupText(rec.gekB64, name);
  const seat = async (inviteeVeilId?: string) => {
    const inv = await createInviteSession(deps, {
      clientId: opts.clientId, dials: opts.dials,
      group: { groupToken: rec.groupToken, groupNameBlob: nameBlob, epoch: rec.epoch, pqPubB64: rec.pqPubB64, inviteeVeilId },
    });
    // Batch C (A1): record the seat before its link leaves this device
    const key = await deriveSeatKey(parseInviteLink(inv.link).linkSecret ?? '', inv.token);
    rec.seats = { ...(rec.seats ?? {}), [inv.token]: { key, ...(inviteeVeilId ? { invitee: inviteeVeilId } : {}) } };
    await saveGroupRecord(deps.storage, rec);
    return groupInviteLink(inv.link, rec.gekB64, rec.epoch, rec.creatorIkPubB64 ?? rec.ikPubB64, rec.groupToken, await groupLinkBinding(rec.groupToken, rec.pqPubB64));
  };
  const contactInvites: { veilId: string; link: string }[] = [];
  for (const veilId of [...new Set(opts.invitees ?? [])]) contactInvites.push({ veilId, link: await seat(veilId) });
  const inviteLinks: string[] = [];
  for (let i = 0; i < Math.max(0, opts.linkCount ?? 0); i++) inviteLinks.push(await seat());
  return { groupName: name, contactInvites, inviteLinks };
}

// ---------- join ----------

export async function joinGroup(
  deps: GroupSessionDeps,
  opts: { link: string; clientId: string; displayName?: string; identity: GroupIdentity; nickname?: string },
): Promise<JoinedGroup> {
  const parsed = parseInviteLink(opts.link);
  if (!parsed.gek) throw new Error('This group invitation is incomplete — ask for a fresh link.');
  // b54 (N-1): the creator IK travels with the GEK in the link fragment — it is
  // the only key allowed to move this group to a new epoch.
  let creatorIkOk = false;
  try { creatorIkOk = !!parsed.creatorIk && fromB64(parsed.creatorIk).length === 32; } catch { creatorIkOk = false; }
  if (!creatorIkOk) throw new Error('This group invitation is from an older version of Vardum — ask for a fresh link.');
  const expectedEpoch = parsed.epoch ?? 1;
  // Batch D (D-03, RV-03): the link names its group; the relay doesn't get to.
  // Links made before b56 carry no group token and are refused (hard cut, D5).
  if (!parsed.groupToken || !parsed.groupBind) throw new Error('This group invitation is from an older version of Vardum — ask for a fresh link.');
  // Batch E (round-3 review F-8): the forum is joined only through its pinned
  // descriptor, never as a "group" someone else claims to have created
  if (isPinnedForumToken(parsed.groupToken)) throw new Error('This link points at the Vardum forum. Join the forum from the forum banner instead.');
  // Batch E (F-9): an unreadable record is not "not a member"
  if (await loadGroupRecordStrict(deps.storage, parsed.groupToken)) throw new Error('You are already in this group on this device.');

  // normal invite join (peek → ratchet → gate join, with all its validations)
  await joinInviteSession(deps, { link: opts.link, clientId: opts.clientId, displayName: opts.displayName });

  // fetch the joined record to read the group binding
  // Batch C (V-16): after the join the stored credential may no longer be the link's w
  const seatWrite = (await deps.sessions.load(parsed.token) as RatchetStateSerialized & { writeSecret?: string } | null)?.writeSecret ?? parsed.writeSecret;
  const pk = await deps.relay.invoke('veilSessionGate', { action: 'peek', token: parsed.token, write_secret: seatWrite });
  const pd = pk.data as { data?: { session?: Record<string, unknown> }; session?: Record<string, unknown> };
  const rec = pd?.data?.session ?? pd?.session;
  if (!rec) throw new Error('Invitation not found or expired.');
  const groupToken = String(rec.group_token ?? '');
  if (!groupToken || Number(rec.group_epoch ?? 0) < 1) throw new Error('This group invitation is incomplete — ask for a fresh link.');
  const epoch = Number(rec.group_epoch) || expectedEpoch || 1;
  if (expectedEpoch && epoch !== expectedEpoch) {
    throw new Error('The group rotated its keys after this invitation was made — ask for a fresh link.');
  }
  // Batch D (D-03): the relay's answer must be the group the link names
  if (groupToken !== parsed.groupToken || await groupLinkBinding(groupToken, String(rec.group_pq_pub ?? '')) !== parsed.groupBind) {
    throw new Error('This invitation does not match the group it was made for, so it was not joined. Ask for a fresh link.');
  }

  // Batch C (A1): prove this seat to the creator with the link secret
  const seatKey = await deriveSeatKey(parsed.linkSecret ?? '', parsed.token);
  const proof = await seatProof(seatKey, groupToken, parsed.token, opts.identity.veilId, opts.identity.ikPubB64);

  const sig = await attestSignature(opts.identity.ikSeedB64, groupToken, opts.identity.veilId, opts.identity.ikPubB64, epoch);
  await deps.relay.invoke('veilGroupGate', {
    action: 'attest',
    group_token: groupToken,
    session_token: parsed.token,
    write_secret: seatWrite,
    veil_id: opts.identity.veilId,
    IK_pub: opts.identity.ikPubB64,
    joined_epoch: epoch,
    sig,
  });

  await saveGroupRecord(deps.storage, {
    groupToken,
    sessionToken: parsed.token, // b198: the member's own group session (background poll + push credential)
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'member',
    creatorIkPubB64: parsed.creatorIk,
    // Batch C (A1): strict from the start — trusts the creator only until its signed member list arrives
    memberSeq: 0,
    memberList: {},
    seatToken: parsed.token,
    seatProof: proof,
    introSentAt: Date.now(),
    epoch,
    gekB64: parsed.gek,
    nameGekB64: parsed.gek,
    pqPubB64: String(rec.group_pq_pub ?? ''),
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    myTag: await senderTag(groupToken, epoch, opts.identity.veilId),
    sendN: 0,
    recv: {},
    envCount: 0,
  });

  try {
    await submitGroupEnvelope(deps, {
      groupToken,
      sessionToken: parsed.token,
      clientId: opts.clientId,
      text: await buildIntroPayload(opts.identity, opts.nickname ?? '', { token: parsed.token, proof }),
    });
  } catch (e) {
    console.error('group-join:auto-intro-failed', e);
  }

  return { token: parsed.token, groupToken, epoch };
}

// ---------- inbox ----------

/** incoming group media (parsed from the __veil_media JSON body) */
export interface GroupIncomingMedia {
  uri: string; k: string; iv: string; mime: string; name: string; size: number; dl?: boolean;
}

export interface GroupMemberRow {
  veilId: string;
  /** display nickname (source of truth when set; '' -> UI falls back to veil id) */
  nick: string;
  ikPub: string;
  role: string;
  joinedEpoch: number;
  tag: string;
  /** Batch C (A1): on the relay roster but not admitted by the creator (creator view only) */
  pending?: boolean;
}

export interface GroupInboxEvents {
  /** a normal chat message (text may be '' for media/intro-only envelopes) */
  onMessage: (info: { envelopeId: string; text: string; senderTag: string; senderVeilId: string | null; senderNick: string | null; senderVerified: boolean; sentAt: string; media?: GroupIncomingMedia; expiresAt: string | null }) => void;
  /** system line (X joined the group / keys rotated) */
  onSystem: (info: { envelopeId: string; note: string; sentAt: string }) => void;
  /** my envelopes confirmed read by peers */
  onRead: (readIds: string[]) => void;
  /** the group moved to a new post-quantum epoch */
  onRotated: (newEpoch: number) => void;
  /** a sender-signature failure — envelope discarded (possible impersonation) */
  onSenderVerifyFailed: (envelopeId: string) => void;
  /** b191 parity (shell Oct 12): this device is BEHIND the group's key epoch —
   *  it can neither open members' envelopes nor be opened by them until it
   *  rejoins. Fire ONCE per group per poll cycle; the App layer dedupes. */
  onEpochBehind?: (info: { groupToken: string; behindEpoch: number; localEpoch: number }) => void;
  /** b191 parity: a real (non-replay) key/counter failure opening a group
   *  envelope — this device may be out of step with the group keys. The App
   *  layer shows a one-per-group "rejoin to catch up" notice. */
  onDecryptFailed?: (info: { groupToken: string; err: string }) => void;
  /** b123: own-envelope echo — my just-sent bubble's text back with its
   *  envelope id, so the App layer can attach envId to the local bubble and
   *  group read receipts can tick it. Cover envelopes echo too (harmless:
   *  no local bubble matches their filler text). */
  onOwnEcho?: (envelopeId: string, text: string) => void;
  /** Play UGC: a report sealed to ME (the forum founder) — opened on this phone only */
  onReport?: (info: { envelopeId: string; reporterVeilId: string | null; report: ForumReport; sentAt: string }) => void;
}

export interface GroupInboxResult {
  tagToVeilId: Record<string, string>;
  /** sender tag -> display nickname (source of truth when set) */
  tagToNick: Record<string, string>;
  members: GroupMemberRow[];
  fingerprint: string | null;
  needsRotation: boolean;
  /** Batch E (F-3): creator of a pre-Batch-C group — the old roster to confirm (asked once) */
  legacyRosterToConfirm?: { veilId: string; ikPub: string }[];
}

function asEnvelopeRow(raw: unknown): Record<string, unknown> {
  return (raw ?? {}) as Record<string, unknown>;
}

// b138: the direct VeilGroupMember entityList is dead — the roster-fence fix
// (published) made the entity admin-only, so a non-admin read silently
// returned 0 rows, wiping senderKeys/fingerprint and breaking group
// decryption on native. The ONLY client-facing roster read is now the
// veilGroupGate 'roster' action: it clears session + write-credential
// checks, then fences membership (403 membership_gone / session-group
// binding), and its projection drops account_hash and session_token.
async function gateRoster(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string },
): Promise<{ members: Record<string, unknown>[]; epoch: number }> {
  const ws = (await deps.sessions.load(opts.sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null;
  const res = await deps.relay.invoke('veilGroupGate', {
    action: 'roster',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: ws,
  }) as { data?: { data?: { members?: Record<string, unknown>[]; epoch?: number }; members?: Record<string, unknown>[]; epoch?: number } };
  // b198 (live-caught, first on-device group test post-flip): the relay returns
  // the BASE44 double-wrapped shape { data: { members, epoch } } and invoke
  // hands back the RAW body — so the roster lived at res.data.data.members,
  // one level deeper than this read. A perfectly good roster read as undefined
  // → "Group roster was rejected by the relay" → and since the poll runs the
  // roster BEFORE the envelope fetch, the whole pass aborted and group
  // messages never arrived (Two's 'hey' never seen on One; rotate looked
  // broken too). Accept both shapes; single source of truth for the parse.
  const body = (res?.data ?? {}) as { data?: { members?: Record<string, unknown>[]; epoch?: number }; members?: Record<string, unknown>[]; epoch?: number };
  const members = Array.isArray(body?.data?.members) ? body.data!.members : (Array.isArray(body?.members) ? body.members : undefined);
  if (!Array.isArray(members)) throw new Error('Group roster was rejected by the relay.');
  // b191 parity: the roster is the only place a device with NO pending
  // foreign-epoch envelope can learn the group has moved on without it.
  const epochRaw = body?.data?.epoch ?? body?.epoch;
  return { members: members as Record<string, unknown>[], epoch: Number(epochRaw ?? 0) };
}

/**
 * One pass over the group's envelopes + roster. The App layer calls this on
 * its poll cycle and keeps a known-id set so processed envelopes are skipped.
 */
export async function pollGroupInbox(
  deps: GroupSessionDeps,
  opts: { groupToken: string; identity: GroupIdentity; knownIds: Set<string>; events: GroupInboxEvents; sessionToken?: string; burnAfterOpen?: boolean;
          /** Batch F (R4-2-02): reports from blocked senders are never queued or opened */
          isBlocked?: (veilId: string) => boolean;
          /** Batch H (round-6 review R6-2-05): queued reports are opened only once the
           *  block list has loaded (before that, a blocked tester's report looked unblocked) */
          blockListReady?: () => boolean;
          /** b54 (device test Oct 18): BACKGROUND PEEK for a closed thread —
           *  read-only. Reports new real messages via onMessage (text empty)
           *  so the app can notify, but consumes NOTHING: no recv/replay
           *  state, no known-ledger entry, no burn, no rekey, no cursor move.
           *  The open thread's normal pass processes and renders them later.
           *  (Before: the background pass consumed + burned the messages and
           *  they never rendered — "notification, nothing in the chat".) */
          peekOnly?: boolean;
          /** Batch C (A1): lets the creator publish the signed member list from the pass */
          clientId?: string },
): Promise<GroupInboxResult | null> {
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec) return null;
  // Batch D (D-08, RV-19): private groups only. Forum and lounge records go
  // through pollLoungeInbox, which checks every sender against the forum roster;
  // here their unknown senders would render unverified.
  if (rec.role !== 'creator' && rec.role !== 'member') {
    console.warn('[veil-group] pollGroupInbox refused a non-private record', { role: rec.role, groupToken: rec.groupToken.slice(0, 6) });
    return null;
  }

  // b132: relay-side burn-after-open for groups. The veilSessionGate 'burn'
  // action authorises any envelope in this group against the CALLER's OWN
  // session credential (session.group_token === env.group_token clause —
  // builder-verified), so a receiving member can burn envelopes it has
  // definitively processed: the group twin of the pairwise burn-on-decrypt
  // in chat.ts. Without this, group envelopes sat at the full 24h submit
  // TTL no matter how many members opened them (owner repro: 5-min lounge,
  // every relay row still +24h after both members opened everything).
  // EXEMPT from burn: rekey payloads (epoch control channel — burning one
  // can permanently desync a member offline past the window) and past-epoch
  // rows (a lagging member can still read those). Own echoes are skipped by
  // the caller below — the sender's envelope serves the OTHER members.
  const burnCred = opts.burnAfterOpen && opts.sessionToken
    ? { token: opts.sessionToken, ws: (await deps.sessions.load(opts.sessionToken))?.writeSecret ?? null }
    : null;
  const burnEnvelope = async (id: string, what: string): Promise<void> => {
    if (!burnCred) return;
    try {
      // b134 (owner Metro log, Sept 27): every burn call — including ones
      // the builder confirmed DID shorten the relay row's TTL — logged
      // "no-op (unknown reason)". relay.invoke() (what sessionBurn calls)
      // returns the WRAPPER shape { data, status }, not the bare response
      // body — burned/reason live at res.data.burned / res.data.reason, one
      // level deeper than this was reading. res.burned was always
      // undefined, so this branch always fell through regardless of the
      // real outcome. Pure logging bug — the burn call itself was fine.
      const wrapped = (await deps.relay.sessionBurn(burnCred.token, burnCred.ws, id)) as { data?: { burned?: boolean; reason?: string } };
      const res = wrapped?.data ?? {};
      console.log(`[veil-group] burn ${what} ${id.slice(0, 8)}: ${res?.burned ? 'burned' : `no-op (${res?.reason ?? 'unknown reason'})`}`);
    } catch (e) {
      // Best-effort by design (same as web); a missed burn leaves the row
      // at its submit TTL. Logged with the id so Metro shows exactly which.
      console.log(`[veil-group] burn FAILED for ${id.slice(0, 8)} (${what}): ${(e as Error).message ?? e}`);
    }
  };

  // ---- roster (web's f()): members + senderKeys + tag->veilId names
  // b138: routed through veilGroupGate 'roster' (entity is admin-only now).
  if (!opts.sessionToken) throw new Error("Group roster requires this member's session.");
  const roster = await gateRoster(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken });
  // b54 (Batch A, H-3): only attestation-verified, non-denied rows count —
  // they alone feed senderKeys (signature checks), names and the fingerprint.
  const memberRows = await verifiedRosterRows(rec, roster.members.map(asEnvelopeRow));
  if (memberRows.length < roster.members.length) {
    console.warn('[veil-group] roster rows failed verification and were ignored', { groupToken: opts.groupToken.slice(0, 6), dropped: roster.members.length - memberRows.length });
  }
  // b191 parity: the roster read is the only place a device with no pending
  // foreign-epoch envelope learns the group moved on without it — same
  // onEpochBehind as the envelope-path mismatch above.
  // b54 (device test Oct 18): RECORDED here, raised only after the envelope
  // pass — the rekey that catches this device up is usually in this very
  // page, and warning first showed a false "rejoin required" banner.
  let behindEpoch = roster.epoch > rec.epoch ? roster.epoch : 0;
  const members: GroupMemberRow[] = [];
  const tagToVeilId: Record<string, string> = {};
  const tagToNick: Record<string, string> = { ...(rec.nicks ?? {}) };
  if (rec.myNick) tagToNick[rec.myTag] = rec.myNick;
  const senderKeys: Record<string, string> = {};
  // Batch C (A1): who counts as a member is decided by the CREATOR, never by
  // the relay roster. Creator: its admitted list (one IK per seat it minted,
  // proven with the seat's link secret). Member: the creator-signed list.
  // Batch E (round-3 review F-3): a pre-Batch-C creator record used to adopt the
  // relay roster on its first poll, so a relay that injected itself at that moment
  // got every later key. Now the roster is held aside and nobody on it is trusted
  // until the creator confirms (confirmLegacyRoster); meanwhile they show as pending.
  let membersChanged = !!rec.memberListDirty;
  if (rec.role === 'creator' && rec.admitted === undefined && !rec.openMembership) {
    rec.admitted = {};
    const held: Record<string, string> = {};
    for (const m of memberRows) {
      const ik = String(m.IK_pub ?? ''), vid = String(m.veil_id ?? '');
      if (ik && vid && ik !== rec.ikPubB64) held[ik] = vid;
    }
    if (Object.keys(held).length) rec.legacyRoster = held;
    console.log('[veil-group] pre-Batch-C group: roster held for the creator to confirm', { groupToken: opts.groupToken.slice(0, 6), members: Object.keys(held).length });
  }
  const trusted = await trustedMembers(rec);
  /** creator only: roster-verified identities that are not admitted yet — their
   *  envelopes are read ONLY to find a seat-proven intro (see the loop) */
  const pendingKeys: Record<string, string> = {};
  const rosterIks = new Set<string>();
  for (const m of memberRows) {
    const veilId = String(m.veil_id ?? '');
    const ikPub = String(m.IK_pub ?? '');
    if (!veilId || !ikPub) continue;
    rosterIks.add(ikPub);
    const tag = await senderTag(opts.groupToken, rec.epoch, veilId);
    if (trusted && !trusted[ikPub]) {
      if (rec.role === 'creator' && !(rec.evictedIks ?? []).includes(ikPub)) {
        pendingKeys[tag] = ikPub;
        tagToVeilId[tag] = veilId;
        members.push({ veilId, nick: '', ikPub, role: 'pending', joinedEpoch: Number(m.joined_epoch ?? 0), tag, pending: true });
      }
      continue;
    }
    members.push({ veilId, nick: '', ikPub, role: String(m.role ?? 'member'), joinedEpoch: Number(m.joined_epoch ?? 0), tag });
    tagToVeilId[tag] = veilId;
    senderKeys[tag] = ikPub;
  }
  // trusted members the relay roster no longer lists still count (the relay
  // can't remove someone the creator admitted); they just aren't shown as joined
  for (const [ik, vid] of Object.entries(trusted ?? {})) {
    if (rosterIks.has(ik)) continue;
    const tag = await senderTag(opts.groupToken, rec.epoch, vid);
    senderKeys[tag] = ik;
    tagToVeilId[tag] = vid;
  }
  rec.senderKeys = senderKeys;
  const confirmed = members.filter((m) => !m.pending);
  const fingerprint = confirmed.length
    ? await epochFingerprint(opts.groupToken, rec.epoch, String(rec.gekB64 ?? ''), String(rec.pqPubB64 ?? ''), confirmed.map((m) => m.ikPub))
    : null;

  // ---- envelopes (web's g()): oldest-first, skip known
  // b92 F10 (b91 audit): the group twin of the b87 pairwise stall — this
  // fetch had NO pagination cursor, so a group past 200 total envelopes
  // (cover traffic accumulates them fast) re-read the same oldest 200
  // forever and NEW group messages silently stopped arriving. Same rule
  // as syncChat: advance the per-group cursor ONLY on a full 200-row
  // page, by (page - margin); a partial page IS the live tail and must
  // stay re-scannable for freshness.
  const GROUP_PAGE = 200;
  const GROUP_MARGIN = 20;
  const startSkip = Math.max(0, Math.floor(Number(rec.syncSkip) || 0));
  const envRaw = await deps.relay.entityList('VeilEnvelope', {
    group_token: opts.groupToken, sort: 'created_date', limit: GROUP_PAGE,
    ...(startSkip > 0 ? { skip: startSkip } : {}),
  });
  const ed = envRaw as unknown[] | { data?: unknown[] };
  const envelopes = (Array.isArray(ed) ? ed : ed.data ?? []).map(asEnvelopeRow);

  // Batch E (round-3 review F-1): never for the forum (open membership). Forum
  // members never apply rekeys and the relay refuses posts off the current
  // epoch, so an automatic rotation would silently break the forum; a forum
  // rotates by a new descriptor instead.
  let needsRotation = rec.role === 'creator' && !rec.openMembership && groupNeedsRotation(rec);

  // b92 F11 (b91 audit): mark known ONLY after a definitive outcome —
  // successful decrypt, or a permanently-irrelevant row (own envelope,
  // foreign protocol, malformed header, PAST epoch whose keys are gone by
  // design). Previously EVERY row was marked known up-front, so an
  // epoch-transition race (rekey payload landing later in the same fetch)
  // or a transient decrypt failure permanently swallowed a REAL message —
  // the exact bug class the Sept 19 audit fix removed from the pairwise
  // path. Future-epoch rows and failed decrypts stay RETRYABLE; the F10
  // cursor eventually retires them from the fetch window.
  const persistedKnown = new Set<string>(rec.knownEnvIds ?? []);
  let storageNoted = false; // Batch G (R5-2-03)
  let reportsDroppedNoted = false; // Batch G (NF-2)
  const markKnown = (id: string): void => {
    opts.knownIds.add(id);
    persistedKnown.add(id);
  };
  for (const env of envelopes) {
    const id = String(env.id ?? '');
    if (!id || opts.knownIds.has(id) || persistedKnown.has(id)) continue;
    const expiresAt = env.expires_at ? String(env.expires_at) : null;
    if (expiresAt && new Date(expiresAt).getTime() < Date.now()) continue;
    const headerStr = String(env.header ?? '');
    let header: { v?: string; sid?: string; ge?: number };
    if (!headerStr) { markKnown(id); await burnEnvelope(id, 'malformed'); continue; } // malformed — never improves
    try { header = JSON.parse(headerStr); } catch { markKnown(id); await burnEnvelope(id, 'malformed'); continue; }
    if (header.v !== GROUP_PROTO) { markKnown(id); await burnEnvelope(id, 'foreign-proto'); continue; } // permanently irrelevant
    const ge = Number(header.ge);
    // b123: my OWN envelope — read the payload back (own GEK, no recv
    // bookkeeping) and emit the id so the App layer can bind envId to the
    // locally-sent bubble; group read receipts then work like pairwise.
    if (header.sid === rec.myTag) {
      if (opts.events.onOwnEcho && ge === rec.epoch) {
        try {
          const own = await decryptOwnGroupEnvelope(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''));
          if (!own.cover && own.text && !own.text.startsWith('{"__veil_intro"')) opts.events.onOwnEcho(id, own.text);
        } catch { /* cover / malformed own envelope — nothing to bind */ }
      }
      markKnown(id); continue;
    }
    if (ge !== rec.epoch) {
      // b191 parity: shell Oct 12 — a foreign epoch used to vanish with NO
      // trace. Trace both sides + deviceBehind; a NEWER epoch means this
      // device missed a rekey and is blind in both directions, so surface it
      // (onEpochBehind) instead of dropping silently forever.
      console.log('[veil-group] epoch mismatch', { groupToken: opts.groupToken.slice(0, 8), envelopeId: id, senderEpoch: ge, localEpoch: rec.epoch, deviceBehind: ge > rec.epoch });
      if (ge > rec.epoch) behindEpoch = Math.max(behindEpoch, ge);
      if (ge < rec.epoch) markKnown(id); // past epoch — keys gone by design
      continue; // future epoch — RETRYABLE until the rekey envelope lands
    }

    // Batch C (A1): a sender the creator has not admitted. Nothing is rendered
    // and nothing is consumed (retryable: it renders once the member is on the
    // creator-signed list). The creator reads such an envelope read-only, and
    // only to find a seat-proven intro to admit.
    {
      const sid = String(header.sid ?? '');
      if ((rec.role === 'creator' || rec.role === 'member') && !senderKeys[sid]) {
        if (!opts.peekOnly && rec.role === 'creator' && pendingKeys[sid]) {
          // Batch D (D-08): one malformed intro can never stall the pass
          const admittedVid = await admitFromIntro(deps.storage, rec, {
            ik: pendingKeys[sid], veilId: tagToVeilId[sid] ?? '', headerStr,
            ciphertextB64: String(env.ciphertext ?? ''), ivB64: String(env.iv ?? ''),
          }).catch((err) => { console.warn('[veil-group] intro not admitted', String((err as Error)?.message ?? err)); return null; });
          if (admittedVid) {
            markKnown(id);
            membersChanged = true;
            senderKeys[sid] = pendingKeys[sid];
            delete pendingKeys[sid];
            const row = members.find((m) => m.tag === sid);
            if (row) { row.pending = false; row.role = 'member'; }
            opts.events.onSystem({ envelopeId: id, note: `${tagToNick[sid] || admittedVid.slice(0, 8)} joined the group`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
          }
        }
        continue;
      }
    }

    if (opts.peekOnly) {
      // b54: read-only — notify for real messages from verified members only;
      // everything stays unconsumed for the open thread's pass.
      const sid = String(header.sid ?? '');
      // Batch C (A2): the peek checks the full v2 signature (it covers the ciphertext)
      const signedByMember = !!senderKeys[sid]
        && await verifyGroupEnvelopeSig(senderKeys[sid], headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''));
      if ((rec.role === 'creator' || rec.role === 'member') && !signedByMember) continue;
      try {
        const peek = await decryptOwnGroupEnvelope(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''));
        const control = /^\{"__veil_(receipt|intro|group_rekey|remove|report|group_members)":/.test(peek.text); // Batch E (F-11)
        if (!peek.cover && peek.text && !control) {
          opts.events.onMessage({
            envelopeId: id, text: '', senderTag: sid, senderVeilId: tagToVeilId[sid] ?? null, senderNick: tagToNick[sid] ?? null,
            senderVerified: signedByMember, sentAt: relayTimestampToIso(env.created_date as string | undefined), expiresAt,
          });
        }
      } catch { /* not decryptable yet — the open thread's pass will retry */ }
      continue;
    }

    let out;
    try {
      out = await decryptGroupMessage(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''), String(env.session_token ?? '') || undefined);
    } catch (e) {
      // b92 F11: NOT marked known — a transient failure (rekey race,
      // momentary roster gap behind a sender-signature check) must stay
      // retryable, exactly like the pairwise path post Sept 19.
      if (/veil-group-sig/i.test((e as Error).message ?? '')) {
        console.error('Group sender signature failed — envelope discarded', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id);
      } else {
        const dmsg = String((e as Error).message ?? 'unknown');
        // b191 parity: replay rejections stay SILENT (normal re-scan result —
        // the poll re-reads the live tail every pass, so a pre-rotation row
        // correctly refuses forever and must not spam the log); a REAL
        // key/counter failure is traced + surfaced so a stale device gets told
        // to rejoin instead of silently missing messages. b198: the
        // console.error moved INSIDE the guard — it was logging replays too.
        if (!/replayed or too-old/i.test(dmsg)) {
          console.error('[veil-group] envelope decrypt failed', { envelopeId: id, msg: dmsg });
          opts.events.onDecryptFailed?.({ groupToken: opts.groupToken, err: dmsg });
        }
      }
      continue;
    }

    markKnown(id); // b92 F11: definitive outcome — safe to record now
    // Batch G (R5-2-03): tell the thread once when the phone refused to save the group state
    if (out.stateNotSaved && !storageNoted) {
      storageNoted = true;
      opts.events.onSystem({ envelopeId: `storage_${opts.groupToken}`, note: 'This phone’s storage refused to save this group’s state. Messages still open, but some of it is only kept until the app closes. Free up space, then reopen the group.', sentAt: new Date().toISOString() });
    }
    // Batch E (N3-5): the rotation counter is a heuristic; a storage error must not abort the pass
    await bumpGroupEnvCount(deps.storage, opts.groupToken).catch((e) => console.log('[veil-group] envelope counter not saved:', String((e as Error)?.message ?? e)));
    if (out.cover) { await burnEnvelope(id, 'cover'); continue; } // cover traffic — never rendered

    // rekey? (b132: EXEMPT from relay burn — the epoch control channel must
    // outlive any single member's burn window or offline members desync)
    const rekey = parseRekeyPayload(out.text);
    if (rekey === 'invalid') {
      console.error('[veil-group] unsigned or malformed rekey dropped', { envelopeId: id });
      continue;
    }
    if (rekey) {
      const applied = await applyRekeyPayload(deps.storage, opts.groupToken, rekey, opts.identity.pqPrivB64).catch((e) => {
        console.error('[veil-group] rekey apply failed', e);
        return false;
      });
      if (applied) {
        // Batch C: sender tags are per epoch — re-derive them so messages in
        // the new epoch later in this same page verify without waiting a pass
        const byKey = Object.entries(senderKeys).map(([tag, ik]) => [ik, tagToVeilId[tag]] as const);
        const pendingByKey = Object.entries(pendingKeys).map(([tag, ik]) => [ik, tagToVeilId[tag]] as const);
        for (const k of Object.keys(senderKeys)) delete senderKeys[k];
        for (const k of Object.keys(pendingKeys)) delete pendingKeys[k];
        for (const [ik, vid] of byKey) {
          if (!vid) continue;
          const t = await senderTag(opts.groupToken, rekey.ge, vid);
          senderKeys[t] = ik; tagToVeilId[t] = vid;
          const m = members.find((x) => x.ikPub === ik); if (m) m.tag = t;
        }
        for (const [ik, vid] of pendingByKey) {
          if (!vid) continue;
          const t = await senderTag(opts.groupToken, rekey.ge, vid);
          pendingKeys[t] = ik; tagToVeilId[t] = vid;
          const m = members.find((x) => x.ikPub === ik); if (m) m.tag = t;
        }
        rec.senderKeys = senderKeys;
        opts.events.onRotated(rekey.ge);
        opts.events.onSystem({ envelopeId: id, note: 'Group keys rotated — new post-quantum epoch.', sentAt: relayTimestampToIso(env.created_date as string | undefined) });
      }
      continue;
    }

    // Batch C (A1): the creator-signed member list
    const memberMsg = parseMembersPayload(out.text);
    if (memberMsg === 'invalid') { console.error('[veil-group] malformed member list dropped', { envelopeId: id }); continue; }
    if (memberMsg) {
      if (rec.role === 'member') {
        try {
          if (await applyMembersPayload(deps.storage, opts.groupToken, memberMsg)) {
            console.log('[veil-group] creator-signed member list applied', { groupToken: opts.groupToken.slice(0, 6), seq: memberMsg.seq, members: memberMsg.members.length });
            // trust the listed members for the rest of this pass too (their
            // messages later in this page render now, not on the next pass)
            for (const [ik, vid] of Object.entries(groupRecord(deps.storage, opts.groupToken)?.memberList ?? {})) {
              if ((rec.evictedIks ?? []).includes(ik)) continue;
              const t = await senderTag(opts.groupToken, rec.epoch, vid);
              if (senderKeys[t]) continue;
              senderKeys[t] = ik; tagToVeilId[t] = vid;
              const row = members.find((m) => m.ikPub === ik);
              if (!row) members.push({ veilId: vid, nick: '', ikPub: ik, role: 'member', joinedEpoch: rec.epoch, tag: t });
            }
            rec.senderKeys = senderKeys;
          }
        } catch (e) {
          console.error('[veil-group] member list refused', { envelopeId: id, msg: String((e as Error).message ?? e) });
          opts.events.onSenderVerifyFailed(id);
        }
      }
      continue;
    }

    // read receipts?
    if (out.text.startsWith('{"__veil_receipt":')) {
      try {
        const t = JSON.parse(out.text) as { __veil_receipt?: number; ids?: string[] };
        if (t.__veil_receipt === 1 && Array.isArray(t.ids)) opts.events.onRead(t.ids.slice(0, 20));
      } catch { /* ignore */ }
      await burnEnvelope(id, 'receipt');
      continue;
    }

    // intro?
    if (out.text.startsWith('{"__veil_intro":')) {
      const parsed = parseGroupIntro(out.text);
      const intro = parsed ? await verifyGroupIntro(parsed) : null;
      // Batch C (B6): the intro's key and ID must be the ones this sender tag
      // is trusted under — no claiming another member's nickname or identity
      const sidKey = String(header.sid);
      if (intro && (intro.ikPub !== senderKeys[sidKey] || intro.veilId !== tagToVeilId[sidKey])) {
        console.error('[veil-group] intro does not match its sender — dropped', { envelopeId: id });
      } else if (intro) {
        if (intro.nick) tagToNick[String(header.sid)] = intro.nick;
        opts.events.onSystem({
          envelopeId: id,
          note: `${intro.nick || intro.veilId.slice(0, 8)} joined the group`,
          sentAt: relayTimestampToIso(env.created_date as string | undefined),
        });
      }
      await burnEnvelope(id, 'intro');
      continue;
    }

    // Play UGC: sealed reports open only on the phone they're addressed to (the
    // forum founder's); everyone else consumes them. Removal posts act on the
    // forum members' path (pollLoungeInbox) and are never shown as text here.
    if (isForumReportText(out.text)) {
      // Batch E (F-2): only the pinned forum, only on the pinned founder's phone —
      // in any other group a "report" is just a member's text and is dropped.
      // N3-2: a capped number of opens (one ML-KEM decapsulation each).
      if (!isPinnedForumFounder(opts.groupToken, opts.identity.veilId, opts.identity.ikPubB64)) continue;
      // Batch F (round-4 review R4-2-02): cheap checks first (blocked sender, not
      // addressed to me), then QUEUE — opened after the loop within the caps, so
      // junk can't use up the budget and over-cap reports wait instead of vanishing
      const reporter = tagToVeilId[String(header.sid)] ?? null;
      if (reporter && opts.isBlocked?.(reporter)) continue;
      if (!reportAddressedTo(out.text, opts.identity.veilId)) continue;
      const droppedForRoom = await enqueueReport(deps.storage, opts.groupToken, { id, reporter, text: out.text, sentAt: relayTimestampToIso(env.created_date as string | undefined) })
        .catch((e) => {
          console.log('[veil-group] report not queued:', String((e as Error)?.message ?? e));
          // Batch H (round-6 review R6-2-02): the founder is told, not only the log
          opts.events.onSystem({ envelopeId: `reportlost_${id}`, note: 'A report could not be stored on this phone (its storage refused it). Free up some space; the tester can send it again.', sentAt: new Date().toISOString() });
          return 0;
        });
      // Batch G (NF-2): the founder is told when a flood pushed out queued reports
      if (droppedForRoom > 0 && !reportsDroppedNoted) {
        reportsDroppedNoted = true;
        opts.events.onSystem({ envelopeId: `reportsdropped_${id}`, note: 'Some older reports were dropped because one tester sent too many. Newer reports are kept.', sentAt: new Date().toISOString() });
      }
      continue;
    }
    if (parseRemoveText(out.text)) continue;

    // normal message (text or media — media rides as __veil_media JSON, same
    // shape as the 1:1 flow; the receiver loads/decrypts the blob by uri)
    let media: { uri: string; k: string; iv: string; mime: string; name: string; size: number; dl?: boolean } | undefined;
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
    await burnEnvelope(id, 'message');
    opts.events.onMessage({
      envelopeId: id,
      text,
      senderTag: String(header.sid),
      senderVeilId: tagToVeilId[String(header.sid)] ?? null,
      senderNick: tagToNick[String(header.sid)] ?? null,
      senderVerified: out.senderVerified,
      sentAt: relayTimestampToIso(env.created_date as string | undefined),
      media,
      expiresAt,
    });
  }

  // b92 F10/F11: persist the per-group cursor + known ledger (survives
  // restarts; capped like every other ledger).
  rec.syncSkip = opts.peekOnly ? startSkip : envelopes.length >= GROUP_PAGE
    ? Math.max(0, startSkip + envelopes.length - GROUP_MARGIN)
    : startSkip;
  // Batch F (R4-2-02): open queued reports within the per-sender and per-forum caps
  if (!opts.peekOnly && isPinnedForumFounder(opts.groupToken, opts.identity.veilId, opts.identity.ikPubB64) && opts.blockListReady?.() !== false) {
    const drained = await drainReportQueue(deps.storage, opts.groupToken, async (it) => {
      const report = await openForumReport(opts.identity.pqPrivB64, opts.identity.veilId, opts.groupToken, it.text);
      if (report) opts.events.onReport?.({ envelopeId: it.id, reporterVeilId: it.reporter, report, sentAt: it.sentAt });
    }, Date.now(), (v) => !!opts.isBlocked?.(v)).catch((e) => { console.log('[veil-group] report queue not drained:', String((e as Error)?.message ?? e)); return null; });
    // Batch H (round-6 review R6-2-02): the founder sees how many reports wait their turn
    if (drained && drained.waiting > 0) {
      opts.events.onSystem({ envelopeId: `reportswaiting_${opts.groupToken}_${drained.waiting}`, note: drained.waiting === 1 ? '1 report is waiting and opens on a later check.' : `${drained.waiting} reports waiting; they open on later checks.`, sentAt: new Date().toISOString() });
    }
  }
  // Batch G (R5-2-03): the known ids are a fast path (replays are refused anyway);
  // 300 keeps the record well under the Keychain's size cliff
  rec.knownEnvIds = Array.from(persistedKnown).slice(-300);
  if (groupRecordBytes(rec) > 40_000) console.log('[veil-group] large group record', { group: opts.groupToken.slice(0, 6), bytes: groupRecordBytes(rec) });
  for (const m of members) m.nick = tagToNick[m.tag] ?? '';
  rec.nicks = { ...tagToNick };
  try { await saveGroupRecord(deps.storage, rec); } catch { /* nickname persistence best-effort */ }
  // Batch C (A1): the creator publishes the signed member list after any admission
  if (membersChanged && rec.role === 'creator' && opts.clientId && !opts.peekOnly) {
    await publishMemberList(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId })
      .then(async () => { if (rec.memberListDirty) { rec.memberListDirty = undefined; await saveGroupRecord(deps.storage, rec); } })
      .catch((e) => console.error('[veil-group] member list publish failed — retried on the next admission or rotation', String((e as Error)?.message ?? e)));
  }
  // Batch C (A1): a member the creator hasn't admitted yet re-sends its
  // seat-proven intro (at most every 10 minutes) in case the first one was lost
  if (rec.role === 'member' && rec.seatToken && rec.seatProof && opts.clientId && !opts.peekOnly
      && !(rec.memberList ?? {})[rec.ikPubB64] && Date.now() - Number(rec.introSentAt ?? 0) > 10 * 60_000) {
    rec.introSentAt = Date.now();
    // Batch H (round-6 review R6-2-07): a refused save must not end the poll pass here
    await saveGroupRecord(deps.storage, rec).catch((e) => console.log('[veil-group] intro time not saved:', String((e as Error)?.message ?? e)));
    await submitGroupEnvelope(deps, {
      groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId,
      text: await buildIntroPayload(opts.identity, rec.myNick ?? '', { token: rec.seatToken, proof: rec.seatProof }),
    }).catch((e) => console.error('[veil-group] intro re-send failed', String((e as Error)?.message ?? e)));
  }
  // Batch C (A3): an unfinished rotation or eviction is finished on the next opportunity
  // Batch G (round-5 review R5-2-08): the forum never rotates, so a pending rotation or
  // eviction left by an older build could never clear and blocked every forum send
  if (rec.openMembership && (rec.pendingRotation || rec.evictionPendingAt !== undefined)) {
    rec.pendingRotation = undefined; rec.evictionPendingAt = undefined;
    await saveGroupRecord(deps.storage, rec).catch(() => undefined);
  }
  if (rec.role === 'creator' && !rec.openMembership && (rec.pendingRotation || rec.evictionPendingAt !== undefined)) needsRotation = true;
  // Batch C (A3): the creator answers missing-wrap requests (at most once a minute per group)
  if (rec.role === 'creator' && !rec.openMembership && !opts.peekOnly) {
    await serviceWrapRequests(deps, rec, opts.sessionToken).catch((e) => console.error('[veil-group] wrap requests not served', String((e as Error)?.message ?? e)));
  }
  // b54: still behind AFTER every rekey in this pass was applied → genuinely
  // missed a rotation. Batch C (A3): first collect a wrap the creator delivered
  // through the gate, otherwise ask for one; surface "behind" only if still behind.
  let epochNow = groupRecord(deps.storage, opts.groupToken)?.epoch ?? rec.epoch;
  if (behindEpoch > epochNow && rec.role === 'member' && !opts.peekOnly) {
    const applied = await recoverMissingWrap(deps, rec, opts.sessionToken, opts.identity).catch((e) => {
      console.error('[veil-group] missing-wrap recovery failed', String((e as Error)?.message ?? e));
      return false;
    });
    if (applied) {
      epochNow = groupRecord(deps.storage, opts.groupToken)?.epoch ?? epochNow;
      opts.events.onRotated(epochNow);
    }
  }
  if (behindEpoch > epochNow) opts.events.onEpochBehind?.({ groupToken: opts.groupToken, behindEpoch, localEpoch: epochNow });
  const legacyRosterToConfirm = rec.role === 'creator' && rec.legacyRoster
    ? Object.entries(rec.legacyRoster).filter(([ik]) => !(rec.evictedIks ?? []).includes(ik)).map(([ikPub, veilId]) => ({ veilId, ikPub }))
    : [];
  return { tagToVeilId, tagToNick, members, fingerprint, needsRotation, ...(legacyRosterToConfirm.length ? { legacyRosterToConfirm } : {}) };
}

// ---------- send / receipts ----------

export async function sendGroupMessage(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string; text: string; cover?: boolean },
): Promise<{ senderTag: string }> {
  const r = await submitGroupEnvelope(deps, opts);
  return { senderTag: r.senderTag };
}

/** web parity: group read receipts are {__veil_receipt:1, ids, read?} through
 *  the encrypted group channel. */
export async function sendGroupReceipt(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string; ids: string[]; read: boolean },
): Promise<void> {
  if (!opts.ids.length) return;
  const body = opts.read
    ? JSON.stringify({ __veil_receipt: 1, ids: opts.ids.slice(0, 20), read: true })
    : JSON.stringify({ __veil_receipt: 1, ids: opts.ids.slice(0, 20) });
  await submitGroupEnvelope(deps, { ...opts, text: body, cover: false });
}

// ---------- media (web parity: __veil_media JSON through the group channel) ----------

export async function sendGroupMediaMessage(
  deps: GroupSessionDeps,
  opts: {
    groupToken: string; sessionToken: string; clientId: string;
    media: { bytes: Uint8Array; name?: string; mime?: string; size?: number; dl?: boolean };
    localUri?: string;
    uploadCiphertext?: (ciphertext: Uint8Array) => Promise<string>;
  },
): Promise<{ id: string; media: { uri: string; k: string; iv: string; mime: string; name: string; size: number; dl: boolean; localUri?: string } }> {
  const size = opts.media.size ?? opts.media.bytes.byteLength;
  const { ciphertext, keyB64, ivB64 } = await encryptMedia(opts.media.bytes);
  const fileUri = opts.uploadCiphertext
    ? await opts.uploadCiphertext(ciphertext)
    : await deps.relay.uploadPrivateFile({ bytes: ciphertext, name: 'veil-media' });
  const f: Record<string, unknown> = { name: opts.media.name || 'media', mime: opts.media.mime || 'application/octet-stream', size };
  if (opts.media.dl) f.dl = 1;
  const body = JSON.stringify({ __veil_media: 1, uri: fileUri, k: keyB64, iv: ivB64, ...f });
  await submitGroupEnvelope(deps, {
    groupToken: opts.groupToken, sessionToken: opts.sessionToken,
    clientId: opts.clientId, text: body, cover: false,
  });
  // note: media_uri rides on the envelope record server-side; the group
  // receiver reads it from the entity row like the web does.
  return {
    id: `local_${Date.now()}_${Math.floor(Math.random() * 1e6)}`,
    media: { uri: fileUri, k: keyB64, iv: ivB64, mime: String(f.mime), name: String(f.name), size, dl: !!opts.media.dl, localUri: opts.localUri },
  };
}

// ---------- rotate / evict (creator) ----------

/** Batch C (A3): one rotation at a time per group, in this process. */
const rotationLocks = new Map<string, Promise<unknown>>();
function withRotationLock<T>(groupToken: string, fn: () => Promise<T>): Promise<T> {
  const prev = rotationLocks.get(groupToken) ?? Promise.resolve();
  const run = prev.catch(() => undefined).then(fn);
  rotationLocks.set(groupToken, run.catch(() => undefined));
  return run;
}

/** Batch C (A3): test hook — throw after the named step to prove a retry converges. */
export const rotationCrashHook: { at: string | null } = { at: null };
function crashPoint(step: string): void {
  if (rotationCrashHook.at === step) { rotationCrashHook.at = null; throw new Error(`[test] crash after ${step}`); }
}

async function mainWriteSecret(deps: GroupSessionDeps, sessionToken: string): Promise<string | null> {
  return (await deps.sessions.load(sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null;
}

/** Batch C (A3): build a rotation; the caller persists it BEFORE anything is sent. */
async function prepareRotation(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string): Promise<PendingRotation> {
  // Batch C (A1): wrap ONLY to members the creator admitted (one IK per seat it
  // minted), minus the local deny list — the relay roster is not consulted.
  // The forum (openMembership) wraps to its attestation-verified roster.
  let trusted = await trustedMembers(rec);
  if (!trusted) {
    trusted = {};
    const roster = (await gateRoster(deps, { groupToken: rec.groupToken, sessionToken })).members;
    for (const m of await verifiedRosterRows(rec, roster.map((r) => (r ?? {}) as Record<string, unknown>))) trusted[String(m.IK_pub)] = String(m.veil_id);
  }
  const targets = Object.entries(trusted).filter(([ik]) => ik !== rec.ikPubB64);
  const newGek = toB64(randomBytes(32));
  const wraps: GroupRekeyWrap[] = [];
  const recipients: string[] = [];
  const skipped: string[] = [];
  for (const [ik, veilId] of targets) {
    let pqPub = '';
    let pqSig = '';
    let lookupIk = '';
    try {
      const d = (await deps.relay.invoke('veilIdentityGate', { action: 'lookup', veil_id: veilId })).data as { IK_pub?: string; pq_pub?: string; pq_sig?: string };
      pqPub = String(d?.pq_pub ?? '');
      pqSig = String(d?.pq_sig ?? '');
      lookupIk = String(d?.IK_pub ?? '');
    } catch { /* lookup failure handled below */ }
    // b54 (Batch A, H-1): the PQ prekey must be signed by the SAME IK the
    // creator admitted — a substituted key would hand the relay the wrap.
    // Batch D (D-06, RV-05): a member without one is SKIPPED, not a veto — a relay
    // serving one bad prekey could otherwise stall every rotation (and with it an
    // eviction) for ever. They stay trusted and recover the key through the
    // missing-wrap request once their prekey checks out.
    if (!pqPub || lookupIk !== ik || !(await verifyPqPrekeySig(ik, pqPub, pqSig).catch(() => false))) {
      console.warn('[veil-group] rotation skips a member without a valid signed prekey', { veilId });
      skipped.push(veilId);
      continue;
    }
    wraps.push(await buildRekeyWrap(pqPub, veilId, newGek));
    recipients.push(ik);
  }
  const pq = await mlkemKeypair();
  const epoch = rec.epoch + 1;
  const rid = hexRand(16);
  const kc = await gekCommitment(rec.groupToken, epoch, newGek);
  // b54: sent in parts of REKEY_WRAPS_PER_PART wraps, each signed on its own.
  // Batch C (A3): every part names the rotation, its key commitment and i of n.
  const chunks = wraps.length
    ? Array.from({ length: Math.ceil(wraps.length / REKEY_WRAPS_PER_PART) }, (_, i) => wraps.slice(i * REKEY_WRAPS_PER_PART, (i + 1) * REKEY_WRAPS_PER_PART))
    : [[]];
  const parts: string[] = [];
  for (let i = 0; i < chunks.length; i++) {
    parts.push(await buildSignedRekeyText(rec.ikSeedB64, rec.groupToken, epoch, pq.pub, chunks[i], { rid, kc, pi: i, pc: chunks.length }));
  }
  return { epoch, gekB64: newGek, pqPubB64: pq.pub, rid, parts, sent: [], recipients, skipped };
}

/**
 * Batch D (D-05, RV-04): a rotation prepared before an eviction may wrap the new
 * key to the member being removed. If none of its parts went out, it is thrown
 * away and a fresh one is prepared. (If some did, the key may already be with
 * them: it is finished, and rotateGroup runs one more rotation past it while
 * the creator's sends stay blocked.)
 */
function dropTaintedRotation(rec: GroupRecord): void {
  const p = rec.pendingRotation;
  if (!p || p.sent.length > 0) return;
  const denied = new Set(rec.evictedIks ?? []);
  if (p.recipients.some((ik) => denied.has(ik))) {
    console.log('[veil-group] discarded an unsent rotation that wrapped to a removed member', { groupToken: rec.groupToken.slice(0, 6), epoch: p.epoch });
    rec.pendingRotation = undefined;
  }
}

/**
 * Batch C (A3): durable rotation. The new key, epoch and signed parts are saved
 * BEFORE the first send; a retry (after a crash, a network error, or a relay
 * refusal) resends the SAME parts, so a group can never split into two keys for
 * one epoch. Parts already accepted are not resent. Serialised per group.
 * If an eviction is pending and the finished rotation still wrapped to an
 * evicted IK (it was prepared before the eviction), one more rotation runs.
 */
export async function rotateGroup(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string },
): Promise<number> {
  return withRotationLock(opts.groupToken, async () => {
    let epoch = await rotateOnce(deps, opts);
    const rec = groupRecord(deps.storage, opts.groupToken);
    if (rec && rec.evictionPendingAt !== undefined) {
      const denied = new Set(rec.evictedIks ?? []);
      if ((rec.lastRotationRecipients ?? []).some((ik) => denied.has(ik))) epoch = await rotateOnce(deps, opts);
      const after = groupRecord(deps.storage, opts.groupToken)!;
      if (!(after.lastRotationRecipients ?? []).some((ik) => denied.has(ik))) {
        after.evictionPendingAt = undefined;
        await saveGroupRecord(deps.storage, after);
      }
    }
    return epoch;
  });
}

async function rotateOnce(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string },
): Promise<number> {
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the group creator can rotate the keys.');
  // Batch F (round-4 review R4-2-01): never for the forum. Forum members don't apply
  // rekeys and the relay refuses posts off the current epoch, so a rotation breaks
  // the forum for everyone; the forum changes keys only by a new descriptor.
  if (rec.openMembership || isPinnedForumToken(opts.groupToken)) throw new Error('The forum’s keys can’t be changed from the app. To deal with a member, block them and remove their posts.');

  dropTaintedRotation(rec);
  let pending: PendingRotation;
  if (rec.pendingRotation && rec.pendingRotation.epoch === rec.epoch + 1) {
    pending = rec.pendingRotation;
  } else {
    pending = await prepareRotation(deps, rec, opts.sessionToken);
    rec.pendingRotation = pending;
  }
  // Batch D (D-07, RV-06): persist-before-send is checked, not assumed — the
  // save throws on a storage error, and the copy ON DISK must hold this rotation
  await saveGroupRecord(deps.storage, rec);
  if ((await readPersistedGroupRecord(deps.storage, opts.groupToken))?.pendingRotation?.rid !== pending.rid) {
    throw new Error('The new group keys could not be saved on this device, so nothing was sent. Try again in a moment.');
  }
  crashPoint('persist');

  for (let i = 0; i < pending.parts.length; i++) {
    if (pending.sent.includes(i)) continue;
    await sendGroupMessage(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, text: pending.parts[i] });
    pending.sent = [...pending.sent, i];
    rec.pendingRotation = pending;
    await saveGroupRecord(deps.storage, rec);
    crashPoint(`part-${i}`);
  }

  let refusal: string | null = null;
  try {
    const res = await deps.relay.invoke('veilGroupGate', {
      action: 'rotate',
      group_token: opts.groupToken,
      session_token: opts.sessionToken,
      write_secret: await mainWriteSecret(deps, opts.sessionToken),
      new_epoch: pending.epoch,
      group_pq_pub: pending.pqPubB64,
    }) as { status?: number; data?: { error?: string } };
    if ((res?.status ?? 200) >= 400 || res?.data?.error) refusal = String(res?.data?.error ?? res?.status);
  } catch (e) { refusal = String((e as Error)?.message ?? e); }
  if (refusal !== null) {
    // a retry after the relay already moved (crash after the relay step): its epoch tells us
    const roster = await gateRoster(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken }).catch(() => null);
    if (roster?.epoch !== pending.epoch) throw new Error(`Rotation refused by the relay: ${refusal}`);
  }
  crashPoint('relay');

  await advanceEpoch(deps.storage, opts.groupToken, pending.epoch, pending.gekB64, pending.pqPubB64);
  const done = groupRecord(deps.storage, opts.groupToken)!;
  done.lastRotationRecipients = pending.recipients;
  done.lastRotationSkipped = pending.skipped ?? [];
  done.pendingRotation = undefined;
  await saveGroupRecord(deps.storage, done);
  // Batch C (A1): a fresh signed member list in the new epoch
  await publishMemberList(deps, opts).catch((e) => console.error('[veil-group] member list publish after rotation failed', String((e as Error)?.message ?? e)));
  return pending.epoch;
}

// ---------- Batch C (A3): missing-wrap requests through the gate ----------

const WRAP_REQUEST_LABEL = 'vardum-wrap-request-v1';
const wrapServiceAt = new Map<string, number>();
/** test knob: how often the creator checks for wrap requests */
export const wrapServiceTiming = { intervalMs: 60_000 };

function gateBody(r: unknown): Record<string, unknown> {
  const d = ((r as { data?: unknown })?.data ?? {}) as Record<string, unknown>;
  return ((d.data && typeof d.data === 'object') ? d.data : d) as Record<string, unknown>;
}

/**
 * Member: this device missed a rotation (the relay refuses envelopes off the
 * current epoch, so it cannot ask in the group). Collect a wrap the creator
 * delivered through the gate; otherwise file a request signed with this
 * device's IK (at most every 10 minutes). A delivered wrap is a normal
 * creator-signed rekey: applyRekeyPayload checks the creator signature, the
 * group, forward-only epoch and the key commitment, exactly as in-group.
 */
async function recoverMissingWrap(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string, identity: GroupIdentity): Promise<boolean> {
  const ws = await mainWriteSecret(deps, sessionToken);
  const fetched = gateBody(await deps.relay.invoke('veilGroupGate', { action: 'wrap_fetch', group_token: rec.groupToken, session_token: sessionToken, write_secret: ws, IK_pub: rec.ikPubB64 }));
  if (typeof fetched.payload === 'string' && fetched.payload) {
    const p = parseRekeyPayload(fetched.payload);
    if (p && p !== 'invalid' && await applyRekeyPayload(deps.storage, rec.groupToken, p, identity.pqPrivB64)) {
      console.log('[veil-group] missing wrap recovered through the gate', { groupToken: rec.groupToken.slice(0, 6), epoch: p.ge });
      return true;
    }
  }
  const live = groupRecord(deps.storage, rec.groupToken) ?? rec;
  if (Date.now() - Number(live.wrapRequestedAt ?? 0) < 10 * 60_000) return false;
  const msg = JSON.stringify({ v: WRAP_REQUEST_LABEL, group_token: rec.groupToken, veil_id: rec.veilId, IK_pub: rec.ikPubB64, have_epoch: live.epoch });
  await deps.relay.invoke('veilGroupGate', {
    action: 'wrap_request', group_token: rec.groupToken, session_token: sessionToken, write_secret: ws,
    veil_id: rec.veilId, IK_pub: rec.ikPubB64, have_epoch: live.epoch, sig: await ikSign(rec.ikSeedB64, toB64(utf8(msg))),
  });
  live.wrapRequestedAt = Date.now();
  await saveGroupRecord(deps.storage, live);
  console.log('[veil-group] asked the creator for a missing wrap', { groupToken: rec.groupToken.slice(0, 6), haveEpoch: live.epoch });
  return false;
}

/**
 * Creator: answer missing-wrap requests. Only for identities this creator
 * admitted (and has not evicted), whose request is signed by that IK, who are
 * behind, and whose published PQ prekey is signed by the same IK. The answer
 * is a creator-signed rekey for the CURRENT epoch carrying one wrap.
 */
async function serviceWrapRequests(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string): Promise<number> {
  if (Date.now() - (wrapServiceAt.get(rec.groupToken) ?? 0) < wrapServiceTiming.intervalMs) return 0;
  wrapServiceAt.set(rec.groupToken, Date.now());
  const ws = await mainWriteSecret(deps, sessionToken);
  const listed = gateBody(await deps.relay.invoke('veilGroupGate', { action: 'wrap_requests', group_token: rec.groupToken, session_token: sessionToken, write_secret: ws }));
  const requests = Array.isArray(listed.requests) ? listed.requests as Record<string, unknown>[] : [];
  const trusted = (await trustedMembers(rec)) ?? {};
  let served = 0;
  for (const r of requests) {
    const ik = String(r.IK_pub ?? ''), vid = String(r.veil_id ?? ''), have = Number(r.have_epoch), sig = String(r.sig ?? '');
    if (!ik || trusted[ik] !== vid || ik === rec.ikPubB64 || !Number.isInteger(have) || have >= rec.epoch) continue;
    const msg = JSON.stringify({ v: WRAP_REQUEST_LABEL, group_token: rec.groupToken, veil_id: vid, IK_pub: ik, have_epoch: have });
    if (!(await verifyWithIk(ik, toB64(utf8(msg)), sig).catch(() => false))) continue;
    const d = gateBody(await deps.relay.invoke('veilIdentityGate', { action: 'lookup', veil_id: vid }).catch(() => null));
    const pqPub = String(d.pq_pub ?? ''), pqSig = String(d.pq_sig ?? '');
    if (String(d.IK_pub ?? '') !== ik || !pqPub || !(await verifyPqPrekeySig(ik, pqPub, pqSig))) continue;
    const wrap = await buildRekeyWrap(pqPub, vid, rec.gekB64);
    const text = await buildSignedRekeyText(rec.ikSeedB64, rec.groupToken, rec.epoch, rec.pqPubB64, [wrap], {
      rid: hexRand(16), kc: await gekCommitment(rec.groupToken, rec.epoch, rec.gekB64), pi: 0, pc: 1,
    });
    await deps.relay.invoke('veilGroupGate', { action: 'wrap_deliver', group_token: rec.groupToken, session_token: sessionToken, write_secret: ws, target_IK_pub: ik, payload: text });
    served += 1;
  }
  if (served) console.log('[veil-group] delivered missing wraps', { groupToken: rec.groupToken.slice(0, 6), served });
  return served;
}

/**
 * Batch E (round-3 review F-3): the creator's answer about a pre-Batch-C group's
 * old roster. The listed identity keys are admitted; everyone else stays pending
 * (they can still come in through a seat). Asked once either way; the signed
 * member list goes out on the next pass.
 */
export async function confirmLegacyRoster(store: VeilStorage, groupToken: string, confirmIks: string[]): Promise<number> {
  const rec = await loadGroupRecordStrict(store, groupToken);
  if (!rec || rec.role !== 'creator' || !rec.legacyRoster) return 0;
  const held = rec.legacyRoster;
  let n = 0;
  rec.admitted = { ...(rec.admitted ?? {}) };
  for (const ik of confirmIks) {
    if (held[ik] && !(rec.evictedIks ?? []).includes(ik)) { rec.admitted[ik] = held[ik]; n += 1; }
  }
  rec.legacyRoster = undefined;
  rec.memberListDirty = true;
  await saveGroupRecord(store, rec);
  return n;
}

/** Batch C (A1): creator — send the signed member list (admitted minus denied). */
export async function publishMemberList(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string },
): Promise<number> {
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec || rec.role !== 'creator') throw new Error('Only the group creator can publish the member list.');
  if (rec.openMembership) return rec.memberSeq ?? 0; // the forum has no signed list
  const trusted = (await trustedMembers(rec)) ?? {};
  const seq = (rec.memberSeq ?? 0) + 1;
  const members = Object.entries(trusted).filter(([ik]) => ik !== rec.ikPubB64) as Array<[string, string]>;
  await sendGroupMessage(deps, { ...opts, text: await buildSignedMembersText(rec.ikSeedB64, opts.groupToken, seq, members) });
  rec.memberSeq = seq;
  await saveGroupRecord(deps.storage, rec);
  return seq;
}

/**
 * Batch C (A1): creator — admit a roster identity ONLY if its signed intro
 * proves possession of a seat this device minted (HMAC with the seat key, which
 * derives from the link secret the relay never sees). One IK per seat; a locked
 * seat admits only its invitee. Read-only on the envelope: nothing is consumed
 * unless the admission succeeds. Returns the admitted veil_id, or null.
 */
async function admitFromIntro(
  store: VeilStorage, rec: GroupRecord,
  e: { ik: string; veilId: string; headerStr: string; ciphertextB64: string; ivB64: string },
): Promise<string | null> {
  if (!e.veilId || (rec.evictedIks ?? []).includes(e.ik)) return null;
  if (!(await verifyGroupEnvelopeSig(e.ik, e.headerStr, e.ciphertextB64, e.ivB64))) return null;
  let text = '';
  try { text = (await decryptOwnGroupEnvelope(store, rec.groupToken, e.headerStr, e.ciphertextB64, e.ivB64)).text; } catch { return null; }
  const parsed = parseGroupIntro(text);
  const intro = parsed ? await verifyGroupIntro(parsed) : null;
  if (!intro || intro.ikPub !== e.ik || intro.veilId !== e.veilId || !intro.seat || !intro.sp) return null;
  // Batch D (D-08, RV-32): own properties only ("__proto__" is not a seat)
  if (!rec.seats || !Object.prototype.hasOwnProperty.call(rec.seats, intro.seat)) return null;
  const seat = rec.seats[intro.seat];
  if (!seat || typeof seat.key !== 'string' || !seat.key) return null;
  if (seat.invitee && seat.invitee !== e.veilId) return null;
  if (seat.usedBy && seat.usedBy !== e.ik) return null;
  const expected = await seatProof(seat.key, rec.groupToken, intro.seat, e.veilId, e.ik);
  if (!ctEqStr(expected, intro.sp)) return null;
  rec.seats = { ...(rec.seats ?? {}), [intro.seat]: { ...seat, usedBy: e.ik } };
  rec.admitted = { ...(rec.admitted ?? {}), [e.ik]: e.veilId };
  if (intro.nick) rec.nicks = { ...(rec.nicks ?? {}), [await senderTag(rec.groupToken, rec.epoch, e.veilId)]: intro.nick };
  await saveGroupRecord(store, rec);
  return e.veilId;
}

function ctEqStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/**
 * Remove a member. Batch C (A3): eviction and rotation are ONE operation —
 * the IK goes on the local deny list, the CREATOR's normal sends are blocked
 * (evictionPendingAt), the relay deny entry is written, then the rotation
 * runs. If the rotation fails, the creator's sends stay blocked and the next
 * poll (or a manual rotate) finishes it. Other members get no signal from
 * this device: until the rotation reaches them they keep sending on the old
 * key, which the removed member holds. Batch D (D-06) bounds that: a member
 * with a valid prekey can't veto the rotation, and members stop sending on a
 * key older than MEMBER_EPOCH_MAX_MS.
 */
export async function evictGroupMember(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; target: { veilId: string; ikPub: string }; clientId?: string },
): Promise<number | null> {
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the group creator can remove members.');
  // Batch F (round-4 review R4-2-01): never for the forum. Forum members don't apply
  // rekeys and the relay refuses posts off the current epoch, so a rotation breaks
  // the forum for everyone; the forum changes keys only by a new descriptor.
  if (rec.openMembership || isPinnedForumToken(opts.groupToken)) throw new Error('The forum’s keys can’t be changed from the app. To deal with a member, block them and remove their posts.');
  // b54 (Batch A, H-3): record the eviction LOCALLY first — later rekeys never
  // wrap to this IK even if the relay re-inserts it into the roster.
  rec.evictedIks = [...new Set([...(rec.evictedIks ?? []), opts.target.ikPub])];
  rec.evictionPendingAt = rec.evictionPendingAt ?? rec.epoch;
  dropTaintedRotation(rec); // Batch D (D-05)
  await saveGroupRecord(deps.storage, rec);
  const deny_sig = await denySignature(rec.ikSeedB64, opts.groupToken, opts.target.ikPub, rec.epoch);
  await deps.relay.invoke('veilGroupGate', {
    action: 'evict',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: await mainWriteSecret(deps, opts.sessionToken),
    remover_IK_pub: rec.ikPubB64,
    target_IK_pub: opts.target.ikPub,
    target_veil_id: opts.target.veilId || '',
    deny_sig,
  });
  if (!opts.clientId) return null; // caller rotates (older call sites)
  return rotateGroup(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId });
}

/**
 * Batch G (round-5 review R5-3-01): take a member's seat away in the FORUM with no
 * key change. The relay's `evict` writes a creator-signed deny entry and removes
 * the member row and posting row; it changes no key (the rotation is a separate
 * call, which stays refused for the forum). Founder only, forum only.
 */
export async function removeForumMember(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; target: { veilId: string; ikPub: string } },
): Promise<void> {
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the forum founder can remove forum members.');
  if (!(rec.openMembership || isPinnedForumToken(opts.groupToken))) throw new Error('This is only for the forum.');
  const deny_sig = await denySignature(rec.ikSeedB64, opts.groupToken, opts.target.ikPub, rec.epoch);
  await deps.relay.invoke('veilGroupGate', {
    action: 'evict',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: await mainWriteSecret(deps, opts.sessionToken),
    remover_IK_pub: rec.ikPubB64,
    target_IK_pub: opts.target.ikPub,
    target_veil_id: opts.target.veilId || '',
    deny_sig,
  });
}

/**
 * Batch H (round-6 reviews R6-2-03 / R6-3-05): a forum removal now bars the
 * removed tester's ACCOUNT (a fresh Vardum ID on the same account used to walk
 * straight back in). The founder can lift that for a mistake. Founder only; no
 * key changes.
 */
export async function unbanForumMember(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; targetVeilId: string },
): Promise<void> {
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the forum founder can let a tester back in.');
  if (!(rec.openMembership || isPinnedForumToken(opts.groupToken))) throw new Error('This is only for the forum.');
  const sig = await ikSign(rec.ikSeedB64, toB64(utf8(JSON.stringify({ group_token: opts.groupToken, unban_veil_id: opts.targetVeilId }))));
  await deps.relay.invoke('veilGroupGate', {
    action: 'unban',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: await mainWriteSecret(deps, opts.sessionToken),
    remover_IK_pub: rec.ikPubB64,
    target_veil_id: opts.targetVeilId,
    unban_sig: sig,
  });
}

// ---------- exports for the App layer ----------

export {
  loadGroupRecords, loadGroupRecord, groupRecord, forgetGroup,
  exportGroupRecords, importGroupRecords,
  decryptGroupText, encryptGroupText, epochFingerprint, senderTag,
  groupNeedsRotation, type GroupRecord, type GroupRekeyPayload,
};

/** creator's main group session finder (web: initiator_client_id === me &&
 *  state active && !responder_client_id). */
export async function findMainGroupSession(
  deps: GroupSessionDeps, groupToken: string, clientId: string,
): Promise<string | null> {
  const raw = await deps.relay.sessionList(clientId);
  const d = raw.data as { data?: Record<string, unknown>[]; sessions?: Record<string, unknown>[] };
  const list = d?.data ?? d?.sessions ?? (raw.data as Record<string, unknown>[] ?? []);
  for (const r of list) {
    if (String(r.group_token ?? '') === groupToken
      && String(r.initiator_client_id ?? '') === clientId
      && String(r.state ?? '') === 'active'
      && !String(r.responder_client_id ?? '')) {
      return String(r.token ?? '');
    }
  }
  return null;
}

/** decrypt a group session row's name blob for display */
export async function groupRowLabel(
  deps: GroupSessionDeps, groupToken: string, nameBlob: string,
): Promise<string | null> {
  const rec = (await loadGroupRecord(deps.storage, groupToken)) ?? groupRecord(deps.storage, groupToken);
  if (!rec) return null;
  try {
    return await decryptGroupText(rec.nameGekB64 || rec.gekB64, nameBlob);
  } catch {
    return null;
  }
}

// re-export writeHashHex (used by callers composing group session records)
export { writeHashHex };

/** unused import guard: createSession/serialize kept for parity with the
 *  main-session ratchet the web stores (harmless, keeps sessions.load working) */
export async function ensureMainSessionRatchet(deps: GroupSessionDeps, token: string, writeSecret: string): Promise<void> {
  const existing = await deps.sessions.load(token);
  if (existing) return;
  const { state } = await createSession(token, toB64(randomBytes(32)), {}); // never joined: the link secret and dials are unused
  state.writeSecret = writeSecret;
  await deps.sessions.save(token, await serializeRatchetState(state));
}
