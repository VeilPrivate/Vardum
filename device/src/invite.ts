/**
 * @veil/device — Strict invite sessions (web parity, build 40).
 *
 * Web contract extracted from the live bundle (createSession qe / joinSession
 * tt / veilSessionGate create-peek-join):
 *
 * INITIATOR ("Create an invite link")
 *   token = xu(24)  (hex of 24 random bytes)
 *   myWrite = xu(32) (hex) — stored on-device as the ratchet state's writeSecret
 *   peerWrite = xu(32) — travels ONLY in the link fragment #w=
 *   createSession(token, '') → pending initiator ratchet (X25519 + ML-KEM pub)
 *   VeilSession.create {token, state:'pending', initiator_client_id, ...,
 *     initiator_pub_jwk, initiator_pq_pub, initiator_write_hash=sha256hex(myWrite),
 *     responder_write_hash=sha256hex(peerWrite), expires 24h,
 *     default_ttl_seconds, key_retention_hours, burn_after_open (BOOL, dial>0),
 *     expire_after_seconds}
 *   link = {origin}/?join={token}#w={encodeURIComponent(peerWrite)}
 *   — the initiator's existing pending loop (App advanceHandshake) completes
 *     the handshake when the responder joins: state active + responder fields.
 *
 * RESPONDER ("Join with an invite link")
 *   parse → { token, #w= }
 *   peek {action:'peek', token, write_secret:w} → session record
 *   validations: ended / active-and-not-mine / expired / missing initiator key
 *   joinSession(token, '', initiator_pub_jwk, initiator_pq_pub) → READY state
 *     + responder fields + fingerprint (writeSecret = w, the #w fragment)
 *   join {action:'join', token, write_secret:w, client_id, display_name,
 *     responder_pub_jwk, responder_ratchet_pub_jwk, responder_pq_ct, fingerprint}
 *   clobber check: record's responder fields must echo ours (VEIL-JOIN-CLOBBERED)
 */
import {
  randomBytes, utf8,
  createSession, joinSession, serializeRatchetState, clampDials, canonicalDials,
} from '../../crypto-core/src/index';
import type { DialsInput } from '../../crypto-core/src/ratchet';
import { sha256 } from '../../crypto-core/src/kdf';
import type { SessionStore } from './session-store';
import { saveOrThrow } from './save-strict';
import type { VeilRelay } from './relay';

export interface InviteDeps {
  sessions: SessionStore;
  relay: VeilRelay;
  /** web origin — the invite link opens the web app; VEIL native can paste it too */
  webBaseUrl: string;
}

export interface InviteDials {
  burnAfterOpen: boolean;
  expireAfterSeconds: number;
  keyRetentionHours: number;
  defaultTtlSeconds: number;
}

export interface CreatedInvite {
  token: string;
  link: string;
}

export interface JoinedInvite {
  token: string;
  fingerprint: string;
  alreadyJoined: boolean;
}

/** web xu(n): hex string of n random bytes */
function hexRand(nBytes: number): string {
  return Array.from(randomBytes(nBytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** web td(s): SHA-256 hex of the utf8 secret — the write_hash fields */
export async function writeHashHex(secret: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', utf8(secret) as unknown as BufferSource);
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Initiator: create the pending session, publish the record, return the link. */
export async function createInviteSession(
  deps: InviteDeps,
  opts: { clientId: string; dials: InviteDials; displayName?: string;
          /** group mode: bind the session to a group + encrypted name blob.
           *  activate=true creates the creator's MAIN group session (immediately
           *  active, no responder ever joins it) — web parity. */
          group?: { groupToken: string; groupNameBlob: string; activate?: boolean; epoch?: number; pqPubB64?: string; stampEpoch?: boolean;
                    /** b199: lock this seat to one person — the relay only lets
                     *  the account that owns this Veil ID peek or join it, so a
                     *  forwarded invite is useless to anyone else. */
                    inviteeVeilId?: string } },
): Promise<CreatedInvite> {
  const token = hexRand(24);
  const myWrite = hexRand(32);
  const peerWrite = hexRand(32);

  // b54 (Batch A): the link secret k travels ONLY in the link fragment and is
  // mixed into the handshake root — a relay without the link cannot sit in
  // the middle of this session at all (the fingerprint stays the second line).
  const linkSecret = hexRand(32);
  // Batch C (V-12): clamped dials — the SAME values go on the row, into the
  // sealed state, and into the fingerprint (the joiner binds the row's copy).
  const dials = clampDials(opts.dials);
  const { state, initiatorPub, initiatorPqPub } = await createSession(token, linkSecret, dials);
  state.writeSecret = myWrite;
  // b188-r5 (owner repro: forum joined fine, then "No posting session for
  // this forum on this device" on first send): KeychainStorage.set swallows
  // write errors and returns false, and the old code IGNORED that — a silent
  // keychain failure left a record pointing at a session that never persisted.
  // Fail the join HONESTLY instead of leaving a dangling posting session.
  // b193: the CREATE path must persist the dials too — the join path always
  // has (7200/86400 fallbacks there); without them every send off a
  // created session falls back to ttl 86400, which is why forum posts were
  // +24h envelopes even after the relay honored 30-day sessions.
  const saved = await deps.sessions.save(token, {
    ...(await serializeRatchetState(state)),
    burnAfterOpen: dials.burnAfterOpen,
    defaultTtlSeconds: dials.defaultTtlSeconds,
    expireAfterSeconds: dials.expireAfterSeconds,
  } as never);
  if (!saved) throw new Error('Secure storage refused this session — join aborted, nothing half-saved. Try again.');

  await deps.relay.entityCreate('VeilSession', {
    token,
    state: 'pending',
    initiator_client_id: opts.clientId,
    responder_client_id: '',
    initiator_display_name: opts.displayName ?? '',
    responder_display_name: '',
    passphrase_required: false,
    session_fingerprint: '',
    initiator_pub_jwk: initiatorPub,
    initiator_pq_pub: initiatorPqPub,
    initiator_write_hash: await writeHashHex(myWrite),
    responder_write_hash: await writeHashHex(peerWrite),
    initiator_verified: false,
    responder_verified: false,
    // b192: session lifetime comes from the DIALS, not a hard-coded 24h — the
    // relay stores the declared expiry (hard 30-day ceiling). Regular invites
    // dial expireAfterSeconds 86400 so behavior is unchanged there; forum
    // posting sessions dial 2592000 and now actually get their 30 days.
    expires_at: new Date(Date.now() + (dials.expireAfterSeconds || 86400) * 1000).toISOString(),
    default_ttl_seconds: dials.defaultTtlSeconds,
    key_retention_hours: dials.keyRetentionHours,
    burn_after_open: dials.burnAfterOpen,
    // b197-r8l (TWO-DIAL SYNCHRONIZED MODEL): expire_after_seconds is the
    // founder-programmable unopened-message deletion horizon (12/24/36/48 h).
    expire_after_seconds: dials.expireAfterSeconds,
    last_activity: new Date().toISOString(),
    ...(opts.group
      ? {
          group_token: opts.group.groupToken,
          group_name: opts.group.groupNameBlob,
          // b188-r8 (owner repro: "Epoch does not match the group epoch"):
          // FORUM POSTING sessions must carry their group's epoch — the relay
          // gate compares the envelope header's ge against this row. Creator /
          // member join rows must NOT pre-stamp it: the gate's rotate action
          // requires new_epoch == current + 1, and pre-stamping the main row
          // makes the group-creation rotate fail with HTTP 400. Hence the
          // explicit stampEpoch flag (only the forum join path sets it).
          ...(opts.group.stampEpoch ? { group_epoch: opts.group.epoch ?? 0 } : {}),
          ...(opts.group.inviteeVeilId ? { invitee_veil_id: opts.group.inviteeVeilId } : {}),
        }
      : {}),
  });

  // web parity: the group MAIN session is activated THROUGH the gate (the
  // web client never writes state:'active' on the entity row itself).
  if (opts.group?.activate) {
    await deps.relay.sessionActivate(token, myWrite);
  }

  const base = deps.webBaseUrl.replace(/\/$/, '');
  // Batch F (round-4 reviews R4-1-01 / R4-4-05): the creator's dials ride in the
  // fragment next to k, so the joiner never has to take the relay's copy
  return { token, link: `${base}/?join=${token}#w=${encodeURIComponent(peerWrite)}&k=${linkSecret}&d=${linkDials(dials)}` };
}

/** Parse an invite link (web URL or pasted text). b54 links carry
 *  #w=<write secret>&k=<link secret>; group invites additionally carry
 *  &g=<group GEK b64>&e=<epoch>&c=<creator IK b64>; from b56 (Batch D, D-03)
 *  also &t=<group token>&ph=<groupLinkBinding hex>. */
/** Batch F (R4-1-01): the dials as they travel in a link: ttl.expire.retention.burn */
export function linkDials(d: Partial<DialsInput>): string {
  const c = clampDials(d);
  return `${c.defaultTtlSeconds}.${c.expireAfterSeconds}.${c.keyRetentionHours}.${c.burnAfterOpen ? 1 : 0}`;
}

/** Batch F (R4-1-01): the longest burn window the app offers (24 h). A session
 *  whose dials came from the relay (an older link without d=) is never purged
 *  locally faster than this, so the relay can only lengthen its burn window. */
export const PEEK_DIALS_BURN_FLOOR_SECONDS = 86400;

export function parseInviteLink(link: string): { token: string; writeSecret: string; linkSecret?: string; creatorIk?: string; gek?: string; epoch?: number; groupToken?: string; groupBind?: string; dials?: DialsInput } {
  const t = link.match(/[?&]join=([^&#\s]+)/i);
  const w = link.match(/[#&?]w=([^&#\s]+)/i);
  // b54: k = invite link secret (64 hex, fragment only); c = group creator IK
  const k = link.match(/[#&]k=([0-9a-f]{64})(?=[&#\s]|$)/i);
  const c = link.match(/[#&]c=([^&#\s]+)/i);
  if (!t || !w) throw new Error('That is not a Vardum invite link — ask your peer for a fresh one.');
  const g = link.match(/[?&]g=([^&#\s]+)/i);
  const e = link.match(/[?&]e=(\d+)/i);
  const gt = link.match(/[#&]t=([0-9a-f]{16,64})(?=[&#\s]|$)/i);
  const ph = link.match(/[#&]ph=([0-9a-f]{64})(?=[&#\s]|$)/i);
  const d = link.match(/[#&]d=(\d+)\.(\d+)\.(\d+)\.([01])(?=[&#\s]|$)/);
  return {
    token: decodeURIComponent(t[1]),
    writeSecret: decodeURIComponent(w[1]),
    linkSecret: k ? k[1].toLowerCase() : undefined,
    creatorIk: c ? decodeURIComponent(c[1]) : undefined,
    gek: g ? decodeURIComponent(g[1]) : undefined,
    epoch: e ? Number(e[1]) : undefined,
    groupToken: gt ? gt[1].toLowerCase() : undefined,
    groupBind: ph ? ph[1].toLowerCase() : undefined,
    dials: d ? clampDials({ defaultTtlSeconds: Number(d[1]), expireAfterSeconds: Number(d[2]), keyRetentionHours: Number(d[3]), burnAfterOpen: d[4] === '1' }) : undefined,
  };
}

/** Responder: join a session from an invite link. READY on return. */
export async function joinInviteSession(
  deps: InviteDeps,
  opts: { link: string; clientId: string; displayName?: string },
): Promise<JoinedInvite> {
  const { token, writeSecret, linkSecret, dials: linkDialsIn } = parseInviteLink(opts.link);
  if (!linkSecret) throw new Error('This invite link is from an older version of Vardum. Ask for a fresh link.');

  const existing = await deps.sessions.load(token);
  if (existing?.ready && existing.fingerprint) {
    return { token, fingerprint: existing.fingerprint, alreadyJoined: true };
  }
  // AUDIT FIX (Sept 19): a ready-but-fingerprint-less local state is a GHOST —
  // a previous attempt saved the ratchet before the relay join confirmed (and
  // the join failed). The relay record has no responder fields, so a fresh
  // join is exactly right. Drop the ghost and fall through.
  if (existing?.ready) {
    console.log('[veil-invite] dropping half-joined ghost state for ' + token.slice(0, 4));
    await deps.sessions.remove(token);
  }

  const pk = await deps.relay.sessionPeek(token, writeSecret);
  const pd = pk.data as { data?: { session?: Record<string, string> }; session?: Record<string, string> };
  const rec = pd?.data?.session ?? pd?.session ?? (pk.data as Record<string, string>);
  if (!rec) throw new Error('Invitation not found or expired.');
  if (rec.state === 'ended') throw new Error('This session has ended.');
  if (rec.state === 'active' && rec.responder_client_id && rec.responder_client_id !== opts.clientId) {
    throw new Error('This session is already in use.');
  }
  if (rec.state === 'pending' && new Date(rec.expires_at).getTime() < Date.now()) {
    throw new Error('This invitation has expired.');
  }
  if (!rec.initiator_pub_jwk) {
    throw new Error('This session was created by an older client and cannot be joined.');
  }

  // Batch C (V-12): the row's dials, clamped, are bound into the fingerprint —
  // if the relay rewrote them, the two phones show different fingerprints.
  const peekDials = clampDials({
    defaultTtlSeconds: rec.default_ttl_seconds as unknown as number,
    expireAfterSeconds: rec.expire_after_seconds as unknown as number,
    keyRetentionHours: rec.key_retention_hours as unknown as number,
    burnAfterOpen: (rec.burn_after_open as unknown) === true,
  });
  // Batch F (round-4 reviews R4-1-01 / R4-4-05): a link made from b60 on carries
  // the creator's dials. They win, and a relay copy that differs is refused (group
  // seats have no fingerprint ceremony, so this is their only check). An older
  // link has none: the relay's copy is used (it is in the fingerprint), and the
  // session is marked so the local burn window is floored (burnWindow).
  if (linkDialsIn && canonicalDials(linkDialsIn) !== canonicalDials(peekDials)) {
    throw new Error('This invitation\'s settings were changed on the server, so it was not opened. Ask for a fresh link.');
  }
  const dials = linkDialsIn ?? peekDials;
  const dialsSource: 'link' | 'peek' = linkDialsIn ? 'link' : 'peek';
  const { state, responderPub, responderRatchetPub, responderPqCt, fingerprint } =
    await joinSession(token, linkSecret, rec.initiator_pub_jwk, rec.initiator_pq_pub || null, dials);
  // Batch C (V-16, client half): retire the link's w at join — a fresh
  // responder credential replaces it, so anyone else holding the link can no
  // longer act as this member. Kept only if the relay confirms the new hash.
  const freshWrite = hexRand(32);
  const freshHash = await writeHashHex(freshWrite);
  state.writeSecret = writeSecret;

  const j = await deps.relay.sessionJoin({
    token,
    write_secret: writeSecret,
    client_id: opts.clientId,
    display_name: opts.displayName ?? '',
    responder_pub_jwk: responderPub,
    responder_ratchet_pub_jwk: responderRatchetPub,
    responder_pq_ct: responderPqCt,
    fingerprint,
    new_responder_write_hash: freshHash,
  });
  const jd = j.data as { data?: { session?: Record<string, string> }; session?: Record<string, string> };
  const joined = jd?.data?.session ?? jd?.session;
  if (!joined) throw new Error('Could not join the session.');
  if (
    joined.responder_pub_jwk !== responderPub ||
    joined.responder_ratchet_pub_jwk !== responderRatchetPub
  ) {
    throw new Error('The session was joined again while you were joining — its keys no longer match. Ask your peer for a fresh invitation.');
  }
  if (joined.responder_write_hash === freshHash) state.writeSecret = freshWrite;

  // AUDIT FIX (Sept 19): persist the ratchet ONLY after the relay join confirmed
  // (and the clobber check passed) — never before.
  // Batch H (round-6 review R6-1-06): a refused save is an error, not a ghost chat
  await saveOrThrow(deps.sessions, token, {
    ...(await serializeRatchetState(state)),
    burnAfterOpen: dials.burnAfterOpen,
    defaultTtlSeconds: dials.defaultTtlSeconds,
    expireAfterSeconds: dials.expireAfterSeconds,
    dialsSource, // Batch F (R4-1-01)
  } as never);

  return { token, fingerprint, alreadyJoined: false };
}


/** Group invite links append the GEK + epoch fragments (web parity:
 *  ?join=<token>#w=<secret>&g=<gek>&e=<epoch>). */
export function groupInviteLink(baseLink: string, gekB64: string, epoch: number, creatorIkB64: string, groupToken: string, groupBindHex: string): string {
  return `${baseLink}&g=${encodeURIComponent(gekB64)}&e=${epoch}&c=${encodeURIComponent(creatorIkB64)}&t=${groupToken}&ph=${groupBindHex}`;
}

/** Batch D (D-03, RV-03): binds a group link to its group. The relay supplies the
 *  group token and the group's ML-KEM public key at join time; a joiner refuses a
 *  peek whose token or key doesn't hash to the value the inviter put in the link. */
export async function groupLinkBinding(groupToken: string, groupPqPubB64: string): Promise<string> {
  const h = await sha256(utf8(`vardum-group-link-v1:${groupToken}:${groupPqPubB64}`));
  return Array.from(h).map((b) => b.toString(16).padStart(2, '0')).join('');
}
