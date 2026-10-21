/**
 * @veil/device — one-tap contact sessions ("pin = identity").
 *
 * Exact web contract (extracted from the fixed reference bundle):
 *   1. identityLookup — fetch the peer's published prekeys (public only)
 *   2. verifyPeerPrekeys — SPK_sig AND pq_sig checked against the PINNED IK;
 *      on mismatch or absence the session is refused (MITM / downgrade guard)
 *   3. createContactSession — ephemeral X25519 vs peer SPK and peer IK + ML-KEM encap
 *   4. sign {v:3,t,ek,to,pq,spk,d} with the identity key (Ed25519); d = canonical dials
 *   5. VeilSession.create server-side (public material + write-secret hashes)
 *   6. ratchet state sealed in the device session store
 */

import {
  createContactSession, acceptContactSession, ikSign, verifyWithIk, veilIdFromIkPub,
  serializeRatchetState, canonicalDials, clampDials,
  utf8, toB64, randomBytes,
} from '../../crypto-core/src/index';
import type { RatchetStateSerialized } from '../../crypto-core/src/index';
import type { VeilRelay, PinStore, SessionStore, KeyvaultIdentity } from './index.js';
import { saveOrThrow } from './save-strict';

export interface OneTapDeps {
  relay: VeilRelay;
  pins: PinStore;
  sessions: SessionStore;
}

export interface OneTapResult {
  token: string;
  state: RatchetStateSerialized;
}

/** Start a one-tap session with a pinned contact. Refuses on any trust failure. */
export interface SessionDials {
  default_ttl_seconds?: number;
  expire_after_seconds?: number;
  key_retention_hours?: number;
  burn_after_open?: boolean;
}

export async function createOneTapSession(
  deps: OneTapDeps,
  identity: KeyvaultIdentity,
  peerVeilId: string,
  clientId: string,
  dials?: SessionDials,
  /** b68: my self-chosen nickname — the peer sees it in this thread's title */
  displayName?: string,
): Promise<OneTapResult> {
  const pin = await deps.pins.getPin(peerVeilId);
  if (!pin) throw new Error('Pin this contact first — the pinned key is the trust anchor.');

  const r = await deps.relay.identityLookup(peerVeilId);
  const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
  const IK_pub = rec?.IK_pub, SPK_pub = rec?.SPK_pub, SPK_sig = rec?.SPK_sig;
  if (!IK_pub || !SPK_pub || !SPK_sig) throw new Error('No published prekeys for that Vardum ID.');

  // b54: SPK_sig AND pq_sig must verify against the PINNED IK (no classical fallback)
  const trust = await deps.pins.verifyPeerPrekeys(peerVeilId, { IK_pub, SPK_pub, SPK_sig, pq_pub: rec?.pq_pub, pq_sig: rec?.pq_sig });
  if (!trust.trusted) {
    if (trust.reason === 'pq-prekey-unsigned') throw new Error('Your contact needs to update Vardum before you can chat securely.');
    throw new Error(`Refusing to start: ${trust.reason}`);
  }

  // b197-r6: handshake stage profiler — the owner reported 5-10s handshake
  // lag; these marks identify which stage eats the time (prime suspects:
  // pure-JS ML-KEM encap on Hermes, relay RTTs, keychain save+verify).
  const HS_T0 = Date.now();
  const hsMark = (label: string) => console.log(`[veil-hs] +${String(Date.now() - HS_T0).padStart(5)}ms ${label}`);
  hsMark('pin + prekey lookup + trust verify done');

  // xu(24) in the web bundle: 24 random bytes, hex — same token format
  const token = [...randomBytes(24)].map((b) => b.toString(16).padStart(2, '0')).join('');
  // Batch C (V-12): the initiator's own dials, clamped — signed into the request and kept locally
  const myDials = clampDials({
    defaultTtlSeconds: dials?.default_ttl_seconds ?? 7200,
    expireAfterSeconds: dials?.expire_after_seconds ?? 86400,
    keyRetentionHours: dials?.key_retention_hours ?? 168,
    burnAfterOpen: dials?.burn_after_open ?? true,
  });
  // Batch C (B9): the PINNED IK feeds the extra DH(EK, IK_peer) term
  const created = await createContactSession(
    token, { spkPubB64: trust.spkPubB64, pqPubB64: trust.pqPubB64, ikPubB64: pin.ikPubB64 }, identity.ikPubB64, myDials,
  );
  hsMark('crypto core done (X25519 + ML-KEM encap) — prime suspect if large');

  // b54: the IK signature also covers the initiator session pub (spk).
  // Batch C (v:3, V-12): and the session dials (d), so the relay can't rewrite them.
  const sigMsg = JSON.stringify({ v: 3, t: token, ek: created.ekPubB64, to: peerVeilId, pq: created.pqCt, spk: created.sessionPub, d: canonicalDials(myDials) });
  const sig = await ikSign(identity.ikSeedB64, toB64(utf8(sigMsg)));
  hsMark('ikSign done');

  const writeHash = async (secret: string) => {
    const h = await crypto.subtle.digest('SHA-256', utf8(secret) as unknown as BufferSource);
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  await deps.relay.entityCreate('VeilSession', {
    token,
    state: 'pending',
    initiator_client_id: clientId,
    responder_client_id: '',
    initiator_display_name: displayName ?? '',
    responder_display_name: '',
    passphrase_required: false,
    session_fingerprint: '',
    initiator_pub_jwk: created.sessionPub,
    initiator_pq_pub: '',
    initiator_pq_ct: created.pqCt,
    initiator_ek_pub: created.ekPubB64,
    initiator_sig: sig,
    initiator_veil_id: identity.veilId,
    responder_veil_id: peerVeilId,
    contact_session: true,
    initiator_write_hash: await writeHash(created.writeSecrets.initiator),
    responder_write_hash: await writeHash(created.writeSecrets.responder),
    initiator_verified: false,
    responder_verified: false,
    // SPEC §2.11: pending contact request expires after 24h (web: 864e5 ms).
    // Dials = the web's default settings values (wh.burnTtlSeconds/expireAfterSeconds/retentionHours).
    default_ttl_seconds: myDials.defaultTtlSeconds,
    // b197-r8l (TWO-DIAL SYNCHRONIZED MODEL, owner spec): BOTH dials are
    // founder-programmable and relay-enforced —
    //   default_ttl_seconds = burn-after-open window (relay copy dies open+N)
    //   expire_after_seconds = unopened-message relay deletion horizon
    //                         (12/24/36/48 h chips)
    expire_after_seconds: myDials.expireAfterSeconds,
    key_retention_hours: myDials.keyRetentionHours,
    burn_after_open: myDials.burnAfterOpen,
    last_activity: new Date().toISOString(),
    expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
  });
  hsMark('entityCreate (relay RTT, big payload) done');

  const state = await serializeRatchetState(created.state);
  await saveOrThrow(deps.sessions, token, { // Batch H (R6-1-06): a refused save is an error
    ...state,
    // Batch F (round-4 review R4-1-04): who this chat is with, from the PIN — the
    // only local record of it (the handshake's contactPending is cleared later)
    peerVeilId,
    peerIkPub: pin.ikPubB64,
    burnAfterOpen: myDials.burnAfterOpen,
    defaultTtlSeconds: myDials.defaultTtlSeconds,
    expireAfterSeconds: myDials.expireAfterSeconds,
  } as never);
  hsMark('ratchet serialize + keychain save(+verify) done — HANDSHAKE COMPLETE');
  return { token, state };
}

// ---------------------------------------------------------------------------
// Responder side (SPEC §3): verify the initiator's request, re-derive the
// shared root from OUR prekeys, join via the session gate, seal the ratchet.
// ---------------------------------------------------------------------------

/**
 * Batch F (round-4 review R4-1-04): who a 1:1 chat is with, from this phone's own
 * sealed state. Only contact (pinned-key) chats record it; invite chats and chats
 * sealed before b60 return null. Never derived from the relay row.
 */
export function sealedPeer(sealed: unknown): { veilId: string; ikPub: string } | null {
  const s = (sealed ?? {}) as { peerVeilId?: unknown; peerIkPub?: unknown };
  return typeof s.peerVeilId === 'string' && s.peerVeilId && typeof s.peerIkPub === 'string' && s.peerIkPub
    ? { veilId: s.peerVeilId, ikPub: s.peerIkPub } : null;
}

/** Batch F (R4-1-04): true when the sealed chat is a contact chat with exactly this peer and key. */
export function sealedPeerMatches(sealed: unknown, veilId: string, ikPub: string): boolean {
  const p = sealedPeer(sealed);
  return !!p && (sealed as { contact?: unknown }).contact === true && p.veilId === veilId && p.ikPub === ikPub;
}

/**
 * Batch F (R4-1-04): of the candidate chats (in the caller's order), the first
 * whose SEALED state is a contact chat with this contact under its pinned key.
 * The relay list only supplies candidates; it can't relabel a chat into this set.
 */
export async function pickContactSession(
  sessions: { load(token: string): Promise<unknown> },
  candidates: string[],
  veilId: string,
  pinnedIkPub: string,
): Promise<string | null> {
  for (const t of candidates) {
    const sealed = await sessions.load(t).catch(() => null);
    if (sealedPeerMatches(sealed, veilId, pinnedIkPub)) return t;
  }
  return null;
}

/** A pending contact-session record as served by veilSessionGate list/peek. */
export interface IncomingContactRequest {
  token: string;
  state: string;
  initiator_veil_id: string;
  initiator_ek_pub: string;
  initiator_pq_ct?: string | null;
  initiator_pub_jwk: string;
  initiator_sig: string;
  default_ttl_seconds?: unknown;
  expire_after_seconds?: unknown;
  key_retention_hours?: unknown;
  burn_after_open?: unknown;
  /** b79: stamped by THIS function's own relay.sessionJoin call — empty
   *  until the responder-side crypto join has actually happened. This is
   *  the correct "already joined" signal, NOT req.state (see guard below). */
  responder_pub_jwk?: string;
}

export async function acceptOneTapSession(
  deps: OneTapDeps,
  identity: KeyvaultIdentity,
  req: IncomingContactRequest,
  clientId: string,
  /** b68: my self-chosen nickname — the initiator sees it in this thread's title */
  displayName?: string,
): Promise<OneTapResult> {
  const { relay, pins, sessions } = deps;
  // Batch G (round-5 review R5-1-06): never overwrite a chat this phone already holds
  // (a relay could relabel my own pending invite as a contact request to me)
  if (await sessions.load(req.token)) throw new Error('This chat already exists on this phone, so the request was not accepted.');
  // b79 CRITICAL FIX (owner report: "no accept window comes up on native,
  // it just appears in the conversations box" — a PINNED-CONTACT one-tap
  // re-message session is created ALREADY 'active' by design (trust already
  // exists via the pin; there is deliberately no pending/accept UI step for
  // it). The OLD guard here refused to run unless state==='pending', which
  // meant the crypto join (the part that actually derives this device's
  // ratchet keys and stamps responder_pub_jwk) never ran AT ALL for that
  // flow — advanceHandshake called this every poll, it threw every time, the
  // bare catch swallowed it silently, and the message could never decrypt
  // (peer stuck on "waiting for their device to open it" forever). The
  // correct guard is "has THIS session already been joined", which
  // responder_pub_jwk answers directly — it's empty until the one
  // relay.sessionJoin call below stamps it, regardless of whether the
  // record started 'pending' (first-time request) or 'active' (pinned
  // one-tap re-message).
  if (req.responder_pub_jwk) throw new Error('Session already joined.');
  if (req.state === 'ended') throw new Error('Session has ended.');

  // 1. resolve the trust anchor for the initiator's IK: pinned if available,
  //    otherwise lookup (SPEC §3.1 allows either; we auto-pin on success like web).
  let ikPubB64: string;
  const pin = await pins.getPin(req.initiator_veil_id);
  if (pin) {
    // Batch D (D-12, RV-22): a pin made before the B1 rule may hold a key that
    // doesn't hash to the ID — re-check on every accept, pinned or not
    if ((await veilIdFromIkPub(pin.ikPubB64)) !== req.initiator_veil_id) throw new Error('Initiator identity does not match their Vardum ID.');
    ikPubB64 = pin.ikPubB64;
  } else {
    const r = await relay.identityLookup(req.initiator_veil_id);
    const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
    if (!rec?.IK_pub) throw new Error('Initiator has no published identity.');
    // Batch C (B1): the Vardum ID IS the hash of the identity key — refuse a registry record that doesn't match
    if ((await veilIdFromIkPub(rec.IK_pub)) !== req.initiator_veil_id) throw new Error('Initiator identity does not match their Vardum ID.');
    ikPubB64 = rec.IK_pub;
  }

  // 2. verify initiator_sig over the BYTE-EXACT payload {v:3,t,ek,to,pq,spk,d}.
  //    Batch C (V-12): the dials come from the row but must match what the
  //    initiator signed — a relay rewrite fails the signature. Clamped first.
  const reqDials = clampDials({
    defaultTtlSeconds: req.default_ttl_seconds as number,
    expireAfterSeconds: req.expire_after_seconds as number,
    keyRetentionHours: req.key_retention_hours as number,
    burnAfterOpen: req.burn_after_open === true,
  });
  const payload = JSON.stringify({
    v: 3, t: req.token, ek: req.initiator_ek_pub,
    to: identity.veilId, pq: req.initiator_pq_ct || '', spk: req.initiator_pub_jwk, d: canonicalDials(reqDials),
  });
  const ok = await verifyWithIk(ikPubB64, toB64(utf8(payload)), req.initiator_sig);
  if (!ok) throw new Error('Request signature failed verification against the initiator identity key.');

  // 3. reproduce the shared root from OUR prekeys (SPEC §3.2)
  const accepted = await acceptContactSession(req.token, {
    ekPubB64: req.initiator_ek_pub,
    pqCt: req.initiator_pq_ct || '',
    spkPrivB64: identity.spkPrivB64,
    spkPubB64: identity.spkPubB64,
    pqPrivB64: identity.pqPrivB64,
    pqPubB64: identity.pqPubB64,
    initiatorSessionPub: req.initiator_pub_jwk,
    ikSeedB64: identity.ikSeedB64,
    ikPubB64: identity.ikPubB64,
    initiatorIkPubB64: ikPubB64,
    dials: reqDials,
  });

  // 4. join (SPEC §3.3) — write_secret is the lowercase-hex responder credential
  await relay.sessionJoin({
    token: req.token,
    write_secret: accepted.writeSecret,
    client_id: clientId,
    display_name: displayName ?? '',
    responder_pub_jwk: accepted.responderPub,
    responder_ratchet_pub_jwk: accepted.responderRatchetPub,
    responder_pq_ct: '',
    fingerprint: accepted.fingerprint,
  });

  // 5. auto-pin the initiator (web contract: accept = pin), device-local only
  if (!pin) await pins.pin(req.initiator_veil_id, ikPubB64);

  const state = await serializeRatchetState(accepted.state);
  await saveOrThrow(sessions, req.token, { // Batch H (R6-1-06): a refused save is an error
    ...state,
    // Batch F (R4-1-04): the initiator, as verified above (pin, or ID = f(IK) + signature)
    peerVeilId: req.initiator_veil_id,
    peerIkPub: ikPubB64,
    burnAfterOpen: reqDials.burnAfterOpen,
    defaultTtlSeconds: reqDials.defaultTtlSeconds,
    expireAfterSeconds: reqDials.expireAfterSeconds,
  } as never);
  return { token: req.token, state };
}
