/**
 * @veil/crypto-core — veil-ratchet-6 session engine (b54 Batch A; Batch C protocol bump).
 *
 * Session setup (PQXDH-style, two entry families):
 *   strict invite  createSession / joinSession / completeHandshake
 *                  X25519 session DH + ML-KEM-768 encapsulation + the invite
 *                  link secret `k` (fragment-only, never sent to the relay)
 *   one-tap contact createContactSession / acceptContactSession / completeHandshake
 *                  ephemeral X25519 vs the peer's IK-signed SPK + ML-KEM-768
 *                  encapsulation to the peer's IK-signed PQ prekey
 * Post-quantum is MANDATORY: a missing or malformed PQ key, ciphertext or
 * keygen failure aborts the handshake (no classical fallback).
 *
 * After setup: the Signal Double Ratchet (rev. 4) over X25519 — KDF_RK =
 * HKDF-SHA256(salt = RK, ikm = DH_out || PQ_secret), KDF_CK = HMAC(ck, 0x01/0x02),
 * skipped-key store, MAX_SKIP guards — with an ML-KEM-768 secret mixed into
 * every ratchet step (per-step PQ re-key) and every header's ratchet pub + PQ
 * step pub signed with a session-scoped Ed25519 key derived from the root.
 *
 * Fingerprint: transcriptFingerprint over every public handshake value plus
 * SHA-256(shared) (kdf.ts), so substitution or downgrade is user-visible.
 *
 * X25519 runs on @noble/curves directly (raw 32-byte keys, b64 on the wire).
 */

import { toB64, fromB64, utf8 } from './bytes';
import { hkdf, hmacSha256, sha256, combine, transcriptFingerprint } from './kdf';
import { mlkemKeypair, mlkemEncap, mlkemDecap } from './mlkem';
import { padPlaintext, unpadPlaintext } from './padding';
import { ed25519, x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import {
  RATCHET_PROTOCOL_LATEST, RATCHET_PROTOCOL_SUPPORTED, ROOT_KEY_INFO, RK0_SALT_PREFIX, RK0_INFO,
  PP_SALT_PREFIX, PP_INFO, RATCHET_SIG_INFO, CONTACT_WRITE_INFO, FINGERPRINT_LABEL,
  MLKEM768_PUB_BYTES, MLKEM768_CT_BYTES,
} from './constants';

const MAX_COUNTER_GAP = 500;   // max skip ahead before "desynchronised"
const MAX_SKIPPED_PER_CHAIN = 100;
const MAX_PROCESSED_IDS = 500;
const MAX_SEEN_PUBS = 64; // replaced key epochs remembered for stale-header rejection
const MAX_MY_PUBS = 64; // own ratchet pubs remembered for own-echo rejection (bounded state)

export type SessionRole = 'initiator' | 'responder';

/** Thrown when a stored session predates the current protocol (hard cut). */
export class LegacySessionError extends Error {
  constructor() {
    super('This chat used an older security protocol and has ended. Start a new chat.');
    this.name = 'LegacySessionError';
  }
}

export interface RatchetState {
  role: SessionRole;
  /** protocol tag written into headers — always RATCHET_PROTOCOL_LATEST */
  proto: string;
  /** replaced remote ratchet pubs — a header from an already-replaced epoch is rejected */
  seenRemotePubs: Set<string>;
  /** one-tap contact session (bootstraps from pinned IK + signed SPK / PQ prekey) */
  contact: boolean;
  ready: boolean;
  fingerprint: string | null;
  /** always 'hybrid' in veil-ratchet-6 (kept as a field so state is self-describing) */
  pq: 'hybrid';
  /** session handshake X25519 key (per session, not the Vardum identity) */
  hsPriv: Uint8Array;
  hsPub: string;
  bound: { initiatorPub: string; responderPub: string; responderRatchetPub?: string } | null;
  /** strict initiator: own handshake ML-KEM pair (pub kept for the transcript) */
  pqPub: string | null;
  pqPriv: string | null;
  /** per-step PQ re-key pair */
  pqStepPriv: string | null;
  pqStepPub: string | null;
  /** ct encapsulated to the peer's current step pub — travels in our next header */
  pendingPqCt: string | null;
  /** strict initiator: HKDF of the invite link secret `k`, mixed into the root */
  ppSecret: Uint8Array | null;
  /** relay write credential (strict: random, link fragment; contact: HKDF of the root) */
  writeSecret: string | null;
  /** session-scoped Ed25519 ratchet signing (null only on an initiator before completion).
   *  Batch C (B9): sigPrivB64 = MY direction's key; sigPubB64 = the PEER's direction's public key. */
  sigPrivB64: string | null;
  sigPubB64: string | null;
  /** Batch C (V-12): canonical dials bound into the fingerprint (initiator keeps its own until completion) */
  dials: string | null;
  /** Batch C (B9): contact initiator — values needed to finish the transcript at completion */
  contactPending: { initiatorIkPub: string; responderIkPub: string; ekPub: string; spkPub: string; pqPub: string; pqCt: string; sharedHash: string } | null;
  ratchetPriv: Uint8Array | null;
  ratchetPub: string;
  remoteRatchetPub: string | null;
  myPubs: Set<string>;
  rootKey: Uint8Array;
  sendChain: Uint8Array | null;
  recvChain: Uint8Array | null;
  sendCount: number;
  prevSendCount: number;
  recvCount: number;
  processedIds: Set<string>;
  skipped: Map<string, Map<number, Uint8Array>>;
}

// ---------- X25519 (@noble/curves) ----------

interface X25519Pair { priv: Uint8Array; pub: string }

function x25519Pair(): X25519Pair {
  const priv = x25519.utils.randomPrivateKey();
  return { priv, pub: toB64(x25519.getPublicKey(priv)) };
}

function x25519PubBytes(pubB64: string): Uint8Array {
  let b: Uint8Array;
  try { b = fromB64(pubB64); } catch { throw new Error('Malformed X25519 public key.'); }
  if (b.length !== 32) throw new Error('Malformed X25519 public key.');
  return b;
}

/** X25519 DH. noble rejects low-order points (all-zero output) — re-checked here. */
function dh(priv: Uint8Array, pubB64: string): Uint8Array {
  const out = x25519.getSharedSecret(priv, x25519PubBytes(pubB64));
  if (out.every((x) => x === 0)) throw new Error('Invalid X25519 shared secret.');
  return out;
}

// ---------- ML-KEM input checks (fail closed) ----------

function requirePqPub(pubB64: string | null | undefined, what: string): string {
  let ok = false;
  try { ok = !!pubB64 && fromB64(pubB64).length === MLKEM768_PUB_BYTES; } catch { ok = false; }
  if (!ok) throw new Error(`Post-quantum key missing or malformed (${what}) — refusing a downgraded session.`);
  return pubB64 as string;
}

function requirePqCt(ctB64: string | null | undefined, what: string): string {
  let ok = false;
  try { ok = !!ctB64 && fromB64(ctB64).length === MLKEM768_CT_BYTES; } catch { ok = false; }
  if (!ok) throw new Error(`Post-quantum ciphertext missing or malformed (${what}) — refusing a downgraded session.`);
  return ctB64 as string;
}

/**
 * PQ key generation, fail-closed: if ML-KEM key generation fails, the
 * operation aborts loudly and the caller retries. Nothing is ever sent
 * without its post-quantum binding.
 */
async function pqStepPair(): Promise<{ pub: string; priv: string }> {
  try {
    return await mlkemKeypair();
  } catch {
    throw new Error('Post-quantum key generation failed — aborted to avoid a security downgrade. Please retry.');
  }
}

// ---------- roots / chains ----------

/** KDF_RK: HKDF-64 -> {rk, ck}; salt = current root, ikm = DH_out (|| PQ secret). */
async function deriveRoot(salt: Uint8Array, ikm: Uint8Array, extra: Uint8Array | null): Promise<{ rk: Uint8Array; ck: Uint8Array }> {
  const material = extra ? combine(ikm, extra) : ikm;
  const out = await hkdf(material, salt, ROOT_KEY_INFO, 64);
  return { rk: out.slice(0, 32), ck: out.slice(32, 64) };
}

/** Handshake root rk0 = HKDF(shared, salt = `vardum-ratchet-6:<token>`, info = rk0). */
async function deriveRk0(shared: Uint8Array, token: string): Promise<Uint8Array> {
  return hkdf(shared, utf8(`${RK0_SALT_PREFIX}${token}`), RK0_INFO, 32);
}

/** Invite link secret term. `k` travels only in the link fragment, never to the relay. */
export async function derivePpSecret(inviteSecret: string, token: string): Promise<Uint8Array> {
  if (!inviteSecret) throw new Error('This invite link is missing its secret — ask for a fresh link.');
  return hkdf(utf8(inviteSecret), utf8(`${PP_SALT_PREFIX}${token}`), PP_INFO, 32);
}

/** One-tap contact relay write credentials (lowercase hex, 64 chars). */
async function contactWriteSecrets(root: Uint8Array): Promise<{ initiator: string; responder: string }> {
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  const initiator = await hkdf(root, utf8(CONTACT_WRITE_INFO), 'initiator', 32);
  const responder = await hkdf(root, utf8(CONTACT_WRITE_INFO), 'responder', 32);
  return { initiator: hex(initiator), responder: hex(responder) };
}

interface ChainKeys { ck: Uint8Array; mk: Uint8Array }

/** KDF_CK: mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02). */
async function advanceChain(chain: Uint8Array): Promise<ChainKeys> {
  const mk = await hmacSha256(chain, new Uint8Array([1]));
  const ck = await hmacSha256(chain, new Uint8Array([2]));
  return { ck, mk };
}

// ---------- fingerprints ----------

/**
 * Batch C (V-12): session dials, canonical form. Both peers bind the SAME
 * string into the fingerprint (and, for contact sessions, the IK-signed
 * request), so a relay that rewrites the burn / expiry dials on the session
 * row produces a visible fingerprint mismatch instead of a silent change.
 */
export interface DialsInput { defaultTtlSeconds: number; expireAfterSeconds: number; keyRetentionHours: number; burnAfterOpen: boolean }

export const DIAL_LIMITS = {
  ttlMax: 30 * 24 * 3600, // 30 days (forum)
  expireMax: 30 * 24 * 3600,
  retentionMax: 24 * 30,
} as const;

/** Clamp to whole numbers inside the supported ranges; non-numbers fall back to the app defaults. */
export function clampDials(d: Partial<DialsInput> | null | undefined): DialsInput {
  const int = (x: unknown, lo: number, hi: number, dflt: number) => {
    const n = Number(x);
    if (!Number.isFinite(n) || !Number.isInteger(n)) return dflt;
    return Math.min(hi, Math.max(lo, n));
  };
  return {
    defaultTtlSeconds: int(d?.defaultTtlSeconds, 0, DIAL_LIMITS.ttlMax, 7200),
    expireAfterSeconds: int(d?.expireAfterSeconds, 0, DIAL_LIMITS.expireMax, 86400),
    keyRetentionHours: int(d?.keyRetentionHours, 0, DIAL_LIMITS.retentionMax, 168), // 0 = Off (settings QUIET_OPTIONS)
    burnAfterOpen: d?.burnAfterOpen === true,
  };
}

export function canonicalDials(d: Partial<DialsInput> | null | undefined): string {
  const c = clampDials(d);
  return `t=${c.defaultTtlSeconds};e=${c.expireAfterSeconds};r=${c.keyRetentionHours};b=${c.burnAfterOpen ? 1 : 0}`;
}

/** Batch C (NF-7, V-12): the responder's first ratchet pub and the dials join the transcript. */
async function inviteFingerprint(
  token: string, initiatorPub: string, responderPub: string, responderRatchetPub: string,
  initiatorPqPub: string, responderPqCt: string, dials: string, shared: Uint8Array,
): Promise<string> {
  return transcriptFingerprint(FINGERPRINT_LABEL, [
    utf8(RATCHET_PROTOCOL_LATEST), utf8('invite'), utf8(token),
    fromB64(initiatorPub), fromB64(responderPub), fromB64(responderRatchetPub),
    fromB64(initiatorPqPub), fromB64(responderPqCt), utf8(dials),
    await sha256(shared),
  ]);
}

/** Batch C (B9, NF-7, V-12): both identity keys, the responder ratchet pub and the dials join the transcript. */
async function contactFingerprint(
  token: string, initiatorIkPub: string, responderIkPub: string, ekPub: string, spkPub: string, pqPub: string, pqCt: string,
  initiatorSessionPub: string, responderPub: string, responderRatchetPub: string, dials: string, sharedHash: Uint8Array,
): Promise<string> {
  return transcriptFingerprint(FINGERPRINT_LABEL, [
    utf8(RATCHET_PROTOCOL_LATEST), utf8('contact'), utf8(token),
    fromB64(initiatorIkPub), fromB64(responderIkPub),
    fromB64(ekPub), fromB64(spkPub), fromB64(pqPub), fromB64(pqCt), fromB64(initiatorSessionPub),
    fromB64(responderPub), fromB64(responderRatchetPub), utf8(dials),
    sharedHash,
  ]);
}

/** Batch C (B9): X25519 term against the responder's long-term identity key
 *  (Ed25519 IK converted to Montgomery form), as in X3DH's DH(EK, IK_B). */
function ikPubToX25519(ikPubB64: string): string {
  let b: Uint8Array;
  try { b = fromB64(ikPubB64); } catch { throw new Error('Malformed identity key.'); }
  if (b.length !== 32) throw new Error('Malformed identity key.');
  return toB64(edwardsToMontgomeryPub(b));
}

// ---------- skipped keys ----------

function storeSkipped(state: RatchetState, rp: string, n: number, mk: Uint8Array): void {
  let per = state.skipped.get(rp);
  if (!per) { per = new Map(); state.skipped.set(rp, per); }
  per.set(n, mk);
  while (per.size > MAX_SKIPPED_PER_CHAIN) per.delete(per.keys().next().value as number);
  let total = 0;
  for (const m of state.skipped.values()) total += m.size;
  while (total > MAX_COUNTER_GAP && state.skipped.size > 1) {
    const oldest = state.skipped.keys().next().value as string;
    total -= state.skipped.get(oldest)!.size;
    state.skipped.delete(oldest);
  }
}

function takeSkipped(state: RatchetState, header: EnvelopeHeader): Uint8Array | null {
  const per = state.skipped.get(header.rp);
  if (!per) return null;
  const mk = per.get(header.n);
  if (mk) per.delete(header.n);
  return mk ?? null;
}

/**
 * Signal DR spec (DHRatchet / header.pn): before accepting the peer's NEW
 * ratchet pub and rotating, skip-and-store message keys on the CURRENT
 * receive chain up to header.pn, so old-chain stragglers stay decryptable.
 */
async function skipOldChainBeforeRotation(state: RatchetState, pn: number): Promise<void> {
  if (!state.recvChain || state.remoteRatchetPub === null) return; // no old chain to protect
  if (pn < state.recvCount || pn - state.recvCount > MAX_COUNTER_GAP) {
    throw new Error('Message counter out of range — the session is desynchronised.');
  }
  while (state.recvCount < pn) {
    const step = await advanceChain(state.recvChain);
    state.recvChain = step.ck;
    storeSkipped(state, state.remoteRatchetPub, state.recvCount, step.mk);
    state.recvCount += 1;
  }
}

// ---------- message header ----------

export interface EnvelopeHeader {
  v: string;
  /** sender's current X25519 ratchet pub (raw, b64) */
  rp: string;
  /** sender's previous chain length at last ratchet step */
  pn: number;
  /** message counter in the current chain */
  n: number;
  /** per-step PQ: sender's current ML-KEM step pub (mandatory) */
  pq?: string;
  /** ct encapsulated to the peer's step pub */
  pqct?: string;
  /** Ed25519 signature over rp + pq with the session signing key (mandatory) */
  sig?: string;
}

export interface Envelope {
  ciphertext: string;
  iv: string;
  /** serialized JSON header — AES-GCM AAD (the exact sender bytes) */
  header: string;
  byteLength?: number;
}

async function importAesKey(mk: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', mk as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---------- signed ratchet keys ----------

/**
 * Session-scoped Ed25519 signing pairs derived from the handshake root (rk0).
 * Batch C (B9): one pair PER DIRECTION. Each side keeps only its own private
 * key (sigPrivB64) and the peer's public key (sigPubB64), so a header signed
 * by one side can never be reflected back and accepted as the other's.
 * Both pairs come from rk0, so this is defence in depth inside the session
 * (the root salt already makes a splice non-exploitable), not peer authentication.
 */
async function deriveSigPairs(rk0: Uint8Array, token: string, role: SessionRole): Promise<{ privB64: string; pubB64: string }> {
  const pair = async (dir: SessionRole) => {
    const seed = await hkdf(rk0, utf8(`${RATCHET_SIG_INFO}:${token}`), `${RATCHET_SIG_INFO}/${dir}`, 32);
    return { priv: seed, pub: ed25519.getPublicKey(seed) };
  };
  const mine = await pair(role);
  const theirs = await pair(role === 'initiator' ? 'responder' : 'initiator');
  return { privB64: toB64(mine.priv), pubB64: toB64(theirs.pub) };
}

function ratchetSigMessage(rp: string, pq: string | undefined): Uint8Array {
  return utf8(`${RATCHET_SIG_INFO}:${rp}:${pq ?? ''}`);
}

function signRatchetPub(state: RatchetState, rp: string, pq: string | undefined): string {
  if (!state.sigPrivB64) throw new Error('Session signing key missing — the handshake is incomplete.');
  return toB64(ed25519.sign(ratchetSigMessage(rp, pq), fromB64(state.sigPrivB64)));
}

/** Fail-closed verification on every ratchet rotation. */
function verifyRatchetPubSig(state: RatchetState, header: EnvelopeHeader): void {
  if (!state.sigPubB64) throw new Error('Session signing key missing — the handshake is incomplete.');
  if (!header.sig) throw new Error('Unsigned ratchet rotation rejected.');
  let ok = false;
  // T-2: strict RFC 8032 (noble's default ZIP-215 accepts forgeries under small-order keys)
  try { ok = ed25519.verify(fromB64(header.sig), ratchetSigMessage(header.rp, header.pq), fromB64(state.sigPubB64), { zip215: false }); } catch { ok = false; }
  if (!ok) throw new Error('Invalid ratchet rotation signature — header did not authenticate against the session.');
}

function emptyState(role: SessionRole, contact: boolean, hs: X25519Pair): RatchetState {
  return {
    role,
    proto: RATCHET_PROTOCOL_LATEST,
    seenRemotePubs: new Set(),
    contact,
    ready: false,
    fingerprint: null,
    pq: 'hybrid',
    hsPriv: hs.priv,
    hsPub: hs.pub,
    bound: null,
    pqPub: null,
    pqPriv: null,
    pqStepPriv: null,
    pqStepPub: null,
    pendingPqCt: null,
    ppSecret: null,
    writeSecret: null,
    sigPrivB64: null,
    sigPubB64: null,
    dials: null,
    contactPending: null,
    ratchetPriv: null,
    ratchetPub: '',
    remoteRatchetPub: null,
    myPubs: new Set<string>(),
    rootKey: new Uint8Array(32),
    sendChain: null,
    recvChain: null,
    sendCount: 0,
    prevSendCount: 0,
    recvCount: 0,
    processedIds: new Set<string>(),
    skipped: new Map(),
  };
}

// ---------- strict invite: initiator create ----------

export interface CreatedSession {
  state: RatchetState;
  /** initiator session X25519 pub (b64) — the `initiator_pub_jwk` relay field */
  initiatorPub: string;
  /** ML-KEM-768 pub (b64) — the `initiator_pq_pub` relay field */
  initiatorPqPub: string;
}

/** Initiator creates a strict session. inviteSecret = the link's `k=` fragment.
 *  dials = the initiator's OWN dials; kept in state and bound into the fingerprint at completion. */
export async function createSession(token: string, inviteSecret: string, dials: Partial<DialsInput>): Promise<CreatedSession> {
  const hs = x25519Pair();
  const ppSecret = await derivePpSecret(inviteSecret, token);
  const pq = await pqStepPair();
  const state = emptyState('initiator', false, hs);
  state.pqPub = pq.pub;
  state.pqPriv = pq.priv;
  state.ppSecret = ppSecret;
  state.dials = canonicalDials(dials);
  return { state, initiatorPub: hs.pub, initiatorPqPub: pq.pub };
}

// ---------- strict invite: responder join ----------

export interface JoinedSession {
  state: RatchetState;
  responderPub: string;
  responderRatchetPub: string;
  /** ct encapsulated to the initiator's ML-KEM pub — the `responder_pq_ct` field */
  responderPqCt: string;
  fingerprint: string;
}

/** Responder joins. Session is READY on return (root1 = send chain). */
export async function joinSession(
  token: string,
  inviteSecret: string,
  initiatorPub: string,
  initiatorPqPub: string | null,
  /** the dials as read from the session row — bound into the fingerprint (V-12) */
  dials: Partial<DialsInput>,
): Promise<JoinedSession> {
  requirePqPub(initiatorPqPub, 'invite');
  const pp = await derivePpSecret(inviteSecret, token);
  const hs = x25519Pair();
  const dhOut = dh(hs.priv, initiatorPub);
  const { ct, secret } = await mlkemEncap(initiatorPqPub as string);
  const stepPq = await pqStepPair();
  const shared = combine(combine(dhOut, secret), pp);
  const rk0 = await deriveRk0(shared, token);
  const sig = await deriveSigPairs(rk0, token, 'responder');
  const ratchet = x25519Pair();
  const root1 = await deriveRoot(rk0, dh(ratchet.priv, initiatorPub), null);
  const dialsStr = canonicalDials(dials);
  const fingerprint = await inviteFingerprint(token, initiatorPub, hs.pub, ratchet.pub, initiatorPqPub as string, ct, dialsStr, shared);
  const state = emptyState('responder', false, hs);
  Object.assign(state, {
    ready: true,
    fingerprint,
    dials: dialsStr,
    bound: { initiatorPub, responderPub: hs.pub, responderRatchetPub: ratchet.pub },
    hsPriv: new Uint8Array(32), // Batch H (R6-1-07): used above, never again
    pqStepPriv: stepPq.priv,
    pqStepPub: stepPq.pub,
    sigPrivB64: sig.privB64,
    sigPubB64: sig.pubB64,
    ratchetPriv: ratchet.priv,
    ratchetPub: ratchet.pub,
    remoteRatchetPub: initiatorPub,
    rootKey: root1.rk,
    sendChain: root1.ck,
  });
  state.myPubs.add(ratchet.pub);
  return { state, responderPub: hs.pub, responderRatchetPub: ratchet.pub, responderPqCt: ct, fingerprint };
}

// ---------- one-tap contact family ----------

export interface ContactPeerPrekeys {
  /** peer's X25519 SPK — SPK_sig verified against the PINNED IK by the caller */
  spkPubB64: string;
  /** peer's ML-KEM-768 prekey — pq_sig verified against the PINNED IK by the caller */
  pqPubB64: string;
  /** Batch C (B9): the peer's PINNED Ed25519 identity key — adds DH(EK, IK_peer) */
  ikPubB64: string;
}

export interface CreatedContactSession {
  state: RatchetState;
  /** ephemeral X25519 pub — travels to the peer in the session request */
  ekPubB64: string;
  /** ML-KEM ct encapsulated to the peer's pq_pub */
  pqCt: string;
  /** initiator session X25519 pub — the `initiator_pub_jwk` relay field */
  sessionPub: string;
  writeSecrets: { initiator: string; responder: string };
  fingerprint: string;
}

/**
 * Initiator bootstraps a one-tap session from the pinned peer's signed prekeys.
 * shared = DH(EK, SPK) ‖ DH(EK, IK_peer) ‖ ML-KEM ss  (Batch C, B9: the IK term
 * means only the holder of the peer's long-term identity key can derive the root).
 * The fingerprint is finished at completion, once the responder's keys are known.
 */
export async function createContactSession(
  token: string, peer: ContactPeerPrekeys, myIkPubB64: string, dials: Partial<DialsInput>,
): Promise<CreatedContactSession> {
  requirePqPub(peer.pqPubB64, 'contact prekey');
  const ek = x25519Pair();
  const dhSpk = dh(ek.priv, peer.spkPubB64);
  const dhIk = dh(ek.priv, ikPubToX25519(peer.ikPubB64));
  const enc = await mlkemEncap(peer.pqPubB64);
  const shared = combine(combine(dhSpk, dhIk), enc.secret);
  const rootKey = await deriveRk0(shared, token);
  const sig = await deriveSigPairs(rootKey, token, 'initiator');
  const writeSecrets = await contactWriteSecrets(rootKey);
  const hs = x25519Pair();
  const state = emptyState('initiator', true, hs);
  Object.assign(state, {
    writeSecret: writeSecrets.initiator,
    sigPrivB64: sig.privB64,
    sigPubB64: sig.pubB64,
    rootKey,
    dials: canonicalDials(dials),
    contactPending: {
      initiatorIkPub: myIkPubB64, responderIkPub: peer.ikPubB64, ekPub: ek.pub,
      spkPub: peer.spkPubB64, pqPub: peer.pqPubB64, pqCt: enc.ct, sharedHash: toB64(await sha256(shared)),
    },
  });
  return { state, ekPubB64: ek.pub, pqCt: enc.ct, sessionPub: hs.pub, writeSecrets, fingerprint: '' };
}

export interface ContactRequest {
  /** initiator's ephemeral X25519 pub */
  ekPubB64: string;
  /** ct encapsulated to OUR pq_pub */
  pqCt: string;
  /** OUR SPK (device keyvault) */
  spkPrivB64: string;
  spkPubB64: string;
  /** OUR ML-KEM prekey (device keyvault) */
  pqPrivB64: string;
  pqPubB64: string;
  /** initiator's session X25519 pub (from the request; covered by initiator_sig) */
  initiatorSessionPub: string;
  /** Batch C (B9): OUR identity seed (adds DH(IK, EK)) and public key */
  ikSeedB64: string;
  ikPubB64: string;
  /** the initiator's identity key (the one that verified initiator_sig) */
  initiatorIkPubB64: string;
  /** Batch C (V-12): the dials carried in the SIGNED request */
  dials: Partial<DialsInput>;
}

export interface AcceptedContactSession {
  state: RatchetState;
  fingerprint: string;
  responderPub: string;
  responderRatchetPub: string;
  writeSecret: string;
}

/** Responder accepts the one-tap request; session is READY on return. */
export async function acceptContactSession(token: string, req: ContactRequest): Promise<AcceptedContactSession> {
  requirePqCt(req.pqCt, 'contact request');
  if (!req.pqPrivB64) throw new Error('Post-quantum prekey missing on this device — re-open Vardum to republish it.');
  if (!req.ikSeedB64) throw new Error('Identity key missing on this device.');
  const ikSeed = fromB64(req.ikSeedB64);
  if (ikSeed.length !== 32 || toB64(ed25519.getPublicKey(ikSeed)) !== req.ikPubB64) throw new Error('Identity key mismatch on this device.');
  const dhSpk = dh(fromB64(req.spkPrivB64), req.ekPubB64);
  const dhIk = dh(edwardsToMontgomeryPriv(ikSeed), req.ekPubB64);
  const shared = combine(combine(dhSpk, dhIk), await mlkemDecap(req.pqPrivB64, req.pqCt));
  const rootKey = await deriveRk0(shared, token);
  const sig = await deriveSigPairs(rootKey, token, 'responder');
  const writeSecrets = await contactWriteSecrets(rootKey);
  const ratchet = x25519Pair();
  const root1 = await deriveRoot(rootKey, dh(ratchet.priv, req.initiatorSessionPub), null);
  const hs = x25519Pair();
  const step = await pqStepPair();
  const dialsStr = canonicalDials(req.dials);
  const fingerprint = await contactFingerprint(
    token, req.initiatorIkPubB64, req.ikPubB64, req.ekPubB64, req.spkPubB64, req.pqPubB64, req.pqCt,
    req.initiatorSessionPub, hs.pub, ratchet.pub, dialsStr, await sha256(shared),
  );
  const state = emptyState('responder', true, hs);
  Object.assign(state, {
    ready: true,
    fingerprint,
    dials: dialsStr,
    bound: { initiatorPub: req.initiatorSessionPub, responderPub: hs.pub, responderRatchetPub: ratchet.pub },
    hsPriv: new Uint8Array(32), // Batch H (R6-1-07): used above, never again
    pqStepPriv: step.priv,
    pqStepPub: step.pub,
    writeSecret: writeSecrets.responder,
    sigPrivB64: sig.privB64,
    sigPubB64: sig.pubB64,
    ratchetPriv: ratchet.priv,
    ratchetPub: ratchet.pub,
    remoteRatchetPub: req.initiatorSessionPub,
    rootKey: root1.rk,
    sendChain: root1.ck,
  });
  state.myPubs.add(ratchet.pub);
  return { state, fingerprint, responderPub: hs.pub, responderRatchetPub: ratchet.pub, writeSecret: writeSecrets.responder };
}

// ---------- initiator completes the handshake ----------

/** Completes the handshake from the responder's join material; returns the converged fingerprint. */
export async function completeHandshake(
  state: RatchetState,
  token: string,
  responderPub: string,
  responderRatchetPub: string,
  responderPqCt: string | null,
): Promise<string> {
  if (state.role !== 'initiator') throw new Error('Only the initiator completes the handshake');
  if (state.ready) return state.fingerprint!;

  // Batch C (V-12): the initiator binds its OWN dials, never the relay row's
  if (!state.dials) throw new Error('Handshake state incomplete — start a new chat.');
  let rootKey: Uint8Array;
  if (state.contact) {
    // contact: root (and the signing pairs) were derived at create from the
    // peer's signed prekeys; the transcript is finished here (NF-7).
    const cp = state.contactPending;
    if (!cp) throw new Error('Handshake state incomplete — start a new chat.');
    rootKey = state.rootKey;
    state.fingerprint = await contactFingerprint(
      token, cp.initiatorIkPub, cp.responderIkPub, cp.ekPub, cp.spkPub, cp.pqPub, cp.pqCt,
      state.hsPub, responderPub, responderRatchetPub, state.dials, fromB64(cp.sharedHash),
    );
    state.contactPending = null;
  } else {
    requirePqCt(responderPqCt, 'invite join');
    if (!state.pqPriv || !state.pqPub || !state.ppSecret) throw new Error('Handshake state incomplete — ask for a fresh invite.');
    const shared = combine(combine(dh(state.hsPriv, responderPub), await mlkemDecap(state.pqPriv, responderPqCt as string)), state.ppSecret);
    rootKey = await deriveRk0(shared, token);
    const sig = await deriveSigPairs(rootKey, token, 'initiator');
    state.sigPrivB64 = sig.privB64;
    state.sigPubB64 = sig.pubB64;
    state.fingerprint = await inviteFingerprint(token, state.hsPub, responderPub, responderRatchetPub, state.pqPub, responderPqCt as string, state.dials, shared);
  }
  const step = await pqStepPair();
  const root1 = await deriveRoot(rootKey, dh(state.hsPriv, responderRatchetPub), null);
  const ratchet = x25519Pair();
  const root2 = await deriveRoot(root1.rk, dh(ratchet.priv, responderRatchetPub), null);

  state.rootKey = root2.rk;
  state.ratchetPriv = ratchet.priv;
  state.ratchetPub = ratchet.pub;
  state.remoteRatchetPub = responderRatchetPub;
  state.bound = { initiatorPub: state.hsPub, responderPub, responderRatchetPub };
  state.sendChain = root2.ck;
  state.recvChain = root1.ck;
  state.sendCount = 0;
  state.prevSendCount = 0;
  state.recvCount = 0;
  state.skipped = new Map();
  state.processedIds = new Set<string>();
  state.myPubs = new Set([ratchet.pub]);
  state.pqStepPriv = step.priv;
  state.pqStepPub = step.pub;
  state.pendingPqCt = null;
  // the handshake ML-KEM key and link secret are single-use: drop them
  state.pqPriv = null;
  state.ppSecret = null;
  // Batch H (round-6 review R6-1-07): the handshake DH key is single-use too — it was
  // kept (and saved, and moved in transfers) for the life of the chat
  state.hsPriv = new Uint8Array(32);
  state.ready = true;
  return state.fingerprint!;
}

// ---------- ratchet step ----------

async function stepRatchet(state: RatchetState, header: EnvelopeHeader): Promise<void> {
  if (header.rp === state.ratchetPub) return; // own pub echoed (multi-tab guard) — no step
  if (state.seenRemotePubs.has(header.rp)) {
    throw new Error('Stale ratchet header — this message belongs to an already-replaced key epoch.');
  }
  // verify BEFORE any DH work or state mutation (runs on the candidate state)
  verifyRatchetPubSig(state, header);
  requirePqPub(header.pq, 'ratchet step');
  let pqRekeySecret: Uint8Array | null = null;
  if (header.pqct) {
    if (!state.pqStepPriv) throw new Error('Post-quantum step key missing — the session is desynchronised.');
    pqRekeySecret = await mlkemDecap(state.pqStepPriv, requirePqCt(header.pqct, 'ratchet step'));
  }
  const { ct, secret: pqAnswerSecret } = await mlkemEncap(header.pq as string);
  state.pendingPqCt = ct;
  if (!state.ratchetPriv) throw new Error('No ratchet key for this session.');
  const rootA = await deriveRoot(state.rootKey, dh(state.ratchetPriv, header.rp), pqRekeySecret);
  const fresh = x25519Pair();
  const rootB = await deriveRoot(rootA.rk, dh(fresh.priv, header.rp), pqAnswerSecret);
  const step = await pqStepPair();
  state.prevSendCount = state.sendCount;
  state.sendCount = 0;
  state.recvCount = 0;
  state.rootKey = rootB.rk;
  state.ratchetPriv = fresh.priv;
  state.ratchetPub = fresh.pub;
  if (state.remoteRatchetPub) {
    state.seenRemotePubs.add(state.remoteRatchetPub);
    while (state.seenRemotePubs.size > MAX_SEEN_PUBS) state.seenRemotePubs.delete(state.seenRemotePubs.keys().next().value as string);
  }
  state.remoteRatchetPub = header.rp;
  state.sendChain = rootB.ck;
  state.recvChain = rootA.ck;
  state.myPubs.add(state.ratchetPub);
  while (state.myPubs.size > MAX_MY_PUBS) state.myPubs.delete(state.myPubs.keys().next().value as string);
  state.pqStepPriv = step.priv;
  state.pqStepPub = step.pub;
}

// ---------- chain catch-up ----------

async function messageKeyFor(state: RatchetState, n: number): Promise<Uint8Array> {
  if (!state.recvChain) throw new Error('No receive chain for this message');
  if (n < state.recvCount || n - state.recvCount > MAX_COUNTER_GAP) {
    throw new Error('Message counter out of range — the session is desynchronised.');
  }
  while (state.recvCount < n) {
    const step = await advanceChain(state.recvChain);
    state.recvChain = step.ck;
    storeSkipped(state, state.remoteRatchetPub!, state.recvCount, step.mk);
    state.recvCount += 1;
  }
  const step = await advanceChain(state.recvChain);
  state.recvChain = step.ck;
  state.recvCount += 1;
  return step.mk;
}

// ---------- per-message pseudonym ----------

/**
 * SPEC §4: sender_client_id = 'a' + lowercaseHex(SHA-256(UTF8(rp_string)))
 * from the FIRST 6 BYTES of the digest (12 hex chars, 13 total).
 * The relay verifies this against the envelope header.
 */
export async function senderPseudonym(headerJson: string): Promise<string> {
  const rp = (JSON.parse(headerJson) as { rp?: string }).rp || '';
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(rp) as unknown as BufferSource));
  return 'a' + [...h.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------- send ----------

/** Returns the envelope to submit to the relay. */
export async function encryptMessage(state: RatchetState, text: string, opts: { cover?: boolean; envelopeId?: string } = {}): Promise<Envelope> {
  if (!state.ready) throw new Error('Session keys not established. The session may have ended or locked.');
  if (!state.pqStepPub) {
    const step = await pqStepPair();
    state.pqStepPriv = step.priv;
    state.pqStepPub = step.pub;
  }
  const step = await advanceChain(state.sendChain!);
  state.sendChain = step.ck;
  const header: EnvelopeHeader = {
    v: state.proto,
    rp: state.ratchetPub,
    pn: state.prevSendCount,
    n: state.sendCount,
    pq: state.pqStepPub!,
  };
  // The ct is re-sent until the sender's NEXT rotation replaces it: the
  // re-send IS the delivery mechanism for the PQ re-key (a lost first copy
  // must not desync the chains). A stale ct decaps to a harmless pseudorandom
  // secret on the peer's current step key.
  if (state.pendingPqCt) header.pqct = state.pendingPqCt;
  header.sig = signRatchetPub(state, header.rp, header.pq);
  state.sendCount += 1;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const headerStr = JSON.stringify(header);
  const key = await importAesKey(step.mk);
  const padded = padPlaintext(text, !!opts.cover);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: utf8(headerStr) as BufferSource }, key, padded as BufferSource);
  return { ciphertext: toB64(new Uint8Array(ct)), iv: toB64(iv), header: headerStr, byteLength: padded.length };
}

// ---------- receive ----------

export interface DecryptedMessage { text: string; cover: boolean }

/** Decrypts an envelope. `envelope.header` is the serialized header (AAD). */
export async function decryptMessage(state: RatchetState, envelope: Envelope, envelopeId?: string): Promise<DecryptedMessage | null> {
  if (!state.ready) throw new Error('Session keys not established. The session may have ended or locked.');
  const header = JSON.parse(envelope.header) as EnvelopeHeader;
  if (!(RATCHET_PROTOCOL_SUPPORTED as readonly string[]).includes(header.v)) throw new Error('Unsupported protocol version in message header.');
  // an envelope whose header rp is one of OUR pubs is our own echo
  if (state.myPubs.has(header.rp)) return null;
  if (envelopeId && state.processedIds.has(envelopeId)) return null; // idempotent replay guard
  // Work on an isolated candidate state: a malformed envelope must not consume
  // skipped keys, advance receive counters, or rotate root keys before AEAD
  // authentication succeeds.
  const candidate: RatchetState = {
    ...state,
    seenRemotePubs: new Set(state.seenRemotePubs),
    myPubs: new Set(state.myPubs),
    processedIds: new Set(state.processedIds),
    skipped: new Map([...state.skipped].map(([rp, keys]) => [rp, new Map(keys)])),
  };
  let mk = takeSkipped(candidate, header);
  if (!mk) {
    if (header.rp !== state.remoteRatchetPub) {
      // Batch D (D-12, RV-21): authenticate the rotation BEFORE any chain work —
      // a forged header must not make this device derive up to MAX_COUNTER_GAP keys
      if (header.rp !== candidate.ratchetPub) {
        if (candidate.seenRemotePubs.has(header.rp)) throw new Error('Stale ratchet header — this message belongs to an already-replaced key epoch.');
        verifyRatchetPubSig(candidate, header);
      }
      await skipOldChainBeforeRotation(candidate, header.pn);
      await stepRatchet(candidate, header);
    }
    mk = await messageKeyFor(candidate, header.n);
  }
  const key = await importAesKey(mk);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(envelope.iv) as BufferSource, additionalData: utf8(envelope.header) as BufferSource },
    key,
    fromB64(envelope.ciphertext) as BufferSource,
  );
  const { text, cover } = unpadPlaintext(new Uint8Array(pt));
  if (envelopeId) {
    candidate.processedIds.add(envelopeId);
    if (candidate.processedIds.size > MAX_PROCESSED_IDS) candidate.processedIds.delete(candidate.processedIds.keys().next().value as string);
  }
  Object.assign(state, candidate); // commit only after authenticated decrypt + frame parse
  return { text, cover };
}

// ---------- persistence ----------

export interface RatchetStateSerialized {
  proto: string;
  role: SessionRole;
  seenRemotePubs: string[];
  contact: boolean;
  ready: boolean;
  fingerprint: string | null;
  pq: 'hybrid';
  writeSecret: string | null;
  hsPub: string;
  hsPrivB64: string;
  bound: RatchetState['bound'];
  pqPub: string | null;
  pqPriv: string | null;
  pqStepPriv: string | null;
  pqStepPub: string | null;
  pendingPqCt: string | null;
  sigPrivB64: string | null;
  sigPubB64: string | null;
  dials: string | null;
  contactPending: RatchetState['contactPending'];
  ppSecretB64: string | null;
  ratchetPub: string;
  ratchetPrivB64: string | null;
  remoteRatchetPub: string | null;
  myPubs: string[];
  rootKeyB64: string;
  sendChainB64: string | null;
  recvChainB64: string | null;
  sendCount: number;
  prevSendCount: number;
  recvCount: number;
  processedIds: string[];
  skipped: Array<[string, Array<[number, string]>]>;
}

/** True when a stored session predates the current protocol (b54 hard cut; Batch C: veil-ratchet-6). */
export function isLegacySessionState(data: unknown): boolean {
  return !!data && typeof data === 'object' && (data as { proto?: unknown }).proto !== RATCHET_PROTOCOL_LATEST;
}

export async function serializeRatchetState(state: RatchetState): Promise<RatchetStateSerialized> {
  return {
    proto: state.proto,
    role: state.role,
    seenRemotePubs: [...state.seenRemotePubs],
    contact: state.contact,
    ready: state.ready,
    fingerprint: state.fingerprint,
    pq: state.pq,
    writeSecret: state.writeSecret,
    hsPub: state.hsPub,
    hsPrivB64: toB64(state.hsPriv),
    bound: state.bound,
    pqPub: state.pqPub,
    pqPriv: state.pqPriv,
    pqStepPriv: state.pqStepPriv,
    pqStepPub: state.pqStepPub,
    pendingPqCt: state.pendingPqCt,
    sigPrivB64: state.sigPrivB64,
    sigPubB64: state.sigPubB64,
    dials: state.dials,
    contactPending: state.contactPending,
    ppSecretB64: state.ppSecret ? toB64(state.ppSecret) : null,
    ratchetPub: state.ratchetPub,
    ratchetPrivB64: state.ratchetPriv ? toB64(state.ratchetPriv) : null,
    remoteRatchetPub: state.remoteRatchetPub,
    myPubs: [...state.myPubs],
    rootKeyB64: toB64(state.rootKey),
    sendChainB64: state.sendChain ? toB64(state.sendChain) : null,
    recvChainB64: state.recvChain ? toB64(state.recvChain) : null,
    sendCount: state.sendCount,
    prevSendCount: state.prevSendCount,
    recvCount: state.recvCount,
    processedIds: [...state.processedIds],
    skipped: [...state.skipped.entries()].map(([rp, m]) => [rp, [...m.entries()].map(([n, mk]) => [n, toB64(mk)])] as [string, Array<[number, string]>]),
  };
}

export async function deserializeRatchetState(data: RatchetStateSerialized): Promise<RatchetState> {
  if (isLegacySessionState(data) || data.pq !== 'hybrid') throw new LegacySessionError();
  return {
    role: data.role,
    proto: data.proto,
    seenRemotePubs: new Set(data.seenRemotePubs ?? []),
    contact: data.contact,
    ready: data.ready,
    fingerprint: data.fingerprint,
    pq: 'hybrid',
    writeSecret: data.writeSecret ?? null,
    // Batch H (R6-1-07): a completed chat needs no handshake key; older saves drop it here
    hsPriv: data.ready ? new Uint8Array(32) : fromB64(data.hsPrivB64),
    hsPub: data.hsPub,
    bound: data.bound,
    pqPub: data.pqPub ?? null,
    pqPriv: data.pqPriv,
    pqStepPriv: data.pqStepPriv,
    pqStepPub: data.pqStepPub,
    pendingPqCt: data.pendingPqCt,
    sigPrivB64: data.sigPrivB64 ?? null,
    sigPubB64: data.sigPubB64 ?? null,
    dials: data.dials ?? null,
    contactPending: data.contactPending ?? null,
    ppSecret: data.ppSecretB64 ? fromB64(data.ppSecretB64) : null,
    ratchetPriv: data.ratchetPrivB64 ? fromB64(data.ratchetPrivB64) : null,
    ratchetPub: data.ratchetPub,
    remoteRatchetPub: data.remoteRatchetPub,
    myPubs: new Set(data.myPubs),
    rootKey: fromB64(data.rootKeyB64),
    sendChain: data.sendChainB64 ? fromB64(data.sendChainB64) : null,
    recvChain: data.recvChainB64 ? fromB64(data.recvChainB64) : null,
    sendCount: data.sendCount,
    prevSendCount: data.prevSendCount,
    recvCount: data.recvCount,
    processedIds: new Set(data.processedIds),
    skipped: new Map(data.skipped.map(([rp, m]) => [rp, new Map(m.map(([n, mkB64]) => [n, fromB64(mkB64)]))])),
  };
}
