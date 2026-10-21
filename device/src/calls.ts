/**
 * @veil/device — ENCRYPTED CALLS core (W2, design docs/encrypted-calls-design.md S3).
 *
 * Threat-model-first layering; nothing here touches the message ratchet:
 *  - L1 (setup): call signaling rides the EXISTING hybrid-PQ session
 *    envelopes (same submitEnvelope channel as chat). A call message is a
 *    control payload tagged __veil_call — indistinguishable from chat at
 *    the relay, ratcheted exactly like a chat message.
 *  - L2 (transport): DTLS-SRTP via WebRTC — NOT this module (W1 native spike).
 *  - L3 (inner layer): every encoded media frame is sealed AGAIN with
 *    AES-GCM-256 under a fresh per-call secret exchanged ONLY inside L1 —
 *    so L3's key establishment inherits the PQ hybrid. The secret is pure
 *    randomness: a call can never burn ratchet keys or advance message
 *    counters (the isolation property is tested in repro/b143_calls.test.ts).
 *
 * Integrity monitor (S3b): LOCAL-ONLY, append-only, per-call event log.
 * Classifies fingerprint hard-fails, AEAD tamper, replay, degradation.
 * Never uploaded; wiped by the same paths as all local data.
 *
 * v1 scope (owner sign-off 1 Oct 2026): audio-only, third-party TURN
 * (disclosed), in-app ring (CallKit deferred to its own submission),
 * public name "call integrity monitor".
 */

import { toB64, fromB64, randomBytes, senderPseudonym } from '../../crypto-core/src/index';
import { serializeRatchetSend } from './send-queue';
import { saveOrThrow } from './save-strict';

export const CALL_CONTROL_TAG = '__veil_call';

// ---------------------------------------------------------------------------
// L3 — inner per-frame AEAD with sliding-window replay detection
// ---------------------------------------------------------------------------

/** Fresh, pure-random 32-byte call secret. NEVER derived from ratchet state. */
export function newCallSecretB64(): string {
  return toB64(randomBytes(32));
}

/**
 * L3 frame sealing. Nonce = 12 bytes = 4-byte direction tag + 8-byte
 * big-endian frame counter, so both sides can track and reject replays with
 * a sliding window (IPsec-AH style): frames must arrive strictly increasing
 * or inside a 64-counter reorder window; anything older is a replay event.
 */
export class CallFrameCrypto {
  private sendCounter = 0;
  private highestSeen = -1;
  private readonly window: Set<number> = new Set();
  private readonly dirTag: Uint8Array;
  /** b143: the tag we REQUIRE on inbound frames — the PEER's direction. A
   *  frame sealed with our own tag (a reflection attack) fails here. */
  private readonly peerTag: number;

  /** dir: OUR sending direction — 'A' for the caller, 'B' for the callee.
   *  Keeps the two directions' nonce spaces disjoint; open() binds inbound
   *  frames to the peer's tag so a reflected frame never decrypts. */
  constructor(private secretB64: string, dir: 'A' | 'B') {
    this.dirTag = new Uint8Array([dir.charCodeAt(0), 0, 0, 1]);
    this.peerTag = dir === 'A' ? 0x42 : 0x41; // 'B' / 'A'
  }

  private async key(): Promise<CryptoKey> {
    return crypto.subtle.importKey('raw', fromB64(this.secretB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  /** Seal one outbound encoded frame. Returns nonce || ciphertext||tag. */
  async seal(frame: Uint8Array): Promise<Uint8Array> {
    if (this.sendCounter >= Number.MAX_SAFE_INTEGER) throw new Error('Call frame counter exhausted.');
    const nonce = new Uint8Array(12);
    nonce.set(this.dirTag, 0);
    const c = this.sendCounter++;
    new DataView(nonce.buffer).setBigUint64(4, BigInt(c));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce as unknown as BufferSource }, await this.key(), frame as unknown as BufferSource));
    const out = new Uint8Array(12 + ct.length);
    out.set(nonce, 0); out.set(ct, 12);
    return out;
  }

  /**
   * Open one inbound frame. Returns the plaintext, or a classified failure:
   *  - 'replay': counter already seen (inside or behind the window)
   *  - 'tamper': AEAD authentication failure (bit-flips, truncation, wrong key)
   */
  async open(sealed: Uint8Array): Promise<{ ok: true; frame: Uint8Array } | { ok: false; reason: 'replay' | 'tamper' }> {
    if (sealed.length < 12 + 16) return { ok: false, reason: 'tamper' };
    const nonce = sealed.slice(0, 12);
    // b143 direction binding: reject our own tag (reflection) and any
    // malformed nonce prefix — classified tamper, never a key attempt.
    if (nonce[0] !== this.peerTag || nonce[1] !== 0 || nonce[2] !== 0 || nonce[3] !== 1) {
      return { ok: false, reason: 'tamper' };
    }
    const counter = Number(new DataView(nonce.buffer, nonce.byteOffset, 12).getBigUint64(4));
    if (counter <= this.highestSeen - 64) return { ok: false, reason: 'replay' };
    if (this.window.has(counter)) return { ok: false, reason: 'replay' };
    if (counter > this.highestSeen) {
      for (const c of this.window) if (c <= counter - 64) this.window.delete(c);
      this.highestSeen = counter;
    }
    try {
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce as unknown as BufferSource }, await this.key(), sealed.slice(12) as unknown as BufferSource));
      this.window.add(counter);
      return { ok: true, frame: pt };
    } catch {
      return { ok: false, reason: 'tamper' };
    }
  }
}

// ---------------------------------------------------------------------------
// L1 — call signaling payloads (ride the existing ratchet envelopes)
// ---------------------------------------------------------------------------

export type CallSignalOp = 'offer' | 'answer' | 'ice' | 'end' | 'ringing'; // 'ringing' (21 Oct 2026): the callee confirms the call reached its screen

export interface CallSignal {
  __veil_call: 1;
  op: CallSignalOp;
  /** 16-hex-char random id, fresh per call attempt */
  call_id: string;
  /** op=offer: the SDP offer AND the L3 secret (b64). Rides L1, so its
   *  confidentiality is PQ-hybrid by inheritance. */
  sdp?: string;
  /** op=offer only: fresh per-call L3 secret (b64, 32 bytes). */
  k?: string;
  /** op=ice: one ICE candidate, as serialized by WebRTC */
  cand?: string;
  /** op=ice (20 Oct 2026): a batch of candidates; `cand` still holds the first,
   *  so a build that predates batching reads at least that one */
  cands?: string[];
  /** op=end: 'hangup' | 'busy' | 'missed' | 'refused' */
  reason?: string;
  /** monotonic attempt number — replays of an OLD offer for the same
   *  call_id are refused by the answerer (tested). */
  seq?: number;
}

export function newCallId(): string {
  return [...randomBytes(8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function parseCallSignal(text: string): CallSignal | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_call":')) return null;
  try {
    const t = JSON.parse(text) as CallSignal;
    if (t.__veil_call !== 1 || typeof t.call_id !== 'string') return null;
    if (!['offer', 'answer', 'ice', 'end', 'ringing'].includes(t.op)) return null;
    return t;
  } catch { return null; }
}

/** True when a decrypted chat payload is a call control signal — the sync
 *  loop filters these out of the message list exactly like receipts/cover. */
export function isCallSignal(text: string): boolean {
  return parseCallSignal(text) !== null;
}

// ---------------------------------------------------------------------------
// Fingerprint binding (S3 authentication core) — the MITM guard
// ---------------------------------------------------------------------------

/** Extract the DTLS certificate fingerprint from an SDP body. WebRTC SDP
 *  carries exactly one a=fingerprint line per m= section in practice; we
 *  require ALL of them to be identical and return it, or null on none/
 *  mismatch — a mismatched set is itself a hard fail (tampered SDP). */
export function extractDtlsFingerprint(sdp: string): string | null {
  if (typeof sdp !== 'string' || sdp.length > 262144) return null; // fuzz guard: SDP beyond 256KB is hostile
  const fps = [...sdp.matchAll(/^a=fingerprint:(\S+)\s+([0-9A-Fa-f:]{16,200})\s*$/gm)];
  if (fps.length === 0) return null;
  const norm = (m: RegExpMatchArray) => `${(m[1] || '').toLowerCase()} ${(m[2] || '').toUpperCase()}`;
  const first = norm(fps[0]);
  return fps.every((m) => norm(m) === first) ? first : null;
}

export class CallRefusedError extends Error {
  constructor(public readonly code: 'fingerprint-mismatch' | 'malformed-sdp' | 'replayed-offer' | 'unknown-call') {
    super(code);
    Object.setPrototypeOf(this, CallRefusedError.prototype);
  }
}

// ---------------------------------------------------------------------------
// Integrity monitor (S3b) — LOCAL-ONLY, append-only, per call
// ---------------------------------------------------------------------------

export type CallEventClass = 'fingerprint' | 'tamper' | 'replay' | 'degraded' | 'churn';

export interface CallEvent {
  cls: CallEventClass;
  detail: string;
  ts: number;
  call_id: string;
}

/** Tamper/replay escalate to a banner after >2 events inside 10s (S3b.2). */
const TAMPER_WINDOW_MS = 10_000;
const TAMPER_BANNER_THRESHOLD = 2;

export class CallIntegrityMonitor {
  private events: CallEvent[] = [];
  constructor(private readonly callId: string) {}

  record(cls: CallEventClass, detail: string): void {
    this.events.push({ cls, detail, ts: Date.now(), call_id: this.callId });
  }

  /** >2 tamper/replay events inside the 10s window -> surface the banner. */
  bannerDue(now = Date.now()): boolean {
    const recent = this.events.filter((e) => (e.cls === 'tamper' || e.cls === 'replay') && now - e.ts <= TAMPER_WINDOW_MS);
    return recent.length > TAMPER_BANNER_THRESHOLD;
  }

  /** Amber in-call dot: any degradation events, and no hard-fail so far. */
  status(now = Date.now()): 'ok' | 'amber' | 'red' {
    if (this.events.some((e) => e.cls === 'fingerprint' || e.cls === 'churn')) return 'red';
    if (this.events.some((e) => e.cls === 'degraded') || this.bannerDue(now)) return 'amber';
    return 'ok';
  }

  /** Post-call report — device-local only, exportable by the user, wiped by
   *  NaR/duress/sign-out alongside all other local data. */
  report(): CallEvent[] { return [...this.events]; }
  /** Hard reset on call teardown — keys and counters never outlive the call. */
  destroy(): void { this.events = []; }
}

// ---------------------------------------------------------------------------
// Call state machine — the answerer-side guard rails
// ---------------------------------------------------------------------------

export type CallPhase = 'idle' | 'ringing' | 'active' | 'ended';

export interface CallState {
  callId: string;
  phase: CallPhase;
  /** fingerprint of the L1-authenticated offer — the trust anchor for the
   *  media path (answerer compares the ACTUAL DTLS handshake against it) */
  offerFingerprint: string | null;
  l3SecretB64: string | null;
  seqSeen: number;
}

/**
 * Process an inbound offer as the CALLEE. Hard-fails (CallRefusedError):
 *  - malformed-sdp: no single consistent a=fingerprint in the offer
 *  - replayed-offer: same call_id re-offered with a stale seq (a replayed
 *    envelope must never ring twice)
 *  - fingerprint-mismatch: an SDP whose fingerprint differs from the one
 *    already authenticated for this call_id (mid-call churn / MITM)
 * On success: phase -> ringing, fingerprint bound, L3 secret stored.
 */
export function processOffer(state: CallState, sig: CallSignal): CallState {
  if (sig.op !== 'offer') throw new CallRefusedError('unknown-call');
  const fp = extractDtlsFingerprint(sig.sdp ?? '');
  if (!fp) throw new CallRefusedError('malformed-sdp');
  const seq = typeof sig.seq === 'number' ? sig.seq : 0;
  if (state.callId === sig.call_id && seq <= state.seqSeen) throw new CallRefusedError('replayed-offer');
  if (state.callId === sig.call_id && state.offerFingerprint && state.offerFingerprint !== fp) {
    throw new CallRefusedError('fingerprint-mismatch');
  }
  if (!sig.k) throw new CallRefusedError('malformed-sdp');
  return { callId: sig.call_id, phase: 'ringing', offerFingerprint: fp, l3SecretB64: sig.k, seqSeen: seq };
}

/**
 * Media-path verification on the ACTIVE call: the DTLS fingerprint the
 * peer's media actually presents must equal the L1-authenticated offer
 * fingerprint. Mismatch = "someone may be in the middle — call refused"
 * (monitor: cls='fingerprint', status red).
 */
export function verifyMediaFingerprint(state: CallState, observedFp: string, monitor: CallIntegrityMonitor): boolean {
  if (!state.offerFingerprint) {
    monitor.record('fingerprint', 'no bound offer fingerprint — refusing media');
    return false;
  }
  if (normalizeFp(state.offerFingerprint) === normalizeFp(observedFp)) return true;
  monitor.record('fingerprint', 'media fingerprint differs from L1-authenticated offer — MITM suspected');
  return false;
}

function normalizeFp(fp: string): string {
  return fp.trim().replace(/\s+/g, ' ').toUpperCase();
}

/** Answerer accepts the ring: phase -> active; the answer SDP (with the
 *  callee's own DTLS fingerprint) rides L1 back via sendCallSignal. */
export function answerCall(state: CallState): CallState {
  if (state.phase !== 'ringing') throw new Error('No call is ringing.');
  return { ...state, phase: 'active' };
}

/** Any side ends the call — counters, L3 keys and monitor die with it. */
export function endCall(state: CallState, _reason: string): CallState {
  if (state.phase === 'ended') return state;
  return { ...state, phase: 'ended' };
}

// ---------------------------------------------------------------------------
// L1 transport — signaling rides the ratchet exactly like a read receipt
// ---------------------------------------------------------------------------

export interface CallRelay {
  submitEnvelope(sub: {
    session_token: string; client_id: string; write_secret: string | null;
    sender_client_id?: string; ciphertext: string; iv: string; header: unknown;
    byte_length?: number; ttl_seconds?: number; protocolVersion?: string;
  }): Promise<{ data: unknown; status: number }>;
  /** b198: the gate notify (the contentless callee wake) — optional so test
   *  doubles stay simple; the live relay client always has it. */
  invoke?: (fn: string, payload: Record<string, unknown>) => Promise<unknown>;
}

export interface CallSessionStore {
  load(token: string): Promise<unknown>;
  save(token: string, s: unknown): Promise<void>;
}

export function sendCallSignal(...args: Parameters<typeof sendCallSignalUnlocked>): ReturnType<typeof sendCallSignalUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendCallSignalUnlocked(...args));
}

async function sendCallSignalUnlocked(
  relay: CallRelay,
  sessions: CallSessionStore,
  token: string,
  clientId: string,
  sig: CallSignal,
  encrypt: (state: unknown, body: string) => Promise<{ ciphertext: string; iv: string; header: unknown; byteLength?: number }>,
  serializeState: (s: unknown) => Promise<unknown>,
  deserializeState: (s: unknown) => Promise<unknown>,
): Promise<void> {
  const sealed = await sessions.load(token) as { writeSecret?: string | null; proto?: string } | null;
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const state = await deserializeState(sealed);
  const body = JSON.stringify({ ...sig, __veil_call: 1 as const });
  const env = await encrypt(state, body);
  // Batch H (round-6 review R6-1-06): persist BEFORE send (a refused save stops the
  // signal; a step is never sent twice). b143: keep the loaded record's extras.
  await saveOrThrow(sessions, token, { ...(sealed as Record<string, unknown>), ...(await serializeState(state) as Record<string, unknown>) });
  const r = await relay.submitEnvelope({
    session_token: token,
    client_id: clientId,
    write_secret: sealed.writeSecret ?? null,
    // SPEC §4: the relay verifies the sender tag against the envelope header
    // (enforced since the b144 backend build-out). The call path previously
    // sent undefined, which native<->native hid — the web relay now rejects
    // it, so every native call offer died as a silent 400 (b145 fix).
    sender_client_id: await senderPseudonym(typeof env.header === 'string' ? env.header : JSON.stringify(env.header)),
    ciphertext: env.ciphertext,
    iv: env.iv,
    header: env.header,
    byte_length: env.byteLength ?? env.ciphertext.length,
    ttl_seconds: 300, // call setup is latency-bound; stale offers must die fast
    protocolVersion: sealed.proto ?? 'veil-ratchet-6',
  });
  const d = r.data as { status?: string; error?: string };
  if (d && typeof d === 'object' && d.status && String(d.status).toLowerCase() !== 'ok') {
    throw new Error(String(d.error ?? 'Call signal rejected by the relay.'));
  }
  // b198 (live-caught: calling a QUIT app rang into the void — the callee's
  // offer sat unfetched until the 21s ringout): fire the contentless callee
  // wake on the OFFER only. The lock screen shows "VEIL — Notification", the
  // callee opens inside the ring window, and the already-mounted overlay
  // presents the call. ICE/answer/end are machine-consumed — no push.
  if (sig.op === 'offer') {
    void relay.invoke?.('veilSessionGate', { action: 'notify', token, write_secret: sealed.writeSecret ?? null, call: true }).catch(() => undefined);
  }
  // b143 FIX (the save above): the resealed state keeps the loaded record's EXTRAS
  // (writeSecret, expire dials, burn flags, proto), as sendChatMessage's withExtras.
}
