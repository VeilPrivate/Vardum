/**
 * VEIL CallManager (b144, W3): the device-side glue that turns the tested
 * calls.ts core (L1 signaling + state machine + integrity monitor) into a
 * live audio call on react-native-webrtc.
 *
 * ARCHITECTURE (design S3, docs/encrypted-calls-design.md):
 *  L1  call setup/ICE/end signals ride the session's PQ-hybrid ratchet
 *      envelopes (sendCallSignal) — the relay sees only cipher-text.
 *  L2  media travels DTLS-SRTP inside WebRTC (transport encryption).
 *  L3  per-call fresh AES-GCM frame key travels inside L1 (CallFrameCrypto)
 *      — wired for the data-channel media path; the W1 spike rides the
 *      standard media path first (see W4 notes in the design doc).
 *
 * PRIVACY: calls go through VEIL's OWN TURN server (coturn on the VEIL VPS,
 * no third-party STUN/TURN). Short-lived credentials come from the relay
 * (veilTurnCredentials, see turnIce below) and the PC runs iceTransportPolicy
 * 'relay' — EVERY call is forced through TURN, so the two peers never learn
 * each other's IP addresses (each only sees the TURN server). Media stays
 * DTLS-SRTP end to end between the devices: TURN forwards encrypted packets
 * it cannot decrypt, so the server can't hear calls — it sees only that two
 * devices exchanged media, when, and roughly how much.
 * FALLBACK: if TURN is unavailable (relay not configured, offline, 4s
 * timeout) the call keeps the pre-TURN behaviour — no iceServers, host
 * candidates only — which connects on the same network only. A call never
 * fails just because TURN is down.
 *
 * UI CONTRACT: CallManager is a module singleton. App configures it once
 * (relay/sessions/clientId closures), syncToken feeds it inbound signals,
 * CallOverlay subscribes to snapshots. No prop drilling, no navigation.
 */
import { Platform, Vibration } from 'react-native';
import { requireOptionalNativeModule } from 'expo-modules-core';
import { createIceBatcher, iceSignalBody, candsOf, type IceBatcher, candidateInSdp } from './iceBatch';
// b149: incoming-call ringtone. expo-av is already in the dev client (media
// playback uses it), so Metro hot-reload can reach the native module.
// Respects the hardware mute switch — silent mode stays silent (vibration
// still runs); we deliberately do NOT set playsInSilentMode.
import { Audio } from 'expo-av';
import ringAsset from '../../assets/veil-ring.wav';
import ringbackAsset from '../../assets/veil-ringback.wav';
import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate, mediaDevices, type MediaStream, type MediaStreamTrack } from 'react-native-webrtc';
import {
  type CallSignal, type CallState, CallIntegrityMonitor, CallRefusedError,
  newCallId, newCallSecretB64, processOffer, answerCall, endCall,
  extractDtlsFingerprint, sendCallSignal,
} from '../../vendor/device/src/calls';
import {
  encryptMessage, serializeRatchetState, deserializeRatchetState,
} from '../../vendor/crypto-core/src/index';

export type CallUiPhase = 'calling' | 'ringing' | 'connecting' | 'active' | 'ended';

export interface CallSnapshot {
  phase: CallUiPhase;
  role: 'caller' | 'callee';
  peerLabel: string;
  callId: string;
  token: string;              // b199: the call's session, for App's call poll
  startedAt: number | null;   // epoch ms, active only
  endedReason: string | null;
  muted: boolean;
  integrity: 'ok' | 'amber' | 'red';
  reach: 'pending' | 'ringing' | 'unreachable' | null; // 21 Oct 2026: caller side, has the other phone confirmed it rings?
}

interface CallSession {
  callId: string;
  token: string;
  peerLabel: string;
  role: 'caller' | 'callee';
  phase: CallUiPhase;
  core: CallState;                 // calls.ts state machine (guard rails)
  monitor: CallIntegrityMonitor;   // local-only interference log
  pc: RTCPeerConnection | null;
  local: MediaStream | null;
  pendingIce: CallSignal[];        // ICE that arrived before remote description
  pendingOfferSdp: string | null;  // callee: the offer SDP stashed until Answer
  startedAt: number | null;
  endedReason: string | null;
  muted: boolean;
  seq: number;
  ringVib: number | null;
  timeoutHandle: ReturnType<typeof setTimeout> | null;
  mediaUp: boolean;                // b199: 'connected' already fired (may beat armConnecting)
  /** 20 Oct 2026: candidate batching and the callee prewarm */
  iceBatcher?: IceBatcher | null;
  iceRelease?: boolean;            // false while a prewarmed callee is still ringing
  heldIce: string[];               // candidates gathered before Accept
  prewarming?: Promise<void> | null;
  answering?: boolean;             // b64 test (C-5): Accept tapped, answer in progress
  gathered?: boolean;              // 21 Oct 2026: this side's candidates are all in
  firstCandAt?: number | null;     // when the first candidate arrived
  reach?: 'pending' | 'ringing' | 'unreachable'; // caller: the callee's ringing confirmation
  ackHandle?: ReturnType<typeof setTimeout> | null;
}

interface CallTransport {
  relay: () => unknown;
  sessions: () => unknown;
  clientId: () => Promise<string | null>;
}

let transport: CallTransport | null = null;
let session: CallSession | null = null;
const listeners = new Set<(s: CallSnapshot | null) => void>();

const IDLE_CORE: CallState = { callId: '', phase: 'idle', offerFingerprint: null, l3SecretB64: null, seqSeen: -1 };

const RING_PATTERN = [0, 600, 800] as number[];

// b157 missed-call tracking: a call this device never answered leaves a
// durable trace, so an offer held out by the lock (hold-until-unlock keeps
// a locked phone holding no message data — call offers are ratcheted exactly
// like chat, so they cannot bypass the hold) still surfaces as a notice.
const locallyEndedCalls = new Set<string>();
const recordedMisses = new Set<string>();

function recordMissed(callId: string, token: string, peerLabel: string): void {
  if (recordedMisses.has(callId)) return;
  recordedMisses.add(callId);
  if (recordedMisses.size > 500) recordedMisses.clear();
  try { CallManager.onMissedCall?.(token, peerLabel); } catch { /* notice must never break calls */ }
}

// b149: looping ringtone for the ringing phase. Lazy-loaded on first use;
// any audio failure degrades to vibration-only (never blocks the call).
let ringSound: Awaited<ReturnType<typeof Audio.Sound.createAsync>>['sound'] | null = null;
let ringLoading: Promise<void> | null = null;
let ringBroken = false;

// b199 (Android handover TODO): iOS's player already obeys the mute switch;
// Android's plays on the media stream, which ignores silent/vibrate. Ask the
// native module for the ringer mode (Android-only function; absent on iOS
// and on older builds → 'normal', i.e. today's behaviour).
function androidRingerMode(): 'normal' | 'vibrate' | 'silent' {
  if (Platform.OS !== 'android') return 'normal';
  try {
    const mod = requireOptionalNativeModule<{ ringerMode?: () => string }>('VeilCrypto');
    const m = mod?.ringerMode?.();
    return m === 'silent' || m === 'vibrate' ? m : 'normal';
  } catch { return 'normal'; }
}

// Call quality (owner test 20 Oct 2026: echo on the Android side): Android only
// applies its call echo cancellation and earpiece routing in call mode. iOS
// needs nothing here (WebRTC's audio session is already a voice-chat session);
// older Android builds without the function keep today's behaviour.
function callAudioMode(active: boolean): void {
  if (Platform.OS !== 'android') return;
  try {
    const mod = requireOptionalNativeModule<{ setCallAudioMode?: (on: boolean) => boolean }>('VeilCrypto');
    if (active) mod?.setCallAudioMode?.(true);
    else mod?.setCallAudioMode?.(false);
  } catch { /* audio routing is best-effort */ }
}

async function startRingtone(): Promise<void> {
  if (ringBroken) return;
  if (androidRingerMode() !== 'normal') return; // silent/vibrate: no ring sound
  try {
    if (!ringSound && !ringLoading) {
      ringLoading = Audio.Sound.createAsync(ringAsset, { isLooping: true, volume: 1.0 }).then(({ sound }) => { // b198 (owner): full volume
        ringSound = sound;
      });
    }
    await ringLoading;
    await ringSound?.setIsLoopingAsync(true);
    await ringSound?.playAsync();
  } catch (e) {
    // Native module missing from this binary, or the asset failed to load:
    // disable for this run, keep calls working, vibration still alerts.
    ringBroken = true;
    console.warn('[veil-call] ringtone unavailable (vibration-only):', (e as Error)?.message ?? e);
  }
}

async function stopRingtone(): Promise<void> {
  try { await ringSound?.stopAsync(); } catch { /* already stopped */ }
}

// Caller ringback (owner request 20 Oct 2026): the caller hears a ring
// (400+450 Hz, 0.4/0.2/0.4 s on, 2 s off) while the other phone rings. Quieter
// than the incoming ring; any audio failure just means a silent wait.
let ringbackSound: Awaited<ReturnType<typeof Audio.Sound.createAsync>>['sound'] | null = null;
let ringbackLoading: Promise<void> | null = null;
let ringbackBroken = false;

async function startRingback(s: CallSession): Promise<void> {
  if (ringbackBroken) return;
  try {
    if (Platform.OS === 'ios') {
      // b63 review (C-2): the mic is already live, so keep the shared audio
      // session record-capable (PlayAndRecord). expo-av's default is a
      // play-only category, which would cut the caller's mic.
      await Audio.setAudioModeAsync({ allowsRecordingIOS: true, playsInSilentModeIOS: true });
    }
    if (!ringbackSound && !ringbackLoading) {
      ringbackLoading = Audio.Sound.createAsync(ringbackAsset, { isLooping: true, volume: 0.45 }).then(({ sound }) => {
        ringbackSound = sound;
      });
    }
    await ringbackLoading;
    if (session !== s || s.phase !== 'calling') return; // answered or ended while loading
    await ringbackSound?.setIsLoopingAsync(true);
    if (session !== s || s.phase !== 'calling') return; // b63 review (C-3)
    await ringbackSound?.playAsync();
    // b63 review (C-3): an answer or hang-up landed during play; stop again
    if (session !== s || s.phase !== 'calling') await ringbackSound?.stopAsync();
  } catch (e) {
    ringbackBroken = true;
    console.warn('[veil-call] ringback unavailable (silent wait):', (e as Error)?.message ?? e);
  }
}

async function stopRingback(): Promise<void> {
  try { await ringbackSound?.stopAsync(); } catch { /* already stopped */ }
}
const RINGOUT_MS = 45_000; // unanswered ring dies (both directions)
// b151 FIX (live-found, owner repro Oct 1): phase was flipping to 'active'
// the moment the answer SDP was sent/received — pure signaling, no proof
// the actual P2P media path ever connected. The owner saw native show
// "Integrity verified" + a running timer while the caller's side was still
// stuck "trying to connect": two peers disagreeing about whether a call
// was live. Phase now only becomes 'active' on pc.connectionState ===
// 'connected' (see wireConnectState below); if that never happens within
// this window, the call ends honestly instead of hanging in fake-active.
const CONNECT_TIMEOUT_MS = 25_000;

function snapshot(): CallSnapshot | null {
  if (!session) return null;
  return {
    phase: session.phase,
    role: session.role,
    peerLabel: session.peerLabel,
    callId: session.callId,
    token: session.token,
    startedAt: session.startedAt,
    endedReason: session.endedReason,
    muted: session.muted,
    integrity: session.monitor.status(),
    reach: session.reach ?? null,
  };
}

function notify(): void {
  const snap = snapshot();
  for (const l of listeners) l(snap);
}

// b146: pre-offer ICE buffer — 10s TTL, swept on each offer handling pass.
const preOfferIce = new Map<string, CallSignal[]>();
setInterval(() => {
  // candidates older than 10s without an offer are dead; the window is
  // bounded by the relay's fetch cadence anyway.
  preOfferIce.clear();
}, 10000).unref?.();

function clearRing(s: CallSession): void {
  void stopRingtone();
  void stopRingback();
  // b199 (owner report: "it won't stop vibrating" after the caller hung up):
  // ringVib was never set anywhere, so this cancel never ran and the
  // repeating ring vibration outlived the call. Cancel unconditionally — it
  // is a no-op when nothing is vibrating.
  Vibration.cancel();
  s.ringVib = null;
  if (s.timeoutHandle !== null) { clearTimeout(s.timeoutHandle); s.timeoutHandle = null; }
  if (s.ackHandle) { clearTimeout(s.ackHandle); s.ackHandle = null; }
}

/** Full teardown: keys, counters and monitor die with the call (design S3b.4). */
function teardown(s: CallSession, reason: string, sendEnd: boolean): void {
  locallyEndedCalls.add(s.callId); // b157: our own decline/clear must not later count as a missed call
  if (locallyEndedCalls.size > 500) locallyEndedCalls.clear();
  clearRing(s);
  callAudioMode(false); // back to normal audio routing, always
  try { s.monitor.destroy(); } catch { /* already destroyed */ }
  try { s.pc?.close(); } catch { /* already closed */ }
  s.local?.getTracks().forEach((t) => t.stop());
  s.pc = null;
  s.local = null;
  console.log(`[veil-call] teardown: ${reason} (role ${s.role}, phase ${s.phase}, sendEnd ${sendEnd})`);
  if (sendEnd && s.phase !== 'ended') {
    // b199: the end signal used to be fire-and-forget — one 429 or network
    // blip and the peer never learned the call was over. Same one-retry rule
    // as ICE (b196).
    const send = () => signal(s.token, { __veil_call: 1, op: 'end', call_id: s.callId, reason });
    send().then(() => console.log('[veil-call] end sent')).catch((err: Error) => {
      console.log(`[veil-call] end send failed (${err.message}) — one retry in 2.5s`);
      setTimeout(() => {
        send().then(() => console.log('[veil-call] end sent on retry'))
          .catch((err2: Error) => console.log(`[veil-call] end send dropped after retry: ${err2.message}`));
      }, 2500);
    });
  }
  s.phase = 'ended';
  s.endedReason = reason;
  s.core = endCall(s.core, reason);
  notify();
  // keep the ended snapshot on screen briefly, then fully clear
  setTimeout(() => { if (session && session.callId === s.callId && session.phase === 'ended') { session = null; notify(); } }, 2200);
}

/** b63 review (C-1): the call ended, or a newer one replaced it, while
 *  start() or answer() was waiting. */
function callGone(s: CallSession): boolean {
  return session !== s || s.phase === 'ended';
}

/** b63 review (C-1): release what an abandoned start()/answer() built after
 *  teardown already ran. Audio routing is reset only when no newer call owns it. */
function abandon(s: CallSession, local: CallSession['local'], pc: CallSession['pc'], audioOn: boolean): void {
  local?.getTracks().forEach((t) => t.stop());
  try { pc?.close(); } catch { /* already closed */ }
  if (audioOn && (!session || session === s || session.phase === 'ended')) callAudioMode(false);
  console.log(`[veil-call] abandoned a ${s.role} setup: the call ended while it was starting`);
}

// 21 Oct 2026 (owner tests: 5–8 s from Answer to hearing each other): each
// side waits briefly for its own connection details and sends them INSIDE the
// offer/answer SDP, instead of as separate messages after it. Standard WebRTC,
// so older builds read them natively. Anything gathered later still trickles.
const GATHER_WAIT_CALLER_MS = 1500;
const GATHER_WAIT_CALLEE_MS = 1000;
const GATHER_SETTLE_MS = 300; // once one candidate is in, a short grace for the rest

async function waitGathered(s: CallSession, ms: number): Promise<void> {
  const until = Date.now() + ms;
  while (!s.gathered && Date.now() < until && !callGone(s)) {
    if (s.firstCandAt && Date.now() - s.firstCandAt >= GATHER_SETTLE_MS) break;
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** The local SDP as it is now (with the gathered candidates), or the fallback. */
function localSdp(pc: RTCPeerConnection, fallback: string): string {
  return (pc as unknown as { localDescription?: { sdp?: string } | null }).localDescription?.sdp || fallback;
}

/** Start trickling: send held candidates the SDP didn't already carry. */
function releaseHeldIce(s: CallSession, sdp: string): void {
  s.iceRelease = true;
  const late = s.heldIce.filter((c) => !candidateInSdp(sdp, c));
  console.log(`[veil-call] candidates: ${s.heldIce.length - late.length} in the ${s.role === 'caller' ? 'offer' : 'answer'}, ${late.length} sent after`);
  s.heldIce = [];
  for (const c of late) s.iceBatcher?.push(c);
  if (s.gathered) s.iceBatcher?.flush();
}

// 21 Oct 2026 (owner: "it sounds like it's ringing but nothing comes through"):
// the callee confirms with a 'ringing' signal. Until then the caller shows
// "Calling…" with no tone; with no confirmation in 20 s, "Not reachable yet".
// Older builds never confirm, so the call keeps going to the ringout until
// they're gone; then REQUIRE_RING_ACK ends it at 20 s.
const RING_ACK_MS = 20_000;
const REQUIRE_RING_ACK = false;

function armRingAck(s: CallSession): void {
  if (s.ackHandle) clearTimeout(s.ackHandle);
  s.ackHandle = setTimeout(() => {
    s.ackHandle = null;
    if (session !== s || s.phase !== 'calling' || s.reach === 'ringing') return;
    s.reach = 'unreachable';
    console.log('[veil-call] no ringing confirmation in 20 s (phone offline, or an older build)');
    notify();
    if (REQUIRE_RING_ACK) teardown(s, 'not reachable', true);
  }, RING_ACK_MS);
}

async function signal(token: string, sig: CallSignal): Promise<void> {
  if (!transport) throw new Error('Call transport not configured yet.');
  const relay = transport.relay();
  const sessions = transport.sessions();
  const who = await transport.clientId();
  if (!relay || !sessions || !who) throw new Error('Session not ready.');
  await sendCallSignal(
    relay as never, sessions as never, token, who, sig,
    encryptMessage as never, serializeRatchetState as never, deserializeRatchetState as never,
  );
}

function armRingout(s: CallSession): void {
  s.timeoutHandle = setTimeout(() => {
    const wasRingingCallee = s.role === 'callee';
    teardown(s, s.role === 'caller' ? 'no answer' : 'missed', true);
    if (wasRingingCallee) recordMissed(s.callId, s.token, s.peerLabel); // b157
  }, RINGOUT_MS);
}

/** b151: signaling is done (answer sent/received) but the real media path
 *  hasn't connected yet — show it honestly and give it a bounded window. */
function armConnecting(s: CallSession): void {
  s.phase = 'connecting';
  if (s.timeoutHandle !== null) clearTimeout(s.timeoutHandle);
  s.timeoutHandle = setTimeout(() => {
    if (session === s && s.phase === 'connecting') {
      teardown(s, 'call failed to connect', true);
    }
  }, CONNECT_TIMEOUT_MS);
  notify();
  // b199 (owner report Oct 16: A stuck on "Connecting" while both could talk;
  // Metro showed the caller's 'connected' event firing DURING the answer
  // handling, while the phase was still 'calling'): markConnected ignored it
  // and no second event ever came. The event is remembered, so a path that
  // came up before this point still flips the call to active.
  if (s.mediaUp) markConnected(s);
}

/** b151: the ONLY place a call becomes 'active' — real transport proof,
 *  not just a signaling exchange. */
function markConnected(s: CallSession): void {
  if (s.phase !== 'connecting') return;
  if (s.timeoutHandle !== null) { clearTimeout(s.timeoutHandle); s.timeoutHandle = null; }
  s.phase = 'active';
  s.startedAt = Date.now();
  notify();
}

// TURN credentials (relay-only internet calling). The VEIL relay mints
// short-lived coturn credentials (TURN REST scheme: username =
// "<expiry-epoch-seconds>:<id>") via veilTurnCredentials; cached until 5
// minutes before expiry. ANY failure — 503 (not configured), 401, network,
// 4s timeout, malformed body — resolves to null and the call keeps the
// host-only behaviour. Never log username/credential.
interface TurnIce {
  iceServers: { urls: string[]; username: string; credential: string }[];
}
type TurnInvoker = { invoke(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }> };
const TURN_FETCH_TIMEOUT_MS = 4_000;
const TURN_REFRESH_MARGIN_MS = 5 * 60_000;
let turnCache: { ice: TurnIce; expiresAt: number } | null = null;

function parseTurn(data: unknown): { ice: TurnIce; expiresAt: number } | null {
  const raw = (data as { iceServers?: unknown } | null)?.iceServers;
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const servers: TurnIce['iceServers'] = [];
  let expiresAt = Infinity;
  for (const e of raw as { urls?: unknown; username?: unknown; credential?: unknown }[]) {
    const urls = typeof e?.urls === 'string' ? [e.urls] : e?.urls;
    if (!Array.isArray(urls) || urls.length === 0 || !urls.every((u) => typeof u === 'string')) return null;
    if (typeof e.username !== 'string' || typeof e.credential !== 'string') return null;
    const exp = Number(e.username.split(':')[0]);
    if (!Number.isFinite(exp) || exp <= 0) return null;
    expiresAt = Math.min(expiresAt, exp * 1000);
    servers.push({ urls: urls as string[], username: e.username, credential: e.credential });
  }
  return { ice: { iceServers: servers }, expiresAt };
}

/** TURN credentials for this call, or null (host-only fallback). */
async function turnIce(): Promise<TurnIce | null> {
  if (turnCache && turnCache.expiresAt - TURN_REFRESH_MARGIN_MS > Date.now()) {
    console.log(`[veil-call] turn: cache hit, ${turnCache.ice.iceServers.length} server(s), relay-only`);
    return turnCache.ice;
  }
  turnCache = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    const relay = transport?.relay() as TurnInvoker | null | undefined;
    if (!relay || typeof relay.invoke !== 'function') throw new Error('relay not ready');
    const timeout = new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), TURN_FETCH_TIMEOUT_MS); });
    const res = await Promise.race([relay.invoke('veilTurnCredentials', {}), timeout]);
    const got = parseTurn(res.data);
    if (!got) throw new Error('malformed credentials');
    if (got.expiresAt - TURN_REFRESH_MARGIN_MS <= Date.now()) throw new Error('credentials already near expiry');
    turnCache = got;
    console.log(`[veil-call] turn: ${got.ice.iceServers.length} server(s), relay-only`);
    return got.ice;
  } catch (e) {
    console.log(`[veil-call] turn unavailable (${(e as Error)?.message ?? e}) — same-network only`);
    return null;
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

async function makePc(s: CallSession, ice: TurnIce | null): Promise<RTCPeerConnection> {
  // Relay-only through VEIL's own TURN when credentials were obtained,
  // otherwise the pre-TURN host-only config (privacy note in the header).
  // iceCandidatePoolSize (20 Oct 2026): start the relay allocations as soon as
  // the connection exists, so they're ready by the time the offer/answer is set.
  const pc = ice
    ? new RTCPeerConnection({ iceServers: ice.iceServers, iceTransportPolicy: 'relay', iceCandidatePoolSize: 1 } as never)
    : new RTCPeerConnection({ iceServers: [] });
  // rn-webrtc extends event-target-shim whose generics don't resolve under
  // bundler moduleResolution — the listeners are structurally sound at
  // runtime, so a narrow structural cast keeps tsc green without weakening
  // any other call on the PC surface.
  const pcEv = pc as unknown as {
    addEventListener(type: 'icecandidate', l: (e: { candidate: RTCIceCandidate | null }) => void): void;
    addEventListener(type: 'connectionstatechange', l: () => void): void;
  };
  // Call quality (20 Oct 2026): candidates go in batches (src/calls/iceBatch.ts)
  // — one ratchet message per short window instead of one per candidate.
  const batcher = createIceBatcher(async (cands) => {
    const send = () => signal(s.token, iceSignalBody(s.callId, cands));
    // b196 (owner Metro log Oct 12: 429s dropped 4 of 9 ICE sends mid-call —
    // the LAN path survived on the ones that got through): one delayed retry
    // before dropping. A batch 2.5s late is still comfortably inside the
    // gathering + connect window, and skips are silent call-quality losses.
    await send().catch((err: Error) => {
      console.log(`[veil-call] ice send failed (${err.message}) — one retry in 2.5s`);
      setTimeout(() => {
        send().catch((err2: Error) => console.log(`[veil-call] ice send dropped after retry: ${err2.message}`));
      }, 2500);
    });
  });
  s.iceBatcher = batcher;
  pcEv.addEventListener('icecandidate', (e) => {
    if (!e.candidate) { s.gathered = true; if (s.iceRelease) batcher.flush(); return; } // null candidate = end-of-gathering
    s.firstCandAt = s.firstCandAt ?? Date.now();
    const cand = JSON.stringify({ candidate: e.candidate.candidate, sdpMid: e.candidate.sdpMid ?? null, sdpMLineIndex: e.candidate.sdpMLineIndex ?? null });
    // a prewarmed callee holds its candidates until the call is accepted
    if (s.iceRelease) batcher.push(cand); else s.heldIce.push(cand);
  });
  pcEv.addEventListener('connectionstatechange', () => {
    const st = pc.connectionState;
    console.log(`[veil-call] connection: ${st} (role ${s.role}, phase ${s.phase})`);
    // b151: this is the real signal — the only trustworthy "it's actually
    // live" event for either side (on the host-only fallback, cross-network
    // pairs correctly keep showing "Connecting…" — there is no path).
    if (st === 'connected') { s.mediaUp = true; markConnected(s); void logPath(pc); return; }
    if (st === 'disconnected' || st === 'failed' || st === 'closed') s.mediaUp = false;
    if (st === 'failed') {
      s.monitor.record('degraded', 'media path failed to establish');
      if (s.phase === 'connecting') { teardown(s, 'call failed to connect', true); return; }
      notify();
    }
    if (st === 'disconnected' && s.phase === 'active') { s.monitor.record('degraded', 'media path dropped mid-call'); notify(); }
  });
  return pc;
}

/** Call quality (20 Oct 2026): while a call rings, the callee fetches relay
 *  credentials, builds its connection and applies the offer, so the relay
 *  allocations are underway before Accept. Nothing is sent: candidates are
 *  held until the call is accepted (iceRelease), and a declined or missed
 *  call just closes the connection in teardown. Any failure leaves answer()
 *  to build it the old way. */
async function prewarm(s: CallSession): Promise<void> {
  try {
    const ice = await turnIce();
    if (session !== s || s.phase !== 'ringing' || s.pc) return;
    const pc = await makePc(s, ice);
    if (session !== s || s.phase !== 'ringing') { try { pc.close(); } catch { /* closed */ } return; }
    s.pc = pc;
    const offer = s.pendingOfferSdp;
    if (offer) {
      await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: offer }) as never);
      for (const c of s.pendingIce) await addIce(pc, c).catch(() => undefined);
      s.pendingIce = [];
    }
  } catch (e) {
    console.log(`[veil-call] prewarm skipped: ${(e as Error).message}`);
    try { s.pc?.close(); } catch { /* closed */ }
    s.pc = null;
  }
}

/** Which path the call took (relay vs host) — candidate types only, never
 *  addresses. Best-effort: stats shapes vary, any failure is silent. */
async function logPath(pc: RTCPeerConnection): Promise<void> {
  try {
    const report = (await pc.getStats()) as unknown as Map<string, Record<string, unknown>>;
    const all = Array.from(report.values());
    const byId = new Map(all.map((r) => [r.id as string, r]));
    const tr = all.find((r) => r.type === 'transport' && r.selectedCandidatePairId);
    const pair = (tr && byId.get(tr.selectedCandidatePairId as string))
      ?? all.find((r) => r.type === 'candidate-pair' && r.state === 'succeeded' && (r.selected || r.nominated));
    if (!pair) return;
    const local = byId.get(pair.localCandidateId as string)?.candidateType ?? '?';
    const remote = byId.get(pair.remoteCandidateId as string)?.candidateType ?? '?';
    console.log(`[veil-call] path: local ${String(local)} / remote ${String(remote)}`);
  } catch { /* diagnostics only */ }
}

/** Attach the mic to the PC — addTrack (rn-webrtc has no addStream). */
function attachMic(pc: RTCPeerConnection, local: MediaStream): void {
  const track: MediaStreamTrack | undefined = local.getAudioTracks()[0];
  if (!track) throw new Error('No audio track from the microphone.');
  pc.addTrack(track, local);
}

async function captureMic(): Promise<MediaStream> {
  // Call quality (20 Oct 2026): ask for WebRTC's echo cancellation, noise
  // suppression and gain control explicitly (the bare default left them to
  // the device, and the ZTE test phone echoed).
  const stream = (await mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    video: false,
  } as never)) as unknown as MediaStream;
  return stream;
}

export const CallManager = {
  /** App wires this once the session context exists (App.tsx). */
  configure(t: CallTransport): void { transport = t; },

  subscribe(l: (s: CallSnapshot | null) => void): () => void {
    listeners.add(l);
    l(snapshot());
    return () => { listeners.delete(l); };
  },

  snapshot,

  /** Caller path: start ringing out. */
  async start(token: string, peerLabel: string): Promise<void> {
    if (session && (session.phase === 'calling' || session.phase === 'ringing' || session.phase === 'connecting' || session.phase === 'active')) {
      throw new Error('A call is already in progress.');
    }
    const callId = newCallId();
    const s: CallSession = {
      callId, token, peerLabel, role: 'caller', phase: 'calling',
      core: { ...IDLE_CORE, callId }, monitor: new CallIntegrityMonitor(callId),
      pc: null, local: null, pendingIce: [], pendingOfferSdp: null, startedAt: null, endedReason: null,
      muted: false, seq: 1, ringVib: null, timeoutHandle: null, mediaUp: false,
      iceBatcher: null, iceRelease: false, heldIce: [], prewarming: null, reach: 'pending',
    };
    session = s;
    notify();
    armRingout(s);
    let local: CallSession['local'] = null, pc: CallSession['pc'] = null, audioOn = false;
    try {
      const [mic, ice] = await Promise.all([captureMic(), turnIce()]);
      local = mic;
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; } // hung up during the mic prompt / TURN
      s.local = local;
      callAudioMode(true); // Android call mode: echo cancellation + earpiece/headset
      audioOn = true;
      pc = await makePc(s, ice);
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      s.pc = pc;
      attachMic(pc, s.local);
      const offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false });
      await pc.setLocalDescription(offer as never);
      await waitGathered(s, GATHER_WAIT_CALLER_MS); // 21 Oct 2026: details ride in the offer
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      const offerSdp = localSdp(pc, (offer as unknown as { sdp: string }).sdp);
      await signal(token, {
        __veil_call: 1, op: 'offer', call_id: callId, seq: s.seq,
        sdp: offerSdp,
        k: newCallSecretB64(),
      });
      if (callGone(s)) return; // teardown already closed what s holds
      releaseHeldIce(s, offerSdp);
      armRingAck(s); // the ringing tone waits for the callee's confirmation
      notify();
    } catch (e) {
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      teardown(s, 'could not start the call', false);
      throw e;
    }
  },

  /** Callee accepted the ring. */
  async answer(): Promise<void> {
    const s = session;
    // b64 test (C-5, live-found 21 Oct): on a slow network the first Accept
    // takes seconds; a second tap re-ran the answer on the same connection,
    // which failed and ended the call. Only the first tap counts.
    if (!s || s.phase !== 'ringing' || s.role !== 'callee' || s.answering) return;
    s.answering = true;
    void stopRingtone(); // feedback that the tap registered
    let local: CallSession['local'] = null, pc: CallSession['pc'] = null, audioOn = false;
    try {
      // 20 Oct 2026: let a prewarm that's still running finish, then reuse it
      const [mic] = await Promise.all([captureMic(), s.prewarming ?? Promise.resolve()]);
      local = mic;
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; } // the caller hung up meanwhile
      s.local = local;
      callAudioMode(true); // Android call mode: echo cancellation + earpiece/headset
      audioOn = true;
      pc = s.pc ?? await makePc(s, await turnIce());
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      s.pc = pc;
      attachMic(pc, s.local);
      const offer = s.pendingOfferSdp;
      if (!offer) throw new Error('No offer SDP for this call.');
      if (!(pc as unknown as { remoteDescription?: unknown }).remoteDescription) {
        await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: offer }) as never);
      }
      // flush ICE that arrived before the remote description existed
      for (const ice of s.pendingIce) await addIce(pc, ice);
      s.pendingIce = [];
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer as never);
      await waitGathered(s, GATHER_WAIT_CALLEE_MS); // 21 Oct 2026: details ride in the answer
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; } // never answer a dead call
      s.core = answerCall(s.core);
      const answerSdp = localSdp(pc, (answer as unknown as { sdp: string }).sdp);
      await signal(s.token, {
        __veil_call: 1, op: 'answer', call_id: s.callId, sdp: answerSdp,
      });
      if (callGone(s)) return; // teardown already closed what s holds
      // accepted: anything the answer didn't carry trickles now
      releaseHeldIce(s, answerSdp);
      clearRing(s);
      armConnecting(s);
    } catch (e) {
      console.log(`[veil-call] answer failed: ${(e as Error).message}`);
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      teardown(s, 'call failed to connect', true);
    }
  },

  /** Callee declined. */
  decline(): void {
    const s = session;
    if (!s || s.phase !== 'ringing' || s.role !== 'callee') return;
    teardown(s, 'declined', true);
  },

  /** Either side hangs up. */
  hangup(): void {
    const s = session;
    if (!s || s.phase === 'ended') return;
    teardown(s, 'hangup', true);
  },

  /** b157: set by App — receives (threadToken, peerLabel) exactly once per
   *  missed call, and persists it into the thread's pending notices. */
  onMissedCall: null as ((threadToken: string, peerLabel: string) => void) | null,

  toggleMute(): void {
    const s = session;
    if (!s || s.phase !== 'active') return;
    s.muted = !s.muted;
    s.local?.getAudioTracks().forEach((t) => { t.enabled = !s.muted; });
    notify();
  },

  /** Entry point from syncToken: every call signal the sync decrypted.
   *  peerLabel (b152): the background sync path has no open thread UI to
   *  source a name from, so App passes the session row's title alongside. */
  async handleSignals(token: string, sigs: CallSignal[], peerLabel?: string): Promise<void> {
    // b157: a batch holding BOTH the offer and the caller's end for the same
    // call_id is a call that died before this device could ring (typically
    // the offer was held while the app was locked) — record the miss and
    // never ring a dead call.
    const ended = new Set(sigs.filter((x) => x.op === 'end').map((x) => x.call_id));
    for (const sig of sigs) {
      if (sig.op === 'offer' && ended.has(sig.call_id)) {
        recordMissed(sig.call_id, token, peerLabel ?? 'Vardum contact');
        continue;
      }
      await this.handleSignal(token, sig, peerLabel);
    }
  },

  async handleSignal(token: string, sig: CallSignal, peerLabel?: string): Promise<void> {
    const s = session;
    console.log(`[veil-call] signal in: ${sig.op} (this call ${s?.callId === sig.call_id ? 'yes' : 'no'}, phase ${s?.phase ?? 'none'})`);
    switch (sig.op) {
      case 'offer': {
        if (s && s.phase === 'ringing' && s.callId !== sig.call_id) {
          // b63 review (C-4): a newer call replaces one still ringing; end the
          // old one properly (its connection, timers, and its caller's ring)
          teardown(s, 'replaced by a newer call', true);
        }
        if (s && (s.phase === 'calling' || s.phase === 'connecting' || s.phase === 'active')) {
          // busy — refuse politely so the caller's UI clears fast
          await signal(token, { __veil_call: 1, op: 'end', call_id: sig.call_id, reason: 'busy' }).catch(() => undefined);
          return;
        }
        const core = s && s.callId === sig.call_id ? s.core : { ...IDLE_CORE, callId: sig.call_id };
        try {
          const next = processOffer(core, sig);
          const fresh: CallSession = {
            callId: sig.call_id, token, peerLabel: peerLabel ?? s?.peerLabel ?? 'Vardum contact',
            role: 'callee', phase: 'ringing', core: next,
            monitor: new CallIntegrityMonitor(sig.call_id),
            pc: null, local: null, pendingIce: [], pendingOfferSdp: sig.sdp ?? null,
            startedAt: null, endedReason: null, muted: false,
            seq: 0, ringVib: null, timeoutHandle: null, mediaUp: false,
            iceBatcher: null, iceRelease: false, heldIce: [], prewarming: null,
          };
          session = fresh;
          // b146: drain any candidates that arrived before this offer
          const early = preOfferIce.get(sig.call_id);
          if (early) { fresh.pendingIce.push(...early); preOfferIce.delete(sig.call_id); }
          if (androidRingerMode() !== 'silent') Vibration.vibrate(RING_PATTERN, true); // b199: Android silent = no buzz
          void startRingtone();
          armRingout(fresh);
          notify();
          fresh.prewarming = prewarm(fresh); // 20 Oct 2026: relay allocations start while it rings
          // 21 Oct 2026: tell the caller it really rings here
          void signal(token, { __veil_call: 1, op: 'ringing', call_id: sig.call_id })
            .catch((e: Error) => console.log(`[veil-call] ringing confirmation not sent: ${e.message}`));
        } catch (e) {
          if (e instanceof CallRefusedError) {
            console.log(`[veil-call] offer refused (${e.code}): replay/MITI guard did its job`);
          } else {
            console.log(`[veil-call] offer error: ${(e as Error).message}`);
          }
        }
        return;
      }
      case 'ringing': {
        if (!s || s.callId !== sig.call_id || s.role !== 'caller' || s.phase !== 'calling') return;
        if (s.reach === 'ringing') return;
        s.reach = 'ringing';
        if (s.ackHandle) { clearTimeout(s.ackHandle); s.ackHandle = null; }
        void startRingback(s); // now the tone is honest
        notify();
        return;
      }
      case 'answer': {
        if (!s || s.callId !== sig.call_id || s.role !== 'caller' || s.phase !== 'calling') return;
        const fp = extractDtlsFingerprint(sig.sdp ?? '');
        if (!fp) { s.monitor.record('fingerprint', 'answer SDP carried no DTLS fingerprint — refusing'); teardown(s, 'call refused', true); return; }
        s.core = { ...s.core, offerFingerprint: fp };
        try {
          if (!s.pc) throw new Error('No peer connection.');
          // b63 review (C-2): ringback off before media can start, so stopping
          // it can't touch the audio session under a live call
          await stopRingback();
          if (callGone(s) || !s.pc) return;
          await s.pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: sig.sdp as string }) as never);
          for (const ice of s.pendingIce) await addIce(s.pc, ice);
          s.pendingIce = [];
          clearRing(s);
          armConnecting(s);
        } catch (e) {
          console.log(`[veil-call] answer error: ${(e as Error).message}`);
          teardown(s, 'call failed to connect', true);
        }
        return;
      }
      case 'ice': {
        if (s && s.callId !== sig.call_id) return; // belongs to another call
        if (!s) {
          // b146: candidates can beat the offer across poll batches (the same
          // race the web client fixed). Buffer them per call and drain into
          // pendingIce the moment the offer creates the session — otherwise
          // the media path silently never connects.
          if (!sig.call_id) return;
          if (!preOfferIce.has(sig.call_id)) preOfferIce.set(sig.call_id, []);
          preOfferIce.get(sig.call_id)!.push(sig);
          if (preOfferIce.get(sig.call_id)!.length > 64) preOfferIce.get(sig.call_id)!.shift();
          return;
        }
        if (s.phase === 'ended') return;
        if (!s.pc || !(s.pc as unknown as { remoteDescription?: unknown }).remoteDescription) { s.pendingIce.push(sig); return; }
        try { await addIce(s.pc, sig); } catch (e) { console.log(`[veil-call] ice error: ${(e as Error).message}`); }
        return;
      }
      case 'end': {
        if (s && s.callId === sig.call_id) {
          // caller gave up while we were still ringing — a missed call
          const missedCandidate = s.role === 'callee' && s.phase === 'ringing' && !recordedMisses.has(sig.call_id);
          teardown(s, sig.reason ?? 'ended', false); // peer already sent their end
          if (missedCandidate) recordMissed(sig.call_id, token, s.peerLabel); // b157
          return;
        }
        // b157: end for a call this device never saw ring (offer held while
        // the app was locked). Our own decline/hangup already marked the
        // call locally-ended, so that echo never counts as a miss.
        if (!locallyEndedCalls.has(sig.call_id)) recordMissed(sig.call_id, token, peerLabel ?? 'Vardum contact');
        return;
      }
    }
  },
};

/** Adds every candidate a signal carries: a single `cand` (older builds) or a
 *  batch in `cands` (20 Oct 2026). One bad candidate doesn't stop the rest. */
async function addIce(pc: RTCPeerConnection, sig: CallSignal): Promise<void> {
  const all = candsOf(sig);
  let firstErr: unknown = null;
  for (const raw of all) {
    try {
      const c = JSON.parse(raw) as { candidate: string; sdpMid?: string | null; sdpMLineIndex?: number | null };
      await pc.addIceCandidate(new RTCIceCandidate({
        candidate: c.candidate, sdpMid: c.sdpMid ?? undefined, sdpMLineIndex: c.sdpMLineIndex ?? undefined,
      }) as never);
    } catch (e) { firstErr = firstErr ?? e; }
  }
  if (firstErr && all.length === 1) throw firstErr;
}

