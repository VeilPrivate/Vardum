/**
 * @veil/device — Device transfer (web parity, build 39).
 *
 * Web contract extracted from the live bundle (createDeviceTransfer /
 * confirmDeviceLink / deviceLink backend fn):
 *
 * SENDER
 *   1. bundle = { v: 2, clientId, sessions: {token: serializedState}, groups: [],
 *                identity: keyvaultJson | null }
 *      (serialized states are the veil_rk_* family — byte-exact with the web)
 *   2. AES-256-GCM: fresh 32-byte key (base64 in the link fragment), fresh
 *      12-byte IV; blob = JSON.stringify({ iv: b64, ct: b64 })
 *   3. blob → UploadPrivateFile (private storage, never public)
 *   4. deviceLink { action:'store', token, container_uri, byte_length }
 *   5. link = {origin}/?deviceLink={token}#k={encodeURIComponent(keyB64)}
 *      — single-use, ~10-minute TTL enforced server-side
 *
 * RECEIVER
 *   1. deviceLink { action:'fetch', token } → { blob } | { signed_url }
 *   2. decrypt with the fragment key → bundle (accepts v1 and v2)
 *   3. import each session not already present; import identity into the
 *      keyvault (kept-safe rule below); groups restored where present
 *
 * Native deviation (disclosed): the web overwrites the local keyvault with the
 * transferred identity unconditionally. Native imports the identity only when
 * this device has none — an existing identity is always kept (transfer still
 * imports the sessions) and the summary says so, so a pasted link can never
 * replace the identity you are using.
 *
 * Batch D (D-10, RV-08): the bundle's identity must derive from its own seed
 * (IK = Ed25519(seed), Vardum ID = f(IK)); anything else is refused before a
 * single session is imported. The user confirms the incoming Vardum ID first.
 */
import { randomBytes, toB64, fromB64, utf8, ikFromSeed, veilIdFromIkPub } from '../../crypto-core/src/index';
import type { RatchetStateSerialized } from '../../crypto-core/src/ratchet';
import type { SessionStore } from './session-store';
import type { IdentityVault } from './keyvault';
import type { VeilRelay } from './relay';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';

export interface TransferBundleV2 {
  v: 2;
  clientId: string;
  sessions: Record<string, RatchetStateSerialized>;
  groups: unknown[];
  identity: KeyvaultIdentityRef | null;
  /** Batch F (R4-4-06): the acknowledgement secret; the relay holds only its SHA-256 */
  ack?: string;
}

async function sha256Hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(s) as unknown as BufferSource));
  return Array.from(d).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Shape of the keyvault identity JSON (keyvault.ts owns the full type;
 *  the bundle carries it as-is so the formats stay web-identical). */
export interface KeyvaultIdentityRef {
  veilId: string;
  [k: string]: unknown;
}

export interface DeviceTransferLink {
  link: string;
  sessionCount: number;
  groupCount: number;
  hasIdentity: boolean;
  /** Batch C (B5): the link token (for waitForTransferPickup) and the moved chats */
  token: string;
  sessionTokens: string[];
}

export interface DeviceTransferResult {
  sessionCount: number;
  importedCount: number;
  skippedExisting: number;
  identityImported: boolean;
  identityKept: boolean;
  /** Batch H (R6-1-04): imported, but no ack was sent, so the old phone keeps its chats */
  ackHeld?: 'different-identity' | 'already-here';
  /** Batch G (R5-3-03): a save was refused; the old phone keeps its chats */
  incomplete?: boolean;
}

export interface TransferDeps {
  sessions: SessionStore;
  vault: IdentityVault;
  relay: VeilRelay;
  /** web origin for the shareable link (the web app opens it natively;
   *  the native app accepts the same link pasted into Settings) */
  webBaseUrl: string;
  fetchImpl?: typeof fetch;
  /** Batch E (F-3): where the pending move is recorded until it is finished */
  storage?: VeilStorage;
}

async function aesGcmEncrypt(keyBytes: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, plaintext as unknown as BufferSource);
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(keyBytes: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, ciphertext as unknown as BufferSource);
  return new Uint8Array(pt);
}

/** Sender: build the bundle, upload it encrypted, return the single-use link. */
export async function createDeviceTransfer(
  deps: TransferDeps,
  opts?: { clientId?: string },
): Promise<DeviceTransferLink> {
  const tokens = await deps.sessions.listTokens();
  const sessions: Record<string, RatchetStateSerialized> = {};
  const ackSecret = Array.from(randomBytes(32)).map((b) => b.toString(16).padStart(2, '0')).join(''); // Batch F (R4-4-06)
  for (const token of tokens) {
    const state = await deps.sessions.load(token);
    if (state) sessions[token] = state;
  }
  const identity = await deps.vault.load();
  const bundle: TransferBundleV2 = {
    v: 2,
    clientId: opts?.clientId ?? identity?.veilId ?? '',
    sessions,
    groups: [],
    identity: identity as unknown as KeyvaultIdentityRef | null,
    // Batch F (round-4 reviews R4-4-06 / R4-3-03): only the phone that decrypts
    // and imports this bundle can prove it to the relay (ack), so a fetch alone —
    // a cancel, a wrong key, a crash, a lost response — never retires the chats here
    ack: ackSecret,
  };
  if (!Object.keys(sessions).length && !identity) {
    throw new Error('There are no conversation keys on this device to transfer. Use Vardum on this device first, then try again. (ref TF-01)');
  }

  const keyBytes = randomBytes(32);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(keyBytes, iv, utf8(JSON.stringify(bundle)));
  const blob = JSON.stringify({ iv: toB64(iv), ct: toB64(ct) });

  // private storage — the bundle never travels anywhere readable but the link
  const containerUri = await deps.relay.uploadPrivateFile({
    bytes: utf8(blob),
    name: 'veil-transfer',
  });
  const token = toB64(randomBytes(16));
  await deps.relay.invoke('deviceLink', {
    action: 'store',
    token,
    ack_hash: await sha256Hex(ackSecret),
    container_uri: containerUri,
    byte_length: blob.length,
  });

  // Batch E (Superagent round 3, F-3): record the move BEFORE the link is shown.
  // The retirement used to live only in memory, so killing the app before the
  // new phone collected the bundle left the same chats on both phones.
  if (deps.storage) await savePendingTransfer(deps.storage, { token, sessionTokens: Object.keys(sessions), createdAt: Date.now() });

  const base = deps.webBaseUrl.replace(/\/$/, '');
  const link = `${base}/?deviceLink=${encodeURIComponent(token)}#k=${encodeURIComponent(toB64(keyBytes))}`;
  return {
    link,
    sessionCount: Object.keys(sessions).length,
    groupCount: 0,
    hasIdentity: !!identity,
    token,
    sessionTokens: Object.keys(sessions),
  };
}

export const PENDING_TRANSFER_KEY = 'veil_pending_transfer_v1';
export interface PendingTransfer { token: string; sessionTokens: string[]; createdAt: number; /** Batch H (R6-1-11 / R6-3-12): when "Did your new phone get your chats?" was answered "Not yet" */ askedAt?: number }

/** Batch E (F-3): throws when the record can't be written, so no link is shown
 *  that this phone could not finish moving. */
// Batch F (round-4 review R4-4-13): one record PER LINK. A second link used to
// overwrite the first, and the first link's loop then deleted the second's record.
function cleanPending(p: unknown): PendingTransfer | null {
  const q = p as PendingTransfer | null;
  if (!q || typeof q.token !== 'string' || !q.token || !Array.isArray(q.sessionTokens)) return null;
  return { token: q.token, sessionTokens: q.sessionTokens.filter((t) => typeof t === 'string'), createdAt: Number(q.createdAt) || 0, ...(Number(q.askedAt) > 0 ? { askedAt: Number(q.askedAt) } : {}) };
}

/** every pending move on this phone (a damaged record reads as none) */
export async function loadPendingTransfers(storage: VeilStorage): Promise<PendingTransfer[]> {
  try {
    const raw = await storage.get(PENDING_TRANSFER_KEY);
    if (!raw) return [];
    const v = JSON.parse(raw) as unknown;
    if (Array.isArray(v)) return v.map(cleanPending).filter((x): x is PendingTransfer => !!x);
    const one = cleanPending(v); // the Batch E single-record format
    return one ? [one] : [];
  } catch {
    return [];
  }
}

export async function savePendingTransfer(storage: VeilStorage, p: PendingTransfer): Promise<void> {
  const all = (await loadPendingTransfers(storage)).filter((x) => x.token !== p.token);
  all.push(p);
  if (!(await storage.set(PENDING_TRANSFER_KEY, JSON.stringify(all)))) {
    throw new Error('Could not prepare the transfer on this phone (storage is full or locked). Try again. (ref TF-05)');
  }
}

export async function clearPendingTransfer(storage: VeilStorage, token: string): Promise<void> {
  const rest = (await loadPendingTransfers(storage)).filter((x) => x.token !== token);
  if (rest.length) await storage.set(PENDING_TRANSFER_KEY, JSON.stringify(rest));
  else await storage.remove(PENDING_TRANSFER_KEY);
}

/** Batch H (round-6 reviews R6-1-11 / R6-3-12): remember that the user answered
 *  "Not yet" for this move, so the question is asked once, as planned. */
export async function markTransferAsked(storage: VeilStorage, token: string): Promise<void> {
  const all = await loadPendingTransfers(storage);
  const p = all.find((x) => x.token === token);
  if (!p) return;
  p.askedAt = Date.now();
  await storage.set(PENDING_TRANSFER_KEY, JSON.stringify(all));
}

/** the first pending move (kept for older callers) */
export async function loadPendingTransfer(storage: VeilStorage): Promise<PendingTransfer | null> {
  return (await loadPendingTransfers(storage))[0] ?? null;
}

/**
 * Batch E (F-3): finish a recorded move. Asks the relay until it answers:
 * 'used' retires the moved chats and clears the record; 'expired' (never
 * collected) clears the record and keeps the chats; no answer before the
 * timeout keeps the record for the next launch.
 */
export async function finishTransferMove(
  deps: { relay: Pick<VeilRelay, 'invoke'>; sessions: Pick<SessionStore, 'remove'>; storage: VeilStorage },
  pending: PendingTransfer,
  /** Batch G (R5-3-02 / R5-3-09): returnOnFetched stops at a "fetched, not yet acknowledged" answer (the launch check) */
  opts: { intervalMs?: number; timeoutMs?: number; returnOnFetched?: boolean } = {},
): Promise<{ state: 'used' | 'expired' | 'waiting' | 'fetched'; retired: number }> {
  const interval = opts.intervalMs ?? 4000;
  const deadline = Date.now() + (opts.timeoutMs ?? 11 * 60_000);
  while (Date.now() < deadline) {
    let state: string | undefined;
    try {
      const r = await deps.relay.invoke('deviceLink', { action: 'status', token: pending.token }) as { data?: { state?: string; data?: { state?: string } } };
      state = r?.data?.state ?? r?.data?.data?.state;
    } catch { /* transient — keep waiting */ }
    if (state === 'used') {
      const retired = await retireTransferredSessions({ sessions: deps.sessions as SessionStore }, pending.sessionTokens);
      await clearPendingTransfer(deps.storage, pending.token);
      return { state: 'used', retired };
    }
    if (state === 'expired') {
      await clearPendingTransfer(deps.storage, pending.token);
      return { state: 'expired', retired: 0 };
    }
    if (state === 'fetched' && opts.returnOnFetched) return { state: 'fetched', retired: 0 };
    await new Promise((res) => setTimeout(res, interval));
  }
  return { state: 'waiting', retired: 0 };
}

/**
 * Batch C (B5, owner decision D3 — a transfer is a MOVE): wait until the new
 * phone has collected the bundle (the relay's link status, asked by the
 * account that created the link), polling every few seconds up to the link's
 * 10-minute life. 'used' = collected; 'expired' = never collected.
 */
export async function waitForTransferPickup(
  deps: Pick<TransferDeps, 'relay'>,
  token: string,
  opts: { intervalMs?: number; timeoutMs?: number } = {},
): Promise<'used' | 'expired'> {
  const interval = opts.intervalMs ?? 4000;
  const deadline = Date.now() + (opts.timeoutMs ?? 11 * 60_000);
  while (Date.now() < deadline) {
    try {
      const r = await deps.relay.invoke('deviceLink', { action: 'status', token }) as { data?: { state?: string; data?: { state?: string } } };
      const state = r?.data?.state ?? r?.data?.data?.state;
      if (state === 'used') return 'used';
      if (state === 'expired') return 'expired';
    } catch { /* transient — keep waiting */ }
    await new Promise((res) => setTimeout(res, interval));
  }
  return 'expired';
}

/**
 * Batch C (B5): after the new phone collected the bundle, the old phone
 * retires the moved chats — their ratchet states, caches and per-chat keys are
 * overwritten and removed, so two phones never hold (and fork) the same
 * session. The identity stays (the account is still this person's).
 */
export async function retireTransferredSessions(deps: Pick<TransferDeps, 'sessions'>, sessionTokens: string[]): Promise<number> {
  let n = 0;
  for (const t of sessionTokens) {
    try { await deps.sessions.remove(t); n += 1; } catch { /* keep going — best effort per chat */ }
  }
  return n;
}

/** Parse a transfer link (either from the web app URL or shared as text). */
export function parseTransferLink(link: string): { token: string; key: string } {
  const tokenMatch = link.match(/deviceLink=([^&#\s]+)/i);
  const keyMatch = link.match(/[#&?]k=([^&#\s]+)/i);
  if (!tokenMatch) throw new Error('That is not a device-transfer link — ask for a fresh one.');
  const token = decodeURIComponent(tokenMatch[1]);
  const key = keyMatch ? decodeURIComponent(keyMatch[1]) : '';
  if (!key) throw new Error('The link is missing its key fragment — ask for a fresh one.');
  return { token, key };
}

/** Receiver: fetch the container, decrypt, import sessions (+ identity). */
export async function receiveDeviceTransfer(
  deps: TransferDeps,
  link: string,
  opts: {
    /** Batch D (D-10): asked with the incoming Vardum ID before an identity is
     *  imported; false cancels the whole transfer. Without it no identity is imported. */
    confirmIdentity?: (veilId: string) => Promise<boolean>;
  } = {},
): Promise<DeviceTransferResult> {
  const { token, key } = parseTransferLink(link);
  const fetchImpl = deps.fetchImpl ?? fetch;

  const r = await deps.relay.invoke('deviceLink', { action: 'fetch', token });
  const d = (r.data ?? {}) as { blob?: string; signed_url?: string; data?: { blob?: string; signed_url?: string } };
  let blob: string = d.blob ?? d.data?.blob ?? '';
  if (!blob && (d.signed_url ?? d.data?.signed_url)) {
    const res = await fetchImpl(d.signed_url ?? d.data!.signed_url!);
    if (!res.ok) throw new Error('The transfer container could not be fetched — the link may have expired. Ask for a fresh one. (ref DL-04)');
    blob = await res.text();
  }
  if (!blob) throw new Error('Transfer link not found — expired or already used.');

  let bundle: TransferBundleV2;
  try {
    const envelope = JSON.parse(blob) as { iv: string; ct: string };
    const keyBytes = fromB64(key);
    const iv = fromB64(envelope.iv);
    const ct = fromB64(envelope.ct);
    const pt = await aesGcmDecrypt(keyBytes, iv, ct);
    const parsed = JSON.parse(new TextDecoder().decode(pt)) as { v: number; sessions?: Record<string, RatchetStateSerialized>; groups?: unknown[]; identity?: KeyvaultIdentityRef | null; clientId?: string };
    if ((parsed.v !== 1 && parsed.v !== 2) || !parsed.sessions) {
      throw new Error('not a bundle');
    }
    bundle = parsed as TransferBundleV2;
  } catch {
    throw new Error('The bundle could not be decrypted with this link — ask for a fresh one. (ref DL-05)');
  }

  // Batch D (D-10): check the identity BEFORE anything is imported
  const local = await deps.vault.load();
  let importIdentity = false;
  if (bundle.identity) {
    const id = bundle.identity as KeyvaultIdentityRef & { ikSeedB64?: unknown; ikPubB64?: unknown };
    let derivedIk = '';
    try { derivedIk = toB64((await ikFromSeed(fromB64(String(id.ikSeedB64 ?? '')))).pubBytes); } catch { derivedIk = ''; }
    const derivedId = derivedIk ? await veilIdFromIkPub(derivedIk) : '';
    if (!derivedIk || derivedIk !== id.ikPubB64 || derivedId !== id.veilId) {
      throw new Error('The identity in this transfer is not valid (its key does not match its Vardum ID), so nothing was imported. (ref DL-06)');
    }
    if (!local && opts.confirmIdentity) {
      if (!(await opts.confirmIdentity(id.veilId))) throw new Error('Transfer cancelled — nothing was imported.');
      importIdentity = true;
    }
  }

  // import sessions not already on this device (web parity: never overwrite)
  let importedCount = 0;
  let skippedExisting = 0;
  // Batch G (round-5 review R5-3-03): every save is checked; the ack below goes out
  // only when all of them (and the identity) really landed
  let allSaved = true;
  for (const [sessToken, state] of Object.entries(bundle.sessions)) {
    if (await deps.sessions.load(sessToken)) { skippedExisting += 1; continue; }
    if (!(await deps.sessions.save(sessToken, state))) allSaved = false;
    else importedCount += 1;
  }

  // identity: imported only onto a phone with none, after the user confirmed it;
  // an existing identity is always kept (Batch D, D-10: even with the "same" ID)
  let identityImported = false;
  let identityKept = false;
  if (bundle.identity) {
    if (importIdentity) {
      await deps.vault.save(bundle.identity as never);
      // Batch G (R5-3-03): the vault ignores a refused write — read it back
      const back = (await deps.vault.load()) as { veilId?: string } | null;
      if (back?.veilId !== (bundle.identity as { veilId?: string }).veilId) allSaved = false;
      else identityImported = true;
    } else if (local) {
      identityKept = true;
    }
  }

  // Batch H (round-6 review R6-1-04): "saved" is not enough for the old phone to
  // erase its chats. No ack when this phone keeps a DIFFERENT Vardum ID (the moved
  // chats belong to an ID it doesn't use), or when chats were skipped because a
  // copy was already here (that copy may be older than the old phone's).
  const differentIdentity = !!(bundle.identity && identityKept && local
    && (local as { veilId?: string }).veilId !== (bundle.identity as { veilId?: string }).veilId);
  const ackHeld: 'different-identity' | 'already-here' | null = differentIdentity ? 'different-identity' : skippedExisting > 0 ? 'already-here' : null;
  // Batch F (R4-4-06): everything is saved — now tell the relay, with the secret
  // from inside the bundle, so the old phone retires the moved chats. If this
  // fails the old phone keeps its copy (safe; the user can retry the move).
  if (allSaved && !ackHeld && typeof bundle.ack === 'string' && bundle.ack) {
    let acked = false;
    for (let i = 0; i < 3 && !acked; i++) {
      try { await deps.relay.invoke('deviceLink', { action: 'ack', token, ack_secret: bundle.ack }); acked = true; } catch { /* retry */ }
    }
    if (!acked) console.log('[veil-transfer] import done, but the relay did not take the acknowledgement — the old phone keeps its copy');
  }

  return {
    sessionCount: Object.keys(bundle.sessions).length,
    importedCount,
    skippedExisting,
    identityImported,
    identityKept,
    incomplete: !allSaved, // Batch G (R5-3-03): something was not saved; no ack was sent
    ...(ackHeld ? { ackHeld } : {}), // Batch H (R6-1-04): saved, but the old phone keeps its copy
  };
}
