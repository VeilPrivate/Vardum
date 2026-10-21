/**
 * @veil/device — Base44 relay client.
 *
 * Speaks the EXACT contract the web bundle speaks (extracted from
 * index-DYGFL-4a.js, Sept 13 2026):
 *   POST {baseURL}/api/apps/{appId}/functions/{fn}   (JSON body = payload)
 *   Authorization: session token (supplied by the shell's token provider)
 *
 * The relay never sees private keys, phrases, pins, or nicknames. It stores
 * ciphertext envelopes and public session records only. All crypto happens
 * in @veil/crypto-core before anything reaches this client.
 */

export const RATCHET_PROTOCOL = 'veil-ratchet-6'; // spec §4 wire tag (b54); sessions carry their own proto
export const GROUP_PROTOCOL = 'veil-group-1';

export interface RelayConfig {
  /** e.g. https://veil-messaging.base44.app */
  baseUrl: string;
  /** the Base44 app id */
  appId: string;
  /** session token provider (Base44 auth). Refresh handled by the shell. */
  getToken: () => Promise<string | null>;
  /** injectable for tests */
  fetchImpl?: typeof fetch;
  /**
   * RN has no working Blob-from-bytes constructor (Hermes/RN's FormData
   * throws "Creating blobs from 'ArrayBuffer' and 'ArrayBufferView' are
   * not supported" — VEIL-P1, Sept 19). uploadPrivateFile's bytes path
   * uses this hook to write the bytes to a temp file and upload via the
   * proven {uri,name,type} FormData part (same path media sends already
   * use successfully). Pure-TS tests never supply it — Node's real Blob
   * accepts ArrayBufferView directly, so the fallback branch covers them.
   */
  bytesToTempFile?: (bytes: Uint8Array, name: string) => Promise<{ uri: string; cleanup: () => void }>;
}

export interface EnvelopeSubmission {
  session_token: string;
  /** Batch D (D-12, RV-48): accepted from callers but never sent — the relay
   *  doesn't need the account's client id on an envelope (V-13) */
  client_id?: string;
  write_secret: string | null;
  sender_client_id: string;
  ciphertext: string;
  iv: string;
  header: string;
  byte_length: number;
  ttl_seconds: number;
  protocolVersion?: string;
  /** media messages only: the encrypted blob's private-storage URI (web adds
   *  media_uri to submitEnvelope exactly when the body is __veil_media). */
  media_uri?: string;
  /** group messages only: the veil-group-1 channel token — group envelopes
   *  carry BOTH session_token and group_token (web parity). */
  group_token?: string;
}

export class VeilRelay {
  private cfg: RelayConfig;

  // b190 (owner Metro log Oct 11, 20:34): background pollers (auto-rotate's
  // identity lookups, group roster polls, heartbeats, session list) each had
  // their own — or no — backoff, so together they hammered the relay's
  // per-account limiter, re-locking it for minutes at a time while ONE idle
  // device sat in the owner's pocket. Every rate-limit response now stamps
  // a SHARED quiet window on the relay client; background loops consult
  // gateHot() before firing and go silent together, letting the lock
  // actually expire instead of resetting it every few seconds.
  private gateHotUntil = 0;

  /** True while the shared rate-limit quiet window is active. */
  gateHot(): boolean {
    return Date.now() < this.gateHotUntil;
  }

  constructor(cfg: RelayConfig) {
    this.cfg = cfg;
  }

  /** Raw function invoke — the V.functions.invoke contract. */
  async invoke(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    const action = typeof payload.action === 'string' ? payload.action : '(none)';
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/functions/${fn}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const d = data as { message?: string; error?: string; locked?: boolean; retry_minutes?: number } | null;
      // b167 (owner Metro log Oct 2: veilIdentityGate 429 body had ONLY
      // {locked:true, retry_minutes:10} — no message/error field, so the
      // thrown error was a useless 'relay error 429'). Surface the lock and
      // its window so the UI can tell the user exactly what to do.
      const msg = d?.message || d?.error
        || (d?.locked ? `Rate limit — locked, try again in about ${d.retry_minutes ?? '?'} minutes`
        : `relay error ${res.status}`);
      // b79 DIAGNOSTIC: "Unknown action" has been unreproducible against the
      // live server via every known action string — log the FULL context at
      // the exact point of failure (function, action, http status, raw
      // body, auth-token presence) so the next occurrence is conclusive
      // instead of another guess.
      // b87/b88 (owner repro): openChat() calls sessionActivate
      // unconditionally on every open (App.tsx) and already .catch()es the
      // result — it's fire-and-forget, the outcome never affects the UI.
      // The server can reject it for more than one KNOWN, harmless reason
      // depending on session type/role, and this blanket console.error was
      // painting every one of them as a scary red failure on ordinary
      // thread-opens. b87 covered the non-creator case; b88 adds the
      // "not a group, no peer yet" case (owner repro Sept 21 ~03:15 Bris,
      // Metro: veilSessionGate(activate) 400 "Only group sessions can be
      // activated without a peer" — a 1:1 session activated before this
      // device's own join call recorded a peer). Only these two specific,
      // well-understood messages drop to info level; every other relay
      // failure (including any OTHER activate rejection) still logs at
      // error level unchanged.
      const isExpectedActivateRejection = action === 'activate' && (
        /only the session creator can activate/i.test(msg)
        || /only group sessions can be activated without a peer/i.test(msg)
      );
      // b88: burn's "Entity VeilEnvelope with ID ... not found" means the
      // envelope is ALREADY gone (already burned by a prior pass, expired
      // and swept by the relay, or removed as part of session cleanup) —
      // the state burn wants (this envelope not sitting around) is already
      // true. chat.ts's own burn loop (see the sibling isExpectedBurnMiss
      // check there) treats this the same way; this invoke()-level log
      // just needs to stop screaming about it too.
      const isExpectedBurnMiss = action === 'burn' && /entity veilenvelope with id .* not found/i.test(msg);
      // b166 (owner Metro log Oct 2, native→web supersede flow): the b155
      // presence heartbeat (30s tick) and the cover-traffic sender (b164's
      // 15%-roll filler envelope) both run on their OWN interval, decoupled
      // from the 10s session-list poll that detects a dead/superseded
      // session. In the window between the peer superseding a thread
      // server-side and this device's next list refresh noticing it, a
      // heartbeat or cover-send can land on the now-gone session and 404.
      // Both call sites already swallow the throw and never affect the UI
      // (see the heartbeat loop's bare catch and sendCoverEnvelope's
      // .catch() in App.tsx) — this was purely a cosmetic console.error
      // scaring the owner into thinking something broke, same class as the
      // b87/b88 cases right above. Downgraded to info level; the underlying
      // behavior (bounded, self-resolving via the next supersede-switch) is
      // unchanged.
      const isExpectedHeartbeatMiss = action === 'heartbeat' && /session not found/i.test(msg);
      const isExpectedSendMiss = fn === 'submitEnvelope' && /session (not found|is not available)/i.test(msg);
      // TURN credentials: the caller (CallManager turnIce) falls back to
      // host-only and logs its own line — not an error worth a red LogBox.
      const isTurnFallback = fn === 'veilTurnCredentials';
      if (isTurnFallback) {
        console.log(`[veil-relay] ${fn} unavailable — HTTP ${res.status}`);
      } else if (isExpectedActivateRejection) {
        console.log(`[veil-relay] ${fn}(activate) skipped — expected rejection for this session's type/role (${msg})`);
      } else if (isExpectedBurnMiss) {
        console.log(`[veil-relay] ${fn}(burn) skipped — envelope already gone (${msg})`);
      } else if (isExpectedHeartbeatMiss) {
        console.log(`[veil-relay] ${fn}(heartbeat) skipped — session already superseded/gone, next poll will switch away (${msg})`);
      } else if (isExpectedSendMiss) {
        console.log(`[veil-relay] ${fn}(${action}) skipped — session already superseded/gone, next poll will switch away (${msg})`);
      } else {
        // b197 (audit L-4): truncate server-controlled response bodies before
        // they land in device logs — a hostile relay could plant oversized or
        // crafted strings there. 240 chars is ample for diagnosis.
        const rawBody = JSON.stringify(data) ?? '';
        console.error(`[veil-relay] ${fn}(${action}) FAILED — HTTP ${res.status}, hadToken=${!!token}, body=${rawBody.length > 240 ? rawBody.slice(0, 240) + '…(' + rawBody.length + 'B truncated)' : rawBody}`);
      }
      // b190: stamp the shared quiet window — a locked limiter (locked:true +
      // retry_minutes) sets it for the full lock window + jitter; a plain
      // 429/500 rate-limit sets a short 30s cool-off. gateHot() consulters
      // (heartbeat, session list, group polls, auto-rotate, cover sends) go
      // quiet together and stop re-triggering the limiter.
      if (res.status === 429 || (res.status === 500 && /rate limit/i.test(msg))) {
        const mins = Math.max(0, Math.floor(Number(d?.retry_minutes) || 0));
        const quietMs = (mins > 0 ? mins * 60_000 + 5_000 : 30_000) + Math.floor(Math.random() * 5_000);
        this.gateHotUntil = Math.max(this.gateHotUntil, Date.now() + quietMs);
        console.log(`[veil-relay] rate-limited (${fn}/${action}) — background gate traffic paused for ${Math.round(quietMs / 1000)}s`);
      }
      throw new Error(msg);
    }
    return { data, status: res.status };
  }

  // ---------- entity REST (client-created records, same auth scope as the web SDK) ----------

  /**
   * Entity REST LIST — the exact receive channel the web client uses
   * (S.entities.VeilEnvelope.filter(...)). GET /entities/{entity} with the
   * filter as a bare query param, sort, limit.
   */
  async entityList(entity: string, params: Record<string, string | number>): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) qs.set(k, String(v));
    const token = await this.cfg.getToken();
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}?${qs.toString()}`, {
      method: 'GET',
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data as { message?: string } | null)?.message || `entity list error ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  async entityCreate(entity: string, record: Record<string, unknown>): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(record),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data as { message?: string } | null)?.message || `entity create error ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  /**
   * SDK contract (base44Client-BZUbQGvX.js): update(t,n){return e.put(`${i}/${t}`,n)}
   * -> PUT /api/apps/{app}/entities/{entity}/{id} with the record body.
   */
  async entityUpdate(entity: string, id: string, patch: Record<string, unknown>): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(patch),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data as { message?: string } | null)?.message || `entity update error ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  /**
   * SDK contract: async delete(t){return e.delete(`${i}/${t}`)}
   * -> DELETE /api/apps/{app}/entities/{entity}/{id}.
   */
  async entityDelete(entity: string, id: string): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}/${id}`, {
      method: 'DELETE',
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data as { message?: string } | null)?.message || `entity delete error ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  // ---------- identity gate (public keys only — never private material) ----------

  identityRegister(material: { veil_id: string; IK_pub: string; SPK_pub: string; SPK_sig: string; pq_pub: string; pq_sig: string }) {
    return this.invoke('veilIdentityGate', { action: 'register', ...material });
  }

  async identityChallenge(veilId: string): Promise<string> {
    const r = await this.invoke('veilIdentityGate', { action: 'challenge', veil_id: veilId });
    const nonce = (r.data as { data?: { nonce?: string } })?.data?.nonce ?? (r.data as { nonce?: string })?.nonce;
    if (!nonce) throw new Error('identity gate returned no nonce');
    return nonce;
  }

  identityBind(veilId: string, nonce: string, signature: string) {
    return this.invoke('veilIdentityGate', { action: 'bind', veil_id: veilId, nonce, signature });
  }

  identityLookup(veilId: string) {
    return this.invoke('veilIdentityGate', { action: 'lookup', veil_id: veilId });
  }

  // ---------- session gate ----------

  sessionActivate(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'activate', token, write_secret: writeSecret });
  }

  sessionJoin(join: {
    token: string;
    write_secret: string | null;
    client_id: string;
    display_name: string;
    responder_pub_jwk: string;
    responder_ratchet_pub_jwk: string;
    responder_pq_ct: string;
    fingerprint: string;
    /** Batch C (V-16): replace the link's responder credential at join */
    new_responder_write_hash?: string;
  }) {
    return this.invoke('veilSessionGate', { action: 'join', ...join });
  }

  /** Batch F (round-4 reviews R4-3-02 / R4-4-21): rows that only name the caller
   *  (contact requests, restore matches) come in pages of 100; follow
   *  naming_next_cursor (at most 10 more pages) and return one merged list. */
  async sessionList(clientId: string, veilId?: string) {
    const first = await this.invoke('veilSessionGate', { action: 'list', client_id: clientId, ...(veilId ? { veil_id: veilId } : {}) });
    const d = first.data as { sessions?: unknown[]; naming_next_cursor?: string | null } | null;
    let next = d?.naming_next_cursor ?? null;
    if (!next || !Array.isArray(d?.sessions)) return first;
    const merged = [...(d!.sessions as unknown[])];
    for (let guard = 0; next && guard < 10; guard++) {
      const pg = await this.invoke('veilSessionGate', { action: 'list', client_id: clientId, ...(veilId ? { veil_id: veilId } : {}), naming_cursor: next });
      const pd = pg.data as { sessions?: unknown[]; naming_next_cursor?: string | null } | null;
      if (Array.isArray(pd?.sessions)) merged.push(...pd!.sessions);
      next = pd?.naming_next_cursor ?? null;
    }
    return { data: { ...d, sessions: merged, naming_next_cursor: null }, status: first.status };
  }

  sessionPeek(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'peek', token, write_secret: writeSecret });
  }

  sessionHeartbeat(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'heartbeat', token, write_secret: writeSecret });
  }

  sessionBump(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'bump', token, write_secret: writeSecret });
  }

  sessionVerify(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'verify', token, write_secret: writeSecret });
  }

  /**
   * b85 LOCKED-SCREEN DELIVERY: ask the relay to push a "New message" ALERT to
   * the session's other participant(s). The gate verifies write_secret first
   * (so only a session participant can trigger it) and the push carries ZERO
   * content — same generic-banner threat model as the local post-decrypt
   * banner, but delivered BY THE SERVER at send time, so it lands on the lock
   * screen instantly even when the app is suspended/JS can't run and the
   * session can't even be joined yet (pending one-taps). Cover traffic NEVER
   * calls this (sendCoverEnvelope must not), so decoys stay silent. Until the
   * gate action exists server-side this 400s — notifySent() swallows that
   * gracefully and logs once.
   */
  sessionNotify(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'notify', token, write_secret: writeSecret });
  }

  /** b197-r8i: burn-priority hold — while burn deletions are pending, AMBIENT
   *  traffic (heartbeats, cover sends — the callers that consult gateHot)
   *  yields the per-account limiter budget to the privacy-critical deletes.
   *  Root cause it fixes: under saturation, burns starved behind 7s
   *  heartbeats + cover + re-fetches, exhausted their 20-attempt budget, and
   *  envelopes the product calls "burnt" stayed on the relay (K-22). */
  holdAmbientFor(ms: number) {
    this.gateHotUntil = Math.max(this.gateHotUntil, Date.now() + ms);
  }

  /** SPEC §4: burn-after-open — destroy an envelope after this receiver read it. */
  sessionBurn(token: string, writeSecret: string | null, envelopeId: string) {
    return this.invoke('veilSessionGate', { action: 'burn', token, write_secret: writeSecret, envelope_id: envelopeId });
  }

  /** b64: bulk duress purge — service-role delete of EVERY session (and its
   *  envelopes) this client participates in, including peer-created rows the
   *  user-scoped entity API can never reach under RLS. Falls back (caller) to
   *  the per-thread end/delete loop until the gate action is deployed. */
  sessionPurge(clientId: string) {
    return this.invoke('veilSessionGate', { action: 'purge', client_id: clientId });
  }

  // b65: client_id is PARTICIPATION PROOF — the relay (once the gate update
  // deploys) accepts it as an alternative to write_secret, which only the
  // initiator ever has. This is what lets the invited party end peer-created
  // threads (and what duress uses to kill them server-side).
  sessionEnd(token: string, writeSecret: string | null, clientId?: string) {
    return this.invoke('veilSessionGate', {
      action: 'end', token, write_secret: writeSecret,
      ...(clientId ? { client_id: clientId } : {}),
    });
  }

  /**
   * PRIMARY receive channel — the web client polls the VeilEnvelope ENTITY
   * (S.entities.VeilEnvelope.filter({session_token}, 'created_date', 200));
   * it NEVER calls a gate 'fetch' action. Polled oldest-first (ascending
   * created_date), 200 records, expiry checked client-side.
   */
  /** b198 MEDIA DELETION: the blob id exists only inside the E2E media payload,
   * so presenting it (authenticated) is the deletion capability. Idempotent on
   * the relay — an already-gone blob is {ok:true}. */
  async deleteBlob(fileUri: string): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/integration-endpoints/Core/DeletePrivateFile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ file_uri: fileUri }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data as { message?: string } | null)?.message || `blob delete error ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  envelopeList(token: string, skip = 0): Promise<unknown> {
    return this.entityList('VeilEnvelope', {
      session_token: token,
      sort: 'created_date',
      limit: 200,
      // b87: pagination cursor — see SessionStore.syncSkip. Omit when 0 so
      // this stays byte-for-byte the original web-parity call in the
      // common (small-session) case.
      ...(skip > 0 ? { skip } : {}),
    });
  }

  /** LEGACY fallback: gate fetch action (unused by web; may not exist server-side). */
  envelopeFetch(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'fetch', token, write_secret: writeSecret });
  }

  // ---------- encrypted media blobs (web's image flow, extracted Sept 19 2026) ----------

  /**
   * Private blob upload — the web SDK contract
   * S.integrations.Core.UploadPrivateFile({file}) → {file_uri}, i.e.
   *   POST /api/apps/{appId}/integration-endpoints/Core/UploadPrivateFile
   * with the ciphertext as a multipart "file" part named veil-media
   * (type application/octet-stream). Plaintext never leaves the device.
   */
  async uploadPrivateFile(source: { uri?: string; bytes?: Uint8Array; name?: string }): Promise<string> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    const name = source.name ?? 'veil-media';
    let cleanup: (() => void) | null = null;
    try {
      const form = new FormData();
      if (source.uri) {
        // RN path: the OS fetch understands {uri,name,type} file parts
        form.append('file', { uri: source.uri, name, type: 'application/octet-stream' } as unknown as Blob);
      } else if (source.bytes && this.cfg.bytesToTempFile) {
        // RN bytes path: route through a real file — Blob-from-bytes is broken on-device
        const tmp = await this.cfg.bytesToTempFile(source.bytes, name);
        cleanup = tmp.cleanup;
        form.append('file', { uri: tmp.uri, name, type: 'application/octet-stream' } as unknown as Blob);
      } else if (source.bytes) {
        // Node/test path: Blob(ArrayBufferView) works fine off-device
        form.append('file', new Blob([source.bytes as unknown as BlobPart], { type: 'application/octet-stream' }), name);
      } else {
        throw new Error('uploadPrivateFile: needs a uri or bytes');
      }
      const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/integration-endpoints/Core/UploadPrivateFile`, {
        method: 'POST',
        // no Content-Type header — the FormData sets its own multipart boundary
        ...(token ? { headers: { Authorization: `Bearer ${token}` } } : {}),
        body: form as unknown as BodyInit,
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        const msg = (data as { message?: string } | null)?.message || `upload error ${res.status}`;
        throw new Error(msg);
      }
      const d = data as { file_uri?: string; data?: { file_uri?: string } } | null;
      const uri = d?.file_uri ?? d?.data?.file_uri;
      if (!uri) throw new Error('upload returned no file_uri');
      return uri;
    } finally {
      cleanup?.();
    }
  }

  /**
   * Signed download URL for a stored blob — the web contract
   * C.functions.invoke('vaultFileSignedUrl', {file_uri, session_token,
   * write_secret}) → {signed_url} (accepts the .data-wrapped form too).
   */
  async vaultFileSignedUrl(fileUri: string, sessionToken: string, writeSecret: string | null): Promise<string> {
    const r = await this.invoke('vaultFileSignedUrl', {
      file_uri: fileUri,
      session_token: sessionToken,
      write_secret: writeSecret,
    });
    const d = r.data as { signed_url?: string; data?: { signed_url?: string } } | null;
    const url = d?.signed_url ?? d?.data?.signed_url;
    if (!url) throw new Error('Signed URL unavailable');
    return url;
  }

  /**
   * Vaults: web p.functions.invoke('vaultFileSignedUrl', {file_uri}) — no
   * session context (the vault unlock path). Same response shapes.
   */
  async vaultContainerSignedUrl(fileUri: string): Promise<string> {
    const r = await this.invoke('vaultFileSignedUrl', { file_uri: fileUri });
    const d = r.data as { signed_url?: string; data?: { signed_url?: string } } | null;
    const url = d?.signed_url ?? d?.data?.signed_url;
    if (!url) throw new Error('Signed URL unavailable');
    return url;
  }

  /** Fetch raw bytes from a (pre-signed, unauthenticated) URL. */
  async fetchBytes(url: string): Promise<Uint8Array> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const res = await fetchImpl(url);
    if (!res.ok) throw new Error(`Media fetch failed (${res.status})`);
    return new Uint8Array(await res.arrayBuffer());
  }

  // ---------- envelope submission (its own function, NOT a gate action) ----------

  async submitEnvelope(sub: EnvelopeSubmission): Promise<{ data: unknown; status: number }> {
    const payload = {
      session_token: sub.session_token,
      write_secret: sub.write_secret,
      sender_client_id: sub.sender_client_id,
      ciphertext: sub.ciphertext,
      iv: sub.iv,
      header: sub.header,
      byte_length: sub.byte_length,
      expires_at: new Date(Date.now() + sub.ttl_seconds * 1000).toISOString(),
      ttl_seconds: sub.ttl_seconds,
      delivery_state: 'accepted',
      protocol_version: sub.protocolVersion ?? RATCHET_PROTOCOL,
      ...(sub.media_uri ? { media_uri: sub.media_uri } : {}),
      ...(sub.group_token ? { group_token: sub.group_token } : {}),
    };
    return this.invoke('submitEnvelope', payload);
  }
}
