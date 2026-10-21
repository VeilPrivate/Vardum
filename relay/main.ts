// VEIL RELAY — self-hosted Phase 1 (b197-r9) + UnifiedPush (GrapheneOS push, 19 Oct)
// The exact URL contract the native client speaks (extracted from relay.ts/auth.ts/chat.ts).
// Deno + Deno KV. Zero external dependencies.
//
// RUN:  deno run -A main.ts          (listens on :8000)
// SEED: deno run -A seed.ts          (creates the founder's user — see seed.ts)
//
// PHASE 1 SCOPE (honest):
//   ✓ auth: login/register/verify-otp/logout (register auto-verifies — OTP email is Phase 2)
//   ✓ generic entity REST: VeilSession, VeilEnvelope, User, VeilAuthNonce, VeilVault, VeilNote...
//   ✓ functions: submitEnvelope, veilSessionGate (activate/notify/burn), purgeExpiredEnvelopes
//   ✓ sweeper: internal interval, purges expired envelopes every 10 min
//   ✗ Phase 2: OTP email delivery, group gate details, agents, vault signed-URLs, TLS (proxy in front)

import { KV } from "./kv.ts";

// Port is env-configurable so a TEST instance can run beside production without
// touching it (systemd sets nothing → 8000; sandbox runs set VEIL_PORT=8001)
const PORT = Number(Deno.env.get("VEIL_PORT") || 8000);
const j = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
const json = j; // alias — both spellings used across handlers
const nowIso = () => new Date().toISOString();
const rid = () => crypto.randomUUID().replace(/-/g, "").slice(0, 24);

// ---------- password hashing (PBKDF2-SHA256, 100k — WebCrypto, works in Deno) ----------
/** b54 (audit L-4 / Q-8): constant-time equality for secret-derived strings
 *  (write-secret hashes, password hashes). Length is not secret (fixed-size
 *  hex digests); the content comparison never short-circuits. */
function ctEq(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function hashPassword(password: string, salt: string): Promise<string> {
  const keyMaterial = new TextEncoder().encode(salt + ":" + password);
  const key = await crypto.subtle.importKey("raw", keyMaterial, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100_000, hash: "SHA-256" },
    key,
    256,
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- auth ----------
async function createUser(email: string, password: string) {
  email = email.toLowerCase().trim();
  // b198 ANONYMOUS SIGNUP: the email is a self-declared label — invented
  // addresses are FINE (never verified, never contacted). Only structural
  // sanity is enforced so KV keys stay usable; the signup screen discloses
  // that a forgotten password + lost phrase = unrecoverable account.
  if (!email || email.length > 64 || !email.includes("@")) throw new Error("Enter an email address — it can be invented; it is never verified or contacted");
  const existing = (await KV.get<string>(["user_email", email])).value;
  if (existing) throw new Error("Email already registered");
  // Batch D (D-17, RV-12): a label given up by a rebind is never handed out again —
  // legacy group rows are keyed on a hash of the label
  if ((await KV.get<string>(["label_retired", email])).value) throw new Error("Email already registered");
  const uid = "u_" + rid();
  const salt = crypto.randomUUID().replace(/-/g, "");
  const passHash = await hashPassword(password, salt);
  const user = { id: uid, email, passHash, salt, verified: true, created: nowIso() };
  await KV.set(["user", uid], user);
  await KV.set(["user_email", email], uid);
  void bumpStat("accounts");
  return user;
}

async function authUser(req: Request): Promise<{ userId: string; email: string } | null> {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  // b199: never log header/token bytes — a partial bearer token in journald is
  // a credential fragment on disk. Path only.
  if (!token) {
    console.log("[auth-debug] NO TOKEN | url: " + new URL(req.url).pathname);
    return null;
  }
  if (token.length > MAX_KEY_PART) return null;
  // b54 hotfix (code review V-18): "h:<hex>" is the at-rest KEY of a hashed
  // token row; presenting it as a bearer token hit that row through the raw
  // fallback below, so a database copy still yielded live logins. Real
  // tokens never start with "h:".
  if (token.startsWith("h:")) return null;
  // b199 (audit: "auth tokens stored raw as KV keys — a DB copy = live
  // tokens"): tokens are stored under a one-way hash. A raw row from before
  // this change is migrated on first use, so nobody is signed out.
  const hk = await authKey(token);
  let r = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(hk);
  if (!r.value) {
    const raw = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(["auth", keySafe(token)]);
    if (raw.value) {
      await KV.set(hk, raw.value);
      await KV.delete(["auth", keySafe(token)]);
      r = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(hk);
    }
  }
  // STOLEN-TOKEN WINDOW: auth tokens expire (30 days) and slide while in use —
  // a leaked token is not a lifetime passport. Refresh throttled to 1/hour.
  if (r.value) {
    const now = Date.now();
    if (r.value.exp && r.value.exp < now) { await KV.delete(hk); return null; }
    if (!r.value.last_used || now - r.value.last_used > 3600_000) {
      await KV.set(hk, { ...r.value, last_used: now, exp: now + 30 * 86400_000 });
    }
  }
  if (!r.value) console.log("[auth-debug] token MISS | url: " + new URL(req.url).pathname);
  return r.value ? { userId: r.value.userId, email: r.value.email } : null;
}

/**
 * b199 NETWORK-ADDRESS MINIMISATION. The per-network throttles (signup cap,
 * password-guessing lockout) need a stable per-network handle, never the
 * address itself. Each address is replaced by an HMAC tag under a key that
 * rotates every UTC day and is itself deleted 48 h after it is minted. Once a
 * day's key is gone, that day's tags cannot be mapped back to addresses — not
 * even by brute-forcing the whole IPv4 space with the database in hand. Every
 * KV row that holds a tag also expires on its own (see THROTTLE_TTL_MS).
 * "local" (no X-Forwarded-For: the server's own console / SSH tunnel) is
 * passed through unchanged — it is not an address and stays unthrottled.
 */
async function clientTag(req: Request): Promise<string> {
  const fwd = req.headers.get("x-forwarded-for") || "";
  // Batch D (D-24; report 3 §3.3): the RIGHTMOST value — the address Caddy
  // itself saw. Anything to its left came from the client, so the old
  // leftmost pick let every per-network throttle be dodged with a fresh fake
  // address on each request.
  const ip = (fwd.split(",").pop() || "").trim();
  if (!ip) return "local";
  const day = Math.floor(Date.now() / 86400_000);
  const mac = await crypto.subtle.sign("HMAC", await ipTagKey(day), enc.encode(ip.slice(0, MAX_KEY_PART)));
  return "nt_" + [...new Uint8Array(mac).slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function ipTagKey(day: number): Promise<CryptoKey> {
  const k = ["secret", "ipTag", day];
  let s = (await KV.get<string>(k)).value;
  if (!s) {
    const fresh = b64e(crypto.getRandomValues(new Uint8Array(32)));
    // atomic mint: two concurrent first requests of the day must agree on ONE key
    const minted = await KV.atomic().check({ key: k, versionstamp: null }).set(k, fresh, { expireIn: 48 * 3600_000 }).commit();
    s = minted.ok ? fresh : (await KV.get<string>(k)).value ?? fresh;
  }
  return crypto.subtle.importKey("raw", b64d(s) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

// ---------- b199 anonymous daily totals (owner dashboard, Oct 16) ----------
// One counter per metric per UTC day: ["stats", metric, "YYYY-MM-DD"] → count.
// Nothing about who, which account or which chat is stored — only how many.
// Read by GET /admin/stats (local-only via Caddy, token-gated). Days older
// than STATS_KEEP_DAYS are pruned by the sweeper.
const STATS_KEEP_DAYS = 400;
const statDay = (t = Date.now()) => new Date(t).toISOString().slice(0, 10);
async function bumpStat(metric: "accounts" | "identities" | "chats" | "envelopes") {
  try { await KV.atomic().sum(["stats", metric, statDay()], 1n).commit(); } catch { /* a missed count never blocks a request */ }
}
async function pruneStats() {
  const cutoff = statDay(Date.now() - STATS_KEEP_DAYS * 86400_000);
  for await (const e of KV.list({ prefix: ["stats"] })) if (String(e.key[2]) < cutoff) await KV.delete(e.key);
}
async function statsSnapshot() {
  const count = async (prefix: Deno.KvKey) => { let n = 0; for await (const _ of KV.list({ prefix })) n++; return n; };
  const groups = new Set<string>();
  for await (const e of KV.list({ prefix: ["veil_gmember"] })) groups.add(String(e.key[1]));
  let liveChats = 0, liveGroupSessions = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilSession"] })) {
    if (e.value?.group_token) liveGroupSessions++; else liveChats++;
  }
  const daily: Record<string, Record<string, number>> = {};
  for await (const e of KV.list<Deno.KvU64>({ prefix: ["stats"] })) {
    const [, metric, day] = e.key as [string, string, string];
    (daily[day] ??= {})[metric] = Number(e.value?.value ?? 0);
  }
  return {
    generated: new Date().toISOString(),
    totals: {
      accounts: await count(["user"]),
      identities: await count(["veil_identity"]),
      live_chats: liveChats,
      live_group_sessions: liveGroupSessions,
      groups: groups.size,
      stored_envelopes: await count(["entity", "VeilEnvelope"]),
      devices_with_alerts: await count(["entity", "VeilPushToken"]),
    },
    daily,
  };
}

/** Throttle/lockout rows expire on their own — no permanent per-network or
 *  per-account trail accumulates in the database. */
const THROTTLE_TTL_MS = 24 * 3600_000;
/** Push-coalescing stamps only matter for their 30 s window; they used to be
 *  kept forever (a per-session / per-veil-id "last pinged" trail). */
const COALESCE_TTL_MS = 5 * 60_000;

// ---------- generic entities ----------
// Rows: ["entity", name, id] → { id, created_date, updated_date, ...fields }
// Token index for VeilSession: ["veil_sess_token", token] → id

async function listEntity(name: string, url: URL, auth?: { userId: string }) {
  const rows: any[] = [];
  for await (const e of KV.list({ prefix: ["entity", name] }, { consistency: "strong" })) {
    rows.push({ ...(e.value as Record<string, unknown>), id: e.key[e.key.length - 1] as string });
  }
  const q = url.searchParams;
  const filters: [string, string][] = [];
  let limit = 200;
  let skip = 0;
  let sortField: string | null = null;
  let sortDesc = false;
  for (const [k, v] of q) {
    if (k === "limit") { limit = Math.max(1, parseInt(v) || 200); continue; }
    if (k === "sort") {
      sortField = v.replace(/^-/, "");
      sortDesc = v.startsWith("-");
      continue;
    }
    if (k === "skip") { skip = Math.max(0, parseInt(v) || 0); continue; }
    if (k === "page" || k === "page_size") continue;
    filters.push([k, v]);
  }
  let out = rows;
  // HARVEST GUARD: shared-entity lists MUST carry their scoping filter — an
  // unfiltered list would dump every user's sessions/envelopes to any
  // authenticated account (metadata + ciphertext harvesting)
  // b198 (live-caught, group battery): GROUP envelopes are scoped by
  // group_token — the group receive channel is one shared stream, so a
  // session_token filter is structurally impossible for groups. A group_token
  // list is accepted as valid scoping ONLY for group members: the gmember row
  // written at attest carries the member's account_hash, so the check is
  // exact and cheap. Every other account keeps the 403 — the guard keeps its
  // teeth (an outsider knowing a group token still cannot read its stream).
  const groupScoped = name === "VeilEnvelope" && !!q.get("group_token");
  const requiredFilter = REQUIRED_LIST_FILTER[name];
  if (requiredFilter && !q.get(requiredFilter) && !groupScoped) {
    return { __blocked: `list requires a ${requiredFilter} filter` } as any;
  }
  if (groupScoped && auth) {
    const acct = await accountHashOf(auth.userId);
    let member = false;
    for await (const e of KV.list({ prefix: ["veil_gmember", keySafe(q.get("group_token") as string)] }, { consistency: "strong" })) {
      if (String((e.value as Record<string, unknown>).account_hash || "") === acct) { member = true; break; }
    }
    if (!member) return { __blocked: "group envelope list requires group membership" } as any;
  }
  // b198 DELETION OBSERVABILITY (live battery Oct 15): a VeilEnvelope list
  // scoped to a session that no longer exists (or has ended) must NOT answer
  // 200 + empty — the native sync reads an empty page as "nothing new" and
  // loops inside a dead thread forever (✕-end, + supersede and the sweeper
  // all left the peer blind; the auto-switch needs the sync ERROR to trigger
  // its forced list refresh). A 404 "Session not found" makes every deletion
  // path observable to every client in one pass.
  if (name === "VeilEnvelope") {
    const st = q.get("session_token");
    if (st) {
      const sess = await findSessionByToken(st);
      if (!sess || String(sess.state || "") === "ended") {
        return { __notfound: "Session not found" } as any;
      }
      // b199 AUTHZ (audit finding #6, Oct 17): a session_token list returns
      // only to the two accounts in that conversation. Anyone holding a token
      // used to page through its ciphertext and metadata. Group streams are
      // listed by group_token (member-gated above); a device transfer keeps
      // the same account, and an identity can't be re-bound to another
      // account (register refuses), so participants never lose access.
      if (auth) {
        const uid = auth.userId;
        if (String(sess.initiator_client_id || "") !== uid && String(sess.responder_client_id || "") !== uid) {
          return { __blocked: "envelope list requires being in this conversation" } as any;
        }
      }
    }
  }
  // owner-scoped entities only ever answer their owner's queries
  if (auth && OWNER_SCOPED_ENTITIES.has(name)) {
    const acct = await accountHashOf(auth.userId);
    out = out.filter((r) => String((r as any)._acct ?? "") === acct);
  }
  for (const [k, v] of filters) out = out.filter((r) => String((r as any)[k] ?? "") === v);
  if (sortField) {
    out.sort((a, b) => {
      const av = String((a as any)[sortField!] ?? ""), bv = String((b as any)[sortField!] ?? "");
      return sortDesc ? bv.localeCompare(av) : av.localeCompare(bv);
    });
  } else {
    out.sort((a, b) => String(b.created_date ?? "").localeCompare(String(a.created_date ?? "")));
  }
  return out.slice(skip, skip + limit);
}

const OWNER_SCOPED_ENTITIES = new Set(["VeilVault", "VeilNote", "VeilPushToken"]);
/** Batch D (D-13): the only fields a client may write when it creates a session row
 *  (invite.ts createInviteSession, contact.ts createOneTapSession, lounge posting rows) */
const VEIL_SESSION_CREATE_FIELDS = [
  "token", "initiator_display_name", "passphrase_required", "session_fingerprint",
  "initiator_pub_jwk", "initiator_pq_pub", "initiator_pq_ct", "initiator_ek_pub", "initiator_sig", "initiator_veil_id",
  "responder_veil_id", "contact_session", "initiator_write_hash", "responder_write_hash",
  "default_ttl_seconds", "expire_after_seconds", "key_retention_hours", "burn_after_open", "last_activity", "expires_at",
  "group_token", "group_name", "group_epoch", "invitee_veil_id",
] as const;
/** Batch D (D-13, RV-11): requests one account may file to one other Vardum ID per day */
const REQUESTS_PER_TARGET_PER_DAY = 10;
/** Batch E (R3-10): session rows one account may create per day (a 100-member
 *  group is 101 rows; the app's own use is far below this) */
const SESSION_CREATES_PER_DAY = 200;
/** Batch E (RV-40): forum roster seats one account may hold */
const FORUM_SEATS_PER_ACCOUNT = 3;
/** Batch E (R3-02): rows that only NAME the caller (requests, restore matches) listed at most */
const LIST_NAMING_CAP = 100;
/** Batch D (D-13, RV-09): one call ring per conversation per ring window */
const CALL_RING_WINDOW_MS = 20_000;
const REQUIRED_LIST_FILTER: Record<string, string> = {
  VeilSession: "token",
  VeilEnvelope: "session_token",
  VeilPushToken: "expo_token",
};

async function createEntity(name: string, body: Record<string, unknown>, auth?: { userId: string; email?: string }) {
  // b199 AUTHZ: the row id is ALWAYS server-chosen — a client-supplied id used
  // to overwrite any existing row of the same entity (another account's vault,
  // note, session). Ownership fields are server-stamped, never client-supplied.
  const ridv = rid();
  // Batch D (D-13, RV-09): server fields are never client-supplied (the row spread
  // used to let a body set created_date / updated_date)
  const { id: _ignoredId, _acct: _ignoredAcct, _owner: _ignoredOwner, created_date: _ignoredC, updated_date: _ignoredU, ...clean } = body;
  body = clean;
  // Batch D (D-13, RV-09/RV-11): a session row is built from a whitelist. It is
  // always owned by its creator, and responder fields are set
  // only by the gate's join (so a row can't claim to be already joined or to be
  // someone else's conversation).
  if (name === "VeilSession") {
    const picked: Record<string, unknown> = {};
    for (const f of VEIL_SESSION_CREATE_FIELDS) if (body[f] !== undefined) picked[f] = body[f];
    // (a peerless row may start active, as group main rows and forum posting rows
    // do; without responder fields that grants nothing — pushes need the target
    // side to have joined from its own account, see pushTargetJoined)
    const state = body.state === "active" ? "active" : "pending";
    body = { ...picked, state, initiator_client_id: auth?.userId ?? "", responder_client_id: "", responder_display_name: "", initiator_verified: false, responder_verified: false };
    // Batch E (round-3 review R3-06): the initiator's Vardum ID must be one bound
    // to the caller's own account. It was taken as written, so a row could show
    // as a request "from" any contact (and pose as that contact's new chat).
    const initVid = String(body.initiator_veil_id ?? "");
    if (initVid) {
      const iid = auth ? (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(initVid)])).value : null;
      if (!iid || iid.bound !== true || String(iid.account_hash || "") !== await accountHashOf(auth!.userId)) {
        return { __forbidden: "That Vardum ID is not yours" } as any;
      }
    }
    // Batch E (R3-10): lifetimes are the relay's, not the client's. A pending
    // row dies at expires_at, clamped to [now, now + its unopened-message dial]
    // (24 h minimum, 30 days at most, the forum's posting rows); last_activity
    // starts now. Far-future values used to make rows the sweeper never removed.
    const nowMs = Date.now();
    const dialS = Number(body.expire_after_seconds);
    const maxLife = Math.min(30 * 86400_000, Math.max(86400_000, Number.isFinite(dialS) ? dialS * 1000 : 0));
    const askedExp = Date.parse(String(body.expires_at ?? ""));
    body.expires_at = new Date(Number.isFinite(askedExp) ? Math.min(nowMs + maxLife, Math.max(nowMs, askedExp)) : nowMs + maxLife).toISOString();
    body.last_activity = new Date(nowMs).toISOString();
    // Batch F (round-4 reviews R4-3-01 / R4-4-20): key_retention_hours, as the app
    // clamps it (whole hours, 0-720; 0 = Off, which the sweeper reads as a year).
    // An unbounded value made rows the sweeper never removed. Same rule as the
    // app's clampDials, so an invite link's dials still match the row.
    { const h = Number(body.key_retention_hours); body.key_retention_hours = Number.isInteger(h) ? Math.min(720, Math.max(0, h)) : 168; }
    // one account can't flood (or fill) another user's request list
    const target = String(body.responder_veil_id || "");
    if (auth && validVeilId(target)) {
      const tid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(target)])).value;
      const mine = !!tid && String(tid.account_hash || "") === await accountHashOf(auth.userId);
      if (!mine && await rateLimit(`req:${await accountHashOf(auth.userId)}:${target}`, REQUESTS_PER_TARGET_PER_DAY, 86400_000, 0)) {
        return { __forbidden: "Too many requests to this Vardum ID today" } as any;
      }
    }
    // Batch E (R3-10): and no account mints session rows without limit
    if (auth && await rateLimit(`vscreate:${auth.userId}`, SESSION_CREATES_PER_DAY, 86400_000, 0)) {
      return { __forbidden: "Too many new conversations today — try again tomorrow" } as any;
    }
  }
  // Batch E (RV-39): a vault row may point only at a file its own account
  // uploaded — the sweeper keeps vault containers, so a row naming someone
  // else's blob kept that file forever (and its delete removed it)
  if (name === "VeilVault" && auth && !(await blobHeldBy(String(body.container_uri ?? ""), await accountHashOf(auth.userId)))) {
    return { __forbidden: "Not your file" } as any;
  }
  // owner-scoped entities (vaults/notes/push tokens) are tagged with the creating account
  if (auth && OWNER_SCOPED_ENTITIES.has(name)) {
    body = { ...body, _acct: await accountHashOf(auth.userId) };
  }
  // Batch H (round-6 reviews R6-3-01, R6-3-06, N6-1): a UnifiedPush row names a plain
  // topic on an allowed host and carries valid Web Push keys; one row per token
  // (the newest registration wins, so the sender's lookup is unambiguous); and at
  // most PUSH_ROWS_PER_ACCOUNT rows per account, the oldest replaced.
  if (name === "VeilPushToken" && auth) {
    const tok = String(body.expo_token || "");
    if (!tok || tok.length > 512) return { __forbidden: "Invalid push token" } as any;
    if (tok.startsWith(UP_TOKEN_PREFIX)) {
      const url = tok.slice(UP_TOKEN_PREFIX.length);
      if (!upEndpointAllowed(url)) return { __forbidden: "Push endpoint not allowed" } as any;
      if (body.up_endpoint !== undefined && String(body.up_endpoint) !== url) return { __forbidden: "Push endpoint mismatch" } as any;
      if (!upKeysValid(body.up_p256dh, body.up_auth)) return { __forbidden: "Push keys missing or invalid" } as any;
    }
    const mine: { key: Deno.KvKey; at: string }[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const r = e.value as Record<string, unknown>;
      if (String(r.expo_token || "") === tok) { await KV.delete(e.key); continue; }
      if (String(r._acct || "") === String(body._acct || "")) mine.push({ key: e.key, at: String(r.created_date || "") });
    }
    mine.sort((x, y) => x.at.localeCompare(y.at));
    for (const old of mine.slice(0, Math.max(0, mine.length - (PUSH_ROWS_PER_ACCOUNT - 1)))) await KV.delete(old.key);
  }
  // every other row records its creator as a per-row tag (unlinkable across
  // rows, so a peer reading a session row learns nothing about the account)
  else if (auth) {
    body = { ...body, _owner: await ownerTag(auth.userId, ridv) };
  }
  // Batch C (V-20): a group_token must be a hex string or absent — a non-string
  // (e.g. an array that stringifies to a real token) used to skip the creator rule
  if (name === "VeilSession" && body.group_token !== undefined && body.group_token !== "" && !(typeof body.group_token === "string" && /^[0-9a-f]{8,128}$/.test(body.group_token))) {
    return { __forbidden: "Invalid group token" } as any;
  }
  // b199 AUTHZ: group rows are minted only by the group's creator (createGroup
  // makes the main row and every invite row; members only JOIN invite rows).
  // Anyone else minting a row with a known group_token became a valid group
  // credential — attest a fresh key, read the roster and stream, rotate.
  if (name === "VeilSession" && auth && typeof body.group_token === "string" && body.group_token) {
    // the Founding Tester Forum is open by design: every tester mints their
    // own posting row in it (lounge.ts join/self-heal/epoch paths)
    if (body.group_token !== await loungeGroupToken() && !(await claimOrCheckGroupOwner(body.group_token, auth))) {
      return { __forbidden: "Only the group's creator can add sessions to it" } as any;
    }
  }
  // Batch D (add-later seats, found by the addlater check): a seat added to an
  // EXISTING group gets the group's current epoch and PQ key from the relay's own
  // group record — rotate stamps only the rows that exist at that moment, so a
  // seat made later used to peek as epoch 0 with no key and could never be joined.
  // (A brand-new group has no record yet: its creation rotate stamps every row.)
  if (name === "VeilSession" && typeof body.group_token === "string" && body.group_token && body.group_token !== await loungeGroupToken()) {
    const grec = await groupRecord(body.group_token);
    if (Number(grec.epoch) > 0) body = { ...body, group_epoch: Number(grec.epoch), group_pq_pub: String(grec.pq_pub || "") };
  }
  // session tokens are unique pointers — a duplicate create must NOT overwrite
  // the index (it would silently repoint submitEnvelope/burn at a hashless row)
  if (name === "VeilSession" && typeof body.token === "string" && body.token) {
    const existing = (await KV.get<string>(["veil_sess_token", body.token])).value;
    if (existing) return { __conflict: true, id: existing } as any;
    // ATOMIC claim of the token (check-and-set) — closes the concurrent-retry
    // race where two creates could both pass the existence check
    const claim = await KV.atomic()
      .check({ key: ["veil_sess_token", body.token], versionstamp: null })
      .set(["veil_sess_token", body.token], ridv)
      .commit();
    if (!claim.ok) return { __conflict: true, id: (await KV.get<string>(["veil_sess_token", body.token])).value ?? "" } as any;
  }
  const row = { id: ridv, created_date: nowIso(), updated_date: nowIso(), ...body };
  await KV.set(["entity", name, ridv], row);
  if (name === "VeilSession" && !(body as Record<string, unknown>).group_token) void bumpStat("chats");
  // b198 (cutover battery): a NEW 1:1 session addressed to a Veil ID is an
  // invite — the addressee gets NO envelope-insert ping from notifySent (an
  // invite carries no message), so without this they'd never see a lock-screen
  // notification for "someone wants to talk". Fire-and-forget, coalesced per
  // veil id, skipped for groups and peerless rows; the ping is contentless
  // ("Notification") exactly like every other push.
  if (name === "VeilSession") {
    const vid = String((body as Record<string, unknown>).responder_veil_id || "");
    const isPendingInvite = String((body as Record<string, unknown>).state || "") === "pending" && !String((body as Record<string, unknown>).responder_client_id || "");
    if (isPendingInvite && validVeilId(vid) && !(body as Record<string, unknown>).group_token) {
      void pushInvitePing(vid);
    }
  }
  return row;
}

// b198: invite ping — same contentless shape as message pings; coalesced per
// addressee so a burst of + presses can't stack pushes.
async function pushInvitePing(veilId: string) {
  try {
    const ck = ["push_coalesce_invite", keySafe(veilId)];
    if (Date.now() - ((await KV.get<number>(ck)).value ?? 0) < 30000) return;
    await KV.set(ck, Date.now(), { expireIn: COALESCE_TTL_MS });
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = id ? String(id.account_hash || "") : "";
    if (!acct) return;
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") !== acct) continue;
      const t = String(row.expo_token || "");
      void pushFetch(EXPO_PUSH_URL, { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ to: t, title: "Vardum", body: "Notification", sound: "default", priority: "high", data: { kind: "new-invite" } }) }).then(async (r) => { const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string } } | null; console.log("[push] invite ticket  device : " + (d?.data?.status ?? r.status) + (d?.data?.message ? " " + d.data.message : "")); }).catch(() => undefined);
    }
  } catch (e) { console.log("[push] invite alert failed (non-fatal)"); }
}

/**
 * b199: which account owns (created) a group. Recorded at the group's first
 * session row; groups from before the record existed are resolved from their
 * rows — a session row the caller created (_owner tag), or the creator's
 * member row (_acct, or the label-derived group account hash). A group with
 * no rows yet is claimed atomically by the caller.
 */
/** Batch C (B1): veil_id = base58(SHA-256(IK_pub))[0:16] — the client's derivation */
async function veilIdOfIk(ikPubB64: string): Promise<string> {
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(atob(ikPubB64), (c) => c.charCodeAt(0))));
  let n = 0n;
  for (const b of h) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of h) { if (b === 0) out = "1" + out; else break; }
  return out.slice(0, 16);
}

async function claimOrCheckGroupOwner(groupToken: string, auth: { userId: string; email?: string }): Promise<boolean> {
  // Batch D (D-18, RV-45): the forum is owned only by its configured founder —
  // never by whoever holds a row in it (every tester does), config or no config
  if (groupToken && groupToken === (await knownForum()).group_token) return await isLoungeFounder(auth);
  const k = ["veil_group_owner", keySafe(groupToken)];
  const acct = await accountHashOf(auth.userId);
  const recorded = (await KV.get<string>(k)).value;
  if (recorded) return recorded === acct;
  let seen = false, owns = false;
  for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const s = e.value as Record<string, unknown>;
    if (String(s.group_token || "") !== groupToken) continue;
    seen = true;
    if (s._owner && String(s._owner) === await ownerTag(auth.userId, String(e.key[e.key.length - 1]))) { owns = true; break; }
  }
  if (!owns) {
    const gAcct = await sha256hex("veil-group-account:" + String(auth.email || "").trim().toLowerCase());
    for await (const e of KV.list({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
      const m = e.value as Record<string, unknown>;
      if (String(m.group_token || "") !== groupToken) continue;
      seen = true;
      if (m.role === "creator" && (String(m._acct || "") === acct || (!!auth.email && String(m.account_hash || "") === gAcct))) { owns = true; break; }
    }
  }
  if (seen && !owns) return false;
  const claim = await KV.atomic().check({ key: k, versionstamp: null }).set(k, acct).commit();
  return claim.ok || (await KV.get<string>(k)).value === acct;
}

async function getEntity(name: string, eid: string) {
  return (await KV.get(["entity", name, eid])).value ?? null;
}

async function deleteEntity(name: string, eid: string) {
  const row = (await KV.get(["entity", name, eid])).value as Record<string, unknown> | null;
  await KV.delete(["entity", name, eid]);
  if (row && name === "VeilSession" && typeof row.token === "string") {
    await KV.delete(["veil_sess_token", row.token]);
    // b199: the session's envelopes go with it. The client falls back to this
    // generic delete when the gate's end-with-proof is refused (peer-created
    // rows), which used to orphan every envelope of the thread.
    await deleteSessionEnvelopes(row.token);
  }
  if (row && name === "VeilVault") await removeVaultBlob(row);
  return row;
}

/**
 * b199: the Founding Tester Forum's group_token. The descriptor's link
 * `?join=<token>` names the forum's invite row, which carries it. (Never the
 * `&g=` fragment — that is the forum's encryption key, not an identifier.)
 * Cached once found; "" if the row is missing, so the forum gets no
 * exemption rather than a wrong one.
 */
/**
 * Batch C (A5; reviews P2 V-7 V-17): the forum is configured on the server, not
 * in source — `{ descriptor: {v, link, founder_veil_id, founder_ik_pub, name},
 * group_token, pingers: [veil ids] }` at VEIL_FORUM_CONFIG (default
 * /opt/veil-relay/forum.json, mode 600). Re-read every 60 s. No (valid) file =
 * no forum: nothing is served and no forum exemption applies (fail closed).
 */
type ForumConfig = { descriptor: Record<string, unknown> & { link: string; founder_veil_id: string; founder_ik_pub: string }; group_token: string; pingers: string[] };
let forumCache: ForumConfig | null = null;
let forumAt = 0;
async function forumConfig(): Promise<ForumConfig | null> {
  if (Date.now() - forumAt < (Number(Deno.env.get("VEIL_FORUM_CACHE_MS")) || 60_000)) return forumCache; // env: test relays only
  forumAt = Date.now();
  try {
    const raw = JSON.parse(await Deno.readTextFile(Deno.env.get("VEIL_FORUM_CONFIG") || "/opt/veil-relay/forum.json"));
    const d = raw?.descriptor;
    const ok = d && typeof d.link === "string" && typeof d.founder_veil_id === "string" && typeof d.founder_ik_pub === "string"
      && typeof raw.group_token === "string" && /^[0-9a-f]{8,128}$/.test(raw.group_token);
    forumCache = ok ? { descriptor: d, group_token: raw.group_token, pingers: Array.isArray(raw.pingers) ? raw.pingers.map(String) : [] } : null;
  } catch { forumCache = null; }
  // Batch D (D-18, RV-45): remember the forum's identifiers, so a missing or
  // broken config file never turns the forum into an ordinary group
  if (forumCache) {
    let join = "";
    try { join = new URL(forumCache.descriptor.link).searchParams.get("join") ?? ""; } catch { join = ""; }
    const known = (await KV.get<{ group_token: string; invite: string }>(["forum_known"])).value;
    if (!known || known.group_token !== forumCache.group_token || known.invite !== join) await KV.set(["forum_known"], { group_token: forumCache.group_token, invite: join });
  }
  return forumCache;
}
/** Batch D (D-18): the forum's group token and founder invite row token as last
 *  configured — still known while the config file is unreadable */
async function knownForum(): Promise<{ group_token: string; invite: string }> {
  const cfg = await forumConfig();
  const known = (await KV.get<{ group_token: string; invite: string }>(["forum_known"])).value;
  if (cfg) return { group_token: cfg.group_token, invite: known?.invite ?? "" };
  return known ?? { group_token: "", invite: "" };
}
/** the forum's group token from config ("" = no forum configured) */
async function loungeGroupToken(): Promise<string> {
  return (await forumConfig())?.group_token ?? "";
}
async function isLoungeFounder(auth: { userId: string }): Promise<boolean> {
  const d = (await forumConfig())?.descriptor;
  if (!d) return false;
  const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(d.founder_veil_id)])).value;
  // bound, the configured founder KEY (not just the label), and the caller's account
  return !!id && id.bound === true && String(id.IK_pub || "") === d.founder_ik_pub
    && String(id.account_hash || "") === await accountHashOf(auth.userId);
}

// b199 (owner, Oct 17): forum PINGS also come from the owner's current main
// ID — ping permission only, none of the founder's other forum powers.
// Batch C: the allowed Vardum IDs live in the forum config, not in source.
async function mayPingLounge(auth: { userId: string }): Promise<boolean> {
  if (await isLoungeFounder(auth)) return true;
  const acct = await accountHashOf(auth.userId);
  for (const vid of (await forumConfig())?.pingers ?? []) {
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(vid)])).value;
    if (id && String(id.account_hash || "") === acct) return true;
  }
  return false;
}

async function findSessionByToken(token: string) {
  const eid = (await KV.get<string>(["veil_sess_token", keySafe(token)])).value;
  if (!eid) return null;
  return (await KV.get(["entity", "VeilSession", eid])).value as Record<string, unknown> | null;
}

// ---------- functions: submitEnvelope ----------
async function fnSubmitEnvelope(auth: { userId: string }, body: Record<string, any>) {
  // b198 HARDENING (live-caught during the vault battery): Deno KV values cap
  // at 64KB — an oversized envelope used to crash the handler into a 500
  // ("Value too large"). Legit chat never approaches this (M-4 chunks cap at
  // 4096 bytes); the guard turns a hostile/buggy oversized envelope into a
  // clean 413. Media never rides envelopes at all (ciphertext lives in blob
  // storage; the envelope carries only the descriptor).
  const b64Ct = String(body?.ciphertext || "");
  if (b64Ct.length > 48000) return j({ error: "Envelope too large", message: "Envelope too large" }, 413);
  // SPEC §3/§4: 150 envelopes/min per account
  const rl = await rateLimit("env:" + auth.userId, 150, 60_000, 2);
  if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
  const { session_token, ciphertext, iv, header, ttl_seconds } = body;
  if (!session_token || !ciphertext || !iv || !header) {
    return j({ error: "Missing envelope fields", message: "Missing envelope fields" }, 400);
  }
  const session = await findSessionByToken(session_token);
  if (!session) return j({ error: "Session not found", message: "Session not found" }, 404);
  if (session.state !== "active") return j({ error: "Session is not available", message: "Session is not available" }, 409);

  // b198 GROUP CLAUSE — faithful port of the Base44 submit's veil-group-1
  // branch (this was entirely MISSING from my submit: group envelopes were
  // stored without their group_token, so the group-scoped receive channel
  // could never see them — One's 'hey' vanished exactly there).
  let headerObj: Record<string, unknown> | null = null;
  try { headerObj = JSON.parse(String(header)); } catch { /* 1:1 path: opaque header string is fine */ }
  const isGroupEnvelope = !!headerObj && (headerObj as Record<string, unknown>).v === "veil-group-1";
  let groupToken = "";
  if (isGroupEnvelope) {
    const gh = headerObj as Record<string, unknown>;
    groupToken = typeof body.group_token === "string" ? body.group_token : "";
    if (!groupToken || !/^[0-9a-f]{8,128}$/.test(groupToken)) return j({ error: "Missing or invalid group_token", message: "Missing or invalid group_token" }, 400);
    if (gh.v !== "veil-group-1" || typeof gh.sid !== "string" || !gh.sid || !Number.isInteger(gh.ge) || (gh.ge as number) < 0 || !Number.isInteger(gh.n) || (gh.n as number) < 0) {
      return j({ error: "Invalid group message header", message: "Invalid group message header" }, 400);
    }
    if (String(body.sender_client_id || "") !== String(gh.sid)) return j({ error: "Sender tag does not match the group header", message: "Sender tag does not match the group header" }, 400);
  }

  // write-secret authorization: sha256(write_secret) must match a stored hash
  const writeSecret = String(body.write_secret || "");
  const sha256 = async (v: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const wHash = writeSecret ? await sha256(writeSecret) : "";
  const iHash = String(session.initiator_write_hash || "");
  const rHash = String(session.responder_write_hash || "");
  if (!wHash || (!ctEq(wHash, iHash) && !ctEq(wHash, rHash))) { // Batch C (B7): constant time (V-30)
    console.log("[submit] write-secret mismatch (session details not logged — b199 audit)");
    return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }

  // b198 GROUP VALIDATIONS (Base44 order): session-group binding, header epoch
  // vs the server-side group epoch, and roster membership of the sender tag.
  if (isGroupEnvelope) {
    const gh = headerObj as Record<string, unknown>;
    if (typeof session.group_token !== "string" || session.group_token !== groupToken) { // Batch C (V-20): strict
      return j({ error: "This session does not belong to that group", message: "This session does not belong to that group" }, 403);
    }
    if (Number(session.group_epoch || 0) !== Number(gh.ge)) {
      return j({ error: "Message epoch does not match the group epoch", message: "Message epoch does not match the group epoch" }, 400);
    }
    // The fetch limit MUST cover the whole roster — a limit below the cohort
    // cap silently refuses legitimate members (Base44 shared-limits lesson).
    const members: Record<string, unknown>[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
      const m = e.value as Record<string, unknown>;
      if (String(m.group_token || "") === groupToken) members.push(m);
    }
    let rostered = false;
    for (const m of members.slice(0, 100)) { // b198: cohort cap 100
      const vid = String(m.veil_id || "");
      if (!vid) continue;
      const tag = "g" + [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`veil-group-sender:${groupToken}:${gh.ge}:${vid}`))).slice(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
      if (tag === String(body.sender_client_id || "")) { rostered = true; break; }
    }
    if (!rostered) return j({ error: "Sender is not a member of this group epoch", message: "Sender is not a member of this group epoch" }, 403);
  }

  // b198 DIAGNOSTIC (two-dial burn investigation): log the incoming ttl + the
  // session's dials — numbers only, never content. Remove after the root cause lands.
  // b198: the clamp rises to the 30-day tier (the Founding Tester Forum's
  // backlog lifetime) — was 36h, which would have killed a 30-day-dial group's
  // messages in a day and a half.
  const ttl = Math.min(Number(ttl_seconds) || 86400, 2592000);
  const envId = rid();
  const env = {
    id: envId,
    session_token,
    // b198: group envelopes carry their group_token + header epoch — the
    // group-scoped receive channel filters on exactly these.
    ...(groupToken ? { group_token: groupToken, group_epoch: Number((headerObj as Record<string, unknown>).ge) } : {}),
    // Batch C (V-13): the sender's stable account id is no longer stored on
    // envelopes (it made the per-rotation sender pseudonym pointless). A
    // per-envelope owner tag (unlinkable across envelopes) lets account
    // deletion still find this account's envelopes.
    _owner: await ownerTag(auth.userId, envId),
    sender_client_id: String(body.sender_client_id || ""),
    ciphertext: String(body.ciphertext || ""),
    iv: String(body.iv || ""),
    header: String(body.header || ""),
    byte_length: Number(body.byte_length) || 0,
    protocolVersion: String(body.protocolVersion || "veil-ratchet-4"),
    created_date: nowIso(),
    expires_at: new Date(Date.now() + ttl * 1000).toISOString(),
  };
  await KV.set(["entity", "VeilEnvelope", envId], env);
  // b199 (Oct 16 audit): a second copy used to be written to ["veil_env",
  // session_token, envId] here. Nothing ever read it and NOTHING deleted it —
  // burn, expiry, ✕ and account deletion all removed only the entity row, so
  // every envelope ever sent survived on disk (ciphertext). Removed; the boot
  // migration below purges the copies already written.
  await KV.set(["veil_sess_token", session_token], session.id as string);
  await touchSession(session_token);
  void bumpStat("envelopes"); // includes cover traffic: the relay can't tell decoys apart
  return json({ id: envId });
}

async function touchSession(token: string, side?: "initiator" | "responder") {
  const eid = (await KV.get<string>(["veil_sess_token", keySafe(token)])).value;
  if (!eid) return;
  const row = (await KV.get(["entity", "VeilSession", eid])).value as Record<string, unknown> | null;
  if (!row) return;
  row.last_activity = nowIso();
  // b162 presence parity: the client reads initiator_seen_at / responder_seen_at
  if (side === "initiator") row.initiator_seen_at = nowIso();
  if (side === "responder") row.responder_seen_at = nowIso();
  await KV.set(["entity", "VeilSession", eid], row);
}

// (veilSessionGate moved to the PHASE 2 section below — full action set)

// ---------- functions: purgeExpiredEnvelopes ----------
async function fnPurgeExpired() {
  let deleted = 0;
  const now = Date.now();
  for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    const exp = new Date(String(row.expires_at || "")).getTime();
    if (Number.isFinite(exp) && exp < now) { await KV.delete(e.key); deleted++; }
  }
  // Batch C (B4; reviews P2 V-19, P3 R9): sessions now age out as the spec says.
  // 1:1 only — a quiet GROUP must never vanish (its rows are the members'
  // credentials). Pending invites die at expires_at; active chats die after
  // key_retention_hours without activity. Envelopes go with them.
  let sessions = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const s = e.value;
    if (!s || s.group_token) continue;
    const state = String(s.state || "");
    const pendingDead = state === "pending" && Number.isFinite(Date.parse(String(s.expires_at || ""))) && Date.parse(String(s.expires_at)) < now;
    const lastSeen = Date.parse(String(s.last_activity || s.updated_date || s.created_date || ""));
    const quietDead = state === "active" && Number.isFinite(lastSeen) && now - lastSeen > retentionMs(s);
    if (!pendingDead && !quietDead) continue;
    const tok = String(s.token || "");
    if (tok) { deleted += await deleteSessionEnvelopes(tok); await KV.delete(["veil_sess_token", keySafe(tok)]); }
    await KV.delete(e.key);
    sessions++;
  }
  // Batch C (B5): expired device-transfer links and their bundles
  let links = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["devlink"] }, { consistency: "strong" })) {
    if (Number(e.value?.exp || 0) >= now) continue;
    const path = blobPathOf(String(e.value?.container_uri || ""));
    if (path) await Deno.remove(path).catch(() => undefined);
    await KV.delete(e.key);
    links++;
  }
  return json({ purged: { success: true, deleted }, sessions: { success: true, deleted: sessions }, links: { success: true, deleted: links }, loginGuards: { success: true, deleted: 0 }, nonces: { success: true, deleted: 0 } });
}

// ==================== PHASE 2 — full client contract (b198 port) ====================
// Contract extracted from vendor/device/src/{relay,contact,group-session,groups,transfer,
// silent-auth,restore,auth}.ts + docs/audit/RELAY-PORT-SPEC.md. Every response shape
// below matches what the client actually parses (data-wrapped and/or bare).

const enc = new TextEncoder();
const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64d = (s: string) => new Uint8Array([...atob(s)].map((c) => c.charCodeAt(0)));
/** b199: storage key for a login token — a one-way hash, never the token */
const authKey = async (token: string) => ["auth", "h:" + await sha256hex("veil-auth-token:" + token)];
const sha256hex = async (v: string) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(v)))].map((b) => b.toString(16).padStart(2, "0")).join("");

async function ed25519Verify(pubB64: string, msgBytes: Uint8Array, sigB64: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", b64d(pubB64) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64d(sigB64) as BufferSource, msgBytes as BufferSource);
  } catch (e) {
    console.log("[verify] ed25519 verify error:", String((e as Error).message).slice(0, 120));
    return false;
  }
}

// ---------- per-account rate limiter (SPEC §3: 150 env/min; identity gate 429 shape) ----------
async function rateLimit(key: string, cap: number, windowMs: number, lockMinutes: number): Promise<{ locked: boolean; retry_minutes: number } | null> {
  const bucket = Math.floor(Date.now() / windowMs);
  const k = ["rl", key, String(bucket)];
  // Batch D (D-15, RV-13): read and write the count in ONE versionstamp-checked
  // step, retrying if another request got in between. The old read-then-write
  // let parallel requests all read the same count and all pass. (Not a `sum`
  // mutation: Deno KV can't put an expiry on one, and these rows must expire.)
  // Once the bucket is full nothing is written, so contention ends at `cap`.
  for (let attempt = 0; attempt < 100; attempt++) {
    const cur = await KV.get<number>(k);
    const n = (cur.value ?? 0) + 1;
    if (n > cap) return { locked: true, retry_minutes: lockMinutes };
    // b199: buckets expire once their window (+ lock) has passed — they used to
    // be kept forever, a growing per-account / per-network activity log
    if ((await KV.atomic().check(cur).set(k, n, { expireIn: windowMs + lockMinutes * 60_000 + 60_000 }).commit()).ok) return null;
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return { locked: true, retry_minutes: 1 }; // still contended: fail closed
}

/** Batch D (D-15, RV-13): login lockout counter — reads the guard and writes
 *  fails+1 (or the lock) in ONE versionstamp-checked step, retrying if another
 *  attempt got in between. ok=false: locked (or still contended after the
 *  retries — fail closed). The guard row keeps its { fails, lockedUntil } shape. */
async function reserveLoginAttempt(k: Deno.KvKey, max: number, lockMs: number): Promise<{ ok: boolean; lockedUntil: number }> {
  for (let attempt = 0; attempt < 50; attempt++) {
    const cur = await KV.get<{ fails: number; lockedUntil: number }>(k);
    const now = Date.now();
    if (cur.value && cur.value.lockedUntil > now) return { ok: false, lockedUntil: cur.value.lockedUntil };
    const fails = (cur.value?.fails ?? 0) + 1;
    const next = fails >= max ? { fails: 0, lockedUntil: now + lockMs } : { fails, lockedUntil: 0 };
    if ((await KV.atomic().check(cur).set(k, next, { expireIn: THROTTLE_TTL_MS }).commit()).ok) return { ok: true, lockedUntil: 0 };
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return { ok: false, lockedUntil: Date.now() + 60_000 };
}

async function accountHashOf(userId: string) {
  return "ah_" + (await sha256hex("veil-acct:" + userId));
}

/** b199: per-row creator tag — proves "this account created this row" without
 *  putting a cross-row account identifier into rows peers can read. */
async function ownerTag(userId: string, rowId: string) {
  return "ow_" + (await sha256hex("veil-owner:" + userId + ":" + rowId));
}

/** b199: group-salted hash of a banned identity's veil id / IK — what a deny
 *  entry keeps once the banned account is deleted (the ban outlives the
 *  account; the identifiers do not). */
async function denyHash(groupToken: string, value: string) {
  return "dh_" + (await sha256hex("veil-deny:" + groupToken + ":" + value));
}

// ---------- veilIdentityGate (public keys only — never private material) ----------
async function fnVeilIdentityGate(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body.action || "");
  const veilId = String(body.veil_id || "").trim();
  if (veilId.length > MAX_VEIL_ID) return j({ error: "Invalid identity", message: "Invalid identity" }, 400); // P7 fix
  if (action === "register") {
    // b198 tuning: 20/min + 10-min lock punished real testing (background
    // loops + manual retries trip it instantly). 60/min + 2-min lock keeps
    // the abuse wall while letting humans + heartbeats coexist.
    const rl = await rateLimit("idreg:" + auth.userId, 60, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    if (!veilId || !body.IK_pub) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    // Batch C (B1; reviews P2 V-8, P3 R4): a Vardum ID IS the hash of its
    // identity key — a registration whose ID doesn't derive from its key is refused
    let ikLen = 0;
    try { ikLen = atob(String(body.IK_pub)).length; } catch { ikLen = 0; }
    if (ikLen !== 32 || (await veilIdOfIk(String(body.IK_pub))) !== veilId) {
      return j({ error: "This Vardum ID does not match its identity key", message: "This Vardum ID does not match its identity key" }, 400);
    }
    // IDENTITY-HIJACK GUARD + b198 RESTORE FIX v2 (the v1 byte-identical rule
    // was wrong: the IK is the identity and derives deterministically from the
    // phrase, but SPK/PQ are FRESHLY GENERATED PREKEYS per restore — no restore
    // can ever reproduce them, and it must not: they are rotatable by design).
    // Rules, mirroring the key hierarchy:
    //   - a DIFFERENT IK on an existing veil_id = a different identity claiming
    //     the label -> 409 always (bound or not — the IK defines the identity);
    //   - same IK + BOUND: prekey rotation allowed ONLY for the bound account
    //     (the signed-in caller proves ownership by session) -> update, 200;
    //   - same IK + UNBOUND: rotate freely (unbound rows are trusted for
    //     nothing until bound).
    // b54: pq_sig = Ed25519(IK, label || pq_pub) — stored and served as-is;
    // clients verify it against the pinned IK (the relay is not trusted to).
    // Shape check only: 64 raw bytes, else stored empty (pre-b54 clients).
    let pqSig = "";
    if (typeof body.pq_sig === "string" && body.pq_sig) {
      try { if (Uint8Array.from(atob(body.pq_sig), (c) => c.charCodeAt(0)).length === 64) pqSig = body.pq_sig; } catch { pqSig = ""; }
    }
    const existingId = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    if (existingId) {
      const sameIk = String(existingId.IK_pub || "") === String(body.IK_pub);
      if (!sameIk) {
        console.warn("register-refused", { reason: "different-identity" });
        return j({ error: "Identity already bound", message: "Identity already bound" }, 409);
      }
      if (existingId.bound === true && String(existingId.account_hash || "") !== String(await accountHashOf(auth.userId))) {
        console.warn("register-refused", { reason: "bound-to-another-account" });
        return j({ error: "Identity already bound", message: "Identity already bound" }, 409);
      }
      // prekey rotation (SPK/PQ) — binding untouched
      await KV.set(["veil_identity", veilId], { ...existingId, SPK_pub: String(body.SPK_pub || ""), SPK_sig: String(body.SPK_sig || ""), pq_pub: String(body.pq_pub || ""), pq_sig: pqSig, updated_date: nowIso() });
      return json({ ok: true, data: { veil_id: veilId, restored: existingId.bound === true } });
    }
    const rec = {
      veil_id: veilId,
      IK_pub: String(body.IK_pub),
      SPK_pub: String(body.SPK_pub || ""),
      SPK_sig: String(body.SPK_sig || ""),
      pq_pub: String(body.pq_pub || ""),
      pq_sig: pqSig,
      account_hash: await accountHashOf(auth.userId),
      bound: false,
      created_date: nowIso(),
      updated_date: nowIso(),
    };
    await KV.set(["veil_identity", veilId], rec);
    void bumpStat("identities");
    return json({ ok: true, data: { veil_id: veilId } });
  }
  if (action === "challenge") {
    // b167: the 429 body carries ONLY {locked:true, retry_minutes} — NO message field
    const rl = await rateLimit("idchallenge:" + auth.userId, 60, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    if (!veilId) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    // nonce is base64 — ikSign(seed, nonce) signs fromB64(nonce), so verification
    // at bind time decodes the nonce the same way
    const nonce = b64e(crypto.getRandomValues(new Uint8Array(32)));
    // Batch C (B1): the nonce belongs to the account that asked for it — another
    // account can neither overwrite it nor present the owner's signed answer
    await KV.set(["id_nonce", veilId, await accountHashOf(auth.userId)], { nonce, exp: Date.now() + 10 * 60_000 });
    return json({ data: { nonce } });
  }
  if (action === "bind") {
    const nonceKey = ["id_nonce", veilId, await accountHashOf(auth.userId)];
    const nonceRow = (await KV.get<{ nonce: string; exp: number }>(nonceKey)).value;
    if (!nonceRow || nonceRow.exp < Date.now()) return j({ error: "Nonce expired", message: "Nonce expired" }, 400);
    const rec = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    if (!rec) return j({ error: "Identity not found", message: "Identity not found" }, 404);
    // b54 (T-1): clients sign the domain-separated bind message
    // ("vardum-identity-bind-v1:" || nonce || ":" || veil_id). Batch C (D5):
    // the old raw-nonce form (b53) is no longer accepted.
    const nonceBytes = b64d(nonceRow.nonce);
    const labelled = new Uint8Array([...enc.encode("vardum-identity-bind-v1:"), ...nonceBytes, ...enc.encode(":" + veilId)]);
    const sigIn = String(body.signature || "");
    const ok = await ed25519Verify(String(rec.IK_pub), labelled, sigIn);
    if (!ok) return j({ error: "Signature verification failed", message: "Signature verification failed" }, 403);
    await KV.delete(nonceKey); // single use
    // Batch C (B1 follow-up): the identity belongs to the account that just
    // proved the key — not to whichever account registered the row first
    // (a pre-registration of someone else's IK can't capture their bind)
    rec.account_hash = await accountHashOf(auth.userId);
    rec.bound = true;
    rec.updated_date = nowIso();
    await KV.set(["veil_identity", veilId], rec);
    return json({ ok: true, data: { bound: true } });
  }
  if (action === "lookup") {
    const rl = await rateLimit("idlookup:" + auth.userId, 300, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    const rec = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    // lookup serves BOUND identities only — binding is the key-possession proof;
    // an unbound (unproven) record would let an attacker publish fake keys
    if (!rec || rec.bound !== true) return j({ error: "Identity not found", message: "Identity not found" }, 404);
    // b198: BARE bundle — exactly Base44's lookup shape (Response.json({veil_id,
    // ...keys...})). My {data:...} wrap made the group rotate's pq_pub read
    // resolve undefined ("no published PQ prekey") while the key sat published
    // on the row; the other lookup consumers were already shape-tolerant.
    return json({ veil_id: rec.veil_id, IK_pub: rec.IK_pub, SPK_pub: rec.SPK_pub, SPK_sig: rec.SPK_sig, pq_pub: rec.pq_pub, pq_sig: rec.pq_sig || "" });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- veilSessionGate — the full action set ----------
function wsHashOf(writeSecret: unknown) {
  return writeSecret ? sha256hex(String(writeSecret)) : "";
}

function sessionMatchesClient(session: Record<string, any>, clientId: string, veilId?: string) {
  if (clientId) {
    if (String(session.initiator_client_id || "") === clientId) return true;
    if (String(session.responder_client_id || "") === clientId) return true;
  }
  if (veilId) {
    if (String(session.initiator_veil_id || "") === veilId) return true;
    if (String(session.responder_veil_id || "") === veilId) return true;
  }
  return false;
}

async function deleteSessionEnvelopes(sessionToken: string) {
  let n = 0;
  for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    if (String(row.session_token || "") === sessionToken) { await KV.delete(e.key); n++; }
  }
  // b199: legacy per-session copies under ["veil_env", token, id] (no longer
  // written; the sweeper drops old ones) die with the session too
  if (sessionToken) {
    for await (const e of KV.list({ prefix: ["veil_env", sessionToken] }, { consistency: "strong" })) await KV.delete(e.key);
  }
  return n;
}

// ---------- UnifiedPush / Web Push delivery (GrapheneOS: no Google) ----------
// Android phones without Google Play register a UnifiedPush endpoint (ntfy)
// instead of an Expo token: their VeilPushToken row carries
// expo_token "up:<endpoint>" + up_p256dh / up_auth. Every push site below
// calls pushFetch() exactly where it used to call fetch() on Expo: Expo tokens
// go to Expo unchanged; "up:" tokens get a Web Push (RFC 8030) with an RFC
// 8291 aes128gcm body that only the phone can decrypt. Same contentless
// threat model: the only plaintext the phone sees is {"kind": ...}; the push
// server (ntfy) sees ciphertext and timing only.
const EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";
const UP_TOKEN_PREFIX = "up:";
// SSRF guard: the endpoint is client-supplied, so the relay only ever POSTs
// to push servers on this list (https, default port, no redirects).
// VEIL_UP_HOSTS adds more, comma-separated (e.g. the self-hosted ntfy).
const UP_ALLOWED_HOSTS = new Set<string>([
  "ntfy.sh",
  ...String(Deno.env.get("VEIL_UP_HOSTS") || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
]);
const upTe = new TextEncoder();

function upB64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function upConcat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function upHkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, bytes: number): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", ikm as unknown as BufferSource, "HKDF", false, ["deriveBits"]); // Batch G: type-only casts (Deno 2 Uint8Array typing)
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt as unknown as BufferSource, info: info as unknown as BufferSource }, k, bytes * 8));
}

/** RFC 8291 aes128gcm Web Push encryption (single record). `opts` is for the RFC test vector only. */
async function webPushEncrypt(
  uaPublicB64u: string,
  authB64u: string,
  plaintext: Uint8Array,
  opts?: { asKeyPair?: CryptoKeyPair; salt?: Uint8Array },
): Promise<Uint8Array> {
  const uaPublic = upB64uDecode(uaPublicB64u);
  const auth = upB64uDecode(authB64u);
  if (uaPublic.length !== 65 || uaPublic[0] !== 0x04 || auth.length !== 16) throw new Error("bad web push keys");
  const asKp = opts?.asKeyPair ?? await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]) as CryptoKeyPair;
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", asKp.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic as unknown as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asKp.privateKey, 256));
  const ikm = await upHkdf(auth, ecdh, upConcat(upTe.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = opts?.salt ?? crypto.getRandomValues(new Uint8Array(16));
  const cek = await upHkdf(salt, ikm, upTe.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await upHkdf(salt, ikm, upTe.encode("Content-Encoding: nonce\0"), 12);
  const key = await crypto.subtle.importKey("raw", cek as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
  // single record: plaintext + 0x02 delimiter (last record), no padding
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as unknown as BufferSource }, key, upConcat(plaintext, new Uint8Array([2])) as unknown as BufferSource));
  const header = new Uint8Array(21 + asPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return upConcat(header, ct);
}

// Batch H (round-6 review R6-3-01): the endpoint must be a plain topic on an
// allowed host. A path or query used to be free, so a row could make the relay
// call any of the push host's API (for example ntfy.sh publish options).
const UP_TOPIC_RE = /^\/[A-Za-z0-9_-]{1,64}$/;
function upEndpointAllowed(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && (u.port === "" || u.port === "443") && !u.username && !u.password &&
      UP_ALLOWED_HOSTS.has(u.hostname.toLowerCase()) &&
      UP_TOPIC_RE.test(u.pathname) && (u.search === "" || u.search === "?up=1") && u.hash === "";
  } catch { return false; }
}

/** Batch H (N6-1 / R6-3-03): Web Push keys of the right shape (P-256 point, 16-byte auth) */
function upKeysValid(p256: unknown, auth: unknown): boolean {
  try {
    const p = upB64uDecode(String(p256 || "")), a = upB64uDecode(String(auth || ""));
    return p.length === 65 && p[0] === 4 && a.length === 16;
  } catch { return false; }
}
/** Batch H (R6-3-01): push rows one account may hold (the oldest is replaced) */
const PUSH_ROWS_PER_ACCOUNT = 5;
/** Batch H (R6-3-07): every Web Push plaintext is padded to this length */
const UP_PLAINTEXT_LEN = 64;

/** Send one contentless Web Push ping to a "up:" token. Returns an Expo-style status string. */
async function sendUnifiedPush(token: string, kind: string): Promise<string> {
  const url = token.slice(UP_TOKEN_PREFIX.length);
  if (!upEndpointAllowed(url)) return "up-host-not-allowed";
  let row: Record<string, unknown> | null = null;
  let rowKey: unknown = null;
  for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
    const r = e.value as Record<string, unknown>;
    if (String(r.expo_token || "") === token) { row = r; rowKey = e.key; break; }
  }
  if (!row) return "up-no-row";
  const k = kind === "call" ? "call" : kind === "new-invite" ? "new-invite" : "new-message";
  const p256 = String(row.up_p256dh || "");
  const auth = String(row.up_auth || "");
  // Batch H (N6-1 / R6-3-03): no plaintext path — a row without valid keys gets nothing
  if (!upKeysValid(p256, auth)) return "up-no-keys";
  // Batch H (round-6 review R6-3-07): one TTL and one padded length for every kind,
  // so the push server can't tell a call from a message. The send time rides inside
  // the encryption; the phone shows "Incoming call" only while it is fresh.
  const headers: Record<string, string> = { "TTL": "86400", "Urgency": "high" };
  const body = await webPushEncrypt(p256, auth, upTe.encode(JSON.stringify({ kind: k, t: Date.now() }).padEnd(UP_PLAINTEXT_LEN)));
  headers["Content-Encoding"] = "aes128gcm";
  headers["Content-Type"] = "application/octet-stream";
  const r = await fetch(url, { method: "POST", headers, body: body as unknown as BodyInit, redirect: "manual", signal: AbortSignal.timeout(10_000) });
  await r.body?.cancel().catch(() => undefined);
  if ((r.status === 404 || r.status === 410) && rowKey) {
    // the distributor dropped this endpoint: prune the dead row
    await KV.delete(rowKey as any).catch(() => undefined);
    return "up-gone";
  }
  return r.ok ? "ok" : "up-http-" + r.status;
}

/** Drop-in for fetch(EXPO_PUSH_URL, …) at every push site: routes "up:" tokens to Web Push. */
async function pushFetch(url: string, init: RequestInit): Promise<Response> {
  let msg: Record<string, any> | null = null;
  try { msg = JSON.parse(String(init.body ?? "")); } catch { msg = null; }
  const to = String(msg?.to ?? "");
  if (url !== EXPO_PUSH_URL || !to.startsWith(UP_TOKEN_PREFIX)) return fetch(url, init);
  let status: string;
  try { status = await sendUnifiedPush(to, String(msg?.data?.kind ?? "new-message")); }
  // Batch H (R6-3-08): fetch errors start with the URL — never log the endpoint
  catch (e) { status = "up-error " + String((e as Error).message || e).replace(/https?:\/\/\S+/g, "<endpoint>").slice(0, 80); }
  console.log("[push] unifiedpush " + String(msg?.data?.kind ?? "") + ": " + status);
  return new Response(JSON.stringify({ data: { status } }), { status: 200, headers: { "Content-Type": "application/json" } });
}

// ---------- push delivery (b85 parity — zero-content banner) ----------
async function pushNewMessageAlert(session: Record<string, any>, side: "initiator" | "responder") {
  try {
    // resolve the recipient: veil_id → identity → account → push tokens
    const veilId = String(side === "initiator" ? session.initiator_veil_id : session.responder_veil_id || "");
    if (!veilId) return; // invite-link sessions carry no veil ids — cannot map yet
    const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = identity ? String(identity.account_hash || "") : "";
    if (!acct) return;
    const tokens: string[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") === acct) tokens.push(String(row.expo_token || ""));
    }
    if (!tokens.length) return;
    const receipts = await Promise.allSettled(tokens.map(async (t) => {
      const r = await pushFetch(EXPO_PUSH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ to: t, title: "Vardum", body: "Notification", sound: "default", priority: "high", data: { kind: "new-message" } }),
      });
      const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string; details?: { error?: string } } } | null;
      const status = d?.data?.status ?? "http-" + r.status;
      console.log("[push] expo ticket for  device : " + status + (d?.data?.message ? " — " + d.data.message : "") + (d?.data?.details?.error ? " (" + d.data.details.error + ")" : ""));
      return status;
    }));
    const okN = receipts.filter(r => r.status === "fulfilled" && r.value === "ok").length;
    console.log("[push] new-message alert: " + okN + "/" + tokens.length + " accepted by Expo for " + "recipient");
  } catch (e) {
    console.log("[push] notify push failed (non-fatal): " + String((e as Error).message || e).slice(0, 120));
  }
}

// b198 CALL RING BURST: a call must RING, not whisper — a burst of pushes
// across the ring window (one every 2.5s for ~20s) buzzes the callee's lock
// screen on-and-off until they open, and each banner says "Incoming call" so
// it is unmistakable next to a message's "Notification". Same contentless
// threat model: no caller, no session, no content — only "a call is ringing
// on your account right now", which the ring itself announces anyway.
/** Batch D (D-13, RV-09): the push target side joined from the account that owns
 *  its Vardum ID. Rows without a Vardum ID (invite links) carry no push target. */
async function pushTargetJoined(session: Record<string, any>, side: "initiator" | "responder"): Promise<boolean> {
  const veilId = String(side === "initiator" ? session.initiator_veil_id || "" : session.responder_veil_id || "");
  if (!veilId) return true;
  const clientId = String(side === "initiator" ? session.initiator_client_id || "" : session.responder_client_id || "");
  if (!clientId) return false;
  const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
  return !!identity && String(identity.account_hash || "") === await accountHashOf(clientId);
}

const CALL_BURST_COUNT = 9;
const CALL_BURST_GAP_MS = 2500;
async function pushCallBurst(session: Record<string, any>, side: "initiator" | "responder") {
  try {
    const veilId = String(side === "initiator" ? session.initiator_veil_id : session.responder_veil_id || "");
    if (!veilId) return;
    const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = identity ? String(identity.account_hash || "") : "";
    if (!acct) return;
    const tokens: string[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") === acct) tokens.push(String(row.expo_token || ""));
    }
    if (!tokens.length) return;
    void (async () => {
      for (let i = 0; i < CALL_BURST_COUNT; i++) {
        if (i > 0) await new Promise((res) => setTimeout(res, CALL_BURST_GAP_MS));
        await Promise.allSettled(tokens.map(async (t) => {
          const r = await pushFetch(EXPO_PUSH_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            // b198 (owner): the burst pushes carry the app's ring sound — under
            // Metro it falls back to the default chime; on the EAS build (the
            // sound bundled with the app) the lock screen RINGS with the call.
            body: JSON.stringify({ to: t, title: "Vardum", body: "Incoming call", sound: "veil-ring.wav", priority: "high", channelId: "calls", data: { kind: "call" } }),
          });
          const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string } } | null;
          console.log("[push] call burst " + (i + 1) + "/" + CALL_BURST_COUNT + " for  device : " + (d?.data?.status ?? r.status));
        }));
      }
      console.log("[push] call ring burst complete for " + "recipient");
    })();
  } catch (e) {
    console.log("[push] call burst failed (non-fatal): " + String((e as Error).message || e).slice(0, 120));
  }
}

// b198: a group member's registered push tokens (owner-scoped rows).
async function groupMemberPushTokens(acct: string): Promise<string[]> {
  const out: string[] = [];
  for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    if (String(row._acct || "") === acct && String(row.expo_token || "")) out.push(String(row.expo_token));
  }
  return out;
}

// ---------- veilGroupGate ----------
async function groupRecord(groupToken: string) {
  return (await KV.get<Record<string, any>>(["veil_group", groupToken])).value ?? { epoch: 0, pq_pub: "", created_date: nowIso() };
}

async function fnVeilGroupGate(auth: { userId: string; email?: string }, body: Record<string, any>) {
  // b198 FAITHFUL PORT of base44_functions_veilGroupGate_entry.ts (the
  // founder's directive: stop interpreting, mirror the proven source
  // action-for-action). Every response shape, validation order and storage
  // semantic below mirrors the extracted Base44 entry — the client was built
  // against THIS contract, and my improvised KV-row variant diverged from it
  // in four ways (double-wrapped roster, wrong epoch source, no member
  // entity rows, no role/deny-list) which broke groups end to end.
  const tryB64Len = (v: unknown, bytes: number): boolean => {
    if (typeof v !== "string" || !v) return false;
    try {
      const raw = Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
      return raw.length === bytes;
    } catch { return false; }
  };
  const HEX_TOKEN = /^[0-9a-f]{8,128}$/;
  const B58_ID = /^[1-9A-HJ-NP-Za-km-z]{16}$/;
  const action = ["attest", "rotate", "evict", "roster", "notify", "wrap_request", "wrap_requests", "wrap_deliver", "wrap_fetch"].includes(String(body?.action || "")) ? String(body.action) : null;
  if (!action) return j({ error: "Unknown action", message: "Unknown action" }, 400);
  const groupToken = typeof body.group_token === "string" ? body.group_token : "";
  const sessionToken = typeof body.session_token === "string" ? body.session_token : "";
  if (!HEX_TOKEN.test(groupToken) || !HEX_TOKEN.test(sessionToken)) {
    return j({ error: "Invalid group or session token", message: "Invalid group or session token" }, 400);
  }
  const session = await findSessionByToken(sessionToken);
  if (!session) return j({ error: "Session not found", message: "Session not found" }, 404);
  if (!session.group_token || session.group_token !== groupToken) {
    return j({ error: "This session does not belong to that group", message: "This session does not belong to that group" }, 403);
  }
  if (String(session.state || "") !== "active") {
    return j({ error: "This session is not active", message: "This session is not active" }, 400);
  }
  const wHash = await wsHashOf(body?.write_secret);
  const slot = wHash && (ctEq(wHash, String(session.initiator_write_hash || "")) ? "initiator" : (ctEq(wHash, String(session.responder_write_hash || "")) ? "responder" : null));
  if (!slot) {
    console.warn("group-credential-refused", { action, state: String(session.state), presented: typeof body?.write_secret === "string" ? String(body.write_secret).length : 0 });
    return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }
  // Base44's group-account hash — reproducible from the auth token's email.
  const groupAccountHash = await sha256hex("veil-group-account:" + String(auth.email || "").trim().toLowerCase());
  const callerAcct = await accountHashOf(auth.userId);

  const memberRows = async (): Promise<Record<string, any>[]> => {
    const out: Record<string, any>[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
      const r = e.value as Record<string, any>;
      if (String(r.group_token || "") === groupToken) out.push({ ...r, id: e.key[e.key.length - 1] });
    }
    return out.slice(0, 100); // b198: MAX_GROUP_MEMBERS — the roster page MUST cover the whole cohort
  };
  const denyRows = async (limit = 200): Promise<Record<string, any>[]> => {
    const out: Record<string, any>[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilGroupDenyEntry"] }, { consistency: "strong" })) {
      const r = e.value as Record<string, any>;
      if (String(r.group_token || "") === groupToken) out.push({ ...r, id: e.key[e.key.length - 1] });
    }
    return out.slice(0, limit); // b198: deny-list page scales with the cohort (Batch H: attest reads all)
  };

  if (action === "roster") {
    const members = await memberRows();
    // Membership fence on CURRENT membership: the credential proves a slot; a
    // slot can outlive the membership it was issued for. Resolved from the
    // roster itself against the bindings written at attestation time.
    const isMember = members.some((m) => m.session_token === sessionToken || (!!groupAccountHash && m.account_hash === groupAccountHash) || (!!callerAcct && m._acct === callerAcct));
    if (!isMember) return j({ error: "You are not a member of this group.", membership_gone: true, message: "You are not a member of this group." }, 403);
    // Deliberately narrow projection — exactly Base44's field set. SINGLE wrap:
    // { members, epoch } at the top level (the client reads res.data.members).
    return json({
      members: members.map((m) => ({ veil_id: m.veil_id || "", IK_pub: m.IK_pub, role: m.role, joined_epoch: m.joined_epoch, attestation_sig: m.attestation_sig || "" })),
      epoch: Number(session.group_epoch || 0),
    });
  }

  if (action === "attest") {
    const ikPub = typeof body.IK_pub === "string" ? body.IK_pub : "";
    const veilId = typeof body.veil_id === "string" ? body.veil_id.trim() : "";
    const sig = typeof body.sig === "string" ? body.sig : "";
    const joinedEpoch = Number(body?.joined_epoch);
    if (!tryB64Len(ikPub, 32) || !tryB64Len(sig, 64)) return j({ error: "Invalid attestation material", message: "Invalid attestation material" }, 400);
    if (veilId !== "" && !B58_ID.test(veilId)) return j({ error: "Invalid veil_id", message: "Invalid Vardum ID" }, 400);
    // Deny-list FIRST — an evicted identity learns they were removed even if
    // their stale attestation no longer matches the current epoch.
    // Batch H (round-6 review R6-2-04): every deny entry is checked (the first 200,
    // in random-id order, used to be the only ones)
    const denies = await denyRows(Infinity);
    // tombstoned entries (banned account since deleted) match by hash only
    const ikHash = await denyHash(groupToken, ikPub);
    const vidHash = veilId !== "" ? await denyHash(groupToken, veilId) : "";
    if (denies.some((d) => d.target_IK_pub === ikPub || (veilId !== "" && d.target_veil_id === veilId)
      || d.target_ik_hash === ikHash || (vidHash !== "" && d.target_vid_hash === vidHash))) {
      return j({ error: "This identity was removed from the group", message: "This identity was removed from the group" }, 403);
    }
    // Batch H (round-6 reviews R6-2-03 / R6-3-05): a forum removal bars the ACCOUNT,
    // so a fresh Vardum ID on it can't take the seat straight back
    if (groupToken === (await knownForum()).group_token && denies.some((d) => !!d.target_acct && d.target_acct === callerAcct)) {
      return j({ error: "This account was removed from the forum", message: "This account was removed from the forum" }, 403);
    }
    if (!Number.isInteger(joinedEpoch) || joinedEpoch < 0 || joinedEpoch !== Number(session.group_epoch || 0)) {
      return j({ error: "joined_epoch does not match the current group epoch", message: "joined_epoch does not match the current group epoch" }, 400);
    }
    // Batch C (A1, reviews P1 NF-2 / P2 V-2 V-3 V-21): membership is bound to
    // the CALLER's own published, bound identity and to ONE seat.
    if (veilId === "") return j({ error: "A Vardum ID is required to join a group", message: "A Vardum ID is required to join a group" }, 400);
    const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    if (!identity) return j({ error: "Unknown identity", message: "Unknown identity" }, 404);
    if (String(identity.IK_pub || "") !== ikPub) return j({ error: "Identity does not match the published key", message: "Identity does not match the published key" }, 403);
    if (identity.bound !== true || String(identity.account_hash || "") !== callerAcct) {
      return j({ error: "That identity is not bound to your account", message: "That identity is not bound to your account" }, 403);
    }
    // the invitee seat lock applies to attest exactly as to peek/join — a
    // forwarded link (or a relay-held w) can't attest a different identity
    const lockedInvitee = String(session.invitee_veil_id || "");
    if (lockedInvitee && lockedInvitee !== veilId) {
      return j({ error: "This invitation was sent to someone else.", message: "This invitation was sent to someone else." }, 403);
    }
    const payload = enc.encode(JSON.stringify({ group_token: groupToken, veil_id: veilId, IK_pub: ikPub, joined_epoch: joinedEpoch }));
    const sigOk = await ed25519Verify(ikPub, payload, sig);
    if (!sigOk) return j({ error: "Attestation signature verification failed", message: "Attestation signature verification failed" }, 401);
    const members = await memberRows();
    // one identity per seat: a seat already attested by another key can't be reused
    const seatTaken = members.find((m) => m.session_token === sessionToken && m.IK_pub !== ikPub);
    if (seatTaken) return j({ error: "This seat already belongs to another member", message: "This seat already belongs to another member" }, 403);
    const existing = members.find((m) => m.IK_pub === ikPub);
    const heldByCaller = (m: Record<string, any>) => m._acct ? String(m._acct) === callerAcct : String(m.account_hash || "") === groupAccountHash;
    if (existing && !heldByCaller(existing)) {
      // re-attest only by the account that holds the membership (V-21)
      return j({ error: "That membership belongs to another account", message: "That membership belongs to another account" }, 403);
    }
    if (existing) {
      // Re-attest: rebind to the current session and epoch.
      await KV.set(["entity", "VeilGroupMember", existing.id], { ...existing, veil_id: veilId, account_hash: groupAccountHash, _acct: callerAcct, session_token: sessionToken, joined_epoch: joinedEpoch, attestation_sig: sig, updated_date: nowIso() });
      await KV.set(["veil_gmember", groupToken, ikPub], { veil_id: veilId, ik_pub: ikPub, joined_epoch: joinedEpoch, sig, account_hash: callerAcct, created_date: nowIso() });
      return json({ ok: true, rejoined: true });
    }
    if (members.length >= 100) return j({ error: "This group is full", message: "This group is full" }, 403); // b198: cohort 100
    // Batch E (Superagent report 2, RV-40): the forum is open, so one account
    // binding many identities could fill its 100 seats. A few seats per account
    // (a main ID plus a spare or two); seats already held are not touched.
    if (groupToken === (await knownForum()).group_token && members.filter(heldByCaller).length >= FORUM_SEATS_PER_ACCOUNT) {
      return j({ error: "This account already holds the most forum seats it can", message: "This account already holds the most forum seats it can" }, 403);
    }
    // W-21: 'creator' belongs to the group's FIRST attester, never to whoever
    // happens to hold an initiator slot.
    const role = members.length === 0 ? "creator" : "member";
    const row = { id: rid(), created_date: nowIso(), updated_date: nowIso(), group_token: groupToken, veil_id: veilId, account_hash: groupAccountHash, _acct: callerAcct, IK_pub: ikPub, session_token: sessionToken, joined_epoch: joinedEpoch, role, attestation_sig: sig };
    await KV.set(["entity", "VeilGroupMember", row.id], row);
    await KV.set(["veil_gmember", groupToken, ikPub], { veil_id: veilId, ik_pub: ikPub, joined_epoch: joinedEpoch, sig, account_hash: callerAcct, created_date: nowIso() });
    return json({ ok: true, role });
  }

  if (action === "rotate") {
    // Batch F (round-4 reviews R4-2-01 / R4-4-04): the forum's keys never change
    // through the relay. Forum members don't apply rekeys, so a rotation (or an
    // eviction, which rotates) breaks the forum for everyone.
    { const fk = (await knownForum()).group_token; if (fk && groupToken === fk) return j({ error: "The forum's keys can't be rotated", message: "The forum's keys can't be rotated" }, 403); }
    // b198: every rotate refusal is DIAGNOSED (slot/epoch/pq) — silent guards
    // made the stuck-epoch state undebuggable from the journal.
    if (slot !== "initiator") {
      console.warn("rotate-refused", { reason: "slot", slot, groupEpoch: Number(session.group_epoch || 0) });
      return j({ error: "Only the group creator can rotate the epoch", message: "Only the group creator can rotate the epoch" }, 403);
    }
    // b199 AUTHZ: the initiator slot alone is not creatorship — the slot's
    // account must own the group (a forged row used to rotate anyone's group).
    // The forum never gets here: it is refused above (Batch F), so the old
    // founder-may-rotate-the-forum branch is gone (Batch G, NF-5).
    if (!(await claimOrCheckGroupOwner(groupToken, auth))) {
      console.warn("rotate-refused", { reason: "not-owner" });
      return j({ error: "Only the group creator can rotate the epoch", message: "Only the group creator can rotate the epoch" }, 403);
    }
    const newEpoch = Number(body?.new_epoch);
    if (!Number.isInteger(newEpoch) || newEpoch !== Number(session.group_epoch || 0) + 1) {
      console.warn("rotate-refused", { reason: "epoch", newEpoch: body?.new_epoch, serverEpoch: Number(session.group_epoch || 0) });
      return j({ error: "new_epoch must be the current epoch + 1", message: "new_epoch must be the current epoch + 1" }, 400);
    }
    // group epochs are PQ-only: raw ML-KEM-768 encapsulation key (FIPS 203).
    if (!tryB64Len(body?.group_pq_pub, 1184)) {
      console.warn("rotate-refused", { reason: "pq", pqLen: typeof body?.group_pq_pub === "string" ? body.group_pq_pub.length : 0 });
      return j({ error: "group_pq_pub must be a base64 ML-KEM-768 public key — group epochs are PQ-only, no silent downgrade", message: "group_pq_pub must be a base64 ML-KEM-768 public key — group epochs are PQ-only, no silent downgrade" }, 400);
    }
    // stamp the new epoch + PQ key on every session row carrying this group
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row.group_token || "") === groupToken) {
        await KV.set(e.key, { ...row, group_epoch: newEpoch, group_pq_pub: String(body.group_pq_pub || ""), updated_date: nowIso() });
      }
    }
    const rec = await groupRecord(groupToken);
    await KV.set(["veil_group", groupToken], { ...rec, epoch: newEpoch, pq_pub: String(body.group_pq_pub || ""), updated_date: nowIso() });
    return json({ ok: true, epoch: newEpoch });
  }

  if (action === "evict") {
    // Batch G (round-5 review R5-3-01): relay `evict` changes no key (the app's
    // rotation is a separate `rotate`, which stays refused for the forum). Batch F
    // refused it for everyone, so forum seats could never be freed. Now only the
    // forum FOUNDER may remove a forum member; anyone else is refused.
    { const fk = (await knownForum()).group_token; if (fk && groupToken === fk && !(await isLoungeFounder(auth))) return j({ error: "Only the forum founder can remove forum members", message: "Only the forum founder can remove forum members" }, 403); }
    if (slot !== "initiator") return j({ error: "Only the group creator can remove members", message: "Only the group creator can remove members" }, 403);
    const removerIkPub = typeof body.remover_IK_pub === "string" ? body.remover_IK_pub : "";
    const targetIkPub = typeof body.target_IK_pub === "string" ? body.target_IK_pub : "";
    const targetVeilId = typeof body.target_veil_id === "string" ? body.target_veil_id.trim() : "";
    const denySig = typeof body.deny_sig === "string" ? body.deny_sig : "";
    if (!tryB64Len(removerIkPub, 32) || !tryB64Len(targetIkPub, 32) || !tryB64Len(denySig, 64)) return j({ error: "Invalid eviction material", message: "Invalid eviction material" }, 400);
    if (removerIkPub === targetIkPub) return j({ error: "The creator cannot evict themselves — end the group instead", message: "The creator cannot evict themselves — end the group instead" }, 400);
    const members = await memberRows();
    const remover = members.find((m) => m.IK_pub === removerIkPub);
    // Batch H (round-6 review R6-3-05): in the forum the remover is the CONFIGURED
    // founder key (the roster's "creator" is only its first attester, which may be an
    // older founder key); elsewhere the group creator, as before
    const forumNow = await knownForum();
    const isForum = !!forumNow.group_token && groupToken === forumNow.group_token;
    const forumFounderIk = isForum ? String((await forumConfig())?.descriptor?.founder_ik_pub || "") : "";
    if (isForum ? (!forumFounderIk || removerIkPub !== forumFounderIk) : (!remover || remover.role !== "creator")) {
      return j({ error: "Remover is not the group creator", message: "Remover is not the group creator" }, 403);
    }
    const denyEpoch = Number(session.group_epoch || 0);
    const denyPayload = JSON.stringify({ group_token: groupToken, target_IK_pub: targetIkPub, deny_epoch: denyEpoch });
    const denyOk = await ed25519Verify(removerIkPub, enc.encode(denyPayload), denySig);
    if (!denyOk) return j({ error: "Deny-list signature verification failed", message: "Deny-list signature verification failed" }, 401);
    const target = members.find((m) => m.IK_pub === targetIkPub);
    // Batch H (R6-2-03): a forum deny entry also names the removed member's account
    const targetAcct = isForum && target ? String(target._acct || "") : "";
    const denyRow = { id: rid(), created_date: nowIso(), group_token: groupToken, target_veil_id: targetVeilId, target_IK_pub: targetIkPub, deny_epoch: denyEpoch, remover_IK_pub: removerIkPub, deny_sig: denySig, ...(targetAcct ? { target_acct: targetAcct } : {}) };
    await KV.set(["entity", "VeilGroupDenyEntry", denyRow.id], denyRow);
    let removedSession = false;
    // Batch H (round-6 review R6-2-08): the cascade never touches the forum's shared invite row
    const forumInvite = isForum ? String(forumNow.invite || "") : "";
    if (target) {
      await KV.delete(["entity", "VeilGroupMember", target.id]);
      await KV.delete(["veil_gmember", groupToken, targetIkPub]);
      if (target.session_token && String(target.session_token) !== forumInvite) {
        // Base44 cascade: the evicted member's envelopes + session row go too.
        for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
          const env = e.value as Record<string, unknown>;
          if (String(env.session_token || "") === String(target.session_token)) await KV.delete(e.key);
        }
        const doomed = await findSessionByToken(String(target.session_token));
        if (doomed) {
          await KV.delete(["entity", "VeilSession", String(doomed.id)]);
          await KV.delete(["veil_sess_token", keySafe(String(target.session_token))]);
          removedSession = true;
        }
      }
    }
    return json({ ok: true, denied: true, removed_session: removedSession });
  }

  // Batch H (round-6 reviews R6-2-03 / R6-3-05): the forum founder lifts an
  // account-level forum ban (a removal made by mistake). Founder key only, signed.
  if (action === "unban") {
    const fk = (await knownForum()).group_token;
    if (!fk || groupToken !== fk || !(await isLoungeFounder(auth))) return j({ error: "Only the forum founder can let a tester back in", message: "Only the forum founder can let a tester back in" }, 403);
    const removerIkPub = typeof body.remover_IK_pub === "string" ? body.remover_IK_pub : "";
    const targetVeilId = typeof body.target_veil_id === "string" ? body.target_veil_id.trim() : "";
    const sig = typeof body.unban_sig === "string" ? body.unban_sig : "";
    const founderIk = String((await forumConfig())?.descriptor?.founder_ik_pub || "");
    if (!B58_ID.test(targetVeilId) || !tryB64Len(sig, 64) || removerIkPub !== founderIk) return j({ error: "Invalid request", message: "Invalid request" }, 400);
    const ok = await ed25519Verify(removerIkPub, enc.encode(JSON.stringify({ group_token: groupToken, unban_veil_id: targetVeilId })), sig);
    if (!ok) return j({ error: "Signature verification failed", message: "Signature verification failed" }, 401);
    const tid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(targetVeilId)])).value;
    const tAcct = tid ? String(tid.account_hash || "") : "";
    let lifted = 0;
    for (const d of await denyRows(Infinity)) {
      if (d.target_veil_id === targetVeilId || (tAcct && d.target_acct === tAcct)) { await KV.delete(["entity", "VeilGroupDenyEntry", String(d.id)]); lifted++; }
    }
    return json({ ok: true, lifted });
  }

  // Batch C (A3 follow-up): missing-wrap requests. A member that missed a
  // rotation cannot use the group channel (submit refuses envelopes off the
  // current epoch), so it asks here; the creator answers with a creator-signed
  // rekey whose wrap only that member can open. The relay stores and forwards:
  // requests are signed by the member's IK, deliveries are opaque to it.
  if (action === "wrap_request" || action === "wrap_requests" || action === "wrap_deliver" || action === "wrap_fetch") {
    const WRAP_TTL_MS = 7 * 24 * 3600 * 1000;
    const heldBy = (m: Record<string, any>) => m._acct ? String(m._acct) === callerAcct : String(m.account_hash || "") === groupAccountHash;
    const isOwner = async () => slot === "initiator"
      && (groupToken === await loungeGroupToken() ? await isLoungeFounder(auth) : await claimOrCheckGroupOwner(groupToken, auth));
    const reqPrefix = ["veil_wrapreq", keySafe(groupToken)];
    const delPrefix = ["veil_wrapdel", keySafe(groupToken)];

    if (action === "wrap_request") {
      const ikPub = typeof body.IK_pub === "string" ? body.IK_pub : "";
      const veilId = typeof body.veil_id === "string" ? body.veil_id.trim() : "";
      const sig = typeof body.sig === "string" ? body.sig : "";
      const haveEpoch = Number(body?.have_epoch);
      if (!tryB64Len(ikPub, 32) || !tryB64Len(sig, 64) || !B58_ID.test(veilId) || !Number.isInteger(haveEpoch) || haveEpoch < 0) {
        return j({ error: "Invalid wrap request", message: "Invalid wrap request" }, 400);
      }
      const members = await memberRows();
      const mine = members.find((m) => m.IK_pub === ikPub && String(m.veil_id || "") === veilId);
      if (!mine || !heldBy(mine)) return j({ error: "You are not a member of this group.", message: "You are not a member of this group." }, 403);
      if (haveEpoch >= Number(session.group_epoch || 0)) return j({ error: "Already on the current epoch", message: "Already on the current epoch" }, 400);
      const msg = JSON.stringify({ v: "vardum-wrap-request-v1", group_token: groupToken, veil_id: veilId, IK_pub: ikPub, have_epoch: haveEpoch });
      if (!(await ed25519Verify(ikPub, enc.encode(msg), sig))) return j({ error: "Wrap request signature verification failed", message: "Wrap request signature verification failed" }, 401);
      await KV.set([...reqPrefix, ikPub], { veil_id: veilId, IK_pub: ikPub, have_epoch: haveEpoch, sig, created_date: nowIso() }, { expireIn: WRAP_TTL_MS });
      return json({ ok: true });
    }

    if (action === "wrap_requests") {
      if (!(await isOwner())) return j({ error: "Only the group creator can read wrap requests", message: "Only the group creator can read wrap requests" }, 403);
      const requests: Record<string, unknown>[] = [];
      for await (const e of KV.list<Record<string, unknown>>({ prefix: reqPrefix }, { consistency: "strong" })) {
        const r = e.value;
        requests.push({ veil_id: r.veil_id, IK_pub: r.IK_pub, have_epoch: r.have_epoch, sig: r.sig, created_date: r.created_date });
        if (requests.length >= 100) break;
      }
      return json({ requests });
    }

    if (action === "wrap_deliver") {
      { const fk = (await knownForum()).group_token; if (fk && groupToken === fk) return j({ error: "The forum's keys can't be changed", message: "The forum's keys can't be changed" }, 403); } // Batch F (R4-2-01)
      if (!(await isOwner())) return j({ error: "Only the group creator can deliver wraps", message: "Only the group creator can deliver wraps" }, 403);
      const target = typeof body.target_IK_pub === "string" ? body.target_IK_pub : "";
      const payload = typeof body.payload === "string" ? body.payload : "";
      if (!tryB64Len(target, 32)) return j({ error: "Invalid target", message: "Invalid target" }, 400);
      if (payload.length > 40000) return j({ error: "Wrap payload too large", message: "Wrap payload too large" }, 413);
      if (!payload.startsWith('{"__veil_group_rekey":')) return j({ error: "Not a rekey payload", message: "Not a rekey payload" }, 400);
      const members = await memberRows();
      if (!members.some((m) => m.IK_pub === target)) return j({ error: "Not a member of this group", message: "Not a member of this group" }, 404);
      await KV.atomic()
        .set([...delPrefix, target], { payload, created_date: nowIso() }, { expireIn: WRAP_TTL_MS })
        .delete([...reqPrefix, target])
        .commit();
      return json({ ok: true });
    }

    // wrap_fetch — the target member only, single use
    const ikPub = typeof body.IK_pub === "string" ? body.IK_pub : "";
    if (!tryB64Len(ikPub, 32)) return j({ error: "Invalid key", message: "Invalid key" }, 400);
    const members = await memberRows();
    const mine = members.find((m) => m.IK_pub === ikPub);
    if (!mine || !heldBy(mine)) return j({ error: "You are not a member of this group.", message: "You are not a member of this group." }, 403);
    const k = [...delPrefix, ikPub];
    const got = await KV.get<{ payload: string }>(k);
    if (!got.value) return json({ payload: null });
    const del = await KV.atomic().check(got).delete(k).commit();
    return json({ payload: del.ok ? got.value.payload : null });
  }

  // b198 notify — kept from the cutover build: the sender proves membership via
  // the wsOk gate above; every OTHER member's account gets the contentless ping.
  // Coalesced per group AND sender, so a burst from one member can't stack
  // pushes but a reply from another member inside the window still pings.
  // The row expires itself, like the b199 throttle rows.
  if (action === "notify") {
    // b199 (owner decision, Oct 17): in the Founding Tester Forum only the
    // founder's posts ping the cohort; tester posts stay silent.
    // Batch E (R3-08): knownForum(), so a missing config still keeps testers silent
    const lounge = (await knownForum()).group_token;
    if (lounge && groupToken === lounge && !(await mayPingLounge(auth))) return json({ ok: true, skipped: "forum: founder posts only" });
    const ck = ["push_coalesce_group", keySafe(groupToken), callerAcct];
    if (Date.now() - ((await KV.get<number>(ck)).value ?? 0) < 30000) return json({ ok: true, coalesced: true });
    await KV.set(ck, Date.now(), { expireIn: COALESCE_TTL_MS });
    const members = await memberRows();
    const recipientAccts = new Set<string>();
    for (const m of members) if (m._acct && m._acct !== callerAcct) recipientAccts.add(String(m._acct));
    let sent = 0;
    for (const acct of recipientAccts) {
      for (const t of await groupMemberPushTokens(acct)) {
        void pushFetch(EXPO_PUSH_URL, { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ to: t, title: "Vardum", body: "Notification", sound: "default", priority: "high", data: { kind: "new-message" } }) }).then(async (r) => { const d = await r.json().catch(() => null) as { data?: { status?: string } } | null; console.log("[push] group ticket  device : " + (d?.data?.status ?? r.status)); }).catch(() => undefined);
        sent++;
      }
    }
    return json({ ok: true, data: { pinged: sent } });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- deviceLink (device-to-device transfer) ----------
async function fnDeviceLink(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body.action || "");
  const token = String(body.token || "");
  if (action === "store") {
    if (!token || token.length > MAX_KEY_PART) return j({ error: "token required", message: "token required" }, 400);
    // Batch C (B5; reviews P2 V-24, P3 R8): 10-minute link (spec §10), and a
    // token can't be overwritten — an existing link is never swapped.
    // Batch E (RV-39): a link carries only a bundle this account uploaded — fetch
    // hands the file out and deletes it, so another account's blob id here was a
    // read-and-delete key for someone else's vault
    if (!(await blobHeldBy(String(body.container_uri || ""), await accountHashOf(auth.userId)))) {
      return j({ error: "Not your file", message: "Not your file" }, 403);
    }
    const k = ["devlink", keySafe(token)];
    const put = await KV.atomic().check({ key: k, versionstamp: null }).set(k, {
      container_uri: String(body.container_uri || ""),
      byte_length: Number(body.byte_length) || 0,
      acct: await accountHashOf(auth.userId),
      // Batch F (round-4 reviews R4-4-06 / R4-3-03): SHA-256 of a secret that is
      // inside the encrypted bundle. Only the phone that decrypted and imported the
      // bundle can present it, so only that phone can mark the move "used".
      ack_hash: /^[0-9a-f]{64}$/.test(String(body.ack_hash || "")) ? String(body.ack_hash) : "",
      exp: Date.now() + 10 * 60_000,
      created_date: nowIso(),
    }).commit();
    if (!put.ok) return j({ error: "Transfer link already exists", message: "Transfer link already exists" }, 409);
    return json({ ok: true });
  }
  if (action === "fetch") {
    const k = ["devlink", keySafe(token)];
    const got = await KV.get<Record<string, any>>(k);
    const row = got.value;
    if (!row || row.exp < Date.now()) {
      await KV.delete(k);
      return j({ error: "Transfer link not found — expired or already used.", message: "Transfer link not found — expired or already used." }, 404);
    }
    // Batch C (B5): consume-once, atomically — two simultaneous fetches can't
    // both win; the bundle file is deleted once read
    // Batch C (B5 move): a short-lived "used" marker lets the SENDING phone
    // learn the bundle was collected, so it can retire the moved chats
    // Batch F (R4-4-06): with an ack hash, a fetch only records "fetched"; the
    // move becomes "used" when the new phone acknowledges a successful import.
    // A link from an older app (no hash) keeps the old rule: used at fetch.
    const marker = row.ack_hash
      ? KV.atomic().check(got).delete(k).set(["devlink_fetched", keySafe(token)], { acct: row.acct, ack_hash: row.ack_hash, at: nowIso() }, { expireIn: 30 * 86_400_000 })
      : KV.atomic().check(got).delete(k).set(["devlink_used", keySafe(token)], { acct: row.acct, at: nowIso() }, { expireIn: 30 * 86_400_000 });
    const claim = await marker.commit();
    if (!claim.ok) return j({ error: "Transfer link not found — expired or already used.", message: "Transfer link not found — expired or already used." }, 404);
    const uri = String(row.container_uri || "");
    if (uri.startsWith("blob:")) {
      const path = blobPathOf(uri);
      try {
        if (!path) throw new Error("bad blob id");
        const text = await Deno.readTextFile(path);
        await Deno.remove(path).catch(() => undefined);
        return json({ data: { blob: text } });
      } catch {
        return j({ error: "Transfer link not found — expired or already used.", message: "Transfer link not found — expired or already used." }, 404);
      }
    }
    return json({ data: { signed_url: uri } });
  }
  if (action === "ack") {
    // Batch F (R4-4-06): the new phone, after it has saved everything, proves it
    // read the bundle (the secret inside it) and the move becomes "used".
    if (!token || token.length > MAX_KEY_PART) return j({ error: "token required", message: "token required" }, 400);
    const fk = ["devlink_fetched", keySafe(token)];
    const fetched = await KV.get<Record<string, any>>(fk);
    const secret = String(body.ack_secret || "");
    if (!fetched.value || !secret || !ctEq(await sha256hex(secret), String(fetched.value.ack_hash || ""))) {
      return j({ error: "Transfer acknowledgement refused", message: "Transfer acknowledgement refused" }, 403);
    }
    const done = await KV.atomic().check(fetched).delete(fk)
      .set(["devlink_used", keySafe(token)], { acct: fetched.value.acct, at: nowIso() }, { expireIn: 30 * 86_400_000 })
      .commit();
    if (!done.ok) return j({ error: "Transfer acknowledgement refused", message: "Transfer acknowledgement refused" }, 409);
    return json({ ok: true });
  }
  if (action === "status") {
    // Batch C (B5 move): only the account that created the link may ask
    if (!token || token.length > MAX_KEY_PART) return j({ error: "token required", message: "token required" }, 400);
    const me = await accountHashOf(auth.userId);
    const live = (await KV.get<Record<string, any>>(["devlink", keySafe(token)])).value;
    if (live && live.acct === me && live.exp >= Date.now()) return json({ state: "waiting" });
    const used = (await KV.get<Record<string, any>>(["devlink_used", keySafe(token)])).value;
    if (used && used.acct === me) return json({ state: "used" });
    // Batch F (R4-4-06): collected but the import not yet acknowledged
    const fetchedRow = (await KV.get<Record<string, any>>(["devlink_fetched", keySafe(token)])).value;
    if (fetchedRow && fetchedRow.acct === me) return json({ state: "fetched" });
    return json({ state: "expired" });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- veilSilentAccount (duress/silent provisioning — phrase never leaves the device) ----------
async function fnVeilSilentAccount(auth: { userId: string }, body: Record<string, any>) {
  if (String(body.action || "") !== "provision") return j({ error: "Unknown action", message: "Unknown action" }, 400);
  try {
    const user = await createUser(String(body.email || ""), String(body.password || ""));
    const token = "vt_" + rid() + rid();
    await KV.set(await authKey(token), { userId: user.id, email: user.email });
    return json({ ok: true, access_token: token, user: { id: user.id, email: user.email } });
  } catch (e) {
    return j({ message: String((e as Error).message) }, 400);
  }
}

/**
 * b199 rebind — the 24-word sign-in follows the identity. The client derives
 * the new credentials from a NEW phrase on-device (silent-auth.ts) and sends
 * only the derived label + password; the phrase never leaves the phone.
 * Used when (a) "Generate new Veil ID" retires the phrase the account was
 * derived from, and (b) a classic made-up-email account switches its sign-in
 * to the 24 words. The old label stops working; the account, its vaults,
 * notes and identities are untouched. Other devices keep their tokens.
 */
async function fnSilentAccountRebind(auth: { userId: string }, body: Record<string, any>) {
  const email = String(body.email || "").toLowerCase().trim();
  const password = String(body.password || "");
  if (!/^v[0-9a-f]{24}@veil\.app$/.test(email) || password.length < 32) {
    return j({ message: "Invalid phrase-derived credentials" }, 400);
  }
  const user = (await KV.get<Record<string, any>>(["user", auth.userId])).value;
  if (!user) return j({ message: "Account not found" }, 404);
  const owner = (await KV.get<string>(["user_email", email])).value;
  if (owner && owner !== auth.userId) return j({ message: "That recovery phrase already signs in to a different account" }, 409);
  // Batch E (round-3 review R3-07): a retired label is never taken again, by a
  // rebind any more than by a sign-up (D-17) — whoever holds a retired phrase
  // could rebind to it and reach the label-keyed legacy group rows
  if ((await KV.get<string>(["label_retired", email])).value) return j({ message: "That recovery phrase was retired and can't be used again" }, 409);
  const oldEmail = String(user.email || "");
  const salt = crypto.randomUUID().replace(/-/g, "");
  // Batch D (D-17): the old label is retired, not freed (see createUser)
  const retired = [...new Set([...(Array.isArray(user.retired_labels) ? user.retired_labels.map(String) : []), ...(oldEmail && oldEmail !== email ? [oldEmail] : [])])];
  const next = { ...user, email, salt, passHash: await hashPassword(password, salt), retired_labels: retired, updated: nowIso() };
  const tx = KV.atomic().set(["user", auth.userId], next).set(["user_email", email], auth.userId);
  if (oldEmail && oldEmail !== email) tx.delete(["user_email", oldEmail]).set(["label_retired", oldEmail], auth.userId);
  const done = await tx.commit();
  if (!done.ok) return j({ message: "Could not update sign-in — try again" }, 409);
  return json({ ok: true, user: { id: auth.userId, email } });
}

// ---------- veilAccountDelete (the K-11 cascade) ----------
// "Deleted means deleted": every row keyed to the account — its id, its label
// (the sign-in email / phrase-derived v…@veil.app), its account hash, its
// per-row owner tags, its veil ids and the sessions it took part in — goes.
// relay/account-delete-test.mjs proves it against the database itself.
async function fnVeilAccountDelete(auth: { userId: string; email?: string }, body: Record<string, any>) {
  // client_id IS the account id (b65), so the account is always one of its own clients
  // b54 hotfix (code review V-1): the set is derived from the CALLER ONLY.
  // It used to merge caller-supplied body.client_ids, so any account could
  // name another user's id and delete their threads and envelopes. The
  // caller's sessions are still found via its identities and owner tags.
  void body;
  const clientIds = new Set([auth.userId]);
  const acct = await accountHashOf(auth.userId);
  const user = (await KV.get<Record<string, unknown>>(["user", auth.userId])).value;
  // the label lives on the user row; the token's copy can be stale after a rebind
  const labels = new Set([String(user?.email || ""), String(auth.email || ""), ...(Array.isArray(user?.retired_labels) ? (user!.retired_labels as unknown[]).map(String) : [])].map((l) => l.toLowerCase().trim()).filter(Boolean));
  const groupAccts = new Set<string>();
  for (const l of labels) groupAccts.add(await sha256hex("veil-group-account:" + l));
  const ownsRow = async (row: Record<string, unknown>, id: string) =>
    !!row._owner && String(row._owner) === await ownerTag(auth.userId, id);
  // this account's published identities (+ their bind nonces and invite-ping coalescers)
  const veilIds = new Set<string>(), ikPubs = new Set<string>();
  for await (const e of KV.list({ prefix: ["veil_identity"] }, { consistency: "strong" })) {
    const rec = e.value as Record<string, unknown>;
    if (String(rec.account_hash || "") === acct) {
      veilIds.add(String(rec.veil_id));
      if (rec.IK_pub) ikPubs.add(String(rec.IK_pub));
      await KV.delete(e.key);
    }
  }
  // group bans on those identities: the ban stays (an evicted member must not
  // rejoin by deleting their account), the identifiers go — the entry keeps
  // only group-salted hashes, and the signature over the plaintext IK is dropped
  for await (const e of KV.list({ prefix: ["entity", "VeilGroupDenyEntry"] }, { consistency: "strong" })) {
    const d = e.value as Record<string, unknown>;
    const vid = String(d.target_veil_id || ""), ik = String(d.target_IK_pub || "");
    if (!veilIds.has(vid) && !ikPubs.has(ik)) continue;
    const gt = String(d.group_token || "");
    await KV.set(e.key, {
      id: d.id, created_date: d.created_date, group_token: gt, deny_epoch: d.deny_epoch, remover_IK_pub: d.remover_IK_pub,
      target_ik_hash: ik ? await denyHash(gt, ik) : "",
      target_vid_hash: vid ? await denyHash(gt, vid) : "",
    });
  }
  // Batch C (B1): bind challenges are keyed [veil_id, account] — drop every
  // one for this account's identities and every one this account asked for
  const delAcct = await accountHashOf(auth.userId);
  for await (const e of KV.list({ prefix: ["id_nonce"] })) {
    if (veilIds.has(String(e.key[1])) || String(e.key[2] ?? "") === delAcct) await KV.delete(e.key);
  }
  for (const vid of veilIds) {
    await KV.delete(["id_nonce", vid]);
    await KV.delete(["push_coalesce_invite", keySafe(vid)]);
  }
  // sessions + envelopes: by client_id, by veil_id binding, or by the b199
  // creator tag (rows created before either field is filled in)
  let sessions = 0, envelopes = 0;
  const doomed: string[] = [];
  for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    const id = e.key[e.key.length - 1] as string;
    const hit = clientIds.has(String(row.initiator_client_id || "")) || clientIds.has(String(row.responder_client_id || ""))
      || veilIds.has(String(row.initiator_veil_id || "")) || veilIds.has(String(row.responder_veil_id || ""))
      || await ownsRow(row, id);
    if (hit) doomed.push(id);
  }
  for (const id of doomed) {
    const row = (await KV.get<Record<string, unknown>>(["entity", "VeilSession", id])).value;
    if (!row) continue;
    const tok = String(row.token || "");
    envelopes += await deleteSessionEnvelopes(tok);
    await KV.delete(["entity", "VeilSession", id]);
    if (tok) {
      await KV.delete(["veil_sess_token", tok]);
      for await (const e of KV.list({ prefix: ["push_coalesce", tok] }, { consistency: "strong" })) await KV.delete(e.key);
    }
    sessions++;
  }
  // envelopes this account sent into sessions that survive it
  for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    const env = e.value as Record<string, unknown>;
    // Batch C (V-13): owner tag on new envelopes; legacy rows still carry client_id
    const mine = (env._owner && String(env._owner) === await ownerTag(auth.userId, String(e.key[e.key.length - 1])))
      || clientIds.has(String(env.client_id || ""));
    if (!mine) continue;
    await KV.delete(e.key);
    envelopes++;
  }
  // group memberships: the gate's index rows (account hash) and the member
  // entity rows (account hash, or the label-derived group account hash)
  let memberships = 0;
  for await (const e of KV.list({ prefix: ["veil_gmember"] }, { consistency: "strong" })) {
    const m = e.value as Record<string, unknown>;
    if (String(m.account_hash || "") === acct) { await KV.delete(e.key); memberships++; }
  }
  for await (const e of KV.list({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
    const m = e.value as Record<string, unknown>;
    if (String(m._acct || "") === acct || groupAccts.has(String(m.account_hash || ""))) await KV.delete(e.key);
  }
  // groups this account created: the owner record keeps no account hash, but
  // stays tombstoned so nobody can claim the orphaned group's token afterwards
  for await (const e of KV.list<string>({ prefix: ["veil_group_owner"] }, { consistency: "strong" })) {
    if (e.value === acct) await KV.set(e.key, "deleted");
  }
  // owner-scoped entities: vaults, notes, push tokens (a device's push address
  // must not stay linked to a dead account)
  let vaults = 0, notes = 0, pushTokens = 0;
  for (const [name, counter] of [["VeilVault", () => vaults++], ["VeilNote", () => notes++], ["VeilPushToken", () => pushTokens++]] as const) {
    for await (const e of KV.list({ prefix: ["entity", name] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") === acct) {
        await KV.delete(e.key);
        if (name === "VeilVault") await removeVaultBlob(row);
        counter();
      }
    }
  }
  // every other row this account created (owner-tagged: analytics and the like)
  for await (const e of KV.list({ prefix: ["entity"] }, { consistency: "strong" })) {
    if (await ownsRow(e.value as Record<string, unknown>, e.key[e.key.length - 1] as string)) await KV.delete(e.key);
  }
  // Batch E (RV-39): files this account uploaded (media, bundles) and their owner records
  for await (const e of KV.list<string>({ prefix: ["blob_owner"] }, { consistency: "strong" })) {
    const id = String(e.key[1]);
    if (e.value !== await blobOwnerTag(acct, id)) continue;
    const p = blobPathOf("blob:" + id);
    if (p) await Deno.remove(p).catch(() => undefined);
    await KV.delete(e.key);
  }
  // transfer links owned by the account
  for await (const e of KV.list({ prefix: ["devlink"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    if (String(row.acct || "") === acct) await KV.delete(e.key);
  }
  // Batch E (F-3) / Batch F (R4-4-06): their "used" and "fetched" markers, kept 30 days
  for await (const e of KV.list({ prefix: ["devlink_fetched"] }, { consistency: "strong" })) {
    if (String((e.value as Record<string, unknown>).acct || "") === acct) await KV.delete(e.key);
  }
  for await (const e of KV.list({ prefix: ["devlink_used"] }, { consistency: "strong" })) {
    if (String((e.value as Record<string, unknown>).acct || "") === acct) await KV.delete(e.key);
  }
  // per-account rate-limit buckets ("env:<uid>", "idreg:<uid>", ...) — they
  // self-expire, but deletion does not wait for them
  for await (const e of KV.list({ prefix: ["rl"] }, { consistency: "strong" })) {
    if (String(e.key[1] || "").endsWith(":" + auth.userId)) await KV.delete(e.key);
  }
  // the label: its sign-in index (left behind, the label stayed on the server
  // and could never register again) and its password-guessing lockout row
  for (const l of labels) {
    if ((await KV.get<string>(["user_email", l])).value === auth.userId) await KV.delete(["user_email", l]);
    if ((await KV.get<string>(["label_retired", l])).value === auth.userId) await KV.delete(["label_retired", l]); // Batch D (D-17)
    await KV.delete(["login_guard", keySafe(l)]);
  }
  // the account itself + its auth tokens
  for await (const e of KV.list({ prefix: ["auth"] }, { consistency: "strong" })) {
    const t = e.value as Record<string, unknown>;
    if (String(t.userId || "") === auth.userId) await KV.delete(e.key);
  }
  await KV.delete(["user", auth.userId]);
  return json({ ok: true, data: { deleted: { sessions, envelopes, memberships, vaults, notes, push_tokens: pushTokens, identities: veilIds.size } } });
}

// ---------- private blob storage + signed URLs (encrypted media + vault files) ----------
const BLOB_DIR = Deno.env.get("VEIL_BLOB_DIR") || "/opt/veil-relay/blobs/"; // env override: local sandbox only
/** b199 PATH-TRAVERSAL FIX: a "blob:<id>" uri is client-supplied (deviceLink
 *  store, DeletePrivateFile) — "blob:../../etc/passwd" used to read or delete
 *  files outside the blob directory. Ids are rid() (24 hex); anything that
 *  is not a plain token resolves to null. */
function blobPathOf(uri: string): string | null {
  if (!uri.startsWith("blob:")) return null;
  const id = uri.slice(5);
  return /^[A-Za-z0-9_-]{1,128}$/.test(id) ? BLOB_DIR + id : null;
}

/**
 * Batch E (Superagent report 2, RV-39): who uploaded a blob. ["blob_owner", id]
 * holds a per-blob tag of the uploading account (unlinkable across blobs, like
 * the row owner tags), or "legacy" for a file from before the record existed.
 * A blob id alone used to be a cross-account key: any account knowing one could
 * delete a vault container (DeletePrivateFile), read and delete it through a
 * transfer link (deviceLink store + fetch), or keep any file from the sweeper
 * with a vault row pointing at it.
 */
async function blobOwnerTag(acct: string, blobId: string) {
  return "bo_" + (await sha256hex("veil-blob-owner:" + acct + ":" + blobId));
}
/** true when `uri` is a blob the account uploaded — or names no stored file at all */
async function blobHeldBy(uri: string, acct: string): Promise<boolean> {
  const path = blobPathOf(uri);
  if (!path) return true; // not a blob reference: nothing on disk to protect
  const id = uri.slice(5);
  const rec = (await KV.get<string>(["blob_owner", id])).value;
  if (rec) return rec === await blobOwnerTag(acct, id);
  return !(await Deno.stat(path).then(() => true).catch(() => false));
}
/** a vault container or a live transfer bundle: deleted only by its owner */
async function blobIsProtected(uri: string): Promise<boolean> {
  for await (const e of KV.list({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) {
    if (String((e.value as Record<string, unknown>).container_uri || "") === uri) return true;
  }
  for await (const e of KV.list({ prefix: ["devlink"] }, { consistency: "strong" })) {
    if (String((e.value as Record<string, unknown>).container_uri || "") === uri) return true;
  }
  return false;
}
/** RV-39: once, at boot — records owners for the files already on disk (a vault
 *  container belongs to its vault row's account; anything else is "legacy") */
async function migrateBlobOwners(): Promise<number> {
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) {
    const uri = String(e.value?.container_uri || ""), acct = String(e.value?._acct || "");
    const path = blobPathOf(uri);
    if (!path || !acct || !(await Deno.stat(path).then(() => true).catch(() => false))) continue;
    const id = uri.slice(5);
    if ((await KV.atomic().check({ key: ["blob_owner", id], versionstamp: null }).set(["blob_owner", id], await blobOwnerTag(acct, id)).commit()).ok) n++;
  }
  try {
    for await (const f of Deno.readDir(BLOB_DIR)) {
      if (!f.isFile || !/^[A-Za-z0-9_-]{1,128}$/.test(f.name)) continue;
      if ((await KV.atomic().check({ key: ["blob_owner", f.name], versionstamp: null }).set(["blob_owner", f.name], "legacy").commit()).ok) n++;
    }
  } catch { /* no blob directory yet */ }
  return n;
}

/** b199: a deleted vault takes its encrypted file with it (unless another
 *  vault row still points at the same blob). Media blobs are unattributed to
 *  any session and age out via BLOB_RETENTION_MS. Batch E (RV-39): only a file
 *  the vault's own account uploaded. */
async function removeVaultBlob(row: Record<string, unknown> | null) {
  const uri = String(row?.container_uri || "");
  const path = blobPathOf(uri);
  if (!path) return;
  for await (const e of KV.list({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) {
    if (String((e.value as Record<string, unknown>).container_uri || "") === uri) return;
  }
  const rec = (await KV.get<string>(["blob_owner", uri.slice(5)])).value;
  if (rec && rec !== await blobOwnerTag(String(row?._acct || ""), uri.slice(5))) return;
  try { await Deno.remove(path); } catch { /* already gone */ }
  await KV.delete(["blob_owner", uri.slice(5)]);
}
async function blobSecret(): Promise<CryptoKey> {
  let s = (await KV.get<string>(["secret", "blobSign"])).value;
  if (!s) { s = b64e(crypto.getRandomValues(new Uint8Array(32))); await KV.set(["secret", "blobSign"], s); }
  return crypto.subtle.importKey("raw", b64d(s) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function signBlobUrl(blobId: string, ttlMs: number, proto: string, host: string) {
  const key = await blobSecret();
  const exp = Date.now() + ttlMs;
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${blobId}:${exp}`));
  const m = b64e(new Uint8Array(mac)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${proto}//${host}/files/${blobId}?e=${exp}&m=${m}`;
}

// ---------- router ----------
const routes: [string, RegExp, (req: Request, m: RegExpMatchArray, url: URL) => Promise<Response>][] = [];

function route(method: string, pattern: string, handler: (req: Request, m: RegExpMatchArray, url: URL) => Promise<Response>) {
  routes.push([method, new RegExp("^" + pattern.replace(/:([a-zA-Z]+)/g, "(?<$1>[^/]+)") + "$"), handler]);
}

// b198: getLoungeInvite — the Founding Tester Forum's PUBLIC descriptor
// (faithful port of the Base44 entry). Open by design: both clients fetch it
// BEFORE any relationship with the forum. Serves a static, hand-verified
// descriptor — no user data, no account binding. The descriptor's link
// fragment carries the forum keys; the relay gate still decides every join.
// Fail-closed guards: the link must be an https forum invitation carrying a
// write-secret fragment; the founder key must be a 32-byte Ed25519 pub.
// Batch C (A5; reviews P2 V-7): the descriptor — its link carries the forum's
// write secret and group key — is no longer in source. It is read from the
// server's forum config (forumConfig()); with no valid config, nothing is served.
const LOUNGE_CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
function loungeDescriptorSound(l: Record<string, unknown>): boolean {
  if (typeof l.link !== "string" || !l.link.startsWith("https://")) return false;
  if (!l.link.includes("join=") || !l.link.includes("w=")) return false;
  try { return atob(String(l.founder_ik_pub)).length === 32; } catch { return false; }
}
route("GET", "/api/apps/:appId/functions/getLoungeInvite", async () => {
  const d = (await forumConfig())?.descriptor;
  if (!d || !loungeDescriptorSound(d)) {
    console.error("getLoungeInvite: no valid forum descriptor configured — refusing to serve");
    return j({ lounge: null }, 200, LOUNGE_CORS);
  }
  return j({ lounge: d }, 200, LOUNGE_CORS);
});
route("OPTIONS", "/api/apps/:appId/functions/getLoungeInvite", async () => new Response(null, { status: 204, headers: LOUNGE_CORS }));

// auth (open)
route("POST", "/api/apps/:appId/auth/login", async (req) => {
  const body = await readJson(req);
  const email = String(body.email || "").toLowerCase().trim();
  if (email.length > MAX_KEY_PART) return j({ message: "Invalid email or password" }, 401);
  // SPEC §1: the 5-attempt server-side lockout (VeilLoginGuard) — the client
  // surfaces the lock message verbatim.
  // Batch D (D-15, RV-13): every attempt RESERVES its place in the count
  // (atomically) before the password is checked, and a correct password
  // clears the count afterwards. The old code read the count, checked the
  // password, then wrote count+1 — parallel guesses all read the same count,
  // so 20 at once were all checked against a 5-attempt lockout.
  const uid = (await KV.get<string>(["user_email", keySafe(email)])).value;
  const user = uid ? (await KV.get<any>(["user", uid])).value : null;
  if (user) {
    const g = await reserveLoginAttempt(["login_guard", keySafe(email)], 5, 10 * 60_000);
    if (!g.ok) {
      const mins = Math.max(1, Math.ceil((g.lockedUntil - Date.now()) / 60_000));
      return j({ message: `Too many failed attempts — try again in ${mins} minute${mins === 1 ? "" : "s"}` }, 429);
    }
  }
  // per-IP throttle: stops distributed guessing across MANY mailboxes from one host
  // ("local" = the server itself / an SSH tunnel — never throttled)
  const ip = await clientTag(req);
  const ipLocal = ip === "local";
  if (!ipLocal && !(await reserveLoginAttempt(["login_guard_ip", ip], 15, 15 * 60_000)).ok) {
    return j({ message: "Too many failed attempts — try again later" }, 429);
  }
  if (!user) return j({ message: "Invalid email or password" }, 401);
  const hash = await hashPassword(String(body.password || ""), user.salt);
  if (!ctEq(hash, String(user.passHash || ""))) {
    return j({ message: "Invalid email or password" }, 401);
  }
  await KV.delete(["login_guard", keySafe(email)]);
  await KV.delete(["login_guard_ip", ip]);
  const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  await KV.set(await authKey(token), { userId: user.id, email: user.email, created: nowIso() });
  return json({ access_token: token, user: { id: user.id, email: user.email } });
});

route("POST", "/api/apps/:appId/auth/register", async (req) => {
  const body = await readJson(req);
  // mass-registration guard (unauthenticated endpoint): 10 accounts/hour/network
  // ("local" exempt — the server's own console / test batteries)
  const regIp = await clientTag(req);
  const regRl = regIp === "local" ? null : await rateLimit("regip:" + regIp, 10, 3600_000, 60);
  if (regRl) return j({ message: "Too many signups from this network — try again later" }, 429);
  try {
    const user = await createUser(String(body.email || ""), String(body.password || ""));
    // b198 ANONYMOUS SIGNUP (founder decision, Oct 15): the email is a
    // SELF-DECLARED account label — real or invented, never verified, never
    // contacted. The Base44-era OTP mandate died with the platform. The
    // account is created + verified + usable in ONE step; the 24-word phrase
    // remains the only recovery path (disclosed at signup). Login lockouts,
    // the per-IP register cap, and the deletion cascade are unchanged.
    user.verified = true;
    await KV.set(["user", user.id], user);
    const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
    await KV.set(await authKey(token), { userId: user.id, email: user.email, created: nowIso() });
    return json({ id: user.id, access_token: token, user: { id: user.id, email: user.email }, message: "Account created — no email verification" });
  } catch (e) { return j({ message: String((e as Error).message) }, 400); }
});

// b199 ACCOUNT-TAKEOVER FIX: this route used to accept ANY code and mint a
// token for whatever email it was given — anyone knowing an account's email
// could sign in as it. Signup is one step (register returns the token) and
// there is no OTP to verify, so the route mints nothing. Kept (not removed)
// so an old client gets a clear message instead of a bare 404.
route("POST", "/api/apps/:appId/auth/verify-otp", async () =>
  j({ message: "Email codes are not used on this relay — sign in with your email and password" }, 410));

// b199: logout revokes the presented token server-side (it used to be a no-op,
// so a copied token stayed valid for up to 30 days after sign-out)
route("POST", "/api/apps/:appId/auth/logout", async (req) => {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (token && token.length <= MAX_KEY_PART) { await KV.delete(await authKey(token)); await KV.delete(["auth", token]); }
  return json({ ok: true });
});

// ---------- b199 entity access policy ----------
// Every generic /entities route is checked against this table. An entity not
// listed is unknown to the generic API (404) — gate functions own those rows
// (VeilGroupMember, VeilGroupDenyEntry, ...). Writes the native client never
// makes through this API are refused: envelopes only enter via submitEnvelope
// (write-secret + rate limit + group roster checks), sessions only change via
// veilSessionGate.
type EntityOp = "list" | "get" | "create" | "update" | "delete";
const ENTITY_POLICY: Record<string, ReadonlySet<EntityOp>> = {
  // b54 hotfix (code review V-14): no generic list — it returned full rows to
  // any token holder. Clients use the participant-scoped veilSessionGate list.
  VeilSession: new Set<EntityOp>(["get", "create", "delete"]),
  VeilEnvelope: new Set<EntityOp>(["list", "get", "delete"]),
  VeilVault: new Set<EntityOp>(["list", "get", "create", "update", "delete"]),
  VeilNote: new Set<EntityOp>(["list", "get", "create", "update", "delete"]),
  VeilPushToken: new Set<EntityOp>(["list", "get", "create", "delete"]),
  // anonymous funnel analytics: write-only
  OnboardingStep: new Set<EntityOp>(["create"]),
  AttributionSource: new Set<EntityOp>(["create"]),
};

/** null = allowed; otherwise the refusal response. */
function entityOpRefusal(entity: string, op: EntityOp): Response | null {
  const ops = ENTITY_POLICY[entity];
  if (!ops) return j({ message: "Not found" }, 404);
  if (!ops.has(op)) return j({ message: "Not allowed" }, 403);
  return null;
}

/** Row-level check for get/update/delete by id. */
async function canAccessRow(entity: string, row: Record<string, unknown>, auth: { userId: string }, op: EntityOp): Promise<boolean> {
  if (entity === "VeilSession") return sessionParticipant(row, auth);
  if (entity === "VeilEnvelope") {
    const session = await findSessionByToken(String(row.session_token || ""));
    if (session && await sessionParticipant(session, auth)) return true;
    // Batch C (V-15): group members may READ the group stream, but only the
    // sending session's participants may delete an envelope (any member used to
    // be able to wipe others' messages, including rekey parts)
    const gt = String(row.group_token || "");
    // Play UGC (Oct 18): the forum founder removes a forum post for everyone —
    // only the account bound to the configured founder key, only in the forum
    if (op === "delete") return !!gt && gt === (await knownForum()).group_token && await isLoungeFounder(auth);
    if (!gt) return false;
    const acct = await accountHashOf(auth.userId);
    for await (const e of KV.list({ prefix: ["veil_gmember", keySafe(gt)] }, { consistency: "strong" })) {
      if (String((e.value as Record<string, unknown>).account_hash || "") === acct) return true;
    }
    return false;
  }
  if (OWNER_SCOPED_ENTITIES.has(entity)) {
    const owner = String(row._acct || "");
    // pre-b199 push-token rows may carry no owner — the client's own cleanup
    // path deletes those (src/notifications.ts), so delete stays open for them
    if (!owner) return entity === "VeilPushToken" && op === "delete";
    return owner === await accountHashOf(auth.userId);
  }
  return false;
}

// entities (auth required)
route("GET", "/api/apps/:appId/entities/:entity", async (req, m, url) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "list");
  if (refused) return refused;
  const listed = await listEntity(m.groups!.entity!, url, auth);
  if (listed && (listed as any).__blocked) {
    return j({ message: String((listed as any).__blocked) }, 403);
  }
  if (listed && (listed as any).__notfound) {
    return j({ error: String((listed as any).__notfound), message: String((listed as any).__notfound) }, 404);
  }
  return json(listed);
});

route("POST", "/api/apps/:appId/entities/:entity", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "create");
  if (refused) return refused;
  const body = await readJson(req);
  const created = await createEntity(m.groups!.entity!, body, auth);
  if (created && (created as any).__conflict) {
    return j({ error: "Conflict", message: "A session with this token already exists" }, 409);
  }
  if (created && (created as any).__forbidden) {
    return j({ error: String((created as any).__forbidden), message: String((created as any).__forbidden) }, 403);
  }
  return json(created);
});

route("PUT", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "update");
  if (refused) return refused;
  const body = await readJson(req);
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  const row = (await KV.get<Record<string, unknown>>(["entity", m.groups!.entity!, m.groups!.id!])).value;
  // b199: someone else's row answers exactly like a missing one (no existence oracle)
  if (!row || !(await canAccessRow(m.groups!.entity!, row, auth, "update"))) return j({ message: "Not found" }, 404);
  // Batch E (RV-39): a vault update can't repoint the row at someone else's file
  if (m.groups!.entity! === "VeilVault" && body.container_uri !== undefined && String(body.container_uri) !== String(row.container_uri ?? "")
    && !(await blobHeldBy(String(body.container_uri), await accountHashOf(auth.userId)))) return j({ message: "Not your file" }, 403);
  // server-owned fields can never be rewritten by a client merge
  const merged = { ...row, ...body, id: m.groups!.id!, created_date: row.created_date, _acct: row._acct, _owner: row._owner, updated_date: nowIso() };
  for (const k of ["_acct", "_owner"] as const) if (merged[k] === undefined) delete merged[k];
  await KV.set(["entity", m.groups!.entity!, m.groups!.id!], merged);
  return json(merged);
});

route("GET", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "get");
  if (refused) return refused;
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  const row = await getEntity(m.groups!.entity!, m.groups!.id!) as Record<string, unknown> | null;
  if (!row || !(await canAccessRow(m.groups!.entity!, row, auth, "get"))) return j({ message: "Not found" }, 404);
  return json(row);
});

// b198 OWNERSHIP GUARD: sessions may only be modified/deleted by their
// participants (client_id IS the account id — b65 participation proof; or a
// veil_id bound to the caller's account). Without this, one device's supersede
// could destroy the OTHER device's brand-new thread (live battery catch).
async function sessionParticipant(session: Record<string, unknown> | null, auth: { userId: string }): Promise<boolean> {
  if (!session) return false;
  // b199: the account that created the row (one-tap/invite creator, even
  // before any client_id field is filled in)
  if (session._owner && String(session._owner) === await ownerTag(auth.userId, String(session.id || ""))) return true;
  if (String(session.initiator_client_id || "") === auth.userId) return true;
  if (String(session.responder_client_id || "") === auth.userId) return true;
  const acct = await accountHashOf(auth.userId);
  for (const vid of [String(session.initiator_veil_id || ""), String(session.responder_veil_id || "")]) {
    if (!vid) continue;
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(vid)])).value;
    if (id && String(id.account_hash || "") === acct) return true;
  }
  return false;
}

route("DELETE", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "delete");
  if (refused) return refused;
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  const existing = (await KV.get<Record<string, unknown>>(["entity", m.groups!.entity!, m.groups!.id!])).value;
  if (!existing) return j({ message: "Not found" }, 404);
  if (!(await canAccessRow(m.groups!.entity!, existing, auth, "delete"))) {
    // sessions keep their explicit 403 (the client's supersede path reads it);
    // every other entity answers like a missing row
    return m.groups!.entity! === "VeilSession" ? j({ message: "Not your session" }, 403) : j({ message: "Not found" }, 404);
  }
  // Batch D (D-18): the forum's founder invite row goes only through the founder
  if (m.groups!.entity! === "VeilSession") {
    const forumInvite = (await knownForum()).invite;
    if (forumInvite && String(existing.token || "") === forumInvite && !(await isLoungeFounder(auth))) return j({ message: "Not your session" }, 403);
  }
  const row = await deleteEntity(m.groups!.entity!, m.groups!.id!);
  return row ? json({ ok: true }) : j({ message: "Not found" }, 404);
});

// functions (auth required)
route("POST", "/api/apps/:appId/functions/submitEnvelope", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnSubmitEnvelope(auth, body);
});

route("POST", "/api/apps/:appId/functions/veilSessionGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilSessionGateAligned(auth, body);
});

route("POST", "/api/apps/:appId/functions/veilIdentityGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilIdentityGate(auth, body);
});

route("POST", "/api/apps/:appId/functions/veilGroupGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilGroupGate(auth, body);
});

// Batch H (round-6 review R6-3-09): a phone removes ITS OWN earlier push rows (by
// the device id it registered them with) when it registers a new token and at every
// wipe. Stale rows used to stay live (an old ntfy.sh topic, an old Expo token).
route("POST", "/api/apps/:appId/functions/veilPushReset", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  const dev = typeof body?.device_id === "string" ? body.device_id : "";
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(dev)) return j({ error: "Invalid device id", message: "Invalid device id" }, 400);
  const acctHash = await accountHashOf(auth.userId);
  let deleted = 0;
  for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
    const r = e.value as Record<string, unknown>;
    if (String(r._acct || "") === acctHash && String(r.device_id || "") === dev) { await KV.delete(e.key); deleted++; }
  }
  return json({ ok: true, deleted });
});

route("POST", "/api/apps/:appId/functions/deviceLink", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnDeviceLink(auth, body);
});

// b198 (audit P0-2, live-confirmed): provisioning IS the account-creation call —
// the caller definitionally has no credentials yet, so requiring auth here 401'd
// every fresh duress account. The route is pre-auth, guarded by the same per-IP
// register cap as /auth/register.
route("POST", "/api/apps/:appId/functions/veilSilentAccount", async (req) => {
  const body = await readJson(req);
  // b199: 'rebind' moves the SIGNED-IN account onto new phrase-derived
  // credentials — token required; never reachable pre-auth
  if (String(body.action || "") === "rebind") {
    const auth = await authUser(req);
    if (!auth) return j({ message: "Unauthorized" }, 401);
    return fnSilentAccountRebind(auth, body);
  }
  const regIp = await clientTag(req);
  const regRl = regIp === "local" ? null : await rateLimit("regip:" + regIp, 10, 3600_000, 60);
  if (regRl) return j({ message: "Too many signups from this network — try again later" }, 429);
  return fnVeilSilentAccount({ userId: "preauth-provision" }, body);
});

route("POST", "/api/apps/:appId/functions/veilAccountDelete", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilAccountDelete(auth, body);
});

route("POST", "/api/apps/:appId/functions/vaultFileSignedUrl", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  const fileUri = String(body.file_uri || "");
  if (!fileUri.startsWith("blob:") || fileUri.length > MAX_KEY_PART + 5) return j({ error: "Unknown file", message: "Unknown file" }, 404);
  // vault-unlock path passes NO session context; media path passes both — verify when present
  if (body.session_token) {
    const session = await findSessionByToken(String(body.session_token));
    const wHash = await wsHashOf(body.write_secret);
    const ok = !!(session && wHash && (ctEq(wHash, String(session.initiator_write_hash || "")) || ctEq(wHash, String(session.responder_write_hash || ""))));
    if (!ok) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }
  // Batch F (round-4 reviews R4-3-04 / R4-4-22): a vault container or a pending
  // transfer bundle is readable only by its uploader. Media keeps the id (known
  // only from inside the E2E message) as the capability, as the burn path needs.
  {
    const id = fileUri.slice(5);
    const rec = (await KV.get<string>(["blob_owner", id])).value;
    const isUploader = !!rec && rec === await blobOwnerTag(await accountHashOf(auth.userId), id);
    if (!isUploader && await blobIsProtected(fileUri)) return j({ error: "Not your file", message: "Not your file" }, 403);
  }
  const host = req.headers.get("host") || "relay.tryveil.app";
  // behind Caddy the inner request is http — trust the proxy's forwarded proto.
  // b198 LIVE-CAUGHT BUG (media load "Network request failed" behind TLS): the
  // two branches used INCONSISTENT formats — "https://" (with slashes) vs
  // new URL().protocol ("https:", slash-free) — while the template below is
  // `${proto}//${host}`. The X-Forwarded-Proto branch therefore produced
  // "https:////host/..." — a malformed URL that RN fetch rejects at the
  // connection level. EVERY media/vault download through Caddy TLS was broken
  // since the relay flip. Both branches must be slash-free.
  const fwdProto = req.headers.get("x-forwarded-proto") || "";
  const proto = fwdProto.startsWith("https") ? "https:" : new URL(req.url).protocol;
  const url = await signBlobUrl(fileUri.slice(5), 10 * 60_000, proto, host);
  return json({ signed_url: url });
});

// private blob upload — the web SDK's Core.UploadPrivateFile contract (multipart)
route("POST", "/api/apps/:appId/integration-endpoints/Core/UploadPrivateFile", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  // size gate BEFORE spooling the multipart body into memory/temp files
  // b198 MEDIA CAP ALIGNED (owner decision): 25 MB files, 26 MB gate to allow
  // multipart overhead. The client cap (MEDIA_LIMIT_BYTES) matches exactly.
  const UPLOAD_BODY_CAP = 26 * 1024 * 1024;
  if (Number(req.headers.get("content-length") || "0") > UPLOAD_BODY_CAP) return TOO_LARGE("File too large");
  // Batch D (D-16, RV-15): a chunked body has no content-length, and
  // req.formData() buffered it without any cap. Read it through a byte counter
  // (as readJson does), refuse past the cap BEFORE parsing, then parse only
  // the bounded bytes as multipart.
  let bodyBytes: Uint8Array;
  try {
    const got = await readCapped(req, UPLOAD_BODY_CAP);
    if (!got) return TOO_LARGE("File too large");
    bodyBytes = got;
  } catch { return j({ message: "Upload failed" }, 400); }
  try {
    const form = await new Response(bodyBytes as BodyInit, { headers: { "content-type": req.headers.get("content-type") || "" } }).formData();
    let file: File | null = null;
    for (const [, v] of form.entries()) { if (v instanceof File) { file = v; break; } }
    if (!file) return j({ message: "No file part" }, 400);
    // disk-fill guard: encrypted media/vault files cap at 25 MB (aligned with
    // the client's MEDIA_LIMIT_BYTES — b198 media cap decision)
    if (file.size > 25 * 1024 * 1024) return j({ message: "File too large" }, 413);
    // b199 (audit: "no per-account upload quota → disk fill"): 1 GB of
    // encrypted files per account per day — about 40 vaults or full-size
    // media files; real use is a small fraction. Counted per UTC day.
    const qKey = ["upload_quota", await accountHashOf(auth.userId), new Date().toISOString().slice(0, 10)];
    // Batch C (B10; review P4 F-6): check-and-increment in ONE atomic step —
    // parallel uploads used to all pass the check before any of them counted
    let counted = false;
    for (let attempt = 0; attempt < 5 && !counted; attempt++) {
      const cur = await KV.get<Deno.KvU64>(qKey);
      const used = Number(cur.value?.value ?? 0n);
      if (used + file.size > UPLOAD_DAILY_CAP) return j({ message: "Daily upload limit reached — try again tomorrow" }, 429);
      counted = (await KV.atomic().check(cur).set(qKey, new Deno.KvU64(BigInt(used + file.size))).commit()).ok;
    }
    if (!counted) return j({ message: "Upload busy — try again" }, 429);
    const id = rid();
    await Deno.mkdir(BLOB_DIR, { recursive: true });
    await Deno.writeFile(BLOB_DIR + id, new Uint8Array(await file.arrayBuffer()));
    // Batch E (RV-39): the owner is recorded before the id is handed out (and
    // after the file exists, so the sweeper never drops the record as orphaned)
    await KV.set(["blob_owner", id], await blobOwnerTag(await accountHashOf(auth.userId), id));
    return json({ file_uri: "blob:" + id });
  } catch (e) {
    console.error("upload error", e); return j({ message: "Upload failed" }, 500); // Batch C (B7)
  }
});

// b198 MEDIA DELETION: the blob id exists ONLY inside the E2E-encrypted media
// payload (the relay never sees it), so knowledge of an unguessable blob id IS
// the decryption proof — an authenticated caller presenting one is the deletion
// capability. The client's burn/✕ paths call this so burnt media leaves NOTHING
// on the relay's disk (text envelopes were already hard-deleted; this closes the
// media half of the burn/✕ claim). Idempotent: an already-gone blob is success.
route("POST", "/api/apps/:appId/integration-endpoints/Core/DeletePrivateFile", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  let body: Record<string, unknown> = {};
  try { body = await readJson(req); } catch { /* empty body tolerated */ }
  const uri = String(body.file_uri || "");
  if (!uri.startsWith("blob:") || uri.length > MAX_KEY_PART + 5) return j({ message: "Unknown file" }, 404);
  const path = blobPathOf(uri);
  if (!path) return j({ message: "Unknown file" }, 404);
  // Batch E (RV-39): the uploader may always delete. Anyone else only a media
  // file — a receiver's burn deletes the sender's upload, so for media the id
  // (known only from inside the E2E payload) stays the capability. A vault
  // container or a pending transfer bundle is its owner's alone.
  const id = uri.slice(5);
  const rec = (await KV.get<string>(["blob_owner", id])).value;
  const isUploader = !!rec && rec === await blobOwnerTag(await accountHashOf(auth.userId), id);
  if (!isUploader && await blobIsProtected(uri)) return j({ message: "Not your file" }, 403);
  try { await Deno.remove(path); } catch { /* already gone — deletion is idempotent */ }
  await KV.delete(["blob_owner", id]);
  return json({ ok: true });
});

// pre-signed blob download (HMAC + expiry, no auth header by design)
route("GET", "/files/:id", async (req, m, url) => {
  const blobId = keySafe(m.groups!.id!);
  const exp = Number(url.searchParams.get("e") || "0");
  const mac = url.searchParams.get("m") || "";
  if (!exp || exp < Date.now() || !mac) return j({ error: "Link expired", message: "Link expired" }, 403);
  const key = await blobSecret();
  const expect = b64e(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${blobId}:${exp}`))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (!ctEq(expect, mac)) return j({ error: "Bad signature", message: "Bad signature" }, 403); // Batch C (B7): constant time (V-30)
  const path = blobPathOf("blob:" + blobId);
  if (!path) return j({ error: "Not found", message: "Not found" }, 404);
  try {
    const data = await Deno.readFile(path);
    return new Response(data, { headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" } });
  } catch {
    return j({ error: "Not found", message: "Not found" }, 404);
  }
});

// auth extras — resend-otp is a no-op success (phase 1 auto-verifies);
// reset-password is HONESTLY offline until SMTP exists (no fake reset path)
route("POST", "/api/apps/:appId/auth/resend-otp", async () => json({ ok: true }));
route("POST", "/api/apps/:appId/auth/reset-password-request", async () =>
  j({ message: "Password reset email delivery is not available on this relay yet" }, 503));
route("POST", "/api/apps/:appId/auth/reset-password", async () =>
  j({ message: "Reset tokens are not issued while email delivery is offline" }, 400));

route("POST", "/api/apps/:appId/functions/purgeExpiredEnvelopes", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  return fnPurgeExpired();
});

// b199 CALL RELAY CREDENTIALS (owner-approved Oct 16): short-lived TURN
// credentials for the self-hosted coturn on this VPS (TURN REST scheme:
// username "<expiry>:<random>", credential = base64 HMAC-SHA1(secret,
// username)). Calls run relay-only, so the two phones never learn each
// other's IP; audio stays DTLS-SRTP end to end and coturn cannot hear it.
// Signed-in users only; nothing is stored.
const TURN_SECRET = Deno.env.get("TURN_SECRET") ?? "";
const TURN_TTL_S = 3600;
// 20 Oct 2026: the coturn hosts, nearest first (comma list; all share TURN_SECRET).
// Sydney (BinaryLane) answers Australian phones in ~25 ms vs ~230 ms for this VPS.
const TURN_HOSTS_SET = (Deno.env.get("TURN_HOSTS") ?? "")
  .split(",").map((h) => h.trim()).filter((h) => /^[A-Za-z0-9.-]+$/.test(h));
const TURN_HOSTS = TURN_HOSTS_SET.length ? TURN_HOSTS_SET : ["relay.tryveil.app"]; // empty or invalid → this VPS
const turnUrls = () => [
  ...TURN_HOSTS.map((h) => `turn:${h}:3478?transport=udp`),
  ...TURN_HOSTS.map((h) => `turn:${h}:3478?transport=tcp`),
];
route("POST", "/api/apps/:appId/functions/veilTurnCredentials", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  if (!TURN_SECRET) return j({ message: "Calling relay not configured" }, 503);
  const rnd = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("");
  const username = `${Math.floor(Date.now() / 1000) + TURN_TTL_S}:${rnd}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(TURN_SECRET) as BufferSource, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username) as BufferSource));
  const credential = btoa(String.fromCharCode(...mac));
  return j({
    iceServers: [{ urls: turnUrls(), username, credential }],
    ttl: TURN_TTL_S,
  });
});

// unknown function → 404 (the client tolerates)
route("POST", "/api/apps/:appId/functions/:fn", async (req, m) => {
  return j({ error: `Backend function '${m.groups!.fn!}' not found or not deployed`, message: `Backend function '${m.groups!.fn!}' not found or not deployed` }, 404);
});

// health
route("GET", "/status", async () => json({ ok: true, relay: "veil-phase1" }));
// b199 owner dashboard: aggregate counts only. Caddy refuses /admin/* from the
// internet; the stats service on the same server calls it with this token.
route("GET", "/admin/stats", async (req) => {
  const want = Deno.env.get("VEIL_STATS_TOKEN") || "";
  const got = req.headers.get("x-veil-stats-token") || "";
  if (want.length < 32 || got.length !== want.length) return j({ message: "Not found" }, 404);
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ got.charCodeAt(i);
  if (diff !== 0) return j({ message: "Not found" }, 404);
  return json(await statsSnapshot());
});

// ---------- request hardening (b198 attack-probe fixes) ----------
const MAX_JSON_BYTES = 1 * 1024 * 1024;      // JSON routes — envelopes are ≤ ~8 KB
const MAX_KEY_PART = 256;                    // any user string that becomes a KV key part
const MAX_VEIL_ID = 128;                     // veil_ids are short (#veil format)

/** Batch D (D-16): reads a request body, counting bytes as they arrive.
 *  Returns null (and stops reading) as soon as the body passes `cap`. */
async function readCapped(req: Request, cap: number): Promise<Uint8Array | null> {
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > cap) { try { await reader.cancel(); } catch { /* already closed */ } return null; }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  return buf;
}

/** Reads a JSON body with a hard size cap; throws tagged errors on violations. */
async function readJson(req: Request): Promise<Record<string, any>> {
  const len = Number(req.headers.get("content-length") || "0");
  if (len > MAX_JSON_BYTES) throw new Error("__too_large__");
  // Batch C (B10; review P4 F-5): count bytes WHILE reading — a chunked body
  // has no content-length and used to be buffered without any cap
  let text = "";
  if (req.body) {
    const reader = req.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_JSON_BYTES) { try { await reader.cancel(); } catch { /* already closed */ } throw new Error("__too_large__"); }
      chunks.push(value);
    }
    const buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
    text = new TextDecoder().decode(buf);
  }
  let body: unknown;
  try { body = text ? JSON.parse(text) : {}; } catch { throw new Error("__bad_json__"); } // malformed or over-deep JSON → clean 400
  if (body && typeof body === "object") {
    for (const k of Object.keys(body)) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") {
        throw new Error("__bad_keys__");
      }
    }
  }
  return body ?? {};
}

/** Caps a user-supplied string used as a KV key part — oversized input misses instead of crashing. */
function keySafe(v: unknown): string {
  const s = String(v ?? "");
  return s.length <= MAX_KEY_PART ? s : "\u0000oversized";
}

const TOO_LARGE = (msg = "Request body too large") => j({ error: msg, message: msg }, 413);
const BAD_KEYS = () => j({ error: "Invalid field name", message: "Invalid field name" }, 400);
const BAD_JSON = () => j({ error: "Malformed JSON", message: "Malformed JSON" }, 400);

// ---------- serve ----------
// b199 (audit: bound 0.0.0.0, only UFW stopped direct :8000 access — and a
// direct hit looks "local", i.e. unthrottled): listen on loopback only; Caddy
// is the sole way in. VEIL_HOST can override for local test setups.
Deno.serve({ port: PORT, hostname: Deno.env.get("VEIL_HOST") || "127.0.0.1" }, async (req, info) => {
  const url = new URL(req.url);
  for (const [method, re, handler] of routes) {
    if (req.method !== method) continue;
    const m = url.pathname.match(re);
    if (m) {
      try { return await handler(req, m, url); }
      catch (e) {
        const msg = String((e as Error).message || e);
        if (msg === "__too_large__") return TOO_LARGE();
        if (msg === "__bad_keys__") return BAD_KEYS();
        if (msg === "__bad_json__") return BAD_JSON();
        console.error("handler error", url.pathname, e);
        return j({ error: "Internal error", message: "Internal error" }, 500); // Batch C (B7): details stay in the server log
      }
    }
  }
  return j({ message: "Not found" }, 404);
});

console.log(`VEIL RELAY Phase 1 — listening on http://localhost:${PORT}`);
console.log("Contract: /api/apps/:appId/{auth/*,entities/*,functions/*} — matches the native client exactly.");

// ---------- sweeper: every 10 min, purge expired envelopes + stale limiter keys (K-30) ----------
// b198 BLOB RETENTION BACKSTOP: media ciphertext whose envelope was deleted
// WITHOUT a client-driven blob delete (never-opened media, ✕ of a session whose
// media was never decrypted) is swept at bounded retention — the max unopened
// horizon (48h chip) + margin. Claim wording: media is deleted at burn, or at
// latest 49h after upload if never opened.

/** b199: per-account daily cap on encrypted file uploads (disk-fill guard) */
const UPLOAD_DAILY_CAP = 1024 * 1024 * 1024;
const BLOB_RETENTION_MS = 49 * 3600 * 1000;
// b199: submitEnvelope used to write a second full ciphertext copy under
// ["veil_env", token, id] that nothing read and that expiry/burn never removed,
// so expired and burnt messages kept a server copy forever. The write is gone;
// this drops every copy left from before, once at boot and on every sweep
// (an empty scan once they are cleared).
// Push-coalesce rows written before they carried an expireIn go the same way.
async function sweepLegacyRows(): Promise<number> {
  let n = 0;
  for await (const e of KV.list({ prefix: ["veil_env"] }, { consistency: "strong" })) { await KV.delete(e.key); n++; }
  for (const p of ["push_coalesce", "push_coalesce_invite", "push_coalesce_group"]) {
    for await (const e of KV.list<number>({ prefix: [p] }, { consistency: "strong" })) {
      if (Date.now() - Number(e.value || 0) > COALESCE_TTL_MS) { await KV.delete(e.key); n++; }
    }
  }
  // b199: daily upload-quota counters are only needed for their own day
  const today = new Date().toISOString().slice(0, 10);
  for await (const e of KV.list({ prefix: ["upload_quota"] }, { consistency: "strong" })) {
    if (String(e.key[2]) < today) { await KV.delete(e.key); n++; }
  }
  return n;
}
migrateBlobOwners().then((n) => { if (n) console.log(`[boot] recorded owners for ${n} existing blob file(s)`); }).catch((e) => console.error("[boot] blob owner migration error", e));
sweepLegacyRows().then((n) => { if (n) console.log(`[boot] dropped ${n} legacy envelope-copy / push-coalesce row(s)`); }).catch((e) => console.error("[boot] legacy row cleanup error", e));
setInterval(async () => {
  try { const r = await fnPurgeExpired(); const d = (await r.json()).purged.deleted; if (d) console.log(`[sweeper] purged ${d} expired envelope(s)`); }
  catch (e) { console.error("[sweeper] error", e); }
  try { await pruneStats(); } catch (e) { console.error("[sweeper] stats prune error", e); }
  try {
    let bn = 0;
    // Batch C (A4b; reviews P2 V-10, P4 F-1; port of the b200 fix): vault
    // containers live in the same directory but are kept until their vault is
    // deleted — the 49 h backstop is for media and transfer bundles only.
    const vaultBlobs = new Set<string>();
    for await (const e of KV.list({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) {
      const v = e.value as Record<string, unknown>;
      const uri = String(v.container_uri || "");
      if (!uri.startsWith("blob:")) continue;
      // Batch E (RV-39): only a container the vault's own account uploaded
      const rec = (await KV.get<string>(["blob_owner", uri.slice(5)])).value;
      if (!rec || rec === await blobOwnerTag(String(v._acct || ""), uri.slice(5))) vaultBlobs.add(uri.slice(5));
    }
    for await (const f of Deno.readDir(BLOB_DIR)) {
      if (!f.isFile || vaultBlobs.has(f.name)) continue;
      const st = await Deno.stat(BLOB_DIR + f.name).catch(() => null);
      if (st && st.mtime && Date.now() - st.mtime.getTime() > BLOB_RETENTION_MS) {
        await Deno.remove(BLOB_DIR + f.name).catch(() => undefined);
        bn++;
      }
    }
    // owner records of files that are gone (burnt, swept, collected)
    for await (const e of KV.list({ prefix: ["blob_owner"] }, { consistency: "strong" })) {
      const p = blobPathOf("blob:" + String(e.key[1]));
      if (!p || !(await Deno.stat(p).then(() => true).catch(() => false))) await KV.delete(e.key);
    }
    if (bn) console.log(`[sweeper] deleted ${bn} expired blob file(s)`);
  } catch (e) { console.error("[sweeper] blob cleanup error", e); }
  try {
    // rate-limit buckets live one window; anything from a previous window is dead weight
    const curMinute = Math.floor(Date.now() / 60_000);
    const curHour = Math.floor(Date.now() / 3_600_000);
    let n = 0;
    for await (const e of KV.list({ prefix: ["rl"] }, { consistency: "strong" })) {
      const bucket = Number(e.key[e.key.length - 1]);
      // minute buckets are epoch-minutes (~29.6 M in 2026); hour keys are epoch-hours
      // (~0.49 M). Batch D (D-15 follow-up): the old test (`bucket < 1e6`) was the
      // wrong way round — every sweep deleted the CURRENT hour's buckets, so the
      // 10-signups-per-hour limit reset every sweep.
      // Batch E (round-3 review R3-03): day buckets (epoch-days, ~20 k in 2026) were
      // read as hour keys and deleted every sweep, so a "per day" cap reset every
      // 2 min. Buckets are told apart by size: minutes > hours > days.
      const curDay = Math.floor(Date.now() / 86_400_000);
      const isMinuteKey = bucket > curHour + 1;
      const isHourKey = !isMinuteKey && bucket > curDay + 1;
      const stale = isMinuteKey ? bucket < curMinute - 2 : isHourKey ? bucket < curHour - 2 : bucket < curDay - 2;
      if (stale) { await KV.delete(e.key); n++; }
    }
    if (n) console.log(`[sweeper] dropped ${n} stale limiter key(s)`);
  } catch (e) { console.error("[sweeper] rl cleanup error", e); }
  try {
    const n = await sweepLegacyRows();
    if (n) console.log(`[sweeper] dropped ${n} legacy envelope-copy / push-coalesce row(s)`);
  } catch (e) { console.error("[sweeper] legacy row cleanup error", e); }
}, Number(Deno.env.get("VEIL_SWEEP_MS")) || 2 * 60 * 1000); // Batch C: VEIL_SWEEP_MS is for TEST relays only; production never sets it. b198 (audit follow-up): 10-min sweeper granularity left burnt/expired rows visible up to 10 min past their death — an auditor checking right after a burn sees the row and reads the burn as a no-op. 2-min cadence: deletion lands close to the promised moment; scan cost is trivial at current scale.

// ========== BASE44-ALIGNED veilSessionGate (b198 mirror of the proven source) ==========
const validClientId = (v: unknown) => /^[A-Za-z0-9_-]{4,64}$/.test(String(v ?? "").trim());
const validVeilId = (v: unknown) => /^[1-9A-HJ-NP-Za-km-z]{16}$/.test(String(v ?? "").trim());
const retentionMs = (s: Record<string, any>) => { const h = Number(s.key_retention_hours); return h === 0 ? 365 * 24 * 3600 * 1000 : ((Number.isFinite(h) && h) || 168) * 3600 * 1000; };
const declaredMessageMs = (s: Record<string, any>) => { const a = Number(s?.default_ttl_seconds), b = Number(s?.expire_after_seconds); return Math.max(0, Math.max(Number.isFinite(a) ? a : 0, Number.isFinite(b) ? b : 0)) * 1000; };
const sessionHorizonMs = (s: Record<string, any>) => Math.max(retentionMs(s), declaredMessageMs(s));
async function verifyIdentitySignedEnd(session: Record<string, any>, token: string, body: Record<string, any>) {
  const veilId = String(body?.end_veil_id || "");
  if (!veilId || (veilId !== String(session.initiator_veil_id || "") && veilId !== String(session.responder_veil_id || ""))) return false;
  const ts = Number(body?.end_ts);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > 300000) return false;
  const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
  if (!id) return false;
  return ed25519Verify(String(id.IK_pub || ""), enc.encode(JSON.stringify({ v: 1, end: token, ts })), String(body?.end_sig || ""));
}
async function pushAlertCoalesced(session: Record<string, any>, senderSlot: string) {
  try {
    const side = senderSlot === "initiator" ? "responder" : "initiator";
    const veilId = String(side === "initiator" ? session.initiator_veil_id : session.responder_veil_id || "");
    if (!veilId) return;
    const ck = ["push_coalesce", String(session.token || ""), side];
    if (Date.now() - ((await KV.get<number>(ck)).value ?? 0) < 30000) return;
    await KV.set(ck, Date.now(), { expireIn: COALESCE_TTL_MS });
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = id ? String(id.account_hash || "") : "";
    if (!acct) return;
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") !== acct) continue;
      const t = String(row.expo_token || "");
      void pushFetch(EXPO_PUSH_URL, { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ to: t, title: "Vardum", body: "Notification", sound: "default", priority: "high", data: { kind: "new-message" } }) }).then(async (r) => { const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string } } | null; console.log("[push] ticket  device : " + (d?.data?.status ?? r.status) + (d?.data?.message ? " " + d.data.message : "")); }).catch(() => undefined);
    }
  } catch (e) { console.log("[push] alert failed (non-fatal)"); }
}
async function fnVeilSessionGateAligned(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body?.action || "");
  // b199 AUTHZ: client_id IS the account id (the app always sends its own), so
  // a client_id naming any other account is refused — it used to let anyone
  // list (and purge) every conversation of an account whose id they'd seen in
  // a shared session row.
  const callerAcctP = accountHashOf(auth.userId);
  const ownVeilId = async (v: string) => {
    if (!validVeilId(v)) return false;
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(v)])).value;
    return !!id && String(id.account_hash || "") === await callerAcctP;
  };
  if ((action === "list" || action === "purge") && String(body?.client_id || "").trim() !== auth.userId) {
    return j({ error: "client_id must be your own account" }, 403);
  }
  if (action === "list") {
    const clientId = String(body?.client_id || "").trim();
    if (!validClientId(clientId)) return j({ error: "Invalid client id" }, 400);
    const veilId = String(body?.veil_id || "").trim();
    // pending contact requests addressed to a Veil ID are only listed for the
    // account that Veil ID is bound to (it used to be anyone who knew the ID)
    const veilIdMine = await ownVeilId(veilId);
    let restoreOk = false;
    if (validVeilId(veilId) && body?.list_ts && body?.list_sig) {
      const ts = Number(body.list_ts);
      if (Number.isFinite(ts) && Math.abs(Date.now() - ts) <= 300000) {
        const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
        if (id) restoreOk = await ed25519Verify(String(id.IK_pub || ""), enc.encode(JSON.stringify({ v: 1, list: clientId, ts })), String(body.list_sig || ""));
      }
    }
    // Batch E (round-3 review R3-02): the caller's OWN sessions (it is a side of
    // the row) are always listed in full. The list used to be cut to the newest
    // 100 rows of everything, so rows that merely name the caller (requests from
    // others, restore matches) pushed its real chats off the end, and the app
    // read a missing chat as ended. Only those naming rows are capped now.
    // Optional paging: `limit` (1-500) + the `next_cursor` of the previous page;
    // without `limit` every own row comes back in one answer (older apps).
    const own: Record<string, unknown>[] = [];
    const naming: Record<string, unknown>[] = [];
    const pendingOnly = new WeakSet<Record<string, unknown>>();
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
      const s = e.value as Record<string, unknown>;
      const match = String(s.initiator_client_id || "") === clientId || String(s.responder_client_id || "") === clientId;
      const pendingForMe = veilIdMine && !!s.contact_session && String(s.state || "") === "pending" && !String(s.responder_client_id || "") && String(s.responder_veil_id || "") === veilId;
      const identityClause = restoreOk && !!s.contact_session && (String(s.initiator_veil_id || "") === veilId || String(s.responder_veil_id || "") === veilId);
      if (match) own.push({ ...(s as any), id: e.key[e.key.length - 1] });
      else if (pendingForMe || identityClause) {
        const row = { ...(s as any), id: e.key[e.key.length - 1] };
        if (pendingForMe && !identityClause) pendingOnly.add(row); // Batch H (R6-3-11)
        naming.push(row);
      }
    }
    // newest first; the row id breaks ties so the paging order is total
    const newestFirst = (a: Record<string, unknown>, b: Record<string, unknown>) =>
      String(b.created_date ?? "").localeCompare(String(a.created_date ?? "")) || String(b.id).localeCompare(String(a.id));
    own.sort(newestFirst);
    naming.sort(newestFirst);
    // Batch G (round-5 review R5-3-05): at most the 3 newest rows per initiating
    // account, so a few throwaway accounts can't bury a real request under paging
    {
      const perInit = new Map<string, number>();
      const kept: Record<string, unknown>[] = [];
      // Batch H (round-6 review R6-3-11): only requests are capped. Restore matches
      // (the user's own old chats, whose initiator is the user's own old account) are not.
      for (const r of naming) {
        if (!pendingOnly.has(r)) { kept.push(r); continue; }
        const k = String(r.initiator_client_id || r.initiator_veil_id || r.id);
        const c = perInit.get(k) ?? 0;
        if (c < 3) { kept.push(r); perInit.set(k, c + 1); }
      }
      naming.length = 0; naming.push(...kept);
    }
    const cursor = typeof body?.cursor === "string" ? body.cursor : "";
    const limitRaw = Number(body?.limit);
    const limit = body?.limit === undefined ? Infinity : (Number.isInteger(limitRaw) ? Math.min(500, Math.max(1, limitRaw)) : 100);
    let start = 0;
    if (cursor) {
      const cut = cursor.indexOf("|");
      if (cut < 0 || cursor.length > MAX_KEY_PART) return j({ error: "Invalid cursor" }, 400);
      const at = { created_date: cursor.slice(0, cut), id: cursor.slice(cut + 1) };
      start = own.findIndex((r) => newestFirst(at, r) < 0);
      if (start < 0) start = own.length;
    }
    // Batch F (round-4 reviews R4-3-02 / R4-4-21): rows that only NAME the caller
    // are paged too, with their own cursor (naming_cursor / naming_next_cursor),
    // so other accounts can't push real requests out of reach. A call with a
    // naming_cursor returns only naming rows.
    const namingCursor = typeof body?.naming_cursor === "string" ? body.naming_cursor : "";
    let nStart = 0;
    if (namingCursor) {
      const cut = namingCursor.indexOf("|");
      if (cut < 0 || namingCursor.length > MAX_KEY_PART) return j({ error: "Invalid cursor" }, 400);
      const at = { created_date: namingCursor.slice(0, cut), id: namingCursor.slice(cut + 1) };
      nStart = naming.findIndex((r) => newestFirst(at, r) < 0);
      if (nStart < 0) nStart = naming.length;
    }
    const nPage = (cursor && !namingCursor) ? [] : naming.slice(nStart, nStart + LIST_NAMING_CAP);
    const nLast = nPage[nPage.length - 1];
    const naming_next_cursor = nStart + nPage.length < naming.length && nLast ? `${String(nLast.created_date ?? "")}|${String(nLast.id)}` : null;
    if (namingCursor) return json({ sessions: nPage, next_cursor: null, naming_next_cursor });
    const page = own.slice(start, start + limit);
    const last = page[page.length - 1];
    const next_cursor = start + page.length < own.length && last ? `${String(last.created_date ?? "")}|${String(last.id)}` : null;
    return json({ sessions: [...page, ...nPage], next_cursor, naming_next_cursor });
  }
  if (action === "purge") {
    const clientId = String(body?.client_id || "").trim();
    if (!validClientId(clientId)) return j({ error: "Invalid client id" }, 400);
    const acct = await accountHashOf(auth.userId);
    const myVeilIds: string[] = [];
    for await (const e of KV.list({ prefix: ["veil_identity"] }, { consistency: "strong" })) { const r = e.value as Record<string, unknown>; if (String(r.account_hash || "") === acct) myVeilIds.push(String(r.veil_id)); }
    let sessions = 0, envelopes = 0;
    const doomed: string[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) { const s = e.value as Record<string, unknown>; if (String(s.initiator_client_id || "") === clientId || String(s.responder_client_id || "") === clientId || myVeilIds.includes(String(s.initiator_veil_id || "")) || myVeilIds.includes(String(s.responder_veil_id || ""))) doomed.push(String(s.token || "")); }
    for (const tok of doomed) { envelopes += await deleteSessionEnvelopes(tok); }
    for (const tok of doomed) { await KV.delete(["veil_sess_token", keySafe(tok)]); for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) { if (String((e.value as Record<string, unknown>).token || "") === tok) { await KV.delete(e.key); sessions++; } } }
    for (const vid of myVeilIds) await KV.delete(["veil_identity", keySafe(vid)]);
    return json({ ok: true, deleted: { sessions, envelopes, identities: myVeilIds.length } });
  }
  const token = String(body?.token || "");
  const session = await findSessionByToken(token);
  if (!session) {
    if (action === "end") return json({ ok: true });
    if (action === "burn") return json({ ok: true, already_gone: true, burned: false, reason: "session_gone" });
    return j({ error: "Session not found" }, 404);
  }
  const wsHash = body?.write_secret ? await sha256hex(String(body.write_secret)) : "";
  let slot: string | null = wsHash && ctEq(wsHash, String(session.initiator_write_hash || "")) ? "initiator" : (wsHash && ctEq(wsHash, String(session.responder_write_hash || "")) ? "responder" : null);
  if (!slot && action === "end" && !!session.contact_session) {
    const addresseeEnd = String(body?.end_veil_id || "") === String(session.responder_veil_id || "");
    if (!(String(session.state || "") === "pending" && addresseeEnd)) { if (await verifyIdentitySignedEnd(session, token, body)) slot = "participant"; }
  }
  if (!slot && action === "end") {
    const clientId = String(body?.client_id || "").trim();
    const veilId = String(body?.veil_id || "").trim();
    // b199 AUTHZ: the client_id / veil_id fallbacks prove participation only
    // when they are the CALLER's own — an account id or Veil ID read off a
    // shared row used to be enough to delete someone else's conversation.
    let participant = clientId === auth.userId && validClientId(clientId) && (clientId === String(session.initiator_client_id || "") || clientId === String(session.responder_client_id || ""));
    if (!participant && await ownVeilId(veilId)) {
      const addresseeEnd = veilId === String(session.responder_veil_id || "");
      if (!(String(session.state || "") === "pending" && addresseeEnd) && (veilId === String(session.initiator_veil_id || "") || addresseeEnd)) participant = true;
    }
    if (participant) slot = "participant";
  }
  if (!slot) {
    console.warn("session-credential-refused", { action, state: session.state, presented: typeof body?.write_secret === "string" ? String(body.write_secret).length : 0 });
    return j({ error: "Invalid session credential" }, 403);
  }
  const horizon = () => new Date(Date.now() + sessionHorizonMs(session)).toISOString();
  // b199: a seat locked to one Veil ID (group invites sent to a pinned contact)
  // can only be viewed or joined by the account that owns that identity — the
  // write secret alone is not enough, so a forwarded invite is useless.
  const lockedInvitee = String(session.invitee_veil_id || "");
  const notTheInvitee = async () => {
    if (!lockedInvitee) return false;
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(lockedInvitee)])).value;
    return !id || String(id.account_hash || "") !== await accountHashOf(auth.userId);
  };
  if ((action === "peek" || action === "join") && slot === "responder" && await notTheInvitee()) {
    return j({ error: "This invitation was sent to someone else." }, 403);
  }
  if (action === "peek") {
    if (slot !== "responder") return j({ error: "Only the invited side can view this session" }, 403);
    return json({ session: { state: session.state, responder_client_id: session.responder_client_id, expires_at: session.expires_at, initiator_pub_jwk: session.initiator_pub_jwk, initiator_pq_pub: session.initiator_pq_pub, passphrase_required: session.passphrase_required, group_token: session.group_token || "", group_epoch: Number(session.group_epoch) || 0, group_name: session.group_name || "", group_pq_pub: session.group_pq_pub || "",
      // Batch D (found by the D-21 spec rewrite): the joiner binds the dials into the
      // fingerprint and its expiry — without them it fell back to the defaults
      default_ttl_seconds: session.default_ttl_seconds, expire_after_seconds: session.expire_after_seconds, key_retention_hours: session.key_retention_hours, burn_after_open: session.burn_after_open === true } });
  }
  if (action === "join") {
    if (slot !== "responder") return j({ error: "Only the invited side can join this session" }, 403);
    // Batch E (round-3 review R3-01): the joiner's client id IS its account id
    // (the app always sends its own). Any other id used to be stored as the
    // responder, planting rows in that account's session list and passing the
    // push-target check with someone else's identity (RV-59, RV-09, RV-11).
    if (String(body?.client_id || "").trim() !== auth.userId) return j({ error: "client_id must be your own account" }, 403);
    // Batch D (D-18, RV-14): the forum founder's invite row is public (its w is in
    // the descriptor); joining it would take it over and break the public link
    const forumInvite = (await knownForum()).invite;
    if (forumInvite && token === forumInvite) return j({ error: "The forum invitation can't be joined" }, 403);
    if (String(session.state || "") === "ended") return j({ error: "This session has ended." }, 400);
    if (String(session.state) === "active" && String(session.responder_client_id || "") === String(body?.client_id || "") && (String(session.responder_pub_jwk || "") !== String(body?.responder_pub_jwk || "") || String(session.responder_ratchet_pub_jwk || "") !== String(body?.responder_ratchet_pub_jwk || ""))) return j({ error: "This session was already accepted from this device with different keys — it cannot be re-joined here. Start a new session." }, 409);
    if (String(session.state) === "active" && String(session.responder_client_id || "") && String(session.responder_client_id || "") !== String(body?.client_id || "")) return j({ error: "This session is already in use." }, 400);
    if (String(session.state) === "pending" && new Date(String(session.expires_at)) < new Date()) return j({ error: "Invitation has expired." }, 400);
    for (const [k, v] of Object.entries({ responder_client_id: body?.client_id, responder_pub_jwk: body?.responder_pub_jwk, responder_ratchet_pub_jwk: body?.responder_ratchet_pub_jwk, fingerprint: body?.fingerprint })) { if (typeof v !== "string" || !v) return j({ error: `Missing join field: ${k}` }, 400); }
    // Batch C (V-16, relay half): a joiner may replace the responder credential
    // with a fresh one, so the link's w stops working once the invite is used.
    // Optional — older apps keep using w.
    const nextHash = typeof body?.new_responder_write_hash === "string" ? body.new_responder_write_hash : "";
    if (nextHash) {
      if (!/^[0-9a-f]{64}$/.test(nextHash)) return j({ error: "Invalid new responder credential" }, 400);
      session.responder_write_hash = nextHash;
    }
    session.responder_client_id = String(body.client_id);
    session.responder_display_name = typeof body?.display_name === "string" ? String(body.display_name).slice(0, 64) : "";
    session.state = "active"; session.expires_at = horizon(); session.responder_pub_jwk = String(body.responder_pub_jwk); session.responder_ratchet_pub_jwk = String(body.responder_ratchet_pub_jwk); session.responder_pq_ct = typeof body?.responder_pq_ct === "string" ? String(body.responder_pq_ct) : ""; session.session_fingerprint = String(body.fingerprint); session.last_activity = nowIso(); session.updated_date = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ session });
  }
  if (action === "activate") {
    if (slot !== "initiator") return j({ error: "Only the session creator can activate this session" }, 403);
    if (!session.group_token) return j({ error: "Only group sessions can be activated without a peer" }, 400);
    if (String(session.state || "") === "ended") return j({ error: "This session has ended." }, 400);
    if (String(session.state) === "active") return json({ session });
    session.state = "active"; session.expires_at = horizon(); session.last_activity = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ session });
  }
  if (action === "verify") {
    const early = slot === "initiator" && !!session.contact_session && String(session.state || "") === "pending";
    if (String(session.state || "") !== "active" && !early) return j({ error: "This conversation is not open yet, so the confirmation could not be recorded. Confirm once the other side has accepted the request." }, 409);
    const flag = slot === "initiator" ? "initiator_verified" : "responder_verified";
    (session as any)[flag] = true; session.updated_date = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    console.info("verify-ceremony", { slot, state: session.state, early_confirm: early, iv: !!session.initiator_verified, rv: !!session.responder_verified });
    return json({ session });
  }
  if (action === "bump") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    session.last_activity = nowIso(); session.expires_at = horizon();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ ok: true });
  }
  if (action === "notify") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    // Batch D (D-13, RV-09): a push goes only to a side whose account actually
    // joined — a row naming someone's Vardum ID is not a conversation with them
    if (!(await pushTargetJoined(session, slot === "initiator" ? "responder" : "initiator"))) {
      return j({ error: "The other side has not joined this conversation" }, 403);
    }
    // b198 CALL RING BURST (the live notify path — my first burst branch was
    // placed in the legacy/dead handler, which is why the callee still saw a
    // single "Notification"): a call rings with a BURST of pushes across the
    // 21s ring window, body "Incoming call" — buzzing on-and-off, unmistakable
    // next to a message's single "Notification".
    if (body?.call === true) {
      // Batch D (D-13): one ring burst per conversation per ring window
      const rk = ["call_ring", keySafe(token)];
      const last = await KV.get<number>(rk);
      if (last.value && Date.now() - last.value < CALL_RING_WINDOW_MS) return json({ ok: true, coalesced: true });
      const claimed = await KV.atomic().check(last).set(rk, Date.now(), { expireIn: CALL_RING_WINDOW_MS * 3 }).commit();
      if (!claimed.ok) return json({ ok: true, coalesced: true });
      void pushCallBurst(session, slot === "initiator" ? "responder" : "initiator");
      return json({ ok: true });
    }
    // Batch D (D-13): message pushes per conversation side are capped too
    if (await rateLimit(`notify:${token}:${slot}`, 60, 60_000, 1)) return j({ error: "Too many notifications" }, 429);
    void pushAlertCoalesced(session, slot);
    return json({ ok: true });
  }
  if (action === "burn") {
    const envelopeId = String(body?.envelope_id || "");
    if (!envelopeId) return j({ error: "Missing envelope id" }, 400);
    let policy: Record<string, any> = session;
    if (session.group_token) {
      // Batch D (D-14, RV-10): nobody burns forum posts — every tester holds a row
      // there and could set any burn policy on it
      if (String(session.group_token) === (await knownForum()).group_token) return j({ error: "Forum posts can't be burned" }, 403);
      // the group's burn policy comes only from the OWNER's main row (rows the
      // recorded owner account created), never from whichever row sorts first
      const ownerAcct = (await KV.get<string>(["veil_group_owner", keySafe(String(session.group_token))])).value ?? "";
      const gs: Record<string, any>[] = [];
      for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) { const s = e.value as Record<string, any>; if (String(s.group_token || "") === String(session.group_token)) gs.push({ ...s, id: e.key[e.key.length - 1] }); }
      const ownerRows: Record<string, any>[] = [];
      for (const s of gs) if (s.initiator_client_id && !s.responder_client_id && s.state === "active" && (!ownerAcct || await accountHashOf(String(s.initiator_client_id)) === ownerAcct)) ownerRows.push(s);
      policy = ownerRows[0] ?? {};
    }
    if (!policy.burn_after_open) return j({ error: "This session is not burn-after-open" }, 400);
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    const env = (await KV.get<Record<string, any>>(["entity", "VeilEnvelope", keySafe(envelopeId)])).value;
    if (!env) return json({ ok: true, already_gone: true, burned: false, reason: "envelope_gone" });
    if (String(env.session_token || "") !== token && !(session.group_token && String(env.group_token || "") === String(session.group_token))) return j({ error: "Envelope does not belong to this session" }, 403);
    const cur = new Date(String(env.expires_at)).getTime();
    if (!Number.isFinite(cur) || cur <= Date.now()) return json({ ok: true, burned: false, reason: "already_expired" });
    const burnSeconds = Number(policy.default_ttl_seconds) || 3600;
    const burnAt = Date.now() + burnSeconds * 1000;
    if (burnAt >= cur) return json({ ok: true, burned: false, reason: "already_within_burn_window", expires_at: env.expires_at, burn_window_seconds: burnSeconds });
    env.expires_at = new Date(burnAt).toISOString(); env.delivery_state = "delivered";
    await KV.set(["entity", "VeilEnvelope", keySafe(envelopeId)], env);
    console.info("burn-executed", { slot, window: burnSeconds });
    return json({ ok: true, burned: true, reason: "shortened", expires_at: env.expires_at });
  }
  if (action === "heartbeat") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    session.last_activity = nowIso();
    if (slot === "initiator") session.initiator_seen_at = nowIso(); else if (slot === "responder") session.responder_seen_at = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ ok: true });
  }
  if (action === "end") {
    // Batch C (A5; review P2 V-17): the forum's founder invite row carries a
    // public w (the descriptor link) — holding it must not let anyone end it
    // Batch E (round-3 review R3-08): knownForum(), not the config alone — with the
    // config missing this check used to see no forum and let the public w end it
    const forumInvite = (await knownForum()).invite;
    if (forumInvite && token === forumInvite && !(await isLoungeFounder(auth))) {
      return j({ error: "Only the forum founder can end the forum invitation" }, 403);
    }
    if (!session.group_token) await deleteSessionEnvelopes(token); // W-19: group envelopes are shared history
    await KV.delete(["entity", "VeilSession", String(session.id)]);
    await KV.delete(["veil_sess_token", keySafe(token)]);
    return json({ ok: true });
  }
  return j({ error: "Unknown action" }, 400);
}
