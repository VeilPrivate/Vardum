/**
 * Contentless push plumbing — iOS 1.0.
 *
 * VEIL's threat model: the push channel must leak NOTHING about who or what.
 * The APNs payload carries no sender, no ciphertext, no session token — the
 * client wakes, polls its own sessions over the encrypted relay, and shows a
 * generic local banner. Server side, the relay's push trigger sends the SAME
 * generic ping regardless of which peer/session/message fired it.
 */
import * as Notifications from 'expo-notifications';
import Constants from 'expo-constants';
import { Platform } from 'react-native';
import { CallManager } from './calls/CallManager';
import { withSystemSheet } from './lock-hold';
import { isUnifiedPushAvailable, ensureEndpoint, storedEndpoint, unregisterUnifiedPush, upTokenFor } from './unifiedpush';

// b199 ANDROID CHANNELS (Android handover TODO, owner OK Oct 17). Android
// shows a push only as loudly as its channel allows, and a channel's
// importance is fixed once created on a device — so both are made here, at
// module load, before the first push can arrive. 'default' is what Expo
// uses for any push without a channelId (messages): HIGH, so it heads-up
// like the iOS banner. 'calls' is MAX for the "Incoming call" burst; the
// relay names it per push (channelId "calls"), and until that relay change
// is live call pushes land on 'default', which still alerts. Lock-screen
// text is the contentless body by design ("Notification" / "Incoming
// call"), so PUBLIC visibility leaks nothing. iOS ignores all of this.
if (Platform.OS === 'android') {
  void Notifications.setNotificationChannelAsync('default', {
    name: 'Messages',
    importance: Notifications.AndroidImportance.HIGH,
    lockscreenVisibility: Notifications.AndroidNotificationVisibility.PUBLIC,
    vibrationPattern: [0, 250, 250, 250],
  }).catch(() => undefined);
  void Notifications.setNotificationChannelAsync('calls', {
    name: 'Calls',
    importance: Notifications.AndroidImportance.MAX,
    lockscreenVisibility: Notifications.AndroidNotificationVisibility.PUBLIC,
    vibrationPattern: [0, 600, 800, 600, 800],
    bypassDnd: false,
  }).catch(() => undefined);
}


// b77 FIX: the handler below used to return the SAME suppressed result for
// every notification, remote or local. The remote APNs wake-ping (contentless,
// fired on every VeilEnvelope insert including cover-traffic decoys) is
// correctly silent by design — but that blanket suppression also silently ate
// the LOCAL "new message" banner scheduled by notifyNewMessage() below,
// after this device had actually decrypted a real message. Net effect:
// notifications never showed at all, foreground or background. (b198: the
// blanket suppression below is retired — see the new posture comment.)
// b198 (owner report: no lock-screen notifications): the OLD posture suppressed
// ALL remote pings and showed a LOCAL banner only after a background wake →
// sync → decrypt cycle. That chain requires the OS to background-wake the app
// on the silent ping — which Metro/dev-client builds cannot do, so the lock
// screen showed NOTHING. On this relay the ping fires ONLY on real text/media
// sends (notifySent — never for cover traffic), so the old reason for the
// suppression is gone: the remote ping itself is now the visible, CONTENTLESS
// lock-screen notification (no sender, no session, no content).
Notifications.setNotificationHandler({
  handleNotification: async (notification) => {
    const d = notification.request.content.data as { veilLocal?: boolean; kind?: string } | null;
    // b198 CALL RING BURST: call pushes (kind 'call', body "Incoming call")
    // display like messages UNTIL the call connects — once the ringing
    // overlay or the call itself is up, the remaining burst banners go silent
    // (the in-call ring + vibration take over; banners would stack over the
    // call UI).
    let callLive = false;
    try { const s = CallManager.snapshot(); callLive = !!s && (s.phase === 'ringing' || s.phase === 'connecting' || s.phase === 'active' || s.phase === 'calling'); } catch { /* no call state */ }
    const show = d?.veilLocal === true || ((d?.kind === 'new-message' || d?.kind === 'call') && !callLive);
    if (d?.kind === 'new-message') lastRemotePingAt = Date.now();
    return {
      shouldShowAlert: show,
      shouldShowBanner: show,
      shouldShowList: show,
      shouldPlaySound: show,
      shouldSetBadge: false,
    };
  },
});

/** b198: when a remote ping just landed, the local post-decrypt banner would
 *  double-fire behind it — skip the local one for a short window. */
let lastRemotePingAt = 0;
const REMOTE_PING_DEDUP_MS = 30_000;

/** Rate limit for local new-message banners (ms). */
const NOTIFY_MIN_INTERVAL_MS = 15_000;
let lastNotifyAt = 0;

/**
 * Generic local banner for an actual new chat message found by polling.
 * Carries no sender, no content, no session — same threat model as the ping.
 * Rate-limited so a burst of arrivals (or a peer's cover stream) can't spam.
 */
/** Rate limit for invite banners (ms) — independent of message banners. */
const NOTIFY_INVITE_MIN_INTERVAL_MS = 30_000;
let lastInviteNotifyAt = 0;

/**
 * b178: generic local banner when a NEW invite session appears on the poll
 * (owner report: invites arrived with zero notification, foreground or
 * background). Same contentless rule as the message banner — no sender,
 * no session identity — the body only says an invite exists. Suppression on
 * the lock screen still requires the server-side VeilSession push trigger
 * (see the b178 note in App.tsx refreshSessions).
 */
export async function notifyNewInvite(): Promise<void> {
  try {
    const now = Date.now();
    if (now - lastInviteNotifyAt < NOTIFY_INVITE_MIN_INTERVAL_MS) return;
    lastInviteNotifyAt = now;
    await Notifications.scheduleNotificationAsync({
      content: { title: 'Vardum', body: 'New chat invite', data: { veilLocal: true } },
      trigger: null,
    });
  } catch { /* notifications are best-effort */ }
}

export async function notifyNewMessage(): Promise<void> {
  try {
    const now = Date.now();
    if (now - lastRemotePingAt < REMOTE_PING_DEDUP_MS) return; // the visible remote ping already covered this
    if (now - lastNotifyAt < NOTIFY_MIN_INTERVAL_MS) return;
    lastNotifyAt = now;
    await Notifications.scheduleNotificationAsync({
      content: { title: 'Vardum', body: 'Notification', data: { veilLocal: true } },
      trigger: null,
    });
  } catch { /* notifications are best-effort */ }
}

export async function ensurePushPermission(): Promise<boolean> {
  try {
    const cur = (await Notifications.getPermissionsAsync()) as unknown as { status: string; canAskAgain?: boolean };
    if (cur.status === 'granted') return true;
    // ask ONCE: after a denial never re-prompt automatically (the OS keeps
    // its answer; repeated requests are the "endless permission prompts").
    // b199 (ZTE device run): Android 13+ reports "denied" BEFORE the first
    // ask, with canAskAgain=true — that is "never asked", not a refusal, and
    // reading it as a refusal meant Android never showed the prompt at all.
    if (cur.status === 'denied' && cur.canAskAgain === false) return false;
    if (cur.status === 'denied' && Platform.OS !== 'android') return false;
    const req = (await withSystemSheet(() => Notifications.requestPermissionsAsync())) as unknown as { status: string };
    return req.status === 'granted';
  } catch { return false; }
}

/** Relay + keychain shapes (injected — keeps this module pure for tests). */
export interface PushRegistrationDeps {
  /** Batch H (round-6 review R6-3-09): relay functions (veilPushReset) */
  invoke?: (fn: string, payload: Record<string, unknown>) => Promise<unknown>;
  entityCreate: (entity: string, record: Record<string, unknown>) => Promise<unknown>;
  /** user-scoped entity LIST (own rows only) — used to dedupe before create */
  entityList: (entity: string, params: Record<string, string | number>) => Promise<unknown>;
  /** b198: delete an untagged (pre-acct) row so it can be replaced by a tagged one */
  entityDelete?: (entity: string, id: string) => Promise<unknown>;
  getCached: (key: string) => Promise<string | null>;
  setCached: (key: string, value: string) => Promise<unknown>;
}

/**
 * Register this device's Expo push token with the relay (VeilPushToken).
 * One record per token; re-registers only when the token CHANGES (Expo tokens
 * can rotate across installs). Cached in the secure store to avoid record spam.
 */
export async function registerPushToken(relay: PushRegistrationDeps): Promise<boolean> {
  try {
    const target = await resolvePushTarget();
    const token = target?.token ?? null;
    if (!token) {
      console.log('[veil-push] registerPushToken: no token available — relay NOT updated');
      return false;
    }
    // b198: the key was bumped once (v2) so existing installs re-register —
    // rows created before the relay tagged them with the owning account could
    // never be matched for push delivery
    const key = 'veil_push_token_cached_v2';
    if ((await relay.getCached(key)) === token) return true; // already registered
    // b69: the cached key dies on sign-out wipe — check the user's OWN rows
    // before creating another one for the same token (each extra row = one
    // extra APNs ping per envelope on the server trigger).
    try {
      const listed = (await relay.entityList('VeilPushToken', { expo_token: token })) as unknown;
      const rows = (Array.isArray(listed) ? listed : ((listed as { data?: unknown[] })?.data ?? [])) as Record<string, unknown>[];
      const mine = rows.find((r) => String(r.expo_token ?? '') === token);
      if (mine) {
        // b198: rows created before the relay tagged them with the owning
        // account can never be matched for push delivery — replace them with
        // a tagged row instead of dedupe-skipping on a dead record
        if (mine.id && !String((mine as { _acct?: string })._acct || '') && relay.entityDelete) {
          await relay.entityDelete('VeilPushToken', String(mine.id)).catch(() => undefined);
        } else {
          await relay.setCached(key, token);
          return true; // live, tagged row already exists — never duplicate
        }
      }
    } catch { /* list unavailable (offline) — fall through to create */ }
    // Batch H (round-6 review R6-3-09): this phone's earlier rows (an older token or
    // endpoint) go first, so a stale row never keeps delivering
    const deviceId = await pushDeviceId(relay);
    if (deviceId && relay.invoke) await relay.invoke('veilPushReset', { device_id: deviceId }).catch(() => undefined);
    await relay.entityCreate('VeilPushToken', { expo_token: token, ...(target?.extra ?? {}), ...(deviceId ? { device_id: deviceId } : {}) });
    await relay.setCached(key, token);
    console.log('[veil-push] registered new token with relay');
    return true;
  } catch (e) {
    console.log(`[veil-push] registerPushToken FAILED: ${(e as Error).message ?? e}`);
    return false;
  }
}

/**
 * b95 NaR v2: remove this device's push registration from the relay so a
 * wiped (Nothing-at-Rest) device goes SILENT — no lock-screen banners, no
 * APNs pings — until the identity is restored from the 24-word phrase, at
 * which point the registration effect in App.tsx re-registers it.
 * Server-side the rows are user-scoped, so deleting own rows is authorized.
 */
/**
 * Batch G (round-5 review R5-3-04): the wipe-time unregister. It uses ONLY the
 * token cached at registration: no permission request and no fresh token from
 * the OS, so a duress wipe never raises a system prompt. No cached token, nothing to do.
 */
/** Batch H (round-6 reviews R6-1-01 / R6-3-10): what a wipe unregisters, read
 *  BEFORE the local wipe deletes the cached token. */
export interface PushTarget { token: string; up: boolean; /** Batch H (R6-3-09) */ deviceId?: string }

/** Batch H (round-6 review R6-3-09): a random id for this install's push rows, so
 *  the phone can remove its own earlier rows (kept through Nothing-at-Rest wipes). */
export const PUSH_DEVICE_KEY = 'veil_push_device_v1';
async function pushDeviceId(relay: Pick<PushRegistrationDeps, 'getCached' | 'setCached'>): Promise<string> {
  try {
    const have = await relay.getCached(PUSH_DEVICE_KEY);
    if (have && /^[A-Za-z0-9_-]{4,64}$/.test(have)) return have;
    const id = 'pd' + Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, '0')).join('');
    await relay.setCached(PUSH_DEVICE_KEY, id);
    return id;
  } catch { return ''; }
}

/** Batch H (R6-3-08): log the push host, never the endpoint (the topic is a capability) */
function pushHostOf(url: string): string {
  try { return new URL(url).host; } catch { return '?'; }
}

/** Batch H: read this phone's push target without asking the OS (no prompt):
 *  the UnifiedPush endpoint from the app's own store, else the cached token. */
export async function capturePushTarget(getCached: (key: string) => Promise<string | null>): Promise<PushTarget | null> {
  try {
    const upEp = Platform.OS === 'android' ? storedEndpoint() : null;
    const deviceId = (await getCached(PUSH_DEVICE_KEY).catch(() => null)) || undefined;
    if (upEp) return { token: upTokenFor(upEp), up: true, deviceId };
    const token = (await getCached('veil_push_token_cached_v2')) || (await getCached('veil_push_token_cached')) || '';
    return token || deviceId ? { token, up: false, deviceId } : null;
  } catch { return null; }
}

export async function unregisterCachedPushToken(relay: PushRegistrationDeps & {
  entityDelete: (entity: string, id: string) => Promise<unknown>;
}, target?: PushTarget | null): Promise<void> {
  // a wipe passes the target it read before wiping; other callers read it now
  const t = target !== undefined ? target : await capturePushTarget((k) => relay.getCached(k));
  // Batch H (R6-1-03 = R6-3-02): release the UnifiedPush registration FIRST. It is
  // local and needs no network, so an offline or slow wipe still leaves no live
  // push address (it used to run only after the relay answered).
  if (t?.up) { try { unregisterUnifiedPush(); } catch { /* best-effort */ } }
  try {
    if (t?.token) {
      const listed = (await relay.entityList('VeilPushToken', { expo_token: t.token })) as unknown;
      const rows = (Array.isArray(listed) ? listed : ((listed as { data?: unknown[] })?.data ?? [])) as Record<string, unknown>[];
      for (const r of rows) {
        if (String(r.expo_token ?? '') === t.token && r.id) await relay.entityDelete('VeilPushToken', String(r.id)).catch(() => undefined);
      }
    }
  } catch { /* best-effort */ }
  // Batch H (R6-3-09): and every earlier row of this phone (an older token or endpoint)
  if (t?.deviceId && relay.invoke) await relay.invoke('veilPushReset', { device_id: t.deviceId }).catch(() => undefined);
  // after a wipe the cached markers are already gone; don't write them back
  if (target === undefined) {
    await relay.setCached('veil_push_token_cached', '').catch(() => undefined);
    await relay.setCached('veil_push_token_cached_v2', '').catch(() => undefined);
  }
}

export async function unregisterPushToken(relay: PushRegistrationDeps & {
  entityDelete: (entity: string, id: string) => Promise<unknown>;
}): Promise<void> {
  try {
    // GrapheneOS path: the relay row is keyed by the UnifiedPush endpoint
    const upEp = Platform.OS === 'android' ? storedEndpoint() : null;
    const token = upEp ? upTokenFor(upEp) : await getPushToken();
    if (token) {
      const listed = (await relay.entityList('VeilPushToken', { expo_token: token })) as unknown;
      const rows = (Array.isArray(listed) ? listed : ((listed as { data?: unknown[] })?.data ?? [])) as Record<string, unknown>[];
      for (const r of rows) {
        if (String(r.expo_token ?? '') === token && r.id) {
          await relay.entityDelete('VeilPushToken', String(r.id)).catch(() => undefined);
        }
      }
    }
    // cached marker dies too — a later re-register (post phrase-restore) must
    // actually create a fresh row, not skip on the stale cache
    await relay.setCached('veil_push_token_cached', '');
    await relay.setCached('veil_push_token_cached_v2', '');
    // also drop the distributor registration, so a wiped phone holds no live
    // push address at all; phrase restore registers a fresh one
    if (upEp) unregisterUnifiedPush();
  } catch { /* best-effort: offline wipe retries at next boot */ }
}

/**
 * Where this device's contentless pings should go.
 * Android with a UnifiedPush distributor (ntfy) installed — the GrapheneOS
 * path, no Google — files the distributor endpoint + its Web Push keys.
 * Everything else uses the Expo token as before.
 *
 * The relay row keeps the same shape (expo_token is the lookup key, here
 * "up:<endpoint>"), plus up_* fields the relay uses to send a Web Push
 * (RFC 8030/8291) ping instead of an Expo one.
 */
async function resolvePushTarget(): Promise<{ token: string; extra?: Record<string, string> } | null> {
  if (Platform.OS === 'android' && isUnifiedPushAvailable()) {
    if (!(await ensurePushPermission())) {
      console.log('[veil-push] permission not granted — skipping UnifiedPush registration');
      return null;
    }
    const ep = await ensureEndpoint();
    if (!ep) return null;
    console.log(`[veil-push] UnifiedPush endpoint OK (${pushHostOf(ep.url)})`); // Batch H (R6-3-08)
    return {
      token: upTokenFor(ep),
      extra: { transport: 'unifiedpush', up_endpoint: ep.url, up_p256dh: ep.pubKey, up_auth: ep.auth },
    };
  }
  if (Platform.OS === 'android') {
    console.log('[veil-push] no UnifiedPush distributor installed (install ntfy for push on GrapheneOS) — trying Expo/FCM');
  }
  const t = await getPushToken();
  return t ? { token: t } : null;
}

/**
 * b124 FIX: getExpoPushTokenAsync() needs an explicit projectId on SDK 52 —
 * without one it throws, and the old catch-and-return-null here made that
 * failure invisible (registerPushToken() below just silently never wrote a
 * row to the relay). Root cause of "no remote push ever arrives": a fresh
 * dev-client install had no linked EAS project, so every registration
 * attempt died at this line with zero trace. Now: read the projectId from
 * app.json (baked in at build time) or the EAS update manifest fallback,
 * and log loudly on failure so this can't go dark again.
 */
function resolveProjectId(): string | null {
  const fromExtra = (Constants.expoConfig?.extra as { eas?: { projectId?: string } } | undefined)?.eas?.projectId;
  const fromEasConfig = (Constants as unknown as { easConfig?: { projectId?: string } }).easConfig?.projectId;
  return fromExtra ?? fromEasConfig ?? null;
}

/** Expo push token for the relay's contentless push trigger. */
export async function getPushToken(): Promise<string | null> {
  try {
    if (!(await ensurePushPermission())) {
      console.log('[veil-push] permission not granted — skipping token fetch');
      return null;
    }
    const projectId = resolveProjectId();
    if (!projectId) {
      console.log('[veil-push] FAILED: no EAS projectId found in app config — run `eas init` and rebuild');
      return null;
    }
    const t = await Notifications.getExpoPushTokenAsync({ projectId });
    const token = (t.data as string) ?? null;
    console.log(`[veil-push] token fetched OK: ${token ? token.slice(0, 24) + '…' : 'null'}`);
    return token;
  } catch (e) {
    console.log(`[veil-push] FAILED to fetch push token: ${(e as Error).message ?? e}`);
    return null;
  }
}


