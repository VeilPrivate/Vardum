/**
 * @veil/device — privacy dials (NATIVE-PARITY-HANDOFF §0).
 *
 * ONE mode ("VEIL"). No presets, no tiers, no defaults applied on the user's
 * behalf. Every dial is set by the user in the Privacy Checkup; the answers
 * ARE the configuration. The numeric fallbacks below are defensive code only —
 * never surfaced to users, never applied on their behalf.
 *
 * Dial value 0 means Off — a chosen value, never a fallback.
 */

export interface VeilSettings {
  /** Burn after opening — seconds; 0 = Off */
  burnTtlSeconds: number;
  /** Unopened messages expire — seconds; 0 = Off (36 h is the relay's hard cap) */
  expireAfterSeconds: number;
  /** End quiet threads after — hours; 0 = Off */
  retentionHours: number;
  /** Keep conversation history on this device */
  localHistory: boolean;
  /** Key storage: 'device' = sealed-at-rest, 'memory' = Nothing-at-Rest */
  storageMode: 'device' | 'hardware' | 'memory';
  /** Hold until unlock — delivery held while the phone is locked */
  holdUntilUnlock: boolean;
  /** Self-destruct countdown — everything on-device wipes on a fixed 14-day clock */
  selfDestruct: boolean;
  /** epoch ms when the 14-day clock was armed (0 = not armed); never reset by messaging */
  selfDestructArmedAt: number;
  /** Read receipts */
  readReceipts: boolean;
  /** Device-local nickname (never transmitted/synced/server-stored) */
  nickname: string;
  /** checkup completed */
  setupDone: boolean;
  /** (b199) a NEW sign-up has not finished the required onboarding
   *  (intro → checkup → passcode) yet — boot resumes it instead of the app */
  onboardingPending: boolean;
  /** (b139 funnel fix) first REAL relay session opened — the "Secure your VEIL"
   *  prompt waits until after this, never before (onboarding-funnel-fix-spec) */
  firstSessionDone: boolean;
  /** (b139 funnel fix) the local "Getting started" welcome note is hidden */
  welcomeDismissed: boolean;
  /** (b139 attribution) the one-tap "How did you hear about VEIL?" prompt ran */
  attributionDone: boolean;
  /** Redact screenshots & screen recording — while VEIL is open, captures of
   *  the screen come out redacted instead of showing conversations (b61). */
  screenshotShield: boolean;
}

/** Auto-lock is NOT a dial: a fixed 1-minute inactivity rule, always on. */
export const AUTO_LOCK_MINUTES = 1;

/** Self-destruct clock: fixed 14 days, warning 12 h before, extend adds 14 days.
 *  b199 (owner, Oct 16 2026): was 48 h. Already-armed clocks keep their start
 *  time, so they simply run longer. */
export const SELF_DESTRUCT_DAYS = 14;
export const SELF_DESTRUCT_HOURS = SELF_DESTRUCT_DAYS * 24;
export const SELF_DESTRUCT_WARN_HOURS = SELF_DESTRUCT_HOURS - 12;

/** "9 days" while two days or more remain, then "30 hours" / "1 hour". */
export function selfDestructLeftLabel(hoursLeft: number): string {
  if (hoursLeft >= 48) return `${Math.ceil(hoursLeft / 24)} days`;
  const h = Math.max(1, Math.ceil(hoursLeft));
  return `${h} hour${h === 1 ? '' : 's'}`;
}

/** Defensive fallbacks only (never surfaced, never applied on the user's behalf) */
const FALLBACK: VeilSettings = {
  burnTtlSeconds: 7200,       // 2 h
  expireAfterSeconds: 86400,  // 24 h
  retentionHours: 168,        // 7 days
  // b199 (owner decision, Oct 16 2026): history ON by default — conversations
  // survive a restart unless the user turns on "read in the moment". The
  // forensic trade-off is disclosed in the checkup and Settings copy.
  localHistory: true,
  storageMode: 'device',
  holdUntilUnlock: false,
  selfDestruct: false,
  selfDestructArmedAt: 0,
  readReceipts: true,
  nickname: '',
  setupDone: false,
  onboardingPending: false,
  firstSessionDone: false,
  welcomeDismissed: false,
  attributionDone: false,
  screenshotShield: true,
};

/** Exact dial option values (handoff §0 table). 0 = Off. */
export const BURN_OPTIONS = [
  { label: '5 min', value: 300 }, { label: '10 min', value: 600 },
  { label: '30 min', value: 1800 }, { label: '1 hour', value: 3600 },
  { label: '2 hours', value: 7200 }, { label: '6 hours', value: 21600 },
  { label: '12 hours', value: 43200 }, { label: '24 hours', value: 86400 },
  { label: 'Off', value: 0 },
];
export const EXPIRY_OPTIONS = [
  { label: '1 hour', value: 3600 }, { label: '6 hours', value: 21600 },
  { label: '12 hours', value: 43200 }, { label: '24 hours', value: 86400 },
  { label: '36 hours', value: 129600 }, { label: '48 hours', value: 172800 },
  // b198: the 30-day tier — the Founding Tester Forum's backlog lifetime
  // (messages persist 30 days, no burn, then the sweeper purges).
  { label: '30 days', value: 2592000 }, { label: 'Off', value: 0 },
];
export const QUIET_OPTIONS = [ // hours
  { label: '1 hour', value: 1 }, { label: '12 hours', value: 12 }, { label: '24 hours', value: 24 },
  { label: '72 hours', value: 72 }, { label: '7 days', value: 168 },
  { label: '30 days', value: 720 }, { label: 'Off', value: 0 },
];

export type Getter = (k: string) => Promise<string | null>;
export type Setter = (k: string, v: string) => Promise<unknown>;

export class SettingsStore {
  static KEY = 'veil_settings_v1';

  constructor(private get: Getter, private set: Setter) {}

  async load(): Promise<VeilSettings> {
    try {
      const raw = await this.get(SettingsStore.KEY);
      return raw ? this.merge(JSON.parse(raw)) : { ...FALLBACK };
    } catch {
      return { ...FALLBACK };
    }
  }

  async save(s: VeilSettings): Promise<void> {
    await this.set(SettingsStore.KEY, JSON.stringify(s));
  }

  private merge(partial: Partial<VeilSettings>): VeilSettings {
    return mergeSettings(partial);
  }
}

/** merge stored settings over fallbacks, clamping to known option values */
export function mergeSettings(partial: Partial<VeilSettings>): VeilSettings {
    const out = { ...FALLBACK, ...partial };
    if (!BURN_OPTIONS.some((o) => o.value === out.burnTtlSeconds)) out.burnTtlSeconds = FALLBACK.burnTtlSeconds;
    if (!EXPIRY_OPTIONS.some((o) => o.value === out.expireAfterSeconds)) out.expireAfterSeconds = FALLBACK.expireAfterSeconds;
    if (!QUIET_OPTIONS.some((o) => o.value === out.retentionHours)) out.retentionHours = FALLBACK.retentionHours;
    if (out.storageMode !== 'device' && out.storageMode !== 'hardware' && out.storageMode !== 'memory') out.storageMode = 'device';
    // Nothing-at-Rest forces local history off
    if (out.storageMode === 'memory') out.localHistory = false;
    return out;
}


/** Per-envelope TTL (web Kh semantics, 36 h hard cap) — used by the send path. */
export function messageTtlSeconds(
  dials: { defaultTtlSeconds: number; expireAfterSeconds: number; burnAfterOpen: boolean },
  sessionExpiresAtMs?: number,
): number {
  const { defaultTtlSeconds, expireAfterSeconds, burnAfterOpen } = dials;
  if (expireAfterSeconds === 0) {
    if (sessionExpiresAtMs && Number.isFinite(sessionExpiresAtMs)) {
      const remaining = Math.round((sessionExpiresAtMs - Date.now()) / 1000);
      if (remaining > 60) return Math.min(remaining, 129600);
    }
    return 129600;
  }
  const base = burnAfterOpen ? (expireAfterSeconds || 86400) : (defaultTtlSeconds || 86400);
  return Math.min(base, 129600);
}

/** normalize a raw object (tests / migration) */
export function normalizeSettings(raw: Partial<VeilSettings> | null): VeilSettings {
  return mergeSettings(raw ?? {});
}

/** Defensive fallbacks only (compat export — never surfaced to users). */
export const DEFAULT_SETTINGS: VeilSettings = mergeSettings({});
