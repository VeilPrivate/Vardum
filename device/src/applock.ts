/**
 * @veil/device — app lock: passcode + Decoy code + Duress code.
 *
 * WEB PARITY (byte-exact from the live bundle, index-CXHmaNHA.js):
 *   storage key `veil_app_lock` -> {
 *     method: 'passcode',
 *     kdf: 'PBKDF2-SHA256-210000',
 *     salt: hex (16 random bytes),
 *     realHash: hex, decoyHash: hex|null, duressHash: hex|null,
 *     autoLockMinutes
 *   }
 *   hash = PBKDF2-SHA256(code, saltHex->bytes, 210000 iters, 32 bytes) -> hex
 *   rules: duress !== real, decoy !== real, decoy !== duress.
 *
 * Codes NEVER leave the device: PBKDF2 runs on-device, only salted hashes are
 * stored in the secure keystore. ANTI-GOAL ENFORCED: no network imports.
 */

import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';

const ITERATIONS = 210000;
const DK_LEN = 32;
export const APPLOCK_KEY = 'veil_app_lock';
export const KDF_LABEL = `PBKDF2-SHA256-210000`;

export interface AppLockRecord {
  method: 'passcode';
  kdf: string;
  salt: string;
  realHash: string;
  decoyHash: string | null;
  duressHash: string | null;
}

export type CodeKind = 'real' | 'decoy' | 'duress';

/** b123 (owner ask, Sept 25): 5 wrong passcode attempts -> timed keypad
 *  lockout, progressively longer each consecutive lockout: 5 min, then
 *  10, 20, 40, capped at 60. The counter and stage reset on a successful
 *  unlock (real or decoy); a duress wipe clears everything anyway. All
 *  state is device-local — the lockout never leaves the phone. */
export const LOCKOUT_KEY = 'veil_lockout';
export const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = [5, 10, 20, 40, 60];

export interface LockoutState {
  /** wrong attempts since the last lockout or successful unlock (0..MAX) */
  fails: number;
  /** consecutive lockouts without a successful unlock — the escalation stage */
  stage: number;
  /** epoch ms until which the keypad refuses input */
  lockedUntil: number;
  /** Batch D (D-11): wall-clock time the current lockout began (a clock set
   *  back past it restarts the window) */
  lockedAt?: number;
}

export const EMPTY_LOCKOUT: LockoutState = { fails: 0, stage: 0, lockedUntil: 0 };

/** Batch D (D-11, RV-18): thrown by verify() while a lockout runs. */
export class AppLockLockedError extends Error {
  constructor(public lockedUntil: number) {
    super('Too many incorrect attempts. Wait for the timer, then try again.');
    this.name = 'AppLockLockedError';
  }
}

/** Batch D (D-11, RV-18): the lock record exists but can't be read. Callers
 *  treat this as LOCKED — never as "no lock set". */
export class AppLockUnreadableError extends Error {
  constructor() {
    super('The app lock settings on this phone could not be read. Restart Vardum and try again.');
    this.name = 'AppLockUnreadableError';
  }
}

/** Batch I (local review V-02): the phone refused to save the wrong-attempt
 *  counter. verify() fails closed: no password is checked until it can be. */
export class AppLockStorageError extends Error {
  constructor() {
    super('This attempt could not be recorded on this phone. Try again in a moment.');
    this.name = 'AppLockStorageError';
  }
}

/** Batch D (D-11): a lockout also runs on the process's monotonic clock, so
 *  setting the phone's clock forward can't end it early while the app is open. */
const monoLockUntil = new WeakMap<object, number>();
/** Batch I (V-02): wrong attempts this process has seen, whatever the stored
 *  counter says, so a counter that keeps reading empty can't reset the budget. */
const memFails = new WeakMap<object, number>();
const monoNow = (): number => (typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now());

export function lockoutMsForStage(stage: number): number {
  const idx = Math.min(Math.max(stage, 1), LOCKOUT_MINUTES.length) - 1;
  return LOCKOUT_MINUTES[idx] * 60_000;
}

/** human "5 min" / "90 min" label for the lockout banner */
export function lockoutLabelForStage(stage: number): string {
  const idx = Math.min(Math.max(stage, 1), LOCKOUT_MINUTES.length) - 1;
  return `${LOCKOUT_MINUTES[idx]} min`;
}

const enc = new TextEncoder();
const toHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array =>
  new Uint8Array((h.match(/.{2}/g) || []).map((x) => parseInt(x, 16)));

/** web Ex(): PBKDF2-SHA256(code, salt, 210000, 256 bits) -> hex string */
export function hashCode(code: string, saltHex: string): string {
  return toHex(pbkdf2(sha256, enc.encode(code), fromHex(saltHex), { c: ITERATIONS, dkLen: DK_LEN }));
}

/**
 * Native fast path: iOS CommonCrypto PBKDF2 (local Expo module `veil-crypto`).
 * Byte-identical to the web contract, computed in milliseconds by the OS.
 * Resolved lazily through expo-modules-core's NativeModulesProxy so this file
 * stays dependency-free outside the app (monorepo tests fall back to JS).
 */
type NativeVeilCrypto = { pbkdf2Sha256(password: string, saltHex: string, iterations: number, dkLen: number): Promise<string> };

let probeOnce = false;
export function getNativeCrypto(): NativeVeilCrypto | null {
  try {
    // BUG FIXED (Sept 19): this used to read NativeModulesProxy.VeilCrypto,
    // which is the legacy unimodules bridge. Our veil-crypto module is a
    // modern Expo module (Module + ModuleDefinition, Swift side) and is
    // exposed via requireNativeModule(), same as modules/veil-crypto/index.ts
    // already did correctly. The proxy lookup silently returned undefined —
    // no error, no fallback log — so every unlock ran the 210k-iteration JS
    // path even after the native module was compiled into the binary.
    //
    // B47 INSTRUMENTATION: the b46-full tree was confirmed extracted and
    // Metro reloaded, yet unlock STILL took ~80s. So we now log loudly and
    // exactly once per app load which of the three failure modes it is:
    //   A. 'VeilCrypto native module FOUND'  -> native path; unlock is fast.
    //   B. 'requireNativeModule threw: ...'  -> the installed BINARY has no
    //      VeilCrypto Swift module compiled in (stale/incomplete EAS build).
    //   C. no [veil-lock][probe] line at all -> this file never ran, i.e.
    //      the phone is still on the old bundle (extraction/Metro issue).
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireNativeModule?: <T>(name: string) => T };
    if (typeof emc?.requireNativeModule !== 'function') {
      if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] expo-modules-core resolved but has no requireNativeModule export'); }
      return null;
    }
    const mod = emc.requireNativeModule<NativeVeilCrypto>('VeilCrypto');
    if (typeof mod?.pbkdf2Sha256 !== 'function') {
      if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] VeilCrypto resolved but pbkdf2Sha256 missing:', typeof mod); }
      return null;
    }
    if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] VeilCrypto native module FOUND'); }
    return mod;
  } catch (e) {
    if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] requireNativeModule threw:', String((e as Error)?.message || e)); }
    return null; // tests / no native module compiled in yet -> JS fallback
  }
}

/**
 * Identical digest to hashCode, but chunked: REAL setTimeout yields every 2000
 * iterations return the RN JS thread to the event loop, so touch events, timers
 * and the bridge keep flowing while the 210k-iteration hash runs.
 * (noble's pbkdf2Async was NOT a fix: it yields via an already-resolved promise
 * — a microtask — which RN never returns to the event loop with, so the UI
 * stayed frozen for the whole computation.)
 */
export async function hashCodeAsync(code: string, saltHex: string): Promise<string> {
  const native = getNativeCrypto();
  if (!native) console.log('[veil-lock] NO native path available — running 210k-iteration JS path (expect ~80s on device)');
  if (native) {
    const tN = Date.now();
    try {
      const h = await native.pbkdf2Sha256(code, saltHex, ITERATIONS, DK_LEN);
      console.log(`[veil-lock] pbkdf2 done NATIVE in ${Date.now() - tN} ms`);
      return h;
    } catch (e) {
      console.log('[veil-lock] native pbkdf2 failed, falling back to JS chunked:', String(e));
    }
  }
  const t0 = Date.now();
  const pw = enc.encode(code);
  const salt = fromHex(saltHex);

  // HMAC-SHA256 key preparation (RFC 2104): pad/hash key to the 64-byte block
  const key = pw.length > 64 ? sha256(pw) : pw;
  const kb = new Uint8Array(64);
  kb.set(key);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ipad[i] = kb[i] ^ 0x36; opad[i] = kb[i] ^ 0x5c; }
  const ipadH = sha256.create().update(ipad);
  const opadH = sha256.create().update(opad);

  // U1 = HMAC(pw, salt || INT_32_BE(1)); DK = T1 = U1 ^ U2 ^ ... ^ Uc  (dkLen = 32 -> single block)
  const s1 = new Uint8Array(salt.length + 4);
  s1.set(salt);
  s1[salt.length + 3] = 1;
  let u = opadH.clone().update(ipadH.clone().update(s1).digest()).digest();
  const t = new Uint8Array(DK_LEN);
  t.set(u);

  let sinceYield = 0;
  for (let i = 1; i < ITERATIONS; i++) {
    u = opadH.clone().update(ipadH.clone().update(u).digest()).digest();
    for (let j = 0; j < DK_LEN; j++) t[j] ^= u[j];
    if (++sinceYield >= 2000) {
      sinceYield = 0;
      await new Promise<void>((r) => setTimeout(r, 0)); // true event-loop yield
      if (i % 42000 === 0) console.log(`[veil-lock] pbkdf2 ${Math.round((i / ITERATIONS) * 100)}%`);
    }
  }
  console.log(`[veil-lock] pbkdf2 done in ${Date.now() - t0} ms`);
  return toHex(t);
}

/** web Dx(): fresh 16-byte random salt as hex */
export function freshSalt(): string {
  const b = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    // audit fix (Sept 19): a predictable salt silently weakens the KDF —
    // fail loudly instead of falling back to Math.random.
    throw new Error('Secure random unavailable — cannot create a lock-code salt.');
  }
  globalThis.crypto.getRandomValues(b);
  return toHex(b);
}

export class AppLockStore {
  constructor(private storage: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown>; remove(k: string): Promise<unknown> }) {}

  /** Batch D (D-11, RV-18): null ONLY when no lock is set. A read or parse
   *  failure throws AppLockUnreadableError (fail closed). */
  async load(): Promise<AppLockRecord | null> {
    let raw: string | null;
    try { raw = await this.storage.get(APPLOCK_KEY); } catch { throw new AppLockUnreadableError(); }
    if (raw === null || raw === undefined || raw === '') return null;
    try {
      const rec = JSON.parse(raw) as AppLockRecord;
      if (!rec || typeof rec !== 'object' || typeof rec.salt !== 'string' || typeof rec.realHash !== 'string') throw new Error('shape');
      return rec;
    } catch {
      throw new AppLockUnreadableError();
    }
  }

  /** web Ve(): save codes with the three differ-rules; throws with web copy on violation */
  async save(passcode: string, decoy?: string | null, duress?: string | null): Promise<AppLockRecord> {
    if (duress && duress === passcode) throw new Error('The duress code must differ from the real passcode');
    if (decoy && decoy === passcode) throw new Error('The decoy code must differ from the real passcode');
    if (decoy && duress && decoy === duress) throw new Error('The decoy and duress codes must differ');
    const salt = freshSalt();
    const rec: AppLockRecord = {
      method: 'passcode',
      kdf: KDF_LABEL,
      salt,
      realHash: await hashCodeAsync(passcode, salt),
      decoyHash: decoy ? await hashCodeAsync(decoy, salt) : null,
      duressHash: duress ? await hashCodeAsync(duress, salt) : null,
    };
    // Batch I (V-02): a refused write is reported, never shown as success
    if ((await this.storage.set(APPLOCK_KEY, JSON.stringify(rec))) === false) {
      throw new Error('The app lock could not be saved on this phone. Try again.');
    }
    return rec;
  }

  /**
   * web Ox(): classify an entered code.
   * Batch D (D-11, RV-18/RV-20): verify enforces the lockout itself (every caller
   * — lock screen, notes gate, removing the lock — gets it), and counts the
   * attempt as wrong BEFORE hashing, so killing the app mid-hash still costs an
   * attempt. The real code resets the budget; decoy and duress codes neither
   * count as wrong nor reset it (V-23). Nothing about the hash is logged.
   */
  async verify(code: string): Promise<CodeKind | null> {
    const before = await this.lockout();
    if (before.lockedUntil > Date.now()) throw new AppLockLockedError(before.lockedUntil);
    const rec = await this.load();
    if (!rec) return null;
    // Batch I (V-02): the process's own count also gates, in case the stored
    // counter keeps reading empty
    const seen = memFails.get(this.storage) ?? 0;
    if (seen >= MAX_ATTEMPTS) {
      const until = Date.now() + lockoutMsForStage(Math.max(before.stage, 1));
      monoLockUntil.set(this.storage, monoNow() + lockoutMsForStage(Math.max(before.stage, 1)));
      memFails.set(this.storage, 0);
      throw new AppLockLockedError(until);
    }
    // Batch I (V-02): the attempt is reserved BEFORE hashing, and a refused
    // reservation throws (AppLockStorageError): no password is checked
    let after: LockoutState | null = null;
    try {
      after = await this.recordFail();
    } catch (e) {
      // b63 review (I3-2): the counter can't be saved, so no password is
      // checked, but the duress code still is. Matching it only erases this
      // phone, so the in-memory budget is enough of a limit here.
      if (!(e instanceof AppLockStorageError) || !rec.duressHash) throw e;
      memFails.set(this.storage, seen + 1);
      if ((await hashCodeAsync(code, rec.salt)) === rec.duressHash) {
        memFails.set(this.storage, seen);
        return 'duress';
      }
      throw e;
    }
    // b63 review (I3-3): once the stored lockout arms, it governs; the
    // in-memory count starts again so it can't add a second window
    memFails.set(this.storage, after.lockedUntil > Date.now() ? 0 : seen + 1);
    const t1 = Date.now();
    const h = await hashCodeAsync(code, rec.salt);
    console.log(`[veil-lock] verify: hashed in ${Date.now() - t1} ms`);
    let kind: CodeKind | null = null;
    if (h === rec.realHash) kind = 'real';
    else if (rec.decoyHash && h === rec.decoyHash) kind = 'decoy';
    else if (rec.duressHash && h === rec.duressHash) kind = 'duress';
    if (kind === 'real') {
      await this.clearLockout();
    } else if (kind) {
      monoLockUntil.delete(this.storage);
      memFails.set(this.storage, seen); // decoy and duress are not wrong attempts
      await this.saveLockout(before).catch(() => undefined); // restoring is best-effort
    }
    return kind;
  }

  async clear(): Promise<void> {
    await this.storage.remove(APPLOCK_KEY);
  }

  // ---------- b123: progressive passcode-attempt lockout (device-local) ----------

  /**
   * Batch C (V-23; review P2): fail CLOSED. An unreadable or damaged lockout
   * record used to read as "no failures" — a reset an attacker could provoke.
   * Now it counts as a lockout window (the first stage), persisted when the
   * record was damaged so a restart doesn't skip it.
   */
  async lockout(): Promise<LockoutState> {
    let raw: string | null;
    try {
      raw = await this.storage.get(LOCKOUT_KEY);
    } catch {
      return { fails: 0, stage: 1, lockedUntil: Date.now() + lockoutMsForStage(1) };
    }
    if (!raw) {
      // b63 review (I3-4): an empty counter doesn't end a lockout this process is enforcing
      const mono = monoLockUntil.get(this.storage);
      const left = mono === undefined ? 0 : mono - monoNow();
      if (left > 0) return { fails: 0, stage: 1, lockedUntil: Date.now() + left };
      monoLockUntil.delete(this.storage);
      return { ...EMPTY_LOCKOUT };
    }
    try {
      const st = JSON.parse(raw) as LockoutState;
      const fails = Number(st.fails), stage = Number(st.stage);
      let lockedUntil = Number(st.lockedUntil);
      let lockedAt = st.lockedAt === undefined ? undefined : Number(st.lockedAt);
      if (![fails, stage, lockedUntil, lockedAt ?? 0].every((x) => Number.isFinite(x) && x >= 0)) throw new Error('shape');
      // Batch D (D-11): a clock set back past the lockout's start restarts the window
      if (lockedAt !== undefined && Date.now() < lockedAt) {
        lockedAt = Date.now();
        lockedUntil = lockedAt + lockoutMsForStage(stage);
        await this.saveLockout({ fails, stage, lockedUntil, lockedAt }).catch(() => undefined);
      }
      // Batch D (D-11): while the app runs, the monotonic clock decides too
      const mono = monoLockUntil.get(this.storage);
      if (mono !== undefined) {
        const left = mono - monoNow();
        // only when the wall clock says the window is over (a clock set forward)
        if (left > 0 && lockedUntil <= Date.now()) lockedUntil = Date.now() + left;
        else monoLockUntil.delete(this.storage);
      }
      return { fails, stage, lockedUntil, ...(lockedAt !== undefined ? { lockedAt } : {}) };
    } catch {
      const locked = { fails: 0, stage: 1, lockedUntil: Date.now() + lockoutMsForStage(1) };
      await this.saveLockout(locked).catch(() => undefined);
      return locked;
    }
  }

  private async saveLockout(st: LockoutState): Promise<void> {
    // Batch I (V-02): KeychainStorage.set reports a refused write as false
    if ((await this.storage.set(LOCKOUT_KEY, JSON.stringify(st))) === false) throw new AppLockStorageError();
  }

  /** one wrong attempt. At MAX_ATTEMPTS the keypad locks: stage escalates
   *  (5 -> 10 -> 20 -> 40 -> 60 min) and the attempt counter resets so the
   *  next window again allows MAX_ATTEMPTS tries. */
  async recordFail(): Promise<LockoutState> {
    const st = await this.lockout();
    const fails = st.fails + 1;
    if (fails < MAX_ATTEMPTS) {
      const next = { fails, stage: st.stage, lockedUntil: st.lockedUntil };
      await this.saveLockout(next);
      return next;
    }
    const stage = st.stage + 1;
    const ms = lockoutMsForStage(stage);
    const next = { fails: 0, stage, lockedUntil: Date.now() + ms, lockedAt: Date.now() };
    monoLockUntil.set(this.storage, monoNow() + ms);
    await this.saveLockout(next);
    return next;
  }

  /** successful unlock — counter and escalation reset to zero */
  async clearLockout(): Promise<void> {
    monoLockUntil.delete(this.storage);
    memFails.delete(this.storage);
    await this.storage.remove(LOCKOUT_KEY);
  }
}
