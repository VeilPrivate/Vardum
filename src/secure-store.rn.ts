/**
 * Expo shell — platform SecureStore over react-native-keychain.
 * Keychain items: service = "veil.<key>", account = "veil", value = the secret.
 * accessible WHEN_UNLOCKED_THIS_DEVICE_ONLY (matches web "locked until first
 * unlock" semantics). Errors are rethrown with a diagnostic hint so a failed
 * native link shows up as readable text on the ErrorBoundary screen instead
 * of a silent launch crash.
 *
 * "Locked in your phone's security chip" storage mode (Settings > Key
 * storage, web parity Sept 19): when active, the identity keyvault entry
 * (veil_keyvault_identity — the single highest-value secret; everything
 * else derives from it) is additionally written with a biometric
 * accessControl + secure-hardware securityLevel, so the OS itself demands
 * Face ID / Touch ID / device passcode before that one item can be read —
 * on top of, not instead of, the existing WHEN_UNLOCKED_THIS_DEVICE_ONLY
 * protection every key already has. Session and group keys (the veil_rk_ and
 * veil_gk_ prefixed entries)
 * are read too frequently during normal chat to gate the same way without
 * prompting on every message, so the gate is scoped to the identity keyvault
 * only — a deliberate, honest scoping decision, not the full-store gate the
 * web copy's wording alone might suggest.
 */
import * as Keychain from 'react-native-keychain';
import { Platform } from 'react-native';
import type { SecureStore } from '../vendor/device/src/index';
import { AUTH_SESSION_KEY } from '../vendor/device/src/auth';

/**
 * b81 (owner report: "no notifications, locked or unlocked" — confirmed
 * directly from a device Metro log: "Keychain get('veil_auth_session')
 * failed — original: User interaction is not allowed"). EVERY key,
 * including the app-login session token, was stored WHEN_UNLOCKED_THIS_
 * DEVICE_ONLY — the strictest tier, which refuses the read unless the
 * screen is unlocked at the EXACT moment of access. That's correct and
 * wanted for actual crypto material (identity keyvault, ratchet/session
 * keys) — it's wrong for the login token, because it means literally every
 * background sync attempt (push-woken or timer-woken) fails before it ever
 * reaches the join/decrypt logic, the instant the phone is locked. This is
 * the standard tradeoff every secure messenger makes: the login session
 * uses the looser AFTER_FIRST_UNLOCK tier (readable in the background once
 * the device has been unlocked at least once since boot — true almost
 * always in practice) so delivery can keep working while locked, while
 * every actual Veil crypto key keeps the strict WHEN_UNLOCKED tier
 * unchanged. Losing this token to a live, already-unlocked-since-boot
 * seizure only exposes the account login — never message content or key
 * material, which stay independently gated exactly as before.
 */
const AUTH_TOKEN_ACCESSIBLE = Keychain.ACCESSIBLE.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY;

/**
 * b62 Secure Enclave seal: in hardware mode the keyvault master key never
 * rests in the keychain in readable form. set() wraps it with an AES-GCM key
 * derived from an ECDH agreement against a non-extractable Secure Enclave
 * P-256 key (biometry-gated); get() unwraps it — Face ID prompts at the
 * Secure Enclave key-use itself. Old raw entries (pre-b62 hardware mode or
 * standard mode) pass through untouched, so existing installs keep working
 * and re-seal on the next save.
 */
const SE_WRAP_PREFIX = '{"__veil_se":1';

interface NativeSeModule {
  seIsAvailable?: () => boolean;
  seWrapKey?: (masterKeyB64: string) => Promise<{ eph: string; salt: string; ct: string }>;
  seUnwrapKey?: (ephB64: string, saltB64: string, ctB64: string) => Promise<string>;
  seResetKey?: () => Promise<boolean>;
}

function nativeSe(): NativeSeModule | null {
  try {
    const emc = require('expo-modules-core') as {
      requireNativeModule?: <T = unknown>(name: string) => T;
    };
    if (typeof emc?.requireNativeModule !== 'function') return null;
    return emc.requireNativeModule<NativeSeModule>('VeilCrypto');
  } catch { return null; }
}

/**
 * b100 FIX (owner hardware finding, Sept 21): every hardware-mode flip threw
 * "Secure Enclave did not accept the seal" — Metro showed the real cause:
 * "[veil-se] wrap failed, falling back to gated keychain: Error: seWrapKey:
 * master key is not valid base64". The native Swift seWrapKey expects its
 * one argument to be base64 (it calls Data(base64Encoded:) on it), but the
 * value actually passed here is IdentityVault.save()'s
 * JSON.stringify(identity) — a JSON object string, never base64. So the SE
 * seal has never once succeeded since it was introduced (b62): every past
 * "hardware" flip silently fell back to the legacy BIOMETRY_CURRENT_SET
 * keychain path below (still correct/secure, just not SE-sealed) with only
 * a console.log — invisible until b96 added keyvaultEntrySealed() to PROVE
 * the seal at flip time, which correctly started detecting "plain" every
 * time and (rightly) began surfacing the failure as a reverted toggle.
 * Fix: base64-encode the JSON payload here (btoa — the whole string is
 * ASCII: base64 sub-fields, an ISO date, a hex veilId) so the native side's
 * base64 decode succeeds; reverse it in seUnwrap. No stored data migrates —
 * no entry was ever actually SE-sealed, so every device today still has the
 * plain legacy-gated JSON and will seal correctly on the next save.
 */
async function seWrap(value: string): Promise<string> {
  const mod = nativeSe();
  if (!mod?.seWrapKey || !mod.seIsAvailable?.()) throw new Error('Secure Enclave unavailable');
  const blob = await mod.seWrapKey(btoa(value));
  return `{"__veil_se":1,"eph":"${blob.eph}","salt":"${blob.salt}","ct":"${blob.ct}"}`;
}

async function seUnwrap(stored: string): Promise<string> {
  const mod = nativeSe();
  if (!mod?.seUnwrapKey) throw new Error('Secure Enclave unavailable');
  const blob = JSON.parse(stored) as { eph: string; salt: string; ct: string };
  const decoded = await mod.seUnwrapKey(blob.eph, blob.salt, blob.ct);
  return atob(decoded);
}

function isSeWrapped(v: string): boolean {
  return typeof v === 'string' && v.startsWith(SE_WRAP_PREFIX);
}

/** must match vendor/device/src/keyvault.ts KEYVAULT_KEY */
const HARDWARE_GATED_KEY = 'veil_keyvault_identity';

function diag(op: string, key: string, e: unknown): never {
  const msg = String((e as Error)?.message || e);
  throw new Error(
    `Keychain ${op}('${key}') failed — ` +
    (msg.includes('null') || msg.includes('undefined')
      ? `react-native-keychain native module did not link into this build. `
      : ``) +
    `original: ${msg}`
  );
}

export interface RnSecureStoreOptions {
  /** true while Settings > Key storage is set to "Locked in your phone's security chip" */
  isHardwareGated?: () => boolean;
}

/**
 * Android read cache. Every react-native-keychain item on Android is its own
 * Keystore key, and every read is a hardware AES op (on the Pixel 8 Pro the
 * old keys sit in the Titan M2 StrongBox: 100-300 ms each, all on one native
 * queue). The background loops re-read the same items every few seconds, so
 * a chat tap waited behind seconds of queued reads (device log Oct 20).
 * iOS reads are already fast, so iOS keeps the direct path.
 * The values are the same ones the app holds decrypted in memory anyway; the
 * hardware-gated identity entry is never cached (its OS prompt must stay).
 */
const CACHE_ON = Platform.OS === 'android';
const cache = new Map<string, string | null>();
const inflight = new Map<string, Promise<string | null>>();
const version = new Map<string, number>();
function bump(key: string): void { version.set(key, (version.get(key) ?? 0) + 1); inflight.delete(key); }

/** Android: an entry whose ciphertext the Keystore can no longer open (old
 *  StrongBox keys fail large finishes with IllegalBlockSizeException). It will
 *  never decrypt, so it reads as missing instead of throwing on every poll and
 *  blocking the chat open; the next write replaces it with a TEE-keyed copy. */
function isUnreadableEntry(e: unknown): boolean {
  return Platform.OS === 'android' && /Could not decrypt data with alias/.test(String((e as Error)?.message ?? e));
}
const unreadableLogged = new Set<string>();

export function createRnSecureStore(opts: RnSecureStoreOptions = {}): SecureStore {
  const direct = createDirectStore(opts);
  if (!CACHE_ON) return direct;
  return {
    async get(key) {
      if (key === HARDWARE_GATED_KEY) return direct.get(key);
      if (cache.has(key)) return cache.get(key) ?? null;
      const pending = inflight.get(key);
      if (pending) return pending;
      const v0 = version.get(key) ?? 0;
      const p = (async () => {
        let value: string | null;
        try {
          value = await direct.get(key);
        } catch (e) {
          if (!isUnreadableEntry(e)) throw e;
          if (!unreadableLogged.has(key)) {
            unreadableLogged.add(key);
            console.log(`[veil-secure] unreadable entry treated as missing: ${key}`);
          }
          value = null;
        }
        if ((version.get(key) ?? 0) === v0) cache.set(key, value);
        return value;
      })();
      inflight.set(key, p);
      try { return await p; } finally { if (inflight.get(key) === p) inflight.delete(key); }
    },
    async set(key, value) {
      bump(key);
      cache.delete(key);
      try { await direct.set(key, value); } finally { bump(key); } // a read that raced the write must not cache the old value
      if (key !== HARDWARE_GATED_KEY) cache.set(key, value);
    },
    async delete(key) {
      bump(key);
      cache.delete(key);
      try { await direct.delete(key); } finally { bump(key); }
      cache.set(key, null);
    },
  };
}

function createDirectStore(opts: RnSecureStoreOptions): SecureStore {
  return {
    async get(key) {
      try {
        // b97: an ACL-gated read with NO explicit authenticationPrompt can
        // silently fail (errSecAuthFailed / "-25293", surfaced by iOS as the
        // nonsensical "user name or passphrase you entered is not correct")
        // instead of showing Face ID/passcode UI, once any recent-unlock
        // grace window has lapsed — this is why a boot-time read can succeed
        // silently (fresh device unlock) while the SAME read moments later,
        // from deep in Settings, fails outright. Passing an explicit prompt
        // for the one gated key makes the OS reliably show the biometric UI
        // instead of guessing.
        const getOpts = key === HARDWARE_GATED_KEY
          ? { service: `veil.${key}`, authenticationPrompt: { title: 'Unlock Vardum', subtitle: 'Confirm to access your identity keys' } }
          : { service: `veil.${key}` };
        const rc = await Keychain.getGenericPassword(getOpts);
        if (!rc) return null;
        const stored = (rc as { password: string }).password;
        // b62: hardware-mode sealed entries unwrap via the Secure Enclave
        if (isSeWrapped(stored)) return await seUnwrap(stored);
        return stored;
      } catch (e) { diag('get', key, e); }
    },
    async set(key, value) {
      const gated = key === HARDWARE_GATED_KEY && !!opts.isHardwareGated?.();
      // b62: hardware mode with a Secure Enclave seals the master key; the
      // keychain then holds only the (useless-off-device) sealed blob. Without
      // a Secure Enclave the legacy biometric-gated entry path below applies.
      if (gated && secureEnclaveAvailable()) {
        try {
          const sealed = await seWrap(value);
          const seSet = { service: `veil.${key}`, accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY } as const;
          try {
            await Keychain.setGenericPassword('veil', sealed, seSet);
            return;
          } catch {
            // same b60 class of iOS bug: an existing GATED entry (pre-b62
            // hardware mode) can't be attribute-updated in place — delete and
            // rewrite fresh once.
            await Keychain.resetGenericPassword({ service: `veil.${key}` });
            await Keychain.setGenericPassword('veil', sealed, seSet);
            return;
          }
        } catch (e) {
          console.log('[veil-se] wrap failed, falling back to gated keychain:', String(e));
          // fall through to the legacy path — a failed seal must not lose the key
        }
      }
      const opts_: Parameters<typeof Keychain.setGenericPassword>[2] = {
        service: `veil.${key}`,
        accessible: key === AUTH_SESSION_KEY ? AUTH_TOKEN_ACCESSIBLE : Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        ...(gated ? {
          accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
          securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
        } : {}),
      };
      try {
        await Keychain.setGenericPassword('veil', value, opts_);
      } catch (e) {
        // AUDIT FIX (Sept 19): iOS Keychain cannot change an existing item's
        // accessControl in place (SecItemUpdate ignores it) — flipping Key
        // storage to/from "Locked in your phone's security chip" re-writes
        // the SAME service with different attributes, which iOS rejects with
        // "the user name or passphrase you entered is not correct" (-25293),
        // even though the passphrase never changed. The record then goes
        // half-written, and every LATER read of it fails the same way.
        // Fix: on any set() failure, delete the stale item and retry once
        // fresh — this is the only way to change accessControl on iOS.
        try {
          await Keychain.resetGenericPassword({ service: `veil.${key}` });
          await Keychain.setGenericPassword('veil', value, opts_);
        } catch (e2) {
          diag('set', key, e2);
        }
      // b196-r7 (owner repro Oct 12, delete+reinstall+24-word restore:
      // "The forum posting session is not ready — try joining again"):
      // setGenericPassword can RESOLVE successfully while the item never
      // lands — a fresh-install keychain flake. The session join then saves,
      // reads back three lines later, finds nothing, and the join dies. A
      // keychain write that claims success must VERIFY: read the item back,
      // and if it is missing, delete + rewrite once. Still missing -> honest
      // readable failure (surfaced by KeychainStorage as a logged set-false)
      // instead of a downstream "not ready" mystery. Gated (SE / biometric)
      // keys are exempt: reading those back would prompt the user.
      if (!gated) {
        const rb = await Keychain.getGenericPassword({ service: `veil.${key}` });
        const rbVal = (rb && typeof rb === 'object' ? (rb as { password?: string }).password : undefined);
        if (rbVal !== value) {
          console.error('[veil-secure] write did not persist (read-back mismatch) — retrying once:', key);
          try {
            await Keychain.resetGenericPassword({ service: `veil.${key}` });
            await Keychain.setGenericPassword('veil', value, opts_);
          } catch (e3) {
            diag('set', key, e3);
          }
          const rb2 = await Keychain.getGenericPassword({ service: `veil.${key}` });
          if ((rb2 && typeof rb2 === 'object' ? (rb2 as { password?: string }).password : undefined) !== value) {
            diag('set', key, new Error('keychain write did not persist (verified read-back)'));
          }
        }
      }
      }
    },
    async delete(key) {
      try {
        await Keychain.resetGenericPassword({ service: `veil.${key}` });
      } catch (e) { diag('delete', key, e); }
    },
  };
}

/**
 * b96: peek the keyvault entry's RAW stored value WITHOUT unwrapping — lets
 * the app tell whether the Secure Enclave seal is actually in place (a failed
 * seal used to look exactly like a successful one; owner hardware finding:
 * "none of the modes asks me for biometrics"). Prompt-free on the SE path —
 * the record holding the sealed blob is an ordinary keychain item; the gate
 * lives at the SE key-use inside seUnwrap(). On the LEGACY gated-entry path
 * (no Secure Enclave) this read prompts exactly like any gated read.
 */
export async function keyvaultEntrySealed(): Promise<'sealed' | 'plain' | 'missing'> {
  try {
    const rc = await Keychain.getGenericPassword({ service: `veil.${HARDWARE_GATED_KEY}` });
    if (!rc) return 'missing';
    const stored = (rc as { password: string }).password;
    return isSeWrapped(stored) ? 'sealed' : 'plain';
  } catch { return 'missing'; }
}

/** b62: is the Secure Enclave path usable on this device? (true hardware mode
 *  requires it; otherwise hardware mode falls back to the biometric-gated
 *  keychain entry, which is what pre-b62 builds shipped). */
export function secureEnclaveAvailable(): boolean {
  try {
    return !!nativeSe()?.seIsAvailable?.();
  } catch { return false; }
}

/**
 * b102 FIX (owner hardware finding, Sept 21: "selecting locked in your
 * phone's security chip does not engage Face ID or anything else" — on b101,
 * with the seal verified 'sealed' and the flip clean): the Secure Enclave key
 * persisted on this device was created back when seAccessControl() carried no
 * biometry constraint, and loadOrCreateSeKey() reuses any existing key
 * forever — so the seal succeeds and unwrap runs WITHOUT ever prompting.
 * Every biometric gate since b62 has been decorative on devices from that
 * era. This deletes the legacy key and recreates it with TODAY's
 * biometryCurrentSet ACL. ONLY call it when the keyvault identity is in
 * memory and is re-sealed immediately after — the previous sealed blob
 * becomes unreadable the moment the old key dies.
 */
export async function resetSecureEnclaveKey(): Promise<boolean> {
  const mod = nativeSe();
  if (!mod?.seResetKey || !mod?.seIsAvailable?.()) return false;
  // Batch E (round-3 review R1-02): a failed reset is an error, not "no hardware".
  // The callers' try blocks then stop the mode flip / re-seal instead of sealing
  // under the old (ungated) key and reporting hardware mode.
  let ok = false;
  try { ok = !!(await mod.seResetKey()); } catch (e) { throw new Error(`Secure Enclave key reset failed: ${String((e as Error)?.message ?? e)}`); }
  if (!ok) throw new Error('Secure Enclave key reset failed');
  return true;
}
