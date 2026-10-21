/**
 * Google-free push for Android (GrapheneOS) via UnifiedPush.
 *
 * Native side: modules/vardum-unifiedpush. Loaded OPTIONALLY, so iOS and any
 * build without the module behave exactly as before (Expo push).
 *
 * The phone needs a UnifiedPush distributor app installed — ntfy (F-Droid,
 * io.heckel.ntfy). With one present, Android uses this path; without one it
 * falls back to Expo/FCM, which only works where Google Play Services exist.
 */
import { Platform } from 'react-native';

export type UpEndpoint = { url: string; pubKey: string; auth: string };

type NativeUp = {
  getDistributors(): string[];
  getSavedDistributor(): string | null;
  getAckDistributor(): string | null;
  saveDistributor(pkg: string): void;
  register(vapid: string | null): void;
  unregister(): void;
  getEndpoint(): UpEndpoint | null;
  getLastError(): string | null;
};

/** ntfy is the recommended distributor (self-hostable — Vardum's own server later). */
export const NTFY_PACKAGE = 'io.heckel.ntfy';

/** Relay token prefix: lets the relay tell a UnifiedPush row from an Expo token. */
export const UP_TOKEN_PREFIX = 'up:';

let native: NativeUp | null | undefined;

function getNative(): NativeUp | null {
  if (native !== undefined) return native;
  native = null;
  if (Platform.OS !== 'android') return native;
  try {
    // same optional-load pattern as noble-subtle.ts / kdf.ts
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireOptionalNativeModule?: <T>(name: string) => T | null };
    native = typeof emc?.requireOptionalNativeModule === 'function'
      ? emc.requireOptionalNativeModule<NativeUp>('VardumUnifiedPush')
      : null;
  } catch {
    native = null;
  }
  return native;
}

function distributors(): string[] {
  const n = getNative();
  if (!n) return [];
  try { return n.getDistributors() ?? []; } catch { return []; }
}

/** True when this phone can do Google-free push: module present AND a distributor installed. */
export function isUnifiedPushAvailable(): boolean {
  return distributors().length > 0;
}

/** Saved distributor if still installed, else ntfy, else the first one found. */
function pickDistributor(n: NativeUp): string | null {
  const all = distributors();
  if (all.length === 0) return null;
  let saved: string | null = null;
  try { saved = n.getSavedDistributor(); } catch { saved = null; }
  const pick = saved && all.includes(saved) ? saved : (all.includes(NTFY_PACKAGE) ? NTFY_PACKAGE : all[0]);
  if (pick !== saved) {
    try { n.saveDistributor(pick); } catch { return null; }
  }
  return pick;
}

/** The endpoint already stored on this device (no network, no registration). */
export function storedEndpoint(): UpEndpoint | null {
  const n = getNative();
  if (!n) return null;
  try {
    const ep = n.getEndpoint();
    return ep && ep.url ? ep : null;
  } catch { return null; }
}

/**
 * Register with the distributor and wait for its endpoint.
 * Re-registering is safe: the distributor answers with the same endpoint.
 */
export async function ensureEndpoint(timeoutMs = 12_000): Promise<UpEndpoint | null> {
  const n = getNative();
  if (!n) return null;
  const pkg = pickDistributor(n);
  if (!pkg) return null;
  const before = storedEndpoint();
  try {
    n.register(null);
  } catch (e) {
    console.log(`[veil-push] UnifiedPush register FAILED: ${(e as Error).message ?? e}`);
    return before;
  }
  if (before) return before;
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 300));
    const ep = storedEndpoint();
    if (ep) return ep;
  }
  let err: string | null = null;
  try { err = n.getLastError(); } catch { err = null; }
  console.log(`[veil-push] UnifiedPush: no endpoint from ${pkg} after ${timeoutMs}ms${err ? ` (${err})` : ''}`);
  return null;
}

/** Drop this device's registration with the distributor (wipe / Nothing-at-Rest). */
export function unregisterUnifiedPush(): void {
  const n = getNative();
  if (!n) return;
  try { n.unregister(); } catch { /* best-effort */ }
}

export function upTokenFor(ep: UpEndpoint): string {
  return UP_TOKEN_PREFIX + ep.url;
}
