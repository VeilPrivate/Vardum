/**
 * Hermes runtime polyfills — MUST be imported before any app module (see index.ts).
 *
 * React Native's Hermes engine lacks several web globals that the VEIL crypto
 * core (ported 1:1 from the web bundle) relies on — some at module scope:
 *   - TextEncoder / TextDecoder  -> fast-text-encoding (pure JS, exact UTF-8)
 *   - crypto.getRandomValues     -> react-native-get-random-values (native SecRandom)
 *   - crypto.subtle              -> src/noble-subtle (pure JS, @noble) — same
 *                                   subset API as WebCrypto, byte-exact outputs
 *                                   (verified against real WebCrypto + NIST
 *                                   vectors, scripts/noble-crosscheck.ts). No
 *                                   WebView, no async bridge, no loading race.
 *   - btoa / atob                -> pure-JS fallbacks below (bytes.ts prefers
 *                                   them when present, so it never hits its
 *                                   Node-only Buffer path)
 */
import 'fast-text-encoding';
import 'react-native-get-random-values';
import { installNobleSubtle } from './noble-subtle';
// pure-JS crypto.subtle (@noble) — replaces the old hidden-WebView bridge that
// hung/failed on device (build 12: both identity flows dead at first crypto op).
installNobleSubtle();

// ---------------------------------------------------------------------------
// LAST-RESORT FATAL-ERROR INTERCEPTOR (diagnostic, added Sept 18).
// Build 13 crashed at the identity-create tap with a NATIVE abort (SIGABRT via
// RN ExceptionsManager) even though every JS path there is inside try/catch —
// i.e. an uncaught JS exception was reported as fatal with no on-screen text.
// RN routes ALL uncaught JS exceptions through ErrorUtils' global handler
// (Libraries/Core/setUpErrorHandling.js). Replacing that handler here means
// we see the exact message + stack in an Alert and the app SURVIVES, instead
// of a blind native crash loop.
const g = globalThis as unknown as Record<string, unknown>;
type ErrorUtilsShape = { setGlobalHandler?: (h: (e: unknown, isFatal?: boolean) => void) => void };
const eu = g.ErrorUtils as ErrorUtilsShape | undefined;
if (eu && typeof eu.setGlobalHandler === 'function') {
  eu.setGlobalHandler((e: unknown, _isFatal?: boolean) => {
    const err = e as Error;
    const msg = String((err && err.message) || e);
    const stack = String((err && err.stack) || '(no stack)');
    g.__VEIL_LAST_FATAL__ = msg + '\n\n' + stack; // same-session retrieval
    // b139 quality gate: persist a crash marker (service 'veil.veil_sess_crash',
    // the exact convention secure-store.rn uses for the keychain store) so the
    // next cold start can emit a session_crashed event for the crash-free
    // percentage. Fire-and-forget, best-effort only — the handler must never
    // itself become a crash source.
    try {
      const KC = require('react-native-keychain') as {
        setGenericPassword: (u: string, p: string, o: unknown) => Promise<boolean>;
      };
      void KC.setGenericPassword('veil', '1', {
        service: 'veil.veil_sess_crash',
        accessible: 'WhenUnlockedThisDeviceOnly',
      }).catch(() => undefined);
    } catch { /* keychain unavailable — marker stays unwritten */ }
    try {
      const { Alert } = require('react-native');
      Alert.alert('Vardum error — photograph this screen', msg + '\n\n' + stack.slice(0, 600));
    } catch {
      // Alert unavailable — the global above still holds the message.
    }
  });
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

if (typeof btoa === 'undefined') {
  (globalThis as unknown as Record<string, unknown>).btoa = (s: string): string => {
    let out = '';
    for (let i = 0; i < s.length; i += 3) {
      const b0 = s.charCodeAt(i);
      const has1 = i + 1 < s.length;
      const has2 = i + 2 < s.length;
      const b1 = has1 ? s.charCodeAt(i + 1) : 0;
      const b2 = has2 ? s.charCodeAt(i + 2) : 0;
      out += B64[b0 >> 2];
      out += B64[((b0 & 3) << 4) | (b1 >> 4)];
      out += has1 ? B64[((b1 & 15) << 2) | (b2 >> 6)] : '=';
      out += has2 ? B64[b2 & 63] : '=';
    }
    return out;
  };
}

if (typeof atob === 'undefined') {
  (globalThis as unknown as Record<string, unknown>).atob = (b64: string): string => {
    const clean = b64.replace(/[^A-Za-z0-9+/]/g, '');
    let out = '';
    for (let i = 0; i < clean.length; i += 4) {
      const n0 = B64.indexOf(clean[i]);
      const n1 = B64.indexOf(clean[i + 1]);
      const n2 = i + 2 < clean.length ? B64.indexOf(clean[i + 2]) : 0;
      const n3 = i + 3 < clean.length ? B64.indexOf(clean[i + 3]) : 0;
      out += String.fromCharCode((n0 << 2) | (n1 >> 4));
      if (i + 2 < clean.length) out += String.fromCharCode(((n1 & 15) << 4) | (n2 >> 2));
      if (i + 3 < clean.length) out += String.fromCharCode(((n2 & 3) << 6) | n3);
    }
    return out;
  };
}
