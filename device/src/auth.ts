/**
 * @veil/device — Base44 account auth (the app account, NOT the Veil identity).
 *
 * Endpoints extracted from the web bundle (index-DYGFL-4a.js):
 *   POST {base}/api/apps/{appId}/auth/login            {email, password, turnstile_token?} -> {access_token, user}
 *   POST {base}/api/apps/{appId}/auth/verify-otp       {email, otp_code}
 *   POST {base}/api/apps/{appId}/auth/resend-otp      {email}
 *   POST {base}/api/apps/{appId}/auth/reset-password-request {email}
 *   POST {base}/api/apps/{appId}/auth/reset-password   {reset_token, new_password}
 *
 * The session token lives ONLY in the secure store (never AsyncStorage/plain
 * files). The 5-attempt server-side lockout (VeilLoginGuard) is enforced by the
 * backend — the client surfaces its lock message verbatim.
 */

import type { VeilStorage } from '../../crypto-core/src/index';

/** b197-r8n (K-26 fix): the auth platform's login response stopped including a
 *  user `id` (observed live Oct 14: two fresh logins, both id-less — the list
 *  machinery broke for every fresh login). Derive a STABLE per-user id from
 *  the email (the JWT's sub is the same identity) — robust to whatever shape
 *  the auth platform returns, now and in future response changes. */
async function normalizeAuthUser(user: unknown, email: string): Promise<{ id: string } & Record<string, unknown>> {
  const u = (user && typeof user === 'object') ? { ...(user as Record<string, unknown>) } : {};
  if (!u.id) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('veil-user:' + String(email).toLowerCase()));
    u.id = 'u_' + [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 24);
  }
  return u as { id: string } & Record<string, unknown>;
}

export const AUTH_SESSION_KEY = 'veil_auth_session';
let authMigratedThisLaunch = false;

export interface AuthUser {
  id: string;
  email?: string;
  [k: string]: unknown;
}

export interface AuthSession {
  access_token: string;
  user: AuthUser;
  savedAt: string;
}

export interface AuthFetchConfig {
  baseUrl: string;
  appId: string;
  fetchImpl?: typeof fetch;
}

export class Base44Auth {
  private cfg: AuthFetchConfig;
  private storage: VeilStorage;

  constructor(cfg: AuthFetchConfig, storage: VeilStorage) {
    this.cfg = cfg;
    this.storage = storage;
  }

  private async post(path: string, body: Record<string, unknown>): Promise<{ data: any; status: number }> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/auth/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data as { message?: string } | null)?.message || `auth error ${res.status}`;
      throw new Error(msg);
    }
    return { data, status: res.status };
  }

/** b198 ANONYMOUS SIGNUP: the relay creates the account in ONE step — the email
 *  is a self-declared label (real or invented, never verified, never contacted);
 *  the Base44-era 6-digit OTP flow is RETIRED. The 24-word phrase remains the
 *  only recovery path. Returns the live session (register → token, like login). */
  async signup(email: string, password: string): Promise<AuthSession> {
    const r = await this.post('register', { email, password });
    const session: AuthSession = {
      access_token: r.data.access_token,
      user: await normalizeAuthUser(r.data.user, email),
      savedAt: new Date().toISOString(),
    };
    await this.persist(session);
    return session;
  }

  async login(email: string, password: string): Promise<AuthSession> {
    const r = await this.post('login', { email, password });
    const session: AuthSession = {
      access_token: r.data.access_token,
      user: await normalizeAuthUser(r.data.user, email),
      savedAt: new Date().toISOString(),
    };
    await this.persist(session);
    return session;
  }

  async verifyOtp(email: string, otpCode: string): Promise<AuthSession> {
    const r = await this.post('verify-otp', { email, otp_code: otpCode });
    const session: AuthSession = { access_token: r.data.access_token, user: await normalizeAuthUser(r.data.user, email), savedAt: new Date().toISOString() };
    await this.persist(session);
    return session;
  }

  async resendOtp(email: string): Promise<void> {
    await this.post('resend-otp', { email });
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.post('reset-password-request', { email });
  }

  async resetPassword(resetToken: string, newPassword: string): Promise<void> {
    await this.post('reset-password', { reset_token: resetToken, new_password: newPassword });
  }

  private async persist(session: AuthSession): Promise<void> {
    await this.storage.set(AUTH_SESSION_KEY, JSON.stringify(session));
  }

  async currentSession(): Promise<AuthSession | null> {
    const raw = await this.storage.get(AUTH_SESSION_KEY);
    if (!raw) return null;
    // b81 ONE-TIME MIGRATION: existing installs already have this keychain
    // item stored under the OLD, stricter WHEN_UNLOCKED accessible tier —
    // iOS does not necessarily upgrade that attribute on a plain re-set, so
    // without this the fix in secure-store.rn.ts would only take effect on
    // the NEXT fresh login. Since a get() only ever succeeds while the
    // device is unlocked anyway, this is exactly the right moment to force
    // a delete+recreate under the new AFTER_FIRST_UNLOCK tier — once per
    // process launch is enough; non-fatal if it fails (session still works,
    // just not yet upgraded for background reads).
    if (!authMigratedThisLaunch) {
      authMigratedThisLaunch = true;
      this.storage.set(AUTH_SESSION_KEY, raw).catch((e) =>
        console.log('[veil-auth] b81 keychain-tier migration skipped:', String((e as Error)?.message ?? e)));
    }
    try {
      const session = JSON.parse(raw) as AuthSession;
      // b197-r8o (K-26 root fix): the auth platform's login STOPPED returning a
      // user object AT ALL (verified live: the stored session is
      // {access_token, savedAt} — no user field). The previous gate
      // (`session.user && …`) skipped exactly these sessions, so the id-less
      // state persisted through every reload. Now: when the user object is
      // missing or id-less, the identity is derived from the JWT's `sub` (the
      // email — the platform still signs it into the token) and the user object
      // is rebuilt + persisted. No re-login required.
      if (session && session.access_token && !session.user?.id) {
        let email = String(session.user?.email || (session as any).email || '');
        try {
          const payload = JSON.parse(atob(session.access_token.split('.')[1]));
          if (payload?.sub) email = String(payload.sub);
        } catch { /* token not a decodable JWT — fall back to the stored email */ }
        session.user = await normalizeAuthUser(session.user, email);
        await this.persist(session).catch(() => undefined);
      }
      return session;
    } catch { return null; }
  }

  /** Token provider for VeilRelay — drop-in: relay cfg getToken: auth.getToken. */
  async getToken(): Promise<string | null> {
    return (await this.currentSession())?.access_token ?? null;
  }

  /** Sign-out: server-side revocation + local wipe (tokens, session; NOT the keyvault). */
  /**
   * Permanently deletes everything this account owns (web parity: the
   * veilAccountDelete backend function, invoked with the account's client_ids).
   * The caller is responsible for wiping device data after this succeeds.
   */
  async deleteAccount(clientIds: string[] = []): Promise<Record<string, unknown>> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.getToken();
    const res = await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/functions/veilAccountDelete`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ client_ids: clientIds }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data as { message?: string } | null)?.message || `Vardum could not reach the relay — nothing was deleted. Try again in a moment.`;
      throw new Error(msg);
    }
    return (data as { data?: Record<string, unknown> } | null)?.data ?? {};
  }

  async logout(): Promise<void> {
    const session = await this.currentSession();
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    try {
      if (session) {
        await fetchImpl(`${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
        });
      }
    } catch {
      /* offline sign-out still clears locally */
    }
    await this.storage.remove(AUTH_SESSION_KEY);
  }
}
