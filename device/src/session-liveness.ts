/**
 * @veil/device — does a session still exist on the relay? (Batch E, round-3
 * review R3-02, Oct 19 2026)
 *
 * The app used to delete an open chat's local keys when the chat was missing
 * from the session list. That list is capped, and other accounts can add rows
 * to it, so a missing row is NOT proof the session ended: a flood of rows (or a
 * busy group creator's own seats) pushed real chats off the list and the phone
 * erased them. Now the app asks the relay about that ONE session first, and
 * only a definite "Session not found" counts as gone. Anything else — the row
 * exists but is inactive, the credential is refused, a network error, a 5xx —
 * keeps the keys.
 *
 * Residual (disclosed): the relay itself (A2) can still answer "not found" for
 * a session it deleted; it can also withhold the envelopes, so this is the
 * same availability boundary as before, not a new capability.
 */
export type SessionLiveness = 'gone' | 'alive' | 'unknown';

export async function relaySessionLiveness(
  relay: { sessionHeartbeat(token: string, writeSecret: string | null): Promise<unknown> },
  token: string,
  writeSecret: string | null,
): Promise<SessionLiveness> {
  try {
    await relay.sessionHeartbeat(token, writeSecret);
    return 'alive';
  } catch (e) {
    const msg = String((e as Error)?.message ?? e);
    if (/^Session not found$/i.test(msg.trim())) return 'gone';
    // the row exists: inactive, ended-but-present, or our credential refused
    if (/not active|has ended|invalid session credential|already in use/i.test(msg)) return 'alive';
    return 'unknown';
  }
}
