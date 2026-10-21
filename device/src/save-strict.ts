/**
 * Batch H (round-6 review R6-1-06): a ratchet save that must land — a send (before
 * it goes out), a join, an accept, a completion. The secure store answers a
 * refused write with false; here that is an error, never a silent continue.
 */
export async function saveOrThrow(sessions: { save(token: string, state: never): Promise<unknown> }, token: string, state: unknown): Promise<void> {
  let ok: unknown;
  try { ok = await sessions.save(token, state as never); } catch { ok = false; }
  if (ok === false) throw new Error('Chat keys could not be saved on this device. Free up some space, then try again.');
}
